"""Versioned encrypted-package format and the hybrid encrypt / verify / decrypt workflow.

Container layout (all integers big-endian):

    +--------+------------+-----------------------+---------------------------+
    | "PQSH" | u32 hdr_len| header (UTF-8 JSON)   | ciphertext || GCM tag (16B)|
    +--------+------------+-----------------------+---------------------------+

Header fields (v1)            | AAD for AES-GCM | covered by signature
------------------------------|-----------------|---------------------
version, package_id           | yes             | yes
filename, filesize, timestamp | yes             | yes
kem/sig/aes/kdf algorithm ids | yes             | yes
nonce, kem_ciphertext         | yes             | yes
sender_*/receiver_fingerprint | yes             | yes
ciphertext_len, tag_length    | yes             | yes
ciphertext || tag (body)      | (is the output) | yes (via SHA3-256 digest)
signature                     | no (it signs)   | -

AAD     = canonical JSON of every header field except `signature`.
SIG MSG = DOMAIN || AAD || SHA3-256(body)

So tampering with *any* header byte invalidates both the signature and the GCM tag,
and tampering with the body invalidates both as well (defence in depth).
"""
from __future__ import annotations

import base64
import binascii
import json
import struct
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import primitives as P
from .errors import IntegrityError, MalformedPackage, SignatureInvalid, WrongReceiver
from .kem import get_kem
from .sig import get_signer

MAGIC = b"PQSH"
VERSION = 1
SIG_DOMAIN = b"PQC-Share/v1/package-signature\x00"
MAX_HEADER_BYTES = 64 * 1024

REQUIRED_FIELDS = {
    "version", "package_id", "filename", "filesize", "timestamp", "kem_algorithm",
    "signature_algorithm", "aes_algorithm", "kdf_algorithm", "nonce", "kem_ciphertext",
    "sender_id", "sender_fingerprint", "receiver_fingerprint", "ciphertext_len", "tag_length",
    "signature",
}


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise MalformedPackage("Package contains invalid encoding.") from exc


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@dataclass
class Package:
    header: dict
    body: bytes  # ciphertext || tag

    @property
    def signature(self) -> bytes:
        return b64d(self.header["signature"])

    def aad(self) -> bytes:
        return canonical({k: v for k, v in self.header.items() if k != "signature"})

    def signed_message(self) -> bytes:
        return SIG_DOMAIN + self.aad() + P.sha3_256(self.body)

    def to_bytes(self) -> bytes:
        h = canonical(self.header)
        return MAGIC + struct.pack(">I", len(h)) + h + self.body


@dataclass
class EncryptResult:
    blob: bytes
    header: dict
    timings_ms: dict = field(default_factory=dict)


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0


def encrypt_package(
    plaintext: bytes,
    filename: str,
    *,
    sender_id: int,
    sender_sig_private_key: bytes,
    sender_sig_fingerprint: str,
    receiver_kem_public_key: bytes,
    receiver_kem_fingerprint: str,
    kem_name: str = "ML-KEM-768",
    sig_name: str = "ML-DSA-65",
) -> EncryptResult:
    kem, signer = get_kem(kem_name), get_signer(sig_name)
    t: dict[str, float] = {}

    # 1) fresh KEM encapsulation -> shared secret  (receiver's PQ public key)
    t0 = time.perf_counter()
    kem_ct, shared_secret = kem.encapsulate(receiver_kem_public_key)
    t["kem_encapsulate"] = _ms(t0)

    package_id = str(uuid.uuid4())
    # 2) session key via HKDF (key separation; never stored or transmitted)
    session_key = P.derive_session_key(shared_secret, sender_sig_fingerprint, receiver_kem_fingerprint, package_id)
    nonce = P.random_bytes(P.NONCE_SIZE)

    header = {
        "version": VERSION,
        "package_id": package_id,
        "filename": filename,
        "filesize": len(plaintext),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kem_algorithm": kem.info.name,
        "signature_algorithm": signer.info.name,
        "aes_algorithm": P.AES_ALGORITHM,
        "kdf_algorithm": P.KDF_ALGORITHM,
        "nonce": b64e(nonce),
        "kem_ciphertext": b64e(kem_ct),
        "sender_id": sender_id,
        "sender_fingerprint": sender_sig_fingerprint,
        "receiver_fingerprint": receiver_kem_fingerprint,
        "ciphertext_len": len(plaintext) + P.TAG_SIZE,
        "tag_length": P.TAG_SIZE,
    }
    aad = canonical(header)

    # 3) AES-256-GCM over the file, header bound as AAD
    t0 = time.perf_counter()
    body = P.aes_encrypt(session_key, nonce, plaintext, aad)
    t["aes_encrypt"] = _ms(t0)
    del session_key, shared_secret

    # 4) ML-DSA signature over domain || AAD || SHA3-256(body)
    t0 = time.perf_counter()
    sig = signer.sign(sender_sig_private_key, SIG_DOMAIN + aad + P.sha3_256(body))
    t["sign"] = _ms(t0)

    header["signature"] = b64e(sig)
    pkg = Package(header, body)
    t["total"] = sum(t.values())
    return EncryptResult(pkg.to_bytes(), header, t)


def parse_package(blob: bytes) -> Package:
    """Strict parser. Raises MalformedPackage on anything unexpected."""
    if len(blob) < 8 or blob[:4] != MAGIC:
        raise MalformedPackage("Not a PQC-Share package.")
    (hlen,) = struct.unpack(">I", blob[4:8])
    if hlen == 0 or hlen > MAX_HEADER_BYTES or 8 + hlen > len(blob):
        raise MalformedPackage("Package header is corrupted.")
    try:
        header = json.loads(blob[8 : 8 + hlen].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedPackage("Package header is corrupted.") from exc
    if not isinstance(header, dict) or not REQUIRED_FIELDS.issubset(header):
        raise MalformedPackage("Package header is incomplete.")
    if header["version"] != VERSION:
        raise MalformedPackage(f"Unsupported package version {header['version']!r}.")
    body = blob[8 + hlen :]
    if not isinstance(header["ciphertext_len"], int) or header["ciphertext_len"] != len(body):
        raise MalformedPackage("Ciphertext length mismatch (truncated or extended).")
    try:
        if header["aes_algorithm"] != P.AES_ALGORITHM or header["kdf_algorithm"] != P.KDF_ALGORITHM:
            raise MalformedPackage("Unsupported symmetric algorithm.")
        get_kem(header["kem_algorithm"]), get_signer(header["signature_algorithm"])
    except ValueError as exc:
        raise MalformedPackage(str(exc)) from exc
    return Package(header, body)


def verify_signature(pkg: Package, sender_sig_public_key: bytes, expected_sender_fp: str | None = None) -> None:
    """Step 2 of decryption: authenticate the sender and the whole package."""
    if expected_sender_fp is not None and pkg.header["sender_fingerprint"] != expected_sender_fp:
        raise SignatureInvalid("Sender key fingerprint does not match the registered sender.")
    if P.fingerprint(sender_sig_public_key) != pkg.header["sender_fingerprint"]:
        raise SignatureInvalid("Sender public key does not match the package fingerprint.")
    get_signer(pkg.header["signature_algorithm"]).verify(
        sender_sig_public_key, pkg.signed_message(), pkg.signature
    )


@dataclass
class DecryptResult:
    plaintext: bytes
    filename: str
    timings_ms: dict


def decrypt_package(
    pkg: Package,
    *,
    receiver_kem_private_key: bytes,
    receiver_kem_fingerprint: str,
) -> DecryptResult:
    """Steps 3-5: KEM decapsulation -> session key -> AES-GCM authenticated decryption.

    Callers MUST call verify_signature() first. Returns plaintext only if the GCM tag verifies.
    """
    h = pkg.header
    if h["receiver_fingerprint"] != receiver_kem_fingerprint:
        raise WrongReceiver("This package was not encrypted for your key.")
    kem = get_kem(h["kem_algorithm"])
    t: dict[str, float] = {}

    t0 = time.perf_counter()
    try:
        shared_secret = kem.decapsulate(receiver_kem_private_key, b64d(h["kem_ciphertext"]))
    except ValueError as exc:
        raise MalformedPackage("Invalid KEM ciphertext.") from exc
    t["kem_decapsulate"] = _ms(t0)

    session_key = P.derive_session_key(shared_secret, h["sender_fingerprint"], h["receiver_fingerprint"], h["package_id"])
    nonce = b64d(h["nonce"])
    if len(nonce) != P.NONCE_SIZE:
        raise MalformedPackage("Invalid nonce length.")

    t0 = time.perf_counter()
    plaintext = P.aes_decrypt(session_key, nonce, pkg.body, pkg.aad())
    t["aes_decrypt"] = _ms(t0)
    del session_key, shared_secret

    if len(plaintext) != h["filesize"]:
        raise IntegrityError()
    t["total"] = sum(t.values())
    return DecryptResult(plaintext, h["filename"], t)
