"""Symmetric layer: AES-256-GCM, HKDF-SHA256 key derivation, fingerprints, key wrapping."""
from __future__ import annotations

import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import IntegrityError

AES_ALGORITHM = "AES-256-GCM"
NONCE_SIZE = 12  # 96-bit nonce, as recommended by NIST SP 800-38D
TAG_SIZE = 16
KDF_ALGORITHM = "HKDF-SHA256"


def random_bytes(n: int) -> bytes:
    return os.urandom(n)  # OS CSPRNG


def aes_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Returns ciphertext || 16-byte tag."""
    if len(key) != 32 or len(nonce) != NONCE_SIZE:
        raise ValueError("AES-256-GCM requires a 32-byte key and 12-byte nonce")
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, nonce: bytes, ct_and_tag: bytes, aad: bytes) -> bytes:
    """One-shot authenticated decryption. Plaintext is only returned if the tag verifies."""
    try:
        return AESGCM(key).decrypt(nonce, ct_and_tag, aad)
    except InvalidTag as exc:
        raise IntegrityError() from exc


def derive_session_key(shared_secret: bytes, sender_fp: str, receiver_fp: str, package_id: str) -> bytes:
    """Domain-separated AES key from the KEM shared secret (key separation + context binding)."""
    info = f"PQC-Share/v1/aes-256-gcm|{package_id}|{sender_fp}|{receiver_fp}".encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def fingerprint(public_key: bytes) -> str:
    """SHA3-256 of the public key, hex (64 chars)."""
    return sha3_256(public_key).hex()


def format_fingerprint(fp: str) -> str:
    return ":".join(fp[i : i + 4] for i in range(0, 32, 4)).upper()


# ---- private-key protection at rest -------------------------------------------------

def _kek(master_key: bytes, user_id: int, kind: str) -> bytes:
    info = f"PQC-Share/v1/keywrap|{kind}|{user_id}".encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(master_key)


def wrap_private_key(master_key: bytes, user_id: int, kind: str, fp: str, private_key: bytes) -> bytes:
    nonce = random_bytes(NONCE_SIZE)
    aad = f"{kind}|{user_id}|{fp}".encode()
    return nonce + AESGCM(_kek(master_key, user_id, kind)).encrypt(nonce, private_key, aad)


def unwrap_private_key(master_key: bytes, user_id: int, kind: str, fp: str, blob: bytes) -> bytes:
    aad = f"{kind}|{user_id}|{fp}".encode()
    try:
        return AESGCM(_kek(master_key, user_id, kind)).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad)
    except InvalidTag as exc:
        raise IntegrityError("Stored private key failed authentication.") from exc
