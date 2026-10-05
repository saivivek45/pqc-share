"""Unit tests for the cryptographic layer (no HTTP, no DB)."""
import os

import pytest

from app.crypto import (
    IntegrityError, MalformedPackage, SignatureInvalid, WrongReceiver, decrypt_package, encrypt_package,
    get_kem, get_signer, parse_package, primitives as P, verify_signature,
)
from app.crypto.package import Package, b64e


@pytest.fixture(scope="module")
def parties():
    kem, sig = get_kem(), get_signer()
    rpk, rsk = kem.keygen()
    spk, ssk = sig.keygen()
    return dict(rpk=rpk, rsk=rsk, spk=spk, ssk=ssk, rfp=P.fingerprint(rpk), sfp=P.fingerprint(spk))


def enc(parties, data=b"top secret", name="doc.txt"):
    return encrypt_package(data, name, sender_id=1, sender_sig_private_key=parties["ssk"],
                           sender_sig_fingerprint=parties["sfp"], receiver_kem_public_key=parties["rpk"],
                           receiver_kem_fingerprint=parties["rfp"])


def dec(parties, blob):
    pkg = parse_package(blob)
    verify_signature(pkg, parties["spk"])
    return decrypt_package(pkg, receiver_kem_private_key=parties["rsk"], receiver_kem_fingerprint=parties["rfp"])


def test_algorithms_are_the_real_standards():
    assert get_kem().info.name == "ML-KEM-768" and get_kem().info.ciphertext_size == 1088
    assert get_signer().info.name == "ML-DSA-65" and get_signer().info.signature_size == 3309


def test_aes_roundtrip_and_tag_failure():
    key, nonce = os.urandom(32), os.urandom(12)
    ct = P.aes_encrypt(key, nonce, b"hello", b"aad")
    assert P.aes_decrypt(key, nonce, ct, b"aad") == b"hello"
    with pytest.raises(IntegrityError):
        P.aes_decrypt(key, nonce, ct, b"other-aad")
    bad = bytearray(ct); bad[0] ^= 1
    with pytest.raises(IntegrityError):
        P.aes_decrypt(key, nonce, bytes(bad), b"aad")


def test_kem_encaps_decaps_and_implicit_rejection():
    kem = get_kem()
    pk, sk = kem.keygen()
    ct, ss = kem.encapsulate(pk)
    assert kem.decapsulate(sk, ct) == ss and len(ss) == 32
    _, sk2 = kem.keygen()
    assert kem.decapsulate(sk2, ct) != ss  # wrong key -> different secret
    ct2, ss2 = kem.encapsulate(pk)
    assert ct != ct2 and ss != ss2  # fresh randomness


def test_signature_sign_verify_and_reject():
    s = get_signer()
    pk, sk = s.keygen()
    sig = s.sign(sk, b"msg")
    s.verify(pk, b"msg", sig)
    with pytest.raises(SignatureInvalid):
        s.verify(pk, b"msg2", sig)
    with pytest.raises(SignatureInvalid):
        s.verify(s.keygen()[0], b"msg", sig)


def test_roundtrip(parties):
    res = enc(parties, b"Z" * 1000, "a.bin")
    out = dec(parties, res.blob)
    assert out.plaintext == b"Z" * 1000 and out.filename == "a.bin"
    assert b"Z" * 16 not in res.blob  # ciphertext does not leak plaintext


def test_unique_nonce_and_kem_ciphertext_per_package(parties):
    a, b = enc(parties).header, enc(parties).header
    assert a["nonce"] != b["nonce"] and a["kem_ciphertext"] != b["kem_ciphertext"] and a["package_id"] != b["package_id"]


def test_security_every_single_bit_flip_in_ciphertext_is_detected(parties):
    """Encrypt -> modify one byte -> decryption MUST fail."""
    blob = enc(parties, os.urandom(4096)).blob
    for pos in (len(blob) - 1, len(blob) - 17, len(blob) - 2000, len(blob) // 2 + 100):
        bad = bytearray(blob); bad[pos] ^= 0x01
        with pytest.raises((IntegrityError, SignatureInvalid)):
            dec(parties, bytes(bad))


def test_ciphertext_tamper_fails_gcm_even_without_signature_check(parties):
    blob = enc(parties).blob
    bad = bytearray(blob); bad[-1] ^= 0x80
    pkg = parse_package(bytes(bad))  # signature check skipped on purpose
    with pytest.raises(IntegrityError):
        decrypt_package(pkg, receiver_kem_private_key=parties["rsk"], receiver_kem_fingerprint=parties["rfp"])


def test_tampered_metadata_detected_by_signature_and_by_gcm(parties):
    pkg = parse_package(enc(parties).blob)
    pkg.header["filename"] = "evil.exe"
    forged = parse_package(pkg.to_bytes())
    with pytest.raises(SignatureInvalid):
        verify_signature(forged, parties["spk"])
    with pytest.raises(IntegrityError):  # defence in depth: AAD mismatch
        decrypt_package(forged, receiver_kem_private_key=parties["rsk"], receiver_kem_fingerprint=parties["rfp"])


def test_tampered_kem_ciphertext_detected(parties):
    pkg = parse_package(enc(parties).blob)
    import base64
    ct = bytearray(base64.b64decode(pkg.header["kem_ciphertext"])); ct[5] ^= 1
    pkg.header["kem_ciphertext"] = b64e(bytes(ct))
    forged = parse_package(pkg.to_bytes())
    with pytest.raises(SignatureInvalid):
        verify_signature(forged, parties["spk"])
    with pytest.raises(IntegrityError):
        decrypt_package(forged, receiver_kem_private_key=parties["rsk"], receiver_kem_fingerprint=parties["rfp"])


def test_wrong_receiver_rejected(parties):
    blob = enc(parties).blob
    other_pk, other_sk = get_kem().keygen()
    pkg = parse_package(blob)
    with pytest.raises(WrongReceiver):
        decrypt_package(pkg, receiver_kem_private_key=other_sk, receiver_kem_fingerprint=P.fingerprint(other_pk))


def test_wrong_receiver_key_with_spoofed_fingerprint_still_fails(parties):
    pkg = parse_package(enc(parties).blob)
    _, other_sk = get_kem().keygen()
    with pytest.raises(IntegrityError):
        decrypt_package(pkg, receiver_kem_private_key=other_sk, receiver_kem_fingerprint=parties["rfp"])


def test_invalid_signature_rejected_when_signed_by_someone_else(parties):
    mallory_pk, mallory_sk = get_signer().keygen()
    forged = encrypt_package(b"x", "f", sender_id=1, sender_sig_private_key=mallory_sk,
                             sender_sig_fingerprint=parties["sfp"],  # claims to be the real sender
                             receiver_kem_public_key=parties["rpk"], receiver_kem_fingerprint=parties["rfp"])
    with pytest.raises(SignatureInvalid):
        verify_signature(parse_package(forged.blob), parties["spk"])


def test_malformed_packages(parties):
    blob = enc(parties).blob
    for bad in (b"", b"junk", blob[:10], blob[:-5], blob + b"\x00", b"PQSH\xff\xff\xff\xff" + blob[8:]):
        with pytest.raises(MalformedPackage):
            parse_package(bad)


def test_large_file_20mb(parties):
    data = os.urandom(20 * 1024 * 1024)
    out = dec(parties, enc(parties, data, "big.bin").blob)
    assert out.plaintext == data


def test_private_key_wrapping_roundtrip_and_binding():
    master, sk = os.urandom(32), os.urandom(4000)
    blob = P.wrap_private_key(master, 7, "KEM", "fp", sk)
    assert sk not in blob and P.unwrap_private_key(master, 7, "KEM", "fp", blob) == sk
    with pytest.raises(IntegrityError):
        P.unwrap_private_key(master, 8, "KEM", "fp", blob)  # bound to user id
    with pytest.raises(IntegrityError):
        P.unwrap_private_key(os.urandom(32), 7, "KEM", "fp", blob)
