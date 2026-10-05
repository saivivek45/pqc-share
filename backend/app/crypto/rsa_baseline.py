"""RSA-2048 classical baseline used ONLY for the Classical-vs-PQ comparison page.
RSA-OAEP(SHA-256) is used to transport a 32-byte key, mirroring KEM usage."""
from __future__ import annotations

import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0


def measure_rsa2048(iterations: int = 5) -> dict:
    import os

    kg, enc, dec = [], [], []
    for _ in range(iterations):
        t0 = time.perf_counter()
        sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kg.append(_ms(t0))
        pk = sk.public_key()
        secret = os.urandom(32)
        t0 = time.perf_counter()
        ct = pk.encrypt(secret, _OAEP)
        enc.append(_ms(t0))
        t0 = time.perf_counter()
        out = sk.decrypt(ct, _OAEP)
        dec.append(_ms(t0))
        assert out == secret
    pub = pk.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv = sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return {
        "algorithm": "RSA-2048 (OAEP, SHA-256)",
        "keygen_ms": kg, "encrypt_ms": enc, "decrypt_ms": dec,
        "public_key_bytes": len(pub), "private_key_bytes": len(priv), "ciphertext_bytes": len(ct),
    }
