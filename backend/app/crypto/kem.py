"""Key Encapsulation Mechanism abstraction.

Only this module (and `sig.py`) import the PQC library. To swap in a different
KEM (e.g. liboqs, ML-KEM-1024, FrodoKEM) implement `KEMBackend` and register it.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class KEMInfo:
    name: str
    standard: str
    security_category: str
    public_key_size: int
    private_key_size: int
    ciphertext_size: int
    shared_secret_size: int
    library: str


class KEMBackend(ABC):
    info: KEMInfo

    @abstractmethod
    def keygen(self) -> tuple[bytes, bytes]:
        """Return (public_key, private_key)."""

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return (kem_ciphertext, shared_secret)."""

    @abstractmethod
    def decapsulate(self, private_key: bytes, kem_ciphertext: bytes) -> bytes:
        """Return shared_secret. ML-KEM uses implicit rejection: a wrong key or
        modified ciphertext yields a *different* secret rather than an error."""


class MLKEM768(KEMBackend):
    """ML-KEM-768 (NIST FIPS 203, formerly CRYSTALS-Kyber-768) via pqcrypto/PQClean."""

    def __init__(self) -> None:
        from pqcrypto.kem import ml_kem_768 as _m

        self._m = _m
        self.info = KEMInfo(
            name="ML-KEM-768",
            standard="NIST FIPS 203",
            security_category="NIST Level 3 (~AES-192)",
            public_key_size=_m.PUBLIC_KEY_SIZE,
            private_key_size=_m.SECRET_KEY_SIZE,
            ciphertext_size=_m.CIPHERTEXT_SIZE,
            shared_secret_size=_m.SHARED_SECRET_SIZE,
            library="pqcrypto (PQClean C reference implementation)",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        pk, sk = self._m.keygen()
        return bytes(pk), bytes(sk)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        if len(public_key) != self.info.public_key_size:
            raise ValueError("invalid KEM public key length")
        ct, ss = self._m.encaps(public_key)
        return bytes(ct), bytes(ss)

    def decapsulate(self, private_key: bytes, kem_ciphertext: bytes) -> bytes:
        if len(kem_ciphertext) != self.info.ciphertext_size:
            raise ValueError("invalid KEM ciphertext length")
        return bytes(self._m.decaps(private_key, kem_ciphertext))


_REGISTRY: dict[str, type[KEMBackend]] = {"ML-KEM-768": MLKEM768}
_DEFAULT = "ML-KEM-768"
_cache: dict[str, KEMBackend] = {}


def get_kem(name: str = _DEFAULT) -> KEMBackend:
    if name not in _REGISTRY:
        raise ValueError(f"unsupported KEM algorithm: {name}")
    if name not in _cache:
        _cache[name] = _REGISTRY[name]()
    return _cache[name]
