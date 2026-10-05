"""Digital signature abstraction (ML-DSA-65, NIST FIPS 204, formerly Dilithium3)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from .errors import SignatureInvalid


@dataclass(frozen=True)
class SigInfo:
    name: str
    standard: str
    security_category: str
    public_key_size: int
    private_key_size: int
    signature_size: int
    library: str


class SignatureBackend(ABC):
    info: SigInfo

    @abstractmethod
    def keygen(self) -> tuple[bytes, bytes]:
        """Return (public_key, private_key)."""

    @abstractmethod
    def sign(self, private_key: bytes, message: bytes) -> bytes: ...

    @abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        """Raise SignatureInvalid when verification fails."""


class MLDSA65(SignatureBackend):
    def __init__(self) -> None:
        from pqcrypto.sign import ml_dsa_65 as _d

        self._d = _d
        self.info = SigInfo(
            name="ML-DSA-65",
            standard="NIST FIPS 204",
            security_category="NIST Level 3",
            public_key_size=_d.PUBLIC_KEY_SIZE,
            private_key_size=_d.SECRET_KEY_SIZE,
            signature_size=_d.SIGNATURE_SIZE,
            library="pqcrypto (PQClean C reference implementation)",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        pk, sk = self._d.keygen()
        return bytes(pk), bytes(sk)

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        return bytes(self._d.sign(private_key, message))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        try:
            self._d.verify(public_key, message, signature)
        except Exception as exc:  # pqcrypto raises InvalidSignatureError / ValueError on bad sizes
            raise SignatureInvalid("Digital signature verification failed.") from exc


_REGISTRY: dict[str, type[SignatureBackend]] = {"ML-DSA-65": MLDSA65}
_DEFAULT = "ML-DSA-65"
_cache: dict[str, SignatureBackend] = {}


def get_signer(name: str = _DEFAULT) -> SignatureBackend:
    if name not in _REGISTRY:
        raise ValueError(f"unsupported signature algorithm: {name}")
    if name not in _cache:
        _cache[name] = _REGISTRY[name]()
    return _cache[name]
