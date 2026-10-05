"""Cryptographic error types. Messages are safe to show to end users."""


class CryptoError(Exception):
    """Base class for all cryptographic failures."""


class SignatureInvalid(CryptoError):
    """The digital signature over the package did not verify."""


class IntegrityError(CryptoError):
    """AES-GCM authentication failed or the package is malformed/modified."""

    USER_MESSAGE = "Integrity verification failed. The file may have been modified or corrupted."

    def __init__(self, msg: str | None = None):
        super().__init__(msg or self.USER_MESSAGE)


class WrongReceiver(CryptoError):
    """The package was not encrypted for this receiver's KEM key."""


class MalformedPackage(IntegrityError):
    """The container could not be parsed / has unsupported fields."""
