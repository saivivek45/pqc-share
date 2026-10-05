"""Password hashing (Argon2id) and JWT session tokens."""
from __future__ import annotations

import re
import secrets
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from .config import get_settings

_ph = PasswordHasher()  # Argon2id, library defaults (RFC 9106 low-memory profile)
_DUMMY_HASH = _ph.hash("dummy-password-for-constant-time")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, hashed: str | None) -> bool:
    """Always performs one Argon2 verification to blunt user-enumeration timing."""
    try:
        return _ph.verify(hashed or _DUMMY_HASH, password) and hashed is not None
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    return _ph.check_needs_rehash(hashed)


def validate_password_strength(password: str) -> str | None:
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if len(password) > 128:
        return "Password must be at most 128 characters."
    if not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password) and re.search(r"\d", password)):
        return "Password must contain upper-case, lower-case letters and a digit."
    return None


def create_token(user_id: int) -> tuple[str, str, datetime]:
    s = get_settings()
    jti = uuid.uuid4().hex
    exp = datetime.now(timezone.utc) + timedelta(minutes=s.token_ttl_minutes)
    token = jwt.encode({"sub": str(user_id), "jti": jti, "exp": exp}, s.jwt_secret, algorithm="HS256")
    return token, jti, exp


def decode_token(token: str) -> dict:
    return jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"], options={"require": ["exp", "sub", "jti"]})


def safe_filename(name: str | None) -> str:
    """Strip directories, control chars and reserved characters; cap length. Never empty."""
    name = unicodedata.normalize("NFKC", name or "")
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f\x7f<>:\"|?*]", "", name).strip(" .")
    name = re.sub(r"\.{2,}", ".", name)
    if len(name) > 200:
        stem, dot, ext = name.rpartition(".")
        name = (stem[:150] + dot + ext[:20]) if dot else name[:200]
    return name or "file"


def new_storage_name() -> str:
    """Server-chosen opaque storage id: user input never reaches the filesystem path."""
    return secrets.token_hex(16) + ".pqsh"
