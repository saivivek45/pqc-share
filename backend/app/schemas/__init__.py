from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, PlainSerializer, field_validator


def _utc(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


UTC = Annotated[datetime, PlainSerializer(_utc, return_type=str, when_used="json")]
OptUTC = Annotated[datetime | None, PlainSerializer(_utc, return_type=str | None, when_used="json")]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---- auth ----
class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def lower(cls, v: str) -> str:
        return v.strip()


class LoginIn(BaseModel):
    username: str = Field(max_length=255)  # username or email
    password: str = Field(max_length=128)


class UserOut(ORM):
    id: int
    username: str
    email: str
    created_at: UTC


class UserPublic(ORM):
    id: int
    username: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: UTC
    user: UserOut


# ---- keys ----
class KeyOut(ORM):
    id: int
    kind: str
    algorithm: str
    fingerprint: str
    fingerprint_pretty: str
    public_key_bytes: int
    status: str
    created_at: UTC


class PublicKeyOut(BaseModel):
    kem_algorithm: str
    kem_fingerprint: str
    kem_public_key: str  # base64
    signature_algorithm: str
    signature_fingerprint: str
    signature_public_key: str  # base64


# ---- files ----
class ShareOut(BaseModel):
    id: int
    file_id: int
    filename: str
    filesize: int
    package_size: int
    status: str
    status_detail: str | None
    sender: UserPublic
    receiver: UserPublic
    kem_algorithm: str
    signature_algorithm: str
    aes_algorithm: str
    sender_fingerprint: str
    receiver_fingerprint: str
    created_at: UTC
    verified_at: OptUTC
    decrypted_at: OptUTC


class ShareIn(BaseModel):
    receiver_id: int


class UploadOut(BaseModel):
    share: ShareOut
    timings_ms: dict[str, float]


class VerifyOut(BaseModel):
    share: ShareOut
    signature_valid: bool
    sender_fingerprint: str
    algorithm: str
    message: str


class DecryptOut(BaseModel):
    share: ShareOut
    timings_ms: dict[str, float]
    message: str


class DashboardOut(BaseModel):
    total_files_shared: int
    files_sent: int
    files_received: int
    successful_decryptions: int
    failed_integrity_checks: int
    recent: list[ShareOut]


class AuditOut(ORM):
    id: int
    event: str
    detail: str | None
    created_at: UTC


class BenchmarkRunIn(BaseModel):
    sizes_mb: list[float] = Field(default_factory=lambda: [1, 5, 10], max_length=6)
    iterations: int = Field(default=5, ge=1, le=50)

    @field_validator("sizes_mb")
    @classmethod
    def sane(cls, v: list[float]) -> list[float]:
        for s in v:
            if not (0.01 <= s <= 50):
                raise ValueError("sizes must be between 0.01 and 50 MB")
        return v


class BenchmarkOut(BaseModel):
    id: int
    kind: str
    parameters: dict[str, Any]
    results: dict[str, Any]
    created_at: UTC
