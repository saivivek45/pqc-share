from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    keys: Mapped[list["Key"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Key(Base):
    """KEM and signature keys are separate rows (key separation). Private keys are stored only
    AES-256-GCM wrapped under a key derived from the server master key."""
    __tablename__ = "keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(8))  # "KEM" | "SIG"
    algorithm: Mapped[str] = mapped_column(String(32))
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    wrapped_private_key: Mapped[bytes] = mapped_column(LargeBinary)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    user: Mapped[User] = relationship(back_populates="keys")


class File(Base):
    __tablename__ = "files"
    id: Mapped[int] = mapped_column(primary_key=True)
    package_id: Mapped[str] = mapped_column(String(36), unique=True)
    storage_name: Mapped[str] = mapped_column(String(64), unique=True)
    filename: Mapped[str] = mapped_column(String(255))  # also authenticated inside the package
    filesize: Mapped[int] = mapped_column(BigInteger)
    package_size: Mapped[int] = mapped_column(BigInteger)
    kem_algorithm: Mapped[str] = mapped_column(String(32))
    signature_algorithm: Mapped[str] = mapped_column(String(32))
    aes_algorithm: Mapped[str] = mapped_column(String(32))
    sender_fingerprint: Mapped[str] = mapped_column(String(64))
    receiver_fingerprint: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FileShare(Base):
    __tablename__ = "file_shares"
    id: Mapped[int] = mapped_column(primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("files.id", ondelete="CASCADE"), index=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    receiver_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="ENCRYPTED")
    status_detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decrypted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    file: Mapped[File] = relationship()
    sender: Mapped[User] = relationship(foreign_keys=[sender_id])
    receiver: Mapped[User] = relationship(foreign_keys=[receiver_id])


class Transfer(Base):
    """Per-operation performance record for a share (encrypt / verify / decrypt)."""
    __tablename__ = "transfers"
    id: Mapped[int] = mapped_column(primary_key=True)
    share_id: Mapped[int] = mapped_column(ForeignKey("file_shares.id", ondelete="CASCADE"), index=True)
    operation: Mapped[str] = mapped_column(String(16))
    bytes: Mapped[int] = mapped_column(BigInteger)
    duration_ms: Mapped[float] = mapped_column()
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    event: Mapped[str] = mapped_column(String(48), index=True)
    detail: Mapped[str | None] = mapped_column(String(500), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Benchmark(Base):
    __tablename__ = "benchmarks"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    kind: Mapped[str] = mapped_column(String(16))  # "primitives" | "pipeline" | "comparison"
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    results: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    jti: Mapped[str] = mapped_column(String(32), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
