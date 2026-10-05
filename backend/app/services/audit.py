"""Audit log. NEVER pass passwords, private keys, session keys or plaintext into `detail`."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AuditLog

EVENTS = {
    "USER_REGISTERED", "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGOUT", "KEYS_GENERATED", "FILE_UPLOADED",
    "FILE_ENCRYPTED", "FILE_SHARED", "FILE_RECEIVED", "SIGNATURE_VERIFIED", "SIGNATURE_INVALID",
    "INTEGRITY_CHECK_FAILED", "FILE_DECRYPTED", "FILE_DOWNLOADED", "BENCHMARK_RUN",
}


def log(db: Session, event: str, user_id: int | None = None, detail: str | None = None, ip: str | None = None) -> None:
    assert event in EVENTS, event
    db.add(AuditLog(user_id=user_id, event=event, detail=(detail or "")[:500] or None, ip=ip))
    db.commit()
