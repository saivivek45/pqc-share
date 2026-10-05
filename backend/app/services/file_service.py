"""Orchestrates the encrypt -> store -> verify -> decrypt lifecycle. All crypto happens server-side
and plaintext is never persisted: only the signed, encrypted package is written to disk."""
from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import new_storage_name, safe_filename
from app.crypto import (
    CryptoError, IntegrityError, MalformedPackage, SignatureInvalid, WrongReceiver,
    decrypt_package, encrypt_package, parse_package, verify_signature,
)
from app.models import File, FileShare, Transfer, User
from app.schemas import ShareOut, UserPublic
from app.services import audit, keys

_STORAGE_RE = re.compile(r"^[0-9a-f]{32}\.pqsh$")


class ShareError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# ---------------- storage ----------------
def _path(storage_name: str) -> Path:
    if not _STORAGE_RE.fullmatch(storage_name):  # path-traversal guard
        raise ShareError(500, "Invalid storage reference.")
    base = get_settings().packages_path
    p = (base / storage_name).resolve()
    if base != p.parent:
        raise ShareError(500, "Invalid storage reference.")
    return p


def write_package(blob: bytes) -> str:
    name = new_storage_name()
    target = _path(name)
    fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")  # secure temp file (0600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return name


def read_package(storage_name: str) -> bytes:
    p = _path(storage_name)
    if not p.exists():
        raise ShareError(410, "Encrypted package is missing from storage.")
    return p.read_bytes()


# ---------------- presentation ----------------
def to_out(s: FileShare) -> ShareOut:
    f = s.file
    return ShareOut(
        id=s.id, file_id=f.id, filename=f.filename, filesize=f.filesize, package_size=f.package_size,
        status=s.status, status_detail=s.status_detail,
        sender=UserPublic.model_validate(s.sender), receiver=UserPublic.model_validate(s.receiver),
        kem_algorithm=f.kem_algorithm, signature_algorithm=f.signature_algorithm, aes_algorithm=f.aes_algorithm,
        sender_fingerprint=f.sender_fingerprint, receiver_fingerprint=f.receiver_fingerprint,
        created_at=s.created_at, verified_at=s.verified_at, decrypted_at=s.decrypted_at,
    )


def get_share_for(db: Session, share_id: int, user: User, *, as_receiver: bool = False) -> FileShare:
    s = db.get(FileShare, share_id)
    allowed = s and (s.receiver_id == user.id or (not as_receiver and s.sender_id == user.id))
    if not allowed:  # same response for "missing" and "not yours": no existence oracle
        raise ShareError(404, "Transfer not found.")
    return s


def list_shares(db: Session, user: User, direction: str | None, limit: int = 200) -> list[FileShare]:
    cond = {
        "sent": FileShare.sender_id == user.id,
        "received": FileShare.receiver_id == user.id,
    }.get(direction or "", or_(FileShare.sender_id == user.id, FileShare.receiver_id == user.id))
    return list(db.scalars(select(FileShare).where(cond).order_by(FileShare.id.desc()).limit(limit)))


# ---------------- encrypt & share ----------------
def encrypt_and_share(db: Session, sender: User, receiver: User, filename: str | None, data: bytes, ip: str | None = None):
    if receiver.id == sender.id:
        raise ShareError(400, "Choose a different recipient than yourself.")
    if not data:
        raise ShareError(400, "The file is empty.")
    if len(data) > get_settings().max_upload_bytes:
        raise ShareError(413, f"File exceeds the {get_settings().max_upload_mb} MB limit.")
    filename = safe_filename(filename)
    sender_sig = keys.get_active_key(db, sender.id, "SIG")
    receiver_kem = keys.get_active_key(db, receiver.id, "KEM")
    audit.log(db, "FILE_UPLOADED", sender.id, f"{filename} ({len(data)} bytes)", ip)

    res = encrypt_package(
        data, filename, sender_id=sender.id, sender_sig_private_key=keys.unwrap(sender_sig),
        sender_sig_fingerprint=sender_sig.fingerprint, receiver_kem_public_key=receiver_kem.public_key,
        receiver_kem_fingerprint=receiver_kem.fingerprint,
    )
    audit.log(db, "FILE_ENCRYPTED", sender.id, f"AES-256-GCM + {res.header['kem_algorithm']}", ip)
    storage = write_package(res.blob)
    h = res.header
    f = File(package_id=h["package_id"], storage_name=storage, filename=filename, filesize=len(data),
             package_size=len(res.blob), kem_algorithm=h["kem_algorithm"], signature_algorithm=h["signature_algorithm"],
             aes_algorithm=h["aes_algorithm"], sender_fingerprint=h["sender_fingerprint"],
             receiver_fingerprint=h["receiver_fingerprint"])
    share = FileShare(file=f, sender_id=sender.id, receiver_id=receiver.id, status="ENCRYPTED")
    db.add(share)
    db.flush()
    db.add(Transfer(share_id=share.id, operation="encrypt", bytes=len(data), duration_ms=res.timings_ms["total"],
                    details=res.timings_ms))
    db.commit()
    audit.log(db, "FILE_SHARED", sender.id, f"to user #{receiver.id}", ip)
    audit.log(db, "FILE_RECEIVED", receiver.id, f"from user #{sender.id}: {filename}", ip)
    return share, res.timings_ms


# ---------------- verify ----------------
def _fail(db: Session, share: FileShare, user: User, event: str, detail: str, ip: str | None) -> None:
    share.status, share.status_detail = "INTEGRITY_FAILED", detail[:255]
    db.commit()
    audit.log(db, event, user.id, f"share #{share.id}: {detail}", ip)


def _verify(db: Session, share: FileShare, user: User, ip: str | None):
    blob = read_package(share.file.storage_name)
    try:
        pkg = parse_package(blob)
        if pkg.header["package_id"] != share.file.package_id or pkg.header["receiver_fingerprint"] != share.file.receiver_fingerprint:
            raise MalformedPackage("Package does not match its database record.")
        sender_key = keys.get_key_by_fingerprint(db, share.sender_id, "SIG", pkg.header["sender_fingerprint"])
        if sender_key is None:
            raise SignatureInvalid("Sender key is not registered.")
        verify_signature(pkg, sender_key.public_key, share.file.sender_fingerprint)
    except SignatureInvalid as exc:
        _fail(db, share, user, "SIGNATURE_INVALID", str(exc), ip)
        raise ShareError(422, f"Signature verification failed. {IntegrityError.USER_MESSAGE}") from exc
    except IntegrityError as exc:
        _fail(db, share, user, "INTEGRITY_CHECK_FAILED", str(exc), ip)
        raise ShareError(422, IntegrityError.USER_MESSAGE) from exc
    return pkg, sender_key


def verify_share(db: Session, share: FileShare, user: User, ip: str | None = None):
    pkg, _ = _verify(db, share, user, ip)
    if share.status in ("ENCRYPTED", "INTEGRITY_FAILED"):
        share.status, share.status_detail = "VERIFIED", None
    share.verified_at = datetime.now(timezone.utc)
    db.commit()
    audit.log(db, "SIGNATURE_VERIFIED", user.id, f"share #{share.id} ({pkg.header['signature_algorithm']})", ip)
    return pkg


# ---------------- decrypt ----------------
def _decrypt(db: Session, share: FileShare, user: User, ip: str | None):
    pkg = verify_share(db, share, user, ip)
    kem_key = keys.get_key_by_fingerprint(db, user.id, "KEM", pkg.header["receiver_fingerprint"])
    if kem_key is None:
        raise ShareError(403, "This package was not encrypted for any of your keys.")
    try:
        res = decrypt_package(pkg, receiver_kem_private_key=keys.unwrap(kem_key),
                              receiver_kem_fingerprint=kem_key.fingerprint)
    except WrongReceiver as exc:
        raise ShareError(403, str(exc)) from exc
    except CryptoError as exc:  # IntegrityError and friends: never return partial plaintext
        _fail(db, share, user, "INTEGRITY_CHECK_FAILED", "AES-GCM authentication failed", ip)
        raise ShareError(422, IntegrityError.USER_MESSAGE) from exc
    return res


def decrypt_share(db: Session, share: FileShare, user: User, ip: str | None = None):
    res = _decrypt(db, share, user, ip)
    first = share.decrypted_at is None
    share.status, share.status_detail = "DECRYPTED", None
    if first:
        share.decrypted_at = datetime.now(timezone.utc)
    db.add(Transfer(share_id=share.id, operation="decrypt", bytes=len(res.plaintext),
                    duration_ms=res.timings_ms["total"], details=res.timings_ms))
    db.commit()
    audit.log(db, "FILE_DECRYPTED", user.id, f"share #{share.id}", ip)
    return res


def download_share(db: Session, share: FileShare, user: User, ip: str | None = None):
    if share.status != "DECRYPTED":
        raise ShareError(409, "Verify & decrypt the file before downloading.")
    res = _decrypt(db, share, user, ip)  # fresh full verification on every download
    audit.log(db, "FILE_DOWNLOADED", user.id, f"share #{share.id}", ip)
    return res


# ---------------- forward (re-share) ----------------
def forward_share(db: Session, share: FileShare, user: User, receiver: User, ip: str | None = None):
    res = _decrypt(db, share, user, ip)
    return encrypt_and_share(db, user, receiver, res.filename, res.plaintext, ip)
