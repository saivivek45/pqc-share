from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import current_user
from app.core.db import get_db
from app.crypto import primitives as P
from app.models import Key, User
from app.schemas import KeyOut, PublicKeyOut, UserPublic
from app.services import keys as key_svc

users_router = APIRouter(prefix="/users", tags=["users"])
keys_router = APIRouter(prefix="/keys", tags=["keys"])


def _key_out(k: Key) -> KeyOut:
    return KeyOut(id=k.id, kind=k.kind, algorithm=k.algorithm, fingerprint=k.fingerprint,
                  fingerprint_pretty=P.format_fingerprint(k.fingerprint), public_key_bytes=len(k.public_key),
                  status=k.status, created_at=k.created_at)  # private key material is never exposed


def _public(db: Session, user_id: int) -> PublicKeyOut:
    try:
        kem, sig = key_svc.get_active_key(db, user_id, "KEM"), key_svc.get_active_key(db, user_id, "SIG")
    except LookupError:
        raise HTTPException(404, "User has no active keys.")
    b = lambda x: base64.b64encode(x).decode()
    return PublicKeyOut(kem_algorithm=kem.algorithm, kem_fingerprint=kem.fingerprint, kem_public_key=b(kem.public_key),
                        signature_algorithm=sig.algorithm, signature_fingerprint=sig.fingerprint,
                        signature_public_key=b(sig.public_key))


@users_router.get("")
def list_users(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Recipient directory (id, username, public-key fingerprints only)."""
    rows = db.scalars(select(User).where(User.id != user.id).order_by(User.username)).all()
    out = []
    for u in rows:
        fps = {k.kind: k.fingerprint for k in u.keys if k.status == "active"}
        out.append({"id": u.id, "username": u.username, "kem_fingerprint": fps.get("KEM"), "signature_fingerprint": fps.get("SIG")})
    return out


@users_router.get("/{user_id}")
def get_user(user_id: int, _: User = Depends(current_user), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "User not found.")
    return {**UserPublic.model_validate(u).model_dump(), "public_keys": _public(db, u.id)}


@keys_router.get("", response_model=list[KeyOut])
def my_keys(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [_key_out(k) for k in db.scalars(select(Key).where(Key.user_id == user.id).order_by(Key.kind, Key.id))]


@keys_router.get("/public", response_model=PublicKeyOut)
def my_public_keys(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _public(db, user.id)
