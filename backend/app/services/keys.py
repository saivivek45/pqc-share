"""Key management: generation, lookup, unwrapping private keys (server-side only)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.crypto import get_kem, get_signer, primitives as P
from app.models import Key


def _master() -> bytes:
    return bytes.fromhex(get_settings().master_key)


def generate_user_keys(db: Session, user_id: int) -> list[Key]:
    """Create one KEM key pair and one *independent* signature key pair."""
    out = []
    for kind, backend in (("KEM", get_kem()), ("SIG", get_signer())):
        pk, sk = backend.keygen()
        fp = P.fingerprint(pk)
        wrapped = P.wrap_private_key(_master(), user_id, kind, fp, sk)
        key = Key(user_id=user_id, kind=kind, algorithm=backend.info.name, public_key=pk,
                  wrapped_private_key=wrapped, fingerprint=fp, status="active")
        db.add(key)
        out.append(key)
    db.commit()
    return out


def get_active_key(db: Session, user_id: int, kind: str) -> Key:
    key = db.scalars(
        select(Key).where(Key.user_id == user_id, Key.kind == kind, Key.status == "active").order_by(Key.id.desc())
    ).first()
    if key is None:
        raise LookupError(f"user {user_id} has no active {kind} key")
    return key


def get_key_by_fingerprint(db: Session, user_id: int, kind: str, fp: str) -> Key | None:
    return db.scalars(select(Key).where(Key.user_id == user_id, Key.kind == kind, Key.fingerprint == fp)).first()


def unwrap(key: Key) -> bytes:
    return P.unwrap_private_key(_master(), key.user_id, key.kind, key.fingerprint, key.wrapped_private_key)
