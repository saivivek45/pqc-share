from __future__ import annotations

from datetime import datetime, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import decode_token
from app.models import RevokedToken, User

_bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def get_token_payload(creds: HTTPAuthorizationCredentials | None = Depends(_bearer), db: Session = Depends(get_db)) -> dict:
    unauth = HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated.", headers={"WWW-Authenticate": "Bearer"})
    if creds is None:
        raise unauth
    try:
        payload = decode_token(creds.credentials)
    except jwt.PyJWTError:
        raise unauth
    if db.get(RevokedToken, payload["jti"]):
        raise unauth
    return payload


def current_user(payload: dict = Depends(get_token_payload), db: Session = Depends(get_db)) -> User:
    user = db.get(User, int(payload["sub"]))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated.")
    return user


def purge_revoked(db: Session) -> None:
    now = datetime.now(timezone.utc)
    for r in db.query(RevokedToken).all():
        exp = r.expires_at if r.expires_at.tzinfo else r.expires_at.replace(tzinfo=timezone.utc)
        if exp < now:
            db.delete(r)
    db.commit()
