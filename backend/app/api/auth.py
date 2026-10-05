from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, current_user, get_token_payload
from app.core import security as sec
from app.core.db import get_db
from app.models import RevokedToken, User
from app.schemas import LoginIn, RegisterIn, TokenOut, UserOut
from app.services import audit, keys

router = APIRouter(prefix="/auth", tags=["auth"])

# Simple in-memory brute-force throttle: 8 failures / 5 min per (ip, username)
_FAILS: dict[str, deque] = defaultdict(deque)
WINDOW, MAX_FAILS = 300, 8


def _throttle_key(request: Request, ident: str) -> str:
    return f"{client_ip(request)}|{ident.lower()}"


def _check_throttle(k: str) -> None:
    q = _FAILS[k]
    while q and q[0] < time.time() - WINDOW:
        q.popleft()
    if len(q) >= MAX_FAILS:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts. Try again in a few minutes.")


def reset_throttle() -> None:
    _FAILS.clear()


@router.post("/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    problem = sec.validate_password_strength(body.password)
    if problem:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, problem)
    exists = db.scalars(select(User).where(or_(User.username.ilike(body.username), User.email.ilike(body.email)))).first()
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "Username or email is already registered.")
    user = User(username=body.username, email=body.email.lower(), password_hash=sec.hash_password(body.password))
    db.add(user)
    db.commit()
    keys.generate_user_keys(db, user.id)
    ip = client_ip(request)
    audit.log(db, "USER_REGISTERED", user.id, None, ip)
    audit.log(db, "KEYS_GENERATED", user.id, "ML-KEM-768 + ML-DSA-65", ip)
    token, _, exp = sec.create_token(user.id)
    return TokenOut(access_token=token, expires_at=exp, user=UserOut.model_validate(user))


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    k = _throttle_key(request, body.username)
    _check_throttle(k)
    user = db.scalars(select(User).where(or_(User.username.ilike(body.username), User.email.ilike(body.username)))).first()
    ok = sec.verify_password(body.password, user.password_hash if user else None)
    if not (user and ok):
        _FAILS[k].append(time.time())
        audit.log(db, "LOGIN_FAILED", user.id if user else None, None, client_ip(request))
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials.")
    if sec.needs_rehash(user.password_hash):
        user.password_hash = sec.hash_password(body.password)
        db.commit()
    _FAILS.pop(k, None)
    audit.log(db, "LOGIN_SUCCESS", user.id, None, client_ip(request))
    token, _, exp = sec.create_token(user.id)
    return TokenOut(access_token=token, expires_at=exp, user=UserOut.model_validate(user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, payload: dict = Depends(get_token_payload), user: User = Depends(current_user),
           db: Session = Depends(get_db)):
    db.merge(RevokedToken(jti=payload["jti"], expires_at=datetime.fromtimestamp(payload["exp"], timezone.utc)))
    db.commit()
    audit.log(db, "LOGOUT", user.id, None, client_ip(request))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user
