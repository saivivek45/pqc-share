from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.api import auth, files, meta, users_keys
from app.core import db as dbm
from app.core.config import get_settings
from app.core.security import hash_password
from app.models import User
from app.services import keys

log = logging.getLogger("pqshare")

DEMO_USERS = [("alice", "alice@example.com"), ("bob", "bob@example.com"), ("carol", "carol@example.com")]
DEMO_PASSWORD = "Demo-Passw0rd!"


def seed_demo() -> None:
    gen = dbm.get_db()
    db = next(gen)
    try:
        if db.scalars(select(User)).first():
            return
        for name, email in DEMO_USERS:
            u = User(username=name, email=email, password_hash=hash_password(DEMO_PASSWORD))
            db.add(u)
            db.commit()
            keys.generate_user_keys(db, u.id)
        log.warning("Seeded demo users alice/bob/carol (password: %s). DISABLE in production.", DEMO_PASSWORD)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
    s = get_settings()
    dbm.init_db()
    _ = s.storage_path
    if s.seed_demo:
        seed_demo()
    yield


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title="PQC-Share API", version="1.0.0",
                  description="Post-quantum secure file sharing: ML-KEM-768 + AES-256-GCM + ML-DSA-65. Academic project.",
                  lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=s.origins, allow_credentials=False,
                       allow_methods=["*"], allow_headers=["*"], expose_headers=["Content-Disposition"])

    @app.middleware("http")
    async def sec_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception):
        log.exception("Unhandled error", exc_info=exc)  # details stay in server logs only
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})

    for r in (auth.router, users_keys.users_router, users_keys.keys_router, files.router,
              meta.dashboard_router, meta.security_router, meta.bench_router):
        app.include_router(r)

    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok"}

    return app


app = create_app()
