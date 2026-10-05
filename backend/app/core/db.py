from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal = None


def get_engine():
    global _engine, _SessionLocal
    if _engine is None:
        url = get_settings().database_url
        kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
        _engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):
            @event.listens_for(_engine, "connect")
            def _fk(dbapi_conn, _):
                dbapi_conn.execute("PRAGMA foreign_keys=ON")
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def init_db() -> None:
    from app import models  # noqa: F401  (register tables)

    Base.metadata.create_all(get_engine())


def get_db() -> Iterator[Session]:
    get_engine()
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()


def reset_engine() -> None:
    """Used by tests to point at a fresh database."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = _SessionLocal = None
