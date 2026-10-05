import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Fresh app + isolated SQLite DB + storage dir per test."""
    monkeypatch.setenv("PQSHARE_STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("PQSHARE_DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    monkeypatch.setenv("PQSHARE_MAX_UPLOAD_MB", "2")
    monkeypatch.setenv("PQSHARE_SEED_DEMO", "false")
    monkeypatch.setenv("PQSHARE_JWT_SECRET", os.urandom(32).hex())
    monkeypatch.setenv("PQSHARE_MASTER_KEY", os.urandom(32).hex())
    from app.core import config, db
    from app.api import auth as auth_api

    config.get_settings.cache_clear()
    db.reset_engine()
    auth_api.reset_throttle()
    from fastapi.testclient import TestClient
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c
    db.reset_engine()
    config.get_settings.cache_clear()


PASSWORD = "Str0ng-Passw0rd!"


def register(client, name):
    r = client.post("/auth/register", json={"username": name, "email": f"{name}@example.com", "password": PASSWORD})
    assert r.status_code == 201, r.text
    d = r.json()
    return d["user"]["id"], {"Authorization": f"Bearer {d['access_token']}"}
