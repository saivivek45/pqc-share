"""Application settings. Secrets are never hardcoded: they come from the environment
or are generated once with a CSPRNG and persisted (0600-ish) inside the storage dir."""
from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PQSHARE_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./storage/pqshare.db"
    storage_dir: str = "./storage"
    max_upload_mb: int = 100
    token_ttl_minutes: int = 60
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    jwt_secret: str = ""
    master_key: str = ""
    seed_demo: bool = False

    @property
    def storage_path(self) -> Path:
        p = Path(self.storage_dir).resolve()
        (p / "packages").mkdir(parents=True, exist_ok=True)
        return p

    @property
    def packages_path(self) -> Path:
        return self.storage_path / "packages"

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


def _load_or_create_secret(path: Path, nbytes: int) -> str:
    if path.exists():
        return path.read_text().strip()
    value = secrets.token_hex(nbytes)
    path.write_text(value)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover (Windows)
        pass
    return value


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if not s.jwt_secret:
        s.jwt_secret = _load_or_create_secret(s.storage_path / ".jwt_secret", 32)
    if not s.master_key:
        s.master_key = _load_or_create_secret(s.storage_path / ".master_key", 32)
    if len(bytes.fromhex(s.master_key)) != 32:
        raise RuntimeError("PQSHARE_MASTER_KEY must be 64 hex characters (32 bytes)")
    return s
