"""Application configuration.

All configuration arrives from the environment (or a ``.env`` file) with the
``ACIP_`` prefix. Nothing is hard-coded at a call site: secrets, paths, limits
and provider selection are all resolved here so they can be changed without
touching code, and so tests can construct isolated settings.
"""

from __future__ import annotations

import functools
import secrets
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from acip.errors import ConfigurationError

Environment = Literal["dev", "test", "prod"]

MIN_SECRET_LENGTH = 32


class Settings(BaseSettings):
    """Resolved application settings."""

    model_config = SettingsConfigDict(
        env_prefix="ACIP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Environment = "dev"
    debug: bool = False

    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"

    # --- Security -----------------------------------------------------------
    secret_key: SecretStr = SecretStr("")
    access_token_ttl_minutes: int = Field(default=60, ge=1, le=24 * 60)
    jwt_algorithm: Literal["HS256"] = "HS256"

    # --- Persistence --------------------------------------------------------
    database_url: str = "sqlite+aiosqlite:///./data/acip.db"
    db_echo: bool = False

    # --- Artifact intake ----------------------------------------------------
    artifact_dir: Path = Path("./data/artifacts")
    max_artifact_bytes: int = Field(default=25 * 1024 * 1024, ge=1024)

    # --- Investigation budgets (spec s29: bounded execution) ----------------
    max_investigation_seconds: int = Field(default=300, ge=5)
    max_tasks_per_investigation: int = Field(default=25, ge=1)

    # --- Detection thresholds (deterministic, so they must be tunable) ------
    bruteforce_min_failures: int = Field(default=5, ge=2)
    bruteforce_window_seconds: int = Field(default=300, ge=1)

    # --- API ----------------------------------------------------------------
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    # --- Dev bootstrap (ignored in prod) ------------------------------------
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: SecretStr = SecretStr("changeme-dev-only")

    @field_validator("log_level")
    @classmethod
    def _upper_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"invalid log level: {value}")
        return level

    @model_validator(mode="after")
    def _validate_secret(self) -> Settings:
        """Require a real secret in production; generate an ephemeral one otherwise.

        A hard-coded fallback secret that silently reaches production is a real
        vulnerability, so prod fails closed. Dev/test get a per-process random
        key: tokens do not survive a restart, which is the correct trade-off
        versus shipping a predictable default.
        """
        raw = self.secret_key.get_secret_value()
        if self.environment == "prod":
            if len(raw) < MIN_SECRET_LENGTH:
                raise ConfigurationError(
                    "ACIP_SECRET_KEY must be set to at least "
                    f"{MIN_SECRET_LENGTH} characters when ACIP_ENVIRONMENT=prod"
                )
        elif not raw:
            object.__setattr__(self, "secret_key", SecretStr(secrets.token_urlsafe(48)))
        return self

    @property
    def is_prod(self) -> bool:
        return self.environment == "prod"

    def ensure_directories(self) -> None:
        """Create runtime directories. Called once at startup."""
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        if self.database_url.startswith("sqlite"):
            db_path = self.database_url.split("///", 1)[-1]
            if db_path and db_path != ":memory:":
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
