"""Application settings.

Every limit that protects the service is expressed here rather than scattered as
magic numbers, so an operator can see the whole safety envelope in one place.
"""

from __future__ import annotations

import functools
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Sentinel value shipped in .env.example. Booting with this outside development is refused.
DEV_PLACEHOLDER_SECRET = "dev-only-insecure-secret-change-me"  # noqa: S105 - a tripwire, not a secret


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    # --- environment -------------------------------------------------------
    app_env: Literal["dev", "test", "prod"] = "dev"
    app_name: str = "SentinelForge"
    api_v1_prefix: str = "/api/v1"

    # --- security ----------------------------------------------------------
    secret_key: str = DEV_PLACEHOLDER_SECRET
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = Field(default=30, ge=1, le=1440)
    refresh_token_ttl_days: int = Field(default=7, ge=1, le=90)
    bcrypt_rounds: int = Field(default=12, ge=10, le=16)

    # Login throttling. The per-IP window is in-process; see `rate_limit.py` for why
    # that is sufficient here and what changes under multi-worker deployment.
    login_rate_limit_attempts: int = Field(default=10, ge=1)
    login_rate_limit_window_seconds: int = Field(default=300, ge=1)
    account_lockout_threshold: int = Field(default=5, ge=1)
    account_lockout_minutes: int = Field(default=15, ge=1)

    # --- database ----------------------------------------------------------
    database_url: str = (
        "postgresql+psycopg://sentinelforge:sentinelforge@localhost:5432/sentinelforge"
    )
    database_echo: bool = False

    # --- upload / import limits -------------------------------------------
    max_upload_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)
    max_yaml_bytes: int = Field(default=512 * 1024, ge=1024)
    max_yaml_depth: int = Field(default=30, ge=1)
    max_zip_entries: int = Field(default=500, ge=1)
    max_zip_total_uncompressed_bytes: int = Field(default=50 * 1024 * 1024, ge=1024)
    max_zip_compression_ratio: int = Field(default=100, ge=2)
    max_dataset_events: int = Field(default=100_000, ge=1)

    # --- detection engine bounds ------------------------------------------
    detection_max_events: int = Field(default=100_000, ge=1)
    detection_time_budget_seconds: float = Field(default=60.0, gt=0)
    max_regex_length: int = Field(default=1000, ge=10)

    # --- frontend ----------------------------------------------------------
    cors_origins: list[str] = ["http://localhost:3000"]

    @property
    def is_dev(self) -> bool:
        return self.app_env == "dev"

    @property
    def is_test(self) -> bool:
        return self.app_env == "test"

    @model_validator(mode="after")
    def _reject_placeholder_secret(self) -> Settings:
        """Fail fast rather than silently running production on a public secret."""
        if self.app_env == "prod" and self.secret_key == DEV_PLACEHOLDER_SECRET:
            raise ValueError(
                "SECRET_KEY is still the .env.example placeholder. Generate one with:\n"
                '  python -c "import secrets; print(secrets.token_urlsafe(64))"'
            )
        if self.app_env == "prod" and len(self.secret_key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters in production.")
        return self


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
