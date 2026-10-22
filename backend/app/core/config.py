"""SentinelX Platform Configuration.

Loads environment variables, enforces fail-closed production rules (ADR 0002),
and provides unified settings across backend services.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings with validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "SentinelX"
    APP_ENV: Literal["development", "testing", "production"] = "development"
    DEBUG: bool = False

    # Dual-Database Configuration (ADR 0002)
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinelx_dev.db"
    TEST_DATABASE_URL: str | None = None

    # Security & Authentication (M1)
    JWT_SECRET: str = "dev_jwt_secret_key_change_in_prod_12345"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480
    INGEST_API_KEY: str = "sen_ingest_demo_key"

    # Rate Limiting & Protection
    RATE_LIMIT_LOGIN_ATTEMPTS: int = 5
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = 900
    MAX_REQUEST_BODY_BYTES: int = 1_048_576  # 1 MB

    # Notifications & External Sinks
    NOTIFICATION_WEBHOOK_URL: str | None = None
    WEBHOOK_TIMEOUT_SECONDS: float = 5.0

    # CORS
    CORS_ORIGINS: list[str] | str = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            v_stripped = v.strip()
            if v_stripped.startswith("[") and v_stripped.endswith("]"):
                try:
                    return json.loads(v_stripped)
                except Exception:
                    pass
            return [i.strip() for i in v_stripped.split(",") if i.strip()]
        elif isinstance(v, list | tuple):
            return list(v)
        return []


    @model_validator(mode="after")
    def validate_production_invariants(self) -> Settings:
        """Enforces fail-closed rules when operating in production mode (ADR 0002)."""
        if self.APP_ENV == "production":
            if "sqlite" in self.DATABASE_URL.lower():
                raise RuntimeError(
                    "Production environment fail-closed: DATABASE_URL must not use SQLite. "
                    "Configure PostgreSQL 16 (postgresql+asyncpg://...)."
                )
            if (
                self.JWT_SECRET == "dev_jwt_secret_key_change_in_prod_12345"
                or len(self.JWT_SECRET) < 32
            ):
                raise RuntimeError(
                    "Production environment fail-closed: JWT_SECRET must be set to a "
                    "secure string of at least 32 characters in production."
                )
        return self


settings = Settings()
