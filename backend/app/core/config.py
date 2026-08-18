"""Application configuration.

All configuration is sourced from environment variables (12-factor).  Secrets are
never committed to the repository; ``.env.example`` documents the surface.

Two deliberate security decisions live here:

1. ``SECRET_KEY`` has *no* usable default.  In non-development environments the
   application refuses to start without an explicit key rather than silently
   signing tokens with a well-known value.
2. ``AI_PROVIDER`` defaults to ``none``.  SENTINEL-X must be fully functional as a
   detection platform with no LLM credentials configured at all.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# repo_root/backend/app/core/config.py -> repo_root
REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(REPO_ROOT / ".env", BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---------------------------------------------------------------- general
    APP_NAME: str = "SENTINEL-X"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "test", "production"] = "development"
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: str = "INFO"

    # --------------------------------------------------------------- database
    # Default targets the docker-compose Postgres service.  Tests override this
    # with an in-memory/temp-file SQLite URL so the suite runs with no services.
    DATABASE_URL: str = "postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinelx"
    DB_ECHO: bool = False
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # --------------------------------------------------------------- security
    SECRET_KEY: str = ""
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8
    JWT_ALGORITHM: str = "HS256"
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"
    MAX_REQUEST_BYTES: int = 4 * 1024 * 1024  # 4 MiB ingestion cap
    RATE_LIMIT_REQUESTS: int = 300
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    # AI endpoints are expensive and are the highest-value target for abuse, so
    # they get their own (much tighter) budget.
    AI_RATE_LIMIT_REQUESTS: int = 20
    AI_RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Bootstrap analyst account, created by scripts/seed_database.py only.
    BOOTSTRAP_ADMIN_USERNAME: str = "analyst"
    BOOTSTRAP_ADMIN_PASSWORD: str = ""

    # ------------------------------------------------------------- detection
    DETECTION_RULES_DIR: str = str(REPO_ROOT / "detection-rules")
    DATA_DIR: str = str(REPO_ROOT / "data")
    # How far back the detection engine looks for stateful (threshold/sequence)
    # rules when a new batch of events arrives.
    DETECTION_LOOKBACK_SECONDS: int = 3600
    # Two alerts are candidates for the same incident only if they share an
    # entity *and* fall within this window of one another.
    CORRELATION_WINDOW_SECONDS: int = 1800

    # ---------------------------------------------------------------- ai layer
    AI_PROVIDER: Literal["none", "anthropic", "openai"] = "none"
    AI_API_KEY: str = ""
    AI_MODEL: str = "claude-sonnet-4-5"
    AI_BASE_URL: str = ""
    AI_MAX_TOKENS: int = 1500
    AI_TIMEOUT_SECONDS: int = 45
    # Hard cap on how much telemetry is packed into an LLM context window.
    AI_MAX_EVIDENCE_EVENTS: int = 60

    # ------------------------------------------------------------------ demo
    DEMO_MODE: bool = True

    @field_validator("SECRET_KEY")
    @classmethod
    def _strip_key(cls, v: str) -> str:
        return v.strip()

    @model_validator(mode="after")
    def _validate_secrets(self) -> Settings:
        if not self.SECRET_KEY:
            if self.ENVIRONMENT == "production":
                raise ValueError(
                    "SECRET_KEY must be set explicitly when ENVIRONMENT=production. "
                    "Generate one with: python -c 'import secrets;print(secrets.token_urlsafe(48))'"
                )
            # Ephemeral key for dev/test: tokens do not survive a restart, which
            # is the correct behaviour for a key nobody configured.
            object.__setattr__(self, "SECRET_KEY", secrets.token_urlsafe(48))
        if self.AI_PROVIDER != "none" and not self.AI_API_KEY:
            # Not fatal: degrade to 'none' so the platform still boots.  The AI
            # panel will render an explicit "unavailable" state.
            object.__setattr__(self, "AI_PROVIDER", "none")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def ai_enabled(self) -> bool:
        return self.AI_PROVIDER != "none" and bool(self.AI_API_KEY)

    @property
    def rules_path(self) -> Path:
        return Path(self.DETECTION_RULES_DIR)

    @property
    def data_path(self) -> Path:
        return Path(self.DATA_DIR)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
