"""Application settings loaded from environment variables (12-factor).

No secret has a usable default outside the `development`/`test` environments: `validate_for_environment`
refuses to start staging or production with placeholder keys.
"""

from __future__ import annotations

import base64
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]

_DEV_JWT_SECRET = "dev-only-insecure-jwt-secret-change-me-0123456789"  # noqa: S105 - dev placeholder
# 32 zero bytes, base64. Only accepted in development/test.
_DEV_ENCRYPTION_KEY = base64.b64encode(b"\x00" * 32).decode()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TR_", env_file=".env", extra="ignore")

    environment: Environment = "development"
    app_name: str = "TrustRelay"
    api_prefix: str = "/api/v1"
    log_level: str = "INFO"

    database_url: str = "postgresql+asyncpg://trustrelay:trustrelay@localhost:5432/trustrelay"
    redis_url: str | None = None  # None -> in-memory rate limiter and inline jobs

    # --- Auth ---
    jwt_secret: str = _DEV_JWT_SECRET
    jwt_issuer: str = "https://auth.trustrelay.local"
    jwt_audience: str = "trustrelay-api"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_days: int = 30
    require_admin_mfa: bool = True
    login_max_failures: int = 5
    login_lockout_minutes: int = 15

    # --- Encryption at rest (application layer) ---
    # Comma-separated "keyid:base64key" pairs. First one encrypts; all decrypt (rotation).
    encryption_keys: str = f"dev1:{_DEV_ENCRYPTION_KEY}"

    # --- CORS / web ---
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    web_refresh_cookie_secure: bool = False

    # --- Analysis ---
    analysis_inline: bool = True  # run jobs in-process (dev/test) instead of the arq worker
    active_url_probing: bool = False  # allow SSRF-guarded HEAD/GET + TLS handshake to submitted hosts
    probe_timeout_seconds: float = 4.0
    probe_max_redirects: int = 5
    max_text_chars: int = 20_000
    max_upload_bytes: int = 8 * 1024 * 1024
    max_image_pixels: int = 40_000_000

    # --- Threat intelligence (all optional) ---
    google_safe_browsing_api_key: str | None = None
    urlhaus_auth_key: str | None = None
    rdap_enabled: bool = False
    threat_intel_mock: bool = False  # deterministic mock provider for dev/tests

    # --- AI provider ---
    ai_provider: Literal["null", "mock", "anthropic"] = "null"
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-opus-5-5"
    anthropic_effort: Literal["low", "medium", "high"] = "low"
    ai_timeout_seconds: float = 20.0
    ai_monthly_budget_eur: float = 50.0

    # --- Storage ---
    storage_backend: Literal["local", "s3"] = "local"
    storage_local_path: str = "./var/uploads"
    s3_endpoint_url: str | None = None
    s3_bucket: str | None = None
    s3_region: str | None = None

    # --- Plans / quotas ---
    free_monthly_checks: int = 30
    plus_monthly_checks: int = 300

    # --- Rate limits (requests per window) ---
    rate_limit_auth_per_minute: int = 10
    rate_limit_analyses_per_minute: int = 20

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @property
    def is_dev_like(self) -> bool:
        return self.environment in ("development", "test")

    def validate_for_environment(self) -> None:
        if self.is_dev_like:
            return
        problems = []
        if self.jwt_secret == _DEV_JWT_SECRET or len(self.jwt_secret) < 32:
            problems.append("TR_JWT_SECRET must be set to a random value of at least 32 characters")
        if _DEV_ENCRYPTION_KEY in self.encryption_keys:
            problems.append("TR_ENCRYPTION_KEYS must not contain the development key")
        if self.analysis_inline:
            problems.append("TR_ANALYSIS_INLINE must be false outside development (use the worker)")
        if not self.redis_url:
            problems.append("TR_REDIS_URL is required outside development")
        if not self.web_refresh_cookie_secure:
            problems.append("TR_WEB_REFRESH_COOKIE_SECURE must be true outside development")
        if self.threat_intel_mock or self.ai_provider == "mock":
            problems.append("mock providers are not allowed outside development")
        if problems:
            raise RuntimeError("Unsafe configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()
