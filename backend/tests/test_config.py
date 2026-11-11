from __future__ import annotations

import pytest

from app.core.config import Settings


def test_cors_origins_accepts_comma_separated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # .env.example documents a comma-separated list; it must parse without JSON.
    monkeypatch.setenv("TR_CORS_ORIGINS", "http://localhost:3000, https://app.example.test")
    assert Settings().cors_origins == ["http://localhost:3000", "https://app.example.test"]


def test_production_refuses_development_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TR_ENVIRONMENT", "production")
    with pytest.raises(Exception):  # noqa: B017 - any refusal is acceptable, starting is not
        Settings().validate_for_environment()
