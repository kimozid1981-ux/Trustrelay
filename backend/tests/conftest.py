"""Test fixtures. Tests run against a real PostgreSQL database migrated with Alembic (TR_TEST_DATABASE_URL)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pyotp
import pytest

TEST_DB = os.environ.get("TR_TEST_DATABASE_URL", "postgresql+asyncpg://trustrelay:trustrelay@localhost:5432/trustrelay_test")
os.environ.update(
    {
        "TR_ENVIRONMENT": "test",
        "TR_DATABASE_URL": TEST_DB,
        "TR_ANALYSIS_INLINE": "true",
        "TR_THREAT_INTEL_MOCK": "true",
        "TR_AI_PROVIDER": "null",
        "TR_STORAGE_LOCAL_PATH": str(Path(__file__).parent / ".." / "var" / "test-uploads"),
        "TR_RATE_LIMIT_AUTH_PER_MINUTE": "1000",
        "TR_RATE_LIMIT_ANALYSES_PER_MINUTE": "1000",
    }
)

import httpx  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.core.ratelimit import get_rate_limiter  # noqa: E402
from app.db.session import dispose_engine, get_sessionmaker  # noqa: E402
from app.main import app  # noqa: E402
from app.services import analysis_service  # noqa: E402

BACKEND = Path(__file__).resolve().parent.parent
TABLES = [
    "findings",
    "shared_warnings",
    "support_access_grants",
    "analyses",
    "uploads",
    "usage_counters",
    "family_invites",
    "family_members",
    "family_groups",
    "support_tickets",
    "auth_sessions",
    "subscriptions",
    "user_preferences",
    "users",
    "feature_flags",
    "system_config",
    "threat_source_health",
    "ai_usage",
    "error_events",
]


@pytest.fixture(scope="session", autouse=True)
def migrated_db() -> None:
    env = {**os.environ}
    subprocess.run([sys.executable, "-m", "alembic", "downgrade", "base"], cwd=BACKEND, env=env, check=True, capture_output=True)
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=env, check=True, capture_output=True)


@pytest.fixture(autouse=True)
async def clean_db(migrated_db: None):  # type: ignore[no-untyped-def]
    analysis_service.set_engine_deps(None)
    import shutil

    shutil.rmtree(os.environ["TR_STORAGE_LOCAL_PATH"], ignore_errors=True)
    limiter = get_rate_limiter()
    if hasattr(limiter, "reset"):
        limiter.reset()
    async with get_sessionmaker()() as db:
        await db.execute(text(f"TRUNCATE {', '.join(TABLES)} CASCADE"))
        await db.execute(text("SET LOCAL trustrelay.audit_purge = 'on'"))
        await db.execute(text("DELETE FROM audit_logs"))
        await db.commit()
    yield
    await dispose_engine()


@pytest.fixture
async def client():  # type: ignore[no-untyped-def]
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


PASSWORD = "Correct-Horse-42!"


async def register(client: httpx.AsyncClient, email: str, *, client_kind: str = "mobile", locale: str = "fr") -> dict:
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "accept_terms": True,
            "client": client_kind,
            "locale": locale,
            "display_name": email.split("@")[0],
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


def auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def make_staff(client: httpx.AsyncClient, email: str, role: str = "admin") -> dict:
    """Register, promote in the DB, enable TOTP and return MFA-backed tokens."""
    await register(client, email)
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE users SET role = :r WHERE email = :e"), {"r": role, "e": email})
        await db.commit()
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD, "client": "mobile"})
    tokens = r.json()
    setup = (await client.post("/api/v1/auth/mfa/setup", headers=auth(tokens))).json()
    code = pyotp.TOTP(setup["secret"]).now()
    r = await client.post("/api/v1/auth/mfa/enable", json={"code": code}, headers=auth(tokens))
    assert r.status_code == 200, r.text
    return r.json() | {"totp_secret": setup["secret"]}
