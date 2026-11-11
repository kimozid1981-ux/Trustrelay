"""Request dependencies: authentication, role checks (RBAC), rate limiting, language."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Coroutine
from typing import Any

import jwt
from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import ApiError
from app.core.audit import client_ip, hash_ip
from app.core.config import get_settings
from app.core.ratelimit import get_rate_limiter
from app.core.security import decode_access_token
from app.db.models import AuthSession, User
from app.db.session import get_db

_bearer = HTTPBearer(auto_error=False)

STAFF_ROLES = {"support", "admin", "security"}


class Principal:
    def __init__(self, user: User, claims: dict[str, Any]):
        self.user = user
        self.claims = claims
        self.session_id = uuid.UUID(claims["sid"])
        self.mfa = "otp" in claims.get("amr", [])

    @property
    def id(self) -> uuid.UUID:
        return self.user.id

    @property
    def role(self) -> str:
        return self.user.role


async def current_principal(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer":
        raise ApiError(401, "not_authenticated", "Authentication required")
    try:
        claims = decode_access_token(creds.credentials)
    except jwt.PyJWTError as exc:
        raise ApiError(401, "invalid_token", "Invalid or expired token") from exc
    user = await db.get(User, uuid.UUID(claims["sub"]))
    if user is None or not user.is_active:
        raise ApiError(401, "invalid_token", "Invalid or expired token")
    session = await db.get(AuthSession, uuid.UUID(claims["sid"]))
    if session is None or session.revoked_at is not None:
        raise ApiError(401, "session_revoked", "Session has ended")
    # A role change takes effect immediately: the token's role must still match the stored role.
    if claims.get("role") != user.role:
        raise ApiError(401, "role_changed", "Please sign in again")
    request.state.user_id = user.id
    return Principal(user, claims)


def require_roles(*roles: str, mfa: bool | None = None) -> Callable[..., Coroutine[Any, Any, Principal]]:
    async def dep(p: Principal = Depends(current_principal)) -> Principal:
        if p.role not in roles:
            raise ApiError(403, "forbidden", "You do not have access to this resource")
        need_mfa = get_settings().require_admin_mfa if mfa is None else mfa
        if need_mfa and p.role in STAFF_ROLES and not p.mfa:
            raise ApiError(403, "mfa_required", "Staff access requires two-factor authentication")
        return p

    return dep


def rate_limit(bucket: str, per_minute: Callable[[], int]) -> Callable[..., Coroutine[Any, Any, None]]:
    async def dep(request: Request) -> None:
        user_id = getattr(request.state, "user_id", None)
        key = f"{bucket}:{user_id or hash_ip(client_ip(request))}"
        allowed, retry = await get_rate_limiter().hit(key, per_minute(), 60)
        if not allowed:
            request.state.rate_limited = True
            raise ApiError(429, "rate_limited", "Too many requests, please wait", headers={"Retry-After": str(retry)})

    return dep


def language(
    accept_language: str | None = Header(default=None),
    lang: str | None = None,
) -> str:
    if lang in ("fr", "en"):
        return lang
    if accept_language:
        for part in accept_language.split(","):
            code = part.split(";")[0].strip().lower()[:2]
            if code in ("fr", "en"):
                return code
    return "fr"


async def load_user_by_email(db: AsyncSession, email: str) -> User | None:
    from sqlalchemy import func

    res = await db.execute(select(User).where(func.lower(User.email) == email.lower()))
    return res.scalar_one_or_none()
