"""Authentication: registration, login (+TOTP for staff), refresh-token rotation, logout, MFA, password change.

Web clients receive the refresh token in an httpOnly, SameSite=Strict cookie scoped to /api/v1/auth;
mobile clients receive it in the body and keep it in the OS keystore.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

import pyotp
from fastapi import APIRouter, Cookie, Depends, Header, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import STAFF_ROLES, Principal, current_principal, load_user_by_email, rate_limit
from app.api.errors import ApiError
from app.core.audit import audit
from app.core.config import get_settings
from app.core.crypto import get_keyring
from app.core.security import (
    create_access_token,
    hash_password,
    hash_refresh_token,
    new_refresh_token,
    new_totp_secret,
    password_problems,
    totp_uri,
    verify_password,
)
from app.db.models import AuthSession, Subscription, User, UserPreferences
from app.db.session import get_db

router = APIRouter(prefix="/auth", tags=["auth"])
REFRESH_COOKIE = "tr_refresh"

_auth_rl = rate_limit("auth", lambda: get_settings().rate_limit_auth_per_minute)


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    display_name: str | None = Field(default=None, max_length=80)
    locale: Literal["fr", "en"] = "fr"
    accept_terms: bool
    client: Literal["web", "mobile"] = "web"


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    totp_code: str | None = Field(default=None, max_length=10)
    client: Literal["web", "mobile"] = "web"


class RefreshIn(BaseModel):
    refresh_token: str | None = Field(default=None, max_length=200)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str | None = None
    mfa: bool
    role: str


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


async def _issue(db: AsyncSession, response: Response, user: User, *, client: str, mfa: bool,
                 user_agent: str | None, chain_id: uuid.UUID | None = None) -> TokenOut:
    s = get_settings()
    token, token_hash = new_refresh_token()
    session = AuthSession(
        user_id=user.id,
        chain_id=chain_id or uuid.uuid4(),
        refresh_token_hash=token_hash,
        mfa=mfa,
        client=client,
        user_agent=(user_agent or "")[:200] or None,
        expires_at=datetime.now(UTC) + timedelta(days=s.refresh_token_ttl_days),
    )
    db.add(session)
    await db.flush()
    access = create_access_token(user_id=user.id, role=user.role, session_id=session.id, mfa=mfa)
    out = TokenOut(access_token=access, expires_in=s.access_token_ttl_seconds, mfa=mfa, role=user.role)
    if client == "web":
        response.set_cookie(
            REFRESH_COOKIE, token, httponly=True, secure=s.web_refresh_cookie_secure, samesite="strict",
            path=f"{s.api_prefix}/auth", max_age=s.refresh_token_ttl_days * 86400,
        )
    else:
        out.refresh_token = token
    return out


@router.post("/register", response_model=TokenOut, status_code=201, dependencies=[Depends(_auth_rl)])
async def register(body: RegisterIn, request: Request, response: Response, db: AsyncSession = Depends(get_db),
                   user_agent: str | None = Header(default=None)) -> TokenOut:
    if not body.accept_terms:
        raise ApiError(422, "terms_not_accepted", "You must accept the terms of service")
    problems = password_problems(body.password, body.email)
    if problems:
        raise ApiError(422, "weak_password", "Password " + "; ".join(problems), extra={"problems": problems})
    if await load_user_by_email(db, body.email):
        # Do not reveal whether the account exists beyond what the UI needs; generic message.
        raise ApiError(409, "registration_failed", "Unable to register with these details")
    user = User(email=body.email.lower(), password_hash=hash_password(body.password),
                display_name=body.display_name, locale=body.locale, role="user")
    user.preferences = UserPreferences()
    user.subscription = Subscription(plan="free")
    db.add(user)
    await db.flush()
    out = await _issue(db, response, user, client=body.client, mfa=False, user_agent=user_agent)
    await audit(db, category="auth", action="user.register", actor_id=user.id, actor_role="user",
                target_type="user", target_id=user.id, request=request)
    await db.commit()
    return out


@router.post("/login", response_model=TokenOut, dependencies=[Depends(_auth_rl)])
async def login(body: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db),
                user_agent: str | None = Header(default=None)) -> TokenOut:
    s = get_settings()
    user = await load_user_by_email(db, body.email)
    now = datetime.now(UTC)
    if user and user.locked_until and user.locked_until > now:
        await audit(db, category="security", action="login.locked", actor_id=user.id, outcome="denied", request=request)
        await db.commit()
        raise ApiError(429, "account_locked", "Too many failed attempts. Try again later.")
    ok = verify_password(body.password, user.password_hash if user else None)
    if not user or not ok or not user.is_active:
        if user:
            user.failed_logins += 1
            if user.failed_logins >= s.login_max_failures:
                user.locked_until = now + timedelta(minutes=s.login_lockout_minutes)
                user.failed_logins = 0
        await audit(db, category="security", action="login.failed", actor_id=user.id if user else None,
                    outcome="denied", request=request)
        await db.commit()
        raise ApiError(401, "invalid_credentials", "Email or password is incorrect")

    mfa = False
    if user.totp_enabled:
        if not body.totp_code:
            raise ApiError(401, "mfa_code_required", "Enter the code from your authenticator app")
        if not _check_totp(user, body.totp_code):
            user.failed_logins += 1
            await audit(db, category="security", action="login.mfa_failed", actor_id=user.id, outcome="denied", request=request)
            await db.commit()
            raise ApiError(401, "invalid_mfa_code", "The code is incorrect")
        mfa = True
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    out = await _issue(db, response, user, client=body.client, mfa=mfa, user_agent=user_agent)
    await audit(db, category="auth", action="login.success", actor_id=user.id, actor_role=user.role,
                request=request, details={"mfa": mfa, "client": body.client})
    await db.commit()
    return out


def _check_totp(user: User, code: str) -> bool:
    """Verify a TOTP code and reject replay of an already-used time step."""
    if not user.totp_secret_enc:
        return False
    secret = get_keyring().decrypt_text(user.totp_secret_enc, associated_data=str(user.id).encode())
    totp = pyotp.TOTP(secret)
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    now = datetime.now(UTC)
    for offset in (-1, 0, 1):
        at = now + timedelta(seconds=30 * offset)
        if totp.verify(code, for_time=at, valid_window=0):
            step = int(at.timestamp()) // 30
            if user.totp_last_step is not None and step <= user.totp_last_step:
                return False
            user.totp_last_step = step
            return True
    return False


@router.post("/refresh", response_model=TokenOut, dependencies=[Depends(_auth_rl)])
async def refresh(request: Request, response: Response, body: RefreshIn | None = None,
                  db: AsyncSession = Depends(get_db),
                  tr_refresh: str | None = Cookie(default=None),
                  x_requested_with: str | None = Header(default=None),
                  user_agent: str | None = Header(default=None)) -> TokenOut:
    token = body.refresh_token if body and body.refresh_token else None
    client = "mobile"
    if token is None:
        # Cookie flow (web): require a custom header as CSRF defence in depth on top of SameSite=Strict.
        if tr_refresh is None or x_requested_with != "trustrelay":
            raise ApiError(401, "invalid_refresh_token", "Session expired, please sign in again")
        token, client = tr_refresh, "web"
    res = await db.execute(select(AuthSession).where(AuthSession.refresh_token_hash == hash_refresh_token(token)))
    session = res.scalar_one_or_none()
    now = datetime.now(UTC)
    if session is None:
        raise ApiError(401, "invalid_refresh_token", "Session expired, please sign in again")
    if session.revoked_at is not None or session.rotated_at is not None:
        # Reuse of a rotated/revoked token: assume theft and revoke the whole chain.
        await db.execute(update(AuthSession).where(AuthSession.chain_id == session.chain_id, AuthSession.revoked_at.is_(None))
                         .values(revoked_at=now))
        await audit(db, category="security", action="refresh.reuse_detected", actor_id=session.user_id,
                    outcome="denied", request=request)
        await db.commit()
        raise ApiError(401, "invalid_refresh_token", "Session expired, please sign in again")
    if session.expires_at <= now:
        raise ApiError(401, "invalid_refresh_token", "Session expired, please sign in again")
    user = await db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise ApiError(401, "invalid_refresh_token", "Session expired, please sign in again")
    session.rotated_at = now
    session.revoked_at = now
    out = await _issue(db, response, user, client=client, mfa=session.mfa, user_agent=user_agent, chain_id=session.chain_id)
    await db.commit()
    return out


@router.post("/logout", status_code=204)
async def logout(request: Request, response: Response, p: Principal = Depends(current_principal),
                 db: AsyncSession = Depends(get_db)) -> Response:
    session = await db.get(AuthSession, p.session_id)
    if session:
        await db.execute(update(AuthSession).where(AuthSession.chain_id == session.chain_id, AuthSession.revoked_at.is_(None))
                         .values(revoked_at=datetime.now(UTC)))
    await audit(db, category="auth", action="logout", actor_id=p.id, actor_role=p.role, request=request)
    await db.commit()
    response = Response(status_code=204)
    response.delete_cookie(REFRESH_COOKIE, path=f"{get_settings().api_prefix}/auth")
    return response


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


@router.post("/mfa/setup", response_model=MfaSetupOut)
async def mfa_setup(request: Request, p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> MfaSetupOut:
    if p.user.totp_enabled:
        raise ApiError(409, "mfa_already_enabled", "Two-factor authentication is already enabled")
    secret = new_totp_secret()
    p.user.totp_secret_enc = get_keyring().encrypt_text(secret, associated_data=str(p.id).encode())
    await audit(db, category="auth", action="mfa.setup_started", actor_id=p.id, actor_role=p.role, request=request)
    await db.commit()
    return MfaSetupOut(secret=secret, otpauth_uri=totp_uri(secret, p.user.email))


@router.post("/mfa/enable", response_model=TokenOut)
async def mfa_enable(body: CodeIn, request: Request, response: Response, p: Principal = Depends(current_principal),
                     db: AsyncSession = Depends(get_db), user_agent: str | None = Header(default=None)) -> TokenOut:
    if p.user.totp_enabled or not p.user.totp_secret_enc:
        raise ApiError(409, "mfa_not_pending", "Start two-factor setup first")
    if not _check_totp(p.user, body.code):
        raise ApiError(422, "invalid_mfa_code", "The code is incorrect")
    p.user.totp_enabled = True
    current = await db.get(AuthSession, p.session_id)
    if current:
        current.revoked_at = datetime.now(UTC)
    out = await _issue(db, response, p.user, client=current.client if current else "web", mfa=True, user_agent=user_agent)
    await audit(db, category="auth", action="mfa.enabled", actor_id=p.id, actor_role=p.role, request=request)
    await db.commit()
    return out


@router.post("/mfa/disable", status_code=204)
async def mfa_disable(body: CodeIn, request: Request, p: Principal = Depends(current_principal),
                      db: AsyncSession = Depends(get_db)) -> Response:
    if p.role in STAFF_ROLES and get_settings().require_admin_mfa:
        raise ApiError(403, "mfa_mandatory", "Two-factor authentication is mandatory for staff accounts")
    if not p.user.totp_enabled or not _check_totp(p.user, body.code):
        raise ApiError(422, "invalid_mfa_code", "The code is incorrect")
    p.user.totp_enabled = False
    p.user.totp_secret_enc = None
    p.user.totp_last_step = None
    await audit(db, category="auth", action="mfa.disabled", actor_id=p.id, actor_role=p.role, request=request)
    await db.commit()
    return Response(status_code=204)


@router.post("/password", status_code=204, dependencies=[Depends(_auth_rl)])
async def change_password(body: PasswordChangeIn, request: Request, p: Principal = Depends(current_principal),
                          db: AsyncSession = Depends(get_db)) -> Response:
    if not verify_password(body.current_password, p.user.password_hash):
        await audit(db, category="security", action="password.change_failed", actor_id=p.id, outcome="denied", request=request)
        await db.commit()
        raise ApiError(401, "invalid_credentials", "Current password is incorrect")
    problems = password_problems(body.new_password, p.user.email)
    if problems:
        raise ApiError(422, "weak_password", "Password " + "; ".join(problems), extra={"problems": problems})
    p.user.password_hash = hash_password(body.new_password)
    # Sign out every other session.
    await db.execute(update(AuthSession).where(AuthSession.user_id == p.id, AuthSession.id != p.session_id,
                                               AuthSession.revoked_at.is_(None)).values(revoked_at=datetime.now(UTC)))
    await audit(db, category="auth", action="password.changed", actor_id=p.id, actor_role=p.role, request=request)
    await db.commit()
    return Response(status_code=204)
