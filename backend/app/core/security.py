"""Password hashing (Argon2id), access tokens (JWT), refresh tokens (opaque, hashed) and TOTP."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import get_settings

_hasher = PasswordHasher()  # argon2id, library defaults (RFC 9106 low-memory profile)
# A real hash of a random string, used to equalize timing when the account does not exist.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 10


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problems(password: str, email: str | None = None) -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 256:
        problems.append("must be at most 256 characters")
    if email and email.split("@")[0].lower() in password.lower() and len(email.split("@")[0]) >= 3:
        problems.append("must not contain your email name")
    if len(set(password)) < 5:
        problems.append("is too repetitive")
    return problems


def create_access_token(*, user_id: uuid.UUID, role: str, session_id: uuid.UUID, mfa: bool) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": s.jwt_issuer,
        "aud": s.jwt_audience,
        "sub": str(user_id),
        "sid": str(session_id),
        "role": role,
        "amr": ["pwd", "otp"] if mfa else ["pwd"],
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=s.access_token_ttl_seconds)).timestamp()),
        "jti": secrets.token_urlsafe(12),
    }
    return jwt.encode(claims, s.jwt_secret, algorithm="HS256")


def decode_access_token(token: str) -> dict[str, Any]:
    s = get_settings()
    return jwt.decode(
        token,
        s.jwt_secret,
        algorithms=["HS256"],
        audience=s.jwt_audience,
        issuer=s.jwt_issuer,
        options={"require": ["exp", "iat", "sub", "sid", "role"]},
    )


def new_refresh_token() -> tuple[str, str]:
    """Returns (token for the client, sha256 hash for the database)."""
    token = secrets.token_urlsafe(48)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="TrustRelay")


def verify_totp(secret: str, code: str) -> bool:
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)
