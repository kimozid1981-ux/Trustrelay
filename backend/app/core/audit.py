"""Audit logging. Never pass message content, URLs, emails or tokens in `details`."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models import AuditLog

_FORBIDDEN_KEYS = {"password", "token", "email", "text", "content", "url", "iban", "code", "note"}


def hash_ip(ip: str | None) -> str | None:
    """Keyed hash so IPs can be correlated for abuse detection without being stored in clear."""
    if not ip:
        return None
    key = get_settings().jwt_secret.encode()
    return hmac.new(key, ip.encode(), hashlib.sha256).hexdigest()[:32]


def client_ip(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None
    return request.client.host


async def audit(
    db: AsyncSession,
    *,
    category: str,
    action: str,
    actor_id: uuid.UUID | None = None,
    actor_role: str | None = None,
    target_type: str | None = None,
    target_id: str | uuid.UUID | None = None,
    outcome: str = "success",
    request: Request | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    details = dict(details or {})
    for k in list(details):
        if k.lower() in _FORBIDDEN_KEYS:
            details.pop(k)
    db.add(
        AuditLog(
            category=category,
            action=action,
            actor_user_id=actor_id,
            actor_role=actor_role,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            outcome=outcome,
            ip_hash=hash_ip(client_ip(request)),
            request_id=getattr(request.state, "request_id", None) if request else None,
            details=details,
        )
    )
