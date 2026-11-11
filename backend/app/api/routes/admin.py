"""Administration API. Admins see accounts, aggregates, health and configuration — never customer content.

No endpoint in this module decrypts an `_enc` column (enforced by tests/test_admin.py::test_admin_never_sees_content).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import Principal, require_roles
from app.api.errors import ApiError
from app.core.audit import audit
from app.core.config import get_settings
from app.db.models import (
    AIUsage,
    Analysis,
    AuditLog,
    ErrorEvent,
    FeatureFlag,
    Subscription,
    SupportTicket,
    SystemConfig,
    ThreatSourceHealth,
    User,
)
from app.db.session import get_db

router = APIRouter(prefix="/admin", tags=["admin"])
admin = require_roles("admin")
admin_or_security = require_roles("admin", "security")

DEFAULT_FLAGS = {
    "module.website": (True, "Website / URL analysis module"),
    "module.message": (True, "Message analysis module"),
    "module.advert": (True, "Advertisement analysis module"),
    "module.payment": (True, "Payment request analysis module"),
    "family_protection": (True, "Family groups and shared warnings"),
    "public_link_checker": (False, "Anonymous website checker on the public site (Phase 5)"),
}


@router.get("/stats")
async def stats(p: Principal = Depends(admin_or_security), db: AsyncSession = Depends(get_db),
                days: int = Query(30, ge=1, le=365)) -> dict:
    since = datetime.now(UTC) - timedelta(days=days)
    by_verdict = dict((await db.execute(select(Analysis.verdict, func.count()).where(Analysis.created_at >= since)
                                        .group_by(Analysis.verdict))).all())
    by_kind = dict((await db.execute(select(Analysis.kind, func.count()).where(Analysis.created_at >= since)
                                     .group_by(Analysis.kind))).all())
    by_status = dict((await db.execute(select(Analysis.status, func.count()).where(Analysis.created_at >= since)
                                       .group_by(Analysis.status))).all())
    daily = (await db.execute(text(
        "SELECT date_trunc('day', created_at)::date AS d, count(*) FROM analyses WHERE created_at >= :s GROUP BY 1 ORDER BY 1"
    ), {"s": since})).all()
    users_total = (await db.execute(select(func.count()).select_from(User))).scalar_one()
    active = (await db.execute(select(func.count()).select_from(User).where(User.last_login_at >= since))).scalar_one()
    plans = dict((await db.execute(select(Subscription.plan, func.count()).group_by(Subscription.plan))).all())
    p95 = (await db.execute(text(
        "SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM completed_at - created_at)) "
        "FROM analyses WHERE completed_at IS NOT NULL AND created_at >= :s"), {"s": since})).scalar()
    return {
        "period_days": days,
        "analyses_by_verdict": {k or "pending": v for k, v in by_verdict.items()},
        "analyses_by_kind": by_kind,
        "analyses_by_status": by_status,
        "analyses_per_day": [{"date": d.isoformat(), "count": c} for d, c in daily],
        "users_total": users_total,
        "users_active": active,
        "plans": plans,
        "analysis_p95_seconds": round(float(p95), 2) if p95 is not None else None,
    }


@router.get("/users")
async def list_users(p: Principal = Depends(admin), db: AsyncSession = Depends(get_db),
                     q: str | None = Query(None, max_length=320), limit: int = Query(50, ge=1, le=200),
                     offset: int = Query(0, ge=0)) -> dict:
    stmt = select(User).order_by(User.created_at.desc())
    if q:
        stmt = stmt.where(func.lower(User.email).startswith(q.lower()))
    rows = (await db.execute(stmt.limit(limit).offset(offset))).unique().scalars().all()
    return {"items": [{
        "id": str(u.id), "email": u.email, "display_name": u.display_name, "role": u.role, "is_active": u.is_active,
        "plan": u.subscription.plan if u.subscription else "free", "mfa_enabled": u.totp_enabled,
        "created_at": u.created_at.isoformat(), "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
    } for u in rows]}


class UserPatch(BaseModel):
    is_active: bool | None = None
    role: Literal["user", "support", "admin", "security"] | None = None


@router.patch("/users/{user_id}")
async def update_user(user_id: uuid.UUID, body: UserPatch, request: Request, p: Principal = Depends(admin),
                      db: AsyncSession = Depends(get_db)) -> dict:
    u = await db.get(User, user_id)
    if u is None:
        raise ApiError(404, "not_found", "User not found")
    if u.id == p.id and (body.role not in (None, "admin") or body.is_active is False):
        raise ApiError(409, "cannot_modify_self", "You cannot remove your own admin access")
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(u, k, v)
    await audit(db, category="admin", action="user.update", actor_id=p.id, actor_role=p.role, target_type="user",
                target_id=user_id, request=request, details=changes)
    await db.commit()
    return {"id": str(u.id), "role": u.role, "is_active": u.is_active}


class SubscriptionPatch(BaseModel):
    plan: Literal["free", "plus", "family", "business", "enterprise"]
    status: Literal["active", "past_due", "canceled"] = "active"


@router.put("/users/{user_id}/subscription")
async def set_subscription(user_id: uuid.UUID, body: SubscriptionPatch, request: Request, p: Principal = Depends(admin),
                           db: AsyncSession = Depends(get_db)) -> dict:
    sub = (await db.execute(select(Subscription).where(Subscription.user_id == user_id))).scalar_one_or_none()
    if sub is None:
        raise ApiError(404, "not_found", "User not found")
    old = {"plan": sub.plan, "status": sub.status}
    sub.plan, sub.status, sub.source = body.plan, body.status, "manual"
    await audit(db, category="admin", action="subscription.update", actor_id=p.id, actor_role=p.role, target_type="user",
                target_id=user_id, request=request, details={"from": old, "to": body.model_dump()})
    await db.commit()
    return {"user_id": str(user_id), **body.model_dump()}


@router.get("/threat-sources")
async def threat_sources(p: Principal = Depends(admin_or_security), db: AsyncSession = Depends(get_db)) -> list[dict]:
    from app.services.analysis_service import get_engine_deps

    deps = get_engine_deps()
    configured = [r.name for r in deps.reputation] + ([deps.domain_age.name] if deps.domain_age else [])
    rows = {r.source: r for r in (await db.execute(select(ThreatSourceHealth))).scalars()}
    out = []
    for name in sorted(set(configured) | set(rows)):
        r = rows.get(name)
        total = (r.success_count + r.failure_count) if r else 0
        out.append({
            "source": name, "configured": name in configured,
            "success_count": r.success_count if r else 0, "failure_count": r.failure_count if r else 0,
            "failure_rate": round(r.failure_count / total, 3) if r and total else None,
            "last_success_at": r.last_success_at.isoformat() if r and r.last_success_at else None,
            "last_failure_at": r.last_failure_at.isoformat() if r and r.last_failure_at else None,
            "last_error": r.last_error if r else None,
        })
    return out


@router.get("/ai-usage")
async def ai_usage(p: Principal = Depends(admin), db: AsyncSession = Depends(get_db),
                   days: int = Query(30, ge=1, le=365)) -> dict:
    since = datetime.now(UTC) - timedelta(days=days)
    rows = (await db.execute(select(AIUsage.provider, AIUsage.model, func.count(), func.sum(AIUsage.input_tokens),
                                    func.sum(AIUsage.output_tokens), func.sum(AIUsage.cost_micro_eur),
                                    func.avg(AIUsage.latency_ms), func.count().filter(AIUsage.success.is_(False)))
                             .where(AIUsage.occurred_at >= since).group_by(AIUsage.provider, AIUsage.model))).all()
    month_start = datetime.now(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_cost = (await db.execute(select(func.coalesce(func.sum(AIUsage.cost_micro_eur), 0))
                                   .where(AIUsage.occurred_at >= month_start))).scalar_one()
    s = get_settings()
    return {
        "period_days": days,
        "by_model": [{"provider": r[0], "model": r[1], "calls": r[2], "input_tokens": r[3] or 0, "output_tokens": r[4] or 0,
                      "estimated_cost_eur": round((r[5] or 0) / 1_000_000, 4), "avg_latency_ms": int(r[6] or 0),
                      "failures": int(r[7] or 0)} for r in rows],
        "month_to_date_estimated_cost_eur": round(month_cost / 1_000_000, 4),
        "monthly_budget_eur": s.ai_monthly_budget_eur,
        "provider": s.ai_provider,
        "note": "Costs are estimates from token counts and list prices, not invoices.",
    }


@router.get("/errors")
async def errors(p: Principal = Depends(admin_or_security), db: AsyncSession = Depends(get_db),
                 days: int = Query(7, ge=1, le=90)) -> dict:
    since = datetime.now(UTC) - timedelta(days=days)
    rows = (await db.execute(select(ErrorEvent.route, ErrorEvent.error_type, func.count(), func.max(ErrorEvent.occurred_at))
                             .where(ErrorEvent.occurred_at >= since).group_by(ErrorEvent.route, ErrorEvent.error_type)
                             .order_by(func.count().desc()).limit(100))).all()
    failed = dict((await db.execute(select(Analysis.error_code, func.count()).where(
        Analysis.status == "failed", Analysis.created_at >= since).group_by(Analysis.error_code))).all())
    return {"http_errors": [{"route": r[0], "error_type": r[1], "count": r[2], "last_at": r[3].isoformat()} for r in rows],
            "failed_analyses": failed}


@router.get("/security-events")
async def security_events(p: Principal = Depends(admin_or_security), db: AsyncSession = Depends(get_db),
                          limit: int = Query(100, ge=1, le=500)) -> list[dict]:
    rows = (await db.execute(select(AuditLog).where(AuditLog.category == "security")
                             .order_by(AuditLog.occurred_at.desc()).limit(limit))).scalars().all()
    return [_log_out(r) for r in rows]


@router.get("/abuse")
async def abuse(p: Principal = Depends(admin_or_security), db: AsyncSession = Depends(get_db)) -> dict:
    since = datetime.now(UTC) - timedelta(hours=24)
    noisy_ips = (await db.execute(select(AuditLog.ip_hash, func.count()).where(
        AuditLog.category == "security", AuditLog.occurred_at >= since, AuditLog.ip_hash.is_not(None))
        .group_by(AuditLog.ip_hash).order_by(func.count().desc()).limit(20))).all()
    heavy_users = (await db.execute(select(Analysis.user_id, func.count()).where(Analysis.created_at >= since)
                                    .group_by(Analysis.user_id).order_by(func.count().desc()).limit(20))).all()
    locked = (await db.execute(select(func.count()).select_from(User).where(User.locked_until > datetime.now(UTC)))).scalar_one()
    return {"window_hours": 24,
            "top_security_event_sources": [{"ip_hash": r[0], "events": r[1]} for r in noisy_ips],
            "top_users_by_analyses": [{"user_id": str(r[0]), "analyses": r[1]} for r in heavy_users],
            "currently_locked_accounts": locked}


@router.get("/audit-logs")
async def audit_logs(p: Principal = Depends(admin_or_security), db: AsyncSession = Depends(get_db),
                     category: str | None = Query(None, max_length=16), action: str | None = Query(None, max_length=64),
                     actor: uuid.UUID | None = None, limit: int = Query(100, ge=1, le=500)) -> list[dict]:
    q = select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(limit)
    if category:
        q = q.where(AuditLog.category == category)
    if action:
        q = q.where(AuditLog.action == action)
    if actor:
        q = q.where(AuditLog.actor_user_id == actor)
    return [_log_out(r) for r in (await db.execute(q)).scalars().all()]


def _log_out(r: AuditLog) -> dict[str, Any]:
    return {"id": r.id, "occurred_at": r.occurred_at.isoformat(), "category": r.category, "action": r.action,
            "actor_user_id": str(r.actor_user_id) if r.actor_user_id else None, "actor_role": r.actor_role,
            "target_type": r.target_type, "target_id": r.target_id, "outcome": r.outcome, "ip_hash": r.ip_hash,
            "details": r.details}


@router.get("/support-overview")
async def support_overview(p: Principal = Depends(admin), db: AsyncSession = Depends(get_db)) -> dict:
    by_status = dict((await db.execute(select(SupportTicket.status, func.count()).group_by(SupportTicket.status))).all())
    by_cat = dict((await db.execute(select(SupportTicket.category, func.count()).where(SupportTicket.status.in_(("open", "pending")))
                                    .group_by(SupportTicket.category))).all())
    return {"tickets_by_status": by_status, "open_by_category": by_cat}


async def ensure_default_flags(db: AsyncSession) -> None:
    existing = {f.key for f in (await db.execute(select(FeatureFlag))).scalars()}
    for k, (enabled, desc) in DEFAULT_FLAGS.items():
        if k not in existing:
            db.add(FeatureFlag(key=k, enabled=enabled, description=desc))
    await db.commit()


@router.get("/feature-flags")
async def get_flags(p: Principal = Depends(admin), db: AsyncSession = Depends(get_db)) -> list[dict]:
    await ensure_default_flags(db)
    rows = (await db.execute(select(FeatureFlag).order_by(FeatureFlag.key))).scalars().all()
    return [{"key": f.key, "enabled": f.enabled, "description": f.description, "updated_at": f.updated_at.isoformat()} for f in rows]


class FlagIn(BaseModel):
    enabled: bool
    description: str | None = Field(default=None, max_length=300)


@router.put("/feature-flags/{key}")
async def set_flag(key: str, body: FlagIn, request: Request, p: Principal = Depends(admin),
                   db: AsyncSession = Depends(get_db)) -> dict:
    if not key.replace(".", "").replace("_", "").isalnum() or len(key) > 64:
        raise ApiError(422, "invalid_key", "Invalid flag key")
    f = await db.get(FeatureFlag, key)
    if f is None:
        f = FeatureFlag(key=key, description=body.description or "")
        db.add(f)
    f.enabled = body.enabled
    if body.description is not None:
        f.description = body.description
    f.updated_by = p.id
    await audit(db, category="admin", action="feature_flag.set", actor_id=p.id, actor_role=p.role, target_type="flag",
                target_id=key, request=request, details={"enabled": body.enabled})
    await db.commit()
    return {"key": key, "enabled": f.enabled}


CONFIG_KEYS = {"support_hours", "status_banner", "quota_overrides"}


@router.get("/config")
async def get_config(p: Principal = Depends(admin), db: AsyncSession = Depends(get_db)) -> dict:
    s = get_settings()
    rows = {c.key: c.value for c in (await db.execute(select(SystemConfig))).scalars()}
    return {
        "editable": rows,
        "runtime": {  # read-only view of non-secret settings
            "environment": s.environment, "ai_provider": s.ai_provider, "active_url_probing": s.active_url_probing,
            "rdap_enabled": s.rdap_enabled, "google_safe_browsing": bool(s.google_safe_browsing_api_key),
            "urlhaus": bool(s.urlhaus_auth_key), "analysis_inline": s.analysis_inline, "storage_backend": s.storage_backend,
            "free_monthly_checks": s.free_monthly_checks, "plus_monthly_checks": s.plus_monthly_checks,
        },
    }


class ConfigIn(BaseModel):
    value: dict[str, Any]


@router.put("/config/{key}")
async def set_config(key: str, body: ConfigIn, request: Request, p: Principal = Depends(admin),
                     db: AsyncSession = Depends(get_db)) -> dict:
    if key not in CONFIG_KEYS:
        raise ApiError(422, "unknown_config_key", f"Editable keys: {sorted(CONFIG_KEYS)}")
    c = await db.get(SystemConfig, key)
    if c is None:
        c = SystemConfig(key=key, value=body.value)
        db.add(c)
    c.value = body.value
    c.updated_by = p.id
    await audit(db, category="admin", action="config.set", actor_id=p.id, actor_role=p.role, target_type="config",
                target_id=key, request=request)
    await db.commit()
    return {"key": key, "value": c.value}
