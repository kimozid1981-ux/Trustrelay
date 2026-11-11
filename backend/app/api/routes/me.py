"""Profile, preferences, sessions, GDPR data export (Art. 15/20) and account deletion (Art. 17)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import Principal, current_principal, language
from app.api.errors import ApiError
from app.core.audit import audit
from app.core.crypto import get_keyring
from app.core.security import verify_password
from app.db.models import (
    Analysis,
    AuditLog,
    AuthSession,
    FamilyGroup,
    FamilyMember,
    SharedWarning,
    SupportAccessGrant,
    SupportTicket,
    Upload,
    UsageCounter,
)
from app.db.session import get_db
from app.services import analysis_service as svc

router = APIRouter(prefix="/me", tags=["me"])


def _profile(p: Principal) -> dict:
    u = p.user
    prefs = u.preferences
    return {
        "id": str(u.id),
        "email": u.email,
        "display_name": u.display_name,
        "role": u.role,
        "locale": u.locale,
        "mfa_enabled": u.totp_enabled,
        "onboarding_completed": u.onboarding_completed_at is not None,
        "created_at": u.created_at.isoformat(),
        "plan": u.subscription.plan if u.subscription else "free",
        "subscription_status": u.subscription.status if u.subscription else "active",
        "preferences": {
            "retention_days": prefs.retention_days,
            "explanation_level": prefs.explanation_level,
            "notify_analysis_complete": prefs.notify_analysis_complete,
            "notify_family_warnings": prefs.notify_family_warnings,
            "product_analytics_opt_in": prefs.product_analytics_opt_in,
            "allow_ai_processing": prefs.allow_ai_processing,
        } if prefs else None,
    }


@router.get("")
async def me(p: Principal = Depends(current_principal)) -> dict:
    return _profile(p)


class ProfilePatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=80)
    locale: Literal["fr", "en"] | None = None
    onboarding_completed: bool | None = None


@router.patch("")
async def update_me(body: ProfilePatch, p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> dict:
    if body.display_name is not None:
        p.user.display_name = body.display_name.strip() or None
    if body.locale:
        p.user.locale = body.locale
    if body.onboarding_completed:
        p.user.onboarding_completed_at = p.user.onboarding_completed_at or datetime.now(UTC)
    await db.commit()
    return _profile(p)


class PrefsPatch(BaseModel):
    retention_days: Literal[0, 30, 90, 365] | None = None
    explanation_level: Literal["simple", "standard", "detailed"] | None = None
    notify_analysis_complete: bool | None = None
    notify_family_warnings: bool | None = None
    product_analytics_opt_in: bool | None = None
    allow_ai_processing: bool | None = None


@router.patch("/preferences")
async def update_prefs(body: PrefsPatch, request: Request, p: Principal = Depends(current_principal),
                       db: AsyncSession = Depends(get_db)) -> dict:
    prefs = p.user.preferences
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(prefs, k, v)
    if "retention_days" in changes:
        # Shorten (never extend) the lifetime of existing analyses to match the new choice.
        from datetime import timedelta

        days = changes["retention_days"] or 1
        await db.execute(
            update(Analysis)
            .where(Analysis.user_id == p.id, Analysis.expires_at > Analysis.created_at + timedelta(days=days))
            .values(expires_at=Analysis.created_at + timedelta(days=days))
        )
    await audit(db, category="data", action="preferences.update", actor_id=p.id, actor_role=p.role, request=request,
                details={"fields": sorted(changes)})
    await db.commit()
    return _profile(p)["preferences"]


@router.get("/sessions")
async def sessions(p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> list[dict]:
    rows = (await db.execute(select(AuthSession).where(AuthSession.user_id == p.id, AuthSession.revoked_at.is_(None),
                                                       AuthSession.expires_at > datetime.now(UTC))
                             .order_by(AuthSession.created_at.desc()))).scalars().all()
    return [{"id": str(s.id), "client": s.client, "user_agent": s.user_agent, "created_at": s.created_at.isoformat(),
             "current": s.id == p.session_id} for s in rows]


@router.delete("/sessions/{session_id}", status_code=204)
async def revoke_session(session_id: uuid.UUID, p: Principal = Depends(current_principal),
                         db: AsyncSession = Depends(get_db)) -> Response:
    s = await db.get(AuthSession, session_id)
    if s is None or s.user_id != p.id:
        raise ApiError(404, "not_found", "Session not found")
    await db.execute(update(AuthSession).where(AuthSession.chain_id == s.chain_id).values(revoked_at=datetime.now(UTC)))
    await db.commit()
    return Response(status_code=204)


@router.get("/export")
async def export_data(request: Request, p: Principal = Depends(current_principal), lang: str = Depends(language),
                      db: AsyncSession = Depends(get_db)) -> Response:
    """Everything we hold about the user, decrypted, as one JSON document (portable format)."""
    analyses = (await db.execute(select(Analysis).where(Analysis.user_id == p.id).order_by(Analysis.created_at))).scalars().all()
    member = (await db.execute(select(FamilyMember).where(FamilyMember.user_id == p.id))).scalar_one_or_none()
    group = await db.get(FamilyGroup, member.group_id) if member else None
    warnings = (await db.execute(select(SharedWarning).where(SharedWarning.shared_by == p.id))).scalars().all()
    tickets = (await db.execute(select(SupportTicket).where(SupportTicket.user_id == p.id))).scalars().all()
    grants = (await db.execute(select(SupportAccessGrant).where(SupportAccessGrant.user_id == p.id))).scalars().all()
    sessions_ = (await db.execute(select(AuthSession).where(AuthSession.user_id == p.id))).scalars().all()
    usage_rows = (await db.execute(select(UsageCounter).where(UsageCounter.user_id == p.id))).scalars().all()
    uploads = (await db.execute(select(Upload).where(Upload.user_id == p.id))).scalars().all()
    logs = (await db.execute(select(AuditLog).where(AuditLog.actor_user_id == p.id).order_by(AuditLog.occurred_at))).scalars().all()
    kr = get_keyring()
    doc = {
        "format": "trustrelay-export-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "profile": _profile(p),
        "analyses": [svc.render(a, lang) for a in analyses],
        "family": {"group_name": group.name, "role": member.role, "age_band": member.age_band,
                   "receive_warnings": member.receive_warnings, "can_share_warnings": member.can_share_warnings}
        if member and group else None,
        "warnings_shared": [{"id": str(w.id), "kind": w.kind, "verdict": w.verdict, "created_at": w.created_at.isoformat(),
                             "message": kr.decrypt_text(w.message_enc, f"warning:{w.id}".encode()) if w.message_enc else None}
                            for w in warnings],
        "support_tickets": [{"id": str(t.id), "category": t.category, "status": t.status, "created_at": t.created_at.isoformat(),
                             "subject": kr.decrypt_text(t.subject_enc, f"ticket:{t.id}:subject".encode()),
                             "body": kr.decrypt_text(t.body_enc, f"ticket:{t.id}:body".encode())} for t in tickets],
        "support_access_grants": [{"analysis_id": str(g.analysis_id), "created_at": g.created_at.isoformat(),
                                   "expires_at": g.expires_at.isoformat(), "revoked": g.revoked_at is not None} for g in grants],
        "sessions": [{"client": s.client, "user_agent": s.user_agent, "created_at": s.created_at.isoformat(),
                      "revoked": s.revoked_at is not None} for s in sessions_],
        "usage": [{"period": u.period, "checks": u.checks} for u in usage_rows],
        "uploads": [{"id": str(u.id), "size_bytes": u.size_bytes, "created_at": u.created_at.isoformat()} for u in uploads],
        "activity_log": [{"at": log.occurred_at.isoformat(), "action": log.action, "outcome": log.outcome} for log in logs],
    }
    await audit(db, category="data", action="account.export", actor_id=p.id, actor_role=p.role, request=request)
    await db.commit()
    return Response(
        json.dumps(doc, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="trustrelay-export.json"', "Cache-Control": "no-store"},
    )


class DeleteAccountIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    confirm: Literal["DELETE"]


@router.post("/delete", status_code=204)
async def delete_account(body: DeleteAccountIn, request: Request, p: Principal = Depends(current_principal),
                         db: AsyncSession = Depends(get_db)) -> Response:
    if not verify_password(body.password, p.user.password_hash):
        raise ApiError(401, "invalid_credentials", "Password is incorrect")
    owned = (await db.execute(select(FamilyGroup).where(FamilyGroup.owner_id == p.id))).scalars().all()
    for g in owned:
        others = [m for m in g.members if m.user_id != p.id]
        successor = next((m for m in others if m.role == "guardian"), None) or next((m for m in others if m.age_band in ("adult", "senior")), None)
        if successor:
            g.owner_id = successor.user_id
            successor.role = "owner"
        else:
            await db.delete(g)
    analyses = (await db.execute(select(Analysis).where(Analysis.user_id == p.id))).scalars().all()
    for a in analyses:
        await svc.delete_analysis(db, a)
    uploads = (await db.execute(select(Upload).where(Upload.user_id == p.id))).scalars().all()
    for up in uploads:
        await svc.get_store().delete(up.storage_key)
    tickets = (await db.execute(select(SupportTicket).where(or_(SupportTicket.user_id == p.id)))).scalars().all()
    for t in tickets:
        await db.delete(t)
    await audit(db, category="data", action="account.delete", actor_id=p.id, actor_role=p.role, request=request)
    await db.delete(p.user)
    await db.commit()
    return Response(status_code=204)
