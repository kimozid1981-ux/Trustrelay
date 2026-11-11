"""Uploads, analyses, history, notes, deletion, sharing with family and support-access consent."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, File, Query, Request, Response, UploadFile
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import Principal, current_principal, language, rate_limit
from app.api.errors import ApiError
from app.core.audit import audit
from app.core.config import get_settings
from app.core.storage import put_encrypted
from app.db.models import Analysis, FamilyMember, SharedWarning, SupportAccessGrant, Upload, UsageCounter
from app.db.session import get_db
from app.services import analysis_service as svc
from app.services.uploads import UploadRejected, sanitize_image

router = APIRouter(tags=["analyses"])

PLAN_LIMITS = {"free": "free_monthly_checks", "plus": "plus_monthly_checks", "family": "plus_monthly_checks"}
_an_rl = rate_limit("analyses", lambda: get_settings().rate_limit_analyses_per_minute)


class UploadOut(BaseModel):
    id: uuid.UUID
    width: int
    height: int
    size_bytes: int


@router.post("/uploads", response_model=UploadOut, status_code=201)
async def upload_image(request: Request, file: UploadFile = File(...), p: Principal = Depends(current_principal),
                       _: None = Depends(_an_rl), db: AsyncSession = Depends(get_db)) -> UploadOut:
    s = get_settings()
    data = await file.read(s.max_upload_bytes + 1)
    try:
        png, w, h = sanitize_image(data, max_bytes=s.max_upload_bytes, max_pixels=s.max_image_pixels)
    except UploadRejected as exc:
        await audit(db, category="security", action="upload.rejected", actor_id=p.id, outcome="denied",
                    request=request, details={"reason": exc.code})
        await db.commit()
        raise ApiError(422, exc.code, "The file could not be accepted") from exc
    up_id = uuid.uuid4()
    key = f"uploads/{p.id}/{up_id}.bin"
    await put_encrypted(key, png)
    up = Upload(id=up_id, user_id=p.id, storage_key=key, content_type="image/png", size_bytes=len(png), width=w, height=h,
                expires_at=datetime.now(UTC) + timedelta(days=1))
    db.add(up)
    await db.commit()
    return UploadOut(id=up_id, width=w, height=h, size_bytes=len(png))


class AnalysisCreate(BaseModel):
    kind: Literal["url", "message", "advert", "payment", "qr", "image"]
    text: str | None = Field(default=None, max_length=20_000)
    upload_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _check(self) -> AnalysisCreate:
        if self.kind == "image" and not self.upload_id:
            raise ValueError("image analysis requires upload_id")
        if self.kind not in ("image", "qr") and self.upload_id:
            raise ValueError("upload_id is only accepted for image or qr analyses")
        if self.kind != "image" and not self.upload_id and not (self.text and self.text.strip()):
            raise ValueError("text is required")
        return self


async def _check_quota(db: AsyncSession, p: Principal) -> UsageCounter:
    s = get_settings()
    period = datetime.now(UTC).strftime("%Y-%m")
    plan = p.user.subscription.plan if p.user.subscription else "free"
    limit_attr = PLAN_LIMITS.get(plan)
    counter = await db.get(UsageCounter, (p.id, period), with_for_update=True)
    if counter is None:
        counter = UsageCounter(user_id=p.id, period=period, checks=0)
        db.add(counter)
    if limit_attr and counter.checks >= getattr(s, limit_attr):
        raise ApiError(402, "quota_exceeded", "You have used all checks included in your plan this month",
                       extra={"limit": getattr(s, limit_attr), "plan": plan})
    counter.checks += 1
    return counter


@router.post("/analyses", status_code=202)
async def create_analysis(body: AnalysisCreate, request: Request, response: Response,
                          p: Principal = Depends(current_principal), _: None = Depends(_an_rl),
                          lang: str = Depends(language), db: AsyncSession = Depends(get_db)) -> dict:
    if body.upload_id:
        up = await db.get(Upload, body.upload_id)
        if up is None or up.user_id != p.id:
            raise ApiError(404, "upload_not_found", "Upload not found")
    await _check_quota(db, p)
    prefs = p.user.preferences
    retention = prefs.retention_days if prefs else 90
    a = Analysis(id=uuid.uuid4(), user_id=p.id, kind=body.kind, status="queued", language=lang, upload_id=body.upload_id,
                 expires_at=datetime.now(UTC) + timedelta(days=retention or 1))
    if body.text:
        a.input_enc = svc.enc(a.id, "input", body.text)
    db.add(a)
    if body.upload_id:
        up.expires_at = a.expires_at
    await audit(db, category="data", action="analysis.create", actor_id=p.id, actor_role=p.role,
                target_type="analysis", target_id=a.id, request=request, details={"kind": body.kind})
    await db.commit()
    if get_settings().analysis_inline:
        await svc.run_analysis(db, a.id)
    else:
        from app.worker import enqueue_analysis

        await enqueue_analysis(a.id)
    await db.refresh(a)
    response.headers["Location"] = f"{get_settings().api_prefix}/analyses/{a.id}"
    simple = bool(prefs and prefs.explanation_level == "simple")
    return svc.render(a, lang, simple=simple)


async def _own(db: AsyncSession, p: Principal, analysis_id: uuid.UUID) -> Analysis:
    a = await db.get(Analysis, analysis_id)
    if a is None or a.user_id != p.id:
        raise ApiError(404, "not_found", "Analysis not found")
    return a


@router.get("/analyses/{analysis_id}")
async def get_analysis(analysis_id: uuid.UUID, p: Principal = Depends(current_principal), lang: str = Depends(language),
                       db: AsyncSession = Depends(get_db)) -> dict:
    a = await _own(db, p, analysis_id)
    prefs = p.user.preferences
    return svc.render(a, lang, simple=bool(prefs and prefs.explanation_level == "simple"))


@router.get("/analyses")
async def list_analyses(p: Principal = Depends(current_principal), lang: str = Depends(language),
                        db: AsyncSession = Depends(get_db),
                        limit: int = Query(20, ge=1, le=100),
                        before: datetime | None = None,
                        kind: str | None = Query(None, pattern="^(url|message|advert|payment|qr|image)$"),
                        verdict: str | None = Query(None, max_length=32)) -> dict:
    q = select(Analysis).where(Analysis.user_id == p.id)
    if before:
        q = q.where(Analysis.created_at < before)
    if kind:
        q = q.where(Analysis.kind == kind)
    if verdict:
        q = q.where(Analysis.verdict == verdict)
    rows = (await db.execute(q.order_by(Analysis.created_at.desc()).limit(limit + 1))).scalars().all()
    items = []
    from app.i18n import catalog

    for a in rows[:limit]:
        items.append({
            "id": str(a.id), "kind": a.kind, "status": a.status, "verdict": a.verdict,
            "verdict_title": catalog.render_verdict(a.verdict, lang)["title"] if a.verdict else None,
            "confidence": a.confidence, "created_at": a.created_at.isoformat(),
            "label": svc.dec(a.id, "label", a.label_enc), "note": svc.dec(a.id, "note", a.note_enc),
            "expires_at": a.expires_at.isoformat(),
        })
    next_before = rows[limit - 1].created_at.isoformat() if len(rows) > limit else None
    return {"items": items, "next_before": next_before}


class NoteIn(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


@router.put("/analyses/{analysis_id}/note")
async def set_note(analysis_id: uuid.UUID, body: NoteIn, p: Principal = Depends(current_principal),
                   db: AsyncSession = Depends(get_db)) -> dict:
    a = await _own(db, p, analysis_id)
    a.note_enc = svc.enc(a.id, "note", body.note) if body.note else None
    await db.commit()
    return {"id": str(a.id), "note": body.note}


@router.delete("/analyses/{analysis_id}", status_code=204)
async def delete_one(analysis_id: uuid.UUID, request: Request, p: Principal = Depends(current_principal),
                     db: AsyncSession = Depends(get_db)) -> Response:
    a = await _own(db, p, analysis_id)
    await svc.delete_analysis(db, a)
    await audit(db, category="data", action="analysis.delete", actor_id=p.id, actor_role=p.role,
                target_type="analysis", target_id=analysis_id, request=request)
    await db.commit()
    return Response(status_code=204)


@router.delete("/analyses", status_code=200)
async def delete_all(request: Request, p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> dict:
    rows = (await db.execute(select(Analysis).where(Analysis.user_id == p.id))).scalars().all()
    for a in rows:
        await svc.delete_analysis(db, a)
    await audit(db, category="data", action="analysis.delete_all", actor_id=p.id, actor_role=p.role, request=request,
                details={"count": len(rows)})
    await db.commit()
    return {"deleted": len(rows)}


class ShareIn(BaseModel):
    message: str | None = Field(default=None, max_length=500)
    confirm: bool = Field(description="Must be true: the user explicitly approves sharing this warning")


@router.post("/analyses/{analysis_id}/share", status_code=201)
async def share_with_family(analysis_id: uuid.UUID, body: ShareIn, request: Request,
                            p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> dict:
    if not body.confirm:
        raise ApiError(422, "confirmation_required", "Sharing requires your explicit confirmation")
    a = await _own(db, p, analysis_id)
    if a.status != "completed":
        raise ApiError(409, "not_completed", "The analysis is not finished")
    member = (await db.execute(select(FamilyMember).where(FamilyMember.user_id == p.id))).scalar_one_or_none()
    if member is None:
        raise ApiError(409, "no_family", "You are not part of a family group")
    if not member.can_share_warnings:
        raise ApiError(403, "sharing_not_allowed", "Your family settings do not allow sharing warnings")
    from app.core.crypto import get_keyring

    w = SharedWarning(id=uuid.uuid4(), group_id=member.group_id, shared_by=p.id, analysis_id=a.id, kind=a.kind,
                      verdict=a.verdict or "insufficient_information",
                      finding_codes=[f.code for f in a.findings if f.severity != "info"][:10])
    if body.message:
        w.message_enc = get_keyring().encrypt_text(body.message, f"warning:{w.id}".encode())
    db.add(w)
    await audit(db, category="data", action="family.warning_shared", actor_id=p.id, actor_role=p.role,
                target_type="analysis", target_id=a.id, request=request)
    await db.commit()
    return {"id": str(w.id)}


class SupportGrantIn(BaseModel):
    hours: int = Field(default=72, ge=1, le=168)
    ticket_id: uuid.UUID | None = None


@router.post("/analyses/{analysis_id}/support-access", status_code=201)
async def grant_support_access(analysis_id: uuid.UUID, body: SupportGrantIn, request: Request,
                               p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> dict:
    a = await _own(db, p, analysis_id)
    g = SupportAccessGrant(id=uuid.uuid4(), user_id=p.id, analysis_id=a.id, ticket_id=body.ticket_id,
                           expires_at=datetime.now(UTC) + timedelta(hours=body.hours))
    db.add(g)
    await audit(db, category="data", action="support.access_granted", actor_id=p.id, actor_role=p.role,
                target_type="analysis", target_id=a.id, request=request, details={"hours": body.hours})
    await db.commit()
    return {"id": str(g.id), "expires_at": g.expires_at.isoformat()}


@router.delete("/support-access/{grant_id}", status_code=204)
async def revoke_support_access(grant_id: uuid.UUID, request: Request, p: Principal = Depends(current_principal),
                                db: AsyncSession = Depends(get_db)) -> Response:
    g = await db.get(SupportAccessGrant, grant_id)
    if g is None or g.user_id != p.id:
        raise ApiError(404, "not_found", "Grant not found")
    g.revoked_at = datetime.now(UTC)
    await audit(db, category="data", action="support.access_revoked", actor_id=p.id, target_type="grant",
                target_id=grant_id, request=request)
    await db.commit()
    return Response(status_code=204)


@router.get("/usage")
async def usage(p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> dict:
    s = get_settings()
    period = datetime.now(UTC).strftime("%Y-%m")
    counter = await db.get(UsageCounter, (p.id, period))
    plan = p.user.subscription.plan if p.user.subscription else "free"
    attr = PLAN_LIMITS.get(plan)
    total = (await db.execute(select(func.count()).select_from(Analysis).where(and_(Analysis.user_id == p.id)))).scalar_one()
    return {"period": period, "plan": plan, "checks_used": counter.checks if counter else 0,
            "checks_limit": getattr(s, attr) if attr else None, "stored_analyses": total}
