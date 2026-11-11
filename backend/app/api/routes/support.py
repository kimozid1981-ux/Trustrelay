"""Minimal support tickets (Phase 4 will build the full support operation) and consent-based case access."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import Principal, current_principal, language, rate_limit, require_roles
from app.api.errors import ApiError
from app.core.audit import audit
from app.core.crypto import get_keyring
from app.db.models import Analysis, SupportAccessGrant, SupportTicket
from app.db.session import get_db
from app.services import analysis_service as svc

router = APIRouter(tags=["support"])
_ticket_rl = rate_limit("tickets", lambda: 5)

Category = Literal["general", "technical", "account", "fraud", "security"]


class TicketIn(BaseModel):
    category: Category
    subject: str = Field(min_length=3, max_length=150)
    body: str = Field(min_length=10, max_length=5000)


def _ticket_out(t: SupportTicket, *, with_content: bool) -> dict:
    out = {"id": str(t.id), "category": t.category, "priority": t.priority, "status": t.status,
           "created_at": t.created_at.isoformat(), "updated_at": t.updated_at.isoformat()}
    if with_content:
        kr = get_keyring()
        out["subject"] = kr.decrypt_text(t.subject_enc, f"ticket:{t.id}:subject".encode())
        out["body"] = kr.decrypt_text(t.body_enc, f"ticket:{t.id}:body".encode())
    return out


@router.post("/support/tickets", status_code=201)
async def create_ticket(body: TicketIn, request: Request, p: Principal = Depends(current_principal),
                        _: None = Depends(_ticket_rl), db: AsyncSession = Depends(get_db)) -> dict:
    tid = uuid.uuid4()
    kr = get_keyring()
    priority = "high" if body.category in ("fraud", "security") else "normal"
    t = SupportTicket(id=tid, user_id=p.id, category=body.category, priority=priority, status="open",
                      subject_enc=kr.encrypt_text(body.subject, f"ticket:{tid}:subject".encode()),
                      body_enc=kr.encrypt_text(body.body, f"ticket:{tid}:body".encode()))
    db.add(t)
    await audit(db, category="data", action="ticket.create", actor_id=p.id, target_type="ticket", target_id=tid,
                request=request, details={"category": body.category})
    await db.commit()
    await db.refresh(t)
    return _ticket_out(t, with_content=True)


@router.get("/support/tickets")
async def my_tickets(p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> list[dict]:
    rows = (await db.execute(select(SupportTicket).where(SupportTicket.user_id == p.id)
                             .order_by(SupportTicket.created_at.desc()))).scalars().all()
    return [_ticket_out(t, with_content=True) for t in rows]


staff = require_roles("support", "admin")


@router.get("/staff/tickets")
async def staff_tickets(p: Principal = Depends(staff), db: AsyncSession = Depends(get_db),
                        status: str | None = None) -> list[dict]:
    q = select(SupportTicket).order_by(SupportTicket.created_at.desc()).limit(200)
    if status:
        q = q.where(SupportTicket.status == status)
    rows = (await db.execute(q)).scalars().all()
    # Support agents need the ticket text to help; reading it is audited per ticket below.
    return [_ticket_out(t, with_content=False) for t in rows]


@router.get("/staff/tickets/{ticket_id}")
async def staff_ticket(ticket_id: uuid.UUID, request: Request, p: Principal = Depends(staff),
                       db: AsyncSession = Depends(get_db)) -> dict:
    t = await db.get(SupportTicket, ticket_id)
    if t is None:
        raise ApiError(404, "not_found", "Ticket not found")
    grants = (await db.execute(select(SupportAccessGrant).where(
        SupportAccessGrant.ticket_id == ticket_id, SupportAccessGrant.revoked_at.is_(None),
        SupportAccessGrant.expires_at > datetime.now(UTC)))).scalars().all()
    await audit(db, category="data", action="ticket.read", actor_id=p.id, actor_role=p.role, target_type="ticket",
                target_id=ticket_id, request=request)
    await db.commit()
    return {**_ticket_out(t, with_content=True), "access_grants": [{"id": str(g.id), "analysis_id": str(g.analysis_id),
                                                                    "expires_at": g.expires_at.isoformat()} for g in grants]}


class TicketPatch(BaseModel):
    status: Literal["open", "pending", "resolved", "closed"] | None = None
    priority: Literal["low", "normal", "high", "urgent"] | None = None


@router.patch("/staff/tickets/{ticket_id}")
async def staff_update_ticket(ticket_id: uuid.UUID, body: TicketPatch, request: Request, p: Principal = Depends(staff),
                              db: AsyncSession = Depends(get_db)) -> dict:
    t = await db.get(SupportTicket, ticket_id)
    if t is None:
        raise ApiError(404, "not_found", "Ticket not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(t, k, v)
    await audit(db, category="admin", action="ticket.update", actor_id=p.id, actor_role=p.role, target_type="ticket",
                target_id=ticket_id, request=request, details=body.model_dump(exclude_none=True))
    await db.commit()
    await db.refresh(t)
    return _ticket_out(t, with_content=False)


@router.get("/staff/access-grants/{grant_id}/analysis")
async def staff_view_analysis(grant_id: uuid.UUID, request: Request, p: Principal = Depends(staff),
                              lang: str = Depends(language), db: AsyncSession = Depends(get_db)) -> dict:
    """The ONLY path by which staff can read a customer's analysis: an active, user-issued grant. Audited."""
    g = await db.get(SupportAccessGrant, grant_id)
    now = datetime.now(UTC)
    if g is None or g.revoked_at is not None or g.expires_at <= now:
        await audit(db, category="security", action="support.access_denied", actor_id=p.id, actor_role=p.role,
                    target_type="grant", target_id=grant_id, outcome="denied", request=request)
        await db.commit()
        raise ApiError(403, "no_active_grant", "The customer has not granted access, or it has expired")
    a = await db.get(Analysis, g.analysis_id)
    if a is None:
        raise ApiError(404, "not_found", "Analysis no longer exists")
    await audit(db, category="data", action="support.analysis_viewed", actor_id=p.id, actor_role=p.role,
                target_type="analysis", target_id=a.id, request=request, details={"grant": str(g.id)})
    await db.commit()
    return svc.render(a, lang)
