"""Optional family protection: groups, invitations by one-time code, per-member permissions, shared warnings.

Privacy rules: members never see each other's analyses or history. Only warnings that a member explicitly chose
to share are visible to the group, and those contain a verdict, finding codes and an optional note — never the
original message, link or image.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import Principal, current_principal, language, rate_limit
from app.api.errors import ApiError
from app.core.audit import audit
from app.core.crypto import get_keyring
from app.core.security import hash_refresh_token
from app.db.models import FamilyGroup, FamilyInvite, FamilyMember, SharedWarning, User
from app.db.session import get_db
from app.i18n import catalog

router = APIRouter(prefix="/family", tags=["family"])
_join_rl = rate_limit("family_join", lambda: 10)

AgeBand = Literal["child", "teen", "adult", "senior"]
Role = Literal["guardian", "member"]


async def _membership(db: AsyncSession, user_id: uuid.UUID) -> FamilyMember | None:
    return (await db.execute(select(FamilyMember).where(FamilyMember.user_id == user_id))).scalar_one_or_none()


def _can_manage(m: FamilyMember) -> bool:
    return m.role in ("owner", "guardian")


class CreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)


@router.post("", status_code=201)
async def create_group(body: CreateIn, request: Request, p: Principal = Depends(current_principal),
                       db: AsyncSession = Depends(get_db), lang: str = Depends(language)) -> dict:
    if await _membership(db, p.id):
        raise ApiError(409, "already_in_family", "You already belong to a family group")
    g = FamilyGroup(id=uuid.uuid4(), name=body.name.strip(), owner_id=p.id)
    db.add(g)
    await db.flush()
    db.add(FamilyMember(group_id=g.id, user_id=p.id, role="owner", age_band="adult"))
    await audit(db, category="data", action="family.create", actor_id=p.id, target_type="family", target_id=g.id, request=request)
    await db.commit()
    return await get_group(p, db, lang)


@router.get("")
async def get_group(p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db),
                    lang: str = Depends(language)) -> dict:
    m = await _membership(db, p.id)
    if m is None:
        return {"group": None}
    g = await db.get(FamilyGroup, m.group_id)
    assert g is not None
    await db.refresh(g, ["members"])
    users = {u.id: u for u in (await db.execute(select(User).where(User.id.in_([x.user_id for x in g.members])))).scalars()}
    members = [{
        "user_id": str(x.user_id),
        "display_name": users[x.user_id].display_name or "—",
        "role": x.role, "age_band": x.age_band,
        "receive_warnings": x.receive_warnings, "can_share_warnings": x.can_share_warnings,
        "is_me": x.user_id == p.id,
    } for x in g.members]
    warnings = []
    if m.receive_warnings:
        rows = (await db.execute(select(SharedWarning).where(SharedWarning.group_id == g.id)
                                 .order_by(SharedWarning.created_at.desc()).limit(50))).scalars().all()
        simple = m.age_band in ("child", "teen")
        kr = get_keyring()
        for w in rows:
            v = catalog.render_verdict(w.verdict, lang, simple=simple)
            warnings.append({
                "id": str(w.id),
                "shared_by": users[w.shared_by].display_name if w.shared_by in users else None,
                "kind": w.kind, "verdict": w.verdict, "verdict_title": v["title"], "verdict_summary": v["summary"],
                "signals": [catalog.render_finding(c, "rules", {}, lang)["title"] for c in w.finding_codes],
                "message": kr.decrypt_text(w.message_enc, f"warning:{w.id}".encode()) if w.message_enc else None,
                "created_at": w.created_at.isoformat(),
            })
    return {"group": {"id": str(g.id), "name": g.name, "my_role": m.role, "members": members}, "warnings": warnings}


class InviteIn(BaseModel):
    role: Role = "member"
    age_band: AgeBand = "adult"


@router.post("/invites", status_code=201)
async def invite(body: InviteIn, request: Request, p: Principal = Depends(current_principal),
                 db: AsyncSession = Depends(get_db)) -> dict:
    m = await _membership(db, p.id)
    if m is None or not _can_manage(m):
        raise ApiError(403, "forbidden", "Only the family owner or a guardian can invite members")
    code = "-".join(secrets.token_hex(2).upper() for _ in range(3))  # e.g. 4F2A-91C0-7B3E, shown once
    inv = FamilyInvite(group_id=m.group_id, code_hash=hash_refresh_token(code), role=body.role, age_band=body.age_band,
                       created_by=p.id, expires_at=datetime.now(UTC) + timedelta(days=7))
    db.add(inv)
    await audit(db, category="data", action="family.invite", actor_id=p.id, target_type="family", target_id=m.group_id,
                request=request, details={"role": body.role, "age_band": body.age_band})
    await db.commit()
    return {"code": code, "expires_at": inv.expires_at.isoformat()}


class JoinIn(BaseModel):
    code: str = Field(min_length=6, max_length=32)


@router.post("/join")
async def join(body: JoinIn, request: Request, p: Principal = Depends(current_principal), _: None = Depends(_join_rl),
               db: AsyncSession = Depends(get_db), lang: str = Depends(language)) -> dict:
    if await _membership(db, p.id):
        raise ApiError(409, "already_in_family", "You already belong to a family group")
    code = body.code.strip().upper()
    inv = (await db.execute(select(FamilyInvite).where(FamilyInvite.code_hash == hash_refresh_token(code)))).scalar_one_or_none()
    if inv is None or inv.accepted_at is not None or inv.expires_at < datetime.now(UTC):
        await audit(db, category="security", action="family.join_failed", actor_id=p.id, outcome="denied", request=request)
        await db.commit()
        raise ApiError(404, "invalid_invite", "This invitation code is invalid or has expired")
    inv.accepted_at = datetime.now(UTC)
    # Children do not share by default; they still receive age-appropriate warnings.
    db.add(FamilyMember(group_id=inv.group_id, user_id=p.id, role=inv.role, age_band=inv.age_band,
                        can_share_warnings=inv.age_band != "child"))
    await audit(db, category="data", action="family.join", actor_id=p.id, target_type="family", target_id=inv.group_id, request=request)
    await db.commit()
    return await get_group(p, db, lang)


class MemberPatch(BaseModel):
    role: Role | None = None
    age_band: AgeBand | None = None
    receive_warnings: bool | None = None
    can_share_warnings: bool | None = None


@router.patch("/members/{user_id}")
async def update_member(user_id: uuid.UUID, body: MemberPatch, request: Request, p: Principal = Depends(current_principal),
                        db: AsyncSession = Depends(get_db), lang: str = Depends(language)) -> dict:
    me = await _membership(db, p.id)
    target = await _membership(db, user_id)
    if me is None or target is None or me.group_id != target.group_id:
        raise ApiError(404, "not_found", "Member not found")
    changes = body.model_dump(exclude_none=True)
    self_only = {"receive_warnings"}
    if user_id != p.id or set(changes) - self_only:
        if not _can_manage(me):
            raise ApiError(403, "forbidden", "Only the family owner or a guardian can change this")
        if target.role == "owner" and user_id != p.id:
            raise ApiError(403, "forbidden", "The owner's settings can only be changed by the owner")
        if "role" in changes and me.role != "owner":
            raise ApiError(403, "forbidden", "Only the owner can change roles")
    if target.role == "owner" and "role" in changes:
        raise ApiError(409, "owner_role_fixed", "Transfer ownership is not supported yet")
    for k, v in changes.items():
        setattr(target, k, v)
    await audit(db, category="data", action="family.member_update", actor_id=p.id, target_type="user", target_id=user_id,
                request=request, details={"fields": sorted(changes)})
    await db.commit()
    return await get_group(p, db, lang)


@router.delete("/members/{user_id}", status_code=204)
async def remove_member(user_id: uuid.UUID, request: Request, p: Principal = Depends(current_principal),
                        db: AsyncSession = Depends(get_db)) -> Response:
    me = await _membership(db, p.id)
    target = await _membership(db, user_id)
    if me is None or target is None or me.group_id != target.group_id:
        raise ApiError(404, "not_found", "Member not found")
    if user_id != p.id and not _can_manage(me):
        raise ApiError(403, "forbidden", "Only the family owner or a guardian can remove members")
    if target.role == "owner":
        g = await db.get(FamilyGroup, target.group_id)
        if user_id != p.id:
            raise ApiError(403, "forbidden", "The owner cannot be removed")
        await db.delete(g)  # owner leaving dissolves the group
    else:
        await db.delete(target)
    await audit(db, category="data", action="family.member_remove", actor_id=p.id, target_type="user", target_id=user_id,
                request=request)
    await db.commit()
    return Response(status_code=204)
