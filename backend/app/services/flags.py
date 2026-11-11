"""Feature flags: defaults live here; admins override them (table `feature_flags`)."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import FeatureFlag

DEFAULT_FLAGS: dict[str, tuple[bool, str]] = {
    "module.website": (True, "Website / URL analysis module"),
    "module.message": (True, "Message analysis module"),
    "module.advert": (True, "Advertisement analysis module"),
    "module.payment": (True, "Payment request analysis module"),
    "module.ai": (True, "AI analysis (only for users who opted in; also skipped once the monthly AI budget is spent)"),
    "family_protection": (True, "Family groups and shared warnings"),
    "public_link_checker": (False, "Anonymous website checker on the public site (not built yet)"),
}


async def is_enabled(db: AsyncSession, key: str) -> bool:
    row = await db.get(FeatureFlag, key)
    return row.enabled if row is not None else DEFAULT_FLAGS.get(key, (False, ""))[0]
