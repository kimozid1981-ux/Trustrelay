from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import ApiError
from app.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(db: AsyncSession = Depends(get_db)) -> dict:
    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        raise ApiError(503, "not_ready", "Database unavailable") from exc
    return {"status": "ready"}
