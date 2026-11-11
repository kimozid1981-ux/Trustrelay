"""Background worker (arq on Redis): runs analyses and the daily retention purge.

Start with:  arq app.worker.WorkerSettings
"""

from __future__ import annotations

import uuid
from typing import Any

from arq import create_pool, cron
from arq.connections import RedisSettings

from app.core.config import get_settings
from app.db.session import get_sessionmaker

_pool: Any = None


async def enqueue_analysis(analysis_id: uuid.UUID) -> None:
    global _pool
    if _pool is None:
        _pool = await create_pool(RedisSettings.from_dsn(get_settings().redis_url or "redis://localhost:6379"))
    await _pool.enqueue_job("process_analysis", str(analysis_id), _job_id=f"analysis:{analysis_id}")


async def process_analysis(ctx: dict, analysis_id: str) -> None:
    from app.services.analysis_service import run_analysis

    async with get_sessionmaker()() as db:
        await run_analysis(db, uuid.UUID(analysis_id))


async def purge(ctx: dict) -> dict:
    from app.services.analysis_service import purge_expired

    async with get_sessionmaker()() as db:
        return await purge_expired(db)


class WorkerSettings:
    functions = [process_analysis]
    cron_jobs = [cron(purge, hour={3}, minute={15})]
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url or "redis://localhost:6379")
    max_jobs = 20
    job_timeout = 120
