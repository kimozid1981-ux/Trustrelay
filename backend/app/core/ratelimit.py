"""Fixed-window rate limiter. Redis in staging/production; in-memory for development and tests."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Protocol


class RateLimiter(Protocol):
    async def hit(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        ...


class MemoryRateLimiter:
    def __init__(self) -> None:
        self._counts: dict[str, int] = defaultdict(int)

    async def hit(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        now = int(time.time())
        window = now // window_seconds
        k = f"{key}:{window}"
        self._counts[k] += 1
        if len(self._counts) > 50_000:
            current = {kk: v for kk, v in self._counts.items() if kk.endswith(f":{window}")}
            self._counts = defaultdict(int, current)
        retry = window_seconds - (now % window_seconds)
        return self._counts[k] <= limit, retry

    def reset(self) -> None:
        self._counts.clear()


class RedisRateLimiter:
    def __init__(self, url: str) -> None:
        import redis.asyncio as redis

        self._r = redis.from_url(url)

    async def hit(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        now = int(time.time())
        window = now // window_seconds
        k = f"rl:{key}:{window}"
        async with self._r.pipeline(transaction=True) as pipe:
            pipe.incr(k)
            pipe.expire(k, window_seconds + 1)
            count, _ = await pipe.execute()
        return int(count) <= limit, window_seconds - (now % window_seconds)


_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        from app.core.config import get_settings

        url = get_settings().redis_url
        _limiter = RedisRateLimiter(url) if url else MemoryRateLimiter()
    return _limiter
