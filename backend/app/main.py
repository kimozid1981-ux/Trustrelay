"""FastAPI application factory."""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api import errors
from app.api.routes import admin, analyses, auth, family, health, me, support
from app.core.config import get_settings
from app.db.session import dispose_engine

logging.basicConfig(level=logging.INFO, format='{"level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    get_settings().validate_for_environment()
    yield
    await dispose_engine()


def create_app() -> FastAPI:
    s = get_settings()
    s.validate_for_environment()
    app = FastAPI(
        title="TrustRelay API",
        version="0.1.0",
        description="Evidence-based checks of suspicious links, messages, adverts, QR codes and payment requests.",
        lifespan=lifespan,
        docs_url="/docs" if s.is_dev_like else None,
        redoc_url=None,
        openapi_url=f"{s.api_prefix}/openapi.json",
    )
    errors.install(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "Accept-Language", "X-Requested-With"],
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get("X-Request-ID", "")
        request.state.request_id = rid if rid.isalnum() and len(rid) <= 64 else secrets.token_hex(8)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if not s.is_dev_like:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    app.include_router(health.router)
    for r in (auth.router, analyses.router, me.router, family.router, support.router, admin.router):
        app.include_router(r, prefix=s.api_prefix)
    return app


app = create_app()
