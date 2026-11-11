"""RFC 9457 problem-details error responses. Internal errors never leak stack traces or content."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("trustrelay.errors")


class ApiError(Exception):
    def __init__(self, status: int, code: str, detail: str, headers: dict[str, str] | None = None,
                 extra: dict | None = None):
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail
        self.headers = headers
        self.extra = extra or {}


def _problem(request: Request, status: int, code: str, detail: str, **extra: object) -> dict:
    return {
        "type": f"https://docs.trustrelay.example/errors/{code}",
        "title": code.replace("_", " ").capitalize(),
        "status": status,
        "code": code,
        "detail": detail,
        "instance": request.url.path,
        "request_id": getattr(request.state, "request_id", None),
        **extra,
    }


def install(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            _problem(request, exc.status, exc.code, exc.detail, **exc.extra),
            status_code=exc.status,
            headers=exc.headers,
            media_type="application/problem+json",
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Only field locations and messages; never echo the submitted values back.
        errors = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()]
        return JSONResponse(
            _problem(request, 422, "validation_error", "The request is invalid", errors=errors),
            status_code=422,
            media_type="application/problem+json",
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return JSONResponse(
            _problem(request, exc.status_code, code, str(exc.detail)),
            status_code=exc.status_code,
            media_type="application/problem+json",
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"request_id": getattr(request.state, "request_id", None)})
        try:
            from app.db.models import ErrorEvent
            from app.db.session import get_sessionmaker

            async with get_sessionmaker()() as db:
                route = request.scope.get("route")
                db.add(ErrorEvent(route=getattr(route, "path", request.url.path)[:120],
                                  error_type=type(exc).__name__[:120],
                                  request_id=getattr(request.state, "request_id", None)))
                await db.commit()
        except Exception:  # noqa: BLE001 - error recording must never mask the original error
            log.warning("could not record error event")
        return JSONResponse(
            _problem(request, 500, "internal_error", "An unexpected error occurred"),
            status_code=500,
            media_type="application/problem+json",
        )
