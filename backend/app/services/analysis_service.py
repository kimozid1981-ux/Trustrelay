"""Persisting, running and rendering analyses. The only place where analysis content is decrypted."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.deps import EngineDeps, build_deps
from app.analysis.pipeline import analyse
from app.analysis.types import AnalysisInput
from app.core.config import get_settings
from app.core.crypto import get_keyring
from app.core.storage import get_decrypted, get_store
from app.db.models import AIUsage, Analysis, FeatureFlag, Finding, ThreatSourceHealth, Upload, UserPreferences
from app.i18n import catalog

log = logging.getLogger(__name__)

_deps: EngineDeps | None = None


def get_engine_deps() -> EngineDeps:
    global _deps
    if _deps is None:
        _deps = build_deps()
    return _deps


def set_engine_deps(deps: EngineDeps | None) -> None:
    """Test hook."""
    global _deps
    _deps = deps


def _aad(analysis_id: uuid.UUID, field: str) -> bytes:
    # Bind ciphertext to its row and column: a ciphertext copied elsewhere will not decrypt.
    return f"analysis:{analysis_id}:{field}".encode()


def enc(analysis_id: uuid.UUID, field: str, value: Any) -> bytes:
    data = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return get_keyring().encrypt_text(data, _aad(analysis_id, field))


def dec(analysis_id: uuid.UUID, field: str, blob: bytes | None, as_json: bool = False) -> Any:
    if blob is None:
        return None
    text = get_keyring().decrypt_text(blob, _aad(analysis_id, field))
    return json.loads(text) if as_json else text


async def disabled_modules(db: AsyncSession) -> set[str]:
    res = await db.execute(select(FeatureFlag).where(FeatureFlag.key.like("module.%")))
    return {f.key.removeprefix("module.") for f in res.scalars() if not f.enabled}


async def run_analysis(db: AsyncSession, analysis_id: uuid.UUID) -> None:
    a = await db.get(Analysis, analysis_id)
    if a is None or a.status not in ("queued", "processing"):
        return
    a.status = "processing"
    a.started_at = datetime.now(UTC)
    await db.commit()

    prefs = await db.get(UserPreferences, a.user_id)
    text = dec(a.id, "input", a.input_enc)
    image = None
    upload: Upload | None = None
    if a.upload_id:
        upload = await db.get(Upload, a.upload_id)
        if upload:
            image = await get_decrypted(upload.storage_key)
    base = get_engine_deps()
    deps = EngineDeps(**{**base.__dict__, "disabled_modules": await disabled_modules(db)})
    try:
        result = await analyse(
            AnalysisInput(kind=a.kind, text=text, image_png=image, language=a.language,
                          allow_ai=bool(prefs.allow_ai_processing) if prefs else True),
            deps,
            max_chars=get_settings().max_text_chars,
        )
    except Exception as exc:  # noqa: BLE001 - mark failed, never leave the row stuck
        log.exception("analysis failed")
        a.status = "failed"
        a.error_code = type(exc).__name__[:64]
        a.completed_at = datetime.now(UTC)
        await db.commit()
        return

    for i, f in enumerate(result.findings):
        fid = uuid.uuid4()
        a.findings.append(Finding(
            id=fid, position=i, module=f.module, code=f.code, severity=f.severity.value, confidence=f.confidence.value,
            source=f.source, checked_at=f.checked_at, ai_generated=f.ai_generated,
            details_enc=get_keyring().encrypt_text(json.dumps({"evidence": f.evidence, "params": f.params}, ensure_ascii=False),
                                                   f"finding:{fid}".encode()),
        ))
    a.verdict = result.verdict.value
    a.confidence = result.confidence.value
    a.modules_run = result.modules_run
    a.sources_checked = [{"source": s.source, "ok": s.ok, "checked_at": s.checked_at.isoformat(), "detail": s.detail}
                         for s in result.sources]
    a.ai_used = result.ai_used
    a.result_enc = enc(a.id, "result", {
        "missing": result.missing,
        "recommended_action": result.recommended_action,
        "organisations": result.identified_organisations,
        "domains": result.identified_domains,
        "extracted": result.extracted,
    })
    label = (result.identified_domains[:1] or result.identified_organisations[:1] or [None])[0]
    if label:
        a.label_enc = enc(a.id, "label", label)
    a.status = "completed"
    a.completed_at = datetime.now(UTC)

    if prefs and prefs.retention_days == 0:
        # "Don't keep my content": drop the submission now, keep the result for 24h so the user can read it.
        a.input_enc = None
        a.expires_at = datetime.now(UTC) + timedelta(days=1)
        if upload:
            await get_store().delete(upload.storage_key)
            await db.delete(upload)
            a.upload_id = None

    await _record_provider_health(db, result.sources)
    for r in result.ai_results:
        db.add(AIUsage(provider=r.provider, model=r.model, input_tokens=r.input_tokens, output_tokens=r.output_tokens,
                       cost_micro_eur=r.cost_micro_eur, latency_ms=r.latency_ms, success=r.ok, error_code=r.error))
    await db.commit()


async def _record_provider_health(db: AsyncSession, sources: list[Any]) -> None:
    now = datetime.now(UTC)
    for s in sources:
        row = await db.get(ThreatSourceHealth, s.source)
        if row is None:
            row = ThreatSourceHealth(source=s.source, success_count=0, failure_count=0, total_latency_ms=0)
            db.add(row)
        if s.ok:
            row.success_count += 1
            row.last_success_at = now
        else:
            row.failure_count += 1
            row.last_failure_at = now
            row.last_error = (s.detail or "error")[:120]


def render(a: Analysis, language: str, *, simple: bool = False, include_input: bool = True) -> dict[str, Any]:
    language = catalog.lang(language)
    out: dict[str, Any] = {
        "id": str(a.id),
        "kind": a.kind,
        "status": a.status,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "completed_at": a.completed_at.isoformat() if a.completed_at else None,
        "expires_at": a.expires_at.isoformat() if a.expires_at else None,
        "label": dec(a.id, "label", a.label_enc),
        "note": dec(a.id, "note", a.note_enc),
        "language": language,
    }
    if include_input:
        out["input"] = dec(a.id, "input", a.input_enc)
        out["has_image"] = a.upload_id is not None
    if a.status != "completed":
        out["error_code"] = a.error_code
        return out
    result = dec(a.id, "result", a.result_enc, as_json=True) or {}
    findings = []
    for f in a.findings:
        details = json.loads(get_keyring().decrypt_text(f.details_enc, f"finding:{f.id}".encode()))
        texts = catalog.render_finding(f.code, f.source, details.get("params", {}), language)
        findings.append({
            "code": f.code,
            "module": f.module,
            "severity": f.severity,
            "confidence": f.confidence,
            "confidence_label": catalog.render_confidence(f.confidence, language),
            "source": f.source,
            "source_name": texts["source_name"],
            "checked_at": f.checked_at.isoformat(),
            "ai_generated": f.ai_generated,
            "title": texts["title"],
            "explanation": texts["detail"],
            "evidence": details.get("evidence", []),
            "limitation": texts["limitation"],
        })
    verdict = catalog.render_verdict(a.verdict or "insufficient_information", language, simple=simple)
    action_code = result.get("recommended_action", "action_verify_independently")
    out.update({
        "verdict": a.verdict,
        "verdict_title": verdict["title"],
        "verdict_summary": verdict["summary"],
        "confidence": a.confidence,
        "confidence_label": catalog.render_confidence(a.confidence or "low", language),
        "recommended_action": {"code": action_code, "text": catalog.render_action(action_code, language)},
        "identified_organisations": result.get("organisations", []),
        "identified_domains": result.get("domains", []),
        "findings": findings,
        "missing_information": [{"code": m, "text": catalog.render_missing(m, language)} for m in result.get("missing", [])],
        "sources_checked": a.sources_checked,
        "modules_run": a.modules_run,
        "ai_used": a.ai_used,
        "extracted": result.get("extracted", {}),
        "disclaimer": _DISCLAIMER[language],
    })
    return out


_DISCLAIMER = {
    "en": "TrustRelay gives an evidence-based opinion, not a guarantee. When in doubt, contact the organisation through its official channels.",
    "fr": "TrustRelay donne un avis fondé sur des éléments vérifiables, pas une garantie. En cas de doute, contactez l'organisme par ses canaux officiels.",
}


async def delete_analysis(db: AsyncSession, a: Analysis) -> None:
    if a.upload_id:
        up = await db.get(Upload, a.upload_id)
        if up:
            await get_store().delete(up.storage_key)
            await db.delete(up)
    await db.delete(a)


async def purge_expired(db: AsyncSession) -> dict[str, int]:
    """Retention job: delete expired analyses, orphan uploads, old sessions and old audit logs."""
    from sqlalchemy import text

    now = datetime.now(UTC)
    expired = (await db.execute(select(Analysis).where(Analysis.expires_at < now))).scalars().all()
    for a in expired:
        await delete_analysis(db, a)
    ups = (await db.execute(select(Upload).where(Upload.expires_at < now))).scalars().all()
    for u in ups:
        await get_store().delete(u.storage_key)
        await db.delete(u)
    from app.db.models import AuthSession

    s_res = await db.execute(delete(AuthSession).where(AuthSession.expires_at < now - timedelta(days=7)))
    await db.execute(text("SET LOCAL trustrelay.audit_purge = 'on'"))
    a_res = await db.execute(text("DELETE FROM audit_logs WHERE occurred_at < now() - interval '400 days'"))
    await db.commit()
    return {"analyses": len(expired), "uploads": len(ups), "sessions": s_res.rowcount or 0, "audit_logs": a_res.rowcount or 0}
