"""Analysis orchestrator: input -> extraction -> modules -> AI (optional) -> correlation -> scoring."""

from __future__ import annotations

import asyncio
import logging

from app.analysis import scoring
from app.analysis.brands import BRANDS_BY_ID
from app.analysis.deps import EngineDeps
from app.analysis.extract import extract_emails, extract_ibans, extract_phones, extract_urls, mask_iban, normalize_text
from app.analysis.modules import qr, text_modules, website
from app.analysis.types import (
    AnalysisContext,
    AnalysisInput,
    AnalysisResult,
    Confidence,
    Finding,
    Severity,
    SourceCheck,
)

log = logging.getLogger(__name__)

TEXT_KINDS = {"message", "advert", "payment", "image", "qr"}
AI_SEVERITY = {"high": Confidence.MEDIUM, "medium": Confidence.MEDIUM, "low": Confidence.LOW}


async def analyse(inp: AnalysisInput, deps: EngineDeps, max_chars: int = 20_000) -> AnalysisResult:
    ctx = AnalysisContext(input=inp)
    raw_text = normalize_text(inp.text or "")[:max_chars]

    # 1. Obtain the text to analyse
    if inp.kind == "url":
        ctx.urls = extract_urls(raw_text, limit=1) or []
        if not ctx.urls:
            ctx.add_missing("url_not_parseable")
    elif inp.kind == "qr":
        payloads: list[str] = []
        if inp.image_png:
            try:
                payloads = await asyncio.to_thread(qr.decode_qr_png, inp.image_png)
            except Exception:  # noqa: BLE001 - image decoding must never crash the job
                payloads = []
            ctx.sources.append(SourceCheck("qr_decoder", bool(payloads), detail=None if payloads else "no_qr_found"))
        elif raw_text:
            payloads = [raw_text]  # decoded on the device
        if not payloads:
            ctx.add_missing("qr_not_decoded")
        for pl in payloads[:3]:
            qr.classify_payload(ctx, normalize_text(pl)[:max_chars])
    else:
        ctx.text = raw_text

    if inp.kind == "image" and inp.image_png:
        await _ai_pass(ctx, deps, image=True)
        if not ctx.text:
            ctx.add_missing("image_text_not_extracted")

    # 2. Deterministic extraction
    if ctx.text:
        for u in extract_urls(ctx.text):
            if u not in ctx.urls:
                ctx.urls.append(u)
        ctx.ibans.extend(i for i in extract_ibans(ctx.text) if i not in ctx.ibans)
        ctx.phones = extract_phones(ctx.text)
        ctx.emails = extract_emails(ctx.text)
        text_modules.detect_claimed_brands(ctx)

    # 3. Modules
    if ctx.urls and "website" not in deps.disabled_modules:
        ctx.modules_run.append("website")
        await website.run(ctx, deps)
    if ctx.text and inp.kind in TEXT_KINDS:
        if "message" not in deps.disabled_modules:
            ctx.modules_run.append("message")
            await text_modules.run_message(ctx, deps)
        if inp.kind == "advert" and "advert" not in deps.disabled_modules:
            ctx.modules_run.append("advert")
            await text_modules.run_advert(ctx, deps)
    if (inp.kind == "payment" or ctx.ibans) and "payment" not in deps.disabled_modules:
        ctx.modules_run.append("payment")
        await text_modules.run_payment(ctx, deps)
    if inp.kind == "qr":
        ctx.modules_run.insert(0, "qr")

    # 4. Optional AI signals on text (not for bare URLs: nothing to read)
    if ctx.text and inp.kind != "image" and inp.kind != "url":
        await _ai_pass(ctx, deps, image=False)

    # 5. Correlation and scoring
    await text_modules.correlate(ctx, deps)
    verdict, confidence, action = scoring.decide(ctx)

    return AnalysisResult(
        verdict=verdict,
        confidence=confidence,
        findings=scoring.sort_findings(ctx.findings),
        sources=ctx.sources,
        missing=ctx.missing,
        modules_run=ctx.modules_run,
        recommended_action=action,
        identified_organisations=[BRANDS_BY_ID[b].name for b in ctx.claimed_brands],
        identified_domains=ctx.identified_domains,
        extracted={
            "urls": ctx.urls[:20],
            "ibans_masked": [mask_iban(i) for i in ctx.ibans],
            "phones": ctx.phones,
            "emails": ctx.emails,
            "qr_payload": ctx.qr_payload,
            "text_origin": ctx.text_origin if ctx.text else None,
        },
        ai_used=ctx.ai_used,
        ai_results=ctx.ai_results,
    )


async def _ai_pass(ctx: AnalysisContext, deps: EngineDeps, *, image: bool) -> None:
    if not ctx.input.allow_ai or deps.ai.name == "null":
        if image:
            ctx.add_missing("ai_disabled")
        return
    try:
        res = await deps.ai.analyse(
            text=None if image else ctx.text,
            image_png=ctx.input.image_png if image else None,
            language=ctx.input.language,
        )
    except Exception as exc:  # noqa: BLE001 - provider bugs must not fail the analysis
        log.warning("ai provider error: %s", type(exc).__name__)
        ctx.sources.append(SourceCheck(f"ai:{deps.ai.name}", False, detail=type(exc).__name__))
        return
    ctx.ai_results.append(res)
    ctx.sources.append(SourceCheck(f"ai:{res.provider}", res.ok, detail=res.error))
    if not res.ok:
        return
    ctx.ai_used = True
    if image and res.extracted_text:
        ctx.text = normalize_text(res.extracted_text)
        ctx.text_origin = "ai_ocr"
    for sig in res.signals:
        ctx.add(
            Finding(
                module="ai",
                code=sig.code,
                severity=Severity.MODERATE,  # capped: AI alone never yields strong / known-malicious
                confidence=AI_SEVERITY[sig.confidence],
                source=f"ai:{res.provider}",
                evidence=[sig.evidence_quote],
                ai_generated=True,
            )
        )
