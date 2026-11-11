"""Explainable evidence and scoring engine.

The verdict is one of five categories, decided by documented rules over the findings — no opaque score.
Rules (also in docs/architecture/05-analysis-engine.md):

R1  Any finding of severity KNOWN_MALICIOUS (independent threat-intelligence listing)   -> known_malicious
R2  Any non-AI STRONG finding                                                           -> strong_suspicious
R3  Three or more distinct non-AI MODERATE findings                                     -> strong_suspicious
R4  Any MODERATE finding (AI findings included)                                         -> moderate_warning
R5  Coverage insufficient (nothing analysable, or links not checked by an independent
    reputation source, or too little text)                                              -> insufficient_information
R6  Otherwise                                                                           -> no_known_warning_signals

AI findings can never trigger R1–R3 on their own, and nothing can lower a verdict reached by an earlier rule.
"no_known_warning_signals" is never presented as "safe" (see i18n texts and UI requirements).
"""

from __future__ import annotations

from app.analysis.types import AnalysisContext, Confidence, Finding, Severity, Verdict

MIN_TEXT_CHARS = 20

PAYMENT_CODES = {
    "pay_off_platform",
    "pay_changed_bank_details",
    "pay_friends_and_family",
    "msg_payment_gift_card_or_voucher",
    "msg_payment_crypto",
    "msg_safe_account_scam",
    "iban_country_mismatch",
    "qr_crypto_payment",
}
SECRET_CODES = {"msg_requests_auth_code", "msg_requests_password", "msg_requests_card_details", "qr_authenticator_setup"}


def coverage_problems(ctx: AnalysisContext) -> list[str]:
    problems: list[str] = []
    has_text = len(ctx.text.strip()) >= MIN_TEXT_CHARS
    if not ctx.urls and not has_text and not ctx.ibans and not ctx.qr_payload:
        problems.append("nothing_analysable")
    unchecked = [u for u in ctx.urls if u not in ctx.reputation_checked_urls]
    if unchecked:
        problems.append("links_not_checked_by_reputation_source")
    if any(x.code == "url_shortener" for x in ctx.findings) and "redirects_not_resolved" in ctx.missing:
        problems.append("shortened_link_not_resolved")
    return problems


def decide(ctx: AnalysisContext) -> tuple[Verdict, Confidence, str]:
    f = ctx.findings
    non_ai = [x for x in f if not x.ai_generated]
    malicious = [x for x in f if x.severity == Severity.KNOWN_MALICIOUS]
    strong = [x for x in non_ai if x.severity == Severity.STRONG]
    moderate_codes = {x.code for x in non_ai if x.severity == Severity.MODERATE}
    any_moderate = [x for x in f if x.severity == Severity.MODERATE]
    codes = {x.code for x in f if x.severity != Severity.INFO}

    if malicious:
        return Verdict.KNOWN_MALICIOUS, Confidence.HIGH, "action_do_not_interact"
    if strong or len(moderate_codes) >= 3:
        high = len(strong) >= 2 or any(x.confidence == Confidence.HIGH for x in strong)
        conf = Confidence.HIGH if high else Confidence.MEDIUM
        return Verdict.STRONG_SUSPICIOUS, conf, _strong_action(codes)
    if any_moderate:
        distinct = {x.code for x in any_moderate}
        conf = Confidence.MEDIUM if len(distinct) >= 2 and len(moderate_codes) >= 1 else Confidence.LOW
        action = _strong_action(codes) if codes & (PAYMENT_CODES | SECRET_CODES) else "action_verify_independently"
        return Verdict.MODERATE_WARNING, conf, action
    problems = coverage_problems(ctx)
    if problems:
        for p in problems:
            ctx.add_missing(p)
        return Verdict.INSUFFICIENT_INFORMATION, Confidence.LOW, "action_verify_independently"
    independent_sources = {s.source for s in ctx.sources if s.ok and s.source not in ("trustrelay_blocklist",)}
    conf = Confidence.MEDIUM if (ctx.urls and len(independent_sources) >= 2) else Confidence.LOW
    return Verdict.NO_KNOWN_WARNING_SIGNALS, conf, "action_stay_cautious"


def _strong_action(codes: set[str]) -> str:
    if codes & SECRET_CODES:
        return "action_never_share_codes"
    if codes & PAYMENT_CODES:
        return "action_do_not_pay_verify_official"
    return "action_do_not_interact"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    from app.analysis.types import SEVERITY_RANK

    conf_rank = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}
    return sorted(findings, key=lambda x: (-SEVERITY_RANK[x.severity], x.ai_generated, -conf_rank[x.confidence]))
