"""Message, advertisement and payment-request analysis modules (rule-based, FR + EN)."""

from __future__ import annotations

import re

from app.analysis.brands import BRANDS_BY_ID, brand_for_registrable_domain, brands_mentioned
from app.analysis.deps import EngineDeps
from app.analysis.extract import iban_is_valid, mask_iban, parse_url
from app.analysis.lexicon import ADVERT_RULES, MESSAGE_RULES, PAYMENT_RULES, match_rules
from app.analysis.types import AnalysisContext, Confidence, Finding, Severity


def _apply(ctx: AnalysisContext, module: str, rules, source: str) -> None:  # type: ignore[no-untyped-def]
    for rule, excerpts in match_rules(rules, ctx.text):
        ctx.add(Finding(module, rule.code, rule.severity, rule.confidence, source, excerpts))


def detect_claimed_brands(ctx: AnalysisContext) -> None:
    for b in brands_mentioned(ctx.text):
        if b.id not in ctx.claimed_brands:
            ctx.claimed_brands.append(b.id)


async def run_message(ctx: AnalysisContext, deps: EngineDeps) -> None:
    _apply(ctx, "message", MESSAGE_RULES, "rules:message")


_DISCOUNT_RE = re.compile(
    r"(?:-\s?(\d{2})\s?%)|(?:(\d{2})\s?%\s?(?:de r[ée]duction|de remise|off|discount))|(?:(?:r[ée]duction|remise|discount) de (\d{2})\s?%)",
    re.IGNORECASE,
)


async def run_advert(ctx: AnalysisContext, deps: EngineDeps) -> None:
    _apply(ctx, "advert", ADVERT_RULES, "rules:advert")
    best = 0
    excerpt = ""
    for m in _DISCOUNT_RE.finditer(ctx.text):
        pct = int(next(g for g in m.groups() if g))
        if pct > best:
            best, excerpt = pct, m.group(0)
    if best >= 90:
        ctx.add(
            Finding(
                "advert", "ad_extreme_discount", Severity.STRONG, Confidence.MEDIUM, "rules:advert", [excerpt], {"percent": best}
            )
        )
    elif best >= 70:
        ctx.add(
            Finding(
                "advert",
                "ad_extreme_discount",
                Severity.MODERATE,
                Confidence.MEDIUM,
                "rules:advert",
                [excerpt],
                {"percent": best},
            )
        )


async def run_payment(ctx: AnalysisContext, deps: EngineDeps) -> None:
    _apply(ctx, "payment", PAYMENT_RULES, "rules:payment")
    # Gift cards / crypto are payment red flags whatever the input kind.
    _apply(ctx, "payment", tuple(r for r in MESSAGE_RULES if r.code.startswith("msg_payment_")), "rules:payment")
    claimed = [BRANDS_BY_ID[b] for b in ctx.claimed_brands]
    for iban in ctx.ibans:
        masked = mask_iban(iban)
        if not iban_is_valid(iban):
            ctx.add(Finding("payment", "iban_invalid_checksum", Severity.MODERATE, Confidence.HIGH, "rules:iban", [masked]))
            continue
        country = iban[:2]
        ctx.add(
            Finding(
                "payment",
                "beneficiary_not_verifiable",
                Severity.INFO,
                Confidence.HIGH,
                "rules:iban",
                [masked],
                {"country": country},
            )
        )
        domestic_claims = [
            b for b in claimed if b.country == "FR" and b.category in ("public", "bank", "energy", "telecom", "parcel")
        ]
        if domestic_claims and country != "FR":
            ctx.add(
                Finding(
                    "payment",
                    "iban_country_mismatch",
                    Severity.MODERATE,
                    Confidence.MEDIUM,
                    "rules:iban",
                    [masked],
                    {"country": country, "brand": domestic_claims[0].name},
                )
            )
    if ctx.ibans:
        ctx.add_missing("beneficiary_identity_unverified")


async def correlate(ctx: AnalysisContext, deps: EngineDeps) -> None:
    """Cross-module check: content claiming to come from brand X links to a domain that no known brand owns.

    Moderate on its own (legitimate content can mention a brand and link elsewhere); combined with other signals
    it contributes to escalation in the scoring engine.
    """
    if not ctx.claimed_brands or not ctx.urls:
        return
    for u in ctx.urls:
        p = parse_url(u)
        if not p or p.is_ip:
            continue
        if brand_for_registrable_domain(p.registrable) is not None:
            continue  # links to an official domain of some known organisation
        brand = BRANDS_BY_ID[ctx.claimed_brands[0]]
        ctx.add(
            Finding(
                "correlation",
                "impersonation_link_mismatch",
                Severity.MODERATE,
                Confidence.MEDIUM,
                "rules:brand_registry",
                [brand.name, p.host],
                {"brand": brand.name, "domain": p.registrable, "official": ", ".join(brand.official_domains[:3])},
            )
        )
        return
