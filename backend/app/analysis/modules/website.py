"""Website / URL analysis: structure, impersonation, reputation, domain age, redirects, TLS."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from app.analysis.brands import PHISHING_DOMAIN_WORDS, brand_for_registrable_domain, official_labels
from app.analysis.deps import EngineDeps
from app.analysis.extract import ParsedURL, parse_url
from app.analysis.types import AnalysisContext, Confidence, Finding, Severity, SourceCheck

MODULE = "website"

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "rb.gy",
    "t.ly",
    "s.id",
    "tiny.cc",
    "lnkd.in",
    "bl.ink",
    "short.io",
}
# TLDs disproportionately used in abuse according to public abuse reports; a weak signal on its own.
HIGH_ABUSE_TLDS = {
    "top",
    "xyz",
    "icu",
    "click",
    "buzz",
    "cfd",
    "sbs",
    "rest",
    "monster",
    "cyou",
    "quest",
    "bond",
    "zip",
    "mov",
    "lol",
    "live",
    "online",
    "site",
    "store",
    "shop",
    "info",
    "support",
}

_CONFUSABLES = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "$": "s",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ӏ": "l",
    }
)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _skeleton(label: str) -> str:
    return label.lower().translate(_CONFUSABLES).replace("rn", "m").replace("vv", "w").replace("-", "")


def structural_findings(p: ParsedURL) -> list[Finding]:
    out: list[Finding] = []
    ev = [p.host]
    if p.has_userinfo:
        out.append(Finding(MODULE, "url_userinfo_trick", Severity.STRONG, Confidence.HIGH, "rules:website", [p.url[:200]]))
    if p.is_ip:
        out.append(Finding(MODULE, "url_ip_address_host", Severity.MODERATE, Confidence.MEDIUM, "rules:website", ev))
        return out
    if p.scheme == "http":
        out.append(Finding(MODULE, "url_no_https", Severity.MODERATE, Confidence.LOW, "rules:website", ev))
    if p.port and p.port not in (80, 443):
        out.append(
            Finding(MODULE, "url_unusual_port", Severity.MODERATE, Confidence.LOW, "rules:website", [f"{p.host}:{p.port}"])
        )
    if p.registrable in URL_SHORTENERS:
        out.append(Finding(MODULE, "url_shortener", Severity.INFO, Confidence.HIGH, "rules:website", ev))
    tld = p.suffix.rsplit(".", 1)[-1]
    if tld in HIGH_ABUSE_TLDS:
        out.append(
            Finding(MODULE, "url_high_abuse_tld", Severity.MODERATE, Confidence.LOW, "rules:website", ev, {"tld": "." + tld})
        )
    if p.host_ascii.startswith("xn--") or ".xn--" in p.host_ascii:
        out.append(
            Finding(
                MODULE,
                "url_punycode_domain",
                Severity.MODERATE,
                Confidence.MEDIUM,
                "rules:website",
                [f"{p.host} ({p.host_ascii})"],
            )
        )
    if p.subdomain.count(".") >= 3:
        out.append(Finding(MODULE, "url_many_subdomains", Severity.MODERATE, Confidence.LOW, "rules:website", ev))

    official = brand_for_registrable_domain(p.registrable)
    if official:
        out.append(
            Finding(
                MODULE,
                "url_official_domain",
                Severity.INFO,
                Confidence.HIGH,
                "rules:brand_registry",
                ev,
                {"brand": official.name},
            )
        )
        return out

    labels = official_labels()
    domain_label = p.registrable.split(".")[0]
    skeleton = _skeleton(domain_label)
    # 1. brand name embedded in subdomain while the registrable domain belongs to someone else
    sub_tokens = set(p.subdomain.replace("-", ".").split("."))
    for label, brand in labels.items():
        if label in sub_tokens:
            out.append(
                Finding(
                    MODULE,
                    "url_brand_in_subdomain",
                    Severity.STRONG,
                    Confidence.HIGH,
                    "rules:brand_registry",
                    ev,
                    {"brand": brand.name, "registrable": p.registrable},
                )
            )
            return out
    # 2. lookalike of an official label (typosquat / homoglyph)
    for label, brand in labels.items():
        if skeleton == label and domain_label != label:
            out.append(
                Finding(
                    MODULE,
                    "url_lookalike_domain",
                    Severity.STRONG,
                    Confidence.HIGH,
                    "rules:brand_registry",
                    ev,
                    {"brand": brand.name, "official": brand.official_domains[0]},
                )
            )
            return out
        if len(label) >= 5 and 0 < _levenshtein(skeleton, label) <= (1 if len(label) < 8 else 2):
            out.append(
                Finding(
                    MODULE,
                    "url_lookalike_domain",
                    Severity.STRONG,
                    Confidence.MEDIUM,
                    "rules:brand_registry",
                    ev,
                    {"brand": brand.name, "official": brand.official_domains[0]},
                )
            )
            return out
    # 3. brand keyword plus a phishing word in the registrable domain, e.g. "laposte-suivi-colis.com"
    parts = set(domain_label.split("-"))
    for label, brand in labels.items():
        if label in parts and len(parts) > 1:
            conf = Confidence.HIGH if parts & set(PHISHING_DOMAIN_WORDS) else Confidence.MEDIUM
            out.append(
                Finding(
                    MODULE,
                    "url_brand_keyword_domain",
                    Severity.STRONG,
                    conf,
                    "rules:brand_registry",
                    ev,
                    {"brand": brand.name, "official": brand.official_domains[0]},
                )
            )
            return out
    return out


async def run(ctx: AnalysisContext, deps: EngineDeps) -> None:
    parsed = [p for p in (parse_url(u) for u in ctx.urls) if p]
    if not parsed:
        return
    for p in parsed:
        if p.registrable and p.registrable not in ctx.identified_domains:
            ctx.identified_domains.append(p.registrable)
        for f in structural_findings(p):
            ctx.add(f)

    urls = [p.url for p in parsed]
    await _check_reputation(ctx, deps, urls)

    if deps.domain_age:
        await _check_domain_age(ctx, deps, [p for p in parsed if not p.is_ip])
    else:
        ctx.add_missing("domain_age_unavailable")

    if deps.active_probing:
        await _probe(ctx, deps, parsed[:3])
    else:
        ctx.add_missing("redirects_not_resolved")
        ctx.add_missing("certificate_not_checked")


async def _check_reputation(ctx: AnalysisContext, deps: EngineDeps, urls: list[str]) -> None:
    if not deps.reputation:
        ctx.add_missing("no_reputation_source")
        return
    results = await asyncio.gather(*(prov.check_urls(urls) for prov in deps.reputation), return_exceptions=True)
    any_ok = False
    for prov, res in zip(deps.reputation, results, strict=True):
        if isinstance(res, BaseException):
            ctx.sources.append(SourceCheck(prov.name, False, detail=type(res).__name__))
            continue
        ctx.sources.append(SourceCheck(res.source, res.ok, detail=res.error))
        if res.ok:
            any_ok = True
            # The local list is curated, not an independent feed: it counts for findings but not for coverage.
            if prov.name != "trustrelay_blocklist":
                ctx.reputation_checked_urls.update(urls)
        for hit in res.hits:
            ctx.add(
                Finding(
                    MODULE,
                    "url_listed_malicious",
                    Severity.KNOWN_MALICIOUS,
                    Confidence.HIGH,
                    res.source,
                    [hit.url[:200]],
                    {"threat_type": hit.threat_type, "reference": hit.reference or ""},
                )
            )
    if not any_ok or not ctx.reputation_checked_urls:
        ctx.add_missing("no_reputation_source")


async def _check_domain_age(ctx: AnalysisContext, deps: EngineDeps, parsed: list[ParsedURL]) -> None:
    assert deps.domain_age is not None
    domains = list(dict.fromkeys(p.registrable for p in parsed))[:5]
    for d in domains:
        try:
            info = await asyncio.wait_for(deps.domain_age.lookup(d), timeout=6.0)
        except Exception as exc:  # noqa: BLE001 - provider failures are reported, not raised
            ctx.sources.append(SourceCheck(deps.domain_age.name, False, detail=type(exc).__name__))
            ctx.add_missing("domain_age_unavailable")
            continue
        ctx.sources.append(SourceCheck(deps.domain_age.name, True))
        if not info or not info.created_at:
            ctx.add_missing("domain_age_unavailable")
            continue
        age_days = (datetime.now(UTC) - info.created_at).days
        if age_days < 30:
            ctx.add(
                Finding(
                    MODULE, "domain_recently_registered", Severity.MODERATE, Confidence.HIGH, info.source, [d], {"days": age_days}
                )
            )
        else:
            ctx.add(Finding(MODULE, "domain_age_known", Severity.INFO, Confidence.HIGH, info.source, [d], {"days": age_days}))


async def _probe(ctx: AnalysisContext, deps: EngineDeps, parsed: list[ParsedURL]) -> None:
    from app.providers.safe_fetch import fetch_certificate, resolve_redirects

    for p in parsed:
        res = await resolve_redirects(
            p.url if "://" in p.url else "http://" + p.url, max_redirects=deps.probe_max_redirects, timeout=deps.probe_timeout
        )
        ctx.sources.append(
            SourceCheck("link_probe", res.blocked_reason is None and res.error is None, detail=res.blocked_reason or res.error)
        )
        if res.blocked_reason:
            ctx.add(
                Finding(
                    MODULE,
                    "url_points_to_private_network",
                    Severity.STRONG,
                    Confidence.MEDIUM,
                    "link_probe",
                    [p.host],
                    {"reason": res.blocked_reason},
                )
                if res.blocked_reason == "non_public_address"
                else Finding(
                    MODULE,
                    "url_probe_refused",
                    Severity.INFO,
                    Confidence.HIGH,
                    "link_probe",
                    [p.host],
                    {"reason": res.blocked_reason},
                )
            )
        if res.too_many_redirects:
            ctx.add(Finding(MODULE, "url_redirect_loop", Severity.MODERATE, Confidence.MEDIUM, "link_probe", [p.host]))
        if res.final_url and res.final_url != res.hops[0].url:
            final = parse_url(res.final_url)
            if final and final.registrable != p.registrable:
                ctx.add(
                    Finding(
                        MODULE,
                        "url_redirects_elsewhere",
                        Severity.INFO if p.registrable in URL_SHORTENERS else Severity.MODERATE,
                        Confidence.HIGH,
                        "link_probe",
                        [p.host, final.host],
                        {"final_domain": final.registrable, "hops": len(res.hops) - 1},
                    )
                )
                if final.registrable not in ctx.identified_domains:
                    ctx.identified_domains.append(final.registrable)
                for f in structural_findings(final):
                    ctx.add(f)
                if res.final_url not in ctx.urls:
                    await _check_reputation(ctx, deps, [res.final_url])
        if p.scheme == "https" or (res.final_url or "").startswith("https://"):
            host = parse_url(res.final_url).host_ascii if res.final_url and parse_url(res.final_url) else p.host_ascii
            cert = await fetch_certificate(host, deps.probe_timeout)
            ctx.sources.append(
                SourceCheck("tls_check", cert.valid or (cert.error or "").startswith("cert_verify"), detail=cert.error)
            )
            if not cert.valid and (cert.error or "").startswith("cert_verify"):
                ctx.add(Finding(MODULE, "tls_certificate_invalid", Severity.STRONG, Confidence.HIGH, "tls_check", [host]))
            elif cert.valid and cert.not_before and (datetime.now(UTC) - cert.not_before).days < 7:
                ctx.add(
                    Finding(
                        MODULE,
                        "tls_certificate_very_new",
                        Severity.INFO,
                        Confidence.HIGH,
                        "tls_check",
                        [host],
                        {"days": (datetime.now(UTC) - cert.not_before).days},
                    )
                )
