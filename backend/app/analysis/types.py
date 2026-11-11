"""Core data types of the analysis engine. Pure Python, no I/O, no framework imports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    KNOWN_MALICIOUS = "known_malicious"  # an independent threat-intelligence source lists it
    STRONG = "strong"
    MODERATE = "moderate"
    INFO = "info"  # context, missing information, or neutral facts — never raises the verdict


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Verdict(StrEnum):
    KNOWN_MALICIOUS = "known_malicious"
    STRONG_SUSPICIOUS = "strong_suspicious"
    MODERATE_WARNING = "moderate_warning"
    INSUFFICIENT_INFORMATION = "insufficient_information"
    NO_KNOWN_WARNING_SIGNALS = "no_known_warning_signals"


SEVERITY_RANK = {Severity.INFO: 0, Severity.MODERATE: 1, Severity.STRONG: 2, Severity.KNOWN_MALICIOUS: 3}


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class Finding:
    """One piece of evidence. `code` maps to localized title/explanation/limitation/action in app/i18n."""

    module: str
    code: str
    severity: Severity
    confidence: Confidence
    source: str  # e.g. "rules:message", "google_safe_browsing", "rdap", "ai:anthropic"
    evidence: list[str] = field(default_factory=list)  # short excerpts or values, user-derived
    params: dict[str, Any] = field(default_factory=dict)  # values interpolated into localized text
    checked_at: datetime = field(default_factory=utcnow)
    ai_generated: bool = False

    def key(self) -> tuple[str, str]:
        return (self.code, "|".join(sorted(self.evidence))[:200])


@dataclass
class SourceCheck:
    """Record that a source was consulted, whether it answered, and what it could not tell us."""

    source: str
    ok: bool
    checked_at: datetime = field(default_factory=utcnow)
    detail: str | None = None  # error code only, never content


@dataclass
class AnalysisInput:
    kind: str  # url | message | advert | payment | qr | image
    text: str | None = None
    image_png: bytes | None = None
    language: str = "fr"
    allow_ai: bool = True


@dataclass
class AnalysisContext:
    input: AnalysisInput
    text: str = ""  # the text actually analysed (submitted, OCR'd, or decoded from a QR code)
    text_origin: str = "user"  # user | qr_decode | ai_ocr
    urls: list[str] = field(default_factory=list)
    ibans: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    qr_payload: str | None = None
    claimed_brands: list[str] = field(default_factory=list)  # brand ids mentioned in text
    identified_domains: list[str] = field(default_factory=list)  # registrable domains seen
    findings: list[Finding] = field(default_factory=list)
    sources: list[SourceCheck] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)  # codes of information we could not obtain
    modules_run: list[str] = field(default_factory=list)
    ai_used: bool = False
    reputation_checked_urls: set[str] = field(default_factory=set)
    ai_results: list[Any] = field(default_factory=list)  # AIResult objects, for usage/cost accounting

    def add(self, finding: Finding) -> None:
        if finding.key() not in {f.key() for f in self.findings}:
            self.findings.append(finding)

    def add_missing(self, code: str) -> None:
        if code not in self.missing:
            self.missing.append(code)


@dataclass
class AnalysisResult:
    verdict: Verdict
    confidence: Confidence
    findings: list[Finding]
    sources: list[SourceCheck]
    missing: list[str]
    modules_run: list[str]
    recommended_action: str  # action code
    identified_organisations: list[str]
    identified_domains: list[str]
    extracted: dict[str, Any]
    ai_used: bool
    ai_results: list[Any] = field(default_factory=list)
