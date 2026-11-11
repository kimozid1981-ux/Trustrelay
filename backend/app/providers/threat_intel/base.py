"""Threat-intelligence provider interface.

Providers receive only URLs / domains — never user identity or the surrounding message. Each provider
declares its terms-of-use constraints in `TERMS` so legal review can audit them (docs/architecture/05-analysis-engine.md).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ReputationHit:
    url: str
    threat_type: str  # e.g. MALWARE, SOCIAL_ENGINEERING, phishing
    source: str
    reference: str | None = None  # public reference URL if the source provides one


@dataclass
class DomainInfo:
    domain: str
    created_at: datetime | None = None
    registrar: str | None = None
    source: str = "rdap"


@dataclass
class ProviderResult:
    source: str
    ok: bool
    hits: list[ReputationHit] = field(default_factory=list)
    error: str | None = None
    latency_ms: int = 0


class ReputationProvider(ABC):
    name: str = "base"
    TERMS: str = ""

    @abstractmethod
    async def check_urls(self, urls: list[str]) -> ProviderResult: ...


class DomainAgeProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def lookup(self, domain: str) -> DomainInfo | None: ...
