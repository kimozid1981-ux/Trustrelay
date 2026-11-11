"""Dependencies injected into analysis modules (providers + switches). Built once per process."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.providers.ai.base import AIProvider
from app.providers.ai.providers import AnthropicProvider, MockAIProvider, NullAIProvider
from app.providers.threat_intel.base import DomainAgeProvider, ReputationProvider
from app.providers.threat_intel.providers import (
    GoogleSafeBrowsing,
    LocalBlocklist,
    MockDomainAge,
    MockReputation,
    RDAPDomainAge,
    URLhaus,
)


@dataclass
class EngineDeps:
    reputation: list[ReputationProvider] = field(default_factory=list)
    domain_age: DomainAgeProvider | None = None
    ai: AIProvider = field(default_factory=NullAIProvider)
    active_probing: bool = False
    probe_timeout: float = 4.0
    probe_max_redirects: int = 5
    disabled_modules: set[str] = field(default_factory=set)


BLOCKLIST_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "blocklist.txt"


def build_deps() -> EngineDeps:
    from app.core.config import get_settings

    s = get_settings()
    reputation: list[ReputationProvider] = [LocalBlocklist(BLOCKLIST_PATH)]
    if s.google_safe_browsing_api_key:
        reputation.append(GoogleSafeBrowsing(s.google_safe_browsing_api_key))
    if s.urlhaus_auth_key:
        reputation.append(URLhaus(s.urlhaus_auth_key))
    if s.threat_intel_mock:
        reputation.append(MockReputation())
    domain_age: DomainAgeProvider | None = None
    if s.threat_intel_mock:
        domain_age = MockDomainAge()
    elif s.rdap_enabled:
        domain_age = RDAPDomainAge()
    ai: AIProvider
    if s.ai_provider == "anthropic" and s.anthropic_api_key:
        ai = AnthropicProvider(s.anthropic_api_key, s.anthropic_model, s.ai_timeout_seconds, s.anthropic_effort)
    elif s.ai_provider == "mock":
        ai = MockAIProvider()
    else:
        ai = NullAIProvider()
    return EngineDeps(
        reputation=reputation,
        domain_age=domain_age,
        ai=ai,
        active_probing=s.active_url_probing,
        probe_timeout=s.probe_timeout_seconds,
        probe_max_redirects=s.probe_max_redirects,
    )
