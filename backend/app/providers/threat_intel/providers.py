"""Concrete threat-intelligence providers.

- Google Safe Browsing v4 Lookup API (API key; Google's terms restrict commercial use — legal review required,
  Web Risk API is Google's commercial alternative).
- abuse.ch URLhaus (Auth-Key required; data under abuse.ch terms of use).
- RDAP (IANA-bootstrapped registry data, public protocol) for domain registration dates.
- Local blocklist (hand-curated, file-based) and a deterministic mock for development/tests.

All network calls go to fixed provider endpoints (no user-controlled hosts), with timeouts and no retries
in the request path.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

import httpx

from app.providers.threat_intel.base import (
    DomainAgeProvider,
    DomainInfo,
    ProviderResult,
    ReputationHit,
    ReputationProvider,
)

_TIMEOUT = httpx.Timeout(5.0, connect=3.0)


class GoogleSafeBrowsing(ReputationProvider):
    name = "google_safe_browsing"
    TERMS = "Safe Browsing Lookup API v4: non-commercial use only; commercial use requires Google Web Risk API."
    ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, api_key: str, client: httpx.AsyncClient | None = None):
        self._key = api_key
        self._client = client

    async def check_urls(self, urls: list[str]) -> ProviderResult:
        started = time.monotonic()
        body = {
            "client": {"clientId": "trustrelay", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls[:500]],
            },
        }
        try:
            async with _client(self._client) as c:
                r = await c.post(self.ENDPOINT, params={"key": self._key}, json=body)
            r.raise_for_status()
            data = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            return ProviderResult(self.name, False, error=type(exc).__name__, latency_ms=_ms(started))
        hits = [
            ReputationHit(url=m["threat"]["url"], threat_type=m.get("threatType", "UNKNOWN"), source=self.name)
            for m in data.get("matches", [])
            if "threat" in m and "url" in m["threat"]
        ]
        return ProviderResult(self.name, True, hits=hits, latency_ms=_ms(started))


class URLhaus(ReputationProvider):
    name = "urlhaus"
    TERMS = "abuse.ch URLhaus: Auth-Key required; see https://urlhaus.abuse.ch/api/ terms."
    ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, auth_key: str, client: httpx.AsyncClient | None = None):
        self._key = auth_key
        self._client = client

    async def check_urls(self, urls: list[str]) -> ProviderResult:
        started = time.monotonic()
        hits: list[ReputationHit] = []
        try:
            async with _client(self._client) as c:
                for u in urls[:10]:
                    r = await c.post(self.ENDPOINT, data={"url": u}, headers={"Auth-Key": self._key})
                    r.raise_for_status()
                    data = r.json()
                    if data.get("query_status") == "ok" and data.get("url_status") in ("online", "offline"):
                        hits.append(
                            ReputationHit(
                                url=u,
                                threat_type=str(data.get("threat") or "malware_download"),
                                source=self.name,
                                reference=data.get("urlhaus_reference"),
                            )
                        )
        except (httpx.HTTPError, ValueError) as exc:
            return ProviderResult(self.name, False, error=type(exc).__name__, latency_ms=_ms(started))
        return ProviderResult(self.name, True, hits=hits, latency_ms=_ms(started))


class LocalBlocklist(ReputationProvider):
    """Exact-host and registrable-domain blocklist curated by the TrustRelay security team."""

    name = "trustrelay_blocklist"
    TERMS = "Internal list. Entries must cite a public source or an internal incident id."

    def __init__(self, path: Path | None = None, entries: set[str] | None = None):
        self._entries = {e.lower() for e in (entries or set())}
        if path and path.exists():
            for line in path.read_text().splitlines():
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    self._entries.add(line)

    async def check_urls(self, urls: list[str]) -> ProviderResult:
        from app.analysis.extract import parse_url

        hits = []
        for u in urls:
            p = parse_url(u)
            if p and (p.host_ascii in self._entries or p.registrable in self._entries):
                hits.append(ReputationHit(url=u, threat_type="phishing", source=self.name))
        return ProviderResult(self.name, True, hits=hits)


class MockReputation(ReputationProvider):
    """Deterministic test double: any host containing 'malicious-test' or ending in '.test-phish' is listed."""

    name = "mock_reputation"

    async def check_urls(self, urls: list[str]) -> ProviderResult:
        hits = [
            ReputationHit(url=u, threat_type="SOCIAL_ENGINEERING", source=self.name)
            for u in urls
            if "malicious-test" in u or ".test-phish" in u
        ]
        return ProviderResult(self.name, True, hits=hits)


class RDAPDomainAge(DomainAgeProvider):
    """RDAP via the rdap.org bootstrap redirector (public). Production should use the IANA bootstrap file."""

    name = "rdap"
    ENDPOINT = "https://rdap.org/domain/"

    def __init__(self, client: httpx.AsyncClient | None = None):
        self._client = client

    async def lookup(self, domain: str) -> DomainInfo | None:
        if not domain or "/" in domain or len(domain) > 253:
            return None
        async with _client(self._client, follow_redirects=True) as c:
            r = await c.get(self.ENDPOINT + domain, headers={"Accept": "application/rdap+json"})
        if r.status_code == 404:
            return DomainInfo(domain=domain, created_at=None, source=self.name)
        r.raise_for_status()
        data = r.json()
        created = None
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                try:
                    created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                except ValueError:
                    created = None
        registrar = None
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                vcard = ent.get("vcardArray", [None, []])[1]
                for item in vcard:
                    if item and item[0] == "fn":
                        registrar = str(item[3])[:100]
        return DomainInfo(domain=domain, created_at=created, registrar=registrar, source=self.name)


class MockDomainAge(DomainAgeProvider):
    """Test double: domains containing 'new-domain' are 3 days old; others 10 years old."""

    name = "mock_rdap"

    async def lookup(self, domain: str) -> DomainInfo | None:
        from datetime import UTC, timedelta

        now = datetime.now(UTC)
        age = timedelta(days=3) if "new-domain" in domain else timedelta(days=3650)
        return DomainInfo(domain=domain, created_at=now - age, source=self.name)


class _client:
    """Use an injected client (tests) or a short-lived one; never inherits proxy env for user hosts."""

    def __init__(self, client: httpx.AsyncClient | None, follow_redirects: bool = False):
        self._given = client
        self._own: httpx.AsyncClient | None = None
        self._follow = follow_redirects

    async def __aenter__(self) -> httpx.AsyncClient:
        if self._given is not None:
            return self._given
        self._own = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=self._follow)
        return self._own

    async def __aexit__(self, *exc: object) -> None:
        if self._own is not None:
            await self._own.aclose()


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
