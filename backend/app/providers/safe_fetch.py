"""SSRF-guarded probing of user-submitted URLs.

What it does: resolve redirects hop by hop (HEAD, falling back to a GET whose body is never read beyond a
small cap) and read TLS certificate metadata. What it never does: render pages, run scripts, send cookies or
credentials, follow non-HTTP schemes, or connect to non-public addresses.

The guard is enforced at *connect time* inside a custom httpcore network backend: every TCP connection
resolves the hostname itself, rejects the connection if ANY resolved address is non-public, and connects to
the validated IP. This closes the DNS-rebinding gap between "check" and "connect".
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

ALLOWED_PORTS = {80, 443}
_EXTRA_BLOCKED = [
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 can reach IPv4 internals
    ipaddress.ip_network("2002::/16"),  # 6to4
]


class BlockedDestination(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or not addr.is_global
    ):
        return False
    return not any(addr in net for net in _EXTRA_BLOCKED if net.version == addr.version)


async def resolve_public(host: str, port: int) -> str:
    """Resolve and return one public IP, or raise BlockedDestination if any address is not public."""
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        candidates = [host]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=3.0
            )
        except (TimeoutError, socket.gaierror) as exc:
            raise BlockedDestination("dns_failure") from exc
        candidates = list(dict.fromkeys(str(i[4][0]) for i in infos))
    if not candidates:
        raise BlockedDestination("dns_failure")
    for ip in candidates:
        if not is_public_ip(ip):
            raise BlockedDestination("non_public_address")
    return candidates[0]


class _GuardedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self) -> None:
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if port not in ALLOWED_PORTS:
            raise BlockedDestination("port_not_allowed")
        ip = await resolve_public(host, port)
        return await self._inner.connect_tcp(ip, port, timeout=timeout, local_address=local_address)

    async def connect_unix_socket(self, *args: Any, **kwargs: Any) -> httpcore.AsyncNetworkStream:
        raise BlockedDestination("unix_socket_not_allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def guarded_client(timeout: float) -> httpx.AsyncClient:
    transport = httpx.AsyncHTTPTransport(retries=0)
    # Replace the pool with one that uses the guarded backend (httpx exposes no public hook for this).
    transport._pool = httpcore.AsyncConnectionPool(  # noqa: SLF001
        ssl_context=ssl.create_default_context(),
        max_connections=4,
        network_backend=_GuardedBackend(),
    )
    return httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout, connect=min(3.0, timeout)),
        follow_redirects=False,
        trust_env=False,  # never route user-supplied URLs through environment proxies
        headers={"User-Agent": "TrustRelay-LinkCheck/0.1 (+https://trustrelay.example/bot)"},
        max_redirects=0,
    )


@dataclass
class Hop:
    url: str
    status: int | None


@dataclass
class ProbeResult:
    hops: list[Hop] = field(default_factory=list)
    final_url: str | None = None
    blocked_reason: str | None = None
    error: str | None = None
    too_many_redirects: bool = False


def validate_url_for_probe(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BlockedDestination("scheme_not_allowed")
    if parts.username or parts.password:
        raise BlockedDestination("userinfo_not_allowed")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise BlockedDestination("invalid_port") from exc
    if port not in ALLOWED_PORTS:
        raise BlockedDestination("port_not_allowed")
    if not parts.hostname:
        raise BlockedDestination("no_host")


async def resolve_redirects(url: str, *, max_redirects: int, timeout: float) -> ProbeResult:
    result = ProbeResult()
    current = url
    async with guarded_client(timeout) as client:
        for _ in range(max_redirects + 1):
            try:
                validate_url_for_probe(current)
                resp = await client.request("HEAD", current)
                if resp.status_code in (405, 501):
                    async with client.stream("GET", current) as s:
                        resp = s
                        # never read the body: headers are enough
            except BlockedDestination as exc:
                result.blocked_reason = exc.reason
                result.hops.append(Hop(current, None))
                return result
            except httpx.HTTPError as exc:
                cause = exc.__cause__ or exc.__context__
                if isinstance(cause, BlockedDestination):
                    result.blocked_reason = cause.reason
                else:
                    result.error = type(exc).__name__
                result.hops.append(Hop(current, None))
                return result
            result.hops.append(Hop(current, resp.status_code))
            location = resp.headers.get("location")
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                continue
            result.final_url = current
            return result
    result.too_many_redirects = True
    return result


@dataclass
class CertInfo:
    valid: bool
    error: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None


async def fetch_certificate(host: str, timeout: float) -> CertInfo:
    """Perform a verified TLS handshake to host:443 (public IPs only) and read certificate dates."""
    try:
        ip = await resolve_public(host, 443)
    except BlockedDestination as exc:
        return CertInfo(valid=False, error=exc.reason)
    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=host), timeout=timeout
        )
    except ssl.SSLCertVerificationError as exc:
        return CertInfo(valid=False, error=f"cert_verify:{exc.verify_code}")
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        return CertInfo(valid=False, error=type(exc).__name__)
    try:
        cert = writer.get_extra_info("peercert") or {}
        issuer = None
        for rdn in cert.get("issuer", ()):
            for k, v in rdn:
                if k == "organizationName":
                    issuer = v
        nb = cert.get("notBefore")
        na = cert.get("notAfter")
        fmt = "%b %d %H:%M:%S %Y %Z"
        return CertInfo(
            valid=True,
            issuer=issuer,
            not_before=datetime.strptime(nb, fmt).replace(tzinfo=UTC) if nb else None,
            not_after=datetime.strptime(na, fmt).replace(tzinfo=UTC) if na else None,
        )
    finally:
        writer.close()
        _ = reader
