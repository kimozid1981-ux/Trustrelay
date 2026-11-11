"""Deterministic extraction of URLs, domains, IBANs, phone numbers and emails from untrusted text."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

# Offline extractor: uses the public-suffix snapshot bundled with tldextract, never fetches at runtime.
_tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_DEFANG = [
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]"), ":"),
]

_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
# Bare domains like "laposte-suivi.com/abc" — validated against the public suffix list afterwards.
_BARE_DOMAIN_RE = re.compile(
    r"(?i)(?<![@\w.-])((?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+"
    r"[a-z¡-￿]{2,24})(/[^\s<>\"'`]*)?"
)
_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]{1,64}@([a-z0-9-]+\.)+[a-z]{2,24}\b")
_IBAN_RE = re.compile(r"\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?)\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+33\s?|0033\s?|0)[1-9](?:[\s.-]?\d{2}){4}(?!\d)|(?<!\d)\+\d{1,3}(?:[\s.-]?\d{2,4}){3,5}(?!\d)")
_TRAILING = ".,;:!?)]}>'\"»"

IBAN_LENGTHS = {
    "FR": 27, "DE": 22, "BE": 16, "ES": 24, "IT": 27, "NL": 18, "LU": 20, "PT": 25, "IE": 22, "GB": 22,
    "CH": 21, "AT": 20, "LT": 20, "PL": 28, "MC": 27, "CY": 28, "MT": 31, "EE": 20, "LV": 21, "FI": 18,
    "GR": 27, "SE": 24, "DK": 18, "NO": 15, "CZ": 24, "SK": 24, "HR": 21, "SI": 19, "RO": 24, "BG": 22,
    "HU": 28, "TR": 26, "AE": 23, "MA": 28, "TN": 24, "SN": 28, "CI": 28,
}


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFC", text)
    # remove zero-width and bidi control characters often used to evade filters
    text = re.sub(r"[​-‏‪-‮⁠-⁤﻿]", "", text)
    for pattern, repl in _DEFANG:
        text = pattern.sub(repl, text)
    return text


@dataclass(frozen=True)
class ParsedURL:
    url: str
    scheme: str
    host: str  # lowercase; IDNA-decoded (unicode) form
    host_ascii: str  # punycode form
    registrable: str  # e.g. "laposte.fr"; empty for IPs
    subdomain: str
    suffix: str
    port: int | None
    path: str
    has_userinfo: bool
    is_ip: bool


def parse_url(raw: str) -> ParsedURL | None:
    raw = raw.strip().rstrip(_TRAILING)
    if not raw:
        return None
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", raw):
        raw = "http://" + raw if raw.lower().startswith("www.") or "/" in raw or "." in raw else raw
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https"):
        return None
    netloc = parts.netloc
    has_userinfo = "@" in netloc
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        return ParsedURL(raw, parts.scheme.lower(), host, host, "", "", "", port, parts.path, has_userinfo, True)
    try:
        host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError:
        host_ascii = host
    try:
        host_unicode = host_ascii.encode("ascii").decode("idna")
    except UnicodeError:
        host_unicode = host
    ext = _tld(host_ascii)
    if not ext.suffix or not ext.domain:
        return None
    registrable = f"{ext.domain}.{ext.suffix}"
    return ParsedURL(
        url=raw,
        scheme=parts.scheme.lower(),
        host=host_unicode,
        host_ascii=host_ascii,
        registrable=registrable,
        subdomain=ext.subdomain,
        suffix=ext.suffix,
        port=port,
        path=parts.path or "/",
        has_userinfo=has_userinfo,
        is_ip=False,
    )


def extract_urls(text: str, limit: int = 20) -> list[str]:
    text = normalize_text(text)
    found: list[str] = []
    spans: list[tuple[int, int]] = []
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(_TRAILING)
        if parse_url(url):
            found.append(url)
            spans.append(m.span())
    email_spans = [m.span() for m in _EMAIL_RE.finditer(text)]
    for m in _BARE_DOMAIN_RE.finditer(text):
        if any(s <= m.start() < e for s, e in spans + email_spans):
            continue
        candidate = m.group(0).rstrip(_TRAILING)
        p = parse_url(candidate)
        # require a real public suffix and avoid treating "e.g." or file names as domains
        if p and p.suffix and not re.search(r"\.(?:jpe?g|png|gif|pdf|docx?|xlsx?|txt|zip)$", p.host):
            found.append(candidate)
    out: list[str] = []
    for u in found:
        if u not in out:
            out.append(u)
    return out[:limit]


def iban_is_valid(iban: str) -> bool:
    iban = iban.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", iban):
        return False
    expected = IBAN_LENGTHS.get(iban[:2])
    if expected and len(iban) != expected:
        return False
    rearranged = iban[4:] + iban[:4]
    digits = "".join(str(int(c, 36)) for c in rearranged)
    return int(digits) % 97 == 1


def extract_ibans(text: str) -> list[str]:
    out: list[str] = []
    for m in _IBAN_RE.finditer(text.upper()):
        iban = m.group(1).replace(" ", "")
        if iban[:2] in IBAN_LENGTHS or len(iban) >= 15:
            if iban not in out:
                out.append(iban)
    return out[:10]


def extract_phones(text: str) -> list[str]:
    out: list[str] = []
    for m in _PHONE_RE.finditer(text):
        p = re.sub(r"[\s.-]", "", m.group(0))
        if p not in out:
            out.append(p)
    return out[:10]


def extract_emails(text: str) -> list[str]:
    out: list[str] = []
    for m in _EMAIL_RE.finditer(text):
        e = m.group(0).lower()
        if e not in out:
            out.append(e)
    return out[:10]


def mask_iban(iban: str) -> str:
    """Show country, check digits and last 4 characters only."""
    return f"{iban[:4]} **** **** {iban[-4:]}" if len(iban) > 8 else "****"
