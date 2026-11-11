# Security design, threat model and controls

Status: **TESTING**. No external penetration test or audit has been performed (planned before launch, risk R-05).

## Reporting a vulnerability

Until a security contact is published, report privately to the repository owner. Do not open public issues for
vulnerabilities.

## Assets and attackers

| Asset | Why it matters |
|---|---|
| Content users submit (messages, screenshots, URLs) | Can reveal finances, health, family and contacts |
| Accounts and family groups | Takeover lets an attacker read history or send fake "all clear" warnings to relatives |
| Verdict integrity | A scammer who can make TrustRelay say "no warning signs" turns the product into a weapon |
| Staff consoles | Concentrated access |
| Our servers' network position | Analysing attacker URLs must not let them reach internal services |

Attackers considered: scammers crafting inputs (prompt injection, SSRF bait, malformed images, decompression bombs),
credential stuffers, curious or compromised staff, and a database thief.

## Controls

| Threat | Control | Evidence |
|---|---|---|
| Credential stuffing / brute force | Argon2id, lockout after 5 failures for 15 min, rate limit 10/min on auth, generic errors | `test_login_lockout_and_generic_errors`, `test_rate_limit` |
| Token theft | 15-min access JWT in memory; refresh token httpOnly SameSite=Strict cookie (web) or OS keystore (mobile); rotation with reuse detection revokes the chain | `test_register_login_refresh_rotation_and_reuse_detection`, `test_web_refresh_uses_httponly_cookie_and_csrf_header`, mobile `api_client_test.dart` |
| CSRF | SameSite=Strict + required `X-Requested-With` on cookie refresh; all other calls use bearer tokens | same |
| Forged/tampered tokens | Signature, expiry, session and role checked against DB on every request | `test_tokens_are_rejected_when_tampered_or_missing`, `test_role_change_invalidates_existing_tokens` |
| Staff account takeover | MFA mandatory for staff (TOTP, replay-protected); role checks server-side | `test_admin_requires_role_and_mfa`, `test_mfa_login_and_replay_protection` |
| Broken access control (IDOR) | Ownership enforced in queries; other users' resources return 404 | `test_users_cannot_access_each_others_analyses` |
| Insider access to content | No admin endpoint returns content; support needs a user grant; all staff actions audited; audit log append-only at DB level | `test_admin_never_sees_content`, `test_support_needs_customer_grant_to_view_analysis`, `test_audit_log_is_append_only` |
| Database theft | Field-level AES-256-GCM with associated data; keys outside the DB; key rotation by key ring | `test_content_is_encrypted_at_rest` |
| SSRF via submitted URLs | No fetching by default; when probing is enabled every connection resolves DNS and refuses non-public IPs at connect time (also after redirects and for IPv4-mapped IPv6), proxies from environment ignored, hop-by-hop redirect limit, timeouts | `test_ssrf_guard_rejects_non_public`, `test_probe_never_connects_to_loopback` |
| Malicious uploads | Size limit, magic-byte check, Pillow decode with pixel limit, re-encoded to PNG (strips metadata and payloads), stored encrypted, never served back raw, never executed | `test_upload_sanitizer_rejects_non_images_and_strips_metadata` |
| Prompt injection | Untrusted-content wrapper, schema-only output, closed code list, quote must exist in content, AI capped at moderate, cannot remove other findings | `test_prompt_injection_text_is_inert`, `test_ai_cannot_escalate_alone_or_downgrade`, `test_ai_output_quotes_must_exist_in_content` |
| Obfuscated links | Zero-width/bidi removal, defang handling, punycode and confusable detection, unknown TLDs kept | `test_zero_width_characters_do_not_hide_links`, `test_link_with_unrecognised_tld_is_still_checked` |
| Input abuse | Pydantic validation with length limits; problem+json never echoes values; quotas and rate limits | `test_input_validation`, `test_free_plan_quota` |
| Web attacks (XSS, clickjacking) | React escaping, no `dangerouslySetInnerHTML`; CSP `default-src 'self'`, `frame-ancestors 'none'`, `nosniff`, strict referrer policy; HSTS outside development | `test_security_headers_and_problem_json` |
| Unsafe deployment config | Startup refuses development secrets, mocks, insecure cookies, CORS `*` outside development | `test_unsafe_production_config_refuses_to_start` |
| Secrets in the repository | `.env` ignored; only `.env.example` without values committed | review of git history |
| Vulnerable dependencies | `pip-audit` and `npm audit` clean on 2026-11-11; pinned versions | CI job |
| Static analysis | `ruff` (incl. flake8-bandit rules) and `bandit` clean | CI job |

## Known gaps (tracked in `docs/STATUS.md`)

- No breached-password check (HIBP k-anonymity) — R-07.
- CSP allows `'unsafe-inline'` scripts because Next.js inline bootstrap needs it; nonce-based CSP planned — R-08.
- Rate limiting is per process unless Redis is configured (production config requires Redis).
- No WAF/bot protection, no external pentest, no SAST beyond ruff/bandit, mobile app not tested on devices.
- Access tokens remain valid up to 15 minutes after logout of *another* session (bounded by role/active checks).
