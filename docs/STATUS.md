# TrustRelay — status and risk register

Single source of truth for what is built, what is verified, and what is not. Updated 2026-11-11 (end of Phase 1 build).
Status values: NOT STARTED · IN PROGRESS · BLOCKED · TESTING · APPROVED · REJECTED. "TESTING" means built and
covered by automated tests, awaiting owner review; only the owner moves an item to APPROVED.

## Phase overview

| Phase | Status |
|---|---|
| 1 — Build | TESTING (handover: [handover/phase-1.md](handover/phase-1.md)) |
| 2 — Benchmark and validation | NOT STARTED |
| 3–5 | NOT STARTED |
| Production deployment | NOT STARTED — requires explicit owner approval |

## Phase 1 workstreams

| Workstream | Status | Verified by | Not done / limits |
|---|---|---|---|
| Architecture docs (system, schema, API, auth, engine/AI/TI, privacy, environments) | TESTING | Review; OpenAPI exported from code | Hosting provider and IdP choice open (Phase 5) |
| Database schema and migrations | TESTING | upgrade/downgrade/upgrade + `alembic check` | — |
| Authentication, sessions, MFA, RBAC | TESTING | API tests | No email verification or password reset (needs email provider); no breached-password check |
| Analysis engine: website, message, advert, QR, payment | TESTING | 40 engine tests | Accuracy not measured (Phase 2); brand list ~42 entries, hand-curated |
| Evidence and scoring (5 categories, explainable rules) | TESTING | engine tests | — |
| Threat-intel integrations | TESTING (mock only) | mock providers in tests | Google Safe Browsing, URLhaus, RDAP never called against real services; GSB commercial terms (R-03) |
| AI analysis (Claude) | TESTING (mock only) | mock provider, sanitiser and injection tests | Never called against the real API; no DPA yet |
| Privacy controls (encryption, retention, export, deletion, no admin content access) | TESTING | API tests | Legal/DPO review not done (R-01) |
| Security controls (rate limits, lockout, SSRF, uploads, headers, audit) | TESTING | API and engine tests; bandit, pip-audit, npm audit clean | No external pentest (R-05) |
| Web app (onboarding, check, result, history, family, settings, guidance) | TESTING | type-check, production build, Playwright smoke test, i18n tests | Accessibility audit not done; payments not built |
| Admin console (users, plans, stats, sources, AI costs, errors, security, abuse, flags, config, support) | TESTING | API tests for every admin endpoint's access rules; UI type-checked and built | UI not covered by e2e test |
| Mobile app (Flutter, Android + iOS) | TESTING (partial) | `flutter analyze`, unit/widget tests, live API contract test | Not built into APK/IPA, not run on any device (AC-19 BLOCKED); family management, MFA setup, export only on web |
| CI | TESTING | `.github/workflows/ci.yml` | First run happens on the Phase 1 pull request |
| Docker images / compose | IN PROGRESS | — | Written but never built (no Docker daemon in the build environment) |
| Payments / subscriptions billing | NOT STARTED | — | Plans can be set manually by admins; billing is Phase 5 |
| Email (verification, reset, notifications) | NOT STARTED | — | Needs provider selection |
| Push notifications | NOT STARTED | — | Preferences stored only |

## Risk register

| ID | Risk | Likelihood | Impact | Mitigation / next step | Owner | Status |
|---|---|---|---|---|---|---|
| R-01 | GDPR/CNIL non-compliance (DPIA, lawful basis, children's data, sub-processors) | Medium | High | Privacy-by-design controls in place; commission legal/DPO review before any real user data | Owner + legal | IN PROGRESS |
| R-02 | Users read "no known warning signals" as "safe" and get scammed | Medium | High | Wording, disclaimers and tests forbid safety claims; validate wording with user research in Phase 2 | Product | TESTING |
| R-03 | Google Safe Browsing Lookup API is for non-commercial use only | High | High | Use Google Web Risk (paid) or other licensed feeds for commercial launch; budget decision needed | Owner | NOT STARTED |
| R-04 | Detection quality unknown (false negatives / false positives) | High | High | Phase 2 labelled FR/EN benchmark with targets per verdict | Phase 2 | NOT STARTED |
| R-05 | Undiscovered vulnerabilities | Medium | High | Automated scans clean; external pentest before launch | Owner | NOT STARTED |
| R-06 | AI provider cost overrun or outage | Medium | Medium | Opt-in AI, monthly budget cap enforced, engine works without AI, admin kill switch | Engineering | TESTING |
| R-07 | Credential stuffing with breached passwords | Medium | Medium | Lockout + rate limit in place; add breached-password check (k-anonymity) and passkeys | Engineering | IN PROGRESS |
| R-08 | XSS impact increased by CSP `'unsafe-inline'` | Low | Medium | No HTML injection sinks in code; move to nonce-based CSP | Engineering | NOT STARTED |
| R-09 | Retention for audit logs, tickets and operational tables not defined | Medium | Medium | Define with legal; implement purge jobs | Owner + legal | NOT STARTED |
| R-10 | Mobile app untested on real devices | High | Medium | Build and test on Android/iOS devices in an environment with SDKs | Engineering | BLOCKED |
| R-11 | Brand registry and official links become outdated | Medium | Medium | Quarterly review; link checks before launch (guidance page notes this) | Customer success | NOT STARTED |
| R-12 | Active URL probing could expose infrastructure or alert scammers | Low (off) | Medium | Keep off until isolated egress network exists | Engineering | TESTING |
| R-13 | Key management: loss of encryption keys makes data unrecoverable; leak exposes content | Low | High | Store keys in a managed KMS/secret manager; documented rotation; backups of key material | Engineering | NOT STARTED |
| R-14 | Single Python process rate limiting bypass when Redis is absent | Low | Low | Production config requires Redis | Engineering | TESTING |

## Bugs found and fixed during Phase 1 verification

| Found by | Problem | Fix |
|---|---|---|
| Browser e2e test | `TR_CORS_ORIGINS` documented as comma-separated but only JSON parsed (startup crash) | Parse comma-separated; regression test |
| Browser e2e test | Explicit links with a TLD missing from the offline suffix list were silently ignored | Keep and flag them (`url_unrecognised_tld`); test |
| Result screenshot review | Website findings showed the message-rule limitation text | Dedicated limitation |
| Code review | AI defaulted to on when preferences were missing | Opt-in everywhere |
| Code review | AI monthly budget shown but not enforced; `family_protection` flag had no effect | Enforced; tests |
| Dependency audit | Critical advisories in the dev-only test runner (vitest/tinypool) | Upgraded to vitest 5.1.0 |
