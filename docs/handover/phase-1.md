# Phase 1 (Build) — handover report

Date: 2026-11-11 · Branch: `claude/project-thread-6grodi` · Status: **TESTING — ready for owner review, not declared complete**

## 1. Summary

The repository was empty at the start of Phase 1. It now contains a working backend (API, analysis engine, worker,
migrations), a web app with an admin console, a Flutter mobile app, architecture and security documentation, CI, and
a status page with a risk register. All automated checks pass in the build environment. Phase 1 is **not** declared
complete because three completion-gate items need things this environment cannot provide or that only the owner can
decide: real-device mobile testing, real threat-intelligence and AI provider calls, and legal review (section 5).

## 2. What was delivered

| Deliverable | Location |
|---|---|
| System and component architecture | `docs/architecture/01-system-architecture.md` |
| Database schema + initial migration | `docs/architecture/02-database-schema.md`, `backend/alembic/versions/0001_initial_schema.py` |
| API specification (55 endpoints) | `docs/architecture/03-api.md`, `docs/api/openapi.json` |
| Authentication design | `docs/architecture/04-authentication.md` |
| AI processing and threat-intel integration | `docs/architecture/05-analysis-engine.md` |
| Data-flow and privacy diagrams | `docs/architecture/06-privacy-data-flows.md` |
| Dev / staging / production specs | `docs/architecture/07-environments.md` |
| Security design and threat model | `docs/security/SECURITY.md` |
| Measurable acceptance criteria | `docs/requirements/acceptance-criteria.md` |
| Status and live risk register | `docs/STATUS.md` |
| Environment templates without secrets | `backend/.env.example`, `web/.env.example` |
| Developer and deployment notes | `docs/development.md`, `backend/Dockerfile`, `docker-compose.yml` (both unverified) |
| Backend: FastAPI, 5 analysis modules, scoring engine, providers, worker, CLI | `backend/` |
| Web app: onboarding, check (6 kinds incl. camera QR), result, history, family, settings, guidance, admin console | `web/` |
| Mobile app: sign-in/MFA, onboarding, check (6 kinds incl. camera QR), result, history, family warnings, settings | `mobile/` |
| CI on every pull request | `.github/workflows/ci.yml` |

## 3. Verification evidence (run on 2026-11-11 in the build environment)

| Check | Result |
|---|---|
| Backend tests (`pytest`) | **72 passed** (40 engine, 30 API, 2 configuration) against PostgreSQL 16 |
| Migrations | upgrade → downgrade → upgrade clean; `alembic check` reports no drift |
| Lint / format / security scan | `ruff check`, `ruff format --check`, `bandit -ll`: no issues |
| Dependency audits | `pip-audit`: no known vulnerabilities; `npm audit`: 0 vulnerabilities (after upgrading the dev test runner) |
| Web | `tsc --noEmit` clean; `next build` succeeds (11 routes); 3 unit tests pass |
| Browser end-to-end (Playwright, Chromium) | **2 passed**: register → onboarding → analyse a phishing SMS → "Known dangerous" result → history → delete; protected pages redirect to sign-in |
| Mobile | `flutter analyze` clean; 7 unit/widget tests pass; live contract test against the running backend passes (register, analyse, read, token rotation, delete) |
| CI on GitHub | Configured; first run will happen on the pull request (results to be checked there) |

The end-to-end and review work found and fixed six real defects (listed in `docs/STATUS.md`), including a startup crash
with the documented CORS setting, scam links on unrecognised TLDs being ignored, AI defaulting to on when preferences
were missing, and an AI budget and a feature flag that were displayed but not enforced.

## 4. What is not done or not verified (honest list)

- **Mobile builds**: no APK/IPA was produced and the app was never run on a device or emulator (no Android SDK or
  Xcode available). Family management, MFA setup and data export exist only on web.
- **Threat intelligence**: Google Safe Browsing and URLhaus clients are implemented but were never called against the
  real services (no keys). Only mock sources were exercised. Google's free Lookup API is non-commercial (R-03).
- **AI**: the Anthropic integration was never called against the real API (no key). Only the mock provider was tested.
- **Accuracy**: no benchmark; detection quality is unknown until Phase 2.
- **Docker**: Dockerfile and compose file were never built or run.
- **Not built**: payments and billing, email (verification, password reset, notifications), push notifications,
  breached-password check, nonce-based CSP, accessibility audit, load testing, external penetration test.
- **Legal**: no GDPR/CNIL review, no DPIA, no privacy policy or terms. No compliance claim is made anywhere.
- **Official links** on the guidance page were checked once by web search on 2026-11-11 and must be re-verified before launch.
- Nothing has been deployed anywhere.

## 5. Completion gate

| Gate item | Met? |
|---|---|
| Core user flows work | Yes on web (browser-tested); mobile verified at API-contract and widget level only |
| APIs | Yes (tested) |
| Migrations | Yes |
| Authentication | Yes |
| Privacy controls | Technically yes (tested); legal review pending |
| Analysis | Yes with mock sources; real sources not exercised |
| Tests pass | Yes |
| No critical vulnerabilities | None known from automated scans; no external pentest |

## 6. Decisions needed from the owner

1. Threat-intel licensing: budget for Google Web Risk (or alternative commercial feeds) — blocks a commercial launch.
2. Provide test API keys (threat intel, AI) for a staging environment so the real integrations can be verified.
3. Legal/DPO review engagement (GDPR, DPIA, children in family groups).
4. An environment with Android SDK / Xcode (or a CI runner) to build and device-test the mobile app.
5. Review and approve (or reject) the Phase 1 pull request.

## 7. Inputs for Phase 2 (benchmark and validation)

- The engine is deterministic and explainable: each verdict is traceable to rules R1–R6 and finding codes, which makes
  per-rule error analysis possible.
- Suggested benchmark: labelled FR/EN set covering parcel, bank-advisor, health-insurance, tax, rental, investment,
  marketplace and QR scams plus legitimate messages from the same brands; measure per-verdict precision/recall and
  the rate of "no known warning signals" on known scams (most important metric).
- Mock providers make offline evaluation reproducible; real-source evaluation needs the keys above.
