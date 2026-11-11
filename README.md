# TrustRelay

AI-assisted consumer protection: helps people decide whether an online offer, website, QR code, email, SMS or payment
request deserves their trust. TrustRelay gives an evidence-based opinion in five categories and never claims that
something is 100% safe.

| Path | What |
|---|---|
| `backend/` | FastAPI API, analysis engine, worker, migrations (Python 3.13, PostgreSQL 16, Redis) |
| `web/` | Next.js web app and admin console (FR/EN) |
| `mobile/` | Flutter app for Android and iOS (FR/EN) |
| `docs/` | Architecture, API, security, privacy, acceptance criteria, **[status and risk register](docs/STATUS.md)**, handover reports |

Getting started: [docs/development.md](docs/development.md). Nothing is deployed; production deployment requires
explicit owner approval.
