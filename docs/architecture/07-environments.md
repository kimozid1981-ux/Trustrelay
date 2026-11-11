# 07 — Environments

Status: development environment **verified** (this repository's tests run against it). Staging and production are
**NOT STARTED**: nothing has been provisioned or deployed. Hosting selection is Phase 5 and production deployment
requires explicit owner approval.

| | Development | Staging (planned) | Production (planned) |
|---|---|---|---|
| Purpose | Local work and automated tests | Pre-release testing with production-like settings, synthetic data only | Real users |
| `TR_ENVIRONMENT` | `development` | `staging` | `production` |
| Data | Local PostgreSQL 16, test databases recreated per run | Separate database, no copies of production data | EU region, encrypted at rest, point-in-time recovery |
| Secrets | Built-in development defaults (clearly marked) | Secret manager | Secret manager; rotation procedure for `TR_JWT_SECRET` and `TR_ENCRYPTION_KEYS` |
| Threat intel | Mock sources | Real sources with test keys | Real sources under commercial terms |
| AI | `null` or `mock` | Real provider, low budget | Real provider, budget cap, DPA signed |
| Analysis execution | Inline in the API process | Redis + worker | Redis + autoscaled workers |
| Storage | Local directory | S3-compatible bucket | S3-compatible bucket, EU, versioning off for deleted content |
| Active URL probing | Off | Off until isolated egress exists | Off until isolated egress exists |
| API docs (`/docs`) | On | Off | Off |
| Observability | Console logs | Structured logs + metrics | Structured logs, metrics, alerting, uptime checks |

## Safety rails in code

`Settings.validate_for_environment()` refuses to start in staging or production when: the development JWT secret or
encryption key is used, the JWT secret is shorter than 32 characters, analysis is inline instead of on the worker,
Redis is not configured, the refresh cookie is not `Secure`, CORS allows `*`, or a mock threat-intel or AI provider
is enabled
(`test_unsafe_production_config_refuses_to_start`, `test_production_refuses_development_defaults`).

## Configuration

All settings are environment variables prefixed `TR_`, documented in `backend/.env.example` (no secrets) and
`backend/app/core/config.py`. The web app needs only `TRUSTRELAY_API_URL` at build time (`web/.env.example`). The
mobile app takes `--dart-define=TR_API_URL=…` at build time.
