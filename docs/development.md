# Developer guide

Tested on Linux with Python 3.13, Node 22, Flutter 3.50, PostgreSQL 16 and Redis 7.

## Backend

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # development defaults work without secrets
createdb trustrelay              # or: docker compose up -d db redis (see below)
alembic upgrade head
uvicorn app.main:app --reload    # http://localhost:8000/docs
python -m app.cli create-staff --email you@example.com --role admin   # staff must then enable MFA in Settings
```

Tests need a database `trustrelay_test` owned by user `trustrelay` (password `trustrelay`) on localhost:

```bash
pytest -q                 # 72 tests
ruff check . && ruff format --check . && bandit -q -r app -ll && pip-audit
```

## Web

```bash
cd web
npm ci
npm run dev               # http://localhost:3000, proxies /api/v1 to TRUSTRELAY_API_URL (default :8000)
npm run typecheck && npm test && npm run build
npx playwright test --trace off   # starts its own backend (port 8100) and web (3100); needs database trustrelay_e2e
```

`TRUSTRELAY_API_URL` is read at build time; rebuild after changing it.

## Mobile

```bash
cd mobile
flutter pub get && flutter analyze && flutter test
flutter run --dart-define=TR_API_URL=http://10.0.2.2:8000   # Android emulator to local backend
```

## Local services with Docker (not verified in the Phase 1 build environment, which has no Docker daemon)

```bash
docker compose up -d db redis
```

## Conventions

- Every user-facing analysis text lives in `backend/app/i18n/catalog.py` (FR + EN); a test fails if a finding code lacks text.
- New finding codes need: the module emitting them, catalog text with a limitation, a test.
- Never log or audit user content. Never add a "safe" verdict.
