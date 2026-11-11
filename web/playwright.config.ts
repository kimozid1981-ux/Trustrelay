import { defineConfig } from "@playwright/test";

// End-to-end smoke tests. They start the real backend (development settings, mock threat intelligence,
// no AI provider) and the production web build. Requires a local PostgreSQL database named in TR_DATABASE_URL.
const db = process.env.E2E_DATABASE_URL ?? "postgresql+asyncpg://trustrelay:trustrelay@localhost:5432/trustrelay_e2e";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  workers: 1,
  use: { baseURL: "http://localhost:3100", trace: "off" },
  webServer: [
    {
      command: "bash -c '${PY:-.venv/bin/python} -m alembic upgrade head && ${PY:-.venv/bin/python} -m uvicorn app.main:app --port 8100'",
      cwd: "../backend",
      url: "http://localhost:8100/healthz",
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        TR_ENVIRONMENT: "development",
        TR_DATABASE_URL: db,
        TR_REDIS_URL: "",
        TR_ANALYSIS_INLINE: "true",
        TR_JWT_SECRET: "e2e-only-secret-not-for-real-use-0123456789abcdef",
        TR_ENCRYPTION_KEYS: "e2e:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        TR_THREAT_INTEL_MOCK: "true",
        TR_AI_PROVIDER: "null",
        TR_CORS_ORIGINS: "http://localhost:3100",
        TR_WEB_REFRESH_COOKIE_SECURE: "false",
        TR_STORAGE_LOCAL_PATH: "./var/e2e-uploads",
      },
    },
    {
      command: "bash -c 'npx next build && npx next start -p 3100'",
      url: "http://localhost:3100/login",
      reuseExistingServer: false,
      timeout: 240_000,
      env: { TRUSTRELAY_API_URL: "http://localhost:8100" },
    },
  ],
});
