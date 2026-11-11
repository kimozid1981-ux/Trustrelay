# 03 — API specification

Status: **TESTING**. The machine-readable contract is [`docs/api/openapi.json`](../api/openapi.json), exported from the
running code with `python -m app.cli export-openapi docs/api/openapi.json`. Interactive docs (`/docs`) are served only
when `TR_ENVIRONMENT=development`.

## Conventions

- Base path `/api/v1`. Breaking changes require `/api/v2`.
- JSON in and out; errors use RFC 9457 `application/problem+json` with a stable `code` (e.g. `validation_error`,
  `quota_exceeded`, `mfa_code_required`, `rate_limited`) plus a human `detail`. Validation errors list field locations
  and messages but **never echo submitted values**.
- `Accept-Language: fr|en` selects the language of every explanation in the response.
- Authentication: `Authorization: Bearer <access token>` (see [04-authentication.md](04-authentication.md)).
- Every response carries `X-Request-ID`; security headers are set on every response.
- Rate limits (per user or IP, fixed window): auth 10/min, analyses 20/min, family join 10/min, tickets 5/min.
  Exceeding returns `429` with `Retry-After`.
- Quota: free 30 checks/month, plus/family 300; exceeding returns `402 quota_exceeded`.

## Endpoints (55)

| Area | Method and path | Who |
|---|---|---|
| Health | `GET /healthz` (process up), `GET /readyz` (database reachable) | public |
| Auth | `POST /auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/password` | public / user |
| MFA | `POST /auth/mfa/setup`, `/auth/mfa/enable`, `/auth/mfa/disable` | user |
| Uploads | `POST /uploads` (multipart image, ≤ 8 MB, PNG/JPEG/WebP, re-encoded) | user |
| Analyses | `POST /analyses` → 202; `GET /analyses` (cursor `before`, filter `kind`); `GET /analyses/{id}`; `DELETE /analyses/{id}`; `DELETE /analyses` (all); `PUT /analyses/{id}/note` | owner only |
| Sharing | `POST /analyses/{id}/share` (requires `confirm: true`) | owner, family member allowed to share |
| Support access | `POST /analyses/{id}/support-access` (time-limited grant), `DELETE /support-access/{grant_id}` | owner |
| Usage | `GET /usage` | user |
| Profile | `GET /me`, `PATCH /me`, `PATCH /me/preferences`, `GET /me/sessions`, `DELETE /me/sessions/{id}`, `GET /me/export`, `POST /me/delete` | user |
| Family | `POST /family`, `GET /family`, `POST /family/invites`, `POST /family/join`, `PATCH /family/members/{user_id}`, `DELETE /family/members/{user_id}` | members; owner/guardian for management |
| Support | `GET/POST /support/tickets` | user |
| Staff | `GET /staff/tickets`, `GET/PATCH /staff/tickets/{id}`, `GET /staff/access-grants/{grant_id}/analysis` | support, admin (MFA required) |
| Admin | `GET /admin/stats`, `/admin/users`, `PATCH /admin/users/{id}`, `PUT /admin/users/{id}/subscription`, `GET /admin/threat-sources`, `/admin/ai-usage`, `/admin/errors`, `/admin/security-events`, `/admin/abuse`, `/admin/audit-logs`, `/admin/support-overview`, `GET/PUT /admin/feature-flags[/{key}]`, `GET/PUT /admin/config[/{key}]` | admin (security role: read-only subset) — MFA required |

## The analysis resource

`POST /analyses` body: `{"kind": "url|message|advert|payment|qr|image", "text": "...", "upload_id": "..."}`
(`text` ≤ 20 000 characters; `image` needs `upload_id`; `qr` takes either decoded text or an image).

A completed analysis (abridged):

```json
{
  "id": "…", "kind": "message", "status": "completed", "created_at": "…", "expires_at": "…",
  "label": "ameli-remboursement.example", "note": null,
  "verdict": "strong_suspicious",
  "verdict_title": "Strong warning signs", "verdict_summary": "…",
  "confidence": "medium", "confidence_label": "Medium confidence",
  "recommended_action": {"code": "action_do_not_interact", "text": "…"},
  "identified_organisations": ["Assurance Maladie (ameli)"],
  "identified_domains": ["ameli-remboursement.example"],
  "findings": [{
    "code": "brand_keyword_domain", "module": "website", "severity": "strong", "confidence": "high",
    "confidence_label": "High confidence", "source": "rules:brand_registry", "source_name": "…",
    "checked_at": "…", "ai_generated": false,
    "title": "…", "explanation": "…", "evidence": ["ameli-remboursement.example"], "limitation": "…"
  }],
  "missing_information": [{"code": "redirects_not_resolved", "text": "We did not follow the link…"}],
  "sources_checked": [{"source": "google_safe_browsing", "ok": true, "checked_at": "…", "detail": null}],
  "modules_run": ["message", "website"], "ai_used": false,
  "disclaimer": "TrustRelay gives an evidence-based opinion, not a guarantee…"
}
```

Each finding carries the six elements required by the programme: evidence, source, date checked, confidence,
limitation, and (at analysis level) the recommended action.

## What admins can and cannot call

There is no admin endpoint that returns analysis input, findings evidence, notes or ticket content. Support staff can
read one analysis only through a grant the user created, and only until it expires or is revoked
(`tests/test_api.py::test_admin_never_sees_content`, `::test_support_needs_customer_grant_to_view_analysis`).
