# 04 — Authentication and authorisation

Status: **TESTING** — implemented in `backend/app/api/routes/auth.py`, `backend/app/core/security.py`,
`backend/app/api/deps.py`; covered by `backend/tests/test_api.py`.

## Decision

Phase 1 uses TrustRelay's own authentication (email + password, optional TOTP) because it keeps the stack simple and
fully testable locally. The token design is standard (short-lived JWT + rotating opaque refresh token), so moving to a
managed or self-hosted OIDC identity provider (e.g. Keycloak or Zitadel, EU-hosted) later only changes how tokens are
issued. That choice is an open decision for Phase 5 (see `docs/STATUS.md`).

## Credentials

- Passwords: Argon2id (`argon2-cffi` defaults), minimum 10 characters, maximum 256, must not contain the part of the email
  before `@`, must not be highly repetitive (fewer than 5 distinct characters). No composition rules (NIST SP 800-63B). Breached-password screening is not implemented yet (risk R-07).
- Login lockout: 5 consecutive failures lock the account for 15 minutes; the response does not reveal whether the
  email exists.
- TOTP (RFC 6238) via `pyotp`; the secret is stored encrypted; each 30-second step can be used once
  (`totp_last_step`) to prevent replay. **Staff roles (admin, support, security) must have MFA enabled** and the access
  token must carry `amr: ["pwd","otp"]` to call staff endpoints (`TR_REQUIRE_ADMIN_MFA`, on by default).

## Tokens

| Token | Format | Lifetime | Storage |
|---|---|---|---|
| Access | JWT HS256 with `sub`, `sid`, `role`, `amr`, `exp` | 15 min | Memory only (web and mobile) |
| Refresh | 256-bit random, only its SHA-256 is stored | 30 days | Web: `HttpOnly; Secure; SameSite=Strict` cookie `tr_refresh` scoped to `/api/v1/auth`. Mobile: OS keystore via `flutter_secure_storage` |

- **Rotation with reuse detection**: every refresh issues a new refresh token and marks the old one rotated. Presenting
  an already-rotated token revokes the whole chain (the session family) — a stolen token stops working for everyone.
- Web refresh requests must carry `X-Requested-With: trustrelay` (CSRF defence in addition to SameSite=Strict).
- Changing the password revokes the user's other sessions. Disabling an account or changing its role makes existing
  access tokens fail on the next request (the `role` claim and `is_active` are checked against the database on every
  call, `test_role_change_invalidates_existing_tokens`). Deleting the account deletes all sessions.
- Users can list and revoke their sessions (`/me/sessions`).

## Roles (RBAC)

| Role | Can |
|---|---|
| `user` | Own analyses, profile, family, support tickets |
| `support` | Ticket queue; view an analysis **only** through a user-issued, unexpired grant |
| `security` | Read-only: stats, threat-source health, errors, security events, abuse signals, audit logs (no user management, AI costs, flags or config) |
| `admin` | Everything above except user content; user management, plans (manual), feature flags, configuration |

Roles are enforced server-side by `require_roles(...)` dependencies; the web admin console only hides tabs for
convenience. Ownership checks return `404` (not `403`) for other users' analyses so IDs cannot be probed.

## Not yet implemented

Email verification, password reset by email, and "new sign-in" notifications all need an email provider (Phase 5).
Until then an admin can deactivate an account and a user can change their password while signed in.
Passkeys/WebAuthn: recommended for a later phase.
