# Acceptance criteria (Phase 1)

Each criterion is measurable and mapped to how it is verified. "Automated" means it runs in CI on every pull
request. Status values follow the programme: NOT STARTED, IN PROGRESS, BLOCKED, TESTING, APPROVED, REJECTED. Only the
owner can mark APPROVED.

| ID | Criterion | Verification | Status |
|---|---|---|---|
| AC-01 | A user can register, complete onboarding, analyse a message and see the result, in a real browser | Playwright `e2e/smoke.spec.ts` | TESTING |
| AC-02 | Every completed analysis returns exactly one of the 5 verdict categories, a confidence, a recommended action and a disclaimer | API tests + engine tests | TESTING |
| AC-03 | Every finding shows evidence, source, date checked, confidence and limitation, in FR and EN | `test_every_finding_code_has_fr_and_en_text`, web/mobile rendering tests | TESTING |
| AC-04 | No user-facing string claims absolute safety | i18n tests (web `messages.test.ts`, mobile `strings_test.dart`), `test_official_domain_is_never_called_safe` | TESTING |
| AC-05 | A threat-intel listing always yields "known malicious"; AI alone never yields "strong" or "known malicious" and cannot downgrade | engine tests | TESTING |
| AC-06 | When a link was not checked by any reputation source, the verdict is never "no known warning signals" | `test_no_reputation_source_gives_insufficient_information` | TESTING |
| AC-07 | User content is unreadable in the database without the application keys | `test_content_is_encrypted_at_rest` | TESTING |
| AC-08 | Admin and security roles cannot retrieve any user content; support only with an unexpired user grant | API tests | TESTING |
| AC-09 | Export returns all user data; deletion removes all user rows and stored files | API tests | TESTING |
| AC-10 | Retention 0 stores no input; expired data is purged by the daily job | API tests | TESTING |
| AC-11 | Staff endpoints require MFA; refresh-token reuse revokes the session chain; lockout after 5 failures | API tests | TESTING |
| AC-12 | No server-side request reaches a non-public IP | SSRF tests | TESTING |
| AC-13 | Uploads that are not valid images are rejected; accepted images are re-encoded | upload tests | TESTING |
| AC-14 | Migrations upgrade and downgrade cleanly, and models match migrations | `alembic upgrade/downgrade`, `alembic check` in CI | TESTING |
| AC-15 | Lint, type check, security scan and dependency audit report no issues | CI | TESTING |
| AC-16 | Web app builds for production; mobile app passes `flutter analyze` and tests | CI | TESTING |
| AC-17 | Detection quality: precision/recall per verdict on a labelled FR/EN dataset | Phase 2 benchmark | NOT STARTED |
| AC-18 | p95 latency of a text analysis < 3 s without AI, < 10 s with AI, at expected load | Phase 2/5 load test | NOT STARTED |
| AC-19 | Mobile app installs and runs on a physical Android and iOS device | Device testing | BLOCKED (no Android SDK or Xcode in the build environment) |
| AC-20 | WCAG 2.1 AA for the core journey | Accessibility audit | NOT STARTED (basic semantics and labels in place) |
