# TrustRelay mobile (Flutter, Android and iOS)

Screens: sign-in / registration (with TOTP when enabled), onboarding (retention choice, opt-in AI consent),
check (link, message, screenshot, QR code via gallery or camera, advert, payment request), analysis result,
history, family (join a group, read shared warnings), settings (language, retention, AI consent, sign out,
account deletion). French and English; analysis explanations come localised from the API.

Security: the access token is kept in memory only; the refresh token is stored with `flutter_secure_storage`
(iOS Keychain / Android Keystore) and rotated on every refresh. Release builds only allow HTTPS.

```bash
flutter pub get
flutter analyze
flutter test                                    # unit + widget tests (mocked HTTP)
TR_LIVE_API_URL=http://localhost:8000 flutter test test/live_contract_test.dart   # against a running backend
flutter run --dart-define=TR_API_URL=http://10.0.2.2:8000                        # Android emulator
```

Not yet done in Phase 1 (see docs/STATUS.md): APK/IPA builds and device testing (no Android SDK or Xcode in the
build environment), app icons and store assets, family group creation and invitations (web only for now),
password change, MFA setup and data export (web only for now), push notifications.
