// Opt-in contract test against a running backend:
//   TR_LIVE_API_URL=http://localhost:8000 flutter test test/live_contract_test.dart
// It uses the real ApiClient so that mobile request/response shapes are verified end to end.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:trustrelay/api/client.dart';
import 'package:trustrelay/api/models.dart';

void main() {
  final base = Platform.environment['TR_LIVE_API_URL'];
  test('register, analyse, read, refresh and delete against the real API', () async {
    final store = MemoryTokenStore();
    final api = ApiClient(baseUrl: base!, store: store)..locale = 'en';
    await api.register('mobile-${DateTime.now().millisecondsSinceEpoch}@example.com', 'Correct-Horse-42!', null, 'en');
    expect(store.value, isNotNull, reason: 'mobile clients receive the refresh token in the body');
    final me = Me.fromJson(await api.call('GET', '/me') as Map<String, dynamic>);
    expect(me.onboardingCompleted, isFalse);

    final created = await api.call('POST', '/analyses', body: {'kind': 'url', 'text': 'http://malicious-test.example.com/login'})
        as Map<String, dynamic>;
    final a = Analysis.fromJson(await api.call('GET', '/analyses/${created['id']}') as Map<String, dynamic>);
    expect(a.verdict, 'known_malicious');
    expect(a.findings, isNotEmpty);

    final before = store.value;
    expect(await api.restoreSession(), isTrue);
    expect(store.value, isNot(before), reason: 'refresh token rotated');

    await api.call('DELETE', '/analyses/${a.id}');
    await api.call('POST', '/me/delete', body: {'password': 'Correct-Horse-42!', 'confirm': 'DELETE'});
  }, skip: base == null ? 'set TR_LIVE_API_URL to run' : false);
}
