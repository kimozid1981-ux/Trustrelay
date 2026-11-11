import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:trustrelay/api/client.dart';

http.Response _json(int status, Object body) =>
    http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json'});

void main() {
  test('login stores the rotated refresh token and sends the bearer token', () async {
    final store = MemoryTokenStore();
    final seen = <String, String?>{};
    final client = ApiClient(
      store: store,
      baseUrl: 'http://api',
      httpClient: MockClient((req) async {
        seen[req.url.path] = req.headers['Authorization'];
        if (req.url.path.endsWith('/auth/login')) {
          final body = jsonDecode(req.body) as Map<String, dynamic>;
          expect(body['client'], 'mobile');
          expect(body.containsKey('totp_code'), isFalse);
          return _json(200, {'access_token': 'A1', 'refresh_token': 'R1', 'expires_in': 900, 'mfa': false, 'role': 'user'});
        }
        return _json(200, {'ok': true});
      }),
    );
    await client.login('a@example.com', 'pw');
    expect(store.value, 'R1');
    await client.call('GET', '/me');
    expect(seen['/api/v1/me'], 'Bearer A1');
  });

  test('a 401 triggers one refresh with the stored token, then one retry', () async {
    final store = MemoryTokenStore()..value = 'R1';
    var meCalls = 0;
    final client = ApiClient(
      store: store,
      baseUrl: 'http://api',
      httpClient: MockClient((req) async {
        if (req.url.path.endsWith('/auth/refresh')) {
          expect(jsonDecode(req.body), {'refresh_token': 'R1'});
          return _json(200, {'access_token': 'A2', 'refresh_token': 'R2', 'expires_in': 900, 'mfa': false, 'role': 'user'});
        }
        meCalls++;
        return req.headers['Authorization'] == 'Bearer A2' ? _json(200, {'email': 'x'}) : _json(401, {'code': 'unauthorized', 'detail': 'no'});
      }),
    );
    final r = await client.call('GET', '/me') as Map<String, dynamic>;
    expect(r['email'], 'x');
    expect(meCalls, 2);
    expect(store.value, 'R2', reason: 'refresh tokens rotate');
  });

  test('a rejected refresh clears local credentials and surfaces the problem detail', () async {
    final store = MemoryTokenStore()..value = 'stolen-or-expired';
    final client = ApiClient(
      store: store,
      baseUrl: 'http://api',
      httpClient: MockClient((req) async => req.url.path.endsWith('/auth/refresh')
          ? _json(401, {'code': 'invalid_refresh', 'detail': 'Session expired'})
          : _json(401, {'code': 'unauthorized', 'detail': 'Please sign in'})),
    );
    await expectLater(
        client.call('GET', '/me'), throwsA(isA<ApiException>().having((e) => e.detail, 'detail', 'Please sign in')));
    expect(store.value, isNull);
    expect(client.signedIn, isFalse);
  });

  test('Accept-Language follows the UI language', () async {
    String? lang;
    final client = ApiClient(
        store: MemoryTokenStore(),
        baseUrl: 'http://api',
        httpClient: MockClient((req) async {
          lang = req.headers['Accept-Language'];
          return _json(200, {});
        }))
      ..locale = 'en';
    await client.call('GET', '/healthz');
    expect(lang, 'en');
  });
}
