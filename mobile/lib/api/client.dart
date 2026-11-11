import 'dart:async';
import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;

/// Base URL of the backend. Set at build time: `--dart-define=TR_API_URL=https://api.example`.
/// The default targets a backend on the developer machine as seen from the Android emulator.
const String kApiBaseUrl = String.fromEnvironment('TR_API_URL', defaultValue: 'http://10.0.2.2:8000');

class ApiException implements Exception {
  ApiException(this.status, this.code, this.detail);
  final int status;
  final String code;
  final String detail;
  @override
  String toString() => detail;
}

/// Where the refresh token is persisted. Production uses the OS keystore (Keychain / Android Keystore);
/// tests use [MemoryTokenStore].
abstract class TokenStore {
  Future<String?> read();
  Future<void> write(String? token);
}

class SecureTokenStore implements TokenStore {
  static const _key = 'tr_refresh_token';
  final _storage = const FlutterSecureStorage();
  @override
  Future<String?> read() => _storage.read(key: _key);
  @override
  Future<void> write(String? token) => token == null ? _storage.delete(key: _key) : _storage.write(key: _key, value: token);
}

class MemoryTokenStore implements TokenStore {
  String? value;
  @override
  Future<String?> read() async => value;
  @override
  Future<void> write(String? token) async => value = token;
}

/// Minimal API client. The access token lives only in memory; the refresh token (rotated on every use by
/// the server) is kept in secure storage. A 401 triggers one refresh and one retry.
class ApiClient {
  ApiClient({http.Client? httpClient, TokenStore? store, this.baseUrl = kApiBaseUrl})
      : _http = httpClient ?? http.Client(),
        _store = store ?? SecureTokenStore();

  final http.Client _http;
  final TokenStore _store;
  final String baseUrl;
  String? _access;
  String locale = 'fr';
  Future<bool>? _refreshing;

  bool get signedIn => _access != null;

  Uri _uri(String path) => Uri.parse('$baseUrl/api/v1$path');

  Future<void> _acceptTokens(Map<String, dynamic> body) async {
    _access = body['access_token'] as String?;
    final refresh = body['refresh_token'] as String?;
    if (refresh != null) await _store.write(refresh);
  }

  Future<bool> restoreSession() => _refresh();

  Future<bool> _refresh() => _refreshing ??= () async {
        try {
          final token = await _store.read();
          if (token == null) return false;
          final res = await _http.post(_uri('/auth/refresh'),
              headers: {'Content-Type': 'application/json'}, body: jsonEncode({'refresh_token': token}));
          if (res.statusCode != 200) {
            _access = null;
            await _store.write(null);
            return false;
          }
          await _acceptTokens(jsonDecode(res.body) as Map<String, dynamic>);
          return true;
        } finally {
          _refreshing = null;
        }
      }();

  Future<dynamic> call(String method, String path, {Object? body, bool retry = true}) async {
    final headers = <String, String>{'Accept-Language': locale};
    if (_access != null) headers['Authorization'] = 'Bearer $_access';
    if (body != null) headers['Content-Type'] = 'application/json';
    final req = http.Request(method, _uri(path))..headers.addAll(headers);
    if (body != null) req.body = jsonEncode(body);
    final res = await http.Response.fromStream(await _http.send(req));
    return _handle(res, retry ? () => call(method, path, body: body, retry: false) : null);
  }

  Future<dynamic> upload(String filename, List<int> bytes, {bool retry = true}) async {
    final req = http.MultipartRequest('POST', _uri('/uploads'))
      ..headers['Accept-Language'] = locale
      ..files.add(http.MultipartFile.fromBytes('file', bytes, filename: filename));
    if (_access != null) req.headers['Authorization'] = 'Bearer $_access';
    final res = await http.Response.fromStream(await _http.send(req));
    return _handle(res, retry ? () => upload(filename, bytes, retry: false) : null);
  }

  Future<dynamic> _handle(http.Response res, Future<dynamic> Function()? again) async {
    if (res.statusCode == 401 && again != null && await _refresh()) return again();
    if (res.statusCode >= 400) {
      var code = 'http_error';
      var detail = 'HTTP ${res.statusCode}';
      try {
        final p = jsonDecode(res.body) as Map<String, dynamic>;
        code = p['code'] as String? ?? code;
        detail = p['detail'] as String? ?? detail;
      } catch (_) {}
      throw ApiException(res.statusCode, code, detail);
    }
    if (res.statusCode == 204 || res.body.isEmpty) return null;
    return jsonDecode(utf8.decode(res.bodyBytes));
  }

  Future<void> login(String email, String password, {String? totp}) async {
    final r = await call('POST', '/auth/login',
        body: {'email': email, 'password': password, 'client': 'mobile', 'totp_code': ?totp}, retry: false);
    await _acceptTokens(r as Map<String, dynamic>);
  }

  Future<void> register(String email, String password, String? displayName, String locale) async {
    final r = await call('POST', '/auth/register',
        body: {
          'email': email,
          'password': password,
          'display_name': displayName,
          'locale': locale,
          'accept_terms': true,
          'client': 'mobile',
        },
        retry: false);
    await _acceptTokens(r as Map<String, dynamic>);
  }

  Future<void> logout() async {
    try {
      await call('POST', '/auth/logout', retry: false);
    } catch (_) {
      // Signing out locally must succeed even when the server is unreachable.
    }
    _access = null;
    await _store.write(null);
  }

  /// Forget local credentials without calling the server (used after account deletion).
  Future<void> forget() async {
    _access = null;
    await _store.write(null);
  }
}
