import 'package:material_ui/material_ui.dart';

import '../api/client.dart';
import '../app_state.dart';

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});
  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  bool _register = false, _needTotp = false, _accept = false, _busy = false;
  String? _error;
  final _email = TextEditingController(), _password = TextEditingController();
  final _name = TextEditingController(), _totp = TextEditingController();

  Future<void> _submit(AppState app) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      if (_register) {
        await app.api.register(_email.text.trim(), _password.text, _name.text.trim().isEmpty ? null : _name.text.trim(), app.locale);
      } else {
        await app.api.login(_email.text.trim(), _password.text, totp: _needTotp ? _totp.text.trim() : null);
      }
      await app.reloadMe();
    } on ApiException catch (e) {
      setState(() => e.code == 'mfa_code_required' ? _needTotp = true : _error = e.detail);
    } catch (_) {
      setState(() => _error = app.s.t('error'));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    return Scaffold(
      appBar: AppBar(title: const Text('TrustRelay'), actions: [
        TextButton(
            onPressed: () => app.setLocale(app.locale == 'fr' ? 'en' : 'fr'),
            child: Text(app.locale == 'fr' ? 'English' : 'Français')),
      ]),
      body: SafeArea(
        child: ListView(padding: const EdgeInsets.all(20), children: [
          Text(s.t('tagline'), style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 16),
          Text(_register ? s.t('register') : s.t('login'), style: Theme.of(context).textTheme.headlineSmall),
          if (_error != null) Padding(padding: const EdgeInsets.only(top: 12), child: _ErrorText(_error!)),
          const SizedBox(height: 12),
          TextField(
              key: const Key('email'),
              controller: _email,
              keyboardType: TextInputType.emailAddress,
              autofillHints: const [AutofillHints.email],
              decoration: InputDecoration(labelText: s.t('email'))),
          TextField(
              key: const Key('password'),
              controller: _password,
              obscureText: true,
              autofillHints: [_register ? AutofillHints.newPassword : AutofillHints.password],
              decoration: InputDecoration(labelText: s.t('password'), helperText: _register ? s.t('passwordHint') : null)),
          if (_register) TextField(controller: _name, decoration: InputDecoration(labelText: s.t('displayName'))),
          if (_needTotp)
            TextField(
                controller: _totp,
                keyboardType: TextInputType.number,
                maxLength: 6,
                autofillHints: const [AutofillHints.oneTimeCode],
                decoration: InputDecoration(labelText: s.t('totp'))),
          if (_register)
            CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                value: _accept,
                onChanged: (v) => setState(() => _accept = v ?? false),
                title: Text(s.t('acceptTerms'))),
          const SizedBox(height: 16),
          FilledButton(
              onPressed: _busy || (_register && !_accept) ? null : () => _submit(app),
              child: Text(_register ? s.t('register') : s.t('login'))),
          TextButton(
              onPressed: () => setState(() {
                    _register = !_register;
                    _error = null;
                  }),
              child: Text(_register ? s.t('haveAccount') : s.t('noAccount'))),
        ]),
      ),
    );
  }
}

class _ErrorText extends StatelessWidget {
  const _ErrorText(this.text);
  final String text;
  @override
  Widget build(BuildContext context) =>
      Semantics(liveRegion: true, child: Text(text, style: TextStyle(color: Theme.of(context).colorScheme.error)));
}
