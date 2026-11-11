import 'package:material_ui/material_ui.dart';

import '../api/client.dart';
import '../app_state.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  Future<void> _pref(AppState app, Map<String, dynamic> patch) async {
    await app.api.call('PATCH', '/me/preferences', body: patch);
    await app.reloadMe();
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    final me = app.me!;
    return ListView(padding: const EdgeInsets.all(16), children: [
      Text(s.t('navSettings'), style: Theme.of(context).textTheme.headlineSmall),
      Text(me.email),
      const SizedBox(height: 12),
      DropdownButtonFormField<String>(
        initialValue: app.locale,
        decoration: InputDecoration(labelText: s.t('language')),
        items: const [DropdownMenuItem(value: 'fr', child: Text('Français')), DropdownMenuItem(value: 'en', child: Text('English'))],
        onChanged: (v) => app.setLocale(v ?? 'fr'),
      ),
      DropdownButtonFormField<int>(
        initialValue: me.retentionDays,
        decoration: InputDecoration(labelText: s.t('retention')),
        items: [0, 30, 90, 365].map((d) => DropdownMenuItem(value: d, child: Text(s.t('ret$d')))).toList(),
        onChanged: (v) => _pref(app, {'retention_days': v}),
      ),
      SwitchListTile(
          contentPadding: EdgeInsets.zero, title: Text(s.t('allowAi')), value: me.allowAi, onChanged: (v) => _pref(app, {'allow_ai_processing': v})),
      ListTile(contentPadding: EdgeInsets.zero, title: Text(s.t('plan')), trailing: Text(me.plan)),
      const SizedBox(height: 12),
      OutlinedButton(onPressed: app.signOut, child: Text(s.t('signOut'))),
      const SizedBox(height: 24),
      TextButton(
        style: TextButton.styleFrom(foregroundColor: Theme.of(context).colorScheme.error),
        onPressed: () => showDialog<void>(context: context, builder: (_) => _DeleteDialog(app: app)),
        child: Text(s.t('deleteAccount')),
      ),
    ]);
  }
}

class _DeleteDialog extends StatefulWidget {
  const _DeleteDialog({required this.app});
  final AppState app;
  @override
  State<_DeleteDialog> createState() => _DeleteDialogState();
}

class _DeleteDialogState extends State<_DeleteDialog> {
  final _pw = TextEditingController(), _confirm = TextEditingController();
  String? _error;
  @override
  Widget build(BuildContext context) {
    final s = widget.app.s;
    return AlertDialog(
      title: Text(s.t('deleteAccount')),
      content: Column(mainAxisSize: MainAxisSize.min, children: [
        Text(s.t('deleteWarn')),
        TextField(controller: _pw, obscureText: true, decoration: InputDecoration(labelText: s.t('password'))),
        TextField(controller: _confirm, onChanged: (_) => setState(() {}), decoration: InputDecoration(labelText: s.t('typeDelete'))),
        if (_error != null) Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
      ]),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(s.t('cancel'))),
        FilledButton(
          onPressed: _confirm.text != 'DELETE'
              ? null
              : () async {
                  try {
                    await widget.app.api.call('POST', '/me/delete', body: {'password': _pw.text, 'confirm': 'DELETE'});
                    await widget.app.api.forget();
                    if (context.mounted) Navigator.pop(context);
                    widget.app.me = null;
                    widget.app.setLocale(widget.app.locale, persist: false);
                  } on ApiException catch (e) {
                    setState(() => _error = e.detail);
                  }
                },
          child: Text(s.t('confirm')),
        ),
      ],
    );
  }
}
