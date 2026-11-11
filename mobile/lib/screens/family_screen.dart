import 'package:material_ui/material_ui.dart';

import '../api/client.dart';
import '../app_state.dart';
import '../widgets/analysis_view.dart';

/// Family protection on mobile: join a group and read shared warnings. Creating groups, invitations and
/// member permissions are managed in the web app (Phase 1 scope).
class FamilyScreen extends StatefulWidget {
  const FamilyScreen({super.key});
  @override
  State<FamilyScreen> createState() => _FamilyScreenState();
}

class _FamilyScreenState extends State<FamilyScreen> {
  Map<String, dynamic>? _data;
  final _code = TextEditingController();
  String? _error;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_data == null) _load();
  }

  Future<void> _load() async {
    final r = await AppScope.of(context).api.call('GET', '/family') as Map<String, dynamic>;
    if (mounted) setState(() => _data = r);
  }

  Future<void> _join(AppState app) async {
    try {
      final r = await app.api.call('POST', '/family/join', body: {'code': _code.text.trim()}) as Map<String, dynamic>;
      setState(() {
        _data = r;
        _error = null;
      });
    } on ApiException catch (e) {
      setState(() => _error = e.detail);
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    final d = _data;
    if (d == null) return const Center(child: CircularProgressIndicator());
    final group = d['group'] as Map<String, dynamic>?;
    final warnings = (d['warnings'] as List?) ?? const [];
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(padding: const EdgeInsets.all(16), children: [
        Text(group?['name'] as String? ?? s.t('navFamily'), style: Theme.of(context).textTheme.headlineSmall),
        Text(s.t('familyIntro')),
        const SizedBox(height: 12),
        if (group == null) ...[
          Text(s.t('familyNone')),
          TextField(controller: _code, decoration: InputDecoration(labelText: s.t('joinCode'))),
          if (_error != null) Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
          FilledButton(onPressed: () => _join(app), child: Text(s.t('join'))),
        ] else if (warnings.isEmpty)
          Text(s.t('noWarnings'))
        else
          for (final w in warnings.cast<Map<String, dynamic>>())
            Card(
              child: ListTile(
                leading: Icon(Icons.warning_amber, color: verdictColor(w['verdict'] as String?, Theme.of(context).colorScheme)),
                title: Text(w['verdict_title'] as String? ?? ''),
                subtitle: Text([
                  w['shared_by'] ?? '',
                  if (w['message'] != null) '“${w['message']}”',
                  w['verdict_summary'] ?? '',
                ].where((e) => '$e'.isNotEmpty).join('\n')),
              ),
            ),
      ]),
    );
  }
}
