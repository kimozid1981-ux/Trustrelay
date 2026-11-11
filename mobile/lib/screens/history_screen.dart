import 'package:material_ui/material_ui.dart';

import '../api/models.dart';
import '../app_state.dart';
import '../widgets/analysis_view.dart';
import 'analysis_screen.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});
  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  List<Analysis>? _items;
  String? _next;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_items == null) _load();
  }

  Future<void> _load({bool more = false}) async {
    final app = AppScope.of(context);
    final q = more && _next != null ? '&before=${Uri.encodeQueryComponent(_next!)}' : '';
    final r = await app.api.call('GET', '/analyses?limit=20$q') as Map<String, dynamic>;
    final items = (r['items'] as List).map((e) => Analysis.fromJson(e as Map<String, dynamic>)).toList();
    if (!mounted) return;
    setState(() {
      _items = more ? [...?_items, ...items] : items;
      _next = r['next_before'] as String?;
    });
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    final items = _items;
    if (items == null) return const Center(child: CircularProgressIndicator());
    return RefreshIndicator(
      onRefresh: _load,
      child: items.isEmpty
          ? ListView(children: [Padding(padding: const EdgeInsets.all(24), child: Text(s.t('historyEmpty')))])
          : ListView.builder(
              itemCount: items.length + (_next != null ? 1 : 0),
              itemBuilder: (context, i) {
                if (i == items.length) return TextButton(onPressed: () => _load(more: true), child: const Text('…'));
                final a = items[i];
                return ListTile(
                  leading: Icon(Icons.circle, color: verdictColor(a.verdict, Theme.of(context).colorScheme), size: 14),
                  title: Text(a.verdictTitle ?? a.status),
                  subtitle: Text('${s.t('kind_${a.kind}')} · ${a.label ?? ''}\n${a.createdAt.split('T').first}', maxLines: 2, overflow: TextOverflow.ellipsis),
                  isThreeLine: true,
                  onTap: () async {
                    await Navigator.of(context).push(MaterialPageRoute(builder: (_) => AnalysisScreen(id: a.id)));
                    _load();
                  },
                );
              }),
    );
  }
}
