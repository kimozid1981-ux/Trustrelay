import 'dart:async';

import 'package:material_ui/material_ui.dart';

import '../api/models.dart';
import '../app_state.dart';
import '../widgets/analysis_view.dart';

class AnalysisScreen extends StatefulWidget {
  const AnalysisScreen({super.key, required this.id});
  final String id;
  @override
  State<AnalysisScreen> createState() => _AnalysisScreenState();
}

class _AnalysisScreenState extends State<AnalysisScreen> {
  Analysis? _a;
  Timer? _poll;
  int _tries = 0;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_a == null && _poll == null) _load();
  }

  Future<void> _load() async {
    final app = AppScope.of(context);
    final a = Analysis.fromJson(await app.api.call('GET', '/analyses/${widget.id}') as Map<String, dynamic>);
    if (!mounted) return;
    setState(() => _a = a);
    // Poll while the worker runs; back off and stop after ~2 minutes.
    if (!a.done && _tries < 40) {
      _tries++;
      _poll = Timer(Duration(milliseconds: 800 + 200 * _tries), _load);
    }
  }

  @override
  void dispose() {
    _poll?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    final a = _a;
    return Scaffold(
      appBar: AppBar(title: Text(a == null ? '' : s.t('kind_${a.kind}')), actions: [
        if (a != null)
          IconButton(
            tooltip: s.t('delete'),
            icon: const Icon(Icons.delete_outline),
            onPressed: () async {
              await app.api.call('DELETE', '/analyses/${a.id}');
              if (context.mounted) Navigator.of(context).pop();
            },
          ),
      ]),
      body: SafeArea(
        child: a == null || !a.done
            ? Center(child: Column(mainAxisSize: MainAxisSize.min, children: [const CircularProgressIndicator(), const SizedBox(height: 12), Text(s.t('analysing'))]))
            : a.status == 'failed'
                ? Center(child: Text(s.t('failed')))
                : ListView(padding: const EdgeInsets.all(16), children: [AnalysisView(analysis: a, s: s)]),
      ),
    );
  }
}
