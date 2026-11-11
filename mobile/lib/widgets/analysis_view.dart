import 'package:material_ui/material_ui.dart';

import '../api/models.dart';
import '../l10n/strings.dart';

/// Colours per verdict. Text always states the verdict too, so colour is never the only signal.
Color verdictColor(String? v, ColorScheme c) => switch (v) {
      'known_malicious' => const Color(0xFFB91C1C),
      'strong_suspicious' => const Color(0xFFC2410C),
      'moderate_warning' => const Color(0xFFA16207),
      'no_known_warning_signals' => const Color(0xFF15803D),
      _ => c.outline,
    };

class AnalysisView extends StatelessWidget {
  const AnalysisView({super.key, required this.analysis, required this.s});
  final Analysis analysis;
  final S s;

  @override
  Widget build(BuildContext context) {
    final a = analysis;
    final theme = Theme.of(context);
    final color = verdictColor(a.verdict, theme.colorScheme);
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Semantics(
        header: true,
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(border: Border.all(color: color, width: 2), borderRadius: BorderRadius.circular(12)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(a.verdictTitle ?? '', key: const Key('verdict-title'), style: theme.textTheme.titleLarge?.copyWith(color: color)),
            const SizedBox(height: 6),
            Text(a.verdictSummary ?? ''),
            if (a.confidenceLabel != null)
              Padding(padding: const EdgeInsets.only(top: 6), child: Text(a.confidenceLabel!, style: theme.textTheme.labelLarge)),
          ]),
        ),
      ),
      const SizedBox(height: 16),
      Text(s.t('recommend'), style: theme.textTheme.titleMedium),
      Text(a.actionText ?? ''),
      ExpansionTile(
        tilePadding: EdgeInsets.zero,
        title: Text(s.t('alreadyActed')),
        children: [Text(s.t('alreadyActedBody'))],
      ),
      if (a.organisations.isNotEmpty) _kv(s.t('organisation'), a.organisations.join(', ')),
      if (a.domains.isNotEmpty) _kv(s.t('domain'), a.domains.join(', ')),
      const SizedBox(height: 16),
      Text(s.t('found'), style: theme.textTheme.titleMedium),
      for (final f in a.findings) _FindingCard(f: f, s: s),
      if (a.missing.isNotEmpty) ...[
        const SizedBox(height: 16),
        Text(s.t('missing'), style: theme.textTheme.titleMedium),
        for (final m in a.missing) Text('• $m'),
      ],
      if (a.disclaimer != null)
        Padding(padding: const EdgeInsets.only(top: 16), child: Text(a.disclaimer!, style: theme.textTheme.bodySmall)),
    ]);
  }

  Widget _kv(String k, String v) => Padding(
      padding: const EdgeInsets.only(top: 8),
      child: Text.rich(TextSpan(children: [TextSpan(text: '$k: ', style: const TextStyle(fontWeight: FontWeight.w600)), TextSpan(text: v)])));
}

class _FindingCard extends StatelessWidget {
  const _FindingCard({required this.f, required this.s});
  final Finding f;
  final S s;
  @override
  Widget build(BuildContext context) {
    final small = Theme.of(context).textTheme.bodySmall;
    return Card(
      margin: const EdgeInsets.only(top: 8),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('${f.confidenceLabel}${f.aiGenerated ? ' · AI' : ''}', style: Theme.of(context).textTheme.labelMedium),
          Text(f.title, style: const TextStyle(fontWeight: FontWeight.w600)),
          Text(f.explanation),
          if (f.evidence.isNotEmpty) Text('${s.t('evidence')}: ${f.evidence.join(' · ')}', style: small),
          Text('${s.t('source')}: ${f.sourceName}', style: small),
          Text('${s.t('checked')}: ${f.checkedAt.replaceFirst('T', ' ').split('.').first}', style: small),
          Text('${s.t('limitation')}: ${f.limitation}', style: small),
        ]),
      ),
    );
  }
}
