import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:trustrelay/api/models.dart';
import 'package:trustrelay/l10n/strings.dart';
import 'package:trustrelay/widgets/analysis_view.dart';

void main() {
  testWidgets('renders verdict, action, findings with evidence, source and limitation, and gaps', (tester) async {
    final a = Analysis.fromJson({
      'id': '1',
      'kind': 'message',
      'status': 'completed',
      'created_at': '2026-11-11T10:00:00Z',
      'verdict': 'strong_suspicious',
      'verdict_title': 'Strong warning signs',
      'verdict_summary': 'Several signs point to a scam.',
      'confidence_label': 'High confidence',
      'recommended_action': {'code': 'x', 'text': 'Do not click.'},
      'identified_organisations': ['La Poste'],
      'identified_domains': ['laposte-colis.example'],
      'findings': [
        {
          'code': 'msg_urgency',
          'severity': 'moderate',
          'confidence_label': 'Medium confidence',
          'source_name': 'rules:message',
          'checked_at': '2026-11-11T10:00:01.123Z',
          'ai_generated': false,
          'title': 'It pressures you to act quickly',
          'explanation': 'Urgency is used to stop you from checking.',
          'evidence': ['sous 24h'],
          'limitation': 'Pattern-based check.',
        }
      ],
      'missing_information': [
        {'code': 'm', 'text': 'We did not follow the link.'}
      ],
      'disclaimer': 'An opinion, not a guarantee.',
    });
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: SingleChildScrollView(child: AnalysisView(analysis: a, s: S('en'))))));
    for (final text in [
      'Strong warning signs',
      'Do not click.',
      'It pressures you to act quickly',
      'Evidence: sous 24h',
      'Source: rules:message',
      'Limitation: Pattern-based check.',
      '• We did not follow the link.',
      'An opinion, not a guarantee.',
    ]) {
      expect(find.text(text), findsOneWidget, reason: text);
    }
  });
}
