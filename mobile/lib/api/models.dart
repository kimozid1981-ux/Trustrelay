// Plain models mirroring the backend JSON (docs/architecture/03-api.md). Parsing is tolerant: unknown
// fields are ignored and missing optional fields become null/empty, so a newer API does not crash the app.

List<String> _strings(Object? v) => v is List ? v.map((e) => e.toString()).toList() : const [];

class Finding {
  Finding.fromJson(Map<String, dynamic> j)
      : code = j['code'] as String? ?? '',
        severity = j['severity'] as String? ?? 'info',
        confidenceLabel = j['confidence_label'] as String? ?? '',
        sourceName = j['source_name'] as String? ?? '',
        checkedAt = j['checked_at'] as String? ?? '',
        aiGenerated = j['ai_generated'] as bool? ?? false,
        title = j['title'] as String? ?? '',
        explanation = j['explanation'] as String? ?? '',
        evidence = _strings(j['evidence']),
        limitation = j['limitation'] as String? ?? '';
  final String code, severity, confidenceLabel, sourceName, checkedAt, title, explanation, limitation;
  final bool aiGenerated;
  final List<String> evidence;
}

class Analysis {
  Analysis.fromJson(Map<String, dynamic> j)
      : id = j['id'] as String,
        kind = j['kind'] as String? ?? '',
        status = j['status'] as String? ?? 'queued',
        createdAt = j['created_at'] as String? ?? '',
        label = j['label'] as String?,
        verdict = j['verdict'] as String?,
        verdictTitle = j['verdict_title'] as String?,
        verdictSummary = j['verdict_summary'] as String?,
        confidenceLabel = j['confidence_label'] as String?,
        actionText = (j['recommended_action'] as Map<String, dynamic>?)?['text'] as String?,
        organisations = _strings(j['identified_organisations']),
        domains = _strings(j['identified_domains']),
        findings = (j['findings'] as List? ?? const []).map((e) => Finding.fromJson(e as Map<String, dynamic>)).toList(),
        missing = (j['missing_information'] as List? ?? const [])
            .map((e) => (e as Map<String, dynamic>)['text'] as String? ?? '')
            .toList(),
        disclaimer = j['disclaimer'] as String?;
  final String id, kind, status, createdAt;
  final String? label, verdict, verdictTitle, verdictSummary, confidenceLabel, actionText, disclaimer;
  final List<String> organisations, domains, missing;
  final List<Finding> findings;
  bool get done => status == 'completed' || status == 'failed';
}

class Me {
  Me.fromJson(Map<String, dynamic> j)
      : email = j['email'] as String? ?? '',
        locale = j['locale'] as String? ?? 'fr',
        plan = j['plan'] as String? ?? 'free',
        onboardingCompleted = j['onboarding_completed'] as bool? ?? false,
        retentionDays = (j['preferences'] as Map<String, dynamic>?)?['retention_days'] as int? ?? 90,
        allowAi = (j['preferences'] as Map<String, dynamic>?)?['allow_ai_processing'] as bool? ?? false;
  final String email, locale, plan;
  final bool onboardingCompleted, allowAi;
  final int retentionDays;
}
