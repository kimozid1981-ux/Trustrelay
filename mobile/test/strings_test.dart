import 'package:flutter_test/flutter_test.dart';
import 'package:trustrelay/l10n/strings.dart';

void main() {
  test('French and English have the same keys and no empty values', () {
    expect(kStrings['fr']!.keys.toSet(), kStrings['en']!.keys.toSet());
    for (final m in kStrings.values) {
      for (final v in m.values) {
        expect(v.trim(), isNotEmpty);
      }
    }
  });

  test('no string promises absolute safety', () {
    final all = kStrings.values.expand((m) => m.values).join(' ').toLowerCase();
    for (final banned in ['100% safe', '100 % sûr', 'guaranteed safe', 'garanti sans danger']) {
      expect(all.contains(banned), isFalse, reason: banned);
    }
  });
}
