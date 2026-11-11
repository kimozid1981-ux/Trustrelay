import 'package:material_ui/material_ui.dart';

import '../app_state.dart';

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});
  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  int _step = 0;
  int _retention = 90;
  bool _allowAi = false; // AI processing is opt-in.

  Future<void> _finish(AppState app) async {
    await app.api.call('PATCH', '/me/preferences', body: {'retention_days': _retention, 'allow_ai_processing': _allowAi});
    await app.api.call('PATCH', '/me', body: {'onboarding_completed': true, 'locale': app.locale});
    await app.reloadMe();
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    final pages = <Widget>[
      _page(context, s.t('onb1t'), Text(s.t('onb1'))),
      _page(context, s.t('onb2t'), Text(s.t('onb2'))),
      _page(
          context,
          s.t('onb3t'),
          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(s.t('onb3')),
            const SizedBox(height: 12),
            DropdownButtonFormField<int>(
              initialValue: _retention,
              decoration: InputDecoration(labelText: s.t('retention')),
              items: [0, 30, 90, 365].map((d) => DropdownMenuItem(value: d, child: Text(s.t('ret$d')))).toList(),
              onChanged: (v) => setState(() => _retention = v ?? 90),
            ),
            CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                value: _allowAi,
                onChanged: (v) => setState(() => _allowAi = v ?? false),
                title: Text(s.t('onbAi'))),
          ])),
    ];
    final last = _step == pages.length - 1;
    return Scaffold(
      appBar: AppBar(title: Text(s.t('onbTitle'))),
      body: SafeArea(child: ListView(padding: const EdgeInsets.all(20), children: [pages[_step]])),
      bottomNavigationBar: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(children: [
            Text('${_step + 1} / ${pages.length}'),
            const Spacer(),
            FilledButton(
                onPressed: () => last ? _finish(app) : setState(() => _step++),
                child: Text(last ? s.t('finish') : s.t('next'))),
          ]),
        ),
      ),
    );
  }

  Widget _page(BuildContext context, String title, Widget body) => Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [Text(title, style: Theme.of(context).textTheme.headlineSmall), const SizedBox(height: 12), body]);
}
