import 'package:material_ui/material_ui.dart';

import 'api/client.dart';
import 'api/models.dart';
import 'l10n/strings.dart';

/// Session state shared by all screens: API client, signed-in profile and UI language.
class AppState extends ChangeNotifier {
  AppState(this.api);
  final ApiClient api;
  Me? me;
  bool booting = true;
  String locale = WidgetsBinding.instance.platformDispatcher.locale.languageCode == 'en' ? 'en' : 'fr';

  S get s => S(locale);

  Future<void> boot() async {
    api.locale = locale;
    try {
      if (await api.restoreSession()) await reloadMe();
    } catch (_) {
      // Offline or server unavailable: show the sign-in screen.
    }
    booting = false;
    notifyListeners();
  }

  Future<void> reloadMe() async {
    me = Me.fromJson(await api.call('GET', '/me') as Map<String, dynamic>);
    setLocale(me!.locale, persist: false);
    notifyListeners();
  }

  void setLocale(String l, {bool persist = true}) {
    locale = l;
    api.locale = l;
    if (persist && me != null) api.call('PATCH', '/me', body: {'locale': l}).ignore();
    notifyListeners();
  }

  Future<void> signOut() async {
    await api.logout();
    me = null;
    notifyListeners();
  }
}

class AppScope extends InheritedNotifier<AppState> {
  const AppScope({super.key, required AppState state, required super.child}) : super(notifier: state);
  static AppState of(BuildContext context) => context.dependOnInheritedWidgetOfExactType<AppScope>()!.notifier!;
}
