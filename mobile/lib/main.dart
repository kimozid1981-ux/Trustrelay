import 'package:material_ui/material_ui.dart';

import 'api/client.dart';
import 'app_state.dart';
import 'screens/auth_screen.dart';
import 'screens/home_screen.dart';
import 'screens/onboarding_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final state = AppState(ApiClient())..boot();
  runApp(TrustRelayApp(state: state));
}

class TrustRelayApp extends StatelessWidget {
  const TrustRelayApp({super.key, required this.state});
  final AppState state;

  @override
  Widget build(BuildContext context) {
    return AppScope(
      state: state,
      child: ListenableBuilder(
        listenable: state,
        builder: (context, _) => MaterialApp(
          title: 'TrustRelay',
          debugShowCheckedModeBanner: false,
          locale: Locale(state.locale),
          supportedLocales: const [Locale('fr'), Locale('en')],
          localizationsDelegates: GlobalMaterialLocalizations.delegates,
          theme: ThemeData(colorSchemeSeed: const Color(0xFF1D4ED8), useMaterial3: true),
          darkTheme: ThemeData(colorSchemeSeed: const Color(0xFF1D4ED8), brightness: Brightness.dark, useMaterial3: true),
          home: state.booting
              ? const Scaffold(body: Center(child: CircularProgressIndicator()))
              : state.me == null
                  ? const AuthScreen()
                  : !state.me!.onboardingCompleted
                      ? const OnboardingScreen()
                      : const HomeScreen(),
        ),
      ),
    );
  }
}
