import 'package:material_ui/material_ui.dart';

import '../app_state.dart';
import 'check_screen.dart';
import 'family_screen.dart';
import 'history_screen.dart';
import 'settings_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _tab = 0;
  @override
  Widget build(BuildContext context) {
    final s = AppScope.of(context).s;
    const screens = [CheckScreen(), HistoryScreen(), FamilyScreen(), SettingsScreen()];
    return Scaffold(
      body: SafeArea(child: screens[_tab]),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: [
          NavigationDestination(icon: const Icon(Icons.search), label: s.t('navCheck')),
          NavigationDestination(icon: const Icon(Icons.history), label: s.t('navHistory')),
          NavigationDestination(icon: const Icon(Icons.family_restroom), label: s.t('navFamily')),
          NavigationDestination(icon: const Icon(Icons.settings), label: s.t('navSettings')),
        ],
      ),
    );
  }
}
