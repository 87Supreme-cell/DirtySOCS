import 'package:flutter/material.dart';
import 'theme/ubuntu_theme.dart';
import 'ui/dashboard_view.dart';
import 'ui/dual_lens_view.dart';
import 'ui/landing_page_view.dart';
import 'ui/mitre_matrix_view.dart';
import 'ui/process_tree_view.dart';
import 'ui/run_prompt_dialog.dart';
import 'ui/security_hardening_view.dart';
import 'ui/terminal_boot_view.dart';

void main() {
  runApp(const DirtySocApp());
}

class DirtySocApp extends StatefulWidget {
  const DirtySocApp({super.key});

  @override
  State<DirtySocApp> createState() => _DirtySocAppState();
}

class _DirtySocAppState extends State<DirtySocApp> {
  ThemeMode _themeMode = ThemeMode.dark;

  void _toggleTheme() {
    setState(() {
      _themeMode =
          _themeMode == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DirtySOCS • Linux Kernel Observability',
      debugShowCheckedModeBanner: false,
      theme: UbuntuTheme.lightTheme,
      darkTheme: UbuntuTheme.darkTheme,
      themeMode: _themeMode,
      home: SocHomeScreen(
        themeMode: _themeMode,
        onToggleTheme: _toggleTheme,
      ),
    );
  }
}

class SocHomeScreen extends StatefulWidget {
  final ThemeMode themeMode;
  final VoidCallback onToggleTheme;

  const SocHomeScreen({
    super.key,
    required this.themeMode,
    required this.onToggleTheme,
  });

  @override
  State<SocHomeScreen> createState() => _SocHomeScreenState();
}

class _SocHomeScreenState extends State<SocHomeScreen> {
  int _selectedNavIndex = 0; // 0 = LANDING, 1 = DASHBOARD, 2 = DUAL-LENS, 3 = PROCESS TREE, 4 = MITRE GRID, 5 = SECURITY
  bool _isBootingTerminal = false;
  bool _hasPromptedOnStartup = false;

  @override
  void initState() {
    super.initState();
    // Prompt the operator immediately on session start (with accidental launch double-confirmation)
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_hasPromptedOnStartup && mounted) {
        _hasPromptedOnStartup = true;
        _showInitialRunPrompt();
      }
    });
  }

  void _showInitialRunPrompt() {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => RunPromptDialog(
        onAcceptedAndConfirmed: () {
          setState(() {
            _isBootingTerminal = true;
          });
        },
      ),
    );
  }

  Widget _buildCurrentScreen() {
    switch (_selectedNavIndex) {
      case 0:
        return LandingPageView(
          onNavigate: (index) {
            setState(() => _selectedNavIndex = index);
          },
          onStartTerminalBoot: () {
            setState(() => _isBootingTerminal = true);
          },
        );
      case 1:
        return const DashboardView();
      case 2:
        return const DualLensView();
      case 3:
        return const ProcessTreeView();
      case 4:
        return const MitreMatrixView();
      case 5:
        return const SecurityHardeningView();
      default:
        return const DashboardView();
    }
  }

  @override
  Widget build(BuildContext context) {
    final isDark = widget.themeMode == ThemeMode.dark;
    final headerBg = isDark ? const Color(0xFF181818) : const Color(0xFFEBEBEB);

    return Scaffold(
      body: Column(
        children: [
          // Authentic Ubuntu / GNOME HeaderBar
          Container(
            height: 48,
            padding: const EdgeInsets.symmetric(horizontal: 16),
            decoration: BoxDecoration(
              color: headerBg,
              border: Border(
                bottom: BorderSide(
                  color: Theme.of(context).colorScheme.outline,
                  width: 1,
                ),
              ),
            ),
            child: Row(
              children: [
                // Window Control Dots (Ubuntu Style)
                Row(
                  children: [
                    _buildDot(const Color(0xFFED6A5E)),
                    const SizedBox(width: 8),
                    _buildDot(const Color(0xFFF4BF4F)),
                    const SizedBox(width: 8),
                    _buildDot(const Color(0xFF61C554)),
                  ],
                ),
                const SizedBox(width: 20),

                // Ubuntu Eye Logo / App Title
                Row(
                  children: [
                    Container(
                      width: 22,
                      height: 22,
                      decoration: const BoxDecoration(
                        color: UbuntuTheme.ubuntuOrange,
                        shape: BoxShape.circle,
                      ),
                      child: const Center(
                        child: Text(
                          '👁',
                          style: TextStyle(fontSize: 12),
                        ),
                      ),
                    ),
                    const SizedBox(width: 10),
                    const Text(
                      'DirtySOCS',
                      style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.bold,
                        letterSpacing: 0.5,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: UbuntuTheme.ubuntuOrange.withValues(alpha: 0.18),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: const Text(
                        'LINUX 7.0 (RING-0)',
                        style: TextStyle(
                          fontSize: 8,
                          fontWeight: FontWeight.bold,
                          color: UbuntuTheme.ubuntuOrange,
                        ),
                      ),
                    ),
                  ],
                ),
                const Spacer(),

                // GNOME Header Tabs
                Container(
                  padding: const EdgeInsets.all(3),
                  decoration: BoxDecoration(
                    color: Theme.of(context).cardTheme.color,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                        color: Theme.of(context).colorScheme.outline),
                  ),
                  child: Row(
                    children: [
                      _buildHeaderTab('LANDING', 0, Icons.home_outlined),
                      _buildHeaderTab('DASHBOARD', 1, Icons.dashboard_outlined),
                      _buildHeaderTab('DUAL-LENS', 2, Icons.visibility_outlined),
                      _buildHeaderTab(
                          'PROCESS TREE', 3, Icons.account_tree_outlined),
                      _buildHeaderTab('MITRE GRID', 4, Icons.grid_view_outlined),
                      _buildHeaderTab('SECURITY', 5, Icons.shield_outlined),
                    ],
                  ),
                ),
                const Spacer(),

                // Theme Mode Switcher (Light / Dark)
                IconButton(
                  tooltip: isDark
                      ? 'Switch to Ubuntu Light Mode'
                      : 'Switch to Ubuntu Dark Mode',
                  icon: Icon(
                    isDark ? Icons.light_mode_outlined : Icons.dark_mode_outlined,
                    size: 18,
                  ),
                  onPressed: widget.onToggleTheme,
                ),
              ],
            ),
          ),

          // Main View Content with Dissolving Terminal Boot Overlay
          Expanded(
            child: Stack(
              children: [
                // Underlying active screen (shows Dashboard underneath when terminal dissolves)
                Positioned.fill(
                  child: _isBootingTerminal
                      ? const DashboardView()
                      : _buildCurrentScreen(),
                ),

                // Terminal Boot Typing Console (dissolves to dashboard upon completion)
                if (_isBootingTerminal)
                  Positioned.fill(
                    child: TerminalBootView(
                      onCompleteDissolve: () {
                        setState(() {
                          _isBootingTerminal = false;
                          _selectedNavIndex = 1; // Transition to DASHBOARD
                        });
                      },
                    ),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDot(Color color) {
    return Container(
      width: 11,
      height: 11,
      decoration: BoxDecoration(
        color: color,
        shape: BoxShape.circle,
      ),
    );
  }

  Widget _buildHeaderTab(String title, int index, IconData icon) {
    final isSelected = _selectedNavIndex == index;
    return GestureDetector(
      onTap: () {
        if (_isBootingTerminal) {
          setState(() => _isBootingTerminal = false);
        }
        setState(() => _selectedNavIndex = index);
      },
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
          color: isSelected ? UbuntuTheme.ubuntuOrange : Colors.transparent,
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(
          children: [
            Icon(
              icon,
              size: 13,
              color: isSelected ? Colors.white : Colors.grey,
            ),
            const SizedBox(width: 5),
            Text(
              title,
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.bold,
                color: isSelected ? Colors.white : Colors.grey,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
