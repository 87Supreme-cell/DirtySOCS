import 'package:flutter/material.dart';
import '../theme/ubuntu_theme.dart';
import 'run_prompt_dialog.dart';

class LandingPageView extends StatelessWidget {
  final Function(int) onNavigate;
  final VoidCallback onStartTerminalBoot;

  const LandingPageView({
    super.key,
    required this.onNavigate,
    required this.onStartTerminalBoot,
  });

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Banner
          _buildWelcomeBanner(context),
          const SizedBox(height: 16),

          // 4 Module Selection Cards
          _buildModuleSelectionGrid(context),
          const SizedBox(height: 20),

          // Main 2-Column Section: Historical Log Analysis & Threat Spectrum
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Left: Historical Log Analysis & Noise Collapsing
              Expanded(
                flex: 6,
                child: _buildPreviousLogsAnalysisCard(context),
              ),
              const SizedBox(width: 16),

              // Right: Current Threat Status & Spectrum Gauge (75% Risk)
              Expanded(
                flex: 5,
                child: _buildCurrentPostureCard(context),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildWelcomeBanner(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      decoration: BoxDecoration(
        color: Theme.of(context).cardTheme.color,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: Theme.of(context).colorScheme.outline),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Text(
                      'INVESTIGATION PORTAL & OBSERVABILITY SELECTION',
                      style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(width: 10),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: UbuntuTheme.statusGreen.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(color: UbuntuTheme.statusGreen.withValues(alpha: 0.4)),
                      ),
                      child: const Text('RING-0 READY', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: UbuntuTheme.statusGreen)),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Row(
                  children: [
                    const Text(
                      'Select a target module to inspect, review historical log trends, or authenticate to initialize active eBPF sensors.',
                      style: TextStyle(fontSize: 11, color: Colors.grey),
                    ),
                    const SizedBox(width: 10),
                    InkWell(
                      onTap: () => _showBuilderNoteDialog(context),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: UbuntuTheme.ubuntuOrange.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(color: UbuntuTheme.ubuntuOrange.withValues(alpha: 0.4)),
                        ),
                        child: const Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Icons.edit_note, size: 12, color: UbuntuTheme.ubuntuOrange),
                            SizedBox(width: 4),
                            Text('Note from the Builder', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: UbuntuTheme.ubuntuOrange)),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(width: 16),
          ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: UbuntuTheme.ubuntuOrange,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            ),
            icon: const Icon(Icons.bolt, size: 18),
            label: const Text('LAUNCH RUN SESSION', style: TextStyle(fontWeight: FontWeight.bold)),
            onPressed: () {
              showDialog(
                context: context,
                barrierDismissible: false,
                builder: (ctx) => RunPromptDialog(
                  onAcceptedAndConfirmed: () {
                    onStartTerminalBoot();
                  },
                ),
              );
            },
          ),
        ],
      ),
    );
  }

  Widget _buildModuleSelectionGrid(BuildContext context) {
    final modules = [
      _ModuleItem(
        title: 'KERNEL TELEMETRY',
        desc: 'Read-only eBPF tracepoints\nsys_enter_execve, connect, openat',
        tag: 'ACTIVE (100%)',
        color: const Color(0xFF3465A4),
        navIndex: 1, // Dashboard
      ),
      _ModuleItem(
        title: 'PREVIOUS LOGS',
        desc: 'Analysis of 60s sliding windows\n98.8% repetitive noise collapsed',
        tag: 'STORED ARCHIVE',
        color: UbuntuTheme.ubuntuOrange,
        navIndex: 1, // Dashboard Logs
      ),
      _ModuleItem(
        title: 'MITRE ATT&CK',
        desc: 'Adversary Tactic Heatmap\nCross-referenced Linux behaviors',
        tag: 'ENTERPRISE v14',
        color: UbuntuTheme.ubuntuAubergine,
        navIndex: 4, // Mitre Grid
      ),
      _ModuleItem(
        title: 'PROCESS LINEAGE',
        desc: 'Correlated tree hierarchy\nReconstructed execve & procfs',
        tag: 'CORRELATED TREE',
        color: UbuntuTheme.statusGreen,
        navIndex: 3, // Process Tree
      ),
    ];

    return Row(
      children: modules.map((m) {
        return Expanded(
          child: Container(
            margin: const EdgeInsets.symmetric(horizontal: 4),
            child: InkWell(
              borderRadius: BorderRadius.circular(8),
              onTap: () => onNavigate(m.navIndex),
              child: Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: Theme.of(context).cardTheme.color,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Theme.of(context).colorScheme.outline),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Container(width: 4, height: 14, color: m.color),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            m.title,
                            style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      m.desc,
                      style: const TextStyle(fontSize: 10, color: Colors.grey, height: 1.3),
                    ),
                    const SizedBox(height: 12),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                      decoration: BoxDecoration(
                        color: m.color.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        m.tag,
                        style: TextStyle(fontSize: 8, fontWeight: FontWeight.bold, color: m.color),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        );
      }).toList(),
    );
  }

  Widget _buildPreviousLogsAnalysisCard(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.history_outlined, size: 18, color: UbuntuTheme.ubuntuOrange),
                const SizedBox(width: 8),
                const Text(
                  'HISTORICAL LOG ANALYSIS & NOISE COLLAPSE',
                  style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const SizedBox(height: 4),
            const Text(
              'Sliding-Window Aggregator snapshot: 1,240 desktop CSS warnings compressed into single count',
              style: TextStyle(fontSize: 10, color: Colors.grey),
            ),
            const Divider(height: 20),

            // Telemetry table
            Container(
              padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 8),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                borderRadius: BorderRadius.circular(6),
              ),
              child: const Row(
                children: [
                  SizedBox(width: 70, child: Text('TIMESTAMP', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.grey))),
                  SizedBox(width: 70, child: Text('SUBSYSTEM', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.grey))),
                  Expanded(child: Text('PROCESS / TARGET', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.grey))),
                  SizedBox(width: 75, child: Text('COUNT', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.grey))),
                  SizedBox(width: 80, child: Text('SEVERITY', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.grey))),
                ],
              ),
            ),
            const SizedBox(height: 8),

            _buildLogRow('16:38:53', 'ebpf', '.sys_update -> /tmp', '1', 'CRITICAL', UbuntuTheme.statusRed),
            _buildLogRow('16:38:53', 'ebpf', '/etc/shadow credential read', '1', 'CRITICAL', UbuntuTheme.statusRed),
            _buildLogRow('16:38:50', 'dbus', 'snapd-desktop portal denial', '4', 'HIGH RISK', UbuntuTheme.statusOrange),
            _buildLogRow('16:38:40', 'systemd', 'auditd.service exit status 1', '1', 'CAUTION', UbuntuTheme.statusYellow),
            _buildLogRow('16:38:25', 'ebpf', 'curl -> port 443 [ip-7f9a12]', '18', 'NOMINAL', UbuntuTheme.statusGreen),
            _buildLogRow('16:38:00', 'journal', 'gnome-shell css_parse_warn', '1,240 (COLLAPSED)', 'FILTERED', Colors.grey),
          ],
        ),
      ),
    );
  }

  Widget _buildLogRow(String ts, String sub, String proc, String count, String sev, Color col) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4, horizontal: 8),
      child: Row(
        children: [
          SizedBox(width: 70, child: Text(ts, style: const TextStyle(fontSize: 10, color: Colors.grey))),
          SizedBox(width: 70, child: Text(sub, style: const TextStyle(fontSize: 10, color: UbuntuTheme.ubuntuOrange, fontWeight: FontWeight.bold))),
          Expanded(child: Text(proc, overflow: TextOverflow.ellipsis, style: const TextStyle(fontSize: 10))),
          SizedBox(width: 75, child: Text(count, style: const TextStyle(fontSize: 10, color: Colors.grey))),
          SizedBox(
            width: 80,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: col.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: col.withValues(alpha: 0.5)),
              ),
              child: Text(
                sev,
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 8, fontWeight: FontWeight.bold, color: col),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCurrentPostureCard(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.security, size: 18, color: UbuntuTheme.statusOrange),
                const SizedBox(width: 8),
                const Text(
                  'CURRENT POSTURE & THREAT SPECTRUM',
                  style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const SizedBox(height: 4),
            const Text(
              'Granular threat level with dynamic risk spectrum',
              style: TextStyle(fontSize: 10, color: Colors.grey),
            ),
            const Divider(height: 20),

            // 75% Risk Box
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: UbuntuTheme.statusOrange.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: UbuntuTheme.statusOrange.withValues(alpha: 0.4)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'THREAT STATUS: 75% AT RISK',
                    style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold, color: UbuntuTheme.statusOrange),
                  ),
                  const SizedBox(height: 4),
                  const Text(
                    'ALERT: World-writable execution & shadow read detected.',
                    style: TextStyle(fontSize: 10, color: Colors.orangeAccent),
                  ),
                  const SizedBox(height: 12),

                  // Rainbow spectrum bar (Green -> Lime -> Yellow -> Orange -> Red)
                  ClipRRect(
                    borderRadius: BorderRadius.circular(4),
                    child: Container(
                      height: 16,
                      decoration: const BoxDecoration(
                        gradient: LinearGradient(
                          colors: [
                            UbuntuTheme.statusGreen,
                            UbuntuTheme.statusLime,
                            UbuntuTheme.statusYellow,
                            UbuntuTheme.statusOrange,
                            UbuntuTheme.statusRed,
                          ],
                          stops: [0.0, 0.25, 0.50, 0.75, 1.0],
                        ),
                      ),
                      child: Stack(
                        children: [
                          // 75% indicator pin
                          Align(
                            alignment: const Alignment(0.5, 0),
                            child: Container(
                              width: 4,
                              height: 16,
                              color: Colors.white,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 4),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text('0% NOMINAL', style: TextStyle(fontSize: 8, color: Colors.grey)),
                      const Text('50% CAUTION', style: TextStyle(fontSize: 8, color: Colors.grey)),
                      const Text('75% ORANGE ALERT', style: TextStyle(fontSize: 8, fontWeight: FontWeight.bold, color: UbuntuTheme.statusOrange)),
                      const Text('100% CRITICAL', style: TextStyle(fontSize: 8, color: Colors.grey)),
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // Host Vitals breakdown
            const Text(
              'HOST SYSTEM & CONTAINER VITALS',
              style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            _buildVitalRow('Kernel RingBuf Drops:', '0 (Adaptive Polling Active)'),
            _buildVitalRow('Active Host Processes:', '376 processes monitored'),
            _buildVitalRow('Open IPC Descriptors:', '77 FDs (Cap: 32 concurrent)'),
            _buildVitalRow('Resident Set (RSS):', '28.4 MB (cgroup slice locked)'),
            _buildVitalRow('Authentication Engine:', 'ARGON2ID (m=64M, t=3, p=4)'),
          ],
        ),
      ),
    );
  }

  Widget _buildVitalRow(String k, String v) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          SizedBox(width: 170, child: Text(k, style: const TextStyle(fontSize: 10, color: Colors.grey))),
          Expanded(child: Text(v, style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold))),
        ],
      ),
    );
  }

  void _showBuilderNoteDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        titlePadding: const EdgeInsets.fromLTRB(20, 20, 20, 10),
        title: Row(
          children: [
            Container(
              width: 26,
              height: 26,
              decoration: const BoxDecoration(
                color: UbuntuTheme.ubuntuOrange,
                shape: BoxShape.circle,
              ),
              child: const Center(
                child: Text('👁', style: TextStyle(fontSize: 14)),
              ),
            ),
            const SizedBox(width: 12),
            const Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'DirtySOCS • About & Note from the Builder',
                    style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold),
                  ),
                  Text(
                    'Hybrid Kernel-Observability & Air-Gapped AI SOC Analyst System',
                    style: TextStyle(fontSize: 9, color: Colors.grey),
                  ),
                ],
              ),
            ),
          ],
        ),
        content: SizedBox(
          width: 580,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: const Color(0xFF1E1E1E),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFF383838)),
                ),
                child: const Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.edit_note, color: UbuntuTheme.ubuntuOrange, size: 16),
                        SizedBox(width: 8),
                        Text(
                          'A Note from the Builder',
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                            color: UbuntuTheme.ubuntuOrange,
                          ),
                        ),
                      ],
                    ),
                    SizedBox(height: 10),
                    Text(
                      '"New to Linux, but I am never going back. Becasue i am still working through Debian / Ubuntu this is only available in this format, for now. I wont disrespect you all with trying to AI my way into something that would work in Flatpak or .rpm. Becasue we are all transparent, this was built with AI as I can only read code, not really write it. The languages, the design, the problem its made to solve, the security posture, standards and testing were all mine. I take pride in being a systems thinker with deep respect and just enough knowledge to work with the specialists. Thank you for checking it out, stars, donations, comments, feedback... they all go a long way. Ronin"',
                      style: TextStyle(
                        fontSize: 11,
                        height: 1.5,
                        fontStyle: FontStyle.italic,
                        color: Color(0xFFDCDCDC),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 14),
              Row(
                children: [
                  Expanded(
                    child: Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: Theme.of(context).cardTheme.color,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Theme.of(context).colorScheme.outline),
                      ),
                      child: const Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('📦 PACKAGING', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.grey)),
                          SizedBox(height: 4),
                          Text('Native Debian (.deb) & apt', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                          Text('Install: sudo apt install ./dirtysocs.deb', style: TextStyle(fontSize: 9, color: Colors.grey)),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: Theme.of(context).cardTheme.color,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Theme.of(context).colorScheme.outline),
                      ),
                      child: const Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('⭐ SUPPORT & SPONSORSHIP', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.grey)),
                          SizedBox(height: 4),
                          Text('Star on GitHub & Donations', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                          Text('github.com/87Supreme-cell/DirtySOCS', style: TextStyle(fontSize: 9, color: UbuntuTheme.ubuntuOrange)),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            child: const Text('CLOSE', style: TextStyle(color: Colors.grey, fontWeight: FontWeight.bold)),
            onPressed: () => Navigator.of(ctx).pop(),
          ),
        ],
      ),
    );
  }
}

class _ModuleItem {
  final String title;
  final String desc;
  final String tag;
  final Color color;
  final int navIndex;

  _ModuleItem({
    required this.title,
    required this.desc,
    required this.tag,
    required this.color,
    required this.navIndex,
  });
}
