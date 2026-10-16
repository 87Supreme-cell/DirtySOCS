import 'package:flutter/material.dart';
import '../theme/ubuntu_theme.dart';

class MitreMatrixView extends StatelessWidget {
  const MitreMatrixView({super.key});

  @override
  Widget build(BuildContext context) {
    final columns = [
      _MitreCol(title: 'INITIAL ACCESS', items: [
        _MitreItem(code: 'T1190', label: 'Exploit Public App', isAlert: false),
        _MitreItem(code: 'T1078', label: 'Valid Accounts', isAlert: false),
      ]),
      _MitreCol(title: 'EXECUTION', items: [
        _MitreItem(code: 'T1204', label: 'User Execution', isAlert: true),
        _MitreItem(code: 'T1059.004', label: 'Unix Shell Script', isAlert: true),
      ]),
      _MitreCol(title: 'PERSISTENCE', items: [
        _MitreItem(code: 'T1053', label: 'Cron / Scheduled Task', isAlert: false),
        _MitreItem(code: 'T1543', label: 'Systemd Unit Hijack', isAlert: false),
      ]),
      _MitreCol(title: 'PRIV ESCALATION', items: [
        _MitreItem(code: 'T1548', label: 'Abuse Sudo Mechanism', isAlert: false),
        _MitreItem(code: 'T1068', label: 'AppArmor Confinement Bypass', isAlert: true),
      ]),
      _MitreCol(title: 'DEFENSE EVASION', items: [
        _MitreItem(code: 'T1070', label: 'Log Tampering', isAlert: false),
        _MitreItem(code: 'T1027', label: 'Obfuscated Binary in /tmp', isAlert: true),
      ]),
      _MitreCol(title: 'CREDENTIAL ACCESS', items: [
        _MitreItem(code: 'T1003.008', label: '/etc/shadow Dumping', isAlert: true),
        _MitreItem(code: 'T1555', label: 'Credentials in Files', isAlert: false),
      ]),
    ];

    return Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'TACTICAL MITRE ATT&CK MATRIX (LINUX ENDPOINT CONTEXT)',
                    style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: Theme.of(context).colorScheme.primary),
                  ),
                  const SizedBox(height: 4),
                  const Text(
                    'Enterprise MITRE ATT&CK v14 tactics cross-referenced with active eBPF syscall triggers',
                    style: TextStyle(fontSize: 11, color: Colors.grey),
                  ),
                ],
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: UbuntuTheme.statusOrange.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: UbuntuTheme.statusOrange.withValues(alpha: 0.4)),
                ),
                child: const Text('ACTIVE ADVERSARY PATH DETECTED', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: UbuntuTheme.statusOrange)),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Expanded(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: columns.map((col) {
                return Expanded(
                  child: Container(
                    margin: const EdgeInsets.symmetric(horizontal: 4),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Container(
                          padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 6),
                          decoration: BoxDecoration(
                            color: Theme.of(context).colorScheme.surfaceContainerHighest,
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Text(
                            col.title,
                            textAlign: TextAlign.center,
                            style: const TextStyle(fontSize: 9, fontWeight: FontWeight.bold, letterSpacing: 0.5),
                          ),
                        ),
                        const SizedBox(height: 8),
                        Expanded(
                          child: ListView.separated(
                            itemCount: col.items.length,
                            separatorBuilder: (_, _) => const SizedBox(height: 6),
                            itemBuilder: (context, idx) {
                              final item = col.items[idx];
                              return Container(
                                padding: const EdgeInsets.all(10),
                                decoration: BoxDecoration(
                                  color: item.isAlert
                                      ? UbuntuTheme.statusRed.withValues(alpha: 0.12)
                                      : Theme.of(context).cardTheme.color,
                                  borderRadius: BorderRadius.circular(8),
                                  border: Border.all(
                                    color: item.isAlert
                                        ? UbuntuTheme.statusRed.withValues(alpha: 0.6)
                                        : Theme.of(context).colorScheme.outline,
                                  ),
                                ),
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Row(
                                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                      children: [
                                        Text(item.code, style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: item.isAlert ? UbuntuTheme.statusRed : Colors.grey)),
                                        if (item.isAlert)
                                          Container(
                                            padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
                                            decoration: BoxDecoration(
                                              color: UbuntuTheme.statusRed,
                                              borderRadius: BorderRadius.circular(4),
                                            ),
                                            child: const Text('TRIGGERED', style: TextStyle(fontSize: 7, fontWeight: FontWeight.bold, color: Colors.white)),
                                          ),
                                      ],
                                    ),
                                    const SizedBox(height: 4),
                                    Text(item.label, style: const TextStyle(fontSize: 10, height: 1.3)),
                                  ],
                                ),
                              );
                            },
                          ),
                        ),
                      ],
                    ),
                  ),
                );
              }).toList(),
            ),
          ),
        ],
      ),
    );
  }
}

class _MitreCol {
  final String title;
  final List<_MitreItem> items;
  _MitreCol({required this.title, required this.items});
}

class _MitreItem {
  final String code;
  final String label;
  final bool isAlert;
  _MitreItem({required this.code, required this.label, required this.isAlert});
}
