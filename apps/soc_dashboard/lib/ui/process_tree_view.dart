import 'package:flutter/material.dart';
import '../theme/ubuntu_theme.dart';

class ProcessTreeView extends StatelessWidget {
  const ProcessTreeView({super.key});

  @override
  Widget build(BuildContext context) {
    final nodes = [
      _TreeNode(label: 'systemd (PID: 1, UID: 0)', detail: 'Root Namespace Supervisor', indent: 0, status: 'BENIGN', color: UbuntuTheme.statusGreen),
      _TreeNode(label: '├── sshd (PID: 812, UID: 0)', detail: 'OpenSSH Server Daemon', indent: 1, status: 'BENIGN', color: UbuntuTheme.statusGreen),
      _TreeNode(label: '│   └── sshd: operator (PID: 1040, UID: 1000)', detail: 'Privilege Separation Child', indent: 2, status: 'SESSION', color: Colors.grey),
      _TreeNode(label: '│       └── bash (PID: 1042, UID: 1000)', detail: 'Interactive Login Shell', indent: 3, status: 'SESSION', color: Colors.grey),
      _TreeNode(label: '│           ├── curl (PID: 4819, UID: 1000)', detail: 'Fetched script via outbound HTTP', indent: 4, status: 'SUSPICIOUS', color: UbuntuTheme.statusYellow),
      _TreeNode(label: '│           ├── sh (PID: 4820, UID: 1000)', detail: 'Shell interpreter spawned script', indent: 4, status: 'SUSPICIOUS', color: UbuntuTheme.statusOrange),
      _TreeNode(label: '│           ├── .sys_update (PID: 4821, UID: 1000)', detail: 'Executing out of /tmp | Violates CIS 1.1.2', indent: 4, status: 'COMPROMISED', color: UbuntuTheme.statusRed),
      _TreeNode(label: '│           └── [?] orphaned_child (PID: 5120, Missing PPID)', detail: 'Orphaned / Missing Telemetry node handled cleanly without tree crash', indent: 4, status: 'ORPHANED / RECOVERED', color: UbuntuTheme.statusOrange),
      _TreeNode(label: '├── systemd-journald (PID: 340, UID: 0)', detail: 'In-Memory Journal Service', indent: 1, status: 'BENIGN', color: UbuntuTheme.statusGreen),
      _TreeNode(label: '└── dbus-daemon (PID: 610, UID: 104)', detail: 'System Message Bus Listener', indent: 1, status: 'BENIGN', color: UbuntuTheme.statusGreen),
    ];

    return Padding(
      padding: const EdgeInsets.all(20),
      child: Card(
        child: Padding(
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
                        'CORRELATED PROCESS HIERARCHY & LINEAGE',
                        style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: Theme.of(context).colorScheme.primary),
                      ),
                      const SizedBox(height: 4),
                      const Text(
                        'Parent-child process tree reconstructed via eBPF sys_enter_execve and Linux procfs',
                        style: TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                    ],
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(
                      color: UbuntuTheme.statusRed.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: UbuntuTheme.statusRed.withValues(alpha: 0.4)),
                    ),
                    child: const Text('1 COMPROMISED NODE DETECTED', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: UbuntuTheme.statusRed)),
                  ),
                ],
              ),
              const Divider(height: 24),
              Expanded(
                child: ListView.separated(
                  itemCount: nodes.length,
                  separatorBuilder: (_, _) => const SizedBox(height: 8),
                  itemBuilder: (context, index) {
                    final node = nodes[index];
                    return Container(
                      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                      decoration: BoxDecoration(
                        color: node.status == 'COMPROMISED'
                            ? UbuntuTheme.statusRed.withValues(alpha: 0.08)
                            : Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                          color: node.status == 'COMPROMISED' ? UbuntuTheme.statusRed.withValues(alpha: 0.4) : Colors.transparent,
                        ),
                      ),
                      child: Row(
                        children: [
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(node.label, style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                                const SizedBox(height: 2),
                                Text(node.detail, style: const TextStyle(fontSize: 10, color: Colors.grey)),
                              ],
                            ),
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            decoration: BoxDecoration(
                              color: node.color.withValues(alpha: 0.18),
                              borderRadius: BorderRadius.circular(5),
                              border: Border.all(color: node.color.withValues(alpha: 0.6)),
                            ),
                            child: Text(
                              node.status,
                              style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: node.color),
                            ),
                          ),
                        ],
                      ),
                    );
                  },
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _TreeNode {
  final String label;
  final String detail;
  final int indent;
  final String status;
  final Color color;

  _TreeNode({
    required this.label,
    required this.detail,
    required this.indent,
    required this.status,
    required this.color,
  });
}
