import 'package:flutter/material.dart';
import '../theme/ubuntu_theme.dart';

class RunPromptDialog extends StatefulWidget {
  final VoidCallback onAcceptedAndConfirmed;

  const RunPromptDialog({
    super.key,
    required this.onAcceptedAndConfirmed,
  });

  @override
  State<RunPromptDialog> createState() => _RunPromptDialogState();
}

class _RunPromptDialogState extends State<RunPromptDialog> {
  int _step = 1; // 1 = Initial Prompt, 2 = Double Confirmation
  bool _confirmedCheckbox = false;

  @override
  Widget build(BuildContext context) {
    if (_step == 1) {
      return _buildInitialPrompt(context);
    } else {
      return _buildDoubleConfirmation(context);
    }
  }

  Widget _buildInitialPrompt(BuildContext context) {
    return AlertDialog(
      titlePadding: const EdgeInsets.all(20),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: UbuntuTheme.ubuntuOrange.withValues(alpha: 0.15),
              shape: BoxShape.circle,
            ),
            child: const Icon(Icons.bolt, color: UbuntuTheme.ubuntuOrange, size: 20),
          ),
          const SizedBox(width: 12),
          const Text('1. RUN INITIALIZATION PROMPT', style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
        ],
      ),
      content: SizedBox(
        width: 480,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'DirtySOCS Session Detected:\n\n'
              'Would you like to initiate real-time eBPF kernel observability now?',
              style: TextStyle(fontSize: 12, height: 1.4),
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).cardTheme.color,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Theme.of(context).colorScheme.outline),
              ),
              child: const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('• Read-only kernel tracepoints', style: TextStyle(fontSize: 10, color: Colors.grey)),
                  SizedBox(height: 4),
                  Text('• Deterministic CIS & NIST rule gate', style: TextStyle(fontSize: 10, color: Colors.grey)),
                  SizedBox(height: 4),
                  Text('• Non-blocking 1MB kernel ring buffer', style: TextStyle(fontSize: 10, color: Colors.grey)),
                ],
              ),
            ),
          ],
        ),
      ),
      actionsPadding: const EdgeInsets.all(16),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('DECLINE / OFFLINE MODE', style: TextStyle(color: Colors.grey)),
        ),
        ElevatedButton(
          style: ElevatedButton.styleFrom(
            backgroundColor: UbuntuTheme.ubuntuOrange,
            foregroundColor: Colors.white,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
          ),
          onPressed: () {
            setState(() {
              _step = 2; // Advance to double confirmation
            });
          },
          child: const Text('ACCEPT RUN ->', style: TextStyle(fontWeight: FontWeight.bold)),
        ),
      ],
    );
  }

  Widget _buildDoubleConfirmation(BuildContext context) {
    return AlertDialog(
      titlePadding: EdgeInsets.zero,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      title: Container(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        decoration: BoxDecoration(
          color: UbuntuTheme.statusRed.withValues(alpha: 0.12),
          borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
          border: Border(bottom: BorderSide(color: UbuntuTheme.statusRed.withValues(alpha: 0.3))),
        ),
        child: Row(
          children: [
            const Icon(Icons.warning_amber_rounded, color: UbuntuTheme.statusRed, size: 24),
            const SizedBox(width: 12),
            const Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '2. ACCIDENTAL LAUNCH PREVENTION',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 0.5,
                      color: UbuntuTheme.statusRed,
                    ),
                  ),
                  SizedBox(height: 2),
                  Text(
                    'CONFIRM KERNEL PROBE ATTACHMENT',
                    style: TextStyle(fontSize: 10, color: Colors.grey),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
      content: SizedBox(
        width: 520,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'SAFETY VERIFICATION PROTOCOL:',
              style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: UbuntuTheme.ubuntuOrange),
            ),
            const SizedBox(height: 8),
            const Text(
              'You are about to attach eBPF tracepoints to the active Linux kernel:\n'
              '  • sys_enter_execve (Process executions)\n'
              '  • sys_enter_openat (Restricted file reads)\n'
              '  • sys_enter_connect (Network sockets)\n\n'
              'To avoid launching the system accidentally, explicit secondary human verification is required before allocating ring buffers.',
              style: TextStyle(fontSize: 11, height: 1.4, color: Colors.grey),
            ),
            const SizedBox(height: 16),

            // Checkbox
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).cardTheme.color,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Theme.of(context).colorScheme.outline),
              ),
              child: CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                value: _confirmedCheckbox,
                activeColor: UbuntuTheme.ubuntuOrange,
                onChanged: (val) => setState(() => _confirmedCheckbox = val ?? false),
                title: const Text(
                  'I confirm operational intent to attach eBPF sensors and monitor endpoint telemetry.',
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
                ),
              ),
            ),
          ],
        ),
      ),
      actionsPadding: const EdgeInsets.all(16),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('CANCEL', style: TextStyle(color: Colors.grey)),
        ),
        ElevatedButton(
          style: ElevatedButton.styleFrom(
            backgroundColor: _confirmedCheckbox ? UbuntuTheme.ubuntuOrange : Colors.grey.withValues(alpha: 0.3),
            foregroundColor: Colors.white,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
          ),
          onPressed: _confirmedCheckbox
              ? () {
                  Navigator.of(context).pop();
                  widget.onAcceptedAndConfirmed();
                }
              : null,
          child: const Text('CONFIRM & COMMENCE RUN', style: TextStyle(fontWeight: FontWeight.bold)),
        ),
      ],
    );
  }
}
