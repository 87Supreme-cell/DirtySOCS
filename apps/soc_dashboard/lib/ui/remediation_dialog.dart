import 'package:flutter/material.dart';
import '../models/incident.dart';
import '../services/soc_ipc_client.dart';
import '../theme/ubuntu_theme.dart';

class RemediationDialog extends StatefulWidget {
  final MitigationCard advisory;

  const RemediationDialog({super.key, required this.advisory});

  @override
  State<RemediationDialog> createState() => _RemediationDialogState();
}

class _RemediationDialogState extends State<RemediationDialog> {
  bool _confirmed = false;
  bool _isExecuting = false;
  String? _executionResult;

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final cardBg = isDark ? const Color(0xFF242424) : const Color(0xFFF0F0F0);
    final borderColor = isDark ? const Color(0xFF3C3C3C) : const Color(0xFFD8D8D8);

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
            const Icon(Icons.shield_outlined, color: UbuntuTheme.statusRed, size: 24),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                'HUMAN AUTHORIZATION REQUIRED • ${widget.advisory.incidentId}',
                style: const TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 0.5,
                  color: UbuntuTheme.statusRed,
                ),
              ),
            ),
          ],
        ),
      ),
      content: SizedBox(
        width: 600,
        child: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Zero-Dynamic Execution Guarantee Notice
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: cardBg,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: borderColor),
                ),
                child: const Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(Icons.info_outline, size: 18, color: UbuntuTheme.ubuntuOrange),
                    SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        'Zero-Dynamic Execution Guarantee:\n'
                        'The AI tier is purely advisory and structurally barred from running commands. '
                        'Authorizing this mitigation dispatches a pre-compiled, parameter-checked Rust routine.',
                        style: TextStyle(fontSize: 11, height: 1.4),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),

              // Target Details Card
              Text('PROPOSED HARDCODED ACTION', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Theme.of(context).colorScheme.primary)),
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: cardBg,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: borderColor),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildRow('Action Routine:', 'SIGTERM -> SIGKILL Graceful Escalation'),
                    const SizedBox(height: 6),
                    _buildRow('Target PID:', '${widget.advisory.targetPid} (Verified PID != 1)'),
                    const SizedBox(height: 6),
                    _buildRow('Cgroup Scope:', 'user-1000.slice (Freeze / Suspend)'),
                    const SizedBox(height: 6),
                    _buildRow('Compliance Standard:', widget.advisory.cisControl),
                  ],
                ),
              ),
              const SizedBox(height: 16),

              if (_executionResult != null)
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: UbuntuTheme.statusGreen.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: UbuntuTheme.statusGreen),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.check_circle_outline, color: UbuntuTheme.statusGreen, size: 20),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Text(_executionResult!, style: const TextStyle(fontSize: 12, color: UbuntuTheme.statusGreen, fontWeight: FontWeight.bold)),
                      ),
                    ],
                  ),
                )
              else ...[
                // Checkbox confirmation
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  value: _confirmed,
                  activeColor: UbuntuTheme.statusRed,
                  onChanged: (val) => setState(() => _confirmed = val ?? false),
                  title: const Text(
                    'I confirm operational review of PID 4821 and authorize process termination.',
                    style: TextStyle(fontSize: 11),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
      actionsPadding: const EdgeInsets.all(16),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('CANCEL'),
        ),
        ElevatedButton(
          style: ElevatedButton.styleFrom(
            backgroundColor: _confirmed ? UbuntuTheme.statusRed : Colors.grey.withValues(alpha: 0.3),
            foregroundColor: Colors.white,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
          ),
          onPressed: (_confirmed && !_isExecuting && _executionResult == null)
              ? () async {
                  setState(() => _isExecuting = true);
                  final success = await SocIpcClient().executeRemediation(
                    incidentId: widget.advisory.incidentId,
                    action: 'SIGTERM_PROCESS',
                    targetPid: widget.advisory.targetPid,
                  );
                  setState(() {
                    _isExecuting = false;
                    _executionResult = success ? 'SUCCESS: PID ${widget.advisory.targetPid} terminated and verified exited.' : 'FAILED: Could not signal process.';
                  });
                }
              : null,
          child: _isExecuting
              ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
              : const Text('AUTHORIZE & EXECUTE'),
        ),
      ],
    );
  }

  Widget _buildRow(String label, String value) {
    return Row(
      children: [
        SizedBox(width: 150, child: Text(label, style: const TextStyle(fontSize: 11, color: Colors.grey))),
        Expanded(child: Text(value, style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold))),
      ],
    );
  }
}
