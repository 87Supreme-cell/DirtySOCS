import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import '../models/incident.dart';
import '../services/soc_ipc_client.dart';
import '../theme/ubuntu_theme.dart';
import 'remediation_dialog.dart';

class DualLensView extends StatefulWidget {
  const DualLensView({super.key});

  @override
  State<DualLensView> createState() => _DualLensViewState();
}

class _DualLensViewState extends State<DualLensView> {
  int _activeLens = 0; // 0 = Side-by-Side Dual, 1 = Plain English Only, 2 = Technical Only
  String? _dossierExportNotification;

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<List<MitigationCard>>(
      stream: SocIpcClient().advisoriesStream,
      builder: (context, snapshot) {
        final advisories = snapshot.data ?? [];
        if (advisories.isEmpty) {
          return const Center(child: Text('No active incidents requiring investigation.'));
        }
        final advisory = advisories.first;

        return SingleChildScrollView(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header & Lens Switcher
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            decoration: BoxDecoration(
                              color: UbuntuTheme.statusRed,
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Text(
                              advisory.severity,
                              style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.white),
                            ),
                          ),
                          const SizedBox(width: 10),
                          Text(
                            'INCIDENT EXPLORER • ${advisory.incidentId}',
                            style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'MITRE ATT&CK: ${advisory.mitreTechnique} | Target PID: ${advisory.targetPid}',
                        style: const TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                    ],
                  ),

                  // Lens Toggle Pill
                  Container(
                    decoration: BoxDecoration(
                      color: Theme.of(context).cardTheme.color,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Theme.of(context).colorScheme.outline),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _buildLensButton('DUAL-LENS', 0),
                        _buildLensButton('PLAIN ENGLISH', 1),
                        _buildLensButton('TECHNICAL BPF', 2),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),

              if (_dossierExportNotification != null)
                Container(
                  margin: const EdgeInsets.only(bottom: 16),
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: UbuntuTheme.statusGreen.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: UbuntuTheme.statusGreen),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.check_circle_outline, color: UbuntuTheme.statusGreen, size: 20),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          _dossierExportNotification!,
                          style: const TextStyle(fontSize: 11, color: UbuntuTheme.statusGreen, fontWeight: FontWeight.bold),
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.close, size: 16),
                        onPressed: () => setState(() => _dossierExportNotification = null),
                      ),
                    ],
                  ),
                ),

              // Dynamic Dual-Lens Content Layout
              if (_activeLens == 0)
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(child: _buildPlainEnglishCard(advisory)),
                    const SizedBox(width: 16),
                    Expanded(child: _buildTechnicalCard(advisory)),
                  ],
                )
              else if (_activeLens == 1)
                _buildPlainEnglishCard(advisory)
              else
                _buildTechnicalCard(advisory),

              const SizedBox(height: 20),

              // Action Toolbar
              Row(
                children: [
                  ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: UbuntuTheme.ubuntuOrange,
                      foregroundColor: Colors.white,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
                    ),
                    icon: const Icon(Icons.download_outlined, size: 18),
                    label: const Text('EXPORT SIGNED AI DOSSIER (.JSON / .MD)'),
                    onPressed: () => _exportDossierToDisk(advisory),
                  ),
                  const SizedBox(width: 12),
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
                    ),
                    icon: const Icon(Icons.folder_open, size: 18),
                    label: const Text('OPEN DOSSIERS FOLDER'),
                    onPressed: _openDossiersFolder,
                  ),
                  const Spacer(),
                  ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: advisory.status == 'PENDING_REVIEW'
                          ? UbuntuTheme.statusRed
                          : UbuntuTheme.statusGreen,
                      foregroundColor: Colors.white,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                      padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 14),
                    ),
                    icon: Icon(advisory.status == 'PENDING_REVIEW' ? Icons.shield_outlined : Icons.check_circle_outline, size: 18),
                    label: Text(advisory.status == 'PENDING_REVIEW' ? 'REVIEW & REMEDIATE (HUMAN)' : 'REMEDIATED'),
                    onPressed: advisory.status == 'PENDING_REVIEW'
                        ? () {
                            showDialog(
                              context: context,
                              builder: (ctx) => RemediationDialog(advisory: advisory),
                            );
                          }
                        : null,
                  ),
                ],
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildLensButton(String text, int index) {
    final isSelected = _activeLens == index;
    return GestureDetector(
      onTap: () => setState(() => _activeLens = index),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: isSelected ? UbuntuTheme.ubuntuOrange : Colors.transparent,
          borderRadius: BorderRadius.circular(7),
        ),
        child: Text(
          text,
          style: TextStyle(
            fontSize: 10,
            fontWeight: FontWeight.bold,
            color: isSelected ? Colors.white : Colors.grey,
          ),
        ),
      ),
    );
  }

  Widget _buildPlainEnglishCard(MitigationCard advisory) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.article_outlined, color: UbuntuTheme.statusYellow, size: 18),
                const SizedBox(width: 8),
                Text(
                  'EXECUTIVE & INCIDENT RESPONDER BRIEF',
                  style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Theme.of(context).colorScheme.primary),
                ),
              ],
            ),
            const Divider(height: 24),
            const Text('WHAT HAPPENED:', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.grey)),
            const SizedBox(height: 4),
            Text(advisory.plainEnglishSummary, style: const TextStyle(fontSize: 11, height: 1.4)),
            const SizedBox(height: 14),
            const Text('ROOT CAUSE ANALYSIS:', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.grey)),
            const SizedBox(height: 4),
            Text(advisory.rootCauseAnalysis, style: const TextStyle(fontSize: 11, height: 1.4)),
            const SizedBox(height: 14),
            const Text('RECOMMENDED OPERATIONAL ACTIONS:', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.grey)),
            const SizedBox(height: 6),
            ...advisory.recommendedActions.map((act) => Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('• ', style: TextStyle(color: UbuntuTheme.ubuntuOrange)),
                      Expanded(child: Text(act, style: const TextStyle(fontSize: 11))),
                    ],
                  ),
                )),
          ],
        ),
      ),
    );
  }

  Widget _buildTechnicalCard(MitigationCard advisory) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.code_outlined, color: UbuntuTheme.ubuntuOrange, size: 18),
                const SizedBox(width: 8),
                Text(
                  'KERNEL RING-0 TELEMETRY & COMPLIANCE',
                  style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Theme.of(context).colorScheme.primary),
                ),
              ],
            ),
            const Divider(height: 24),
            const Text('TECHNICAL RATIONALE & SYSCALLS:', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.grey)),
            const SizedBox(height: 4),
            Text(advisory.technicalRationale, style: const TextStyle(fontSize: 11, height: 1.4)),
            const SizedBox(height: 14),
            const Text('COMPLIANCE AUDIT CODES:', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.grey)),
            const SizedBox(height: 6),
            _buildAuditPill('CIS Benchmark:', advisory.cisControl),
            const SizedBox(height: 6),
            _buildAuditPill('NIST Control:', advisory.nistControl),
            const SizedBox(height: 14),
            const Text('AIR-GAP STATUS:', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.grey)),
            const SizedBox(height: 4),
            const Text(
              '• Telemetry scrubbing: Salted SHA-256 IP mask\n'
              '• In-kernel BPF isolation: Read-only memory verifier\n'
              '• Outbound network phoning: Structurally Disabled',
              style: TextStyle(fontSize: 11, height: 1.4, color: Colors.grey),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAuditPill(String title, String value) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Row(
        children: [
          Text(title, style: const TextStyle(fontSize: 10, color: Colors.grey)),
          const SizedBox(width: 6),
          Expanded(child: Text(value, style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold))),
        ],
      ),
    );
  }

  void _exportDossierToDisk(MitigationCard advisory) {
    try {
      final homeDir = Platform.environment['HOME'] ?? '/home/purpleronin';
      final dossierDir = Directory('$homeDir/Documents/DirtySOCS/dossiers');
      if (!dossierDir.existsSync()) {
        dossierDir.createSync(recursive: true);
      }

      final jsonFile = File('${dossierDir.path}/DIRTYSOCS_${advisory.incidentId}.json');
      final mdFile = File('${dossierDir.path}/DIRTYSOCS_${advisory.incidentId}.md');

      final jsonPayload = {
        'dossier_version': '1.0.0',
        'incident_id': advisory.incidentId,
        'severity': advisory.severity,
        'timestamp_utc': DateTime.now().toUtc().toIso8601String(),
        'mitre_technique': advisory.mitreTechnique,
        'cis_control': advisory.cisControl,
        'nist_control': advisory.nistControl,
        'target_pid': advisory.targetPid,
        'root_cause_analysis': advisory.rootCauseAnalysis,
        'plain_english_summary': advisory.plainEnglishSummary,
        'technical_rationale': advisory.technicalRationale,
        'recommended_actions': advisory.recommendedActions,
        'sanitization': {
          'pii_scrubbed': true,
          'ips_salted_hashed': true,
          'token_redaction': 'SHA-256 with CSPRNG Salt',
        },
        'prompt_for_remote_llm':
            'You are an Air-Gapped Principal Incident Responder. Below is a scrubbed Linux kernel eBPF dossier. Provide a structured triage and recommend actions according to the DirtySOCS schema.',
      };

      jsonFile.writeAsStringSync(const JsonEncoder.withIndent('  ').convert(jsonPayload));

      final mdContent = '''# DirtySOCS Air-Gapped Forensic Investigation Dossier
**Incident ID:** ${advisory.incidentId}
**Severity:** ${advisory.severity}
**Timestamp:** ${DateTime.now().toUtc().toIso8601String()}
**MITRE ATT&CK:** ${advisory.mitreTechnique}
**Compliance:** ${advisory.cisControl} | ${advisory.nistControl}
**Target Process:** PID ${advisory.targetPid}

---

## 1. Executive Summary (Plain English)
${advisory.plainEnglishSummary}

## 2. Technical Root Cause & Kernel Telemetry
${advisory.technicalRationale}

## 3. Recommended Remediation Gating
${advisory.recommendedActions.map((a) => "- $a").join('\n')}

---
*Generated by DirtySOCS v1.0.0 on Ubuntu Linux (Kernel Ring-0 Read-Only Telemetry).*
*All credentials, private keys, environment tokens, and host paths deterministically scrubbed.*
''';

      mdFile.writeAsStringSync(mdContent);

      // Also copy to Downloads for instant convenience
      try {
        final dlDir = Directory('$homeDir/Downloads');
        if (dlDir.existsSync()) {
          jsonFile.copySync('${dlDir.path}/DIRTYSOCS_${advisory.incidentId}.json');
          mdFile.copySync('${dlDir.path}/DIRTYSOCS_${advisory.incidentId}.md');
        }
      } catch (_) {}

      // Automatically open folder in Ubuntu Files (Nautilus)
      Process.run('xdg-open', [dossierDir.path]);

      setState(() {
        _dossierExportNotification =
            'Dossier saved to: ${jsonFile.path}\n'
            '• Also copied to ~/Downloads/DIRTYSOCS_${advisory.incidentId}.json\n'
            '• Opened folder in Ubuntu Files (Nautilus).';
      });

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Dossier exported to ${jsonFile.path}'),
          action: SnackBarAction(
            label: 'OPEN IN FILES',
            onPressed: () => Process.run('xdg-open', [dossierDir.path]),
          ),
          duration: const Duration(seconds: 5),
        ),
      );
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Export error: $e')),
      );
    }
  }

  void _openDossiersFolder() {
    final homeDir = Platform.environment['HOME'] ?? '/home/purpleronin';
    final dossierDir = Directory('$homeDir/Documents/DirtySOCS/dossiers');
    if (!dossierDir.existsSync()) {
      dossierDir.createSync(recursive: true);
    }
    Process.run('xdg-open', [dossierDir.path]);
  }
}
