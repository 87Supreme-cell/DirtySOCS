import 'dart:async';
import '../models/host_metrics.dart';
import '../models/incident.dart';

class SocIpcClient {
  static final SocIpcClient _instance = SocIpcClient._internal();
  factory SocIpcClient() => _instance;

  final _metricsController = StreamController<HostTelemetry>.broadcast();
  final _logsController = StreamController<List<TelemetryLog>>.broadcast();
  final _trendController = StreamController<List<TrendPoint>>.broadcast();
  final _advisoriesController = StreamController<List<MitigationCard>>.broadcast();

  Stream<HostTelemetry> get metricsStream => _metricsController.stream;
  Stream<List<TelemetryLog>> get logsStream => _logsController.stream;
  Stream<List<TrendPoint>> get trendStream => _trendController.stream;
  Stream<List<MitigationCard>> get advisoriesStream => _advisoriesController.stream;

  final List<TelemetryLog> _storedLogs = [];
  final List<TrendPoint> _storedTrends = [];
  final List<MitigationCard> _storedAdvisories = [];
  Timer? _ticker;

  SocIpcClient._internal() {
    _initData();
    _startLiveStream();
  }

  void _initData() {
    // Populate Initial Previous Logs Archive
    _storedLogs.addAll([
      TelemetryLog(
        timestamp: '16:38:53',
        subsystem: 'ebpf',
        eventType: 'sys_enter_execve',
        process: '.sys_update',
        pid: 4821,
        count: 1,
        riskLevel: 'CRITICAL',
        targetPath: '/tmp/.sys_update',
        details: 'Execution from unprivileged temporary directory violating CIS-RHEL-1.1.2',
      ),
      TelemetryLog(
        timestamp: '16:38:53',
        subsystem: 'ebpf',
        eventType: 'sys_enter_openat',
        process: '.sys_update',
        pid: 4821,
        count: 1,
        riskLevel: 'CRITICAL',
        targetPath: '/etc/shadow',
        details: 'Unauthorized credential store read attempt intercepted via eBPF',
      ),
      TelemetryLog(
        timestamp: '16:38:50',
        subsystem: 'dbus',
        eventType: 'apparmor_denial',
        process: 'snapd-desktop',
        pid: 4117,
        count: 4,
        riskLevel: 'HIGH_RISK',
        targetPath: 'org.freedesktop.host.portal.Registry',
        details: 'D-Bus mediation denial emitted under confined profile',
      ),
      TelemetryLog(
        timestamp: '16:38:40',
        subsystem: 'systemd',
        eventType: 'service_failure',
        process: 'auditd.service',
        pid: 840,
        count: 1,
        riskLevel: 'CAUTION',
        targetPath: '/lib/systemd/system/auditd.service',
        details: 'Audit logging unit exited with non-zero status',
      ),
      TelemetryLog(
        timestamp: '16:38:25',
        subsystem: 'ebpf',
        eventType: 'sys_enter_connect',
        process: 'curl',
        pid: 1092,
        count: 18,
        riskLevel: 'NOMINAL',
        targetPath: 'port: 443 [ip-7f9a12]',
        details: 'Salted-hashed outbound socket connection attempt',
      ),
      TelemetryLog(
        timestamp: '16:38:00',
        subsystem: 'journal',
        eventType: 'css_parse_warn',
        process: 'gnome-shell',
        pid: 1840,
        count: 1240,
        riskLevel: 'NOMINAL',
        targetPath: 'desktop-styling.css',
        details: 'Repetitive CSS parse noise collapsed via 60s sliding window',
      ),
    ]);

    // Populate Initial Active Advisory
    _storedAdvisories.add(
      MitigationCard(
        incidentId: 'INC-84821',
        severity: 'CRITICAL',
        mitreTechnique: 'T1059.004 - Unix Shell Execution',
        cisControl: 'CIS RHEL 9 (Control 1.1.2)',
        nistControl: 'NIST SP 800-53 (AC-6 / AU-12)',
        rootCauseAnalysis:
            'A suspicious binary (.sys_update) executed out of world-writable /tmp and immediately attempted to read /etc/shadow.',
        plainEnglishSummary:
            'A hidden program launched from a temporary folder and tried to read system password files. Confinement blocked the file read, but the compromised process is still running.',
        technicalRationale:
            'Ring-0 eBPF tracepoint sys_enter_execve detected execution out of /tmp (violates CIS RHEL 9 mount controls). sys_enter_openat intercepted flags 0x0 targeting /etc/shadow.',
        recommendedActions: [
          'Authorize SIGTERM -> SIGKILL escalation on PID 4821',
          'Freeze parent cgroup (user-1000.slice)',
          'Verify /tmp filesystem mount options (ensure noexec,nosuid)',
        ],
        status: 'PENDING_REVIEW',
        targetPid: 4821,
      ),
    );

    // Populate Initial Historical Trends
    final now = DateTime.now();
    for (int i = 12; i >= 0; i--) {
      _storedTrends.add(
        TrendPoint(
          time: now.subtract(Duration(minutes: i * 5)),
          eventsPerSec: 120.0 + (i % 3) * 45,
          noiseDropPercent: 98.8 + (i % 2) * 0.7,
          riskScore: (i == 0) ? 0.75 : (0.15 + (i % 4) * 0.1),
        ),
      );
    }
  }

  void _startLiveStream() {
    _ticker = Timer.periodic(const Duration(seconds: 2), (timer) {
      // 75% at risk status as requested in prompt!
      final telemetry = HostTelemetry(
        cpuPercent: 2.4,
        memoryRssBytes: 28 * 1024 * 1024,
        totalMemoryBytes: 16 * 1024 * 1024 * 1024,
        openFds: 77,
        activeProcs: 376,
        riskScore: 0.75, // 75% At Risk (Orange status)
        statusLabel: '75% AT RISK (ORANGE HIGH ALERT)',
      );

      _metricsController.add(telemetry);
      _logsController.add(List.from(_storedLogs));
      _trendController.add(List.from(_storedTrends));
      _advisoriesController.add(List.from(_storedAdvisories));
    });
  }

  Future<bool> executeRemediation({
    required String incidentId,
    required String action,
    required int targetPid,
  }) async {
    // Hardcoded parameter verification
    if (targetPid <= 1) return false;

    // Update local advisory status to EXECUTED
    for (int i = 0; i < _storedAdvisories.length; i++) {
      if (_storedAdvisories[i].incidentId == incidentId) {
        _storedAdvisories[i] = MitigationCard(
          incidentId: incidentId,
          severity: 'RESOLVED',
          mitreTechnique: _storedAdvisories[i].mitreTechnique,
          cisControl: _storedAdvisories[i].cisControl,
          nistControl: _storedAdvisories[i].nistControl,
          rootCauseAnalysis: _storedAdvisories[i].rootCauseAnalysis,
          plainEnglishSummary: 'Threat neutralized: Process terminated and isolated.',
          technicalRationale: _storedAdvisories[i].technicalRationale,
          recommendedActions: ['Remediation verified: PID $targetPid exited.'],
          status: 'EXECUTED_BY_OPERATOR',
          targetPid: targetPid,
        );
      }
    }

    _advisoriesController.add(List.from(_storedAdvisories));
    return true;
  }

  void dispose() {
    _ticker?.cancel();
    _metricsController.close();
    _logsController.close();
    _trendController.close();
    _advisoriesController.close();
  }
}
