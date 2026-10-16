class TelemetryLog {
  final String timestamp;
  final String subsystem; // "ebpf", "dbus", "systemd"
  final String eventType;
  final String process;
  final int pid;
  final int count;
  final String riskLevel; // "NOMINAL", "CAUTION", "HIGH_RISK", "CRITICAL"
  final String targetPath;
  final String details;

  TelemetryLog({
    required this.timestamp,
    required this.subsystem,
    required this.eventType,
    required this.process,
    required this.pid,
    required this.count,
    required this.riskLevel,
    required this.targetPath,
    required this.details,
  });

  factory TelemetryLog.fromJson(Map<String, dynamic> json) {
    return TelemetryLog(
      timestamp: json['timestamp'] ?? '',
      subsystem: json['subsystem'] ?? 'ebpf',
      eventType: json['type'] ?? 'sys_enter_execve',
      process: json['process'] ?? 'unknown',
      pid: json['pid'] ?? 0,
      count: json['count'] ?? 1,
      riskLevel: json['risk_level'] ?? 'NOMINAL',
      targetPath: json['target_path'] ?? '',
      details: json['details'] ?? '',
    );
  }
}

class MitigationCard {
  final String incidentId;
  final String severity; // "LOW", "MEDIUM", "HIGH", "CRITICAL"
  final String mitreTechnique;
  final String cisControl;
  final String nistControl;
  final String rootCauseAnalysis;
  final String plainEnglishSummary;
  final String technicalRationale;
  final List<String> recommendedActions;
  final String status;
  final int targetPid;

  MitigationCard({
    required this.incidentId,
    required this.severity,
    required this.mitreTechnique,
    required this.cisControl,
    required this.nistControl,
    required this.rootCauseAnalysis,
    required this.plainEnglishSummary,
    required this.technicalRationale,
    required this.recommendedActions,
    required this.status,
    required this.targetPid,
  });
}
