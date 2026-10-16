class HostTelemetry {
  final double cpuPercent;
  final int memoryRssBytes;
  final int totalMemoryBytes;
  final int openFds;
  final int activeProcs;
  final double riskScore; // 0.0 (0% nominal) to 1.0 (100% critical)
  final String statusLabel;

  HostTelemetry({
    required this.cpuPercent,
    required this.memoryRssBytes,
    required this.totalMemoryBytes,
    required this.openFds,
    required this.activeProcs,
    required this.riskScore,
    required this.statusLabel,
  });

  String get formattedRssMb =>
      '${(memoryRssBytes / (1024 * 1024)).toStringAsFixed(1)} MB';

  String get formattedTotalGb =>
      '${(totalMemoryBytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
}

class TrendPoint {
  final DateTime time;
  final double eventsPerSec;
  final double noiseDropPercent;
  final double riskScore;

  TrendPoint({
    required this.time,
    required this.eventsPerSec,
    required this.noiseDropPercent,
    required this.riskScore,
  });
}
