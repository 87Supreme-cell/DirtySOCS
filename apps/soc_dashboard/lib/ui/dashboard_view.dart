import 'package:flutter/material.dart';
import '../models/host_metrics.dart';
import '../models/incident.dart';
import '../services/soc_ipc_client.dart';
import '../theme/ubuntu_theme.dart';

class DashboardView extends StatefulWidget {
  const DashboardView({super.key});

  @override
  State<DashboardView> createState() => _DashboardViewState();
}

class _DashboardViewState extends State<DashboardView> {
  String _selectedSubsystem = 'ALL';
  String _searchQuery = '';

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<HostTelemetry>(
      stream: SocIpcClient().metricsStream,
      initialData: HostTelemetry(
        cpuPercent: 2.4,
        memoryRssBytes: 28 * 1024 * 1024,
        totalMemoryBytes: 16 * 1024 * 1024 * 1024,
        openFds: 77,
        activeProcs: 376,
        riskScore: 0.75, // 75% at risk
        statusLabel: '75% AT RISK (ORANGE HIGH ALERT)',
      ),
      builder: (context, metricsSnapshot) {
        final metrics = metricsSnapshot.data!;

        return StreamBuilder<List<TelemetryLog>>(
          stream: SocIpcClient().logsStream,
          initialData: const [],
          builder: (context, logsSnapshot) {
            final allLogs = logsSnapshot.data ?? [];
            final filteredLogs = allLogs.where((log) {
              final matchesSubsystem = _selectedSubsystem == 'ALL' ||
                  log.subsystem.toUpperCase() == _selectedSubsystem;
              final matchesQuery = _searchQuery.isEmpty ||
                  log.process.toLowerCase().contains(_searchQuery.toLowerCase()) ||
                  log.targetPath.toLowerCase().contains(_searchQuery.toLowerCase()) ||
                  log.details.toLowerCase().contains(_searchQuery.toLowerCase()) ||
                  log.pid.toString().contains(_searchQuery);
              return matchesSubsystem && matchesQuery;
            }).toList();

            return SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // 1. Current Status Banner with Granular Hue Gauge (Red, Yellow, Green & hues in-between)
                  _buildGranularHealthCard(metrics),
                  const SizedBox(height: 16),

                  // 2. Host Telemetry KPI Cards
                  Row(
                    children: [
                      Expanded(child: _buildMetricTile('CGROUP CPU', '${metrics.cpuPercent.toStringAsFixed(1)}%', 'Normal usage', Icons.speed)),
                      const SizedBox(width: 12),
                      Expanded(child: _buildMetricTile('RESIDENT RAM', metrics.formattedRssMb, 'Bounded 1MB ringbuf', Icons.memory)),
                      const SizedBox(width: 12),
                      Expanded(child: _buildMetricTile('OPEN FDS', '${metrics.openFds}', 'RAII auto-cleanup', Icons.folder_open)),
                      const SizedBox(width: 12),
                      Expanded(child: _buildMetricTile('ACTIVE PROCS', '${metrics.activeProcs}', 'Procfs monitoring', Icons.account_tree_outlined)),
                    ],
                  ),
                  const SizedBox(height: 16),

                  // 3. Trend Analysis Card (Velocity & Noise Collapse)
                  _buildTrendAnalysisCard(),
                  const SizedBox(height: 16),

                  // 4. Historical & Previous Logs Store
                  _buildLogsStoreCard(filteredLogs),
                ],
              ),
            );
          },
        );
      },
    );
  }

  Widget _buildGranularHealthCard(HostTelemetry metrics) {
    final healthColor = UbuntuTheme.getGranularHealthColor(metrics.riskScore);
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    Container(
                      width: 14,
                      height: 14,
                      decoration: BoxDecoration(
                        color: healthColor,
                        shape: BoxShape.circle,
                        boxShadow: [
                          BoxShadow(
                            color: healthColor.withValues(alpha: 0.5),
                            blurRadius: 8,
                            spreadRadius: 2,
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 10),
                    Text(
                      'SYSTEM THREAT LEVEL: ${metrics.statusLabel}',
                      style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.bold,
                        color: healthColor,
                      ),
                    ),
                  ],
                ),
                Text(
                  '${(metrics.riskScore * 100).toInt()}% Risk Factor',
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.bold,
                    color: healthColor,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),

            // Continuous Granular Spectrum Bar (Green -> Lime -> Yellow -> Orange -> Red)
            Container(
              height: 10,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(5),
                gradient: const LinearGradient(
                  colors: [
                    UbuntuTheme.statusGreen,
                    UbuntuTheme.statusLime,
                    UbuntuTheme.statusYellow,
                    UbuntuTheme.statusOrange,
                    UbuntuTheme.statusRed,
                  ],
                ),
              ),
              child: LayoutBuilder(
                builder: (context, constraints) {
                  return Stack(
                    children: [
                      Positioned(
                        left: (constraints.maxWidth * metrics.riskScore) - 6,
                        top: 0,
                        bottom: 0,
                        child: Container(
                          width: 12,
                          decoration: BoxDecoration(
                            color: isDark ? Colors.white : Colors.black,
                            shape: BoxShape.circle,
                            border: Border.all(color: healthColor, width: 2),
                          ),
                        ),
                      ),
                    ],
                  );
                },
              ),
            ),
            const SizedBox(height: 8),

            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: const [
                Text('NOMINAL (0%)', style: TextStyle(fontSize: 9, color: UbuntuTheme.statusGreen, fontWeight: FontWeight.bold)),
                Text('LOW (25%)', style: TextStyle(fontSize: 9, color: UbuntuTheme.statusLime, fontWeight: FontWeight.bold)),
                Text('CAUTION (50%)', style: TextStyle(fontSize: 9, color: UbuntuTheme.statusYellow, fontWeight: FontWeight.bold)),
                Text('ALERT (75% AT RISK)', style: TextStyle(fontSize: 9, color: UbuntuTheme.statusOrange, fontWeight: FontWeight.bold)),
                Text('CRITICAL (100%)', style: TextStyle(fontSize: 9, color: UbuntuTheme.statusRed, fontWeight: FontWeight.bold)),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildMetricTile(String title, String value, String sub, IconData icon) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(title, style: const TextStyle(fontSize: 10, color: Colors.grey, fontWeight: FontWeight.bold)),
                Icon(icon, size: 16, color: Theme.of(context).colorScheme.primary),
              ],
            ),
            const SizedBox(height: 6),
            Text(value, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
            const SizedBox(height: 4),
            Text(sub, style: const TextStyle(fontSize: 9, color: Colors.grey)),
          ],
        ),
      ),
    );
  }

  Widget _buildTrendAnalysisCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
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
                      'EVENT INGESTION & NOISE REDUCTION TRENDS',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                    ),
                    const SizedBox(height: 4),
                    const Text(
                      '60-minute sliding window rate analysis and deduplication efficiency',
                      style: TextStyle(fontSize: 10, color: Colors.grey),
                    ),
                  ],
                ),
                Row(
                  children: [
                    _buildLegendItem('Events/sec', UbuntuTheme.ubuntuOrange),
                    const SizedBox(width: 14),
                    _buildLegendItem('Noise Suppressed (99.4%)', UbuntuTheme.statusGreen),
                  ],
                ),
              ],
            ),
            const SizedBox(height: 16),

            // Custom Painted Trend Sparkline
            SizedBox(
              height: 90,
              width: double.infinity,
              child: CustomPaint(
                painter: _TrendChartPainter(isDark: Theme.of(context).brightness == Brightness.dark),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildLegendItem(String label, Color color) {
    return Row(
      children: [
        Container(width: 8, height: 8, decoration: BoxDecoration(color: color, shape: BoxShape.circle)),
        const SizedBox(width: 6),
        Text(label, style: const TextStyle(fontSize: 10, color: Colors.grey)),
      ],
    );
  }

  Widget _buildLogsStoreCard(List<TelemetryLog> logs) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'HISTORICAL & PREVIOUS LOGS STORE',
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Stored events deduplicated across 60s windows with PII redaction (${logs.length} entries)',
                        style: const TextStyle(fontSize: 10, color: Colors.grey),
                      ),
                    ],
                  ),
                ),
                // Subsystem Selector Filter
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: DropdownButtonHideUnderline(
                    child: DropdownButton<String>(
                      value: _selectedSubsystem,
                      style: TextStyle(
                        fontFamily: 'Monaco',
                        fontSize: 10,
                        color: Theme.of(context).colorScheme.onSurface,
                        fontWeight: FontWeight.bold,
                      ),
                      items: ['ALL', 'EBPF', 'DBUS', 'SYSTEMD', 'JOURNAL']
                          .map((val) => DropdownMenuItem(value: val, child: Text(val)))
                          .toList(),
                      onChanged: (val) => setState(() => _selectedSubsystem = val ?? 'ALL'),
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                // Search Input
                SizedBox(
                  width: 200,
                  height: 36,
                  child: TextField(
                    style: const TextStyle(fontSize: 11),
                    decoration: InputDecoration(
                      hintText: 'Search PID, path, comm...',
                      hintStyle: const TextStyle(fontSize: 10, color: Colors.grey),
                      prefixIcon: const Icon(Icons.search, size: 16),
                      contentPadding: const EdgeInsets.symmetric(vertical: 0, horizontal: 10),
                      filled: true,
                      fillColor: Theme.of(context).colorScheme.surfaceContainerHighest,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: BorderSide.none,
                      ),
                    ),
                    onChanged: (val) => setState(() => _searchQuery = val),
                  ),
                ),
              ],
            ),
            const Divider(height: 24),

            // Log Table
            ListView.separated(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: logs.length,
              separatorBuilder: (_, _) => const Divider(height: 12),
              itemBuilder: (context, index) {
                final log = logs[index];
                Color badgeColor;
                switch (log.riskLevel) {
                  case 'CRITICAL':
                    badgeColor = UbuntuTheme.statusRed;
                    break;
                  case 'HIGH_RISK':
                    badgeColor = UbuntuTheme.statusOrange;
                    break;
                  case 'CAUTION':
                    badgeColor = UbuntuTheme.statusYellow;
                    break;
                  default:
                    badgeColor = UbuntuTheme.statusGreen;
                }

                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: Row(
                    children: [
                      SizedBox(
                        width: 70,
                        child: Text(log.timestamp, style: const TextStyle(fontSize: 10, color: Colors.grey)),
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.surfaceContainerHighest,
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          log.subsystem.toUpperCase(),
                          style: const TextStyle(fontSize: 8, fontWeight: FontWeight.bold),
                        ),
                      ),
                      const SizedBox(width: 10),
                      SizedBox(
                        width: 140,
                        child: Text(log.eventType, style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                      ),
                      SizedBox(
                        width: 120,
                        child: Text('${log.process} (PID ${log.pid})', style: const TextStyle(fontSize: 10)),
                      ),
                      Expanded(
                        child: Text(
                          log.targetPath.isNotEmpty ? log.targetPath : log.details,
                          style: const TextStyle(fontSize: 10, color: Colors.grey),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      if (log.count > 1) ...[
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: UbuntuTheme.ubuntuOrange.withValues(alpha: 0.15),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text('×${log.count}', style: const TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: UbuntuTheme.ubuntuOrange)),
                        ),
                        const SizedBox(width: 8),
                      ],
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: badgeColor.withValues(alpha: 0.18),
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(color: badgeColor.withValues(alpha: 0.5)),
                        ),
                        child: Text(
                          log.riskLevel,
                          style: TextStyle(fontSize: 8, fontWeight: FontWeight.bold, color: badgeColor),
                        ),
                      ),
                    ],
                  ),
                );
              },
            ),
          ],
        ),
      ),
    );
  }
}

class _TrendChartPainter extends CustomPainter {
  final bool isDark;
  _TrendChartPainter({required this.isDark});

  @override
  void paint(Canvas canvas, Size size) {
    final gridPaint = Paint()
      ..color = (isDark ? Colors.white : Colors.black).withValues(alpha: 0.06)
      ..strokeWidth = 1;

    // Draw horizontal grid lines
    for (double y = 0; y <= size.height; y += size.height / 3) {
      canvas.drawLine(Offset(0, y), Offset(size.width, y), gridPaint);
    }

    // Draw Event Rate Curve (Orange)
    final orangePath = Path();
    final orangePaint = Paint()
      ..color = UbuntuTheme.ubuntuOrange
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2;

    final points = [
      Offset(0, size.height * 0.7),
      Offset(size.width * 0.2, size.height * 0.65),
      Offset(size.width * 0.4, size.height * 0.8),
      Offset(size.width * 0.6, size.height * 0.4),
      Offset(size.width * 0.8, size.height * 0.3),
      Offset(size.width, size.height * 0.15),
    ];

    orangePath.moveTo(points[0].dx, points[0].dy);
    for (int i = 1; i < points.length; i++) {
      orangePath.lineTo(points[i].dx, points[i].dy);
    }
    canvas.drawPath(orangePath, orangePaint);

    // Draw Noise Reduction Curve (Green)
    final greenPath = Path();
    final greenPaint = Paint()
      ..color = UbuntuTheme.statusGreen
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2;

    final greenPoints = [
      Offset(0, size.height * 0.2),
      Offset(size.width * 0.2, size.height * 0.18),
      Offset(size.width * 0.4, size.height * 0.15),
      Offset(size.width * 0.6, size.height * 0.12),
      Offset(size.width * 0.8, size.height * 0.10),
      Offset(size.width, size.height * 0.08),
    ];

    greenPath.moveTo(greenPoints[0].dx, greenPoints[0].dy);
    for (int i = 1; i < greenPoints.length; i++) {
      greenPath.lineTo(greenPoints[i].dx, greenPoints[i].dy);
    }
    canvas.drawPath(greenPath, greenPaint);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
