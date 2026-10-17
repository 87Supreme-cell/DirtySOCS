import 'dart:async';
import 'package:flutter/material.dart';
import '../theme/ubuntu_theme.dart';

class TerminalBootView extends StatefulWidget {
  final VoidCallback onCompleteDissolve;

  const TerminalBootView({
    super.key,
    required this.onCompleteDissolve,
  });

  @override
  State<TerminalBootView> createState() => _TerminalBootViewState();
}

class _TerminalBootViewState extends State<TerminalBootView> {
  final List<String> _allLines = [
    'purpleronin@dirtysocs-workstation:~\$ dirtysocs-daemon --attach --strict-hil',
    '[ +0.001s ] [INFO] Initializing DirtySOCS Kernel Observability Engine v2.0...',
    '[ +0.012s ] [OK] Linux 7.0.0-38-generic (BTF Enabled, x86_64) verified.',
    '[ +0.025s ] [OK] Binding secure IPC: /run/dirtysocs/dirtysocs.sock (mode 0600, uid: 1000)',
    '[ +0.038s ] [OK] Attaching eBPF tracepoint: syscalls/sys_enter_execve',
    '[ +0.049s ] [OK] Attaching eBPF tracepoint: syscalls/sys_enter_connect',
    '[ +0.060s ] [OK] Attaching eBPF tracepoint: syscalls/sys_enter_openat',
    '[ +0.071s ] [OK] Allocated 1MB non-blocking kernel ring buffer (Adaptive Polling: ACTIVE)',
    '[ +0.084s ] [OK] Loaded compliance corpus: CIS RHEL 9 (1.1.2, 1.6, 4.1.4) & NIST SP 800-53',
    '[ +0.098s ] [OK] Prime token scrubber: Hex/Octal/Dword IP normalizer & Salted SHA-256',
    '[ +0.112s ] [OK] Double human-in-the-loop gate armed (pidfd_open atomic pinning active)',
    '[ +0.128s ] [OK] Process lifecycle check: 0 lingering background threads verified.',
    '[ +0.145s ] [>>] All kernel sensors synchronized. Dissolving console to Dashboard summary...',
  ];

  final List<String> _renderedLines = [];
  int _currentLineIndex = 0;
  Timer? _lineTimer;
  Timer? _cursorTimer;
  bool _cursorVisible = true;
  double _opacity = 1.0;

  @override
  void initState() {
    super.initState();
    _startTerminalTyping();
    _startCursorBlink();
  }

  void _startCursorBlink() {
    _cursorTimer = Timer.periodic(const Duration(milliseconds: 500), (timer) {
      if (mounted) {
        setState(() => _cursorVisible = !_cursorVisible);
      }
    });
  }

  void _startTerminalTyping() {
    _lineTimer = Timer.periodic(const Duration(milliseconds: 140), (timer) {
      if (!mounted) return;
      if (_currentLineIndex < _allLines.length) {
        setState(() {
          _renderedLines.add(_allLines[_currentLineIndex]);
          _currentLineIndex++;
        });
      } else {
        timer.cancel();
        // Wait 1 second after finishing typing, then dissolve
        Timer(const Duration(milliseconds: 900), _startDissolve);
      }
    });
  }

  void _startDissolve() {
    if (!mounted) return;
    setState(() => _opacity = 0.0);
    Timer(const Duration(milliseconds: 600), () {
      if (mounted) widget.onCompleteDissolve();
    });
  }

  @override
  void dispose() {
    _lineTimer?.cancel();
    _cursorTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedOpacity(
      duration: const Duration(milliseconds: 600),
      opacity: _opacity,
      child: Container(
        color: const Color(0xFF0F0F0F),
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Terminal Window TitleBar
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: BoxDecoration(
                color: const Color(0xFF181818),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF2B2B2B)),
              ),
              child: Row(
                children: [
                  const Text('🔴 🟡 🟢', style: TextStyle(fontSize: 10)),
                  const SizedBox(width: 16),
                  const Text(
                    'purpleronin@dirtysocs-workstation: ~ (eBPF Terminal Boot Engine)',
                    style: TextStyle(fontSize: 11, color: Colors.grey, fontWeight: FontWeight.bold),
                  ),
                  const Spacer(),
                  TextButton.icon(
                    style: TextButton.styleFrom(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                      foregroundColor: UbuntuTheme.ubuntuOrange,
                    ),
                    icon: const Icon(Icons.fast_forward, size: 14),
                    label: const Text('SKIP / DISSOLVE NOW', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                    onPressed: _startDissolve,
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // Typed-out text area
            Expanded(
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: const Color(0xFF141414),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFF222222)),
                ),
                child: SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      ..._renderedLines.map((line) => _formatLine(line)),
                      const SizedBox(height: 4),
                      Row(
                        children: [
                          if (_cursorVisible)
                            Container(
                              width: 8,
                              height: 14,
                              color: UbuntuTheme.ubuntuOrange,
                            ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ),
            const SizedBox(height: 12),

            // Bottom Dissolve Status Bar
            Center(
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                decoration: BoxDecoration(
                  color: const Color(0xFF1C1C1C),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: UbuntuTheme.ubuntuOrange.withValues(alpha: 0.6)),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(strokeWidth: 2, color: UbuntuTheme.ubuntuOrange),
                    ),
                    const SizedBox(width: 12),
                    Text(
                      _currentLineIndex < _allLines.length
                          ? 'INITIALIZING KERNEL TELEMETRY SUBSYSTEM...'
                          : 'SYNCHRONIZED. DISSOLVING TO DASHBOARD SUMMARY...',
                      style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.white),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _formatLine(String line) {
    if (line.contains('purpleronin@')) {
      return Padding(
        padding: const EdgeInsets.only(bottom: 6),
        child: Text(line, style: const TextStyle(fontSize: 11, color: UbuntuTheme.ubuntuOrange, fontWeight: FontWeight.bold)),
      );
    }

    final isOk = line.contains('[OK]');
    final isInfo = line.contains('[INFO]');
    final isTransition = line.contains('[>>]');

    Color col = Colors.white;
    if (isOk) col = UbuntuTheme.statusGreen;
    if (isInfo) col = const Color(0xFF3465A4);
    if (isTransition) col = UbuntuTheme.ubuntuOrange;

    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Text(
        line,
        style: TextStyle(
          fontSize: 10.5,
          color: col,
          height: 1.3,
          fontWeight: isTransition ? FontWeight.bold : FontWeight.normal,
        ),
      ),
    );
  }
}
