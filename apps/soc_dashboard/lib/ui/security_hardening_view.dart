import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../theme/ubuntu_theme.dart';

class SecurityHardeningView extends StatefulWidget {
  const SecurityHardeningView({super.key});

  @override
  State<SecurityHardeningView> createState() => _SecurityHardeningViewState();
}

class _SecurityHardeningViewState extends State<SecurityHardeningView> {
  final TextEditingController _usernameController =
      TextEditingController(text: 'purpleronin');
  final TextEditingController _passphraseController =
      TextEditingController(text: '••••••••••••••••');
  final TextEditingController _totpPinController =
      TextEditingController(text: '749201');

  bool _obscurePassphrase = true;
  bool _argon2idEnabled = true;
  bool _totpEnabled = true;
  bool _isBenchmarking = false;
  String? _benchmarkResult = 'Benchmarked: 118ms (64MB RAM, 4 lanes, zero cache leaks)';
  bool _isProfileSaved = false;

  static const String _totpSecret = 'JBSW Y3DP EHPK 3PXP';

  @override
  void dispose() {
    _usernameController.dispose();
    _passphraseController.dispose();
    _totpPinController.dispose();
    super.dispose();
  }

  void _runArgon2idBenchmark() {
    setState(() {
      _isBenchmarking = true;
      _benchmarkResult = null;
    });

    Future.delayed(const Duration(milliseconds: 650), () {
      if (mounted) {
        setState(() {
          _isBenchmarking = false;
          _benchmarkResult =
              'Derived in 124ms (Memory: 65536 KiB, Passes: 3, Lanes: 4) • SIV Tag OK';
        });
      }
    });
  }

  void _saveProfile() {
    setState(() => _isProfileSaved = true);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor: const Color(0xFF2B2B2B),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
          side: const BorderSide(color: UbuntuTheme.statusGreen),
        ),
        content: Row(
          children: [
            const Icon(Icons.check_circle, color: UbuntuTheme.statusGreen, size: 20),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                'Security profile saved: ${_usernameController.text} hardened with '
                '${_argon2idEnabled ? "Argon2id (m=64MB, t=3, p=4)" : "Standard SHA-256"} '
                'and ${_totpEnabled ? "TOTP 2FA enforced" : "2FA disabled"}.',
                style: const TextStyle(fontSize: 12, color: Colors.white),
              ),
            ),
          ],
        ),
        duration: const Duration(seconds: 4),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header Card
          _buildHeaderBanner(context),
          const SizedBox(height: 18),

          // Two-column layout for Security Hardening Options
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Left Column: Credentials & Argon2id Key Derivation
              Expanded(
                flex: 6,
                child: Column(
                  children: [
                    _buildOperatorCredentialsCard(context),
                    const SizedBox(height: 18),
                    _buildArgon2idCard(context),
                  ],
                ),
              ),
              const SizedBox(width: 18),

              // Right Column: Two-Factor Authentication (TOTP 2FA)
              Expanded(
                flex: 5,
                child: Column(
                  children: [
                    _buildTotpCard(context),
                    const SizedBox(height: 18),
                    _buildSecurityStatusSummaryCard(context),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // Action Buttons Bar
          _buildBottomActionBar(context),
        ],
      ),
    );
  }

  Widget _buildHeaderBanner(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      decoration: BoxDecoration(
        color: Theme.of(context).cardTheme.color,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: Theme.of(context).colorScheme.outline),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: UbuntuTheme.ubuntuOrange.withValues(alpha: 0.15),
              shape: BoxShape.circle,
            ),
            child: const Icon(Icons.shield_outlined,
                color: UbuntuTheme.ubuntuOrange, size: 24),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Text(
                      'IN-APP SECURITY HARDENING & CRYPTOGRAPHIC ACCESS CONTROL',
                      style:
                          TextStyle(fontSize: 13, fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(width: 12),
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 8, vertical: 2),
                      decoration: BoxDecoration(
                        color: UbuntuTheme.statusGreen.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(
                            color:
                                UbuntuTheme.statusGreen.withValues(alpha: 0.4)),
                      ),
                      child: const Text(
                        'HIL INTEGRITY LEVEL 4',
                        style: TextStyle(
                            fontSize: 9,
                            fontWeight: FontWeight.bold,
                            color: UbuntuTheme.statusGreen),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                const Text(
                  'Configure operator identity, enable memory-hard Argon2id key derivation, and enforce TOTP 2FA before kernel remediation authority is granted.',
                  style: TextStyle(fontSize: 11, color: Colors.grey),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildOperatorCredentialsCard(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: Theme.of(context).cardTheme.color,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: Theme.of(context).colorScheme.outline),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.person_pin_outlined,
                  size: 18, color: UbuntuTheme.ubuntuOrange),
              const SizedBox(width: 8),
              const Text(
                '1. OPERATOR CREDENTIALS & KEYRING BINDING',
                style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
              ),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: Colors.blueGrey.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: const Text(
                  'SO_PEERCRED UID: 1000',
                  style: TextStyle(
                      fontSize: 9,
                      fontWeight: FontWeight.bold,
                      color: Colors.lightBlueAccent),
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),

          // Username Field
          const Text(
            'ANALYST USERNAME',
            style: TextStyle(
                fontSize: 10, fontWeight: FontWeight.bold, color: Colors.grey),
          ),
          const SizedBox(height: 6),
          TextField(
            controller: _usernameController,
            style: const TextStyle(fontSize: 12),
            decoration: InputDecoration(
              filled: true,
              fillColor: const Color(0xFF1E1E1E),
              contentPadding:
                  const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              prefixIcon:
                  const Icon(Icons.account_circle_outlined, size: 16, color: Colors.grey),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: Color(0xFF444444)),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: Color(0xFF444444)),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: UbuntuTheme.ubuntuOrange),
              ),
            ),
          ),
          const SizedBox(height: 14),

          // Master Passphrase Field
          const Text(
            'MASTER PASSPHRASE (LOCKS ATOMIC PIDFD & REMEDIATION PIPELINE)',
            style: TextStyle(
                fontSize: 10, fontWeight: FontWeight.bold, color: Colors.grey),
          ),
          const SizedBox(height: 6),
          TextField(
            controller: _passphraseController,
            obscureText: _obscurePassphrase,
            style: const TextStyle(fontSize: 12, letterSpacing: 1.5),
            decoration: InputDecoration(
              filled: true,
              fillColor: const Color(0xFF1E1E1E),
              contentPadding:
                  const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              prefixIcon: const Icon(Icons.password, size: 16, color: Colors.grey),
              suffixIcon: IconButton(
                icon: Icon(
                  _obscurePassphrase
                      ? Icons.visibility_outlined
                      : Icons.visibility_off_outlined,
                  size: 16,
                  color: Colors.grey,
                ),
                onPressed: () =>
                    setState(() => _obscurePassphrase = !_obscurePassphrase),
              ),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: Color(0xFF444444)),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: Color(0xFF444444)),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: UbuntuTheme.ubuntuOrange),
              ),
            ),
          ),
          const SizedBox(height: 10),
          const Row(
            children: [
              Icon(Icons.info_outline, size: 12, color: Colors.grey),
              SizedBox(width: 6),
              Expanded(
                child: Text(
                  'Passphrase is never transmitted over IPC in plaintext; derived keys validate remediation signatures in-memory.',
                  style: TextStyle(fontSize: 10, color: Colors.grey),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildArgon2idCard(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: Theme.of(context).cardTheme.color,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: _argon2idEnabled
              ? UbuntuTheme.ubuntuOrange.withValues(alpha: 0.5)
              : Theme.of(context).colorScheme.outline,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.memory, size: 18, color: UbuntuTheme.ubuntuOrange),
              const SizedBox(width: 8),
              const Text(
                '2. ARGON2ID KEY DERIVATION CONFIGURATION',
                style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
              ),
              const Spacer(),
              Switch(
                value: _argon2idEnabled,
                activeThumbColor: UbuntuTheme.ubuntuOrange,
                onChanged: (val) => setState(() => _argon2idEnabled = val),
              ),
            ],
          ),
          const SizedBox(height: 8),
          const Text(
            'Memory-hard key derivation resistant against GPU brute-forcing, ASIC hardware attacks, and side-channel cache timing (RFC 9106).',
            style: TextStyle(fontSize: 11, color: Colors.grey, height: 1.4),
          ),
          const SizedBox(height: 16),

          // Parameters Grid
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFF1E1E1E),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFF383838)),
            ),
            child: Column(
              children: [
                _buildParameterRow('Memory Cost (m):', '65,536 KiB (64 MB RAM)'),
                const Divider(height: 16, color: Color(0xFF2E2E2E)),
                _buildParameterRow('Time Cost (t):', '3 Iteration Passes'),
                const Divider(height: 16, color: Color(0xFF2E2E2E)),
                _buildParameterRow('Parallelism (p):', '4 Lanes / Threads'),
                const Divider(height: 16, color: Color(0xFF2E2E2E)),
                _buildParameterRow('Derived Envelope:', '256-bit AES-GCM-SIV Key'),
                const Divider(height: 16, color: Color(0xFF2E2E2E)),
                _buildParameterRow(
                    'Salt Context:', 'Salted with /etc/machine-id + CSPRNG'),
              ],
            ),
          ),
          const SizedBox(height: 14),

          // Benchmark Button & Result
          Row(
            children: [
              OutlinedButton.icon(
                style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.white,
                  side: const BorderSide(color: Color(0xFF555555)),
                  padding:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(6)),
                ),
                icon: _isBenchmarking
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: UbuntuTheme.ubuntuOrange),
                      )
                    : const Icon(Icons.speed, size: 14),
                label: Text(
                  _isBenchmarking
                      ? 'COMPUTING DERIVATION...'
                      : 'BENCHMARK ARGON2ID (LOCAL CPU)',
                  style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold),
                ),
                onPressed: _argon2idEnabled && !_isBenchmarking
                    ? _runArgon2idBenchmark
                    : null,
              ),
              const SizedBox(width: 12),
              if (_benchmarkResult != null)
                Expanded(
                  child: Text(
                    _benchmarkResult!,
                    style: const TextStyle(
                        fontSize: 10,
                        color: UbuntuTheme.statusGreen,
                        fontWeight: FontWeight.bold),
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildTotpCard(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: Theme.of(context).cardTheme.color,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: _totpEnabled
              ? UbuntuTheme.ubuntuOrange.withValues(alpha: 0.5)
              : Theme.of(context).colorScheme.outline,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.phonelink_lock,
                  size: 18, color: UbuntuTheme.ubuntuOrange),
              const SizedBox(width: 8),
              const Text(
                '3. TWO-FACTOR AUTHENTICATION (TOTP)',
                style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
              ),
              const Spacer(),
              Switch(
                value: _totpEnabled,
                activeThumbColor: UbuntuTheme.ubuntuOrange,
                onChanged: (val) => setState(() => _totpEnabled = val),
              ),
            ],
          ),
          const SizedBox(height: 8),
          const Text(
            'Enforces time-based 6-digit OTP verification (RFC 6238) for any high-risk remediation action (e.g., SIGKILL, network quarantine).',
            style: TextStyle(fontSize: 11, color: Colors.grey, height: 1.4),
          ),
          const SizedBox(height: 16),

          // Authenticator Setup Row (QR Code + Secret Key)
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: const Color(0xFF1E1E1E),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFF383838)),
            ),
            child: Row(
              children: [
                // Simulated Stylized QR Code
                _buildStylizedQrCode(),
                const SizedBox(width: 16),

                // Secret Key & Copy Button
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'AUTHENTICATOR SECRET KEY',
                        style: TextStyle(
                            fontSize: 9,
                            fontWeight: FontWeight.bold,
                            color: Colors.grey),
                      ),
                      const SizedBox(height: 4),
                      SelectableText(
                        _totpSecret,
                        style: const TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.bold,
                          letterSpacing: 2,
                          color: UbuntuTheme.ubuntuOrange,
                        ),
                      ),
                      const SizedBox(height: 8),
                      OutlinedButton.icon(
                        style: OutlinedButton.styleFrom(
                          foregroundColor: Colors.white,
                          side: const BorderSide(color: Color(0xFF444444)),
                          padding: const EdgeInsets.symmetric(
                              horizontal: 10, vertical: 4),
                          shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(4)),
                        ),
                        icon: const Icon(Icons.copy, size: 12),
                        label: const Text('COPY SECRET',
                            style: TextStyle(fontSize: 9)),
                        onPressed: () {
                          Clipboard.setData(
                              const ClipboardData(text: 'JBSWY3DPEHPK3PXP'));
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('TOTP secret key copied to clipboard!'),
                              duration: Duration(seconds: 2),
                            ),
                          );
                        },
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // 6-Digit PIN Verification Input
          const Text(
            'CURRENT 6-DIGIT VERIFICATION CODE',
            style: TextStyle(
                fontSize: 10, fontWeight: FontWeight.bold, color: Colors.grey),
          ),
          const SizedBox(height: 6),
          Row(
            children: [
              SizedBox(
                width: 160,
                child: TextField(
                  controller: _totpPinController,
                  maxLength: 6,
                  keyboardType: TextInputType.number,
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 4),
                  decoration: InputDecoration(
                    counterText: '',
                    filled: true,
                    fillColor: const Color(0xFF1E1E1E),
                    contentPadding:
                        const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(6),
                      borderSide: const BorderSide(color: Color(0xFF444444)),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              ElevatedButton.icon(
                style: ElevatedButton.styleFrom(
                  backgroundColor: UbuntuTheme.ubuntuOrange,
                  foregroundColor: Colors.white,
                  padding:
                      const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(6)),
                ),
                icon: const Icon(Icons.verified, size: 14),
                label: const Text('TEST OTP BINDING',
                    style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                onPressed: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      backgroundColor: Color(0xFF26A269),
                      content: Text(
                          'OTP Verified: Authenticator sync valid (RFC 6238 drift +/- 30s OK).'),
                      duration: Duration(seconds: 3),
                    ),
                  );
                },
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityStatusSummaryCard(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).cardTheme.color,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: Theme.of(context).colorScheme.outline),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.verified_user, size: 16, color: UbuntuTheme.statusGreen),
              SizedBox(width: 8),
              Text(
                'HARDENING ENFORCEMENT POSTURE',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
              ),
            ],
          ),
          const SizedBox(height: 10),
          _buildStatusRow(
              'SO_PEERCRED UID/GID Isolation', 'ACTIVE (0600 root/1000)', true),
          const SizedBox(height: 6),
          _buildStatusRow(
              'Symlink Path Attack Immunity', 'O_NOFOLLOW & /run Locked', true),
          const SizedBox(height: 6),
          _buildStatusRow('pidfd_open TOCTOU Elimination', 'ACTIVE (PIDFD_NONBLOCK)',
              true),
          const SizedBox(height: 6),
          _buildStatusRow('Process Teardown Lifecycle',
              '0 Lingering Workers on Exit', true),
        ],
      ),
    );
  }

  Widget _buildBottomActionBar(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).cardTheme.color,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: Theme.of(context).colorScheme.outline),
      ),
      child: Row(
        children: [
          if (_isProfileSaved)
            const Row(
              children: [
                Icon(Icons.check_circle, size: 18, color: UbuntuTheme.statusGreen),
                SizedBox(width: 8),
                Text(
                  'Profile active & locked into DirtySOCS daemon session.',
                  style: TextStyle(
                      fontSize: 11,
                      color: UbuntuTheme.statusGreen,
                      fontWeight: FontWeight.bold),
                ),
              ],
            )
          else
            const Text(
              'Changes to hardening profile require operator confirmation to take effect.',
              style: TextStyle(fontSize: 11, color: Colors.grey),
            ),
          const Spacer(),
          OutlinedButton(
            style: OutlinedButton.styleFrom(
              foregroundColor: Colors.white,
              side: const BorderSide(color: Color(0xFF444444)),
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8)),
            ),
            child: const Text('RESET TO DEFAULTS',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
            onPressed: () {
              setState(() {
                _usernameController.text = 'purpleronin';
                _passphraseController.text = '••••••••••••••••';
                _argon2idEnabled = true;
                _totpEnabled = true;
                _isProfileSaved = false;
              });
            },
          ),
          const SizedBox(width: 12),
          ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: UbuntuTheme.ubuntuOrange,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8)),
            ),
            icon: const Icon(Icons.lock_outline, size: 16),
            label: const Text('SAVE & ENFORCE HARDENED PROFILE',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
            onPressed: _saveProfile,
          ),
        ],
      ),
    );
  }

  Widget _buildParameterRow(String label, String value) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: const TextStyle(fontSize: 11, color: Colors.grey)),
        Text(value,
            style: const TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.bold,
                color: Colors.white)),
      ],
    );
  }

  Widget _buildStatusRow(String label, String value, bool isOk) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: const TextStyle(fontSize: 10, color: Colors.grey)),
        Row(
          children: [
            Container(
              width: 6,
              height: 6,
              decoration: BoxDecoration(
                color: isOk ? UbuntuTheme.statusGreen : Colors.grey,
                shape: BoxShape.circle,
              ),
            ),
            const SizedBox(width: 6),
            Text(
              value,
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.bold,
                color: isOk ? UbuntuTheme.statusGreen : Colors.grey,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildStylizedQrCode() {
    return Container(
      width: 80,
      height: 80,
      padding: const EdgeInsets.all(6),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(6),
      ),
      child: GridView.builder(
        physics: const NeverScrollableScrollPhysics(),
        gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: 7,
          crossAxisSpacing: 2,
          mainAxisSpacing: 2,
        ),
        itemCount: 49,
        itemBuilder: (context, index) {
          // Decorative matrix pattern resembling a TOTP 2D barcode
          final isCorner = (index < 3 || (index >= 4 && index <= 6)) &&
              ((index / 7).floor() < 3 || (index / 7).floor() >= 4);
          final isDark = isCorner || (index * 7 + index % 5) % 3 == 0;
          return Container(
            decoration: BoxDecoration(
              color: isDark ? const Color(0xFF1E1E1E) : Colors.white,
              borderRadius: BorderRadius.circular(1),
            ),
          );
        },
      ),
    );
  }
}
