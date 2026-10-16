# DirtySOCS Security Posture & Architecture Specification

## 1. Threat Model & Security Posture Overview

DirtySOCS is designed under the assumption of an adversarial environment where host services may encounter untrusted binary execution, privilege escalation attempts, credential theft, and lateral movement.

### Core Defense Tenets
1. **Ring 0 Kernel Isolation**: Kernel observability is strictly read-only. eBPF tracepoints are verified to be bounded, loop-free, and unable to alter kernel memory or register states.
2. **True Air-Gap AI Separation**: The system structurally prohibits unsolicited network telemetry transmission. Outbound AI queries are never automatically executed; instead, an encrypted or signed **Forensic Investigation Dossier** is generated locally for operator review and manual or controlled export.
3. **Zero Dynamic AI Command Execution**: The AI advisory tier is purely analytical. No LLM output is ever piped to `sh`, `bash`, `exec`, or evaluated dynamically. Mitigation actions map exclusively to hardcoded, parameter-checked Rust routines requiring explicit human authorization.
4. **Deterministic PII Masking & Salted Pseudonymization**: Telemetry is scrubbed of credentials, private keys, authorization headers, environment variables, and user home directory names. Internal IP addresses are hashed using a locally generated cryptographic salt to prevent network mapping disclosures.

---

## 2. Compliance Framework Mapping

### CIS Red Hat Enterprise Linux 9 & Linux Benchmark
* **CIS Control 1.1.2**: Ensure `/tmp` is a separate partition and mounted with `noexec,nosuid,nodev`.
  * *DirtySOCS Enforcement*: Heuristic Gate flags any `sys_enter_execve` where executable path originates from `/tmp`, `/dev/shm`, or `/var/tmp`.
* **CIS Control 1.6**: Mandatory Access Control (AppArmor / SELinux).
  * *DirtySOCS Enforcement*: Passive subscription to D-Bus mediation denials (`org.freedesktop.DBus`) and desktop portal access violations.
* **CIS Control 4.1.3**: Record events that modify date and time information.
* **CIS Control 4.1.4**: Record events that modify user/group information (`/etc/group`, `/etc/passwd`, `/etc/shadow`).
  * *DirtySOCS Enforcement*: Ring-0 `sys_enter_openat` monitoring targeting credential and identity files.
* **CIS Control 5.2.4**: SSH Access Control & Key Security.
  * *DirtySOCS Enforcement*: Real-time alerts on write/read attempts to `~/.ssh/authorized_keys` and host private keys.

### NIST SP 800-53 (Revision 5) Controls
* **AU-2 (Event Logging)**: Identifies auditable events across kernel execution, socket creation, and service transitions.
* **AU-6 (Audit Record Review, Analysis, and Reporting)**: Automated 60-second sliding window deduplication and heuristic anomaly flagging.
* **AU-12 (Audit Generation)**: Generation of immutable, cryptographically hashed incident bundles.
* **AC-6 (Least Privilege)**: Detects unexpected UID 0 executions and unprivileged portal registrations.
* **SI-4 (Information System Monitoring)**: Non-blocking sensor correlation across kernel tracepoints, D-Bus, and systemd in-memory journals.
* **CM-7 (Least Functionality)**: Identifies unauthorized listening socket bindings or atypical network connects.

### CISSP Domain Alignment
* **Domain 3 (Security Architecture and Engineering)**: Enforcement of ring boundaries (Ring 0 vs Ring 3), least privilege, and memory safety via Rust.
* **Domain 7 (Security Operations)**: Incident triage lifecycle, non-repudiation, evidence preservation, and human-in-the-loop remediation.

---

## 3. Scrubbing & Redaction Specifications

Before telemetry is queued for dossier export, it passes through three deterministic scrubbing filters:

### Regex Scrubbing Patterns
```text
Private Keys:      /-----BEGIN [A-Z ]+PRIVATE KEY-----[^-]+-----END [A-Z ]+PRIVATE KEY-----/
Bearer Tokens:     /(?:Bearer|token|api_key|secret)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{16,})["']?/i
Password Fields:   /(?:password|passwd|pwd)\s*[:=]\s*["']?([^"' \t\n\r]{6,})["']?/i
User Home Paths:   /\/home\/[a-zA-Z0-9_\-]+(\/.*)?/ -> "/home/<user>$1"
```

### IP Pseudonymization
* Internal IP addresses (RFC 1918 & RFC 4193) are pseudonymized via `HMAC-SHA256(Local_Node_Salt, IP_Address)[0..12]`.
* Preserves correlation across repeated incidents on the same node without exposing internal network subnets to third-party LLMs.

---

## 4. Human-in-the-Loop Mitigation Handlers

All remediation actions are implemented as static, pre-compiled Rust functions:

1. `SIGTERM_PROCESS`: Sends `libc::kill(target_pid, SIGTERM)` with graceful escalation to `SIGKILL` after 3 seconds. Verified against `PID != 1` and `PID != daemon_pid`.
2. `FREEZE_CGROUP`: Writes `1` to `/sys/fs/cgroup/<slice>/cgroup.freeze` to pause suspect process trees without state loss.
3. `RESTART_SYSTEMD_UNIT`: Dispatches a typed D-Bus method call to `org.freedesktop.systemd1.Manager.RestartUnit`.

No dynamic string interpolation or shell commands (`/bin/sh -c`) exist anywhere in the remediation pipeline.
