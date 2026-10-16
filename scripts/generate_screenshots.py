import os
from PIL import Image, ImageDraw, ImageFont

os.makedirs("docs/screenshots", exist_ok=True)

WIDTH, HEIGHT = 1000, 640

def get_font(size):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size)
    except:
        try:
            return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", size)
        except:
            return ImageFont.load_default()

def get_bold_font(size):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", size)
    except:
        return get_font(size)

def draw_window_frame(draw, title):
    # Window background
    draw.rectangle([0, 0, WIDTH, HEIGHT], fill="#0a0f1d")
    # Title bar
    draw.rectangle([0, 0, WIDTH, 40], fill="#0f172a", outline="#1e293b", width=1)
    # Window controls (mac/linux style dots)
    draw.ellipse([16, 14, 28, 26], fill="#ef4444")
    draw.ellipse([36, 14, 48, 26], fill="#f59e0b")
    draw.ellipse([56, 14, 68, 26], fill="#10b981")
    # Title text
    font_title = get_bold_font(13)
    draw.text((WIDTH // 2 - 120, 12), title, fill="#94a3b8", font=font_title)

# 1. Dashboard Overview
def create_dashboard_overview():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#0a0f1d")
    draw = ImageDraw.Draw(img)
    draw_window_frame(draw, "DirtySOCS • Real-Time Endpoint Observability")

    # Header Stats Bar
    font_bold = get_bold_font(12)
    font_large = get_bold_font(18)
    font_med = get_font(11)
    font_small = get_font(10)

    # Metric Card 1: Ring-0 eBPF Events
    draw.rectangle([20, 55, 245, 145], fill="#0f172a", outline="#334155", width=1)
    draw.text((35, 68), "eBPF RING-0 STREAM", fill="#38bdf8", font=font_bold)
    draw.text((35, 90), "1,428,912", fill="#f8fafc", font=font_large)
    draw.text((35, 118), "• Verifier: Safe | 0% Drops", fill="#10b981", font=font_small)

    # Metric Card 2: 60s Sliding Deduplication
    draw.rectangle([265, 55, 490, 145], fill="#0f172a", outline="#334155", width=1)
    draw.text((280, 68), "60s SLIDING COLLAPSE", fill="#f59e0b", font=font_bold)
    draw.text((280, 90), "99.4% Noise Drop", fill="#f8fafc", font=font_large)
    draw.text((280, 118), "• 4,812 raw -> 29 aggregated", fill="#94a3b8", font=font_small)

    # Metric Card 3: Host Resource Metrics
    draw.rectangle([510, 55, 735, 145], fill="#0f172a", outline="#334155", width=1)
    draw.text((525, 68), "CGROUP CPU / RSS", fill="#a855f7", font=font_bold)
    draw.text((525, 90), "1.8% | 28.4 MB", fill="#f8fafc", font=font_large)
    draw.text((525, 118), "• Bounded memory footprint", fill="#10b981", font=font_small)

    # Metric Card 4: Compliance Status
    draw.rectangle([755, 55, 980, 145], fill="#0f172a", outline="#334155", width=1)
    draw.text((770, 68), "CIS & NIST POSTURE", fill="#10b981", font=font_bold)
    draw.text((770, 90), "COMPLIANT (1 ANOM)", fill="#f8fafc", font=font_large)
    draw.text((770, 118), "• CIS RHEL 9.1: Enforced", fill="#38bdf8", font=font_small)

    # Live Sliding Window Telemetry Table
    draw.rectangle([20, 160, 640, 615], fill="#0f172a", outline="#1e293b", width=1)
    draw.text((35, 175), "ACTIVE TELEMETRY STREAM (AGGREGATED & REDACTED)", fill="#38bdf8", font=font_bold)
    draw.line([35, 198, 625, 198], fill="#1e293b", width=1)

    table_headers = "TIME     SUBSYSTEM  TYPE               PID   PROCESS         COUNT  RISK"
    draw.text((35, 208), table_headers, fill="#64748b", font=font_small)

    events = [
        ("16:04:12", "ebpf",   "sys_enter_execve", "4821", "/tmp/.sys_upd", "1",   "CRITICAL", "#ef4444"),
        ("16:04:10", "dbus",   "apparmor_denial",  "4821", "snapd-desktop",  "4",   "HIGH",     "#f97316"),
        ("16:04:02", "ebpf",   "sys_enter_openat", "4821", "/etc/shadow",   "1",   "CRITICAL", "#ef4444"),
        ("16:03:55", "systemd","service_failure",  "-",    "auditd.service", "1",   "MEDIUM",   "#eab308"),
        ("16:03:40", "ebpf",   "sys_enter_connect","1092", "curl [hashed_ip]","12", "LOW",      "#38bdf8"),
        ("16:03:20", "dbus",   "portal_register",  "2104", "gnome-portal",   "1",   "INFO",     "#94a3b8"),
        ("16:03:00", "journal","css_parse_warn",   "1840", "gnome-shell",    "1000","NOISE",    "#64748b"),
    ]

    y = 230
    for t, sub, typ, pid, proc, cnt, rsk, col in events:
        line = f"{t}  {sub:<9}  {typ:<17}  {pid:<4}  {proc:<14}  {cnt:<5}"
        draw.text((35, y), line, fill="#cbd5e1", font=font_small)
        draw.rectangle([560, y - 2, 625, y + 14], fill=col)
        draw.text((565, y), rsk, fill="#ffffff", font=font_small)
        y += 32

    # Right Panel: Active Anomaly & Compliance Card
    draw.rectangle([655, 160, 980, 615], fill="#0f172a", outline="#ef4444", width=2)
    draw.rectangle([655, 160, 980, 195], fill="#450a0a")
    draw.text((670, 172), "🚨 ACTIVE ANOMALY: INC-91024", fill="#fca5a5", font=font_bold)

    draw.text((670, 210), "PLAIN ENGLISH SUMMARY:", fill="#fbbf24", font=font_bold)
    summary_text = (
        "An unauthorized binary executed\n"
        "from /tmp and attempted to read\n"
        "credential store /etc/shadow.\n"
        "AppArmor mediated the syscall."
    )
    draw.text((670, 230), summary_text, fill="#e2e8f0", font=font_small)

    draw.text((670, 310), "COMPLIANCE CROSS-REFERENCE:", fill="#38bdf8", font=font_bold)
    compliance_text = (
        "• CIS RHEL 9: Control 1.1.2\n"
        "  (Ensure /tmp is mounted noexec)\n"
        "• NIST SP 800-53: AC-6 & AU-12\n"
        "  (Least Privilege & Audit Trigger)\n"
        "• MITRE ATT&CK: T1059.004"
    )
    draw.text((670, 330), compliance_text, fill="#94a3b8", font=font_small)

    # Buttons
    draw.rectangle([670, 480, 965, 520], fill="#0284c7", outline="#38bdf8")
    draw.text((710, 495), "EXPORT AI FORENSIC DOSSIER", fill="#ffffff", font=font_bold)

    draw.rectangle([670, 535, 965, 575], fill="#dc2626", outline="#ef4444")
    draw.text((720, 550), "REVIEW & REMEDIATE (PID 4821)", fill="#ffffff", font=font_bold)

    img.save("docs/screenshots/dashboard_overview.png")

# 2. Process Tree
def create_process_tree():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#0a0f1d")
    draw = ImageDraw.Draw(img)
    draw_window_frame(draw, "DirtySOCS • Correlated Process Hierarchy & Lineage")

    font_bold = get_bold_font(12)
    font_large = get_bold_font(16)
    font_small = get_font(11)

    draw.rectangle([20, 55, 980, 615], fill="#0f172a", outline="#1e293b", width=1)
    draw.text((40, 75), "PROCESS LINEAGE CORRELATION (PARENT -> CHILD)", fill="#38bdf8", font=font_bold)
    draw.text((40, 95), "Correlating eBPF sys_enter_execve with procfs namespace hierarchy", fill="#64748b", font=font_small)
    draw.line([40, 115, 960, 115], fill="#1e293b", width=1)

    tree = [
        ("systemd (PID: 1, UID: 0) [ROOT NAMESPACE]", 140, 0, "#10b981", "BENIGN"),
        ("├── sshd (PID: 812, UID: 0) [NETWORK DAEMON]", 185, 20, "#10b981", "BENIGN"),
        ("│   └── sshd: operator (PID: 1040, UID: 1000)", 230, 40, "#38bdf8", "SESSION"),
        ("│       └── bash (PID: 1042, UID: 1000) [/bin/bash]", 275, 60, "#38bdf8", "SESSION"),
        ("│           └── curl (PID: 4819, UID: 1000) [FETCH RAW SCRIPT]", 320, 80, "#f59e0b", "SUSPICIOUS"),
        ("│           └── sh (PID: 4820, UID: 1000) [/bin/sh]", 365, 80, "#f59e0b", "ANOMALY"),
        ("│               └── .sys_update (PID: 4821, UID: 1000) [/tmp/.sys_update]", 410, 100, "#ef4444", "COMPROMISED"),
        ("├── systemd-journald (PID: 340, UID: 0)", 465, 20, "#10b981", "BENIGN"),
        ("└── dbus-daemon (PID: 610, UID: 104)", 510, 20, "#10b981", "BENIGN"),
    ]

    for label, y, indent, col, badge in tree:
        draw.text((40 + indent, y), label, fill="#f8fafc", font=font_small)
        draw.rectangle([820, y - 3, 940, y + 17], fill=col)
        draw.text((830, y), badge, fill="#ffffff", font=font_bold)

    draw.rectangle([40, 560, 960, 600], fill="#1e293b")
    draw.text((55, 572), "SELECTED: PID 4821 • Path: /tmp/.sys_update • Exec Origin: UNVERIFIED • Violates CIS-RHEL-1.1.2", fill="#fca5a5", font=font_small)

    img.save("docs/screenshots/process_tree.png")

# 3. Advisory Export
def create_advisory_export():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#0a0f1d")
    draw = ImageDraw.Draw(img)
    draw_window_frame(draw, "DirtySOCS • True Air-Gapped Forensic Dossier Export")

    font_bold = get_bold_font(12)
    font_large = get_bold_font(16)
    font_small = get_font(11)

    draw.rectangle([40, 65, 960, 605], fill="#0f172a", outline="#0284c7", width=2)
    draw.text((60, 85), "FORENSIC INCIDENT INVESTIGATION DOSSIER (AIR-GAPPED)", fill="#38bdf8", font=font_large)
    draw.text((60, 110), "All internal PII, home paths, and IP addresses have been deterministically redacted and salted-hashed.", fill="#94a3b8", font=font_small)
    draw.line([60, 130, 940, 130], fill="#1e293b", width=1)

    # Dual Column: Left Plain English / Right Technical
    draw.rectangle([60, 145, 485, 470], fill="#0a0f1d", outline="#334155")
    draw.text((80, 160), "📋 PLAIN ENGLISH INCIDENT BRIEF", fill="#fbbf24", font=font_bold)
    plain_text = (
        "• Incident ID: INC-91024\n"
        "• Status: Gated Anomaly (Ready for AI Export)\n"
        "• Severity Level: CRITICAL (Immediate Action Needed)\n\n"
        "Summary for Incident Responders:\n"
        "At 16:04:12, a process running from temporary storage\n"
        "attempted to access the system password file (/etc/shadow).\n"
        "The attempt triggered an AppArmor security mediation.\n"
        "The process remains active in memory under PID 4821.\n\n"
        "Recommended Next Step:\n"
        "Export this dossier to an offline LLM or trusted AI,\n"
        "review root-cause confirmation, and execute process\n"
        "termination via the Human-in-the-Loop control panel."
    )
    draw.text((80, 190), plain_text, fill="#e2e8f0", font=font_small)

    # Right Technical Telemetry
    draw.rectangle([515, 145, 940, 470], fill="#0a0f1d", outline="#334155")
    draw.text((535, 160), "⚙️ REDACTED TECHNICAL PAYLOAD & COMPLIANCE", fill="#38bdf8", font=font_bold)
    tech_json = (
        '{\n'
        '  "timestamp": "2026-10-16T16:04:12Z",\n'
        '  "host_id": "sha256:7f9a12c8... (Salted)",\n'
        '  "kernel_version": "7.0.0-38-generic",\n'
        '  "cis_benchmark_violation": "CIS-RHEL-9-1.1.2",\n'
        '  "nist_control_mapping": "NIST-SP800-53-AC-6",\n'
        '  "telemetry_batch": [\n'
        '    {\n'
        '      "subsystem": "ebpf",\n'
        '      "syscall": "sys_enter_execve",\n'
        '      "path": "/tmp/.sys_update",\n'
        '      "target": "/etc/shadow",\n'
        '      "pid": 4821, "ppid": 1042,\n'
        '      "comm": ".sys_update"\n'
        '    }\n'
        '  ]\n'
        '}'
    )
    draw.text((535, 190), tech_json, fill="#cbd5e1", font=font_small)

    # Export & Import Buttons
    draw.rectangle([60, 500, 485, 550], fill="#0284c7")
    draw.text((120, 520), "💾 SAVE SIGNED DOSSIER (.JSON / .MD)", fill="#ffffff", font=font_bold)

    draw.rectangle([515, 500, 940, 550], fill="#059669")
    draw.text((570, 520), "📥 IMPORT AI ADVISORY RESPONSE", fill="#ffffff", font=font_bold)

    img.save("docs/screenshots/advisory_export.png")

# 4. Remediation Modal
def create_remediation_modal():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#0a0f1d")
    draw = ImageDraw.Draw(img)
    draw_window_frame(draw, "DirtySOCS • Human-in-the-Loop Safe Remediation")

    font_bold = get_bold_font(12)
    font_large = get_bold_font(18)
    font_small = get_font(11)

    # Dimmed background
    draw.rectangle([20, 55, 980, 615], fill="#070b14")

    # Center Modal
    draw.rectangle([180, 110, 820, 560], fill="#0f172a", outline="#dc2626", width=3)
    draw.rectangle([180, 110, 820, 160], fill="#450a0a")
    draw.text((210, 128), "🛡️ HUMAN CONFIRMATION REQUIRED: REMEDIATE THREAT", fill="#fca5a5", font=font_large)

    warning_text = (
        "Zero-Dynamic Execution Guarantee:\n"
        "DirtySOCS structurally bars AI models from running shell strings.\n"
        "The action below is a pre-compiled, parameter-checked Rust routine.\n"
        "Execution will ONLY proceed after operator confirmation."
    )
    draw.text((210, 180), warning_text, fill="#94a3b8", font=font_small)
    draw.line([210, 255, 790, 255], fill="#334155", width=1)

    details_text = (
        "PROPOSED HARDCODED REMEDIATION ROUTINE:\n\n"
        "• Target Action: SIGTERM -> SIGKILL Graceful Escalation\n"
        "• Target PID: 4821 (Path: /tmp/.sys_update)\n"
        "• Cgroup Action: Freeze parent slice (user-1000.slice/cgroup)\n"
        "• Compliance Standard: CIS-RHEL-9-1.1.2 Hardening\n"
        "• Safety Verification: Verified PID is not root init (PID != 1)"
    )
    draw.text((210, 275), details_text, fill="#f8fafc", font=font_small)

    # Checkbox
    draw.rectangle([210, 420, 235, 445], outline="#38bdf8", width=2, fill="#0284c7")
    draw.text((217, 424), "X", fill="#ffffff", font=font_bold)
    draw.text((250, 426), "I confirm the operational review of PID 4821 and authorize mitigation.", fill="#e2e8f0", font=font_small)

    # Action Buttons
    draw.rectangle([210, 480, 490, 525], fill="#1e293b", outline="#475569")
    draw.text((310, 498), "CANCEL", fill="#94a3b8", font=font_bold)

    draw.rectangle([510, 480, 790, 525], fill="#dc2626", outline="#ef4444")
    draw.text((580, 498), "CONFIRM & EXECUTE", fill="#ffffff", font=font_bold)

    img.save("docs/screenshots/remediation_modal.png")

create_dashboard_overview()
create_process_tree()
create_advisory_export()
create_remediation_modal()
print("All 4 screenshots generated successfully!")
