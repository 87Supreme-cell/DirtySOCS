import os
from PIL import Image, ImageDraw, ImageFont

os.makedirs("docs/screenshots", exist_ok=True)
WIDTH, HEIGHT = 1000, 640

def get_font(size):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size)
    except:
        return ImageFont.load_default()

def get_bold_font(size):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", size)
    except:
        return get_font(size)

def draw_window_frame(draw, title):
    draw.rectangle([0, 0, WIDTH, HEIGHT], fill="#070b14")
    draw.rectangle([0, 0, WIDTH, 40], fill="#0d1527", outline="#1e293b", width=1)
    draw.ellipse([16, 14, 28, 26], fill="#ef4444")
    draw.ellipse([36, 14, 48, 26], fill="#f59e0b")
    draw.ellipse([56, 14, 68, 26], fill="#10b981")
    font_title = get_bold_font(13)
    draw.text((WIDTH // 2 - 140, 12), title, fill="#94a3b8", font=font_title)

# Concept 1: Dual-Lens View (Plain English vs Technical Telemetry)
def create_dual_view_concept():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#070b14")
    draw = ImageDraw.Draw(img)
    draw_window_frame(draw, "DirtySOCS • UI Concept 1: Dual-Lens Incident Explorer")

    font_bold = get_bold_font(12)
    font_large = get_bold_font(16)
    font_small = get_font(10)
    font_tiny = get_font(9)

    # Top Navigation / Mode Selector
    draw.rectangle([20, 50, 980, 95], fill="#0f172a", outline="#334155")
    draw.text((40, 65), "INCIDENT EXPLORER: INC-84821", fill="#38bdf8", font=font_large)

    # Toggle Pill Button (Active: Dual-Lens Mode)
    draw.rectangle([680, 58, 960, 87], fill="#1e293b", outline="#0284c7")
    draw.rectangle([682, 60, 818, 85], fill="#0284c7")
    draw.text((700, 67), "PLAIN ENGLISH", fill="#ffffff", font=font_bold)
    draw.text((830, 67), "TECHNICAL BPF", fill="#94a3b8", font=font_bold)

    # Left Column: Plain English Executive Briefing
    draw.rectangle([20, 110, 485, 560], fill="#0f172a", outline="#f59e0b", width=2)
    draw.rectangle([20, 110, 485, 145], fill="#451a03")
    draw.text((40, 122), "📋 EXECUTIVE & TRIAGE BRIEF (PLAIN ENGLISH)", fill="#fde68a", font=font_bold)

    plain_content = (
        "WHAT HAPPENED:\n"
        "At 16:38:53, a suspicious binary named '.sys_update' was\n"
        "executed from the temporary storage folder (/tmp).\n"
        "Shortly after launching, it attempted to open the system's\n"
        "restricted password hash file (/etc/shadow).\n\n"
        "WHO IS RESPONSIBLE:\n"
        "• Process: .sys_update (PID: 4821)\n"
        "• User: Standard desktop session user (UID: 1000)\n"
        "• Parent Shell: Interactive bash shell (PID: 1042)\n\n"
        "WHY IT MATTERS:\n"
        "Legitimate programs do not execute from /tmp. Attackers\n"
        "frequently stage droppers here because world-write permissions\n"
        "allow unprivileged download of malicious payloads.\n\n"
        "SYSTEM ACTION TAKEN:\n"
        "• The event was gated and captured in Ring 0.\n"
        "• AppArmor profile mediation prevented unauthorized password read.\n"
        "• An air-gapped investigation dossier was generated for audit."
    )
    draw.text((40, 160), plain_content, fill="#e2e8f0", font=font_small)

    # Right Column: Deep Kernel & Compliance Telemetry
    draw.rectangle([515, 110, 980, 560], fill="#0f172a", outline="#0ea5e9", width=2)
    draw.rectangle([515, 110, 980, 145], fill="#0c4a6e")
    draw.text((535, 122), "⚙️ KERNEL RING-0 TELEMETRY & COMPLIANCE", fill="#bae6fd", font=font_bold)

    tech_content = (
        "eBPF TRACEPOINT CAPTURE:\n"
        "• Probe: syscalls/sys_enter_execve [Aya BPF]\n"
        "  - filename: /tmp/.sys_update (18 bytes)\n"
        "  - comm: .sys_update | tgid: 4821 | ppid: 1042\n"
        "  - args: [0] /tmp/.sys_update [1] --daemon\n"
        "• Probe: syscalls/sys_enter_openat [Aya BPF]\n"
        "  - filename: /etc/shadow | flags: O_RDONLY (0x0)\n\n"
        "COMPLIANCE MAPPING MATRIX:\n"
        "• CIS RHEL 9: Control 1.1.2 (VIOLATION)\n"
        "  - Mandate: /tmp mounted with 'noexec' flag\n"
        "• NIST SP 800-53 Rev 5: AC-6 (Least Privilege)\n"
        "• NIST SP 800-53 Rev 5: AU-12 (Audit Generation)\n"
        "• MITRE ATT&CK: T1059.004 (Unix Shell)\n"
        "• MITRE ATT&CK: T1003.008 (/etc/shadow Dumping)\n\n"
        "AIR-GAP INTEGRITY:\n"
        "• Cryptographic Digest: sha256:b2b6d72d... (Salted)\n"
        "• Telemetry State: Scrubbed & Redacted"
    )
    draw.text((535, 160), tech_content, fill="#cbd5e1", font=font_small)

    # Bottom Actions Bar
    draw.rectangle([20, 575, 485, 620], fill="#0284c7")
    draw.text((130, 592), "EXPORT AUDIT DOSSIER (.JSON / .MD)", fill="#ffffff", font=font_bold)

    draw.rectangle([515, 575, 980, 620], fill="#dc2626")
    draw.text((630, 592), "INITIATE HUMAN REMEDIATION (PID 4821)", fill="#ffffff", font=font_bold)

    img.save("docs/screenshots/ui_concept_dual_view.png")

# Concept 2: MITRE ATT&CK Tactical Heatmap & Timeline
def create_mitre_concept():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#070b14")
    draw = ImageDraw.Draw(img)
    draw_window_frame(draw, "DirtySOCS • UI Concept 2: MITRE ATT&CK Tactical Grid & Event Timeline")

    font_bold = get_bold_font(11)
    font_title = get_bold_font(13)
    font_small = get_font(9)

    draw.rectangle([20, 50, 980, 85], fill="#0f172a", outline="#1e293b")
    draw.text((40, 60), "TACTICAL MITRE ATT&CK MATRIX FOR LINUX ENDPOINTS", fill="#38bdf8", font=font_title)

    # MITRE Tactics Columns
    tactics = [
        ("INITIAL ACCESS", ["T1190 Exploit App", "T1078 Valid Acct"]),
        ("EXECUTION", ["T1204 User Exec [!] ", "T1059.004 Unix Sh [!]"]),
        ("PERSISTENCE", ["T1053 Cron / Job", "T1543 Systemd Unit"]),
        ("PRIV ESCALATION", ["T1548 Sudo Abuse", "T1068 Kernel Expl"]),
        ("DEFENSE EVASION", ["T1070 Log Tamper", "T1027 Obfuscation"]),
        ("CREDENTIAL ACCESS", ["T1003.008 Shadow [!]", "T1555 Keyring"]),
    ]

    x = 20
    for col_title, techniques in tactics:
        # Header
        draw.rectangle([x, 100, x + 150, 130], fill="#1e293b", outline="#334155")
        draw.text((x + 8, 110), col_title, fill="#94a3b8", font=font_bold)

        # Tech cards
        y = 140
        for tech in techniques:
            is_active = "[!]" in tech
            bg_col = "#450a0a" if is_active else "#0f172a"
            border_col = "#ef4444" if is_active else "#1e293b"
            txt_col = "#fca5a5" if is_active else "#64748b"

            draw.rectangle([x, y, x + 150, y + 45], fill=bg_col, outline=border_col, width=2 if is_active else 1)
            draw.text((x + 8, y + 14), tech.replace(" [!]", ""), fill=txt_col, font=font_small)
            if is_active:
                draw.rectangle([x + 105, y + 4, x + 145, y + 18], fill="#ef4444")
                draw.text((x + 110, y + 5), "ALERT", fill="#ffffff", font=font_small)
            y += 55

        x += 162

    # Bottom Timeline Bar
    draw.rectangle([20, 480, 980, 620], fill="#0f172a", outline="#1e293b")
    draw.text((40, 495), "REAL-TIME INVESTIGATION TIMELINE (60s SLIDING WINDOW)", fill="#38bdf8", font=font_bold)

    timeline_points = [
        ("16:38:44", "eBPF probe attachment active (syscalls/sys_enter_execve)", "#10b981"),
        ("16:38:48", "60s sliding window deduplication initialized: 0 drops", "#10b981"),
        ("16:38:53", "ANOMALY: /tmp/.sys_update executed by UID 1000 (T1059.004)", "#ef4444"),
        ("16:38:53", "ANOMALY: openat targeting /etc/shadow intercepted (T1003.008)", "#ef4444"),
        ("16:38:54", "Signed Air-Gapped Dossier generated: DIRTYSOCS_INC-84821", "#38bdf8"),
    ]

    ty = 520
    for time_str, desc, col in timeline_points:
        draw.ellipse([40, ty + 2, 48, ty + 10], fill=col)
        draw.text((60, ty), f"[{time_str}] {desc}", fill="#cbd5e1", font=font_small)
        ty += 18

    img.save("docs/screenshots/ui_concept_mitre_heatmap.png")

create_dual_view_concept()
create_mitre_concept()
print("UI Concepts generated successfully!")
