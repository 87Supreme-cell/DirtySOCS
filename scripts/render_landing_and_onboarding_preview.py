import os
from PIL import Image, ImageDraw, ImageFont

os.makedirs("docs/screenshots", exist_ok=True)
WIDTH, HEIGHT = 1100, 720

def get_monaco(size):
    font_path = "/home/purpleronin/.local/share/fonts/Monaco/Monaco.ttf"
    if os.path.exists(font_path):
        return ImageFont.truetype(font_path, size)
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size)
    except:
        return ImageFont.load_default()

def draw_ubuntu_frame(draw, title="DirtySOCS • Operations Center", active_tab="LANDING"):
    # Background
    draw.rectangle([0, 0, WIDTH, HEIGHT], fill="#1c1c1c")
    
    # Header bar
    draw.rectangle([0, 0, WIDTH, 48], fill="#141414", outline="#2b2b2b", width=1)
    
    # Ubuntu window controls
    draw.ellipse([16, 18, 28, 30], fill="#ed6a5e")
    draw.ellipse([36, 18, 48, 30], fill="#f4bf4f")
    draw.ellipse([56, 18, 68, 30], fill="#61c554")
    
    # Egyptian Third Eye Icon in Ubuntu Orange
    draw.ellipse([88, 14, 112, 38], fill="#e95420")
    draw.ellipse([96, 22, 104, 30], fill="#ffffff")
    draw.ellipse([98, 24, 102, 28], fill="#141414")
    
    f_bold = get_monaco(12)
    f_sm = get_monaco(10)
    
    draw.text((122, 17), "DirtySOCS", fill="#f0f0f0", font=f_bold)
    
    # Subsystem pill
    draw.rounded_rectangle([206, 15, 330, 35], radius=6, fill="#2a2a2a")
    draw.text((214, 18), "LINUX 7.0 • BTF", fill="#e95420", font=f_sm)
    
    # Nav Tabs
    tabs = ["LANDING", "DASHBOARD", "DUAL-LENS", "PROCESS TREE", "SECURITY"]
    tx = 350
    for tab in tabs:
        is_active = (tab == active_tab)
        bg = "#e95420" if is_active else "#222222"
        txt_col = "#ffffff" if is_active else "#888888"
        draw.rounded_rectangle([tx, 12, tx + 92, 38], radius=6, fill=bg)
        draw.text((tx + 12, 18), tab, fill=txt_col, font=f_sm)
        tx += 100
        
    # User Profile / Hardening Pill
    draw.rounded_rectangle([WIDTH - 150, 12, WIDTH - 16, 38], radius=6, fill="#262626", outline="#3a3a3a")
    draw.ellipse([WIDTH - 142, 18, WIDTH - 128, 32], fill="#61c554")
    draw.text((WIDTH - 122, 18), "2FA: ARGON2ID", fill="#61c554", font=f_sm)

# 1. Landing Page with Module Selection, Previous Logs Analysis, and 75% Risk Spectrum
def render_landing_page():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#1c1c1c")
    draw = ImageDraw.Draw(img)
    draw_ubuntu_frame(draw, active_tab="LANDING")
    
    f_title = get_monaco(14)
    f_card = get_monaco(11)
    f_mono = get_monaco(10)
    f_sm = get_monaco(9)
    
    # Welcome Banner
    draw.rounded_rectangle([24, 60, WIDTH - 24, 120], radius=10, fill="#242424", outline="#383838")
    draw.text((44, 72), "INVESTIGATION PORTAL & OBSERVABILITY SELECTION", fill="#f0f0f0", font=f_title)
    draw.text((44, 96), "Select target module to inspect, review historical log trends, or authenticate to initialize active eBPF sensors.", fill="#999999", font=f_sm)
    draw.rounded_rectangle([WIDTH - 250, 72, WIDTH - 44, 108], radius=6, fill="#e95420")
    draw.text((WIDTH - 236, 83), "⚡ LAUNCH RUN SESSION", fill="#ffffff", font=f_card)
    
    # 4 Module Selection Cards
    modules = [
        ("KERNEL TELEMETRY", "Read-only eBPF tracepoints\nsys_enter_execve, connect, openat", "#3465a4", "ACTIVE (100%)"),
        ("PREVIOUS LOGS", "Analysis of 60s sliding windows\n98.8% repetitive noise collapsed", "#e95420", "STORED ARCHIVE"),
        ("MITRE ATT&CK", "Adversary Tactic Heatmap\nCross-referenced Linux behaviors", "#75507b", "ENTERPRISE v14"),
        ("PROCESS LINEAGE", "Correlated tree hierarchy\nReconstructed execve & procfs", "#4e9a06", "CORRELATED TREE"),
    ]
    cx = 24
    for title, desc, col, tag in modules:
        draw.rounded_rectangle([cx, 132, cx + 250, 230], radius=8, fill="#242424", outline="#363636")
        draw.rectangle([cx + 12, 144, cx + 18, 160], fill=col)
        draw.text((cx + 26, 146), title, fill="#f0f0f0", font=f_card)
        draw.text((cx + 12, 172), desc, fill="#888888", font=f_sm)
        draw.rounded_rectangle([cx + 12, 202, cx + 130, 222], radius=4, fill="#2e2e2e")
        draw.text((cx + 18, 207), tag, fill=col, font=f_sm)
        cx += 268
        
    # Main Content: Left = Previous Logs Analysis, Right = Current Status Threat Spectrum
    # Left Panel: Previous Logs Analysis
    draw.rounded_rectangle([24, 244, 620, HEIGHT - 20], radius=8, fill="#222222", outline="#333333")
    draw.text((40, 258), "HISTORICAL LOG ANALYSIS & NOISE COLLAPSE", fill="#f0f0f0", font=f_card)
    draw.text((40, 278), "Sliding-Window Aggregator snapshot: 1,240 desktop CSS warnings compressed into single count", fill="#777777", font=f_sm)
    
    # Table header
    draw.rectangle([40, 298, 604, 320], fill="#2a2a2a")
    draw.text((46, 304), "TIMESTAMP", fill="#aaaaaa", font=f_sm)
    draw.text((140, 304), "SUBSYSTEM", fill="#aaaaaa", font=f_sm)
    draw.text((230, 304), "PROCESS / TARGET", fill="#aaaaaa", font=f_sm)
    draw.text((420, 304), "COUNT", fill="#aaaaaa", font=f_sm)
    draw.text((500, 304), "SEVERITY", fill="#aaaaaa", font=f_sm)
    
    logs = [
        ("16:38:53", "ebpf", ".sys_update -> /tmp", "1", "CRITICAL", "#ef2929"),
        ("16:38:53", "ebpf", "/etc/shadow credential read", "1", "CRITICAL", "#ef2929"),
        ("16:38:50", "dbus", "snapd-desktop portal denial", "4", "HIGH RISK", "#f57900"),
        ("16:38:40", "systemd", "auditd.service exit status 1", "1", "CAUTION", "#edd400"),
        ("16:38:25", "ebpf", "curl -> port 443 [ip-7f9a12]", "18", "NOMINAL", "#4e9a06"),
        ("16:38:00", "journal", "gnome-shell css_parse_warn", "1240 (COLLAPSED)", "FILTERED", "#888888"),
    ]
    ly = 328
    for ts, sub, proc, cnt, sev, col in logs:
        draw.text((46, ly), ts, fill="#999999", font=f_mono)
        draw.text((140, ly), sub, fill="#e95420", font=f_mono)
        draw.text((230, ly), proc[:26], fill="#ffffff", font=f_mono)
        draw.text((420, ly), cnt, fill="#cccccc", font=f_mono)
        draw.rounded_rectangle([500, ly - 2, 595, ly + 14], radius=4, fill="#2c2c2c", outline=col)
        draw.text((508, ly), sev, fill=col, font=f_sm)
        ly += 26
        
    # Right Panel: Current Status Threat Spectrum
    draw.rounded_rectangle([636, 244, WIDTH - 24, HEIGHT - 20], radius=8, fill="#222222", outline="#333333")
    draw.text((652, 258), "CURRENT POSTURE & THREAT SPECTRUM", fill="#f0f0f0", font=f_card)
    draw.text((652, 278), "Granular threat level with dynamic risk spectrum", fill="#777777", font=f_sm)
    
    # 75% Risk Orange Gauge Box
    draw.rounded_rectangle([652, 306, WIDTH - 40, 410], radius=8, fill="#2a1f18", outline="#e95420")
    draw.text((668, 320), "THREAT STATUS: 75% AT RISK", fill="#e95420", font=f_title)
    draw.text((668, 344), "ALERT: World-writable execution & shadow read detected.", fill="#ffaa77", font=f_sm)
    
    # Granular Rainbow Spectrum Bar (Green -> Lime -> Yellow -> Orange (75%) -> Red)
    bar_x = 668
    bar_w = WIDTH - 40 - 668 - 16
    draw.rectangle([bar_x, 370, bar_x + bar_w, 390], fill="#111111")
    # Draw segments
    seg = bar_w / 4
    draw.rectangle([bar_x, 370, bar_x + seg, 390], fill="#4e9a06") # 0-25% Green
    draw.rectangle([bar_x + seg, 370, bar_x + seg * 2, 390], fill="#c4a000") # 25-50% Yellow
    draw.rectangle([bar_x + seg * 2, 370, bar_x + seg * 3, 390], fill="#e95420") # 50-75% Orange (Current)
    draw.rectangle([bar_x + seg * 3, 370, bar_x + bar_w, 390], fill="#cc0000") # 75-100% Red
    # Pointer on 75%
    ptr_x = bar_x + int(seg * 3)
    draw.polygon([(ptr_x, 362), (ptr_x - 6, 350), (ptr_x + 6, 350)], fill="#ffffff")
    draw.text((ptr_x - 30, 396), "75% AT RISK", fill="#e95420", font=f_mono)
    
    # System Metrics breakdown
    draw.text((668, 436), "HOST SYSTEM & CONTAINER VITALS", fill="#f0f0f0", font=f_card)
    vitals = [
        ("Kernel RingBuf Drops:", "0 (Adaptive Polling Active)"),
        ("Active Host Processes:", "376 processes monitored"),
        ("Open IPC Descriptors:", "77 FDs (Cap: 32 concurrent)"),
        ("Resident Set (RSS):", "28.4 MB (cgroup slice locked)"),
        ("Authentication Engine:", "ARGON2ID (m=64M, t=3, p=4)"),
    ]
    vy = 464
    for k, v in vitals:
        draw.text((668, vy), k, fill="#888888", font=f_mono)
        draw.text((850, vy), v, fill="#dddddd", font=f_mono)
        vy += 24
        
    draw.rounded_rectangle([668, vy + 10, WIDTH - 40, vy + 48], radius=6, fill="#2a2a2a", outline="#444444")
    draw.text((684, vy + 22), "AUTHENTICATE PROFILE TO HARDEN / ENTER CONSOLE", fill="#ffffff", font=f_card)
    
    img.save("docs/screenshots/01_landing_selection_overview.png")

# 2. Login Prompt & Accidental Launch Double Confirmation Modal
def render_prompt_and_double_confirmation():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#1c1c1c")
    draw = ImageDraw.Draw(img)
    draw_ubuntu_frame(draw, active_tab="LANDING")
    
    # Dim overlay
    overlay = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 180))
    img.paste(Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB"))
    draw = ImageDraw.Draw(img)
    
    f_title = get_monaco(13)
    f_card = get_monaco(11)
    f_mono = get_monaco(10)
    f_sm = get_monaco(9)
    
    # Step 1: Initial Prompt Dialog (Left/Behind)
    draw.rounded_rectangle([80, 160, 480, 480], radius=10, fill="#242424", outline="#444444")
    draw.rectangle([80, 160, 480, 204], fill="#1c1c1c")
    draw.text((100, 174), "1. RUN INITIALIZATION PROMPT", fill="#ffffff", font=f_title)
    draw.text((100, 224), "DirtySOCS Session Detected:\n\nWould you like to initiate real-time eBPF\nkernel observability now?", fill="#cccccc", font=f_card)
    
    draw.rounded_rectangle([100, 310, 460, 370], radius=6, fill="#1c1c1c", outline="#333333")
    draw.text((114, 324), "• Read-only kernel tracepoints\n• Deterministic CIS & NIST rule gate", fill="#888888", font=f_sm)
    
    draw.rounded_rectangle([100, 410, 260, 450], radius=6, fill="#333333")
    draw.text((120, 423), "DECLINE / OFFLINE", fill="#888888", font=f_card)
    draw.rounded_rectangle([280, 410, 460, 450], radius=6, fill="#e95420")
    draw.text((310, 423), "ACCEPT RUN ->", fill="#ffffff", font=f_card)
    
    # Step 2: Double Confirmation Dialog (Foreground / Right)
    mx = 510
    draw.rounded_rectangle([mx, 120, mx + 510, 530], radius=12, fill="#262626", outline="#e95420", width=2)
    # Header
    draw.rectangle([mx, 120, mx + 510, 172], fill="#3a1c14")
    draw.ellipse([mx + 20, 136, mx + 44, 160], fill="#e95420")
    draw.text((mx + 29, 140), "!", fill="#ffffff", font=f_title)
    draw.text((mx + 56, 138), "2. ACCIDENTAL LAUNCH PREVENTION", fill="#ffffff", font=f_title)
    draw.text((mx + 56, 154), "CONFIRM KERNEL PROBE ATTACHMENT", fill="#ffaa77", font=f_sm)
    
    # Content
    draw.text((mx + 24, 192), "SAFETY VERIFICATION PROTOCOL:", fill="#e95420", font=f_card)
    warn_text = (
        "You are about to attach eBPF tracepoints to the active Linux kernel:\n"
        "  • sys_enter_execve (Process executions)\n"
        "  • sys_enter_openat (Restricted file reads)\n"
        "  • sys_enter_connect (Network sockets)\n\n"
        "To avoid launching the system accidentally, explicit secondary\n"
        "human verification is required before allocating ring buffers."
    )
    draw.text((mx + 24, 216), warn_text, fill="#cccccc", font=f_mono)
    
    # Checkbox verification
    draw.rounded_rectangle([mx + 24, 370, mx + 486, 424], radius=6, fill="#1c1c1c", outline="#444444")
    draw.rectangle([mx + 38, 386, mx + 56, 404], fill="#e95420")
    draw.text((mx + 42, 387), "✓", fill="#ffffff", font=f_card)
    draw.text((mx + 68, 384), "I confirm operational intent to attach eBPF sensors\nand monitor endpoint telemetry.", fill="#ffffff", font=f_sm)
    
    # Actions
    draw.rounded_rectangle([mx + 24, 454, mx + 200, 498], radius=6, fill="#333333")
    draw.text((mx + 70, 468), "CANCEL", fill="#888888", font=f_card)
    
    draw.rounded_rectangle([mx + 220, 454, mx + 486, 498], radius=6, fill="#e95420")
    draw.text((mx + 250, 468), "CONFIRM & COMMENCE RUN", fill="#ffffff", font=f_card)
    
    img.save("docs/screenshots/02_prompt_and_double_confirmation.png")

# 3. Terminal Typing Boot Sequence before Dissolving into Dashboard
def render_terminal_boot_sequence():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#0f0f0f")
    draw = ImageDraw.Draw(img)
    
    f_title = get_monaco(12)
    f_term = get_monaco(11)
    
    # Ubuntu Terminal Window
    draw.rectangle([0, 0, WIDTH, 36], fill="#181818", outline="#2b2b2b")
    draw.ellipse([16, 12, 26, 22], fill="#ed6a5e")
    draw.ellipse([34, 12, 44, 22], fill="#f4bf4f")
    draw.ellipse([52, 12, 62, 22], fill="#61c554")
    draw.text((WIDTH // 2 - 140, 10), "purpleronin@dirtysocs-workstation: ~ (eBPF Boot)", fill="#aaaaaa", font=f_title)
    
    # Terminal text typing output
    lines = [
        ("purpleronin@dirtysocs-workstation:~$", " dirtysocs-daemon --attach --strict-hil", "#ffffff"),
        ("[ +0.001s ]", " [INFO] Initializing DirtySOCS Kernel Observability Engine v2.0...", "#61c554"),
        ("[ +0.012s ]", " [OK] Linux 7.0.0-38-generic (BTF Enabled, x86_64) verified.", "#61c554"),
        ("[ +0.025s ]", " [OK] Binding secure IPC: /run/dirtysocs/dirtysocs.sock (mode 0600, uid: 1000)", "#61c554"),
        ("[ +0.038s ]", " [OK] Attaching eBPF tracepoint: syscalls/sys_enter_execve", "#61c554"),
        ("[ +0.049s ]", " [OK] Attaching eBPF tracepoint: syscalls/sys_enter_connect", "#61c554"),
        ("[ +0.060s ]", " [OK] Attaching eBPF tracepoint: syscalls/sys_enter_openat", "#61c554"),
        ("[ +0.071s ]", " [OK] Allocated 1MB non-blocking kernel ring buffer (Adaptive Microsecond Polling: ACTIVE)", "#61c554"),
        ("[ +0.084s ]", " [OK] Loaded deterministic compliance corpus: CIS RHEL 9 (1.1.2, 1.6, 4.1.4)", "#61c554"),
        ("[ +0.098s ]", " [OK] Prime token scrubber: Hex/Octal/Dword IP normalizer & Salted SHA-256", "#61c554"),
        ("[ +0.112s ]", " [OK] Double human-in-the-loop gate armed (pidfd_open atomic pinning active)", "#61c554"),
        ("[ +0.128s ]", " [OK] Process lifecycle check: 0 lingering background threads on exit verified.", "#61c554"),
        ("[ +0.145s ]", " [>>] All kernel sensors synchronized. Dissolving console to Dashboard summary...", "#e95420"),
    ]
    
    ty = 60
    for prefix, content, col in lines:
        draw.text((36, ty), prefix, fill="#e95420" if "dirtysocs" in prefix else "#aaaaaa", font=f_term)
        draw.text((160 if prefix.startswith("[") else 370, ty), content, fill=col, font=f_term)
        ty += 32
        
    # Blinking terminal cursor block
    draw.rectangle([36, ty + 10, 48, ty + 26], fill="#e95420")
    
    # Bottom Dissolve Indicator
    draw.rounded_rectangle([WIDTH // 2 - 200, HEIGHT - 70, WIDTH // 2 + 200, HEIGHT - 24], radius=8, fill="#242424", outline="#e95420")
    draw.text((WIDTH // 2 - 160, HEIGHT - 55), "DISSOLVING INTO OPERATIONS DASHBOARD...", fill="#ffffff", font=f_title)
    
    img.save("docs/screenshots/03_terminal_boot_sequence.png")

# 4. In-App Hardening View with Username/Password & Argon2id + 2FA
def render_in_app_hardening():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#1c1c1c")
    draw = ImageDraw.Draw(img)
    draw_ubuntu_frame(draw, active_tab="SECURITY")
    
    f_title = get_monaco(13)
    f_card = get_monaco(11)
    f_mono = get_monaco(10)
    f_sm = get_monaco(9)
    
    # Center Hardening Card
    mx = 180
    mw = WIDTH - 360
    draw.rounded_rectangle([mx, 70, mx + mw, HEIGHT - 20], radius=10, fill="#242424", outline="#3c3c3c")
    
    # Card Header
    draw.rectangle([mx, 70, mx + mw, 120], fill="#1c1c1c")
    draw.text((mx + 24, 85), "ANALYST AUTHENTICATION & ACCESS HARDENING", fill="#f0f0f0", font=f_title)
    draw.text((mx + 24, 103), "Harden console access using memory-hard Argon2id key derivation and TOTP 2FA", fill="#888888", font=f_sm)
    
    # 1. Credentials Section
    cy = 138
    draw.text((mx + 24, cy), "1. OPERATOR CREDENTIALS", fill="#e95420", font=f_card)
    cy += 24
    draw.text((mx + 24, cy), "Analyst Username:", fill="#888888", font=f_sm)
    draw.rounded_rectangle([mx + 24, cy + 16, mx + mw - 24, cy + 46], radius=6, fill="#1c1c1c", outline="#444444")
    draw.text((mx + 36, cy + 24), "purpleronin_soc", fill="#ffffff", font=f_mono)
    cy += 56
    
    draw.text((mx + 24, cy), "Master Passphrase:", fill="#888888", font=f_sm)
    draw.rounded_rectangle([mx + 24, cy + 16, mx + mw - 24, cy + 46], radius=6, fill="#1c1c1c", outline="#444444")
    draw.text((mx + 36, cy + 26), "••••••••••••••••••••••••••••••••", fill="#e95420", font=f_mono)
    cy += 64
    
    # 2. Argon2id Key Derivation Configuration
    draw.text((mx + 24, cy), "2. ARGON2ID MEMORY-HARD KEY DERIVATION", fill="#e95420", font=f_card)
    cy += 24
    
    draw.rounded_rectangle([mx + 24, cy, mx + mw - 24, cy + 86], radius=8, fill="#1c1c1c", outline="#383838")
    # Switch toggle active
    draw.rounded_rectangle([mx + 38, cy + 14, mx + 78, cy + 34], radius=10, fill="#e95420")
    draw.ellipse([mx + 58, cy + 16, mx + 76, cy + 32], fill="#ffffff")
    draw.text((mx + 90, cy + 18), "ACTIVATE ARGON2ID ENCRYPTION (ACTIVE)", fill="#61c554", font=f_card)
    
    params = "m_cost: 65,536 KiB (64 MB) | t_cost: 3 passes | p_cost: 4 lanes | Tag: 256-bit"
    draw.text((mx + 38, cy + 48), params, fill="#aaaaaa", font=f_mono)
    draw.text((mx + 38, cy + 66), "Resistant against GPU / ASIC brute-force and side-channel timing attacks.", fill="#777777", font=f_sm)
    cy += 100
    
    # 3. 2FA Authenticator Section
    draw.text((mx + 24, cy), "3. TWO-FACTOR AUTHENTICATION (TOTP 2FA)", fill="#e95420", font=f_card)
    cy += 24
    
    draw.rounded_rectangle([mx + 24, cy, mx + mw - 24, cy + 110], radius=8, fill="#1c1c1c", outline="#383838")
    # Mock QR Code Box
    draw.rectangle([mx + 36, cy + 12, mx + 116, cy + 92], fill="#ffffff")
    for qx in range(mx + 42, mx + 110, 10):
        for qy in range(cy + 18, cy + 86, 10):
            if (qx + qy) % 3 == 0:
                draw.rectangle([qx, qy, qx + 6, qy + 6], fill="#000000")
                
    draw.text((mx + 130, cy + 16), "Scan with Google Authenticator / YubiKey:", fill="#ffffff", font=f_sm)
    draw.text((mx + 130, cy + 34), "Secret: JBSWY3DPEHPK3PXP", fill="#e95420", font=f_mono)
    
    draw.text((mx + 130, cy + 58), "Enter 6-Digit Code:", fill="#888888", font=f_sm)
    draw.rounded_rectangle([mx + 130, cy + 72, mx + 260, cy + 100], radius=4, fill="#2a2a2a", outline="#e95420")
    draw.text((mx + 148, cy + 78), "8 4 9 1 0 2", fill="#ffffff", font=f_card)
    draw.text((mx + 280, cy + 78), "✓ VERIFIED", fill="#61c554", font=f_mono)
    cy += 126
    
    # Bottom Buttons
    draw.rounded_rectangle([mx + 24, cy, mx + 200, cy + 42], radius=6, fill="#333333")
    draw.text((mx + 60, cy + 14), "DISCARD", fill="#888888", font=f_card)
    
    draw.rounded_rectangle([mx + mw - 280, cy, mx + mw - 24, cy + 42], radius=6, fill="#e95420")
    draw.text((mx + mw - 250, cy + 14), "PERSIST HARDENED PROFILE", fill="#ffffff", font=f_card)
    
    img.save("docs/screenshots/04_in_app_hardening_argon2id.png")

if __name__ == "__main__":
    render_landing_page()
    render_prompt_and_double_confirmation()
    render_terminal_boot_sequence()
    render_in_app_hardening()
    print("Rendered all 4 UI preview screenshots successfully.")
