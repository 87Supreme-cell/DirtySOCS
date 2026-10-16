import os
from PIL import Image, ImageDraw, ImageFont

os.makedirs("docs/screenshots", exist_ok=True)
WIDTH, HEIGHT = 1000, 640

def get_font(size):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/custom/Monaco.ttf", size)
    except:
        try:
            return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size)
        except:
            return ImageFont.load_default()

def get_bold_font(size):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", size)
    except:
        return get_font(size)

def draw_ubuntu_header(draw, title, is_dark=True):
    bg_color = "#181818" if is_dark else "#e4e4e4"
    border_color = "#333333" if is_dark else "#cccccc"
    text_color = "#f5f5f5" if is_dark else "#222222"

    # Header bar
    draw.rectangle([0, 0, WIDTH, 44], fill=bg_color, outline=border_color, width=1)
    # Ubuntu Control Dots
    draw.ellipse([16, 16, 26, 26], fill="#ed6a5e")
    draw.ellipse([34, 16, 44, 26], fill="#f4bf4f")
    draw.ellipse([52, 16, 62, 26], fill="#61c554")

    # Ubuntu Eye Icon
    draw.ellipse([80, 12, 102, 34], fill="#e95420")
    font_bold = get_bold_font(11)
    font_small = get_font(9)

    draw.text((112, 15), "DirtySOCS", fill=text_color, font=font_bold)
    draw.rectangle([190, 14, 305, 32], fill="#383838" if is_dark else "#d0d0d0")
    draw.text((196, 17), "LINUX 7.0 (RING-0)", fill="#e95420", font=font_small)

    # Header Navigation Pills
    tabs = ["DASHBOARD", "DUAL-LENS", "PROCESS TREE", "MITRE GRID"]
    tx = 330
    for idx, tab in enumerate(tabs):
        is_active = (idx == 0)
        pill_bg = "#e95420" if is_active else ("#242424" if is_dark else "#ffffff")
        pill_txt = "#ffffff" if is_active else ("#a0a0a0" if is_dark else "#555555")
        draw.rounded_rectangle([tx, 10, tx + 95, 34], radius=6, fill=pill_bg)
        draw.text((tx + 10, 16), tab, fill=pill_txt, font=font_small)
        tx += 105

    # Theme Toggle Indicator
    mode_text = "☀ LIGHT" if is_dark else "🌙 DARK"
    draw.rounded_rectangle([WIDTH - 90, 10, WIDTH - 16, 34], radius=6, fill="#2b2b2b" if is_dark else "#dcdcdc")
    draw.text((WIDTH - 80, 16), mode_text, fill=text_color, font=font_small)

# 1. Main Landing Dashboard (Dark Mode)
def render_ubuntu_dashboard_dark():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#1e1e1e")
    draw = ImageDraw.Draw(img)
    draw_ubuntu_header(draw, "DirtySOCS • Ubuntu Dark Theme", is_dark=True)

    font_bold = get_bold_font(11)
    font_large = get_bold_font(16)
    font_small = get_font(9)

    # Granular Status Banner (Orange 75% at risk)
    draw.rounded_rectangle([20, 56, 980, 135], radius=10, fill="#2b2b2b", outline="#383838", width=1)
    
    # 75% Orange Status Dot
    draw.ellipse([40, 72, 54, 86], fill="#f57900")
    draw.text((64, 72), "SYSTEM THREAT LEVEL: 75% AT RISK (ORANGE HIGH ALERT)", fill="#f57900", font=font_bold)
    draw.text((820, 72), "75% Risk Factor", fill="#f57900", font=font_bold)

    # Continuous Granular Spectrum Bar: Green -> Lime -> Yellow -> Orange -> Red
    draw.rounded_rectangle([40, 96, 960, 106], radius=5, fill="#383838")
    # Spectrum segments
    draw.rectangle([40, 96, 224, 106], fill="#26a269")  # Green
    draw.rectangle([224, 96, 408, 106], fill="#73c936") # Lime
    draw.rectangle([408, 96, 592, 106], fill="#e5a50a") # Yellow
    draw.rectangle([592, 96, 776, 106], fill="#f57900") # Orange
    draw.rectangle([776, 96, 960, 106], fill="#c01c28") # Red

    # 75% Position Indicator Thumb
    draw.ellipse([724, 92, 742, 110], fill="#ffffff", outline="#f57900", width=3)

    # Spectrum Legend
    draw.text((40, 114), "NOMINAL (0%)", fill="#26a269", font=font_small)
    draw.text((224, 114), "LOW (25%)", fill="#73c936", font=font_small)
    draw.text((408, 114), "CAUTION (50%)", fill="#e5a50a", font=font_small)
    draw.text((592, 114), "ALERT (75% AT RISK)", fill="#f57900", font=font_bold)
    draw.text((870, 114), "CRITICAL (100%)", fill="#c01c28", font=font_small)

    # 4 KPI Tiles
    tiles = [
        ("CGROUP CPU", "2.4%", "Normal usage"),
        ("RESIDENT RAM", "28.4 MB", "Bounded ringbuf"),
        ("OPEN FDS", "77", "RAII auto-cleanup"),
        ("ACTIVE PROCS", "376", "Procfs telemetry"),
    ]
    x = 20
    for title, val, sub in tiles:
        draw.rounded_rectangle([x, 145, x + 232, 215], radius=10, fill="#2b2b2b", outline="#383838", width=1)
        draw.text((x + 14, 157), title, fill="#a0a0a0", font=font_small)
        draw.text((x + 14, 173), val, fill="#f5f5f5", font=font_large)
        draw.text((x + 14, 196), sub, fill="#666666", font=font_small)
        x += 248

    # Trend Analysis Card
    draw.rounded_rectangle([20, 226, 980, 345], radius=10, fill="#2b2b2b", outline="#383838", width=1)
    draw.text((36, 238), "EVENT INGESTION & NOISE REDUCTION TRENDS", fill="#e95420", font=font_bold)
    draw.text((36, 252), "60-minute sliding window rate analysis and deduplication efficiency", fill="#888888", font=font_small)

    draw.ellipse([700, 242, 708, 250], fill="#e95420")
    draw.text((714, 240), "Events/sec", fill="#aaaaaa", font=font_small)
    draw.ellipse([810, 242, 818, 250], fill="#26a269")
    draw.text((824, 240), "Noise Suppressed (99.4%)", fill="#aaaaaa", font=font_small)

    # Trend Sparkline Line
    draw.line([36, 310, 960, 310], fill="#383838", width=1)
    draw.line([36, 280, 960, 280], fill="#383838", width=1)
    # Event rate curve (Orange)
    pts_orange = [(36, 320), (180, 315), (360, 325), (540, 290), (720, 275), (960, 260)]
    for i in range(len(pts_orange) - 1):
        draw.line([pts_orange[i], pts_orange[i+1]], fill="#e95420", width=2)
    # Noise reduction curve (Green)
    pts_green = [(36, 270), (180, 268), (360, 265), (540, 262), (720, 260), (960, 258)]
    for i in range(len(pts_green) - 1):
        draw.line([pts_green[i], pts_green[i+1]], fill="#26a269", width=2)

    # Historical Logs Store Card
    draw.rounded_rectangle([20, 356, 980, 620], radius=10, fill="#2b2b2b", outline="#383838", width=1)
    draw.text((36, 370), "HISTORICAL & PREVIOUS LOGS STORE", fill="#e95420", font=font_bold)
    draw.text((36, 384), "Stored events deduplicated across 60s windows with PII redaction", fill="#888888", font=font_small)

    # Filter Tabs
    draw.rounded_rectangle([720, 366, 810, 392], radius=6, fill="#383838")
    draw.text((740, 374), "EBPF [4]", fill="#ffffff", font=font_small)
    draw.rounded_rectangle([820, 366, 960, 392], radius=6, fill="#1e1e1e", outline="#383838")
    draw.text((835, 374), "🔍 Search...", fill="#666666", font=font_small)

    # Log rows
    logs = [
        ("16:38:53", "EBPF", "sys_enter_execve", ".sys_update (PID 4821)", "/tmp/.sys_update", "CRITICAL", "#c01c28", 1),
        ("16:38:53", "EBPF", "sys_enter_openat", ".sys_update (PID 4821)", "/etc/shadow", "CRITICAL", "#c01c28", 1),
        ("16:38:50", "DBUS", "apparmor_denial", "snapd-desktop (PID 4117)", "org.freedesktop.host.portal", "ALERT", "#f57900", 4),
        ("16:38:40", "SYSTEMD", "service_failure", "auditd.service", "/lib/systemd/system/auditd", "CAUTION", "#e5a50a", 1),
        ("16:38:00", "JOURNAL", "css_parse_warn", "gnome-shell (PID 1840)", "desktop-styling.css", "NOMINAL", "#26a269", 1240),
    ]

    ly = 412
    for time_s, sub, ev, proc, target, rsk, col, cnt in logs:
        draw.line([36, ly, 960, ly], fill="#333333", width=1)
        ly += 8
        draw.text((36, ly), time_s, fill="#888888", font=font_small)
        draw.rounded_rectangle([110, ly - 2, 165, ly + 14], radius=4, fill="#383838")
        draw.text((118, ly), sub, fill="#f5f5f5", font=font_small)
        draw.text((180, ly), ev, fill="#f5f5f5", font=font_bold)
        draw.text((320, ly), proc, fill="#f5f5f5", font=font_small)
        draw.text((500, ly), target, fill="#888888", font=font_small)
        if cnt > 1:
            draw.rounded_rectangle([780, ly - 2, 830, ly + 14], radius=4, fill="#451a03")
            draw.text((790, ly), f"×{cnt}", fill="#f57900", font=font_bold)
        draw.rounded_rectangle([860, ly - 2, 950, ly + 14], radius=4, fill=col)
        draw.text((875, ly), rsk, fill="#ffffff", font=font_bold)
        ly += 28

    img.save("docs/screenshots/ubuntu_dashboard_dark.png")
    img.save("docs/screenshots/dashboard_overview.png")

# 2. Main Landing Dashboard (Light Mode)
def render_ubuntu_dashboard_light():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#f5f5f5")
    draw = ImageDraw.Draw(img)
    draw_ubuntu_header(draw, "DirtySOCS • Ubuntu Light Porcelain Theme", is_dark=False)

    font_bold = get_bold_font(11)
    font_large = get_bold_font(16)
    font_small = get_font(9)

    # Granular Status Banner (Orange 75% at risk)
    draw.rounded_rectangle([20, 56, 980, 135], radius=10, fill="#ffffff", outline="#e2e2e2", width=1)
    
    draw.ellipse([40, 72, 54, 86], fill="#f57900")
    draw.text((64, 72), "SYSTEM THREAT LEVEL: 75% AT RISK (ORANGE HIGH ALERT)", fill="#f57900", font=font_bold)
    draw.text((820, 72), "75% Risk Factor", fill="#f57900", font=font_bold)

    # Spectrum Bar
    draw.rounded_rectangle([40, 96, 960, 106], radius=5, fill="#e8e8e8")
    draw.rectangle([40, 96, 224, 106], fill="#26a269")
    draw.rectangle([224, 96, 408, 106], fill="#73c936")
    draw.rectangle([408, 96, 592, 106], fill="#e5a50a")
    draw.rectangle([592, 96, 776, 106], fill="#f57900")
    draw.rectangle([776, 96, 960, 106], fill="#c01c28")

    draw.ellipse([724, 92, 742, 110], fill="#ffffff", outline="#f57900", width=3)

    draw.text((40, 114), "NOMINAL (0%)", fill="#26a269", font=font_small)
    draw.text((224, 114), "LOW (25%)", fill="#73c936", font=font_small)
    draw.text((408, 114), "CAUTION (50%)", fill="#e5a50a", font=font_small)
    draw.text((592, 114), "ALERT (75% AT RISK)", fill="#f57900", font=font_bold)
    draw.text((870, 114), "CRITICAL (100%)", fill="#c01c28", font=font_small)

    # 4 KPI Tiles
    tiles = [
        ("CGROUP CPU", "2.4%", "Normal usage"),
        ("RESIDENT RAM", "28.4 MB", "Bounded ringbuf"),
        ("OPEN FDS", "77", "RAII auto-cleanup"),
        ("ACTIVE PROCS", "376", "Procfs telemetry"),
    ]
    x = 20
    for title, val, sub in tiles:
        draw.rounded_rectangle([x, 145, x + 232, 215], radius=10, fill="#ffffff", outline="#e2e2e2", width=1)
        draw.text((x + 14, 157), title, fill="#666666", font=font_small)
        draw.text((x + 14, 173), val, fill="#222222", font=font_large)
        draw.text((x + 14, 196), sub, fill="#999999", font=font_small)
        x += 248

    # Trend Card
    draw.rounded_rectangle([20, 226, 980, 345], radius=10, fill="#ffffff", outline="#e2e2e2", width=1)
    draw.text((36, 238), "EVENT INGESTION & NOISE REDUCTION TRENDS", fill="#e95420", font=font_bold)
    draw.text((36, 252), "60-minute sliding window rate analysis and deduplication efficiency", fill="#777777", font=font_small)

    draw.line([36, 310, 960, 310], fill="#e8e8e8", width=1)
    draw.line([36, 280, 960, 280], fill="#e8e8e8", width=1)

    pts_orange = [(36, 320), (180, 315), (360, 325), (540, 290), (720, 275), (960, 260)]
    for i in range(len(pts_orange) - 1):
        draw.line([pts_orange[i], pts_orange[i+1]], fill="#e95420", width=2)
    pts_green = [(36, 270), (180, 268), (360, 265), (540, 262), (720, 260), (960, 258)]
    for i in range(len(pts_green) - 1):
        draw.line([pts_green[i], pts_green[i+1]], fill="#26a269", width=2)

    # Logs Card
    draw.rounded_rectangle([20, 356, 980, 620], radius=10, fill="#ffffff", outline="#e2e2e2", width=1)
    draw.text((36, 370), "HISTORICAL & PREVIOUS LOGS STORE", fill="#e95420", font=font_bold)
    draw.text((36, 384), "Stored events deduplicated across 60s windows with PII redaction", fill="#777777", font=font_small)

    logs = [
        ("16:38:53", "EBPF", "sys_enter_execve", ".sys_update (PID 4821)", "/tmp/.sys_update", "CRITICAL", "#c01c28", 1),
        ("16:38:53", "EBPF", "sys_enter_openat", ".sys_update (PID 4821)", "/etc/shadow", "CRITICAL", "#c01c28", 1),
        ("16:38:50", "DBUS", "apparmor_denial", "snapd-desktop (PID 4117)", "org.freedesktop.host.portal", "ALERT", "#f57900", 4),
        ("16:38:40", "SYSTEMD", "service_failure", "auditd.service", "/lib/systemd/system/auditd", "CAUTION", "#e5a50a", 1),
        ("16:38:00", "JOURNAL", "css_parse_warn", "gnome-shell (PID 1840)", "desktop-styling.css", "NOMINAL", "#26a269", 1240),
    ]

    ly = 412
    for time_s, sub, ev, proc, target, rsk, col, cnt in logs:
        draw.line([36, ly, 960, ly], fill="#e8e8e8", width=1)
        ly += 8
        draw.text((36, ly), time_s, fill="#666666", font=font_small)
        draw.rounded_rectangle([110, ly - 2, 165, ly + 14], radius=4, fill="#e8e8e8")
        draw.text((118, ly), sub, fill="#222222", font=font_small)
        draw.text((180, ly), ev, fill="#222222", font=font_bold)
        draw.text((320, ly), proc, fill="#222222", font=font_small)
        draw.text((500, ly), target, fill="#666666", font=font_small)
        if cnt > 1:
            draw.rounded_rectangle([780, ly - 2, 830, ly + 14], radius=4, fill="#fde8d7")
            draw.text((790, ly), f"×{cnt}", fill="#e95420", font=font_bold)
        draw.rounded_rectangle([860, ly - 2, 950, ly + 14], radius=4, fill=col)
        draw.text((875, ly), rsk, fill="#ffffff", font=font_bold)
        ly += 28

    img.save("docs/screenshots/ubuntu_dashboard_light.png")

render_ubuntu_dashboard_dark()
render_ubuntu_dashboard_light()
print("Ubuntu native screenshots rendered successfully!")
