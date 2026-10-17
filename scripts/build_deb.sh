#!/usr/bin/env bash
# ==============================================================================
# DirtySOCS • Debian Package Builder (.deb for apt installation)
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_NAME="dirtysocs"
PKG_VERSION="1.0.0"
PKG_ARCH="amd64"
DEB_NAME="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"
STAGE_DIR="${ROOT_DIR}/target/debian/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}"
OUTPUT_DIR="${ROOT_DIR}/output"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}  DirtySOCS: Building Production Debian (.deb) Package for Ubuntu ${NC}"
echo -e "${CYAN}================================================================${NC}"

# Ensure cargo is in PATH if available in ~/.cargo/bin
if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
fi

# Step 1: Verify Release Binaries
echo -e "\n${CYAN}[1/5] Verifying Pre-built Release Binaries...${NC}"
if [ ! -f "${ROOT_DIR}/target/release/soc-daemon" ]; then
    echo -e "${YELLOW}[!] Building soc-daemon release binary...${NC}"
    cargo build --release --bin soc-daemon
fi

if [ ! -f "${ROOT_DIR}/apps/soc_dashboard/build/linux/x64/release/bundle/soc_dashboard" ]; then
    echo -e "${YELLOW}[!] Building Flutter desktop release bundle...${NC}"
    (cd "${ROOT_DIR}/apps/soc_dashboard" && flutter build linux --release)
fi

echo -e "${GREEN}[✓] Release binaries verified.${NC}"

# Step 2: Prepare Staging Tree
echo -e "\n${CYAN}[2/5] Creating Debian Package Filesystem Hierarchy...${NC}"
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}/DEBIAN"
mkdir -p "${STAGE_DIR}/usr/bin"
mkdir -p "${STAGE_DIR}/usr/lib/dirtysocs"
mkdir -p "${STAGE_DIR}/lib/systemd/system"
mkdir -p "${STAGE_DIR}/usr/share/applications"
mkdir -p "${STAGE_DIR}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${OUTPUT_DIR}"

# Step 3: Populate Binaries & Assets
echo -e "\n${CYAN}[3/5] Installing Binaries, Systemd Service, and Desktop Metadata...${NC}"

# 3a. Kernel Daemon
cp -p "${ROOT_DIR}/target/release/soc-daemon" "${STAGE_DIR}/usr/bin/dirtysocs-daemon"

# 3b. Flutter Application Release Bundle
cp -rp "${ROOT_DIR}/apps/soc_dashboard/build/linux/x64/release/bundle/"* "${STAGE_DIR}/usr/lib/dirtysocs/"

# 3c. GUI Launcher Script
cat << 'EOF' > "${STAGE_DIR}/usr/bin/dirtysocs"
#!/usr/bin/env bash
# DirtySOCS Desktop GUI Launcher
exec /usr/lib/dirtysocs/soc_dashboard "$@"
EOF
chmod 755 "${STAGE_DIR}/usr/bin/dirtysocs"

# 3d. Systemd Service Unit
cp -p "${ROOT_DIR}/deploy/dirtysocs.service" "${STAGE_DIR}/lib/systemd/system/dirtysocs.service"

# 3e. GNOME Desktop Entry & App Icon
cp -p "${ROOT_DIR}/deploy/dirtysocs.desktop" "${STAGE_DIR}/usr/share/applications/dirtysocs.desktop"
cp -p "${ROOT_DIR}/docs/assets/logo.svg" "${STAGE_DIR}/usr/share/icons/hicolor/scalable/apps/dirtysocs.svg"

# Step 4: Generate Package Metadata (control, postinst, prerm)
echo -e "\n${CYAN}[4/5] Generating Package Control & Maintainer Scripts...${NC}"

cat << EOF > "${STAGE_DIR}/DEBIAN/control"
Package: ${PKG_NAME}
Version: ${PKG_VERSION}
Section: admin
Priority: optional
Architecture: ${PKG_ARCH}
Maintainer: Ronin <purpleronin@dirtysocs.io>
Depends: libc6 (>= 2.31), libgtk-3-0 (>= 3.24)
Homepage: https://github.com/87Supreme-cell/DirtySOCS
Description: Hybrid Kernel-Observability & Air-Gapped AI SOC Analyst System
 DirtySOCS couples read-only eBPF kernel telemetry (execve, connect, openat)
 with local sliding-window deduplication, deterministic token redaction, and
 a native Flutter GTK control plane for incident triage and human-in-the-loop
 remediation.
EOF

cat << 'EOF' > "${STAGE_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    mkdir -p /var/log/dirtysocs/dossiers
    chmod 750 /var/log/dirtysocs
    systemctl daemon-reload || true
    if which update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if which gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q /usr/share/icons/hicolor || true
    fi
    echo "===================================================================="
    echo "  DirtySOCS v1.0.0 has been installed successfully."
    echo "  • Start the eBPF Kernel Daemon:  sudo systemctl enable --now dirtysocs"
    echo "  • Check Daemon Service Status:   systemctl status dirtysocs"
    echo "  • Launch the Desktop Dashboard:  dirtysocs"
    echo "===================================================================="
fi
EOF
chmod 755 "${STAGE_DIR}/DEBIAN/postinst"

cat << 'EOF' > "${STAGE_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    systemctl stop dirtysocs || true
    systemctl disable dirtysocs || true
fi
EOF
chmod 755 "${STAGE_DIR}/DEBIAN/prerm"

# Step 5: Build Debian Archive
echo -e "\n${CYAN}[5/5] Building Package Archive via dpkg-deb...${NC}"
dpkg-deb --build --root-owner-group "${STAGE_DIR}" "${OUTPUT_DIR}/${DEB_NAME}"

echo -e "\n${GREEN}================================================================${NC}"
echo -e "${GREEN}  PACKAGE READY: ${OUTPUT_DIR}/${DEB_NAME}                        ${NC}"
echo -e "${GREEN}================================================================${NC}"
ls -lh "${OUTPUT_DIR}/${DEB_NAME}"
echo -e "Install on Ubuntu / Debian using:"
echo -e "  sudo apt install ./${OUTPUT_DIR}/${DEB_NAME}\n"
