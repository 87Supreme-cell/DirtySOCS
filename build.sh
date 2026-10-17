#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# DirtySOCS • Unified Automated Build Script
# ==============================================================================

GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}  DirtySOCS: Building Production-Grade Kernel & SOC System      ${NC}"
echo -e "${CYAN}================================================================${NC}"

# Source user cargo environment
if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
fi

echo -e "\n${CYAN}[1/4] Verifying Toolchain Prerequisites...${NC}"
cargo --version
flutter --version | head -n 2

echo -e "\n${CYAN}[2/4] Compiling Ring-0 eBPF Bytecode (Aya)...${NC}"
cargo +nightly build --manifest-path crates/soc-ebpf/Cargo.toml --target bpfel-unknown-none -Z build-std=core --release
echo -e "${GREEN}[✓] eBPF bytecode compiled successfully.${NC}"

echo -e "\n${CYAN}[3/4] Building Workspace Daemon & IPC Libraries...${NC}"
cargo build --workspace
echo -e "${GREEN}[✓] soc-daemon and soc-ipc built successfully.${NC}"

echo -e "\n${CYAN}[4/4] Executing Comprehensive Automated Test Suite...${NC}"
cargo test --workspace
(cd apps/soc_dashboard && flutter analyze)
echo -e "${GREEN}[✓] All automated unit/integration tests and UI checks passed!${NC}"

echo -e "\n${GREEN}================================================================${NC}"
echo -e "${GREEN}  BUILD COMPLETE: DirtySOCS is ready for audit and deployment!   ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "Quickstart Options:"
echo -e "  • Start Daemon:   make run-daemon"
echo -e "  • Start UI:       make run-ui"
echo -e "  • Run Simulation: make simulate-attack\n"
