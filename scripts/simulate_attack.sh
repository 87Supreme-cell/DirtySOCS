#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# DirtySOCS • Interactive Attack Simulation & Verification Script
# This script simulates a realistic compromise scenario to verify eBPF tracepoints,
# heuristic gating, and air-gapped investigation dossier generation.
# ==============================================================================

GREEN='\033[0;32m'
ORANGE='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}  DirtySOCS Attack Simulation: /tmp Execution & Credential Read ${NC}"
echo -e "${CYAN}================================================================${NC}"

TMP_PAYLOAD="/tmp/.sys_update"

# Trap cleanup on exit
cleanup() {
    echo -e "\n${ORANGE}[*] Cleaning up simulation artifacts...${NC}"
    rm -f "${TMP_PAYLOAD}"
    echo -e "${GREEN}[✓] Removed ${TMP_PAYLOAD}. Clean state restored.${NC}"
}
trap cleanup EXIT

echo -e "${ORANGE}[1] Staging untrusted payload in temporary storage (${TMP_PAYLOAD})...${NC}"
cat << 'EOF' > "${TMP_PAYLOAD}"
#!/usr/bin/env bash
# Simulating credential harvesting attempt
cat /etc/shadow > /dev/null 2>&1 || true
sleep 1
EOF
chmod +x "${TMP_PAYLOAD}"
echo -e "${GREEN}[✓] Payload written: ${TMP_PAYLOAD} (Violates CIS RHEL 9 Control 1.1.2)${NC}"

echo -e "\n${ORANGE}[2] Executing simulated payload to trigger eBPF sys_enter_execve probe...${NC}"
"${TMP_PAYLOAD}" &
PAYLOAD_PID=$!
echo -e "${RED}[!] Spawned suspect process with PID: ${PAYLOAD_PID}${NC}"

wait ${PAYLOAD_PID} || true

echo -e "\n${GREEN}[3] Sycall execution completed.${NC}"
echo -e "${CYAN}Expected Daemon Action:${NC}"
echo -e "  • Ring-0 eBPF 'sys_enter_execve' intercepted path '${TMP_PAYLOAD}'"
echo -e "  • Ring-0 eBPF 'sys_enter_openat' intercepted target '/etc/shadow'"
echo -e "  • Heuristic Gate triggered: CIS-RHEL-9-1.1.2 & NIST-SP800-53-AC-6"
echo -e "  • Signed Air-Gapped Dossier generated in output/dossiers/"
echo -e "\n${GREEN}[✓] Simulation finished successfully! Inspect daemon logs or UI dashboard.${NC}"
