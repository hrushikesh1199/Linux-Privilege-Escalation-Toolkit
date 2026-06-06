#!/bin/bash
# ============================================================================
#  Linux Privilege Escalation Quick Scan (Bash)
#  Part of: Linux PrivEsc Automation Toolkit
#  Author : Hrushikesh Chaudhari | github.com/hrushikesh1199
# ============================================================================
#
#  Usage:
#    chmod +x scripts/quick_scan.sh
#    sudo bash scripts/quick_scan.sh
#    sudo bash scripts/quick_scan.sh | tee /tmp/scan_output.txt
#
#  This script performs rapid manual enumeration — useful when Python is
#  unavailable or for a quick first-pass audit.
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'  # No Color

OK()  { echo -e "  ${GREEN}[✓]${NC} $*"; }
WARN(){ echo -e "  ${YELLOW}[!]${NC} $*"; }
CRIT(){ echo -e "  ${RED}[✗]${NC} $*"; }
INFO(){ echo -e "  ${CYAN}[*]${NC} $*"; }

divider() {
    echo -e "\n${CYAN}${BOLD}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║  $1${NC}"
    echo -e "${CYAN}${BOLD}╚════════════════════════════════════════════════════╝${NC}"
}

echo -e "${RED}${BOLD}"
cat << 'EOF'
  ╔══════════════════════════════════════════════════╗
  ║   Linux PrivEsc Quick Scan  │  Authorized Use   ║
  ╚══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo -e "  Scan started: $(date)"
echo -e "  ⚠  Run on systems you OWN or have written permission to test.\n"

# ─── 1. SYSTEM INFORMATION ───────────────────────────────────────────────────
divider "1. SYSTEM INFORMATION"
INFO "Hostname   : $(hostname)"
INFO "OS         : $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
INFO "Kernel     : $(uname -r)"
INFO "Full uname : $(uname -a)"
INFO "Current user: $(id)"
INFO "Home dir   : $HOME"
INFO "Groups     : $(groups)"

# ─── 2. SUDO PRIVILEGES ──────────────────────────────────────────────────────
divider "2. SUDO PRIVILEGES (sudo -l)"
SUDO_OUT=$(sudo -l -n 2>/dev/null)
if echo "$SUDO_OUT" | grep -q "NOPASSWD"; then
    CRIT "NOPASSWD sudo rule detected → $(echo "$SUDO_OUT" | grep NOPASSWD)"
    echo -e "      ${YELLOW}Reference: https://gtfobins.github.io${NC}"
elif echo "$SUDO_OUT" | grep -q "(ALL)"; then
    WARN "Broad sudo access → $SUDO_OUT"
else
    INFO "sudo -l output:"
    echo "$SUDO_OUT" | head -20 | sed 's/^/      /'
fi

# ─── 3. SUID BINARIES ────────────────────────────────────────────────────────
divider "3. SUID BINARY SCAN"
INFO "Scanning for SUID binaries (this may take a moment)..."
SUID_BINS=$(find / -perm -4000 -type f 2>/dev/null)
SUID_COUNT=$(echo "$SUID_BINS" | grep -c . 2>/dev/null || echo 0)
INFO "Total SUID binaries: $SUID_COUNT"

# Check against common GTFOBins
DANGEROUS_SUID=(bash sh dash find awk gawk perl python python2 python3 ruby php
                vim vi nano less more nmap wget curl cp mv tee dd tar zip env
                strace gdb node lua ftp mysql git rsync ssh taskset watch)

echo ""
FOUND_DANGEROUS=0
for bin in "${DANGEROUS_SUID[@]}"; do
    match=$(echo "$SUID_BINS" | grep -E "/(usr/bin/|bin/|usr/local/bin/)${bin}$" | head -1)
    if [ -n "$match" ]; then
        CRIT "EXPLOITABLE SUID: $match  → GTFOBins: https://gtfobins.github.io/gtfobins/${bin}/#suid"
        FOUND_DANGEROUS=1
    fi
done
[ "$FOUND_DANGEROUS" -eq 0 ] && OK "No common exploitable SUID binaries found"

echo ""
INFO "All SUID binaries found:"
echo "$SUID_BINS" | sed 's/^/      /'

# ─── 4. FILE PERMISSIONS ─────────────────────────────────────────────────────
divider "4. SENSITIVE FILE PERMISSIONS"

check_file() {
    local file="$1"
    if [ -e "$file" ]; then
        perms=$(stat -c "%a %U %G" "$file" 2>/dev/null)
        if [ -w "$file" ]; then
            CRIT "$file [$perms] → WRITABLE by current user!"
        elif [ -r "$file" ] && [[ "$file" == *"shadow"* ]]; then
            WARN "$file [$perms] → Readable (sensitive!)"
        else
            OK "$file [$perms]"
        fi
    fi
}

SENSITIVE_FILES=(
    /etc/passwd /etc/shadow /etc/sudoers
    /etc/crontab /etc/ssh/sshd_config
    /root/.bashrc /root/.ssh/authorized_keys
)

for f in "${SENSITIVE_FILES[@]}"; do
    check_file "$f"
done

echo ""
INFO "Scanning world-writable files in system paths..."
WW_SYS=$(find /etc /usr /bin /sbin /opt -writable -type f 2>/dev/null | head -20)
if [ -n "$WW_SYS" ]; then
    CRIT "World-writable files in system paths:"
    echo "$WW_SYS" | sed 's/^/      /'
else
    OK "No writable files in critical system paths"
fi

# ─── 5. PATH ANALYSIS ────────────────────────────────────────────────────────
divider "5. PATH HIJACKING CHECK"
INFO "PATH = $PATH"
echo ""
for p in $(echo $PATH | tr ':' ' '); do
    if [ -d "$p" ] && [ -w "$p" ]; then
        CRIT "WRITABLE PATH DIR: $p → PATH Hijacking possible!"
    else
        OK "$p (not writable)"
    fi
done

echo ""
if [ -n "$LD_PRELOAD" ]; then
    CRIT "LD_PRELOAD is set: $LD_PRELOAD → .so injection risk!"
fi
if [ -n "$LD_LIBRARY_PATH" ]; then
    WARN "LD_LIBRARY_PATH set: $LD_LIBRARY_PATH"
fi

# ─── 6. CRON JOBS ────────────────────────────────────────────────────────────
divider "6. CRON JOB ANALYSIS"
INFO "System crontab (/etc/crontab):"
cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$' | sed 's/^/      /'

echo ""
INFO "Cron.d entries:"
cat /etc/cron.d/* 2>/dev/null | grep -v '^#' | grep -v '^$' | sed 's/^/      /'

echo ""
INFO "Scripts in cron directories:"
for crondir in /etc/cron.{daily,hourly,monthly,weekly}; do
    [ -d "$crondir" ] && ls -la "$crondir" 2>/dev/null | sed "s/^/  $crondir: /"
done

echo ""
INFO "Checking for writable cron scripts..."
WRITABLE_CRON=$(find /etc/cron* -writable -type f 2>/dev/null)
if [ -n "$WRITABLE_CRON" ]; then
    CRIT "Writable cron scripts found:"
    echo "$WRITABLE_CRON" | sed 's/^/      /'
else
    OK "No writable cron scripts detected"
fi

# ─── 7. SERVICES ─────────────────────────────────────────────────────────────
divider "7. SERVICE ANALYSIS"
INFO "Services running as root:"
ps aux 2>/dev/null | awk 'NR==1{print}; /^root/{print}' | grep -v grep | head -20 | sed 's/^/      /'

echo ""
INFO "Checking systemd service files for misconfigurations..."
find /etc/systemd/system /lib/systemd/system -name "*.service" 2>/dev/null | while read sf; do
    exec_start=$(grep "^ExecStart=" "$sf" 2>/dev/null | head -1 | cut -d= -f2-)
    user=$(grep "^User=" "$sf" 2>/dev/null | cut -d= -f2)
    if [ -z "$user" ] || [ "$user" = "root" ]; then
        bin=$(echo "$exec_start" | sed 's/^[-+@!]*//' | awk '{print $1}')
        if [ -n "$bin" ] && [ -f "$bin" ] && [ -w "$bin" ]; then
            CRIT "Root service with writable binary: $sf → $bin"
        fi
    fi
done
OK "Service file scan complete"

# ─── 8. KERNEL INFO ──────────────────────────────────────────────────────────
divider "8. KERNEL INFORMATION"
INFO "Kernel : $(uname -r)"
INFO "Arch   : $(uname -m)"
INFO "Full   : $(uname -a)"
echo ""
WARN "Manually check kernel CVEs at:"
echo -e "      ${CYAN}→ https://www.linuxkernelcves.com${NC}"
echo -e "      ${CYAN}→ https://nvd.nist.gov/vuln/search?query=linux+kernel&results_type=overview${NC}"
echo -e "      ${CYAN}→ https://www.exploit-db.com/search?q=linux+kernel+privilege+escalation${NC}"

# ─── 9. LINUX CAPABILITIES ───────────────────────────────────────────────────
divider "9. LINUX CAPABILITIES"
INFO "Scanning Linux capabilities..."
CAPS=$(getcap -r / 2>/dev/null)
if [ -n "$CAPS" ]; then
    WARN "Linux capabilities found:"
    echo "$CAPS" | sed 's/^/      /'
    echo ""
    echo -e "      ${CYAN}Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities${NC}"
else
    OK "No special Linux capabilities detected"
fi

# ─── 10. NETWORK ─────────────────────────────────────────────────────────────
divider "10. NETWORK INFORMATION"
INFO "IP Addresses:"
ip addr show 2>/dev/null | grep 'inet ' | awk '{print "      "$2}' || ifconfig 2>/dev/null | grep 'inet ' | awk '{print "      "$2}'
echo ""
INFO "Listening services:"
ss -tlnp 2>/dev/null | head -20 | sed 's/^/      /' || netstat -tlnp 2>/dev/null | head -20 | sed 's/^/      /'

# ─── SUMMARY ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════╗"
echo    "║            QUICK SCAN COMPLETE                   ║"
echo    "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo    "  Next steps:"
echo -e "  ${CYAN}1.${NC} Run full Python toolkit: sudo python3 privesc_toolkit.py"
echo -e "  ${CYAN}2.${NC} Review exported report in ./reports/"
echo -e "  ${CYAN}3.${NC} Cross-reference: https://gtfobins.github.io"
echo -e "  ${CYAN}4.${NC} Kernel CVEs   : https://linuxkernelcves.com"
echo -e "  ${CYAN}5.${NC} HackTricks    : https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
echo ""
echo -e "  ${YELLOW}⚠  Use findings only for authorized security testing.${NC}"
echo    "  Scan finished: $(date)"