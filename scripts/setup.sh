#!/bin/bash
# ============================================================================
#  Setup Script – Linux PrivEsc Automation Toolkit
#  Author: Hrushikesh Chaudhari | github.com/hrushikesh1199
# ============================================================================

GREEN='\033[0;32m' YELLOW='\033[1;33m' CYAN='\033[0;36m' RED='\033[0;31m' NC='\033[0m'
OK()  { echo -e "${GREEN}[✓]${NC} $*"; }
WARN(){ echo -e "${YELLOW}[!]${NC} $*"; }
INFO(){ echo -e "${CYAN}[*]${NC} $*"; }
FAIL(){ echo -e "${RED}[✗]${NC} $*"; }

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║   Linux PrivEsc Toolkit - Setup                 ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python 3
INFO "Checking Python 3..."
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1)
    OK "Found: $PY_VER"
else
    FAIL "Python 3 not found. Install: sudo apt install python3"
    exit 1
fi

# Check pip
INFO "Checking pip..."
if command -v pip3 &>/dev/null; then
    OK "pip3 found"
else
    WARN "pip3 not found. Installing..."
    sudo apt-get install python3-pip -y 2>/dev/null || true
fi

# Install Python dependencies
INFO "Installing Python dependencies..."
pip3 install -r requirements.txt --quiet 2>/dev/null || \
    pip3 install colorama tabulate requests 2>/dev/null || true
OK "Dependencies installed"

# Create directories
INFO "Creating directory structure..."
mkdir -p reports tests assets docs
OK "Directories created"

# Set permissions
INFO "Setting file permissions..."
chmod +x privesc_toolkit.py
chmod +x scripts/quick_scan.sh
OK "Permissions set"

# Check system tools
INFO "Checking required system tools..."
TOOLS=(find ls stat grep awk sed uname hostname id whoami ps ss getcap sudo)
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        OK "$tool → $(which $tool)"
    else
        WARN "$tool not found (some checks may be incomplete)"
    fi
done

# Summary
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗"
echo    "║  Setup Complete! Run the toolkit with:              ║"
echo    "║                                                      ║"
echo    "║   sudo python3 privesc_toolkit.py                   ║"
echo    "║   sudo bash scripts/quick_scan.sh                   ║"
echo    "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"