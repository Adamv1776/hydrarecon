#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
#  _   ___   ______  ____   ___   ____  _____ ____  ___  
# | | | \ \ / /  _ \|  _ \ / _ \ |  _ \| ____/ ___|/ _ \ 
# | |_| |\ V /| | | | |_) | |_| || |_) |  _|| |   | | | |
# |  _  | | | | |_| |  _ <|  _  ||  _ <| |__| |___| |_| |
# |_| |_| |_| |____/|_| \_\_| |_||_| \_\_____\____|\___/ 
#
#  Enterprise Security Assessment Suite - Quick Installer
#═══════════════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "${CYAN}"
echo "═══════════════════════════════════════════════════════════════════"
echo "         HydraRecon Enterprise - Quick Installer"
echo "═══════════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="redhat"
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
    else
        DISTRO="other"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
fi

echo -e "${BLUE}Detected OS:${NC} $OS"

# Check Python version
echo -e "\n${BLUE}[1/5]${NC} Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python3 not found. Please install Python 3.10+${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 10 ]]; then
    echo -e "${RED}✗ Python 3.10+ required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python $PYTHON_VERSION${NC}"

# Install system dependencies
echo -e "\n${BLUE}[2/5]${NC} Installing system dependencies..."
if [[ "$OS" == "linux" ]]; then
    if [[ "$DISTRO" == "debian" ]]; then
        echo -e "${YELLOW}Installing Qt6 and Nmap (may require sudo)...${NC}"
        sudo apt-get update -qq
        sudo apt-get install -y -qq python3-pyqt6 nmap libxcb-cursor0 2>/dev/null || true
    elif [[ "$DISTRO" == "arch" ]]; then
        sudo pacman -S --noconfirm --needed python-pyqt6 nmap 2>/dev/null || true
    elif [[ "$DISTRO" == "redhat" ]]; then
        sudo dnf install -y python3-qt6 nmap 2>/dev/null || true
    fi
elif [[ "$OS" == "macos" ]]; then
    if command -v brew &> /dev/null; then
        brew install nmap pyqt@6 2>/dev/null || true
    fi
fi
echo -e "${GREEN}✓ System dependencies checked${NC}"

# Create virtual environment (optional but recommended)
echo -e "\n${BLUE}[3/5]${NC} Setting up Python environment..."
if [[ ! -d "venv" ]]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv --system-site-packages 2>/dev/null || python3 -m venv venv
fi

# Activate venv
if [[ -f "venv/bin/activate" ]]; then
    source venv/bin/activate
    echo -e "${GREEN}✓ Virtual environment activated${NC}"
else
    echo -e "${YELLOW}⚠ Using system Python${NC}"
fi

# Install Python dependencies
echo -e "\n${BLUE}[4/5]${NC} Installing Python dependencies..."
pip install --upgrade pip -q

# Core dependencies
pip install -q PyQt6 PyQt6-WebEngine 2>/dev/null || pip install -q --break-system-packages PyQt6 PyQt6-WebEngine
pip install -q -r requirements.txt 2>/dev/null || pip install -q --break-system-packages -r requirements.txt

echo -e "${GREEN}✓ Python dependencies installed${NC}"

# Create desktop entry (Linux)
echo -e "\n${BLUE}[5/5]${NC} Creating shortcuts..."
INSTALL_DIR="$(pwd)"

if [[ "$OS" == "linux" ]]; then
    # Create applications menu entry
    DESKTOP_DIR="${HOME}/.local/share/applications"
    mkdir -p "$DESKTOP_DIR"
    
    cat > "$DESKTOP_DIR/hydrarecon.desktop" << EOF
[Desktop Entry]
Version=2.0
Type=Application
Name=HydraRecon
Comment=Enterprise Security Assessment Suite
Exec=${INSTALL_DIR}/launch.sh
Icon=${INSTALL_DIR}/gui/icons/hydrarecon.png
Terminal=false
Categories=Security;Network;System;
Keywords=security;pentest;hacking;scanner;drone;esp32;
StartupWMClass=HydraRecon
EOF
    chmod +x "$DESKTOP_DIR/hydrarecon.desktop"
    echo -e "${GREEN}✓ Applications menu entry created${NC}"
    
    # Create Desktop shortcut
    if [[ -d "${HOME}/Desktop" ]]; then
        DESKTOP_SHORTCUT="${HOME}/Desktop/HydraRecon.desktop"
        cat > "$DESKTOP_SHORTCUT" << EOF
[Desktop Entry]
Version=2.0
Type=Application
Name=HydraRecon
Comment=Enterprise Security Assessment Suite - Click to Launch!
Exec=${INSTALL_DIR}/launch.sh
Icon=${INSTALL_DIR}/gui/icons/hydrarecon.png
Terminal=false
Categories=Security;Network;System;
Keywords=security;pentest;hacking;scanner;drone;esp32;
StartupWMClass=HydraRecon
EOF
        chmod +x "$DESKTOP_SHORTCUT"
        # Mark as trusted on GNOME/Ubuntu
        gio set "$DESKTOP_SHORTCUT" metadata::trusted true 2>/dev/null || true
        echo -e "${GREEN}✓ Desktop shortcut created on Desktop!${NC}"
    fi
    
    # Update desktop database
    update-desktop-database "${DESKTOP_DIR}" 2>/dev/null || true
    
elif [[ "$OS" == "macos" ]]; then
    # Create macOS Application alias on Desktop
    if [[ -d "${HOME}/Desktop" ]]; then
        cat > "${HOME}/Desktop/HydraRecon.command" << EOF
#!/bin/bash
cd "${INSTALL_DIR}"
source venv/bin/activate 2>/dev/null || true
python3 launcher.py
EOF
        chmod +x "${HOME}/Desktop/HydraRecon.command"
        echo -e "${GREEN}✓ Desktop shortcut created (HydraRecon.command)${NC}"
    fi
fi

# Make scripts executable
chmod +x start.sh launcher.py lite.py main.py 2>/dev/null || true

# Done!
echo -e "\n${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ HydraRecon installed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}To start HydraRecon:${NC}"
echo -e "  ${YELLOW}./start.sh${NC}          - Full mode with health checks"
echo -e "  ${YELLOW}./start.sh --lite${NC}   - Lite mode (faster startup)"
echo -e "  ${YELLOW}python3 launcher.py${NC} - Direct Python launch"
echo ""
echo -e "${CYAN}First launch notes:${NC}"
echo -e "  • You must accept the license agreement on first run"
echo -e "  • Some features require root/sudo for network scanning"
echo -e "  • Configure API keys in Settings for full OSINT capabilities"
echo ""
