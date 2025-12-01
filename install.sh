#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
#  ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
#  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
#  ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
#  ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
#  ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
#  ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
#  Enterprise Security Assessment Suite - Desktop Installer
#═══════════════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Installation paths
INSTALL_DIR="$HOME/.local/share/hydrarecon"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  ⚡ HydraRecon Enterprise Security Suite - Installer"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Function to print status
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check if running as root (not recommended)
if [ "$EUID" -eq 0 ]; then
    print_warning "Running as root is not recommended. Installing for current user instead."
fi

echo -e "\n${BOLD}Step 1: Checking dependencies...${NC}\n"

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    print_status "Python 3 found: $PYTHON_VERSION"
else
    print_error "Python 3 not found. Please install Python 3.10 or later."
    exit 1
fi

# Check pip
if command -v pip3 &> /dev/null; then
    print_status "pip3 found"
else
    print_warning "pip3 not found. Installing..."
    sudo apt-get install -y python3-pip
fi

# Check and install system dependencies
echo -e "\n${BOLD}Step 2: Installing system dependencies...${NC}\n"

DEPS_TO_INSTALL=""

# Check nmap
if ! command -v nmap &> /dev/null; then
    DEPS_TO_INSTALL="$DEPS_TO_INSTALL nmap"
    print_warning "nmap not found - will install"
else
    print_status "nmap found: $(nmap --version | head -1)"
fi

# Check hydra
if ! command -v hydra &> /dev/null; then
    DEPS_TO_INSTALL="$DEPS_TO_INSTALL hydra"
    print_warning "hydra not found - will install"
else
    print_status "hydra found: $(hydra -h 2>&1 | head -1)"
fi

# Check whois
if ! command -v whois &> /dev/null; then
    DEPS_TO_INSTALL="$DEPS_TO_INSTALL whois"
fi

# Check dig (dnsutils)
if ! command -v dig &> /dev/null; then
    DEPS_TO_INSTALL="$DEPS_TO_INSTALL dnsutils"
fi

# Install missing system dependencies
if [ -n "$DEPS_TO_INSTALL" ]; then
    print_info "Installing system packages:$DEPS_TO_INSTALL"
    sudo apt-get update
    sudo apt-get install -y $DEPS_TO_INSTALL
    print_status "System dependencies installed"
else
    print_status "All system dependencies satisfied"
fi

echo -e "\n${BOLD}Step 3: Setting up Python virtual environment...${NC}\n"

# Create virtual environment
VENV_DIR="$INSTALL_DIR/venv"
print_info "Creating virtual environment..."

# Create install dir first
mkdir -p "$INSTALL_DIR"

# Create venv
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Install Python dependencies in venv
print_info "Installing Python packages in virtual environment..."
pip install --upgrade pip
pip install PyQt6 cryptography pyyaml aiohttp dnspython python-whois requests beautifulsoup4 python-nmap

print_status "Python packages installed"

echo -e "\n${BOLD}Step 4: Setting up application...${NC}\n"

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"
mkdir -p "$DESKTOP_DIR"
mkdir -p "$ICON_DIR"

# Copy application files
print_info "Copying application files..."
cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
print_status "Application files copied to $INSTALL_DIR"

# Create launcher script
cat > "$BIN_DIR/hydrarecon" << 'LAUNCHER'
#!/bin/bash
source "$HOME/.local/share/hydrarecon/venv/bin/activate"
cd "$HOME/.local/share/hydrarecon"
python main.py "$@"
LAUNCHER

chmod +x "$BIN_DIR/hydrarecon"
print_status "Launcher script created"

# Create desktop entry
cat > "$DESKTOP_DIR/hydrarecon.desktop" << DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=HydraRecon
GenericName=Security Assessment Suite
Comment=Enterprise Penetration Testing & OSINT Platform
Exec=$BIN_DIR/hydrarecon
Icon=hydrarecon
Terminal=false
Categories=Security;Network;System;
Keywords=security;pentest;nmap;hydra;osint;hacking;
StartupWMClass=HydraRecon
StartupNotify=true
DESKTOP

chmod +x "$DESKTOP_DIR/hydrarecon.desktop"
print_status "Desktop entry created"

# Create icon (SVG)
cat > "$ICON_DIR/hydrarecon.svg" << 'ICON'
<?xml version="1.0" encoding="UTF-8"?>
<svg width="256" height="256" viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0d1117"/>
      <stop offset="100%" style="stop-color:#161b22"/>
    </linearGradient>
    <linearGradient id="glowGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#00ff88"/>
      <stop offset="100%" style="stop-color:#0088ff"/>
    </linearGradient>
    <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
      <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
      <feMerge>
        <feMergeNode in="coloredBlur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>
  
  <!-- Background circle -->
  <circle cx="128" cy="128" r="120" fill="url(#bgGrad)" stroke="#21262d" stroke-width="4"/>
  
  <!-- Inner ring -->
  <circle cx="128" cy="128" r="100" fill="none" stroke="#21262d" stroke-width="2"/>
  
  <!-- Shield outline -->
  <path d="M128 40 L200 70 L200 130 C200 170 170 210 128 230 C86 210 56 170 56 130 L56 70 Z" 
        fill="none" stroke="url(#glowGrad)" stroke-width="4" filter="url(#glow)"/>
  
  <!-- Lock body -->
  <rect x="98" y="115" width="60" height="50" rx="8" fill="url(#glowGrad)" filter="url(#glow)"/>
  
  <!-- Lock shackle -->
  <path d="M108 115 L108 95 C108 75 148 75 148 95 L148 115" 
        fill="none" stroke="url(#glowGrad)" stroke-width="8" stroke-linecap="round" filter="url(#glow)"/>
  
  <!-- Keyhole -->
  <circle cx="128" cy="135" r="8" fill="#0d1117"/>
  <rect x="124" y="135" width="8" height="18" fill="#0d1117"/>
  
  <!-- Lightning bolts -->
  <path d="M70 80 L85 100 L75 100 L90 125 L78 105 L88 105 Z" fill="#00ff88" filter="url(#glow)"/>
  <path d="M186 80 L171 100 L181 100 L166 125 L178 105 L168 105 Z" fill="#0088ff" filter="url(#glow)"/>
  
  <!-- Scan lines -->
  <line x1="80" y1="180" x2="100" y2="180" stroke="#00ff88" stroke-width="3" stroke-linecap="round" filter="url(#glow)"/>
  <line x1="110" y1="180" x2="146" y2="180" stroke="#00ff88" stroke-width="3" stroke-linecap="round" filter="url(#glow)"/>
  <line x1="156" y1="180" x2="176" y2="180" stroke="#00ff88" stroke-width="3" stroke-linecap="round" filter="url(#glow)"/>
  
  <line x1="90" y1="195" x2="120" y2="195" stroke="#0088ff" stroke-width="3" stroke-linecap="round" filter="url(#glow)"/>
  <line x1="130" y1="195" x2="166" y2="195" stroke="#0088ff" stroke-width="3" stroke-linecap="round" filter="url(#glow)"/>
</svg>
ICON

print_status "Application icon created"

# Update icon cache
if command -v gtk-update-icon-cache &> /dev/null; then
    gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
fi

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi

# Add to PATH if not already
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "" >> "$HOME/.bashrc"
    echo "# HydraRecon" >> "$HOME/.bashrc"
    echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$HOME/.bashrc"
    
    if [ -f "$HOME/.zshrc" ]; then
        echo "" >> "$HOME/.zshrc"
        echo "# HydraRecon" >> "$HOME/.zshrc"
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$HOME/.zshrc"
    fi
    print_status "Added to PATH"
fi

echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}"
echo "  ✅ HydraRecon installed successfully!"
echo -e "${NC}"
echo -e "  ${BOLD}Launch options:${NC}"
echo -e "    • From terminal:  ${CYAN}hydrarecon${NC}"
echo -e "    • From desktop:   Look for ${CYAN}HydraRecon${NC} in your application menu"
echo -e "    • Direct:         ${CYAN}$BIN_DIR/hydrarecon${NC}"
echo ""
echo -e "  ${BOLD}Installation location:${NC} $INSTALL_DIR"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Offer to launch
read -p "Would you like to launch HydraRecon now? [Y/n] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    print_info "Launching HydraRecon..."
    "$BIN_DIR/hydrarecon" &
fi

exit 0
