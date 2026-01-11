#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
# HydraRecon - Professional Security Assessment Suite
# Start Script - Production Launch with Health Checks
#═══════════════════════════════════════════════════════════════════════════════

set -e

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "${CYAN}"
echo "======================================================================="
echo "   _   ___   ______  ____   ___   ____  _____ ____  ___  "
echo "  | | | \ \ / /  _ \|  _ \ / _ \ |  _ \| ____/ ___|/ _ \ "
echo "  | |_| |\ V /| | | | |_) | |_| || |_) |  _|| |   | | | |"
echo "  |  _  | | | | |_| |  _ <|  _  ||  _ <| |__| |___| |_| |"
echo "  |_| |_| |_| |____/|_| \_\_| |_||_| \_\_____\____|\___/ "
echo ""
echo "           Enterprise Security Assessment Suite v1.0"
echo "======================================================================="
echo -e "${NC}"

# Parse arguments
MODE="full"
while [[ $# -gt 0 ]]; do
    case $1 in
        --lite)
            MODE="lite"
            shift
            ;;
        --check)
            MODE="check"
            shift
            ;;
        --help|-h)
            echo -e "${GREEN}Usage:${NC} $0 [options]"
            echo ""
            echo "Options:"
            echo "  --lite    Launch in lite mode (faster startup, core features only)"
            echo "  --check   Run health check only, don't start the app"
            echo "  --help    Show this help message"
            echo ""
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Check Python version
echo -e "${BLUE}[1/4]${NC} Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 10 ]]; then
    echo -e "${RED}✗ Python 3.10+ required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python $PYTHON_VERSION${NC}"

# Check memory
echo -e "${BLUE}[2/4]${NC} Checking available memory..."
if command -v free &> /dev/null; then
    AVAILABLE_MB=$(free -m | awk '/^Mem:/ {print $7}')
    if [[ $AVAILABLE_MB -lt 500 ]]; then
        echo -e "${RED}✗ Insufficient memory: ${AVAILABLE_MB}MB available (500MB+ required)${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ ${AVAILABLE_MB}MB available${NC}"
else
    echo -e "${YELLOW}⚠ Cannot check memory (free command not available)${NC}"
fi

# Check display
echo -e "${BLUE}[3/4]${NC} Checking display..."
if [[ -z "$DISPLAY" ]] && [[ -z "$WAYLAND_DISPLAY" ]]; then
    echo -e "${RED}✗ No display available. Set DISPLAY or WAYLAND_DISPLAY.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Display available${NC}"

# Check PyQt6
echo -e "${BLUE}[4/4]${NC} Checking PyQt6..."
if ! python3 -c "import PyQt6.QtWidgets" 2>/dev/null; then
    echo -e "${RED}✗ PyQt6 not installed. Run: pip install PyQt6${NC}"
    exit 1
fi
QT_VERSION=$(python3 -c "from PyQt6.QtCore import QT_VERSION_STR; print(QT_VERSION_STR)" 2>/dev/null)
echo -e "${GREEN}✓ PyQt6 (Qt $QT_VERSION)${NC}"

echo ""

# Launch based on mode
case $MODE in
    check)
        echo -e "${GREEN}✓ All checks passed!${NC}"
        exit 0
        ;;
    lite)
        echo -e "${CYAN}Launching HydraRecon in LITE mode...${NC}"
        exec python3 lite.py "$@"
        ;;
    full)
        echo -e "${CYAN}Launching HydraRecon...${NC}"
        exec python3 launcher.py "$@"
        ;;
esac
