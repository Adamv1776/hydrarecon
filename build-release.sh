#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
# HydraRecon - Build Release Package
# Creates distributable ZIP/TAR files for customers
#═══════════════════════════════════════════════════════════════════════════════

set -e

VERSION="1.0.0"
NAME="hydrarecon"
RELEASE_DIR="releases"
DATE=$(date +%Y%m%d)

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Building HydraRecon v${VERSION} release packages...${NC}"

# Create release directory
mkdir -p "$RELEASE_DIR"

# Clean previous builds
rm -f "$RELEASE_DIR/${NAME}-${VERSION}"*.zip
rm -f "$RELEASE_DIR/${NAME}-${VERSION}"*.tar.gz

# Files to exclude from release
EXCLUDE_PATTERNS=(
    "*.db"
    "*.log"
    "*.pyc"
    "__pycache__"
    ".git"
    ".pytest_cache"
    "venv"
    "env"
    ".env"
    "releases"
    "evidence/*"
    "logs/*"
    ".DS_Store"
    "*.sqlite"
    "build"
    "dist"
    "*.egg-info"
)

# Build exclude string
EXCLUDES=""
for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    EXCLUDES="$EXCLUDES --exclude=$pattern"
done

echo -e "${BLUE}[1/4]${NC} Creating Linux/Mac release (tar.gz)..."
tar czf "$RELEASE_DIR/${NAME}-${VERSION}-linux.tar.gz" \
    $EXCLUDES \
    --transform "s,^,${NAME}-${VERSION}/," \
    .

echo -e "${BLUE}[2/4]${NC} Creating Windows release (zip)..."
# Create temp directory for zip
TEMP_DIR=$(mktemp -d)
mkdir -p "$TEMP_DIR/${NAME}-${VERSION}"

# Copy files (excluding patterns)
rsync -a --exclude-from=<(printf '%s\n' "${EXCLUDE_PATTERNS[@]}") \
    . "$TEMP_DIR/${NAME}-${VERSION}/"

# Create zip
(cd "$TEMP_DIR" && zip -rq "${NAME}-${VERSION}-windows.zip" "${NAME}-${VERSION}")
mv "$TEMP_DIR/${NAME}-${VERSION}-windows.zip" "$RELEASE_DIR/"

# Cleanup
rm -rf "$TEMP_DIR"

echo -e "${BLUE}[3/4]${NC} Creating minimal release (core only)..."
MINIMAL_FILES=(
    "core"
    "gui"
    "scanners"
    "main.py"
    "launcher.py"
    "lite.py"
    "start.sh"
    "install-quick.sh"
    "install-windows.bat"
    "requirements-core.txt"
    "requirements.txt"
    "README.md"
    "INSTALL.md"
    "LICENSE"
    "DISCLAIMER.md"
)

TEMP_DIR=$(mktemp -d)
mkdir -p "$TEMP_DIR/${NAME}-${VERSION}-minimal"

for item in "${MINIMAL_FILES[@]}"; do
    if [ -e "$item" ]; then
        cp -r "$item" "$TEMP_DIR/${NAME}-${VERSION}-minimal/"
    fi
done

(cd "$TEMP_DIR" && tar czf "${NAME}-${VERSION}-minimal.tar.gz" "${NAME}-${VERSION}-minimal")
mv "$TEMP_DIR/${NAME}-${VERSION}-minimal.tar.gz" "$RELEASE_DIR/"
rm -rf "$TEMP_DIR"

echo -e "${BLUE}[4/4]${NC} Generating checksums..."
(cd "$RELEASE_DIR" && sha256sum *.tar.gz *.zip > SHA256SUMS.txt 2>/dev/null)

# Show results
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Release packages created:${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
ls -lh "$RELEASE_DIR"/*.tar.gz "$RELEASE_DIR"/*.zip 2>/dev/null

echo ""
echo -e "${BLUE}Checksums (SHA256):${NC}"
cat "$RELEASE_DIR/SHA256SUMS.txt"

echo ""
echo -e "${GREEN}Done! Packages ready in: ${RELEASE_DIR}/${NC}"
