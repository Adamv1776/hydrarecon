# ═══════════════════════════════════════════════════════════════════════════════
#  HydraRecon - Enterprise Security Assessment Suite
#  Makefile for Installation & Management
# ═══════════════════════════════════════════════════════════════════════════════

.PHONY: help install install-full install-dev clean run run-lite test check

# Default target
help:
	@echo ""
	@echo "╔═══════════════════════════════════════════════════════════════════╗"
	@echo "║              HydraRecon - Installation Commands                   ║"
	@echo "╚═══════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "  make install      - Quick install (core features)"
	@echo "  make install-full - Full install (all features)"
	@echo "  make install-dev  - Development install (with tests)"
	@echo ""
	@echo "  make run          - Launch HydraRecon"
	@echo "  make run-lite     - Launch in lite mode"
	@echo "  make check        - System health check"
	@echo "  make test         - Run test suite"
	@echo ""
	@echo "  make clean        - Remove cache files"
	@echo "  make uninstall    - Remove virtual environment"
	@echo ""

# Install core dependencies
install:
	@echo "Installing HydraRecon (core)..."
	@python3 -m pip install --upgrade pip
	@python3 -m pip install -r requirements-core.txt
	@chmod +x start.sh launcher.py lite.py 2>/dev/null || true
	@echo "✓ Installation complete! Run: ./start.sh"

# Install all dependencies
install-full:
	@echo "Installing HydraRecon (full)..."
	@python3 -m pip install --upgrade pip
	@python3 -m pip install -r requirements-full.txt
	@chmod +x start.sh launcher.py lite.py 2>/dev/null || true
	@echo "✓ Full installation complete! Run: ./start.sh"

# Install with development tools
install-dev: install-full
	@echo "Installing development dependencies..."
	@python3 -m pip install pytest pytest-asyncio black flake8 mypy
	@echo "✓ Development environment ready!"

# Create virtual environment and install
venv:
	@echo "Creating virtual environment..."
	@python3 -m venv venv --system-site-packages 2>/dev/null || python3 -m venv venv
	@. venv/bin/activate && pip install --upgrade pip
	@. venv/bin/activate && pip install -r requirements-core.txt
	@echo "✓ Virtual environment created! Activate with: source venv/bin/activate"

# Run the application
run:
	@./start.sh

# Run in lite mode
run-lite:
	@./start.sh --lite

# Health check
check:
	@./start.sh --check

# Run tests
test:
	@python3 -m pytest tests/ -v

# Clean cache files
clean:
	@echo "Cleaning cache files..."
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@find . -type f -name ".DS_Store" -delete 2>/dev/null || true
	@echo "✓ Cleaned!"

# Remove virtual environment
uninstall:
	@echo "Removing virtual environment..."
	@rm -rf venv
	@echo "✓ Virtual environment removed"

# Build distribution package
dist:
	@echo "Building distribution package..."
	@python3 -m pip install build
	@python3 -m build
	@echo "✓ Package built in dist/"

# Docker build (if Dockerfile exists)
docker:
	@echo "Building Docker image..."
	@docker build -t hydrarecon:latest .
	@echo "✓ Docker image built!"
