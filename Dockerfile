# ═══════════════════════════════════════════════════════════════════════════════
#  HydraRecon - Docker Container
# ═══════════════════════════════════════════════════════════════════════════════

FROM python:3.12-slim

LABEL maintainer="HydraRecon Team <support@hydrarecon.io>"
LABEL version="1.0.0"
LABEL description="Enterprise Security Assessment Suite"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libxcb-cursor0 \
    libxkbcommon0 \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libdbus-1-3 \
    libxcb-xinerama0 \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-randr0 \
    libxcb-render-util0 \
    libxcb-shape0 \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements-core.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements-core.txt

# Copy application
COPY . .

# Create non-root user for security
RUN useradd -m -s /bin/bash hydra && \
    chown -R hydra:hydra /app

USER hydra

# Expose any necessary ports
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "from core import Config; print('OK')" || exit 1

# Default command
ENTRYPOINT ["python3", "launcher.py"]
