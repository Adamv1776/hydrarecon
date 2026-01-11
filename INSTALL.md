# 🚀 HydraRecon - Quick Start Guide

## One-Line Installation

### Linux / macOS
```bash
curl -sSL https://hydrarecon.io/install.sh | bash
```

Or manually:
```bash
git clone https://github.com/hydrarecon/hydrarecon.git
cd hydrarecon
./install-quick.sh
```

### Windows
1. Download the [Windows Installer](https://hydrarecon.io/download/hydrarecon-windows.zip)
2. Extract the ZIP file
3. Double-click `install-windows.bat`
4. Run `start.bat`

---

## Installation Methods

### Method 1: Quick Install (Recommended)
```bash
# Clone repository
git clone https://github.com/hydrarecon/hydrarecon.git
cd hydrarecon

# Run installer
./install-quick.sh

# Start
./start.sh
```

### Method 2: pip Install
```bash
pip install hydrarecon
hydrarecon-gui
```

### Method 3: Manual Install
```bash
# Clone
git clone https://github.com/hydrarecon/hydrarecon.git
cd hydrarecon

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements-core.txt

# Run
python3 launcher.py
```

### Method 4: Docker
```bash
docker pull hydrarecon/hydrarecon:latest
docker run -it --net=host -e DISPLAY=$DISPLAY hydrarecon/hydrarecon
```

### Method 5: Make
```bash
git clone https://github.com/hydrarecon/hydrarecon.git
cd hydrarecon
make install
make run
```

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Linux, macOS, Windows 10+ | Kali Linux, Ubuntu 22.04+ |
| Python | 3.10 | 3.12+ |
| RAM | 2 GB | 8 GB+ |
| Storage | 500 MB | 2 GB |
| Display | 1280x720 | 1920x1080 |

### Required Software
- **Python 3.10+** - [Download](https://python.org)
- **Nmap** - Network scanner (included in Kali)
- **Qt6** - GUI framework (installed automatically)

### Optional Software
- **Shodan API key** - Enhanced OSINT
- **Censys API key** - Certificate search
- **VirusTotal API** - Malware analysis

---

## First Run

1. **Accept License** - Required on first launch
2. **Configure API Keys** - Settings → API Configuration
3. **Run Health Check** - `./start.sh --check`

### Launch Options
```bash
./start.sh              # Full mode (all features)
./start.sh --lite       # Lite mode (fast startup)
./start.sh --check      # Health check only
python3 launcher.py     # Direct Python launch
```

---

## Troubleshooting

### "PyQt6 not found"
```bash
pip install PyQt6 PyQt6-WebEngine
```

### "Permission denied"
```bash
chmod +x start.sh launcher.py
```

### "Display not found"
```bash
export DISPLAY=:0  # or :1
```

### Slow startup?
Use lite mode: `./start.sh --lite`

---

## Uninstall

```bash
# Remove virtual environment
rm -rf venv

# Remove config
rm -rf ~/.hydrarecon

# Remove application
cd .. && rm -rf hydrarecon
```

---

## Support

- 📖 **Documentation**: [docs.hydrarecon.io](https://docs.hydrarecon.io)
- 💬 **Discord**: [discord.gg/hydrarecon](https://discord.gg/hydrarecon)
- 📧 **Email**: support@hydrarecon.io
- 🐛 **Issues**: [GitHub Issues](https://github.com/hydrarecon/hydrarecon/issues)

---

**⚠️ Legal Notice**: HydraRecon is for authorized security testing only. 
Always obtain written permission before testing any systems.
