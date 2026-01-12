# 🚀 HydraRecon - Installation Guide

## ⬇️ Quick Download

**GitHub Repository**: https://github.com/Adamv1776/hydrarecon

---

## One-Line Installation

### 🐧 Linux / 🍎 macOS
```bash
git clone https://github.com/Adamv1776/hydrarecon.git && cd hydrarecon && chmod +x install-quick.sh && ./install-quick.sh
```

### 🪟 Windows
1. **[Download ZIP](https://github.com/Adamv1776/hydrarecon/archive/refs/heads/main.zip)**
2. Extract to a folder (e.g., `C:\HydraRecon`)
3. Double-click `install-windows.bat`
4. A desktop shortcut will be created automatically!

---

## Installation Methods

### Method 1: Quick Install (Recommended) ⭐
```bash
# Clone repository
git clone https://github.com/Adamv1776/hydrarecon.git
cd hydrarecon

# Make installer executable and run
chmod +x install-quick.sh
./install-quick.sh

# A desktop shortcut is created automatically!
# Or start manually:
./start.sh
```

### Method 2: Manual Install
```bash
# Clone
git clone https://github.com/Adamv1776/hydrarecon.git
cd hydrarecon

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install PyQt6 pyserial requests dnspython aiohttp numpy

# Run
python3 launcher.py
```

### Method 3: Docker
```bash
git clone https://github.com/Adamv1776/hydrarecon.git
cd hydrarecon
docker-compose up -d
```

---

## ▶️ Running HydraRecon

After installation:

**Linux/macOS:**
- Double-click the **HydraRecon** icon on your Desktop
- Or run: `cd hydrarecon && source venv/bin/activate && python launcher.py`

**Windows:**
- Double-click the **HydraRecon** shortcut on your Desktop
- Or run: `start.bat`

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
- **Git** - [Download](https://git-scm.com)

### Optional Software (for full functionality)
- **Nmap** - Network scanner (`apt install nmap`)
- **Hydra** - Password cracker (`apt install hydra`)
- **Shodan API key** - Enhanced OSINT
- **ESP32** - For drone detection feature

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
