# HydraRecon - Enterprise Security Assessment Suite

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                   ║
║   ⚡ HYDRARECON v2.0                                                              ║
║   Enterprise Security Assessment Suite                                            ║
║                                                                                   ║
║   ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ║
║   ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ║
║   ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║██████╔╝█████╗  ██║     ██║   ██║██╔██╗║
║   ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║██╔══██╗██╔══╝  ██║     ██║   ██║██║ ╚╝║
║   ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝██║   ║
║   ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝   ║
║                                                                                   ║
║   Professional Penetration Testing • OSINT • Vulnerability Assessment             ║
║                                                                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
```

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-00ff88?style=for-the-badge&logo=security" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.10+-0088ff?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/PyQt6-6.6+-a855f7?style=for-the-badge&logo=qt" alt="PyQt6">
  <img src="https://img.shields.io/badge/License-Commercial-ff8800?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Lines-408K+-00d4ff?style=for-the-badge" alt="Lines of Code">
  <img src="https://img.shields.io/badge/ESP32-Supported-green?style=for-the-badge&logo=espressif" alt="ESP32">
</p>

<p align="center">
  <b>⚠️ FOR AUTHORIZED SECURITY TESTING ONLY ⚠️</b>
</p>

---

## 🚨 Important Legal Notice

**READ BEFORE USE**: This software is designed **EXCLUSIVELY** for:
- ✅ Authorized penetration testing with written permission
- ✅ Security assessments of systems you own or are authorized to test
- ✅ Educational research in controlled environments
- ✅ Bug bounty programs with defined scope
- ✅ Compliance auditing (PCI-DSS, HIPAA, SOC2, ISO 27001)

**❌ UNAUTHORIZED USE IS A CRIMINAL OFFENSE** that may result in prosecution.

See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md) for full terms.

---

## ⬇️ Quick Download & Install

### 🐧 Linux / 🍎 macOS (One Command!)
```bash
git clone https://github.com/Adamv1776/hydrarecon.git && cd hydrarecon && chmod +x install-quick.sh && ./install-quick.sh
```
**After install, double-click the HydraRecon icon on your Desktop!**

### 🪟 Windows
1. **[Download ZIP](https://github.com/Adamv1776/hydrarecon/archive/refs/heads/main.zip)**
2. Extract the ZIP file
3. Double-click `install-windows.bat`
4. Double-click the **HydraRecon** shortcut on your Desktop!

### 📦 Alternative Methods
| Method | Instructions |
|--------|--------------|
| **Git Clone** | `git clone https://github.com/Adamv1776/hydrarecon.git` |
| **Download ZIP** | [Click here to download](https://github.com/Adamv1776/hydrarecon/archive/refs/heads/main.zip) |
| **Docker** | `docker-compose up -d` (after cloning) |

### ▶️ Running HydraRecon
After installation, you can launch HydraRecon:
```bash
# Linux/Mac - Use the desktop shortcut OR:
cd hydrarecon && source venv/bin/activate && python launcher.py

# Windows - Use the desktop shortcut OR:
start.bat
```

📖 **Full installation guide**: [INSTALL.md](INSTALL.md)

---

## 🎯 What is HydraRecon?

**HydraRecon** is a **comprehensive enterprise security assessment platform** with **408,000+ lines** of professional-grade code. It integrates:

- 🔍 **Network Scanning** - Nmap integration with 10+ scan profiles
- 🔓 **Credential Testing** - Hydra integration with 21+ protocols
- 🌐 **OSINT Reconnaissance** - Automated intelligence gathering
- 🛡️ **Vulnerability Assessment** - CVE discovery and management
- 🔴 **Red Team Tools** - Advanced attack simulation
- 🔵 **Blue Team Defense** - Detection and response capabilities
- 🧠 **AI-Powered Analysis** - Machine learning threat detection
- 📊 **Professional Reporting** - Executive and technical reports

### Key Statistics

| Metric | Value |
|--------|-------|
| Total Lines of Code | 408,000+ |
| Core Security Modules | 130+ |
| GUI Pages | 100+ |
| Supported Protocols | 21+ |
| Scan Profiles | 10+ |
| Report Formats | 4 |

---

## ✨ Features

### 🎨 **Modern Cyberpunk Interface**
- **Glassmorphism Design** - Frosted glass UI components
- **Neon Glow Effects** - Dynamic button and status animations
- **3D Visualizations** - Network topology, attack paths, threat globe
- **Real-time Updates** - Live scan progress and results
- **Dark Theme** - Professional eye-friendly aesthetic

### 🔒 **Security Assessment Modules**

#### Offensive Security
| Module | Description |
|--------|-------------|
| Network Scanning | Comprehensive port/service discovery |
| Credential Testing | Multi-protocol password attacks |
| Vulnerability Scanning | CVE detection and exploitation |
| Web Application Testing | OWASP Top 10 assessment |
| Wireless Attacks | WiFi security testing |
| Social Engineering | Phishing and pretexting tools |
| Exploit Framework | Research-grade exploit chains |
| C2 Framework | Command and control simulation |

#### Defensive Security
| Module | Description |
|--------|-------------|
| Threat Intelligence | Real-time threat feeds |
| SOAR Integration | Security orchestration |
| Incident Response | IR playbook automation |
| Forensics | Memory and disk analysis |
| Blue Team Tools | Detection engineering |
| Compliance Audit | Framework assessments |

#### Advanced Capabilities
| Module | Description |
|--------|-------------|
| AI Threat Analysis | ML-powered detection |
| Quantum Cryptography | Post-quantum security |
| WiFi Sensing | CSI-based environment mapping |
| Blockchain Forensics | Cryptocurrency tracking |
| Cloud Security | AWS/Azure/GCP assessment |
| IoT/SCADA | Industrial security testing |
| **🚁 Drone Detection** | **ESP32-based UAV detection radar** |

---

## 🚁 ESP32 Drone Detection (NEW!)

HydraRecon now includes an advanced **ESP32-based drone detection system** with real-time radar visualization!

### Features
- **Real-time Radar Display** - Animated sweep with drone blip visualization
- **Multi-Manufacturer Detection** - Identifies DJI, Parrot, Autel, Skydio, Holy Stone, Hubsan, Syma drones
- **Signal Analysis** - RSSI-based distance estimation and signal strength monitoring
- **Threat Assessment** - Automatic threat level classification (Critical/High/Medium/Low)
- **WiFi Protocol Analysis** - Detects drone probe requests and beacon frames
- **Channel Hopping** - Full 2.4GHz spectrum scanning across all 13 channels
- **Export Results** - Save detections to JSON or CSV format
- **Alert System** - Real-time notifications for new drone contacts

### ESP32 Hardware Setup

```
Required Hardware:
- ESP32 DevKit V1 or ESP32-WROOM-32
- USB cable for programming and serial communication

Wiring: None required - uses built-in WiFi
```

### Firmware Installation

1. Install Arduino IDE with ESP32 board support
2. Open `esp32_firmware/drone_detector.ino`
3. Select board: "ESP32 Dev Module"
4. Upload firmware to ESP32
5. Note the COM port (e.g., /dev/ttyUSB0 or COM3)

### Usage

1. Navigate to **Drone Detection** page in HydraRecon
2. Enter ESP32 serial port (e.g., `/dev/ttyUSB0`)
3. Click **Start Scanning**
4. View detected drones on the radar display
5. Monitor threat levels and signal strength in real-time

### Detection Capabilities

| Manufacturer | OUI Prefixes | Detection Range |
|--------------|--------------|-----------------|
| DJI | 60:60:1F, 34:D2:62 | ~100-500m |
| Parrot | 90:03:B7, A0:14:3D | ~50-200m |
| Autel | B8:9A:2A | ~50-300m |
| Skydio | 6C:DF:FB | ~50-200m |
| Holy Stone | 28:BD:89 | ~30-150m |
| Hubsan | 74:5A:AA | ~30-150m |
| Syma | 1C:B7:2C | ~20-100m |

---

## ✨ Visual Features

### 🎨 **Cyberpunk Dark Theme**
- **Matrix Rain Splash Screen** with animated falling characters
- **Glassmorphism Components** with frosted glass effects
- **Neon Glow Effects** on buttons and interactive elements
- **Animated Progress Indicators** with pulsing gradients
- **Hexagonal Status Widgets** for sci-fi aesthetic

### 🌟 **UI Components**
- **Glowing Buttons** with ripple click effects
- **Stats Cards** with counting animations
- **Circular Progress** with gradient arcs
- **Console Output** with Matrix-style typewriter effects
- **Severity Badges** with color-coded glow
- **Modern Data Tables** with hover effects

--- Features

### 🔍 Network Scanning (Nmap Integration)
- **10 Scan Profiles**: Quick, Standard, Comprehensive, Stealth, Aggressive, Vulnerability, Discovery, UDP, Web, and Full Port scans
- **Real-time Progress**: Live feedback during scans
- **NSE Script Support**: Full Nmap Scripting Engine categories
- **Export Results**: Save to XML, JSON, or HTML

### 🔓 Credential Testing (Hydra Integration)
- **21+ Protocols**: SSH, FTP, RDP, Telnet, MySQL, MSSQL, PostgreSQL, SMB, VNC, HTTP, HTTPS, SMTP, POP3, IMAP, LDAP, SNMP, Oracle, MongoDB, Redis, Memcached, and more
- **Wordlist Support**: Custom username and password wordlists
- **Smart Attack Modes**: Password spraying, credential stuffing, brute force
- **Credential Management**: Store and verify discovered credentials

### 🌐 OSINT Reconnaissance
- **DNS Enumeration**: A, AAAA, MX, NS, TXT, SOA records
- **WHOIS Lookup**: Domain registration information
- **IP Intelligence**: Geolocation, ASN, reputation data
- **Shodan Integration**: Internet-connected device discovery
- **Certificate Transparency**: SSL certificate monitoring
- **Web Technology Analysis**: Identify frameworks, CMS, and technologies
- **Email Harvesting**: Discover email addresses

### 📊 Professional Reporting
- **Multiple Formats**: HTML, PDF, Markdown, JSON
- **Executive Summaries**: High-level vulnerability overviews
- **Detailed Findings**: Technical vulnerability descriptions
- **Customizable Templates**: Professional report templates

### 🎨 Modern GUI
- **Dark Theme**: Eye-friendly cybersecurity aesthetic
- **Animated Components**: Smooth transitions and feedback
- **Real-time Updates**: Live scan progress and results
- **Responsive Layout**: Adapts to window size

## Installation

### Prerequisites
- Python 3.10 or higher
- Nmap installed (`apt install nmap` or `brew install nmap`)
- Hydra installed (`apt install hydra` or `brew install hydra`)

### Quick Start

```bash
# Clone or navigate to the project
cd hydrarecon

# Make the launcher executable
chmod +x start.sh

# Run HydraRecon
./start.sh
```

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py
```

## Configuration

### API Keys (Optional - for enhanced OSINT)

Configure in Settings → API Keys:
- **Shodan**: Internet device search
- **Censys**: Certificate and host data
- **VirusTotal**: Malware analysis
- **Hunter.io**: Email discovery
- **SecurityTrails**: DNS history

### Scanner Settings

- **Nmap Path**: Default `/usr/bin/nmap`
- **Hydra Path**: Default `/usr/bin/hydra`
- **Wordlists**: Configure default username/password lists

## Usage

### Creating a Project
1. File → New Project
2. Enter project name and details
3. Select project type
4. Click Create

### Running an Nmap Scan
1. Navigate to Nmap page
2. Enter target (IP, domain, or CIDR)
3. Select scan profile
4. Click "Start Scan"
5. View results in the tabs

### Running a Hydra Attack
1. Navigate to Hydra page
2. Enter target and port
3. Select protocol
4. Configure usernames/passwords
5. Click "Start Attack"
6. Discovered credentials appear in results

### Gathering OSINT
1. Navigate to OSINT page
2. Enter target domain
3. Select modules to run
4. Click "Start Gathering"
5. Review findings by category

### Generating Reports
1. Navigate to Reports page
2. Configure report settings
3. Select output format
4. Click "Generate Report"

## Project Structure

```
hydrarecon/
├── main.py              # Main entry point
├── run.py               # Launcher with splash screen
├── start.sh             # Shell launcher script
├── requirements.txt     # Python dependencies
│
├── core/                # Core modules
│   ├── __init__.py
│   ├── config.py        # Configuration management
│   ├── database.py      # SQLite database
│   └── logger.py        # Logging system
│
├── scanners/            # Scanner implementations
│   ├── __init__.py
│   ├── base.py          # Abstract base scanner
│   ├── nmap_scanner.py  # Nmap integration
│   ├── hydra_scanner.py # Hydra integration
│   └── osint_scanner.py # OSINT modules
│
└── gui/                 # GUI components
    ├── __init__.py
    ├── themes.py        # Dark/Light themes
    ├── widgets.py       # Custom widgets
    ├── main_window.py   # Main window
    ├── dialogs.py       # Dialogs
    │
    └── pages/           # Page components
        ├── __init__.py
        ├── dashboard.py
        ├── nmap_page.py
        ├── hydra_page.py
        ├── osint_page.py
        ├── targets_page.py
        ├── credentials_page.py
        ├── vulnerabilities_page.py
        ├── reports_page.py
        └── settings_page.py
```

## Screenshots

The application features a modern dark theme with:
- **Matrix Rain Animated Splash Screen** - Full animated loading experience
- **Neon Accents**: Cyberpunk green (#00ff88) and electric blue (#0088ff)
- **Glassmorphism Effects**: Frosted glass panels throughout
- **Animated Components**: Smooth 60fps animations everywhere
- **Professional Security Aesthetic**: Enterprise-ready visual design
- **Responsive Layout**: Adapts to any window size

### UI Preview
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  ⚡ HydraRecon                                                    v1.0.0        │
├──────────────────┬──────────────────────────────────────────────────────────────┤
│                  │                                                              │
│  🏠 Dashboard    │   ████████████████████████████████████████████████████████  │
│  🔍 Nmap         │   █                 DASHBOARD                            █  │
│  🔓 Hydra        │   █                                                      █  │
│  🌐 OSINT        │   █  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    █  │
│                  │   █  │  HOSTS  │ │  PORTS  │ │  CREDS  │ │  VULNS  │    █  │
│  ─────────────   │   █  │   127   │ │   843   │ │    23   │ │    47   │    █  │
│  🎯 Targets      │   █  │   ▲ 12% │ │   ▲ 8%  │ │   ▲ 15% │ │   ▼ 3%  │    █  │
│  🔑 Credentials  │   █  └─────────┘ └─────────┘ └─────────┘ └─────────┘    █  │
│  ⚠️ Vulns        │   █                                                      █  │
│  📊 Reports      │   █  ┌────────────────────────────────────────────────┐  █  │
│                  │   █  │ [15:42:33] ❯ nmap -sV 192.168.1.0/24           │  █  │
│  ─────────────   │   █  │ ✓ Discovered 127 hosts                         │  █  │
│  ⚙️ Settings     │   █  │ ✓ Found 843 open ports                         │  █  │
│                  │   █  │ ⚠ 47 potential vulnerabilities detected        │  █  │
│                  │   █  └────────────────────────────────────────────────┘  █  │
│                  │   █                                                      █  │
│                  │   ████████████████████████████████████████████████████████  │
└──────────────────┴──────────────────────────────────────────────────────────────┘
```

## Security Notice

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only.

- Always obtain proper authorization before scanning targets
- Use responsibly and ethically
- Follow all applicable laws and regulations
- Never use against systems you don't own or have permission to test

## License

This software is provided for educational and authorized security testing purposes only.

## Support

For issues, questions, or feature requests, please use the built-in help system or check the documentation.

---

**HydraRecon** - *Enterprise Security Assessment Suite*  
*Combining the power of Nmap, Hydra, and OSINT in one unified platform.*
