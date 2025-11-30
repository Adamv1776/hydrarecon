# HydraRecon - Enterprise Security Assessment Suite

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   🔒 HYDRARECON                                                           ║
║   Enterprise Security Assessment Suite                                    ║
║                                                                           ║
║   Combining Nmap • Hydra • OSINT in one powerful interface               ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

## Overview

HydraRecon is a professional-grade security assessment platform that integrates network scanning, brute-force capabilities, and open-source intelligence gathering into a single, unified application with a stunning dark-themed GUI.

## Features

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
- Neon green (#00ff88) and blue (#0088ff) accent colors
- Glassmorphism effects
- Animated components
- Professional security aesthetic

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
