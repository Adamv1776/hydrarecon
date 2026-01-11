# HydraRecon User Documentation

## Table of Contents

1. [Getting Started](#getting-started)
2. [Installation](#installation)
3. [Quick Start Guide](#quick-start-guide)
4. [Core Features](#core-features)
5. [Module Reference](#module-reference)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)
8. [Legal Compliance](#legal-compliance)

---

## Getting Started

### What is HydraRecon?

HydraRecon is an enterprise-grade security assessment suite designed for professional penetration testers, security researchers, and compliance auditors. It integrates multiple security tools into a unified, modern interface.

### Who Should Use HydraRecon?

- **Penetration Testers** - Conduct authorized security assessments
- **Security Researchers** - Analyze vulnerabilities in controlled environments
- **Red Team Operators** - Simulate adversary techniques
- **Blue Team Analysts** - Understand attack methodologies for defense
- **Compliance Auditors** - Assess security posture against standards
- **Bug Bounty Hunters** - Find vulnerabilities within defined scope

### Prerequisites

- **Written Authorization** - Must have documented permission to test target systems
- **Python 3.10+** - Python 3.10 or higher
- **Operating System** - Linux (recommended), macOS, or Windows
- **External Tools** - Nmap and Hydra installed for full functionality

---

## Installation

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/hydrarecon.git
cd hydrarecon

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run HydraRecon
python main.py
```

### External Tool Installation

#### Nmap
```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS
brew install nmap

# Arch Linux
sudo pacman -S nmap
```

#### Hydra
```bash
# Ubuntu/Debian
sudo apt install hydra

# macOS
brew install hydra

# Arch Linux
sudo pacman -S hydra
```

### First Run

On first launch, you'll be presented with a license agreement. You must:
1. Read the LICENSE and DISCLAIMER documents
2. Enter your full name
3. Check all agreement boxes
4. Click "Accept" to proceed

---

## Quick Start Guide

### 1. Dashboard Overview

The dashboard provides:
- **System Status** - Current operational state
- **Statistics** - Discovered hosts, open ports, credentials, vulnerabilities
- **Quick Actions** - Launch common scans
- **Activity Feed** - Recent operations

### 2. Running Your First Scan

1. Navigate to **Network Scanning** (Nmap)
2. Enter target IP or hostname
3. Select scan profile:
   - **Quick Scan** - Fast port discovery
   - **Standard** - Common ports with service detection
   - **Comprehensive** - Full port scan with scripts
4. Click **Start Scan**
5. View results in real-time

### 3. Credential Testing

1. Navigate to **Credential Testing** (Hydra)
2. Enter target host
3. Select protocol (SSH, FTP, RDP, etc.)
4. Load or enter wordlists
5. Configure options (threads, timeout)
6. Click **Start Attack**

⚠️ **Warning**: Only test credentials on systems you own or have explicit permission to test.

### 4. OSINT Reconnaissance

1. Navigate to **OSINT** section
2. Enter target domain or organization
3. Select modules:
   - DNS enumeration
   - WHOIS lookup
   - Subdomain discovery
   - Email harvesting
4. Click **Start Reconnaissance**

---

## Core Features

### Network Scanning (Nmap Integration)

| Profile | Description | Use Case |
|---------|-------------|----------|
| Quick | Top 100 ports, fast | Initial discovery |
| Standard | Top 1000 ports, services | Regular assessments |
| Comprehensive | All ports, scripts | Deep analysis |
| Stealth | SYN scan, slow timing | Evasion testing |
| Aggressive | Fast, all detection | Time-critical tests |
| Vulnerability | vuln scripts | CVE discovery |

### Credential Testing (Hydra Integration)

Supported protocols:
- SSH, FTP, Telnet, RDP
- MySQL, MSSQL, PostgreSQL, Oracle
- HTTP/HTTPS (forms, basic auth)
- SMB, VNC, LDAP
- SMTP, POP3, IMAP
- And 15+ more...

### Advanced Modules

- **Threat Intelligence** - Real-time threat feeds
- **Vulnerability Management** - Track and prioritize findings
- **Exploit Framework** - Research-grade exploit chains
- **Forensics** - Memory and disk analysis
- **Cloud Security** - AWS, Azure, GCP assessments
- **Wireless Attacks** - WiFi security testing
- **IoT Exploitation** - Smart device testing
- **SCADA/ICS** - Industrial control system security

---

## Module Reference

### Core Modules (`/core/`)

| Module | Description |
|--------|-------------|
| `config.py` | Application configuration |
| `database.py` | Data persistence |
| `threat_intelligence.py` | Threat feed integration |
| `vuln_scanner.py` | Vulnerability scanning |
| `malware_analysis.py` | Malware sandbox |
| `forensics.py` | Digital forensics |
| `cloud_security.py` | Cloud assessment |
| `wireless_attacks.py` | WiFi testing |

### GUI Pages (`/gui/pages/`)

| Page | Description |
|------|-------------|
| `dashboard.py` | Main dashboard |
| `nmap_page.py` | Network scanning |
| `hydra_page.py` | Credential testing |
| `osint_page.py` | Open source intelligence |
| `reports_page.py` | Report generation |
| `settings_page.py` | Configuration |

### Scanners (`/scanners/`)

| Scanner | Description |
|---------|-------------|
| `nmap_scanner.py` | Nmap wrapper |
| `hydra_scanner.py` | Hydra wrapper |
| `osint_scanner.py` | OSINT automation |

---

## Best Practices

### Before Testing

1. **Get Written Authorization**
   - Formal engagement letter or contract
   - Defined scope (IPs, domains, timeframes)
   - Excluded systems clearly documented
   - Emergency contacts established

2. **Verify Scope**
   - Confirm target ownership
   - Check for shared hosting
   - Identify production vs. test systems
   - Note business-critical hours

3. **Document Everything**
   - Start and end times
   - Commands/actions taken
   - Screenshots of findings
   - Hash evidence files

### During Testing

1. **Stay In Scope**
   - Never test beyond authorized boundaries
   - Stop immediately if unauthorized access occurs
   - Report out-of-scope findings to client

2. **Minimize Impact**
   - Use low-intensity scans first
   - Avoid denial of service
   - Test during approved windows
   - Have rollback procedures ready

3. **Secure Findings**
   - Encrypt sensitive data
   - Use secure channels for communication
   - Don't store credentials in plaintext
   - Follow data handling requirements

### After Testing

1. **Responsible Disclosure**
   - Report critical findings immediately
   - Follow agreed-upon timelines
   - Provide remediation guidance
   - Offer re-testing if needed

2. **Cleanup**
   - Remove test accounts
   - Delete uploaded files
   - Restore modified configurations
   - Document cleanup actions

---

## Troubleshooting

### Common Issues

#### Application Won't Start
```bash
# Check Python version
python --version  # Should be 3.10+

# Verify dependencies
pip install -r requirements.txt

# Check for errors
python main.py 2>&1 | head -50
```

#### GUI Not Displaying
```bash
# Linux - Install display server
sudo apt install xvfb
xvfb-run python main.py

# Or check DISPLAY variable
echo $DISPLAY
export DISPLAY=:0
```

#### Nmap/Hydra Not Found
```bash
# Verify installation
which nmap
which hydra

# Install if missing
sudo apt install nmap hydra
```

#### Database Errors
```bash
# Reset database
rm -f *.db
python main.py  # Creates fresh databases
```

### Log Files

Logs are stored in the `logs/` directory:
- `crash_*.log` - Crash reports
- Application logs in console output

### Getting Help

1. Check this documentation
2. Review `docs/` directory
3. Search existing issues
4. Create detailed bug report

---

## Legal Compliance

### Authorization Requirements

You **MUST** have written authorization before using HydraRecon against any system. This includes:

- **Penetration Test Agreement** - Formal contract with scope
- **Bug Bounty Program Rules** - Published scope documentation  
- **Internal Authorization** - Documented approval for own systems
- **Lab Environment** - Systems you control in isolated networks

### Applicable Laws

Be aware of and comply with:

| Region | Law |
|--------|-----|
| United States | Computer Fraud and Abuse Act (CFAA) |
| United Kingdom | Computer Misuse Act 1990 |
| European Union | Various national implementations + GDPR |
| Australia | Criminal Code Act 1995 |
| Canada | Criminal Code §342.1 |

### Penalties for Misuse

Unauthorized computer access can result in:
- **Criminal Prosecution** - Fines and imprisonment
- **Civil Liability** - Damages and legal fees
- **Professional Consequences** - Career impact

### Reporting Illegal Activity

If you witness HydraRecon being used illegally, report to:
- Local law enforcement
- FBI IC3 (US): ic3.gov
- NCSC (UK): ncsc.gov.uk

---

## Support

### Documentation
- Full documentation: `docs/` directory
- API reference: `docs/api/`
- Tutorials: `docs/tutorials/`

### Community
- GitHub Issues: Report bugs and feature requests
- Discussions: Ask questions and share knowledge

### Commercial Support
- Enterprise licensing available
- Priority support options
- Custom development services

---

**Remember: Use HydraRecon responsibly and legally. Your skills should protect, not harm.**
