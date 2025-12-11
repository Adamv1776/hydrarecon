#!/usr/bin/env python3
"""
HydraRecon Configuration Manager
Handles all application configuration and settings.
"""

import os
import json
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from cryptography.fernet import Fernet
import base64


@dataclass
class NmapConfig:
    """Nmap scanner configuration"""
    path: str = "nmap"
    default_args: str = "-sV -sC"
    timing_template: int = 4  # T4
    max_retries: int = 3
    host_timeout: int = 300
    script_timeout: int = 60
    max_parallelism: int = 100
    min_parallelism: int = 10
    version_intensity: int = 7
    os_detection: bool = True
    service_detection: bool = True
    aggressive_scan: bool = False
    custom_scripts: List[str] = field(default_factory=list)


@dataclass
class HydraConfig:
    """Hydra brute-force configuration"""
    path: str = "hydra"
    tasks: int = 16
    timeout: int = 30
    max_attempts: int = 3
    exit_on_first: bool = True
    verbose: bool = True
    default_wordlist_user: str = "/usr/share/wordlists/usernames.txt"
    default_wordlist_pass: str = "/usr/share/wordlists/passwords.txt"
    supported_protocols: List[str] = field(default_factory=lambda: [
        "ssh", "ftp", "telnet", "http-get", "http-post", "http-form-get",
        "http-form-post", "https-get", "https-post", "https-form-get",
        "https-form-post", "smb", "smbnt", "mysql", "mssql", "postgres",
        "oracle", "vnc", "rdp", "smtp", "pop3", "imap", "ldap", "ldaps",
        "snmp", "redis", "mongodb", "memcached", "cisco", "cisco-enable"
    ])


@dataclass  
class OSINTConfig:
    """OSINT module configuration"""
    # Network Intelligence
    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    zoomeye_api_key: str = ""
    binaryedge_api_key: str = ""
    
    # Threat Intelligence
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    alienvault_otx_key: str = ""
    pulsedive_api_key: str = ""
    threatfox_api_key: str = ""
    
    # Domain/DNS Intelligence
    securitytrails_api_key: str = ""
    passivetotal_api_key: str = ""
    passivetotal_username: str = ""
    dnsdb_api_key: str = ""
    
    # Email Intelligence
    hunter_api_key: str = ""
    haveibeenpwned_api_key: str = ""
    emailrep_api_key: str = ""
    
    # Vulnerability Intelligence
    vulners_api_key: str = ""
    nvd_api_key: str = ""
    
    # Blockchain Intelligence
    etherscan_api_key: str = ""
    blockchain_api_key: str = ""
    chainalysis_api_key: str = ""
    
    # Additional Sources
    builtwith_api_key: str = ""
    fullhunt_api_key: str = ""
    intelx_api_key: str = ""
    leakix_api_key: str = ""
    urlscan_api_key: str = ""
    
    # Geolocation
    ipinfo_api_key: str = ""
    ipapi_api_key: str = ""
    
    # Rate Limiting & Timeouts
    whois_timeout: int = 30
    dns_timeout: int = 10
    max_concurrent_requests: int = 50
    rate_limit_delay: float = 0.5


@dataclass
class GUIConfig:
    """GUI appearance configuration"""
    theme: str = "dark"
    accent_color: str = "#00ff88"
    secondary_color: str = "#0088ff"
    danger_color: str = "#ff4444"
    warning_color: str = "#ffaa00"
    font_family: str = "Segoe UI"
    font_size: int = 10
    icon_size: int = 24
    sidebar_width: int = 250
    animation_enabled: bool = True
    animation_duration: int = 300
    show_welcome: bool = True
    auto_save_project: bool = True
    save_interval: int = 300


@dataclass
class ScanConfig:
    """General scan configuration"""
    max_threads: int = 100
    timeout: int = 60
    retry_count: int = 3
    verify_ssl: bool = True  # SECURITY: SSL verification enabled by default
    follow_redirects: bool = True
    user_agent: str = "HydraRecon/1.0 Security Scanner"
    proxy: str = ""
    tor_enabled: bool = False
    tor_host: str = "127.0.0.1"
    tor_port: int = 9050
    rate_limit: int = 100  # requests per second
    respect_robots: bool = False


class Config:
    """Main configuration manager for HydraRecon"""
    
    DEFAULT_CONFIG_DIR = Path.home() / ".hydrarecon"
    DEFAULT_CONFIG_FILE = "config.yaml"
    DEFAULT_DATABASE = "hydrarecon.db"
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager"""
        self.config_dir = Path(config_path) if config_path else self.DEFAULT_CONFIG_DIR
        self.config_file = self.config_dir / self.DEFAULT_CONFIG_FILE
        self.database_path = self.config_dir / self.DEFAULT_DATABASE
        
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize encryption key for sensitive data
        self._init_encryption()
        
        # Load or create default configuration
        self.nmap = NmapConfig()
        self.hydra = HydraConfig()
        self.osint = OSINTConfig()
        self.gui = GUIConfig()
        self.scan = ScanConfig()
        
        # Load existing config if available
        if self.config_file.exists():
            self.load()
        else:
            self.save()
    
    def _init_encryption(self):
        """Initialize encryption for sensitive data"""
        key_file = self.config_dir / ".key"
        if key_file.exists():
            self._key = key_file.read_bytes()
        else:
            self._key = Fernet.generate_key()
            key_file.write_bytes(self._key)
            os.chmod(key_file, 0o600)
        
        self._cipher = Fernet(self._key)
    
    def encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not data:
            return ""
        return self._cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, data: str) -> str:
        """Decrypt sensitive data"""
        if not data:
            return ""
        try:
            return self._cipher.decrypt(data.encode()).decode()
        except:
            return ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "nmap": {
                "path": self.nmap.path,
                "default_args": self.nmap.default_args,
                "timing_template": self.nmap.timing_template,
                "max_retries": self.nmap.max_retries,
                "host_timeout": self.nmap.host_timeout,
                "script_timeout": self.nmap.script_timeout,
                "max_parallelism": self.nmap.max_parallelism,
                "min_parallelism": self.nmap.min_parallelism,
                "version_intensity": self.nmap.version_intensity,
                "os_detection": self.nmap.os_detection,
                "service_detection": self.nmap.service_detection,
                "aggressive_scan": self.nmap.aggressive_scan,
                "custom_scripts": self.nmap.custom_scripts
            },
            "hydra": {
                "path": self.hydra.path,
                "tasks": self.hydra.tasks,
                "timeout": self.hydra.timeout,
                "max_attempts": self.hydra.max_attempts,
                "exit_on_first": self.hydra.exit_on_first,
                "verbose": self.hydra.verbose,
                "default_wordlist_user": self.hydra.default_wordlist_user,
                "default_wordlist_pass": self.hydra.default_wordlist_pass,
                "supported_protocols": self.hydra.supported_protocols
            },
            "osint": {
                "shodan_api_key": self.encrypt(self.osint.shodan_api_key),
                "censys_api_id": self.encrypt(self.osint.censys_api_id),
                "censys_api_secret": self.encrypt(self.osint.censys_api_secret),
                "virustotal_api_key": self.encrypt(self.osint.virustotal_api_key),
                "hunter_api_key": self.encrypt(self.osint.hunter_api_key),
                "haveibeenpwned_api_key": self.encrypt(self.osint.haveibeenpwned_api_key),
                "securitytrails_api_key": self.encrypt(self.osint.securitytrails_api_key),
                "builtwith_api_key": self.encrypt(self.osint.builtwith_api_key),
                "whois_timeout": self.osint.whois_timeout,
                "dns_timeout": self.osint.dns_timeout,
                "max_concurrent_requests": self.osint.max_concurrent_requests,
                "rate_limit_delay": self.osint.rate_limit_delay
            },
            "gui": {
                "theme": self.gui.theme,
                "accent_color": self.gui.accent_color,
                "secondary_color": self.gui.secondary_color,
                "danger_color": self.gui.danger_color,
                "warning_color": self.gui.warning_color,
                "font_family": self.gui.font_family,
                "font_size": self.gui.font_size,
                "icon_size": self.gui.icon_size,
                "sidebar_width": self.gui.sidebar_width,
                "animation_enabled": self.gui.animation_enabled,
                "animation_duration": self.gui.animation_duration,
                "show_welcome": self.gui.show_welcome,
                "auto_save_project": self.gui.auto_save_project,
                "save_interval": self.gui.save_interval
            },
            "scan": {
                "max_threads": self.scan.max_threads,
                "timeout": self.scan.timeout,
                "retry_count": self.scan.retry_count,
                "verify_ssl": self.scan.verify_ssl,
                "follow_redirects": self.scan.follow_redirects,
                "user_agent": self.scan.user_agent,
                "proxy": self.scan.proxy,
                "tor_enabled": self.scan.tor_enabled,
                "tor_host": self.scan.tor_host,
                "tor_port": self.scan.tor_port,
                "rate_limit": self.scan.rate_limit,
                "respect_robots": self.scan.respect_robots
            }
        }
    
    def from_dict(self, data: Dict[str, Any]):
        """Load configuration from dictionary"""
        if "nmap" in data:
            for key, value in data["nmap"].items():
                if hasattr(self.nmap, key):
                    setattr(self.nmap, key, value)
        
        if "hydra" in data:
            for key, value in data["hydra"].items():
                if hasattr(self.hydra, key):
                    setattr(self.hydra, key, value)
        
        if "osint" in data:
            osint_data = data["osint"]
            # Decrypt sensitive fields
            sensitive_fields = [
                "shodan_api_key", "censys_api_id", "censys_api_secret",
                "virustotal_api_key", "hunter_api_key", "haveibeenpwned_api_key",
                "securitytrails_api_key", "builtwith_api_key"
            ]
            for key, value in osint_data.items():
                if hasattr(self.osint, key):
                    if key in sensitive_fields:
                        setattr(self.osint, key, self.decrypt(value))
                    else:
                        setattr(self.osint, key, value)
        
        if "gui" in data:
            for key, value in data["gui"].items():
                if hasattr(self.gui, key):
                    setattr(self.gui, key, value)
        
        if "scan" in data:
            for key, value in data["scan"].items():
                if hasattr(self.scan, key):
                    setattr(self.scan, key, value)
    
    def save(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)
    
    def load(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                data = yaml.safe_load(f)
                if data:
                    self.from_dict(data)
        except Exception as e:
            print(f"Error loading config: {e}")
    
    def reset_to_defaults(self):
        """Reset all configuration to defaults"""
        self.nmap = NmapConfig()
        self.hydra = HydraConfig()
        self.osint = OSINTConfig()
        self.gui = GUIConfig()
        self.scan = ScanConfig()
        self.save()
    
    @property
    def projects_dir(self) -> Path:
        """Get projects directory"""
        projects = self.config_dir / "projects"
        projects.mkdir(exist_ok=True)
        return projects
    
    @property
    def reports_dir(self) -> Path:
        """Get reports directory"""
        reports = self.config_dir / "reports"
        reports.mkdir(exist_ok=True)
        return reports
    
    @property
    def wordlists_dir(self) -> Path:
        """Get wordlists directory"""
        wordlists = self.config_dir / "wordlists"
        wordlists.mkdir(exist_ok=True)
        return wordlists
    
    @property
    def scripts_dir(self) -> Path:
        """Get custom scripts directory"""
        scripts = self.config_dir / "scripts"
        scripts.mkdir(exist_ok=True)
        return scripts
