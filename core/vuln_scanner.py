"""
Vulnerability Scanner Engine
Advanced CVE detection and vulnerability assessment
"""

import asyncio
import re
import json
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, Set
from enum import Enum
from datetime import datetime
import logging
import aiohttp

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class VulnType(Enum):
    """Vulnerability types"""
    RCE = "remote_code_execution"
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    CSRF = "cross_site_request_forgery"
    PATH_TRAVERSAL = "path_traversal"
    FILE_INCLUSION = "file_inclusion"
    SSRF = "server_side_request_forgery"
    XXE = "xml_external_entity"
    AUTHENTICATION = "authentication_bypass"
    AUTHORIZATION = "authorization_flaw"
    INFO_DISCLOSURE = "information_disclosure"
    DOS = "denial_of_service"
    MISCONFIGURATION = "misconfiguration"
    OUTDATED_SOFTWARE = "outdated_software"
    DEFAULT_CREDENTIALS = "default_credentials"
    WEAK_CRYPTO = "weak_cryptography"
    BUFFER_OVERFLOW = "buffer_overflow"


@dataclass
class CVE:
    """CVE information"""
    cve_id: str
    description: str
    severity: Severity
    cvss_score: float
    published: datetime
    modified: datetime
    references: List[str] = field(default_factory=list)
    cpe: List[str] = field(default_factory=list)
    exploit_available: bool = False
    
    def to_dict(self) -> dict:
        return {
            'cve_id': self.cve_id,
            'description': self.description,
            'severity': self.severity.value,
            'cvss_score': self.cvss_score,
            'published': self.published.isoformat(),
            'references': self.references,
            'exploit_available': self.exploit_available
        }


@dataclass
class Vulnerability:
    """Detected vulnerability"""
    vuln_id: str
    title: str
    description: str
    vuln_type: VulnType
    severity: Severity
    cvss_score: float = 0.0
    cve: Optional[CVE] = None
    target: str = ""
    port: int = 0
    service: str = ""
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.now)
    false_positive: bool = False
    verified: bool = False
    
    def to_dict(self) -> dict:
        return {
            'vuln_id': self.vuln_id,
            'title': self.title,
            'description': self.description,
            'type': self.vuln_type.value,
            'severity': self.severity.value,
            'cvss_score': self.cvss_score,
            'cve': self.cve.to_dict() if self.cve else None,
            'target': self.target,
            'port': self.port,
            'service': self.service,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'detected_at': self.detected_at.isoformat()
        }


@dataclass
class ScanTarget:
    """Scan target with service information"""
    host: str
    port: int
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    os: str = ""
    
    @property
    def cpe(self) -> str:
        """Generate CPE string"""
        if self.product and self.version:
            vendor = self.product.split()[0].lower() if self.product else 'unknown'
            product = self.product.lower().replace(' ', '_')
            return f"cpe:2.3:a:{vendor}:{product}:{self.version}"
        return ""


class VulnDatabase:
    """Local vulnerability database"""
    
    # Known vulnerable software versions
    KNOWN_VULNS = {
        'apache': {
            '2.4.49': [
                ('CVE-2021-41773', 'Path Traversal', Severity.HIGH, 7.5),
                ('CVE-2021-42013', 'RCE via Path Traversal', Severity.CRITICAL, 9.8),
            ],
            '2.4.50': [
                ('CVE-2021-42013', 'RCE via Path Traversal', Severity.CRITICAL, 9.8),
            ],
        },
        'openssh': {
            '7.7': [
                ('CVE-2018-15473', 'User Enumeration', Severity.MEDIUM, 5.3),
            ],
        },
        'nginx': {
            '1.16.0': [
                ('CVE-2019-20372', 'HTTP Request Smuggling', Severity.MEDIUM, 5.3),
            ],
        },
        'vsftpd': {
            '2.3.4': [
                ('CVE-2011-2523', 'Backdoor Command Execution', Severity.CRITICAL, 9.8),
            ],
        },
        'proftpd': {
            '1.3.5': [
                ('CVE-2015-3306', 'Remote Code Execution', Severity.CRITICAL, 10.0),
            ],
        },
        'samba': {
            '3.5.0': [
                ('CVE-2017-7494', 'SambaCry RCE', Severity.CRITICAL, 9.8),
            ],
        },
        'mysql': {
            '5.5.': [
                ('CVE-2016-6662', 'Remote Root Code Execution', Severity.CRITICAL, 9.8),
            ],
        },
        'postgresql': {
            '9.3': [
                ('CVE-2019-10164', 'Buffer Overflow', Severity.HIGH, 8.8),
            ],
        },
        'tomcat': {
            '8.5.0': [
                ('CVE-2020-1938', 'Ghostcat File Read/Inclusion', Severity.CRITICAL, 9.8),
            ],
            '9.0.0': [
                ('CVE-2020-1938', 'Ghostcat File Read/Inclusion', Severity.CRITICAL, 9.8),
            ],
        },
        'weblogic': {
            '12.': [
                ('CVE-2020-14882', 'Unauthenticated RCE', Severity.CRITICAL, 9.8),
            ],
        },
        'elasticsearch': {
            '1.': [
                ('CVE-2015-1427', 'Remote Code Execution', Severity.CRITICAL, 9.8),
            ],
        },
        'redis': {
            '4.': [
                ('CVE-2022-0543', 'Lua Sandbox Escape', Severity.CRITICAL, 10.0),
            ],
        },
        'jenkins': {
            '2.': [
                ('CVE-2019-1003000', 'Script Security Sandbox Bypass', Severity.CRITICAL, 9.8),
            ],
        },
    }
    
    # Default credentials database
    DEFAULT_CREDS = {
        'ssh': [
            ('root', 'root'), ('root', 'toor'), ('admin', 'admin'),
            ('root', 'password'), ('root', '123456'), ('admin', 'password'),
        ],
        'ftp': [
            ('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin'),
            ('user', 'user'), ('root', 'root'),
        ],
        'mysql': [
            ('root', ''), ('root', 'root'), ('root', 'password'),
            ('admin', 'admin'), ('mysql', 'mysql'),
        ],
        'postgresql': [
            ('postgres', 'postgres'), ('postgres', 'password'),
            ('admin', 'admin'),
        ],
        'redis': [
            ('', ''),  # No auth
        ],
        'mongodb': [
            ('', ''),  # No auth
            ('admin', 'admin'), ('root', 'root'),
        ],
        'telnet': [
            ('admin', 'admin'), ('root', 'root'), ('user', 'user'),
            ('admin', '1234'), ('admin', 'password'),
        ],
        'vnc': [
            ('', 'password'), ('', '123456'), ('', 'vnc'),
        ],
        'tomcat': [
            ('tomcat', 'tomcat'), ('admin', 'admin'), ('manager', 'manager'),
            ('tomcat', 's3cret'), ('admin', 'password'),
        ],
        'weblogic': [
            ('weblogic', 'weblogic'), ('weblogic', 'weblogic1'),
            ('system', 'password'),
        ],
    }
    
    # Service fingerprints
    SERVICE_FINGERPRINTS = {
        'SSH-2.0-OpenSSH': 'openssh',
        'Apache': 'apache',
        'nginx': 'nginx',
        'Microsoft-IIS': 'iis',
        'vsftpd': 'vsftpd',
        'ProFTPD': 'proftpd',
        'MySQL': 'mysql',
        'PostgreSQL': 'postgresql',
        'Redis': 'redis',
        'MongoDB': 'mongodb',
        'Samba': 'samba',
        'Apache Tomcat': 'tomcat',
        'WebLogic': 'weblogic',
        'Elasticsearch': 'elasticsearch',
        'Jenkins': 'jenkins',
    }


class VulnerabilityScanner:
    """
    Advanced Vulnerability Scanner
    Performs comprehensive vulnerability detection
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.db = VulnDatabase()
        self.session: Optional[aiohttp.ClientSession] = None
        self.vulnerabilities: List[Vulnerability] = []
        self.scan_results: Dict[str, Any] = {}
        
        # NVD API key (optional)
        self.nvd_api_key = self.config.get('nvd_api_key', '')
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def scan_target(self, target: ScanTarget) -> List[Vulnerability]:
        """Scan a single target for vulnerabilities"""
        vulns = []
        
        # Version-based vulnerability detection
        version_vulns = await self.check_version_vulns(target)
        vulns.extend(version_vulns)
        
        # Service-specific checks
        service_vulns = await self.check_service_vulns(target)
        vulns.extend(service_vulns)
        
        # Default credential checks
        cred_vulns = await self.check_default_creds(target)
        vulns.extend(cred_vulns)
        
        # Configuration checks
        config_vulns = await self.check_misconfigurations(target)
        vulns.extend(config_vulns)
        
        self.vulnerabilities.extend(vulns)
        return vulns
    
    async def check_version_vulns(self, target: ScanTarget) -> List[Vulnerability]:
        """Check for known vulnerable versions"""
        vulns = []
        
        # Identify software from banner/version
        software = None
        version = target.version
        
        for fingerprint, sw_name in self.db.SERVICE_FINGERPRINTS.items():
            if fingerprint.lower() in target.service.lower() or \
               fingerprint.lower() in target.product.lower():
                software = sw_name
                break
        
        if not software or not version:
            return vulns
        
        # Check against known vulns
        if software in self.db.KNOWN_VULNS:
            for vuln_version, cve_list in self.db.KNOWN_VULNS[software].items():
                if version.startswith(vuln_version) or vuln_version in version:
                    for cve_id, title, severity, cvss in cve_list:
                        vuln = Vulnerability(
                            vuln_id=hashlib.md5(f"{target.host}:{target.port}:{cve_id}".encode()).hexdigest()[:12],
                            title=f"{title} ({software} {version})",
                            description=f"The {software} version {version} is vulnerable to {cve_id}",
                            vuln_type=VulnType.OUTDATED_SOFTWARE,
                            severity=severity,
                            cvss_score=cvss,
                            target=target.host,
                            port=target.port,
                            service=target.service,
                            evidence=f"Detected version: {version}",
                            remediation=f"Upgrade {software} to the latest version",
                            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                            cve=CVE(
                                cve_id=cve_id,
                                description=title,
                                severity=severity,
                                cvss_score=cvss,
                                published=datetime.now(),
                                modified=datetime.now(),
                                exploit_available=severity == Severity.CRITICAL
                            )
                        )
                        vulns.append(vuln)
        
        return vulns
    
    async def check_service_vulns(self, target: ScanTarget) -> List[Vulnerability]:
        """Service-specific vulnerability checks"""
        vulns = []
        service = target.service.lower()
        
        # HTTP/HTTPS checks
        if 'http' in service or target.port in [80, 443, 8080, 8443]:
            http_vulns = await self.check_http_vulns(target)
            vulns.extend(http_vulns)
        
        # SMB checks
        elif target.port in [139, 445] or 'smb' in service or 'samba' in service:
            smb_vulns = await self.check_smb_vulns(target)
            vulns.extend(smb_vulns)
        
        # FTP checks
        elif target.port == 21 or 'ftp' in service:
            ftp_vulns = await self.check_ftp_vulns(target)
            vulns.extend(ftp_vulns)
        
        # SSH checks
        elif target.port == 22 or 'ssh' in service:
            ssh_vulns = await self.check_ssh_vulns(target)
            vulns.extend(ssh_vulns)
        
        # Database checks
        elif target.port in [3306, 5432, 1433, 1521, 27017, 6379]:
            db_vulns = await self.check_database_vulns(target)
            vulns.extend(db_vulns)
        
        return vulns
    
    async def check_http_vulns(self, target: ScanTarget) -> List[Vulnerability]:
        """Check HTTP-specific vulnerabilities"""
        vulns = []
        protocol = 'https' if target.port == 443 else 'http'
        base_url = f"{protocol}://{target.host}:{target.port}"
        
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        try:
            # Check for common sensitive files
            sensitive_paths = [
                '/.git/config', '/.env', '/config.php', '/wp-config.php',
                '/phpinfo.php', '/.htaccess', '/server-status', '/server-info',
                '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
                '/admin', '/phpmyadmin', '/adminer.php',
                '/.svn/entries', '/backup.sql', '/database.sql',
            ]
            
            for path in sensitive_paths:
                try:
                    async with self.session.get(
                        f"{base_url}{path}",
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            vuln = Vulnerability(
                                vuln_id=hashlib.md5(f"{base_url}{path}".encode()).hexdigest()[:12],
                                title=f"Sensitive File Exposed: {path}",
                                description=f"Sensitive file or directory accessible at {path}",
                                vuln_type=VulnType.INFO_DISCLOSURE,
                                severity=Severity.HIGH if '.env' in path or '.git' in path else Severity.MEDIUM,
                                target=target.host,
                                port=target.port,
                                service='http',
                                evidence=f"HTTP 200 returned for {path}",
                                remediation="Restrict access to sensitive files"
                            )
                            vulns.append(vuln)
                except:
                    continue
            
            # Check security headers
            async with self.session.get(base_url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                headers = resp.headers
                
                missing_headers = []
                if 'X-Frame-Options' not in headers:
                    missing_headers.append('X-Frame-Options')
                if 'X-Content-Type-Options' not in headers:
                    missing_headers.append('X-Content-Type-Options')
                if 'Content-Security-Policy' not in headers:
                    missing_headers.append('Content-Security-Policy')
                if 'Strict-Transport-Security' not in headers and protocol == 'https':
                    missing_headers.append('Strict-Transport-Security')
                
                if missing_headers:
                    vuln = Vulnerability(
                        vuln_id=hashlib.md5(f"{base_url}:headers".encode()).hexdigest()[:12],
                        title="Missing Security Headers",
                        description=f"Missing headers: {', '.join(missing_headers)}",
                        vuln_type=VulnType.MISCONFIGURATION,
                        severity=Severity.LOW,
                        target=target.host,
                        port=target.port,
                        service='http',
                        evidence=f"Missing: {', '.join(missing_headers)}",
                        remediation="Implement security headers"
                    )
                    vulns.append(vuln)
                
                # Check for server version disclosure
                server = headers.get('Server', '')
                if server and any(v in server for v in ['Apache/', 'nginx/', 'IIS/']):
                    vuln = Vulnerability(
                        vuln_id=hashlib.md5(f"{base_url}:server".encode()).hexdigest()[:12],
                        title="Server Version Disclosure",
                        description=f"Server header reveals version: {server}",
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        severity=Severity.LOW,
                        target=target.host,
                        port=target.port,
                        service='http',
                        evidence=f"Server: {server}",
                        remediation="Remove or mask server version in headers"
                    )
                    vulns.append(vuln)
        
        except Exception as e:
            logger.debug(f"HTTP check error: {e}")
        
        return vulns
    
    async def check_smb_vulns(self, target: ScanTarget) -> List[Vulnerability]:
        """Check SMB vulnerabilities"""
        vulns = []
        
        # Check for EternalBlue (MS17-010)
        # This would require actual SMB protocol interaction
        # Simplified check based on version
        if 'samba' in target.service.lower():
            version = target.version
            if version and any(v in version for v in ['3.', '4.0', '4.1', '4.2', '4.3', '4.4', '4.5']):
                vuln = Vulnerability(
                    vuln_id=hashlib.md5(f"{target.host}:445:samba".encode()).hexdigest()[:12],
                    title="Potentially Vulnerable Samba Version",
                    description="Older Samba version may be vulnerable to various CVEs",
                    vuln_type=VulnType.OUTDATED_SOFTWARE,
                    severity=Severity.HIGH,
                    target=target.host,
                    port=target.port,
                    service='smb',
                    evidence=f"Samba version: {version}",
                    remediation="Upgrade Samba to latest version"
                )
                vulns.append(vuln)
        
        return vulns
    
    async def check_ftp_vulns(self, target: ScanTarget) -> List[Vulnerability]:
        """Check FTP vulnerabilities"""
        vulns = []
        
        # Check for anonymous login
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port),
                timeout=5
            )
            
            # Read banner
            banner = await asyncio.wait_for(reader.readline(), timeout=5)
            banner = banner.decode().strip()
            
            # Try anonymous login
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=5)
            
            if b'331' in resp:
                writer.write(b"PASS anonymous@\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readline(), timeout=5)
                
                if b'230' in resp:
                    vuln = Vulnerability(
                        vuln_id=hashlib.md5(f"{target.host}:21:anon".encode()).hexdigest()[:12],
                        title="FTP Anonymous Login Allowed",
                        description="FTP server allows anonymous authentication",
                        vuln_type=VulnType.DEFAULT_CREDENTIALS,
                        severity=Severity.HIGH,
                        target=target.host,
                        port=target.port,
                        service='ftp',
                        evidence="Anonymous login successful",
                        remediation="Disable anonymous FTP access"
                    )
                    vulns.append(vuln)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"FTP check error: {e}")
        
        return vulns
    
    async def check_ssh_vulns(self, target: ScanTarget) -> List[Vulnerability]:
        """Check SSH vulnerabilities"""
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port),
                timeout=5
            )
            
            banner = await asyncio.wait_for(reader.readline(), timeout=5)
            banner = banner.decode().strip()
            
            # Check for weak algorithms in banner
            if 'SSH-1' in banner:
                vuln = Vulnerability(
                    vuln_id=hashlib.md5(f"{target.host}:22:ssh1".encode()).hexdigest()[:12],
                    title="SSH Protocol Version 1 Enabled",
                    description="Server supports deprecated SSH v1 protocol",
                    vuln_type=VulnType.WEAK_CRYPTO,
                    severity=Severity.HIGH,
                    target=target.host,
                    port=target.port,
                    service='ssh',
                    evidence=banner,
                    remediation="Disable SSH v1 protocol"
                )
                vulns.append(vuln)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"SSH check error: {e}")
        
        return vulns
    
    async def check_database_vulns(self, target: ScanTarget) -> List[Vulnerability]:
        """Check database vulnerabilities"""
        vulns = []
        
        # Check for unauthenticated access
        if target.port == 6379:  # Redis
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port),
                    timeout=5
                )
                
                writer.write(b"PING\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readline(), timeout=5)
                
                if b'PONG' in resp:
                    vuln = Vulnerability(
                        vuln_id=hashlib.md5(f"{target.host}:6379:noauth".encode()).hexdigest()[:12],
                        title="Redis No Authentication",
                        description="Redis server accessible without authentication",
                        vuln_type=VulnType.AUTHENTICATION,
                        severity=Severity.CRITICAL,
                        target=target.host,
                        port=target.port,
                        service='redis',
                        evidence="PING returned PONG without auth",
                        remediation="Enable Redis authentication"
                    )
                    vulns.append(vuln)
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                logger.debug(f"Redis check error: {e}")
        
        elif target.port == 27017:  # MongoDB
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port),
                    timeout=5
                )
                
                # MongoDB wire protocol - simplified check
                # Just check if we can connect
                vuln = Vulnerability(
                    vuln_id=hashlib.md5(f"{target.host}:27017:exposed".encode()).hexdigest()[:12],
                    title="MongoDB Exposed to Network",
                    description="MongoDB port is accessible from network",
                    vuln_type=VulnType.MISCONFIGURATION,
                    severity=Severity.HIGH,
                    target=target.host,
                    port=target.port,
                    service='mongodb',
                    evidence="Port 27017 accessible",
                    remediation="Restrict MongoDB network access"
                )
                vulns.append(vuln)
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                logger.debug(f"MongoDB check error: {e}")
        
        return vulns
    
    async def check_default_creds(self, target: ScanTarget) -> List[Vulnerability]:
        """Check for default credentials"""
        # This would require actual authentication attempts
        # Simplified for demonstration
        vulns = []
        
        service = target.service.lower()
        
        if service in self.db.DEFAULT_CREDS or target.port in [21, 22, 23, 3306, 5432]:
            vuln = Vulnerability(
                vuln_id=hashlib.md5(f"{target.host}:{target.port}:creds".encode()).hexdigest()[:12],
                title="Default Credentials Check Required",
                description=f"Service {service} should be checked for default credentials",
                vuln_type=VulnType.DEFAULT_CREDENTIALS,
                severity=Severity.INFO,
                target=target.host,
                port=target.port,
                service=service,
                evidence="Common service identified",
                remediation="Test for default credentials using Hydra"
            )
            vulns.append(vuln)
        
        return vulns
    
    async def check_misconfigurations(self, target: ScanTarget) -> List[Vulnerability]:
        """Check for common misconfigurations"""
        vulns = []
        
        # Check for services on unusual ports
        common_ports = {
            22: 'ssh', 21: 'ftp', 80: 'http', 443: 'https',
            3306: 'mysql', 5432: 'postgresql', 27017: 'mongodb'
        }
        
        service = target.service.lower()
        for expected_port, expected_service in common_ports.items():
            if expected_service in service and target.port != expected_port:
                vuln = Vulnerability(
                    vuln_id=hashlib.md5(f"{target.host}:{target.port}:port".encode()).hexdigest()[:12],
                    title="Service on Non-Standard Port",
                    description=f"{service} running on port {target.port} instead of {expected_port}",
                    vuln_type=VulnType.MISCONFIGURATION,
                    severity=Severity.INFO,
                    target=target.host,
                    port=target.port,
                    service=service,
                    evidence=f"Port {target.port} for {service}",
                    remediation="Document non-standard port usage"
                )
                vulns.append(vuln)
                break
        
        return vulns
    
    async def lookup_cve(self, cve_id: str) -> Optional[CVE]:
        """Lookup CVE from NVD"""
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key
            
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get('vulnerabilities'):
                        vuln_data = data['vulnerabilities'][0]['cve']
                        
                        # Parse CVSS
                        cvss = 0.0
                        severity = Severity.MEDIUM
                        metrics = vuln_data.get('metrics', {})
                        if 'cvssMetricV31' in metrics:
                            cvss = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                        elif 'cvssMetricV2' in metrics:
                            cvss = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                        
                        if cvss >= 9.0:
                            severity = Severity.CRITICAL
                        elif cvss >= 7.0:
                            severity = Severity.HIGH
                        elif cvss >= 4.0:
                            severity = Severity.MEDIUM
                        else:
                            severity = Severity.LOW
                        
                        return CVE(
                            cve_id=cve_id,
                            description=vuln_data['descriptions'][0]['value'],
                            severity=severity,
                            cvss_score=cvss,
                            published=datetime.fromisoformat(vuln_data['published'].replace('Z', '+00:00')),
                            modified=datetime.fromisoformat(vuln_data['lastModified'].replace('Z', '+00:00')),
                            references=[ref['url'] for ref in vuln_data.get('references', [])[:5]]
                        )
        
        except Exception as e:
            logger.error(f"CVE lookup error: {e}")
        
        return None
    
    async def search_cves(self, keyword: str, limit: int = 20) -> List[CVE]:
        """Search CVEs by keyword"""
        cves = []
        
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage={limit}"
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key
            
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for vuln in data.get('vulnerabilities', []):
                        vuln_data = vuln['cve']
                        
                        cvss = 0.0
                        severity = Severity.MEDIUM
                        metrics = vuln_data.get('metrics', {})
                        if 'cvssMetricV31' in metrics:
                            cvss = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                        elif 'cvssMetricV2' in metrics:
                            cvss = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                        
                        if cvss >= 9.0:
                            severity = Severity.CRITICAL
                        elif cvss >= 7.0:
                            severity = Severity.HIGH
                        elif cvss >= 4.0:
                            severity = Severity.MEDIUM
                        else:
                            severity = Severity.LOW
                        
                        cves.append(CVE(
                            cve_id=vuln_data['id'],
                            description=vuln_data['descriptions'][0]['value'][:200] + "...",
                            severity=severity,
                            cvss_score=cvss,
                            published=datetime.fromisoformat(vuln_data['published'].replace('Z', '+00:00')),
                            modified=datetime.fromisoformat(vuln_data['lastModified'].replace('Z', '+00:00'))
                        ))
        
        except Exception as e:
            logger.error(f"CVE search error: {e}")
        
        return cves
    
    def get_summary(self) -> Dict[str, Any]:
        """Get vulnerability scan summary"""
        severity_counts = {s.value: 0 for s in Severity}
        type_counts = {}
        
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity.value] += 1
            vtype = vuln.vuln_type.value
            type_counts[vtype] = type_counts.get(vtype, 0) + 1
        
        return {
            'total': len(self.vulnerabilities),
            'by_severity': severity_counts,
            'by_type': type_counts,
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'exploitable': sum(1 for v in self.vulnerabilities if v.cve and v.cve.exploit_available)
        }
    
    def export_report(self, format: str = 'json') -> str:
        """Export vulnerabilities report"""
        if format == 'json':
            return json.dumps({
                'summary': self.get_summary(),
                'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
            }, indent=2)
        
        elif format == 'csv':
            lines = ['CVE,Title,Severity,CVSS,Target,Port,Type']
            for v in self.vulnerabilities:
                cve_id = v.cve.cve_id if v.cve else '-'
                lines.append(f'{cve_id},"{v.title}",{v.severity.value},{v.cvss_score},{v.target},{v.port},{v.vuln_type.value}')
            return '\n'.join(lines)
        
        return ""
