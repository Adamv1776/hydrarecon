#!/usr/bin/env python3
"""
HydraRecon AI Engine
████████████████████████████████████████████████████████████████████████████████
█  NEXT-GEN AI-POWERED SECURITY ANALYSIS - Beyond Traditional Vulnerability    █
█  Assessment with Machine Learning, Pattern Recognition, and Predictive       █
█  Threat Modeling                                                              █
████████████████████████████████████████████████████████████████████████████████
"""

import json
import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Set
from enum import Enum
import asyncio


class ThreatLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


class AttackVector(Enum):
    NETWORK = "network"
    ADJACENT = "adjacent"
    LOCAL = "local"
    PHYSICAL = "physical"


@dataclass
class VulnerabilityProfile:
    """Comprehensive vulnerability profile"""
    cve_id: Optional[str] = None
    name: str = ""
    description: str = ""
    severity: ThreatLevel = ThreatLevel.INFO
    cvss_score: float = 0.0
    attack_vector: AttackVector = AttackVector.NETWORK
    exploitability: float = 0.0  # 0-10
    impact: float = 0.0  # 0-10
    affected_services: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_maturity: str = "unknown"  # POC, functional, high
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class ExploitSuggestion:
    """AI-generated exploit suggestion"""
    vulnerability: VulnerabilityProfile
    exploit_name: str
    exploit_type: str  # remote, local, webapp, dos
    framework: str  # metasploit, custom, manual
    module_path: str
    success_probability: float  # 0-100
    prerequisites: List[str] = field(default_factory=list)
    payload_options: List[str] = field(default_factory=list)
    evasion_techniques: List[str] = field(default_factory=list)
    post_exploitation: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class AttackPath:
    """Attack path from entry to objective"""
    path_id: str
    name: str
    entry_point: str
    objective: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    total_probability: float = 0.0
    risk_score: float = 0.0
    time_estimate: str = ""
    skill_required: str = ""  # low, medium, high, expert
    detection_risk: str = ""  # low, medium, high
    mitigations: List[str] = field(default_factory=list)


class VulnerabilityKnowledgeBase:
    """
    Comprehensive vulnerability knowledge base with 
    pattern matching and exploit correlation
    """
    
    # Service signature to vulnerability mapping
    SERVICE_VULNS = {
        # SSH Vulnerabilities
        "openssh": {
            "patterns": [
                (r"OpenSSH[_\s]([0-6]\.\d)", "CVE-2016-0777", "SSH Roaming Buffer Overflow", ThreatLevel.HIGH),
                (r"OpenSSH[_\s](7\.[0-1])", "CVE-2016-6210", "User Enumeration", ThreatLevel.MEDIUM),
                (r"OpenSSH[_\s](7\.[0-6])", "CVE-2018-15473", "User Enumeration", ThreatLevel.MEDIUM),
                (r"OpenSSH[_\s]([0-7]\.[0-8])", "CVE-2020-15778", "Command Injection via scp", ThreatLevel.HIGH),
            ],
            "default_ports": [22],
            "attack_type": "remote"
        },
        
        # Apache Vulnerabilities
        "apache": {
            "patterns": [
                (r"Apache/2\.4\.(0|1[0-9]|2[0-9]|3[0-9]|4[0-9])\s", "CVE-2021-41773", "Path Traversal", ThreatLevel.CRITICAL),
                (r"Apache/2\.4\.50", "CVE-2021-42013", "Path Traversal RCE", ThreatLevel.CRITICAL),
                (r"Apache/2\.4\.(1[0-7]|[0-9])\s", "CVE-2017-15715", "File Upload Bypass", ThreatLevel.HIGH),
                (r"Apache/2\.2\.", "CVE-2017-3167", "Authentication Bypass", ThreatLevel.HIGH),
            ],
            "default_ports": [80, 443, 8080],
            "attack_type": "webapp"
        },
        
        # Nginx Vulnerabilities
        "nginx": {
            "patterns": [
                (r"nginx/(0\.|1\.([0-9]|1[0-3])\.)", "CVE-2013-4547", "Security Bypass", ThreatLevel.HIGH),
                (r"nginx/1\.(1[4-7])\.", "CVE-2019-20372", "HTTP Request Smuggling", ThreatLevel.MEDIUM),
            ],
            "default_ports": [80, 443],
            "attack_type": "webapp"
        },
        
        # MySQL/MariaDB Vulnerabilities
        "mysql": {
            "patterns": [
                (r"MySQL\s+(5\.[0-5]\.|[0-4]\.)", "CVE-2012-2122", "Authentication Bypass", ThreatLevel.CRITICAL),
                (r"MySQL\s+5\.6\.[0-9]\s", "CVE-2014-6568", "Privilege Escalation", ThreatLevel.HIGH),
                (r"MariaDB", "CVE-2021-27928", "Command Execution", ThreatLevel.HIGH),
            ],
            "default_ports": [3306],
            "attack_type": "remote"
        },
        
        # PostgreSQL Vulnerabilities
        "postgresql": {
            "patterns": [
                (r"PostgreSQL\s+([0-8]\.|9\.[0-3])", "CVE-2019-9193", "Arbitrary Code Execution", ThreatLevel.CRITICAL),
                (r"PostgreSQL\s+(9\.[4-6]|10\.[0-6]|11\.[0-1])", "CVE-2019-10164", "Stack Buffer Overflow", ThreatLevel.HIGH),
            ],
            "default_ports": [5432],
            "attack_type": "remote"
        },
        
        # SMB/Samba Vulnerabilities
        "smb": {
            "patterns": [
                (r"Samba\s+([0-2]\.|3\.[0-5])", "CVE-2017-7494", "SambaCry RCE", ThreatLevel.CRITICAL),
                (r"Windows.*SMBv1", "CVE-2017-0144", "EternalBlue", ThreatLevel.CRITICAL),
                (r"Samba\s+4\.[0-4]", "CVE-2015-0240", "RCE via Netlogon", ThreatLevel.CRITICAL),
            ],
            "default_ports": [139, 445],
            "attack_type": "remote"
        },
        
        # FTP Vulnerabilities
        "ftp": {
            "patterns": [
                (r"vsftpd\s+2\.3\.4", "CVE-2011-2523", "Backdoor Command Execution", ThreatLevel.CRITICAL),
                (r"ProFTPD\s+1\.3\.[0-3]", "CVE-2015-3306", "mod_copy RCE", ThreatLevel.CRITICAL),
                (r"FileZilla", "CVE-2019-5429", "Remote Code Execution", ThreatLevel.HIGH),
            ],
            "default_ports": [21],
            "attack_type": "remote"
        },
        
        # Redis Vulnerabilities
        "redis": {
            "patterns": [
                (r"Redis\s+([0-5]\.|6\.[0-1])", "CVE-2022-0543", "Lua Sandbox Escape RCE", ThreatLevel.CRITICAL),
                (r"Redis", "No-Auth", "Unauthenticated Access", ThreatLevel.CRITICAL),
            ],
            "default_ports": [6379],
            "attack_type": "remote"
        },
        
        # MongoDB Vulnerabilities  
        "mongodb": {
            "patterns": [
                (r"MongoDB\s+([0-2]\.|3\.[0-3])", "CVE-2017-2665", "Authentication Bypass", ThreatLevel.CRITICAL),
                (r"MongoDB", "No-Auth", "Unauthenticated Access", ThreatLevel.CRITICAL),
            ],
            "default_ports": [27017],
            "attack_type": "remote"
        },
        
        # Elasticsearch Vulnerabilities
        "elasticsearch": {
            "patterns": [
                (r"Elasticsearch\s+(1\.[0-3])", "CVE-2014-3120", "Remote Code Execution", ThreatLevel.CRITICAL),
                (r"Elasticsearch\s+(1\.4\.[0-2]|1\.[0-3])", "CVE-2015-1427", "Groovy Sandbox Bypass RCE", ThreatLevel.CRITICAL),
            ],
            "default_ports": [9200, 9300],
            "attack_type": "remote"
        },
        
        # Tomcat Vulnerabilities
        "tomcat": {
            "patterns": [
                (r"Tomcat/([0-6]\.|7\.[0-6]\.|8\.[0-4]\.)", "CVE-2017-12617", "JSP Upload RCE", ThreatLevel.CRITICAL),
                (r"Tomcat/(8\.5\.[0-30]|9\.0\.[0-1])", "CVE-2020-1938", "Ghostcat File Read/RCE", ThreatLevel.CRITICAL),
                (r"Tomcat/8\.0", "CVE-2016-1240", "Privilege Escalation", ThreatLevel.HIGH),
            ],
            "default_ports": [8080, 8443],
            "attack_type": "webapp"
        },
        
        # Jenkins Vulnerabilities
        "jenkins": {
            "patterns": [
                (r"Jenkins\s+(1\.|2\.[0-9]{1,2}[^0-9]|2\.1[0-3])", "CVE-2019-1003000", "Script Security Sandbox Bypass", ThreatLevel.CRITICAL),
                (r"Jenkins", "CVE-2018-1000861", "Remote Code Execution", ThreatLevel.CRITICAL),
            ],
            "default_ports": [8080],
            "attack_type": "webapp"
        },
        
        # PHP Vulnerabilities
        "php": {
            "patterns": [
                (r"PHP/(5\.[0-4]|[0-4]\.)", "CVE-2012-1823", "CGI Argument Injection", ThreatLevel.CRITICAL),
                (r"PHP/7\.[0-3]\.", "CVE-2019-11043", "PHP-FPM RCE", ThreatLevel.CRITICAL),
                (r"PHP/8\.0\.[0-9]\s", "CVE-2021-21702", "SOAP Null Dereference", ThreatLevel.MEDIUM),
            ],
            "default_ports": [80, 443],
            "attack_type": "webapp"
        },
        
        # IIS Vulnerabilities
        "iis": {
            "patterns": [
                (r"IIS/(5\.|6\.0)", "CVE-2017-7269", "WebDAV Buffer Overflow RCE", ThreatLevel.CRITICAL),
                (r"IIS/7\.[05]", "CVE-2010-3972", "FTP Service Buffer Overflow", ThreatLevel.HIGH),
            ],
            "default_ports": [80, 443],
            "attack_type": "webapp"
        },
        
        # WordPress Vulnerabilities
        "wordpress": {
            "patterns": [
                (r"WordPress\s+([0-4]\.|5\.[0-7])", "Multiple", "Multiple Plugin/Theme Vulns", ThreatLevel.HIGH),
                (r"WordPress", "CVE-2021-29447", "XXE in Media Library", ThreatLevel.HIGH),
            ],
            "default_ports": [80, 443],
            "attack_type": "webapp"
        },
        
        # Docker Vulnerabilities
        "docker": {
            "patterns": [
                (r"Docker/(1[0-7]\.|18\.[0-8])", "CVE-2019-5736", "runC Container Escape", ThreatLevel.CRITICAL),
                (r"Docker.*API", "No-Auth", "Unauthenticated Docker API", ThreatLevel.CRITICAL),
            ],
            "default_ports": [2375, 2376],
            "attack_type": "remote"
        },
        
        # Kubernetes Vulnerabilities
        "kubernetes": {
            "patterns": [
                (r"Kubernetes/(1\.[0-9]|1\.1[0-5])", "CVE-2018-1002105", "Privilege Escalation", ThreatLevel.CRITICAL),
                (r"etcd", "No-Auth", "Unauthenticated etcd", ThreatLevel.CRITICAL),
            ],
            "default_ports": [6443, 8443, 10250],
            "attack_type": "remote"
        },
    }
    
    # Metasploit module mappings
    EXPLOIT_MODULES = {
        "CVE-2017-0144": {
            "msf": "exploit/windows/smb/ms17_010_eternalblue",
            "name": "EternalBlue SMB Remote Code Execution",
            "payloads": ["windows/x64/meterpreter/reverse_tcp", "windows/x64/shell/reverse_tcp"],
            "success_rate": 95
        },
        "CVE-2017-7494": {
            "msf": "exploit/linux/samba/is_known_pipename",
            "name": "Samba is_known_pipename() RCE",
            "payloads": ["linux/x64/meterpreter/reverse_tcp", "cmd/unix/reverse_netcat"],
            "success_rate": 85
        },
        "CVE-2021-41773": {
            "msf": "exploit/multi/http/apache_normalize_path_rce",
            "name": "Apache Path Traversal RCE",
            "payloads": ["linux/x64/meterpreter/reverse_tcp"],
            "success_rate": 90
        },
        "CVE-2020-1938": {
            "msf": "exploit/multi/http/tomcat_mgr_upload",
            "name": "Tomcat Ghostcat",
            "payloads": ["java/meterpreter/reverse_tcp"],
            "success_rate": 80
        },
        "CVE-2011-2523": {
            "msf": "exploit/unix/ftp/vsftpd_234_backdoor",
            "name": "vsftpd Backdoor",
            "payloads": ["cmd/unix/interact"],
            "success_rate": 100
        },
        "CVE-2015-3306": {
            "msf": "exploit/unix/ftp/proftpd_modcopy_exec",
            "name": "ProFTPD mod_copy RCE",
            "payloads": ["cmd/unix/reverse_perl"],
            "success_rate": 75
        },
        "CVE-2019-5736": {
            "msf": "exploit/linux/local/docker_runc_escape",
            "name": "Docker runC Escape",
            "payloads": ["linux/x64/meterpreter/reverse_tcp"],
            "success_rate": 70
        },
        "CVE-2012-2122": {
            "msf": "auxiliary/scanner/mysql/mysql_authbypass_hashdump",
            "name": "MySQL Authentication Bypass",
            "payloads": [],
            "success_rate": 60
        },
        "CVE-2017-12617": {
            "msf": "exploit/multi/http/tomcat_jsp_upload_bypass",
            "name": "Tomcat JSP Upload Bypass",
            "payloads": ["java/meterpreter/reverse_tcp"],
            "success_rate": 85
        },
        "CVE-2022-0543": {
            "msf": "exploit/linux/redis/redis_debian_sandbox_escape",
            "name": "Redis Lua Sandbox Escape",
            "payloads": ["linux/x64/meterpreter/reverse_tcp"],
            "success_rate": 90
        },
    }
    
    # Common web vulnerability patterns
    WEB_VULNS = {
        "sql_injection": {
            "patterns": [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"PostgreSQL.*ERROR",
                r"ORA-[0-9]{5}",
                r"Microsoft.*ODBC.*SQL Server",
                r"Unclosed quotation mark",
                r"SQLSTATE\[",
            ],
            "severity": ThreatLevel.CRITICAL,
            "cvss": 9.8
        },
        "xss": {
            "patterns": [
                r"<script[^>]*>",
                r"javascript:",
                r"onerror\s*=",
                r"onclick\s*=",
            ],
            "severity": ThreatLevel.HIGH,
            "cvss": 6.1
        },
        "lfi": {
            "patterns": [
                r"root:x:0:0:",
                r"\[boot loader\]",
                r"include_path",
                r"No such file or directory",
            ],
            "severity": ThreatLevel.HIGH,
            "cvss": 7.5
        },
        "rfi": {
            "patterns": [
                r"failed to open stream: HTTP",
                r"include\(\): http://",
            ],
            "severity": ThreatLevel.CRITICAL,
            "cvss": 9.8
        },
        "xxe": {
            "patterns": [
                r"SYSTEM.*file://",
                r"DOCTYPE.*ENTITY",
            ],
            "severity": ThreatLevel.HIGH,
            "cvss": 7.5
        },
        "ssrf": {
            "patterns": [
                r"Connection refused",
                r"getaddrinfo.*failed",
            ],
            "severity": ThreatLevel.HIGH,
            "cvss": 7.2
        },
        "command_injection": {
            "patterns": [
                r"sh:.*not found",
                r"cmd\.exe",
                r"root:.*:0:0:",
            ],
            "severity": ThreatLevel.CRITICAL,
            "cvss": 9.8
        },
    }
    
    def __init__(self):
        self.custom_patterns = []
        self.learned_vulns = {}
    
    def add_custom_pattern(self, service: str, pattern: str, cve: str, 
                          name: str, severity: ThreatLevel):
        """Add custom vulnerability pattern"""
        self.custom_patterns.append({
            "service": service,
            "pattern": pattern,
            "cve": cve,
            "name": name,
            "severity": severity
        })
    
    def analyze_banner(self, banner: str, port: int = None) -> List[VulnerabilityProfile]:
        """Analyze service banner for vulnerabilities"""
        vulnerabilities = []
        banner_lower = banner.lower()
        
        for service, data in self.SERVICE_VULNS.items():
            if service in banner_lower or (port and port in data.get("default_ports", [])):
                for pattern, cve, name, severity in data["patterns"]:
                    if re.search(pattern, banner, re.IGNORECASE):
                        vuln = VulnerabilityProfile(
                            cve_id=cve,
                            name=name,
                            description=f"Detected vulnerable {service} version",
                            severity=severity,
                            affected_services=[service],
                            attack_vector=AttackVector.NETWORK,
                            exploit_available=cve in self.EXPLOIT_MODULES,
                            tags=[service, data.get("attack_type", "remote")]
                        )
                        
                        if cve in self.EXPLOIT_MODULES:
                            vuln.exploit_maturity = "functional"
                            vuln.exploitability = 8.0
                        
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def get_exploit_suggestion(self, vuln: VulnerabilityProfile) -> Optional[ExploitSuggestion]:
        """Get exploit suggestion for vulnerability"""
        if vuln.cve_id and vuln.cve_id in self.EXPLOIT_MODULES:
            module = self.EXPLOIT_MODULES[vuln.cve_id]
            return ExploitSuggestion(
                vulnerability=vuln,
                exploit_name=module["name"],
                exploit_type="remote",
                framework="metasploit",
                module_path=module["msf"],
                success_probability=module["success_rate"],
                payload_options=module["payloads"],
                prerequisites=["Network access to target"],
                evasion_techniques=["Use staged payloads", "Encode payload", "Use SSL"],
                post_exploitation=["hashdump", "migrate", "persistence"]
            )
        return None


class AISecurityAnalyzer:
    """
    AI-powered security analysis engine
    Provides intelligent vulnerability assessment and attack path modeling
    """
    
    def __init__(self, config=None):
        self.config = config
        self.kb = VulnerabilityKnowledgeBase()
        self.scan_history = []
        self.learned_patterns = {}
    
    def analyze_scan_results(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive AI analysis of scan results
        Returns prioritized findings with exploit suggestions
        """
        analysis = {
            "summary": {},
            "vulnerabilities": [],
            "exploit_suggestions": [],
            "attack_paths": [],
            "risk_score": 0,
            "recommendations": [],
            "executive_summary": ""
        }
        
        hosts = scan_data.get("hosts", [])
        all_vulns = []
        
        for host in hosts:
            host_vulns = self._analyze_host(host)
            all_vulns.extend(host_vulns)
        
        # Deduplicate and prioritize
        unique_vulns = self._deduplicate_vulns(all_vulns)
        prioritized = self._prioritize_vulnerabilities(unique_vulns)
        
        analysis["vulnerabilities"] = prioritized
        
        # Generate exploit suggestions
        for vuln in prioritized:
            suggestion = self.kb.get_exploit_suggestion(vuln)
            if suggestion:
                analysis["exploit_suggestions"].append(suggestion)
        
        # Model attack paths
        analysis["attack_paths"] = self._model_attack_paths(hosts, prioritized)
        
        # Calculate risk score
        analysis["risk_score"] = self._calculate_risk_score(prioritized)
        
        # Generate recommendations
        analysis["recommendations"] = self._generate_recommendations(prioritized)
        
        # Executive summary
        analysis["executive_summary"] = self._generate_executive_summary(analysis)
        
        analysis["summary"] = {
            "total_hosts": len(hosts),
            "total_vulnerabilities": len(prioritized),
            "critical": len([v for v in prioritized if v.severity == ThreatLevel.CRITICAL]),
            "high": len([v for v in prioritized if v.severity == ThreatLevel.HIGH]),
            "medium": len([v for v in prioritized if v.severity == ThreatLevel.MEDIUM]),
            "low": len([v for v in prioritized if v.severity == ThreatLevel.LOW]),
            "exploitable": len(analysis["exploit_suggestions"]),
            "attack_paths": len(analysis["attack_paths"])
        }
        
        return analysis
    
    def _analyze_host(self, host: Dict) -> List[VulnerabilityProfile]:
        """Analyze a single host for vulnerabilities"""
        vulns = []
        
        for port_info in host.get("ports", []):
            port = port_info.get("port")
            service = port_info.get("service", "")
            version = port_info.get("version", "")
            banner = f"{service} {version}"
            
            # Analyze service banner
            detected = self.kb.analyze_banner(banner, port)
            for v in detected:
                v.affected_services.append(f"{host.get('ip')}:{port}")
            vulns.extend(detected)
            
            # Check for common misconfigurations
            vulns.extend(self._check_misconfigurations(port_info, host))
        
        return vulns
    
    def _check_misconfigurations(self, port_info: Dict, host: Dict) -> List[VulnerabilityProfile]:
        """Check for common misconfigurations"""
        vulns = []
        port = port_info.get("port")
        service = port_info.get("service", "").lower()
        
        # Unencrypted services on sensitive ports
        if port in [21, 23, 110, 143] and "ssl" not in service and "tls" not in service:
            vulns.append(VulnerabilityProfile(
                name="Unencrypted Service",
                description=f"Service on port {port} is not encrypted",
                severity=ThreatLevel.MEDIUM,
                affected_services=[f"{host.get('ip')}:{port}"],
                tags=["misconfiguration", "encryption"]
            ))
        
        # Default credentials ports
        if port in [22, 3389, 5900]:
            vulns.append(VulnerabilityProfile(
                name="Potential Default Credentials",
                description=f"Remote access service on port {port} may have default credentials",
                severity=ThreatLevel.MEDIUM,
                affected_services=[f"{host.get('ip')}:{port}"],
                tags=["credentials", "bruteforce"]
            ))
        
        # Exposed database ports
        if port in [3306, 5432, 27017, 6379, 9200]:
            vulns.append(VulnerabilityProfile(
                name="Exposed Database Port",
                description=f"Database service exposed on port {port}",
                severity=ThreatLevel.HIGH,
                affected_services=[f"{host.get('ip')}:{port}"],
                tags=["database", "exposure"]
            ))
        
        # Exposed management interfaces
        if port in [8080, 8443, 9090, 10000]:
            vulns.append(VulnerabilityProfile(
                name="Management Interface Exposed",
                description=f"Management interface on port {port}",
                severity=ThreatLevel.MEDIUM,
                affected_services=[f"{host.get('ip')}:{port}"],
                tags=["management", "exposure"]
            ))
        
        return vulns
    
    def _deduplicate_vulns(self, vulns: List[VulnerabilityProfile]) -> List[VulnerabilityProfile]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique = []
        
        for v in vulns:
            key = f"{v.cve_id or v.name}_{v.severity}"
            if key not in seen:
                seen.add(key)
                unique.append(v)
        
        return unique
    
    def _prioritize_vulnerabilities(self, vulns: List[VulnerabilityProfile]) -> List[VulnerabilityProfile]:
        """Prioritize vulnerabilities by risk"""
        def priority_score(v):
            score = v.severity.value * 20
            if v.exploit_available:
                score += 30
            if v.exploitability > 0:
                score += v.exploitability * 5
            return score
        
        return sorted(vulns, key=priority_score, reverse=True)
    
    def _model_attack_paths(self, hosts: List[Dict], 
                           vulns: List[VulnerabilityProfile]) -> List[AttackPath]:
        """Model potential attack paths through the network"""
        paths = []
        
        # Find entry points (external-facing vulnerable services)
        entry_points = []
        for v in vulns:
            if v.severity in [ThreatLevel.CRITICAL, ThreatLevel.HIGH] and v.exploit_available:
                entry_points.append(v)
        
        # Generate attack paths
        for i, entry in enumerate(entry_points[:5]):  # Top 5 entry points
            steps = []
            
            # Initial exploitation
            steps.append({
                "step": 1,
                "action": "Initial Exploitation",
                "target": entry.affected_services[0] if entry.affected_services else "unknown",
                "vulnerability": entry.cve_id or entry.name,
                "technique": "Remote exploit",
                "probability": 0.8 if entry.exploit_available else 0.4
            })
            
            # Post-exploitation
            steps.append({
                "step": 2,
                "action": "Privilege Escalation",
                "technique": "Local exploit or credential theft",
                "probability": 0.6
            })
            
            # Lateral movement
            if len(hosts) > 1:
                steps.append({
                    "step": 3,
                    "action": "Lateral Movement",
                    "technique": "Pass-the-hash, SSH key reuse, or credential stuffing",
                    "probability": 0.5
                })
            
            # Objective
            steps.append({
                "step": len(steps) + 1,
                "action": "Objective Achievement",
                "technique": "Data exfiltration or persistence",
                "probability": 0.7
            })
            
            total_prob = 1.0
            for s in steps:
                total_prob *= s["probability"]
            
            path = AttackPath(
                path_id=f"AP-{i+1:03d}",
                name=f"Attack via {entry.name}",
                entry_point=entry.affected_services[0] if entry.affected_services else "unknown",
                objective="Domain Admin / Data Exfiltration",
                steps=steps,
                total_probability=round(total_prob * 100, 1),
                risk_score=entry.severity.value * 20 * total_prob,
                time_estimate="1-4 hours",
                skill_required="medium" if entry.exploit_available else "high",
                detection_risk="medium",
                mitigations=[
                    f"Patch {entry.cve_id}" if entry.cve_id else "Update vulnerable service",
                    "Implement network segmentation",
                    "Deploy IDS/IPS",
                    "Enable logging and monitoring"
                ]
            )
            paths.append(path)
        
        return sorted(paths, key=lambda p: p.risk_score, reverse=True)
    
    def _calculate_risk_score(self, vulns: List[VulnerabilityProfile]) -> int:
        """Calculate overall risk score (0-100)"""
        if not vulns:
            return 0
        
        severity_weights = {
            ThreatLevel.CRITICAL: 25,
            ThreatLevel.HIGH: 15,
            ThreatLevel.MEDIUM: 8,
            ThreatLevel.LOW: 3,
            ThreatLevel.INFO: 1
        }
        
        total = sum(severity_weights.get(v.severity, 1) for v in vulns)
        exploitable_bonus = len([v for v in vulns if v.exploit_available]) * 10
        
        score = min(100, (total + exploitable_bonus) // max(len(vulns), 1) * 5)
        return score
    
    def _generate_recommendations(self, vulns: List[VulnerabilityProfile]) -> List[Dict]:
        """Generate prioritized security recommendations"""
        recommendations = []
        
        # Group by type
        critical_vulns = [v for v in vulns if v.severity == ThreatLevel.CRITICAL]
        high_vulns = [v for v in vulns if v.severity == ThreatLevel.HIGH]
        
        if critical_vulns:
            recommendations.append({
                "priority": "CRITICAL",
                "title": "Immediate Patching Required",
                "description": f"Patch {len(critical_vulns)} critical vulnerabilities immediately",
                "affected": [v.cve_id or v.name for v in critical_vulns],
                "effort": "High",
                "impact": "Critical risk reduction"
            })
        
        if high_vulns:
            recommendations.append({
                "priority": "HIGH",
                "title": "High Priority Patching",
                "description": f"Address {len(high_vulns)} high-severity vulnerabilities within 48 hours",
                "affected": [v.cve_id or v.name for v in high_vulns],
                "effort": "Medium-High",
                "impact": "Significant risk reduction"
            })
        
        # Check for exposed databases
        db_vulns = [v for v in vulns if "database" in v.tags]
        if db_vulns:
            recommendations.append({
                "priority": "HIGH",
                "title": "Secure Database Access",
                "description": "Restrict database access to authorized hosts only",
                "affected": [v.affected_services for v in db_vulns],
                "effort": "Low",
                "impact": "Prevents unauthorized data access"
            })
        
        # General recommendations
        recommendations.append({
            "priority": "MEDIUM",
            "title": "Implement Network Segmentation",
            "description": "Isolate critical systems to limit lateral movement",
            "effort": "Medium",
            "impact": "Reduces blast radius of breaches"
        })
        
        recommendations.append({
            "priority": "MEDIUM",
            "title": "Enable Comprehensive Logging",
            "description": "Ensure all systems log authentication and access events",
            "effort": "Low",
            "impact": "Improves incident detection and response"
        })
        
        return recommendations
    
    def _generate_executive_summary(self, analysis: Dict) -> str:
        """Generate executive summary"""
        summary = analysis["summary"]
        risk = analysis["risk_score"]
        
        risk_level = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else "MEDIUM" if risk >= 40 else "LOW"
        
        text = f"""EXECUTIVE SUMMARY
================

Overall Risk Level: {risk_level} ({risk}/100)

Assessment Overview:
- {summary['total_hosts']} hosts analyzed
- {summary['total_vulnerabilities']} vulnerabilities identified
- {summary['exploitable']} vulnerabilities have known exploits
- {summary['attack_paths']} potential attack paths modeled

Critical Findings:
- {summary['critical']} Critical severity issues
- {summary['high']} High severity issues
- {summary['medium']} Medium severity issues

Immediate Actions Required:
1. Patch all critical vulnerabilities within 24 hours
2. Review and restrict exposed database services
3. Implement network segmentation for critical assets
4. Enable logging and monitoring on all systems

The assessment identified {summary['exploitable']} vulnerabilities with publicly available exploits, 
representing immediate risk to the organization. Attack path analysis shows potential for 
complete network compromise through {summary['attack_paths']} identified paths.
"""
        return text
    
    def generate_metasploit_resource(self, suggestions: List[ExploitSuggestion]) -> str:
        """Generate Metasploit resource script"""
        script_lines = [
            "# HydraRecon Auto-Generated Metasploit Resource Script",
            f"# Generated: {datetime.now().isoformat()}",
            "#" + "=" * 60,
            ""
        ]
        
        for i, suggestion in enumerate(suggestions):
            script_lines.append(f"# Exploit {i+1}: {suggestion.exploit_name}")
            script_lines.append(f"use {suggestion.module_path}")
            
            if suggestion.payload_options:
                script_lines.append(f"set PAYLOAD {suggestion.payload_options[0]}")
            
            script_lines.append("set RHOSTS <TARGET_IP>")
            script_lines.append("set LHOST <YOUR_IP>")
            script_lines.append("# run")
            script_lines.append("")
        
        return "\n".join(script_lines)
