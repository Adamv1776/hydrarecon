#!/usr/bin/env python3
"""
HydraRecon AI Security Assistant
Provides intelligent analysis and recommendations for security assessments.
"""

import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SecurityFinding:
    """Represents a security finding"""
    severity: str  # critical, high, medium, low, info
    category: str
    title: str
    description: str
    recommendation: str
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


class AISecurityAssistant:
    """
    AI-powered security analysis assistant.
    Provides intelligent insights without external API dependencies.
    """
    
    # Known vulnerable service patterns
    VULNERABLE_SERVICES = {
        'vsftpd 2.3.4': {
            'severity': 'critical',
            'title': 'vsFTPd 2.3.4 Backdoor',
            'cve': 'CVE-2011-2523',
            'description': 'This version contains a backdoor that allows remote code execution.',
            'recommendation': 'Upgrade vsFTPd immediately to version 3.0.0 or later.'
        },
        'openssh 4': {
            'severity': 'high',
            'title': 'Outdated OpenSSH Version',
            'description': 'OpenSSH 4.x has multiple known vulnerabilities.',
            'recommendation': 'Upgrade to OpenSSH 8.x or later.'
        },
        'apache 2.2': {
            'severity': 'high',
            'title': 'Apache 2.2.x End of Life',
            'description': 'Apache 2.2 is no longer supported and has multiple vulnerabilities.',
            'recommendation': 'Upgrade to Apache 2.4.x with latest security patches.'
        },
        'proftpd 1.3.3': {
            'severity': 'critical',
            'title': 'ProFTPD 1.3.3c Backdoor',
            'cve': 'CVE-2010-4221',
            'description': 'This version may contain a backdoor from a compromised source.',
            'recommendation': 'Verify installation source and upgrade to latest version.'
        },
        'samba 3': {
            'severity': 'critical',
            'title': 'Samba 3.x Vulnerabilities',
            'cve': 'CVE-2017-7494',
            'description': 'Samba 3.x is vulnerable to remote code execution.',
            'recommendation': 'Upgrade to Samba 4.x with latest patches.'
        },
        'mysql 5.0': {
            'severity': 'high',
            'title': 'MySQL 5.0 End of Life',
            'description': 'MySQL 5.0 is no longer supported.',
            'recommendation': 'Upgrade to MySQL 8.0 or MariaDB 10.x.'
        },
        'php 5': {
            'severity': 'high',
            'title': 'PHP 5.x End of Life',
            'description': 'PHP 5 is no longer supported and has critical vulnerabilities.',
            'recommendation': 'Upgrade to PHP 8.x immediately.'
        },
        'tomcat 6': {
            'severity': 'high',
            'title': 'Apache Tomcat 6 End of Life',
            'description': 'Tomcat 6 is no longer maintained.',
            'recommendation': 'Upgrade to Tomcat 9 or 10.'
        },
    }
    
    # Port risk assessments
    HIGH_RISK_PORTS = {
        21: ('FTP', 'high', 'FTP transmits credentials in cleartext'),
        23: ('Telnet', 'critical', 'Telnet is unencrypted - use SSH instead'),
        25: ('SMTP', 'medium', 'Open mail relay potential'),
        69: ('TFTP', 'high', 'TFTP has no authentication'),
        110: ('POP3', 'medium', 'Unencrypted email retrieval'),
        111: ('RPC', 'high', 'RPC can expose internal services'),
        135: ('MSRPC', 'high', 'Windows RPC - common attack vector'),
        139: ('NetBIOS', 'high', 'NetBIOS exposes file shares'),
        143: ('IMAP', 'medium', 'Unencrypted email access'),
        161: ('SNMP', 'high', 'SNMP v1/v2 has weak authentication'),
        445: ('SMB', 'critical', 'SMB is a major attack vector (EternalBlue)'),
        512: ('rexec', 'critical', 'Remote execution without encryption'),
        513: ('rlogin', 'critical', 'Remote login without encryption'),
        514: ('rsh', 'critical', 'Remote shell without encryption'),
        1433: ('MSSQL', 'high', 'Database exposed to network'),
        1521: ('Oracle', 'high', 'Database exposed to network'),
        2049: ('NFS', 'high', 'Network file system can expose sensitive data'),
        3306: ('MySQL', 'high', 'Database exposed to network'),
        3389: ('RDP', 'high', 'Remote Desktop is common attack target'),
        5432: ('PostgreSQL', 'high', 'Database exposed to network'),
        5900: ('VNC', 'high', 'VNC often has weak authentication'),
        6379: ('Redis', 'critical', 'Redis often has no authentication'),
        27017: ('MongoDB', 'critical', 'MongoDB often has no authentication'),
    }
    
    # Common default credentials
    DEFAULT_CREDS = {
        'ssh': [('root', 'root'), ('root', 'toor'), ('admin', 'admin'), ('admin', 'password')],
        'ftp': [('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin')],
        'mysql': [('root', ''), ('root', 'root'), ('mysql', 'mysql')],
        'postgres': [('postgres', 'postgres'), ('admin', 'admin')],
        'mongodb': [('admin', 'admin'), ('root', 'root')],
        'redis': [('', '')],  # Often no auth
        'vnc': [('', 'password'), ('', '1234')],
        'tomcat': [('tomcat', 'tomcat'), ('admin', 'admin'), ('manager', 'manager')],
    }
    
    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.scan_history: List[Dict] = []
    
    def analyze_nmap_results(self, scan_data: Dict) -> List[SecurityFinding]:
        """Analyze Nmap scan results and provide security insights"""
        findings = []
        
        hosts = scan_data.get('hosts', [])
        for host in hosts:
            host_ip = host.get('address', 'Unknown')
            
            # Analyze each port/service
            for port_info in host.get('ports', []):
                port = port_info.get('port', 0)
                service = port_info.get('service', '').lower()
                version = port_info.get('version', '').lower()
                state = port_info.get('state', '')
                
                if state != 'open':
                    continue
                
                # Check for high-risk ports
                if port in self.HIGH_RISK_PORTS:
                    svc_name, severity, reason = self.HIGH_RISK_PORTS[port]
                    findings.append(SecurityFinding(
                        severity=severity,
                        category='Network Exposure',
                        title=f'{svc_name} Service Exposed ({host_ip}:{port})',
                        description=reason,
                        recommendation=self._get_port_recommendation(port)
                    ))
                
                # Check for vulnerable service versions
                full_service = f"{service} {version}"
                for pattern, vuln_info in self.VULNERABLE_SERVICES.items():
                    if pattern in full_service:
                        findings.append(SecurityFinding(
                            severity=vuln_info['severity'],
                            category='Vulnerable Service',
                            title=f"{vuln_info['title']} ({host_ip}:{port})",
                            description=vuln_info['description'],
                            recommendation=vuln_info['recommendation'],
                            cve_ids=[vuln_info.get('cve')] if vuln_info.get('cve') else []
                        ))
        
        self.findings.extend(findings)
        return findings
    
    def analyze_credentials(self, credentials: List[Dict]) -> List[SecurityFinding]:
        """Analyze discovered credentials for security issues"""
        findings = []
        
        for cred in credentials:
            username = cred.get('username', '').lower()
            password = cred.get('password', '')
            service = cred.get('service', '').lower()
            host = cred.get('host', 'Unknown')
            
            # Check for weak passwords
            if self._is_weak_password(password):
                findings.append(SecurityFinding(
                    severity='critical',
                    category='Weak Credentials',
                    title=f'Weak Password Found ({host})',
                    description=f'The account "{username}" on {service} has a weak password.',
                    recommendation='Enforce strong password policies. Use passwords with 12+ characters, mixed case, numbers, and symbols.'
                ))
            
            # Check for default credentials
            if self._is_default_credential(username, password, service):
                findings.append(SecurityFinding(
                    severity='critical',
                    category='Default Credentials',
                    title=f'Default Credentials ({host})',
                    description=f'Default credentials found for {service} service.',
                    recommendation='Change all default credentials immediately. Implement credential management policies.'
                ))
            
            # Check for privilege escalation risk
            if username in ['root', 'admin', 'administrator', 'sa']:
                findings.append(SecurityFinding(
                    severity='critical',
                    category='Privileged Access',
                    title=f'Administrative Credentials Compromised ({host})',
                    description=f'High-privilege account "{username}" credentials discovered.',
                    recommendation='Immediately rotate credentials. Implement MFA for admin accounts. Review access logs.'
                ))
        
        self.findings.extend(findings)
        return findings
    
    def generate_executive_summary(self) -> str:
        """Generate an executive summary of findings"""
        critical = len([f for f in self.findings if f.severity == 'critical'])
        high = len([f for f in self.findings if f.severity == 'high'])
        medium = len([f for f in self.findings if f.severity == 'medium'])
        low = len([f for f in self.findings if f.severity == 'low'])
        
        risk_level = 'CRITICAL' if critical > 0 else 'HIGH' if high > 0 else 'MEDIUM' if medium > 0 else 'LOW'
        
        summary = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    EXECUTIVE SECURITY SUMMARY                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Overall Risk Level: {risk_level:<58}║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Finding Breakdown:                                                           ║
║    🔴 Critical:  {critical:<62}║
║    🟠 High:      {high:<62}║
║    🟡 Medium:    {medium:<62}║
║    🟢 Low:       {low:<62}║
║    Total:        {len(self.findings):<62}║
╚══════════════════════════════════════════════════════════════════════════════╝

KEY FINDINGS:
"""
        # Add top critical findings
        for finding in self.findings[:5]:
            if finding.severity in ['critical', 'high']:
                summary += f"\n• [{finding.severity.upper()}] {finding.title}\n"
                summary += f"  └─ {finding.recommendation}\n"
        
        return summary
    
    def get_attack_recommendations(self, target_info: Dict) -> List[str]:
        """Get recommended attack vectors based on discovered services"""
        recommendations = []
        
        services = target_info.get('services', [])
        for svc in services:
            service = svc.get('name', '').lower()
            port = svc.get('port', 0)
            
            if 'ssh' in service:
                recommendations.append(f"SSH ({port}): Try password spraying with common credentials")
                recommendations.append(f"SSH ({port}): Check for key-based auth misconfigurations")
            
            if 'http' in service:
                recommendations.append(f"HTTP ({port}): Run directory enumeration (gobuster/dirbuster)")
                recommendations.append(f"HTTP ({port}): Check for common CMS vulnerabilities")
                recommendations.append(f"HTTP ({port}): Test for SQL injection and XSS")
            
            if 'smb' in service or port == 445:
                recommendations.append(f"SMB ({port}): Enumerate shares (smbclient -L)")
                recommendations.append(f"SMB ({port}): Check for EternalBlue (MS17-010)")
                recommendations.append(f"SMB ({port}): Try null session enumeration")
            
            if 'ftp' in service:
                recommendations.append(f"FTP ({port}): Check for anonymous access")
                recommendations.append(f"FTP ({port}): Test for common default credentials")
            
            if 'mysql' in service or 'maria' in service:
                recommendations.append(f"MySQL ({port}): Check for no-password root access")
                recommendations.append(f"MySQL ({port}): Try UDF privilege escalation if access gained")
            
            if 'redis' in service:
                recommendations.append(f"Redis ({port}): Check for unauthenticated access")
                recommendations.append(f"Redis ({port}): Try SSH key injection via Redis")
        
        return recommendations
    
    def _is_weak_password(self, password: str) -> bool:
        """Check if password is weak"""
        if len(password) < 8:
            return True
        
        weak_patterns = [
            r'^password\d*$',
            r'^123456',
            r'^admin\d*$',
            r'^root$',
            r'^qwerty',
            r'^letmein',
            r'^welcome',
            r'^monkey',
            r'^dragon',
            r'^master',
            r'^abc123',
            r'^111111',
            r'^passw0rd',
        ]
        
        for pattern in weak_patterns:
            if re.match(pattern, password.lower()):
                return True
        
        return False
    
    def _is_default_credential(self, username: str, password: str, service: str) -> bool:
        """Check if credentials are defaults"""
        service_key = service.split()[0].lower() if service else ''
        
        for svc, creds in self.DEFAULT_CREDS.items():
            if svc in service_key:
                for default_user, default_pass in creds:
                    if username.lower() == default_user and password == default_pass:
                        return True
        return False
    
    def _get_port_recommendation(self, port: int) -> str:
        """Get recommendation for exposed port"""
        recommendations = {
            21: 'Disable FTP and use SFTP/SCP instead. If FTP is required, use FTPS.',
            23: 'Disable Telnet immediately and use SSH for remote access.',
            25: 'Ensure SMTP relay is properly configured. Use authentication.',
            69: 'Disable TFTP unless absolutely necessary.',
            110: 'Use POP3S (port 995) with TLS encryption.',
            111: 'Block RPC at firewall. Only allow from trusted networks.',
            135: 'Block MSRPC at firewall. Restrict to internal network only.',
            139: 'Disable NetBIOS if not needed. Block at firewall.',
            143: 'Use IMAPS (port 993) with TLS encryption.',
            161: 'Use SNMPv3 with authentication. Block SNMP at perimeter.',
            445: 'Block SMB at perimeter. Patch against EternalBlue (MS17-010).',
            512: 'Disable rexec and use SSH instead.',
            513: 'Disable rlogin and use SSH instead.',
            514: 'Disable rsh and use SSH instead.',
            1433: 'Restrict MSSQL to application servers only. Use firewalls.',
            1521: 'Restrict Oracle to application servers only. Use firewalls.',
            2049: 'Restrict NFS access. Use NFSv4 with Kerberos.',
            3306: 'Restrict MySQL to localhost or app servers. Use SSL.',
            3389: 'Use NLA for RDP. Restrict access via firewall. Enable MFA.',
            5432: 'Restrict PostgreSQL access. Use SSL connections.',
            5900: 'Use VNC over SSH tunnel. Enable authentication.',
            6379: 'Enable Redis authentication. Bind to localhost only.',
            27017: 'Enable MongoDB authentication. Bind to localhost.',
        }
        return recommendations.get(port, 'Review service necessity and restrict access appropriately.')
    
    def suggest_next_steps(self, scan_results: Dict) -> List[str]:
        """Suggest next steps based on current findings"""
        steps = []
        
        # Based on findings
        if any(f.severity == 'critical' for f in self.findings):
            steps.append("🚨 PRIORITY: Address critical findings immediately")
            steps.append("   - Isolate affected systems if necessary")
            steps.append("   - Begin incident response procedures")
        
        # Based on services found
        has_web = any('http' in str(s).lower() for s in scan_results.get('services', []))
        has_smb = any('smb' in str(s).lower() or '445' in str(s) for s in scan_results.get('services', []))
        
        if has_web:
            steps.append("🌐 Web Services Detected:")
            steps.append("   - Run web vulnerability scanner (Nikto, OWASP ZAP)")
            steps.append("   - Enumerate directories and files")
            steps.append("   - Test authentication mechanisms")
        
        if has_smb:
            steps.append("📁 SMB Services Detected:")
            steps.append("   - Enumerate shares and permissions")
            steps.append("   - Check for sensitive file exposure")
            steps.append("   - Test for MS17-010 vulnerability")
        
        steps.append("\n📋 General Recommendations:")
        steps.append("   - Document all findings with evidence")
        steps.append("   - Prioritize remediation by severity")
        steps.append("   - Verify fixes and retest")
        
        return steps


# Singleton instance
ai_assistant = AISecurityAssistant()
