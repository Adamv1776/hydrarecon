"""
HydraRecon Advanced Active Directory Security Module
Comprehensive AD security assessment, attack simulation, and hardening
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


class ADObjectType(Enum):
    """Active Directory object types"""
    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    OU = "organizational_unit"
    GPO = "group_policy_object"
    DOMAIN = "domain"
    TRUST = "trust"
    SERVICE_ACCOUNT = "service_account"
    GMSA = "group_managed_service_account"


class AttackType(Enum):
    """AD attack types"""
    KERBEROASTING = "kerberoasting"
    ASREPROASTING = "asreproasting"
    PASSWORD_SPRAY = "password_spray"
    PASS_THE_HASH = "pass_the_hash"
    PASS_THE_TICKET = "pass_the_ticket"
    GOLDEN_TICKET = "golden_ticket"
    SILVER_TICKET = "silver_ticket"
    DCSYNC = "dcsync"
    DELEGATION_ABUSE = "delegation_abuse"
    ACL_ABUSE = "acl_abuse"
    NTLM_RELAY = "ntlm_relay"
    ZEROLOGON = "zerologon"
    PETITPOTAM = "petitpotam"
    PRINTNIGHTMARE = "printnightmare"


class SeverityLevel(Enum):
    """Vulnerability severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PrivilegeLevel(Enum):
    """Privilege levels"""
    DOMAIN_ADMIN = "domain_admin"
    ENTERPRISE_ADMIN = "enterprise_admin"
    SCHEMA_ADMIN = "schema_admin"
    ACCOUNT_OPERATOR = "account_operator"
    SERVER_OPERATOR = "server_operator"
    BACKUP_OPERATOR = "backup_operator"
    PRIVILEGED_USER = "privileged_user"
    STANDARD_USER = "standard_user"


@dataclass
class ADUser:
    """Active Directory user"""
    distinguished_name: str
    sam_account_name: str
    user_principal_name: str = ""
    sid: str = ""
    enabled: bool = True
    admin_count: int = 0
    password_last_set: Optional[datetime] = None
    last_logon: Optional[datetime] = None
    password_never_expires: bool = False
    password_not_required: bool = False
    dont_require_preauth: bool = False
    has_spn: bool = False
    spns: List[str] = field(default_factory=list)
    member_of: List[str] = field(default_factory=list)
    description: str = ""
    is_privileged: bool = False
    privilege_level: PrivilegeLevel = PrivilegeLevel.STANDARD_USER


@dataclass
class ADGroup:
    """Active Directory group"""
    distinguished_name: str
    sam_account_name: str
    sid: str = ""
    group_type: str = ""
    members: List[str] = field(default_factory=list)
    member_of: List[str] = field(default_factory=list)
    is_privileged: bool = False
    admin_count: int = 0


@dataclass
class ADComputer:
    """Active Directory computer"""
    distinguished_name: str
    sam_account_name: str
    dns_hostname: str = ""
    operating_system: str = ""
    os_version: str = ""
    is_dc: bool = False
    is_trusted_for_delegation: bool = False
    is_constrained_delegation: bool = False
    last_logon: Optional[datetime] = None
    spns: List[str] = field(default_factory=list)


@dataclass
class ADGPO:
    """Group Policy Object"""
    name: str
    gpo_id: str
    display_name: str = ""
    path: str = ""
    link_enabled: bool = True
    linked_to: List[str] = field(default_factory=list)
    security_settings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ADTrust:
    """Active Directory trust relationship"""
    source_domain: str
    target_domain: str
    trust_type: str = ""
    trust_direction: str = ""
    is_transitive: bool = False
    sid_filtering_enabled: bool = True


@dataclass
class ADFinding:
    """AD security finding"""
    finding_id: str
    title: str
    description: str
    severity: SeverityLevel
    category: str
    affected_objects: List[str] = field(default_factory=list)
    attack_vector: Optional[AttackType] = None
    mitre_technique: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class AttackPath:
    """Attack path to domain admin"""
    path_id: str
    start_node: str
    end_node: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    techniques_used: List[AttackType] = field(default_factory=list)
    success_likelihood: float = 0.0


class LDAPClient:
    """LDAP client for AD queries"""
    
    def __init__(self, server: str, port: int = 389, ssl: bool = False):
        self.server = server
        self.port = port
        self.ssl = ssl
        self.base_dn = ""
        
    async def connect(self, username: str, password: str, domain: str) -> bool:
        """Connect to LDAP server"""
        # Parse domain to base DN
        self.base_dn = ','.join(f"DC={part}" for part in domain.split('.'))
        
        logger.info(f"Connecting to {self.server}:{self.port}")
        
        # In real implementation, would use ldap3 or similar library
        return True
        
    async def search(self, search_filter: str, attributes: List[str] = None,
                    base: str = None) -> List[Dict[str, Any]]:
        """Search LDAP directory"""
        # Placeholder for LDAP search
        return []
        
    async def get_users(self) -> List[ADUser]:
        """Get all domain users"""
        users = []
        
        # LDAP filter for users
        filter_str = "(&(objectCategory=person)(objectClass=user))"
        
        # Query would return results here
        # Simulated data for testing
        return users
        
    async def get_groups(self) -> List[ADGroup]:
        """Get all domain groups"""
        groups = []
        filter_str = "(objectCategory=group)"
        return groups
        
    async def get_computers(self) -> List[ADComputer]:
        """Get all domain computers"""
        computers = []
        filter_str = "(objectCategory=computer)"
        return computers


class PasswordPolicy:
    """Domain password policy analysis"""
    
    def __init__(self):
        self.min_password_length = 0
        self.password_history = 0
        self.max_password_age = 0
        self.min_password_age = 0
        self.lockout_threshold = 0
        self.lockout_duration = 0
        self.complexity_enabled = False
        
    def analyze(self) -> List[ADFinding]:
        """Analyze password policy"""
        findings = []
        
        if self.min_password_length < 14:
            findings.append(ADFinding(
                finding_id="PWD-001",
                title="Weak Minimum Password Length",
                description=f"Minimum password length is {self.min_password_length}, should be at least 14",
                severity=SeverityLevel.HIGH if self.min_password_length < 8 else SeverityLevel.MEDIUM,
                category="password_policy",
                remediation="Increase minimum password length to 14 or more characters"
            ))
            
        if not self.complexity_enabled:
            findings.append(ADFinding(
                finding_id="PWD-002",
                title="Password Complexity Disabled",
                description="Password complexity requirements are not enforced",
                severity=SeverityLevel.HIGH,
                category="password_policy",
                remediation="Enable password complexity requirements"
            ))
            
        if self.password_history < 24:
            findings.append(ADFinding(
                finding_id="PWD-003",
                title="Insufficient Password History",
                description=f"Password history is {self.password_history}, should be at least 24",
                severity=SeverityLevel.MEDIUM,
                category="password_policy",
                remediation="Increase password history to 24 or more"
            ))
            
        if self.lockout_threshold == 0:
            findings.append(ADFinding(
                finding_id="PWD-004",
                title="Account Lockout Disabled",
                description="Account lockout is not configured",
                severity=SeverityLevel.HIGH,
                category="password_policy",
                attack_vector=AttackType.PASSWORD_SPRAY,
                remediation="Configure account lockout threshold (recommended: 3-5 attempts)"
            ))
            
        if self.max_password_age == 0:
            findings.append(ADFinding(
                finding_id="PWD-005",
                title="Password Never Expires",
                description="Maximum password age is not configured",
                severity=SeverityLevel.MEDIUM,
                category="password_policy",
                remediation="Configure maximum password age (60-90 days recommended)"
            ))
            
        return findings


class KerberosSecurityAnalyzer:
    """Kerberos security analysis"""
    
    def __init__(self):
        self.vulnerable_users: List[ADUser] = []
        self.kerberoastable: List[ADUser] = []
        self.asreproastable: List[ADUser] = []
        
    def analyze_users(self, users: List[ADUser]) -> List[ADFinding]:
        """Analyze users for Kerberos vulnerabilities"""
        findings = []
        
        for user in users:
            # Check for Kerberoasting
            if user.has_spn and user.enabled:
                self.kerberoastable.append(user)
                
                # Higher severity for privileged accounts
                severity = SeverityLevel.CRITICAL if user.is_privileged else SeverityLevel.HIGH
                
                findings.append(ADFinding(
                    finding_id=f"KERB-001-{user.sam_account_name}",
                    title=f"Kerberoastable Account: {user.sam_account_name}",
                    description=f"User {user.sam_account_name} has SPNs and is vulnerable to Kerberoasting",
                    severity=severity,
                    category="kerberos",
                    affected_objects=[user.distinguished_name],
                    attack_vector=AttackType.KERBEROASTING,
                    mitre_technique="T1558.003",
                    remediation="Remove unnecessary SPNs or use gMSAs with strong passwords"
                ))
                
            # Check for AS-REP Roasting
            if user.dont_require_preauth and user.enabled:
                self.asreproastable.append(user)
                
                findings.append(ADFinding(
                    finding_id=f"KERB-002-{user.sam_account_name}",
                    title=f"AS-REP Roastable Account: {user.sam_account_name}",
                    description=f"User {user.sam_account_name} does not require Kerberos pre-authentication",
                    severity=SeverityLevel.HIGH,
                    category="kerberos",
                    affected_objects=[user.distinguished_name],
                    attack_vector=AttackType.ASREPROASTING,
                    mitre_technique="T1558.004",
                    remediation="Enable Kerberos pre-authentication"
                ))
                
        return findings


class DelegationAnalyzer:
    """Analyze delegation configurations"""
    
    def analyze_delegation(self, computers: List[ADComputer], 
                          users: List[ADUser]) -> List[ADFinding]:
        """Analyze delegation vulnerabilities"""
        findings = []
        
        for computer in computers:
            if computer.is_trusted_for_delegation and not computer.is_dc:
                findings.append(ADFinding(
                    finding_id=f"DELEG-001-{computer.sam_account_name}",
                    title=f"Unconstrained Delegation: {computer.sam_account_name}",
                    description=f"Computer {computer.sam_account_name} is trusted for unconstrained delegation",
                    severity=SeverityLevel.CRITICAL,
                    category="delegation",
                    affected_objects=[computer.distinguished_name],
                    attack_vector=AttackType.DELEGATION_ABUSE,
                    mitre_technique="T1558",
                    remediation="Use constrained delegation or remove delegation trust"
                ))
                
        return findings


class ACLAnalyzer:
    """Analyze AD ACL permissions"""
    
    def __init__(self):
        self.dangerous_rights = {
            'GenericAll': 'Full control over object',
            'GenericWrite': 'Can modify object attributes',
            'WriteOwner': 'Can change object owner',
            'WriteDACL': 'Can modify object permissions',
            'AllExtendedRights': 'All extended rights including password reset',
            'ForceChangePassword': 'Can reset password',
            'AddMembers': 'Can add members to group',
            'Replication-Get-Changes-All': 'DCSync capability'
        }
        
    def analyze_acls(self, objects: List[Dict]) -> List[ADFinding]:
        """Analyze ACLs for dangerous permissions"""
        findings = []
        
        # In real implementation, would parse and analyze ACLs
        # This is a placeholder for the ACL analysis logic
        
        return findings


class AttackPathFinder:
    """Find attack paths to privileged accounts"""
    
    def __init__(self):
        self.graph: Dict[str, List[Dict]] = {}
        self.privileged_groups = {
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators'
        }
        
    def build_graph(self, users: List[ADUser], groups: List[ADGroup],
                   computers: List[ADComputer]) -> None:
        """Build attack graph"""
        # Add group memberships
        for group in groups:
            group_dn = group.distinguished_name
            
            for member in group.members:
                if group_dn not in self.graph:
                    self.graph[group_dn] = []
                    
                self.graph[group_dn].append({
                    'source': member,
                    'relationship': 'MemberOf',
                    'target': group_dn
                })
                
        # Add delegation relationships
        for computer in computers:
            if computer.is_trusted_for_delegation:
                for spn in computer.spns:
                    # Parse SPN to find target
                    pass
                    
    def find_paths(self, start_node: str, end_nodes: Set[str] = None) -> List[AttackPath]:
        """Find attack paths from start to privileged groups"""
        if end_nodes is None:
            end_nodes = {f"CN={g}" for g in self.privileged_groups}
            
        paths = []
        
        # BFS/DFS to find paths
        visited = set()
        queue = [(start_node, [start_node])]
        
        while queue:
            node, path = queue.pop(0)
            
            if node in visited:
                continue
                
            visited.add(node)
            
            # Check if reached target
            for end in end_nodes:
                if end in node:
                    paths.append(AttackPath(
                        path_id=hashlib.md5(str(path).encode()).hexdigest()[:12],
                        start_node=start_node,
                        end_node=node,
                        steps=[{'node': n, 'index': i} for i, n in enumerate(path)]
                    ))
                    
            # Add neighbors
            if node in self.graph:
                for edge in self.graph[node]:
                    if edge['target'] not in visited:
                        queue.append((edge['target'], path + [edge['target']]))
                        
        return paths


class TrustAnalyzer:
    """Analyze domain trust relationships"""
    
    def analyze_trusts(self, trusts: List[ADTrust]) -> List[ADFinding]:
        """Analyze trust security"""
        findings = []
        
        for trust in trusts:
            # Check for SID filtering
            if not trust.sid_filtering_enabled:
                findings.append(ADFinding(
                    finding_id=f"TRUST-001-{trust.target_domain}",
                    title=f"SID Filtering Disabled: {trust.target_domain}",
                    description=f"SID filtering is disabled on trust with {trust.target_domain}",
                    severity=SeverityLevel.HIGH,
                    category="trust",
                    affected_objects=[trust.source_domain, trust.target_domain],
                    remediation="Enable SID filtering on the trust relationship"
                ))
                
            # Check for transitive trusts
            if trust.is_transitive:
                findings.append(ADFinding(
                    finding_id=f"TRUST-002-{trust.target_domain}",
                    title=f"Transitive Trust: {trust.target_domain}",
                    description=f"Trust with {trust.target_domain} is transitive",
                    severity=SeverityLevel.MEDIUM,
                    category="trust",
                    affected_objects=[trust.source_domain, trust.target_domain],
                    remediation="Review if transitive trust is necessary"
                ))
                
        return findings


class GPOSecurityAnalyzer:
    """Analyze Group Policy security"""
    
    def analyze_gpos(self, gpos: List[ADGPO]) -> List[ADFinding]:
        """Analyze GPO security settings"""
        findings = []
        
        for gpo in gpos:
            settings = gpo.security_settings
            
            # Check for insecure settings
            if settings.get('LmCompatibilityLevel', 0) < 5:
                findings.append(ADFinding(
                    finding_id=f"GPO-001-{gpo.gpo_id}",
                    title=f"Weak LM Compatibility: {gpo.display_name}",
                    description="NTLM v1 is allowed, vulnerable to relay attacks",
                    severity=SeverityLevel.HIGH,
                    category="gpo",
                    affected_objects=[gpo.path],
                    remediation="Set LmCompatibilityLevel to 5 (NTLMv2 only)"
                ))
                
            if settings.get('NoLMHash', False) == False:
                findings.append(ADFinding(
                    finding_id=f"GPO-002-{gpo.gpo_id}",
                    title=f"LM Hash Storage Enabled: {gpo.display_name}",
                    description="LM hashes are stored, vulnerable to cracking",
                    severity=SeverityLevel.HIGH,
                    category="gpo",
                    affected_objects=[gpo.path],
                    remediation="Enable 'Do not store LM hash value on next password change'"
                ))
                
            if settings.get('SMBSigningRequired', False) == False:
                findings.append(ADFinding(
                    finding_id=f"GPO-003-{gpo.gpo_id}",
                    title=f"SMB Signing Not Required: {gpo.display_name}",
                    description="SMB signing is not required, vulnerable to relay attacks",
                    severity=SeverityLevel.MEDIUM,
                    category="gpo",
                    affected_objects=[gpo.path],
                    attack_vector=AttackType.NTLM_RELAY,
                    remediation="Require SMB signing on all systems"
                ))
                
        return findings


class PrivilegedAccountAnalyzer:
    """Analyze privileged accounts"""
    
    def __init__(self):
        self.privileged_sids = {
            'S-1-5-32-544': 'Administrators',
            'S-1-5-21-*-512': 'Domain Admins',
            'S-1-5-21-*-519': 'Enterprise Admins',
            'S-1-5-21-*-518': 'Schema Admins',
            'S-1-5-21-*-498': 'Enterprise Read-only Domain Controllers',
        }
        
    def analyze_privileged(self, users: List[ADUser], 
                          groups: List[ADGroup]) -> List[ADFinding]:
        """Analyze privileged accounts"""
        findings = []
        privileged_users = []
        
        for user in users:
            if user.is_privileged:
                privileged_users.append(user)
                
                # Check for password issues
                if user.password_never_expires:
                    findings.append(ADFinding(
                        finding_id=f"PRIV-001-{user.sam_account_name}",
                        title=f"Privileged Account Password Never Expires: {user.sam_account_name}",
                        description=f"Privileged user {user.sam_account_name} has password set to never expire",
                        severity=SeverityLevel.HIGH,
                        category="privileged_accounts",
                        affected_objects=[user.distinguished_name],
                        remediation="Remove 'Password never expires' flag"
                    ))
                    
                # Check for old passwords
                if user.password_last_set:
                    age = (datetime.now() - user.password_last_set).days
                    if age > 90:
                        findings.append(ADFinding(
                            finding_id=f"PRIV-002-{user.sam_account_name}",
                            title=f"Privileged Account Stale Password: {user.sam_account_name}",
                            description=f"Privileged user {user.sam_account_name} password is {age} days old",
                            severity=SeverityLevel.MEDIUM,
                            category="privileged_accounts",
                            affected_objects=[user.distinguished_name],
                            remediation="Change password regularly (at least every 90 days)"
                        ))
                        
        # Check for too many privileged users
        if len(privileged_users) > 10:
            findings.append(ADFinding(
                finding_id="PRIV-003",
                title="Excessive Privileged Accounts",
                description=f"There are {len(privileged_users)} privileged accounts in the domain",
                severity=SeverityLevel.MEDIUM,
                category="privileged_accounts",
                affected_objects=[u.distinguished_name for u in privileged_users[:10]],
                remediation="Review and reduce the number of privileged accounts"
            ))
            
        return findings


class ADSecurityAssessment:
    """Comprehensive AD security assessment"""
    
    def __init__(self, domain: str, server: str):
        self.domain = domain
        self.server = server
        self.ldap_client = LDAPClient(server)
        self.password_policy = PasswordPolicy()
        self.kerberos_analyzer = KerberosSecurityAnalyzer()
        self.delegation_analyzer = DelegationAnalyzer()
        self.acl_analyzer = ACLAnalyzer()
        self.path_finder = AttackPathFinder()
        self.trust_analyzer = TrustAnalyzer()
        self.gpo_analyzer = GPOSecurityAnalyzer()
        self.priv_analyzer = PrivilegedAccountAnalyzer()
        
    async def run_assessment(self, username: str, password: str) -> Dict[str, Any]:
        """Run comprehensive AD security assessment"""
        results = {
            'assessment_id': hashlib.md5(f"{self.domain}{datetime.now()}".encode()).hexdigest()[:12],
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'statistics': {},
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'attack_paths': [],
            'recommendations': []
        }
        
        # Connect to LDAP
        connected = await self.ldap_client.connect(username, password, self.domain)
        
        if not connected:
            results['error'] = 'Failed to connect to domain controller'
            return results
            
        # Collect AD objects
        users = await self.ldap_client.get_users()
        groups = await self.ldap_client.get_groups()
        computers = await self.ldap_client.get_computers()
        
        results['statistics'] = {
            'total_users': len(users),
            'total_groups': len(groups),
            'total_computers': len(computers),
            'enabled_users': len([u for u in users if u.enabled]),
            'privileged_users': len([u for u in users if u.is_privileged]),
            'domain_controllers': len([c for c in computers if c.is_dc])
        }
        
        # Password policy analysis
        pwd_findings = self.password_policy.analyze()
        results['findings'].extend([self._finding_to_dict(f) for f in pwd_findings])
        
        # Kerberos analysis
        kerb_findings = self.kerberos_analyzer.analyze_users(users)
        results['findings'].extend([self._finding_to_dict(f) for f in kerb_findings])
        
        results['statistics']['kerberoastable'] = len(self.kerberos_analyzer.kerberoastable)
        results['statistics']['asreproastable'] = len(self.kerberos_analyzer.asreproastable)
        
        # Delegation analysis
        deleg_findings = self.delegation_analyzer.analyze_delegation(computers, users)
        results['findings'].extend([self._finding_to_dict(f) for f in deleg_findings])
        
        # Privileged account analysis
        priv_findings = self.priv_analyzer.analyze_privileged(users, groups)
        results['findings'].extend([self._finding_to_dict(f) for f in priv_findings])
        
        # Calculate summary
        for finding in results['findings']:
            severity = finding.get('severity', 'info').lower()
            if severity in results['summary']:
                results['summary'][severity] += 1
                
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
        
    def _finding_to_dict(self, finding: ADFinding) -> Dict:
        """Convert finding to dictionary"""
        return {
            'id': finding.finding_id,
            'title': finding.title,
            'description': finding.description,
            'severity': finding.severity.value,
            'category': finding.category,
            'affected_objects': finding.affected_objects[:5],  # Limit for report size
            'attack_vector': finding.attack_vector.value if finding.attack_vector else None,
            'mitre_technique': finding.mitre_technique,
            'remediation': finding.remediation
        }
        
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        if results['summary']['critical'] > 0:
            recommendations.append("CRITICAL: Address all critical findings immediately")
            
        stats = results.get('statistics', {})
        
        if stats.get('kerberoastable', 0) > 0:
            recommendations.append("Migrate service accounts to Group Managed Service Accounts (gMSA)")
            recommendations.append("Implement strong passwords (25+ characters) for service accounts")
            
        if stats.get('asreproastable', 0) > 0:
            recommendations.append("Enable Kerberos pre-authentication for all accounts")
            
        # General best practices
        recommendations.extend([
            "Implement tiered administration model",
            "Deploy Privileged Access Workstations (PAW)",
            "Enable Advanced Threat Analytics (ATA) or Microsoft Defender for Identity",
            "Implement LAPS for local administrator passwords",
            "Configure Fine-Grained Password Policies for privileged accounts",
            "Review and minimize privileged group memberships",
            "Enable audit logging for AD changes",
            "Implement Protected Users security group for privileged accounts"
        ])
        
        return recommendations
        
    def generate_report(self, results: Dict) -> str:
        """Generate assessment report"""
        report = []
        
        report.append("=" * 70)
        report.append("ACTIVE DIRECTORY SECURITY ASSESSMENT REPORT")
        report.append("=" * 70)
        
        report.append(f"\nAssessment ID: {results['assessment_id']}")
        report.append(f"Domain: {results['domain']}")
        report.append(f"Timestamp: {results['timestamp']}")
        
        report.append(f"\n{'=' * 50}")
        report.append("DOMAIN STATISTICS")
        report.append("=" * 50)
        
        stats = results.get('statistics', {})
        report.append(f"Total Users: {stats.get('total_users', 0)}")
        report.append(f"Enabled Users: {stats.get('enabled_users', 0)}")
        report.append(f"Privileged Users: {stats.get('privileged_users', 0)}")
        report.append(f"Total Groups: {stats.get('total_groups', 0)}")
        report.append(f"Total Computers: {stats.get('total_computers', 0)}")
        report.append(f"Domain Controllers: {stats.get('domain_controllers', 0)}")
        report.append(f"Kerberoastable Accounts: {stats.get('kerberoastable', 0)}")
        report.append(f"AS-REP Roastable Accounts: {stats.get('asreproastable', 0)}")
        
        report.append(f"\n{'=' * 50}")
        report.append("FINDINGS SUMMARY")
        report.append("=" * 50)
        
        summary = results.get('summary', {})
        report.append(f"Critical: {summary.get('critical', 0)}")
        report.append(f"High: {summary.get('high', 0)}")
        report.append(f"Medium: {summary.get('medium', 0)}")
        report.append(f"Low: {summary.get('low', 0)}")
        report.append(f"Informational: {summary.get('info', 0)}")
        
        report.append(f"\n{'=' * 50}")
        report.append("DETAILED FINDINGS")
        report.append("=" * 50)
        
        for finding in results.get('findings', [])[:30]:
            report.append(f"\n[{finding['severity'].upper()}] {finding['title']}")
            report.append(f"  Category: {finding['category']}")
            report.append(f"  Description: {finding['description']}")
            if finding.get('attack_vector'):
                report.append(f"  Attack Vector: {finding['attack_vector']}")
            if finding.get('mitre_technique'):
                report.append(f"  MITRE ATT&CK: {finding['mitre_technique']}")
            if finding.get('remediation'):
                report.append(f"  Remediation: {finding['remediation']}")
                
        report.append(f"\n{'=' * 50}")
        report.append("RECOMMENDATIONS")
        report.append("=" * 50)
        
        for i, rec in enumerate(results.get('recommendations', []), 1):
            report.append(f"\n{i}. {rec}")
            
        return "\n".join(report)


class AdvancedADSecurity:
    """Main integration class for AD security"""
    
    def __init__(self, domain: str, server: str):
        self.assessment = ADSecurityAssessment(domain, server)
        
    async def run_full_assessment(self, username: str, password: str) -> Dict[str, Any]:
        """Run comprehensive AD security assessment"""
        return await self.assessment.run_assessment(username, password)
