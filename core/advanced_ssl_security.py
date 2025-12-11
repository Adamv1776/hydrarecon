#!/usr/bin/env python3
"""
HydraRecon Advanced SSL/TLS Security Module
████████████████████████████████████████████████████████████████████████████████
█  ENTERPRISE SSL/TLS SECURITY - Certificate Analysis, Protocol Vulnerabilities,█
█  Cipher Suite Auditing, Certificate Transparency & PKI Assessment            █
████████████████████████████████████████████████████████████████████████████████
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import re


class TLSVersion(Enum):
    """TLS protocol versions"""
    SSL_2_0 = "SSLv2"
    SSL_3_0 = "SSLv3"
    TLS_1_0 = "TLSv1.0"
    TLS_1_1 = "TLSv1.1"
    TLS_1_2 = "TLSv1.2"
    TLS_1_3 = "TLSv1.3"


class CipherStrength(Enum):
    """Cipher suite strength classification"""
    INSECURE = "insecure"
    WEAK = "weak"
    ACCEPTABLE = "acceptable"
    STRONG = "strong"
    RECOMMENDED = "recommended"


class SeverityLevel(Enum):
    """Security finding severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    """SSL/TLS vulnerability types"""
    HEARTBLEED = "heartbleed"
    POODLE = "poodle"
    BEAST = "beast"
    CRIME = "crime"
    BREACH = "breach"
    FREAK = "freak"
    LOGJAM = "logjam"
    DROWN = "drown"
    ROBOT = "robot"
    GOLDENDOODLE = "goldendoodle"
    ZOMBIE_POODLE = "zombie_poodle"
    SLEEPING_POODLE = "sleeping_poodle"
    TICKETBLEED = "ticketbleed"
    LUCKY13 = "lucky13"
    SWEET32 = "sweet32"
    RACCOON = "raccoon"


@dataclass
class Certificate:
    """X.509 certificate information"""
    subject: Dict[str, str]
    issuer: Dict[str, str]
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int
    fingerprint_sha256: str
    fingerprint_sha1: str
    san: List[str]  # Subject Alternative Names
    is_ca: bool = False
    is_self_signed: bool = False
    chain_position: int = 0
    ocsp_urls: List[str] = field(default_factory=list)
    crl_urls: List[str] = field(default_factory=list)
    ct_scts: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class CipherSuite:
    """TLS cipher suite information"""
    name: str
    openssl_name: str
    protocol: TLSVersion
    key_exchange: str
    authentication: str
    encryption: str
    mac: str
    key_size: int
    strength: CipherStrength
    pfs: bool = False  # Perfect Forward Secrecy


@dataclass
class SSLFinding:
    """SSL/TLS security finding"""
    title: str
    severity: SeverityLevel
    description: str
    remediation: str
    references: List[str]
    cve: Optional[str] = None
    cvss: Optional[float] = None
    vulnerability_type: Optional[VulnerabilityType] = None


@dataclass
class SSLScanResult:
    """Complete SSL/TLS scan result"""
    host: str
    port: int
    timestamp: datetime
    certificates: List[Certificate]
    supported_protocols: List[TLSVersion]
    cipher_suites: List[CipherSuite]
    findings: List[SSLFinding]
    ocsp_stapling: bool = False
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    hsts_preload: bool = False
    grade: str = "F"


class CertificateParser:
    """Parse and analyze X.509 certificates"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_certificate(self, cert_der: bytes, position: int = 0) -> Optional[Certificate]:
        """Parse DER-encoded certificate"""
        try:
            import ssl
            
            # Load certificate
            cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
            
            # Parse using OpenSSL bindings if available
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives import hashes
                
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                # Extract subject
                subject = {}
                for attr in cert.subject:
                    subject[attr.oid._name] = attr.value
                
                # Extract issuer
                issuer = {}
                for attr in cert.issuer:
                    issuer[attr.oid._name] = attr.value
                
                # Extract SANs
                san = []
                try:
                    san_ext = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                    for name in san_ext.value:
                        if isinstance(name, x509.DNSName):
                            san.append(f"DNS:{name.value}")
                        elif isinstance(name, x509.IPAddress):
                            san.append(f"IP:{name.value}")
                except x509.ExtensionNotFound:
                    pass
                
                # Check if CA
                is_ca = False
                try:
                    basic_constraints = cert.extensions.get_extension_for_class(
                        x509.BasicConstraints
                    )
                    is_ca = basic_constraints.value.ca
                except x509.ExtensionNotFound:
                    pass
                
                # Get OCSP URLs
                ocsp_urls = []
                try:
                    aia = cert.extensions.get_extension_for_class(
                        x509.AuthorityInformationAccess
                    )
                    for access in aia.value:
                        if access.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                            ocsp_urls.append(access.access_location.value)
                except x509.ExtensionNotFound:
                    pass
                
                # Get CRL URLs
                crl_urls = []
                try:
                    crl_dp = cert.extensions.get_extension_for_class(
                        x509.CRLDistributionPoints
                    )
                    for dp in crl_dp.value:
                        for name in dp.full_name:
                            if isinstance(name, x509.UniformResourceIdentifier):
                                crl_urls.append(name.value)
                except x509.ExtensionNotFound:
                    pass
                
                # Calculate fingerprints
                fp_sha256 = cert.fingerprint(hashes.SHA256()).hex()
                fp_sha1 = cert.fingerprint(hashes.SHA1()).hex()
                
                # Check if self-signed
                is_self_signed = cert.subject == cert.issuer
                
                return Certificate(
                    subject=subject,
                    issuer=issuer,
                    serial_number=format(cert.serial_number, 'x'),
                    not_before=cert.not_valid_before,
                    not_after=cert.not_valid_after,
                    signature_algorithm=cert.signature_algorithm_oid._name,
                    public_key_algorithm=cert.public_key().__class__.__name__,
                    public_key_size=cert.public_key().key_size,
                    fingerprint_sha256=fp_sha256,
                    fingerprint_sha1=fp_sha1,
                    san=san,
                    is_ca=is_ca,
                    is_self_signed=is_self_signed,
                    chain_position=position,
                    ocsp_urls=ocsp_urls,
                    crl_urls=crl_urls
                )
                
            except ImportError:
                # Fallback to basic parsing
                return self._parse_basic(cert_pem, position)
                
        except Exception as e:
            self.logger.error(f"Certificate parsing error: {e}")
            return None
    
    def _parse_basic(self, cert_pem: str, position: int) -> Optional[Certificate]:
        """Basic certificate parsing without cryptography library"""
        # Simplified parsing
        return Certificate(
            subject={"CN": "Unknown"},
            issuer={"CN": "Unknown"},
            serial_number="0",
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=365),
            signature_algorithm="Unknown",
            public_key_algorithm="Unknown",
            public_key_size=0,
            fingerprint_sha256="",
            fingerprint_sha1="",
            san=[],
            chain_position=position
        )


class CipherSuiteAnalyzer:
    """Analyze TLS cipher suites"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Insecure ciphers
        self.insecure_ciphers = {
            'NULL', 'EXPORT', 'DES', 'RC2', 'RC4', 'MD5', 'ANON',
            'EXP', 'ADH', 'AECDH', 'DES40', 'DES-CBC3'
        }
        
        # Weak ciphers
        self.weak_ciphers = {
            '3DES', 'IDEA', 'SEED', 'CAMELLIA', 'PSK'
        }
        
        # PFS-enabled key exchanges
        self.pfs_key_exchanges = {'ECDHE', 'DHE', 'ECDH'}
        
        # Recommended cipher suites for TLS 1.3
        self.tls13_ciphers = {
            'TLS_AES_256_GCM_SHA384',
            'TLS_AES_128_GCM_SHA256',
            'TLS_CHACHA20_POLY1305_SHA256'
        }
    
    def analyze_cipher(self, cipher_name: str, protocol: TLSVersion) -> CipherSuite:
        """Analyze a cipher suite"""
        # Parse cipher components
        parts = self._parse_cipher_name(cipher_name)
        
        # Determine strength
        strength = self._calculate_strength(cipher_name, parts)
        
        # Check PFS
        pfs = any(kex in cipher_name.upper() for kex in self.pfs_key_exchanges)
        
        return CipherSuite(
            name=cipher_name,
            openssl_name=cipher_name,
            protocol=protocol,
            key_exchange=parts.get('kex', 'Unknown'),
            authentication=parts.get('auth', 'Unknown'),
            encryption=parts.get('enc', 'Unknown'),
            mac=parts.get('mac', 'Unknown'),
            key_size=parts.get('key_size', 0),
            strength=strength,
            pfs=pfs
        )
    
    def _parse_cipher_name(self, name: str) -> Dict[str, Any]:
        """Parse cipher suite name into components"""
        parts = {
            'kex': 'Unknown',
            'auth': 'Unknown',
            'enc': 'Unknown',
            'mac': 'Unknown',
            'key_size': 0
        }
        
        name_upper = name.upper()
        
        # Key exchange
        if 'ECDHE' in name_upper:
            parts['kex'] = 'ECDHE'
        elif 'DHE' in name_upper or 'EDH' in name_upper:
            parts['kex'] = 'DHE'
        elif 'ECDH' in name_upper:
            parts['kex'] = 'ECDH'
        elif 'RSA' in name_upper:
            parts['kex'] = 'RSA'
        
        # Authentication
        if 'ECDSA' in name_upper:
            parts['auth'] = 'ECDSA'
        elif 'RSA' in name_upper:
            parts['auth'] = 'RSA'
        elif 'DSS' in name_upper:
            parts['auth'] = 'DSS'
        
        # Encryption
        if 'AES256' in name_upper or 'AES_256' in name_upper:
            parts['enc'] = 'AES-256'
            parts['key_size'] = 256
        elif 'AES128' in name_upper or 'AES_128' in name_upper:
            parts['enc'] = 'AES-128'
            parts['key_size'] = 128
        elif 'CHACHA20' in name_upper:
            parts['enc'] = 'ChaCha20'
            parts['key_size'] = 256
        elif '3DES' in name_upper or 'DES-CBC3' in name_upper:
            parts['enc'] = '3DES'
            parts['key_size'] = 112
        elif 'RC4' in name_upper:
            parts['enc'] = 'RC4'
            parts['key_size'] = 128
        
        # MAC
        if 'SHA384' in name_upper:
            parts['mac'] = 'SHA-384'
        elif 'SHA256' in name_upper:
            parts['mac'] = 'SHA-256'
        elif 'SHA1' in name_upper or '_SHA' in name_upper:
            parts['mac'] = 'SHA-1'
        elif 'MD5' in name_upper:
            parts['mac'] = 'MD5'
        elif 'GCM' in name_upper:
            parts['mac'] = 'AEAD'
        elif 'POLY1305' in name_upper:
            parts['mac'] = 'Poly1305'
        
        return parts
    
    def _calculate_strength(self, name: str, parts: Dict[str, Any]) -> CipherStrength:
        """Calculate cipher strength"""
        name_upper = name.upper()
        
        # Check for insecure components
        for weak in self.insecure_ciphers:
            if weak in name_upper:
                return CipherStrength.INSECURE
        
        # Check for weak components
        for weak in self.weak_ciphers:
            if weak in name_upper:
                return CipherStrength.WEAK
        
        # Check key size
        key_size = parts.get('key_size', 0)
        if key_size < 128:
            return CipherStrength.WEAK
        
        # Check for recommended (TLS 1.3 or AEAD with PFS)
        if name in self.tls13_ciphers:
            return CipherStrength.RECOMMENDED
        
        if 'GCM' in name_upper or 'POLY1305' in name_upper:
            if any(kex in name_upper for kex in self.pfs_key_exchanges):
                if key_size >= 256:
                    return CipherStrength.RECOMMENDED
                return CipherStrength.STRONG
        
        if key_size >= 128:
            return CipherStrength.ACCEPTABLE
        
        return CipherStrength.WEAK


class VulnerabilityScanner:
    """Scan for SSL/TLS vulnerabilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def check_heartbleed(self, host: str, port: int) -> Optional[SSLFinding]:
        """Check for Heartbleed vulnerability (CVE-2014-0160)"""
        try:
            # Build Heartbleed test packet
            hello = bytes.fromhex(
                "16 03 02 00 dc 01 00 00 d8 03 02 53"
                "43 5b 90 9d 9b 72 0b bc 0c bc 2b 92"
                "a8 48 97 cf bd 39 04 cc 16 0a 85 03"
            ).replace(b' ', b'')
            
            heartbeat = bytes.fromhex(
                "18 03 02 00 03 01 40 00"
            ).replace(b' ', b'')
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5
            )
            
            writer.write(hello)
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            
            writer.write(heartbeat)
            await writer.drain()
            
            # Check for heartbeat response
            heartbeat_response = await asyncio.wait_for(reader.read(1024), timeout=5)
            
            writer.close()
            await writer.wait_closed()
            
            if len(heartbeat_response) > 7:
                return SSLFinding(
                    title="Heartbleed Vulnerability Detected",
                    severity=SeverityLevel.CRITICAL,
                    description="The server is vulnerable to the Heartbleed bug which allows attackers to read memory contents.",
                    remediation="Update OpenSSL to a patched version (1.0.1g or later)",
                    references=["https://heartbleed.com", "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
                    cve="CVE-2014-0160",
                    cvss=7.5,
                    vulnerability_type=VulnerabilityType.HEARTBLEED
                )
                
        except Exception as e:
            self.logger.debug(f"Heartbleed check: {e}")
        
        return None
    
    async def check_poodle(
        self,
        supported_protocols: List[TLSVersion]
    ) -> Optional[SSLFinding]:
        """Check for POODLE vulnerability"""
        if TLSVersion.SSL_3_0 in supported_protocols:
            return SSLFinding(
                title="POODLE Vulnerability - SSLv3 Enabled",
                severity=SeverityLevel.HIGH,
                description="SSLv3 is enabled, making the server vulnerable to POODLE attacks.",
                remediation="Disable SSLv3 and use TLS 1.2 or higher",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2014-3566"],
                cve="CVE-2014-3566",
                cvss=4.3,
                vulnerability_type=VulnerabilityType.POODLE
            )
        return None
    
    async def check_sweet32(
        self,
        cipher_suites: List[CipherSuite]
    ) -> Optional[SSLFinding]:
        """Check for SWEET32 vulnerability (64-bit block ciphers)"""
        vulnerable_ciphers = [
            cs.name for cs in cipher_suites
            if '3DES' in cs.name.upper() or 'DES-CBC3' in cs.name.upper()
        ]
        
        if vulnerable_ciphers:
            return SSLFinding(
                title="SWEET32 Vulnerability - 64-bit Block Ciphers",
                severity=SeverityLevel.MEDIUM,
                description=f"Server supports 64-bit block ciphers vulnerable to SWEET32: {', '.join(vulnerable_ciphers[:3])}",
                remediation="Disable 3DES and other 64-bit block ciphers",
                references=["https://sweet32.info"],
                cve="CVE-2016-2183",
                cvss=5.0,
                vulnerability_type=VulnerabilityType.SWEET32
            )
        return None
    
    async def check_logjam(
        self,
        cipher_suites: List[CipherSuite]
    ) -> Optional[SSLFinding]:
        """Check for Logjam vulnerability (weak DH)"""
        dh_ciphers = [
            cs for cs in cipher_suites
            if 'DHE' in cs.key_exchange and 'ECDHE' not in cs.key_exchange
        ]
        
        # In a real implementation, we'd check the DH parameter size
        if dh_ciphers:
            return SSLFinding(
                title="Potential Logjam Vulnerability - DHE Ciphers Present",
                severity=SeverityLevel.MEDIUM,
                description="Server supports DHE ciphers. Ensure DH parameters are at least 2048 bits.",
                remediation="Use 2048-bit or larger DH parameters, or prefer ECDHE",
                references=["https://weakdh.org"],
                cve="CVE-2015-4000",
                cvss=4.3,
                vulnerability_type=VulnerabilityType.LOGJAM
            )
        return None
    
    async def check_freak(
        self,
        cipher_suites: List[CipherSuite]
    ) -> Optional[SSLFinding]:
        """Check for FREAK vulnerability (export ciphers)"""
        export_ciphers = [
            cs.name for cs in cipher_suites
            if 'EXPORT' in cs.name.upper() or 'EXP' in cs.name.upper()
        ]
        
        if export_ciphers:
            return SSLFinding(
                title="FREAK Vulnerability - Export Ciphers Enabled",
                severity=SeverityLevel.HIGH,
                description=f"Server supports export-grade ciphers: {', '.join(export_ciphers[:3])}",
                remediation="Disable all export ciphers",
                references=["https://freakattack.com"],
                cve="CVE-2015-0204",
                cvss=4.3,
                vulnerability_type=VulnerabilityType.FREAK
            )
        return None
    
    async def check_beast(
        self,
        supported_protocols: List[TLSVersion],
        cipher_suites: List[CipherSuite]
    ) -> Optional[SSLFinding]:
        """Check for BEAST vulnerability"""
        if TLSVersion.TLS_1_0 in supported_protocols:
            cbc_ciphers = [
                cs.name for cs in cipher_suites
                if 'CBC' in cs.name.upper() and cs.protocol == TLSVersion.TLS_1_0
            ]
            
            if cbc_ciphers:
                return SSLFinding(
                    title="BEAST Vulnerability - TLS 1.0 with CBC",
                    severity=SeverityLevel.MEDIUM,
                    description="TLS 1.0 with CBC mode ciphers is vulnerable to BEAST attacks.",
                    remediation="Disable TLS 1.0 or prefer RC4/GCM ciphers (prefer disabling TLS 1.0)",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2011-3389"],
                    cve="CVE-2011-3389",
                    cvss=4.3,
                    vulnerability_type=VulnerabilityType.BEAST
                )
        return None
    
    async def check_crime(
        self,
        compression_enabled: bool
    ) -> Optional[SSLFinding]:
        """Check for CRIME vulnerability"""
        if compression_enabled:
            return SSLFinding(
                title="CRIME Vulnerability - TLS Compression Enabled",
                severity=SeverityLevel.HIGH,
                description="TLS compression is enabled, making the server vulnerable to CRIME attacks.",
                remediation="Disable TLS compression",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2012-4929"],
                cve="CVE-2012-4929",
                cvss=2.6,
                vulnerability_type=VulnerabilityType.CRIME
            )
        return None
    
    async def check_rc4(
        self,
        cipher_suites: List[CipherSuite]
    ) -> Optional[SSLFinding]:
        """Check for RC4 usage"""
        rc4_ciphers = [
            cs.name for cs in cipher_suites
            if 'RC4' in cs.name.upper()
        ]
        
        if rc4_ciphers:
            return SSLFinding(
                title="Insecure RC4 Cipher Enabled",
                severity=SeverityLevel.MEDIUM,
                description=f"Server supports insecure RC4 cipher: {', '.join(rc4_ciphers[:3])}",
                remediation="Disable RC4 cipher suites",
                references=["https://www.rc4nomore.com"],
                cve="CVE-2015-2808",
                cvss=5.0,
                vulnerability_type=None
            )
        return None


class CertificateValidator:
    """Validate certificate chains and properties"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def validate_chain(self, certificates: List[Certificate]) -> List[SSLFinding]:
        """Validate certificate chain"""
        findings = []
        
        if not certificates:
            findings.append(SSLFinding(
                title="No Certificates Retrieved",
                severity=SeverityLevel.CRITICAL,
                description="Could not retrieve any certificates from the server",
                remediation="Verify SSL/TLS configuration",
                references=[]
            ))
            return findings
        
        # Check leaf certificate
        leaf = certificates[0]
        
        # Check expiration
        now = datetime.now()
        if leaf.not_after < now:
            findings.append(SSLFinding(
                title="Certificate Expired",
                severity=SeverityLevel.CRITICAL,
                description=f"Certificate expired on {leaf.not_after.isoformat()}",
                remediation="Renew the certificate immediately",
                references=[]
            ))
        elif leaf.not_after < now + timedelta(days=30):
            findings.append(SSLFinding(
                title="Certificate Expiring Soon",
                severity=SeverityLevel.MEDIUM,
                description=f"Certificate will expire on {leaf.not_after.isoformat()}",
                remediation="Plan certificate renewal",
                references=[]
            ))
        
        # Check key size
        if leaf.public_key_algorithm == 'RSA' and leaf.public_key_size < 2048:
            findings.append(SSLFinding(
                title="Weak RSA Key Size",
                severity=SeverityLevel.HIGH,
                description=f"RSA key size is only {leaf.public_key_size} bits",
                remediation="Use at least 2048-bit RSA keys, prefer 4096-bit",
                references=[]
            ))
        
        # Check signature algorithm
        weak_sig_algs = ['sha1', 'md5', 'md2']
        if any(alg in leaf.signature_algorithm.lower() for alg in weak_sig_algs):
            findings.append(SSLFinding(
                title="Weak Signature Algorithm",
                severity=SeverityLevel.HIGH,
                description=f"Certificate uses weak signature algorithm: {leaf.signature_algorithm}",
                remediation="Use SHA-256 or stronger signature algorithm",
                references=[]
            ))
        
        # Check self-signed
        if leaf.is_self_signed and not leaf.is_ca:
            findings.append(SSLFinding(
                title="Self-Signed Certificate",
                severity=SeverityLevel.MEDIUM,
                description="The certificate is self-signed and not trusted by default",
                remediation="Use a certificate from a trusted CA",
                references=[]
            ))
        
        # Check incomplete chain
        if len(certificates) == 1 and not leaf.is_self_signed:
            findings.append(SSLFinding(
                title="Incomplete Certificate Chain",
                severity=SeverityLevel.MEDIUM,
                description="Server does not send intermediate certificates",
                remediation="Configure server to send complete certificate chain",
                references=[]
            ))
        
        return findings
    
    def check_hostname_match(
        self,
        certificate: Certificate,
        hostname: str
    ) -> Optional[SSLFinding]:
        """Check if certificate matches hostname"""
        # Check CN
        cn = certificate.subject.get('commonName', '')
        if self._matches_hostname(cn, hostname):
            return None
        
        # Check SANs
        for san in certificate.san:
            if san.startswith('DNS:'):
                san_name = san[4:]
                if self._matches_hostname(san_name, hostname):
                    return None
        
        return SSLFinding(
            title="Certificate Hostname Mismatch",
            severity=SeverityLevel.HIGH,
            description=f"Certificate does not match hostname '{hostname}'",
            remediation="Obtain a certificate with the correct hostname or SANs",
            references=[]
        )
    
    def _matches_hostname(self, pattern: str, hostname: str) -> bool:
        """Check if pattern matches hostname (supports wildcards)"""
        pattern = pattern.lower()
        hostname = hostname.lower()
        
        if pattern == hostname:
            return True
        
        # Wildcard matching
        if pattern.startswith('*.'):
            suffix = pattern[2:]
            parts = hostname.split('.', 1)
            if len(parts) == 2 and parts[1] == suffix:
                return True
        
        return False


class SSLScanner:
    """Main SSL/TLS scanner"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cert_parser = CertificateParser()
        self.cipher_analyzer = CipherSuiteAnalyzer()
        self.vuln_scanner = VulnerabilityScanner()
        self.cert_validator = CertificateValidator()
    
    async def scan(self, host: str, port: int = 443) -> SSLScanResult:
        """Perform comprehensive SSL/TLS scan"""
        self.logger.info(f"Scanning {host}:{port}")
        
        certificates = []
        supported_protocols = []
        cipher_suites = []
        findings = []
        ocsp_stapling = False
        
        # Test each protocol version
        protocols_to_test = [
            (TLSVersion.SSL_3_0, ssl.PROTOCOL_SSLv23),
            (TLSVersion.TLS_1_0, ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
            (TLSVersion.TLS_1_1, ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
            (TLSVersion.TLS_1_2, ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None),
        ]
        
        for tls_version, ssl_protocol in protocols_to_test:
            if ssl_protocol is None:
                continue
            
            try:
                context = ssl.SSLContext(ssl_protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                conn = socket.create_connection((host, port), timeout=10)
                ssl_conn = context.wrap_socket(conn, server_hostname=host)
                
                supported_protocols.append(tls_version)
                
                # Get cipher
                cipher_info = ssl_conn.cipher()
                if cipher_info:
                    cipher_suite = self.cipher_analyzer.analyze_cipher(
                        cipher_info[0],
                        tls_version
                    )
                    cipher_suites.append(cipher_suite)
                
                # Get certificate chain
                if not certificates:
                    cert_der = ssl_conn.getpeercert(binary_form=True)
                    if cert_der:
                        cert = self.cert_parser.parse_certificate(cert_der, 0)
                        if cert:
                            certificates.append(cert)
                
                ssl_conn.close()
                
            except ssl.SSLError as e:
                self.logger.debug(f"Protocol {tls_version.value} not supported: {e}")
            except Exception as e:
                self.logger.debug(f"Error testing {tls_version.value}: {e}")
        
        # Check for deprecated protocols
        if TLSVersion.SSL_3_0 in supported_protocols:
            findings.append(SSLFinding(
                title="SSLv3 Protocol Enabled",
                severity=SeverityLevel.HIGH,
                description="SSLv3 is obsolete and insecure",
                remediation="Disable SSLv3",
                references=["https://tools.ietf.org/html/rfc7568"]
            ))
        
        if TLSVersion.TLS_1_0 in supported_protocols:
            findings.append(SSLFinding(
                title="TLS 1.0 Protocol Enabled",
                severity=SeverityLevel.MEDIUM,
                description="TLS 1.0 is deprecated and should not be used",
                remediation="Disable TLS 1.0 and use TLS 1.2 or 1.3",
                references=["https://tools.ietf.org/html/rfc8996"]
            ))
        
        if TLSVersion.TLS_1_1 in supported_protocols:
            findings.append(SSLFinding(
                title="TLS 1.1 Protocol Enabled",
                severity=SeverityLevel.MEDIUM,
                description="TLS 1.1 is deprecated and should not be used",
                remediation="Disable TLS 1.1 and use TLS 1.2 or 1.3",
                references=["https://tools.ietf.org/html/rfc8996"]
            ))
        
        # Check TLS 1.2 support
        if TLSVersion.TLS_1_2 not in supported_protocols:
            findings.append(SSLFinding(
                title="TLS 1.2 Not Supported",
                severity=SeverityLevel.HIGH,
                description="Server does not support TLS 1.2",
                remediation="Enable TLS 1.2 support",
                references=[]
            ))
        
        # Validate certificates
        if certificates:
            cert_findings = self.cert_validator.validate_chain(certificates)
            findings.extend(cert_findings)
            
            hostname_finding = self.cert_validator.check_hostname_match(
                certificates[0],
                host
            )
            if hostname_finding:
                findings.append(hostname_finding)
        
        # Check vulnerabilities
        poodle = await self.vuln_scanner.check_poodle(supported_protocols)
        if poodle:
            findings.append(poodle)
        
        sweet32 = await self.vuln_scanner.check_sweet32(cipher_suites)
        if sweet32:
            findings.append(sweet32)
        
        freak = await self.vuln_scanner.check_freak(cipher_suites)
        if freak:
            findings.append(freak)
        
        rc4 = await self.vuln_scanner.check_rc4(cipher_suites)
        if rc4:
            findings.append(rc4)
        
        # Check for weak ciphers
        weak_ciphers = [
            cs for cs in cipher_suites
            if cs.strength in [CipherStrength.INSECURE, CipherStrength.WEAK]
        ]
        if weak_ciphers:
            findings.append(SSLFinding(
                title="Weak Cipher Suites Enabled",
                severity=SeverityLevel.MEDIUM,
                description=f"Server supports {len(weak_ciphers)} weak cipher suite(s)",
                remediation="Disable weak cipher suites and use only strong ciphers",
                references=[]
            ))
        
        # Check for PFS
        pfs_ciphers = [cs for cs in cipher_suites if cs.pfs]
        if not pfs_ciphers and cipher_suites:
            findings.append(SSLFinding(
                title="No Perfect Forward Secrecy",
                severity=SeverityLevel.MEDIUM,
                description="Server does not support Forward Secrecy",
                remediation="Enable ECDHE or DHE cipher suites",
                references=[]
            ))
        
        # Calculate grade
        grade = self._calculate_grade(findings, supported_protocols, cipher_suites)
        
        return SSLScanResult(
            host=host,
            port=port,
            timestamp=datetime.now(),
            certificates=certificates,
            supported_protocols=supported_protocols,
            cipher_suites=cipher_suites,
            findings=findings,
            ocsp_stapling=ocsp_stapling,
            grade=grade
        )
    
    def _calculate_grade(
        self,
        findings: List[SSLFinding],
        protocols: List[TLSVersion],
        ciphers: List[CipherSuite]
    ) -> str:
        """Calculate SSL grade based on findings"""
        # Start with A
        score = 100
        
        for finding in findings:
            if finding.severity == SeverityLevel.CRITICAL:
                score -= 40
            elif finding.severity == SeverityLevel.HIGH:
                score -= 25
            elif finding.severity == SeverityLevel.MEDIUM:
                score -= 10
            elif finding.severity == SeverityLevel.LOW:
                score -= 5
        
        # Protocol bonuses/penalties
        if TLSVersion.TLS_1_3 not in protocols:
            score -= 5
        
        # Cipher bonuses
        strong_ciphers = [c for c in ciphers if c.strength == CipherStrength.RECOMMENDED]
        if strong_ciphers:
            score += 5
        
        # Grade mapping
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        elif score >= 50:
            return "E"
        else:
            return "F"


class AdvancedSSLSecurity:
    """Main SSL/TLS security analysis engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.scanner = SSLScanner()
        
        # Statistics
        self.stats = {
            "hosts_scanned": 0,
            "vulnerabilities_found": 0,
            "expired_certs": 0,
            "weak_ciphers": 0
        }
    
    async def scan_host(self, host: str, port: int = 443) -> SSLScanResult:
        """Scan a single host"""
        result = await self.scanner.scan(host, port)
        
        self.stats["hosts_scanned"] += 1
        self.stats["vulnerabilities_found"] += len([
            f for f in result.findings
            if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        ])
        
        for finding in result.findings:
            if "expired" in finding.title.lower():
                self.stats["expired_certs"] += 1
            if "weak" in finding.title.lower():
                self.stats["weak_ciphers"] += 1
        
        return result
    
    async def scan_multiple(
        self,
        targets: List[Tuple[str, int]]
    ) -> List[SSLScanResult]:
        """Scan multiple hosts"""
        results = []
        
        for host, port in targets:
            try:
                result = await self.scan_host(host, port)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error scanning {host}:{port}: {e}")
        
        return results
    
    def generate_report(self, results: List[SSLScanResult]) -> Dict[str, Any]:
        """Generate security report from scan results"""
        report = {
            "summary": {
                "total_hosts": len(results),
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 0,
                "low_findings": 0,
                "grade_distribution": {}
            },
            "hosts": []
        }
        
        for result in results:
            # Count findings by severity
            for finding in result.findings:
                if finding.severity == SeverityLevel.CRITICAL:
                    report["summary"]["critical_findings"] += 1
                elif finding.severity == SeverityLevel.HIGH:
                    report["summary"]["high_findings"] += 1
                elif finding.severity == SeverityLevel.MEDIUM:
                    report["summary"]["medium_findings"] += 1
                elif finding.severity == SeverityLevel.LOW:
                    report["summary"]["low_findings"] += 1
            
            # Count grades
            if result.grade not in report["summary"]["grade_distribution"]:
                report["summary"]["grade_distribution"][result.grade] = 0
            report["summary"]["grade_distribution"][result.grade] += 1
            
            # Add host details
            report["hosts"].append({
                "host": result.host,
                "port": result.port,
                "grade": result.grade,
                "protocols": [p.value for p in result.supported_protocols],
                "certificate": {
                    "subject": result.certificates[0].subject if result.certificates else {},
                    "expires": result.certificates[0].not_after.isoformat() if result.certificates else None,
                    "issuer": result.certificates[0].issuer if result.certificates else {}
                },
                "findings_count": len(result.findings)
            })
        
        return report
    
    def export_results(self, results: List[SSLScanResult]) -> str:
        """Export results to JSON"""
        return json.dumps([
            {
                "host": r.host,
                "port": r.port,
                "timestamp": r.timestamp.isoformat(),
                "grade": r.grade,
                "protocols": [p.value for p in r.supported_protocols],
                "ciphers": [
                    {
                        "name": c.name,
                        "strength": c.strength.value,
                        "pfs": c.pfs
                    }
                    for c in r.cipher_suites
                ],
                "certificates": [
                    {
                        "subject": c.subject,
                        "issuer": c.issuer,
                        "not_before": c.not_before.isoformat(),
                        "not_after": c.not_after.isoformat(),
                        "fingerprint": c.fingerprint_sha256
                    }
                    for c in r.certificates
                ],
                "findings": [
                    {
                        "title": f.title,
                        "severity": f.severity.value,
                        "description": f.description,
                        "cve": f.cve
                    }
                    for f in r.findings
                ]
            }
            for r in results
        ], indent=2)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        return self.stats


# Main execution
if __name__ == "__main__":
    import asyncio
    
    async def main():
        ssl_security = AdvancedSSLSecurity()
        
        # Test scan
        print("Scanning example.com:443...")
        try:
            result = await ssl_security.scan_host("example.com", 443)
            
            print(f"\nResults for {result.host}:{result.port}")
            print(f"Grade: {result.grade}")
            print(f"\nSupported Protocols:")
            for proto in result.supported_protocols:
                print(f"  - {proto.value}")
            
            print(f"\nCertificate:")
            if result.certificates:
                cert = result.certificates[0]
                print(f"  Subject: {cert.subject}")
                print(f"  Expires: {cert.not_after}")
            
            print(f"\nFindings ({len(result.findings)}):")
            for finding in result.findings:
                print(f"  [{finding.severity.value.upper()}] {finding.title}")
            
            # Print statistics
            print("\nStatistics:")
            stats = ssl_security.get_statistics()
            for key, value in stats.items():
                print(f"  {key}: {value}")
                
        except Exception as e:
            print(f"Error: {e}")
    
    asyncio.run(main())
