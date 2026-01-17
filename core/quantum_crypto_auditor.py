#!/usr/bin/env python3
"""
Quantum-Safe Cryptographic Auditor
═══════════════════════════════════════════════════════════════════════════════
Comprehensive audit engine to assess cryptographic infrastructure readiness
for the post-quantum era. Identifies vulnerable algorithms, keys, certificates,
and provides migration paths to quantum-resistant alternatives.

Based on NIST Post-Quantum Cryptography standards and industry best practices.
═══════════════════════════════════════════════════════════════════════════════
"""

import asyncio
import hashlib
import json
import logging
import ssl
import socket
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class CryptoAlgorithm(Enum):
    """Cryptographic algorithms and their quantum vulnerability status."""
    # Asymmetric - VULNERABLE to quantum
    RSA_1024 = "RSA-1024"
    RSA_2048 = "RSA-2048"
    RSA_4096 = "RSA-4096"
    ECDSA_P256 = "ECDSA-P256"
    ECDSA_P384 = "ECDSA-P384"
    ECDSA_P521 = "ECDSA-P521"
    ECDH_P256 = "ECDH-P256"
    ECDH_P384 = "ECDH-P384"
    DSA_2048 = "DSA-2048"
    DH_2048 = "DH-2048"
    ED25519 = "Ed25519"
    ED448 = "Ed448"
    
    # Symmetric - SECURE against quantum (with larger keys)
    AES_128 = "AES-128"
    AES_192 = "AES-192"
    AES_256 = "AES-256"
    CHACHA20 = "ChaCha20"
    TWOFISH = "Twofish"
    CAMELLIA = "Camellia"
    
    # Hash - SECURE against quantum
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"
    SHA3_256 = "SHA3-256"
    SHA3_512 = "SHA3-512"
    BLAKE2 = "BLAKE2"
    BLAKE3 = "BLAKE3"
    
    # Legacy - VULNERABLE even without quantum
    MD5 = "MD5"
    SHA1 = "SHA-1"
    DES = "DES"
    TRIPLE_DES = "3DES"
    RC4 = "RC4"
    
    # Post-Quantum (NIST standardized)
    KYBER_512 = "KYBER-512"
    KYBER_768 = "KYBER-768"
    KYBER_1024 = "KYBER-1024"
    DILITHIUM_2 = "DILITHIUM-2"
    DILITHIUM_3 = "DILITHIUM-3"
    DILITHIUM_5 = "DILITHIUM-5"
    FALCON_512 = "FALCON-512"
    FALCON_1024 = "FALCON-1024"
    SPHINCS_SHA256_128F = "SPHINCS+-SHA256-128f"
    SPHINCS_SHA256_256F = "SPHINCS+-SHA256-256f"


class QuantumThreatLevel(Enum):
    """Quantum threat assessment levels."""
    CRITICAL = "critical"        # Broken by quantum, needs immediate migration
    HIGH = "high"                # Vulnerable, quantum-enabled attacks in 5-10 years
    MEDIUM = "medium"            # Theoretically vulnerable but adequate for now
    LOW = "low"                  # Symmetric crypto needing larger keys
    SECURE = "secure"            # Post-quantum or quantum-resistant
    UNKNOWN = "unknown"          # Unable to determine


class AssetType(Enum):
    """Types of cryptographic assets."""
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    PUBLIC_KEY = "public_key"
    TLS_CONFIG = "tls_config"
    SSH_KEY = "ssh_key"
    VPN_CONFIG = "vpn_config"
    DATABASE_ENCRYPTION = "database_encryption"
    FILE_ENCRYPTION = "file_encryption"
    KEY_EXCHANGE = "key_exchange"
    DIGITAL_SIGNATURE = "digital_signature"
    PASSWORD_HASH = "password_hash"
    CODE_SIGNING = "code_signing"


class MigrationPriority(Enum):
    """Priority levels for migration."""
    IMMEDIATE = "immediate"      # Migrate now
    HIGH = "high"               # Migrate within 6 months
    MEDIUM = "medium"           # Migrate within 1-2 years
    LOW = "low"                 # Migrate within 3-5 years
    MONITOR = "monitor"         # Keep monitoring, no action needed


@dataclass
class CryptoAsset:
    """Represents a cryptographic asset in the infrastructure."""
    asset_id: str
    asset_type: AssetType
    location: str
    algorithm: CryptoAlgorithm
    key_size: int
    usage: str
    owner: str
    expiry: Optional[datetime] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QuantumVulnerability:
    """Identified quantum vulnerability."""
    vuln_id: str
    asset: CryptoAsset
    threat_level: QuantumThreatLevel
    attack_vector: str
    quantum_break_estimate: str  # e.g., "2030-2035"
    current_security_bits: int
    post_quantum_security_bits: int
    recommendation: str
    migration_priority: MigrationPriority
    affected_data: List[str]
    compliance_impact: List[str]


@dataclass
class MigrationPath:
    """Recommended migration path to quantum-safe cryptography."""
    path_id: str
    source_algorithm: CryptoAlgorithm
    target_algorithm: CryptoAlgorithm
    hybrid_option: Optional[str]  # Combined classical + PQ
    complexity: str  # Low/Medium/High
    estimated_effort: str  # e.g., "2-4 weeks"
    dependencies: List[str]
    steps: List[str]
    rollback_plan: str
    testing_requirements: List[str]


@dataclass
class ComplianceRequirement:
    """Compliance requirements for quantum readiness."""
    standard: str
    requirement_id: str
    description: str
    deadline: Optional[datetime]
    current_status: str
    gaps: List[str]


@dataclass
class AuditReport:
    """Complete quantum cryptographic audit report."""
    report_id: str
    generated_at: datetime
    organization: str
    scope: List[str]
    total_assets: int
    vulnerable_assets: int
    critical_findings: int
    vulnerabilities: List[QuantumVulnerability]
    migration_paths: List[MigrationPath]
    compliance_status: List[ComplianceRequirement]
    risk_score: float
    executive_summary: str
    recommendations: List[str]
    timeline: Dict[str, str]


class QuantumCryptoAuditor:
    """
    Quantum-Safe Cryptographic Auditor.
    
    Comprehensive analysis engine that:
    1. Discovers cryptographic assets across infrastructure
    2. Assesses quantum vulnerability of each asset
    3. Provides migration paths to PQC standards
    4. Tracks compliance with emerging regulations
    5. Monitors cryptographic agility readiness
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # Algorithm vulnerability database
        self.algorithm_threats = self._build_threat_database()
        
        # NIST PQC recommendations
        self.pqc_recommendations = self._load_pqc_recommendations()
        
        # Discovered assets
        self.assets: List[CryptoAsset] = []
        self.vulnerabilities: List[QuantumVulnerability] = []
        
        # Migration tracking
        self.migration_plans: Dict[str, MigrationPath] = {}
        
        # Statistics
        self.stats = {
            "scans_performed": 0,
            "assets_discovered": 0,
            "vulnerabilities_found": 0,
            "critical_issues": 0
        }
        
        # Demo data
        self._load_demo_assets()
        
        logger.info("Quantum-Safe Cryptographic Auditor initialized")
    
    def _build_threat_database(self) -> Dict[CryptoAlgorithm, Dict[str, Any]]:
        """Build database of algorithm quantum vulnerabilities."""
        return {
            # RSA - Vulnerable to Shor's algorithm
            CryptoAlgorithm.RSA_1024: {
                "threat_level": QuantumThreatLevel.CRITICAL,
                "classical_bits": 80,
                "quantum_bits": 0,
                "attack": "Shor's Algorithm",
                "break_estimate": "Already weak classically",
                "recommendation": "Migrate immediately to KYBER + DILITHIUM"
            },
            CryptoAlgorithm.RSA_2048: {
                "threat_level": QuantumThreatLevel.HIGH,
                "classical_bits": 112,
                "quantum_bits": 0,
                "attack": "Shor's Algorithm",
                "break_estimate": "2030-2035 with CRQC",
                "recommendation": "Plan migration to KYBER-768 + DILITHIUM-3"
            },
            CryptoAlgorithm.RSA_4096: {
                "threat_level": QuantumThreatLevel.HIGH,
                "classical_bits": 140,
                "quantum_bits": 0,
                "attack": "Shor's Algorithm",
                "break_estimate": "2033-2040 with CRQC",
                "recommendation": "Plan migration to KYBER-1024 + DILITHIUM-5"
            },
            
            # ECDSA/ECDH - Vulnerable to Shor's algorithm
            CryptoAlgorithm.ECDSA_P256: {
                "threat_level": QuantumThreatLevel.HIGH,
                "classical_bits": 128,
                "quantum_bits": 0,
                "attack": "Shor's Algorithm (ECDLP)",
                "break_estimate": "2030-2035 with CRQC",
                "recommendation": "Migrate to DILITHIUM-3 for signatures"
            },
            CryptoAlgorithm.ECDSA_P384: {
                "threat_level": QuantumThreatLevel.HIGH,
                "classical_bits": 192,
                "quantum_bits": 0,
                "attack": "Shor's Algorithm (ECDLP)",
                "break_estimate": "2032-2037 with CRQC",
                "recommendation": "Migrate to DILITHIUM-5 for signatures"
            },
            CryptoAlgorithm.ECDH_P256: {
                "threat_level": QuantumThreatLevel.HIGH,
                "classical_bits": 128,
                "quantum_bits": 0,
                "attack": "Shor's Algorithm (ECDLP)",
                "break_estimate": "2030-2035 with CRQC",
                "recommendation": "Migrate to KYBER-768 for key exchange"
            },
            CryptoAlgorithm.ED25519: {
                "threat_level": QuantumThreatLevel.HIGH,
                "classical_bits": 128,
                "quantum_bits": 0,
                "attack": "Shor's Algorithm (ECDLP)",
                "break_estimate": "2030-2035 with CRQC",
                "recommendation": "Migrate to DILITHIUM-3"
            },
            
            # DH/DSA - Vulnerable
            CryptoAlgorithm.DH_2048: {
                "threat_level": QuantumThreatLevel.HIGH,
                "classical_bits": 112,
                "quantum_bits": 0,
                "attack": "Shor's Algorithm (DLP)",
                "break_estimate": "2030-2035 with CRQC",
                "recommendation": "Migrate to KYBER key exchange"
            },
            CryptoAlgorithm.DSA_2048: {
                "threat_level": QuantumThreatLevel.HIGH,
                "classical_bits": 112,
                "quantum_bits": 0,
                "attack": "Shor's Algorithm (DLP)",
                "break_estimate": "2030-2035 with CRQC",
                "recommendation": "Migrate to DILITHIUM signatures"
            },
            
            # Symmetric - Grover's algorithm halves security
            CryptoAlgorithm.AES_128: {
                "threat_level": QuantumThreatLevel.MEDIUM,
                "classical_bits": 128,
                "quantum_bits": 64,
                "attack": "Grover's Algorithm",
                "break_estimate": "Reduced security post-quantum",
                "recommendation": "Upgrade to AES-256 for quantum resistance"
            },
            CryptoAlgorithm.AES_256: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 256,
                "quantum_bits": 128,
                "attack": "Grover's Algorithm",
                "break_estimate": "Secure against known quantum attacks",
                "recommendation": "No action needed - quantum resistant"
            },
            CryptoAlgorithm.CHACHA20: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 256,
                "quantum_bits": 128,
                "attack": "Grover's Algorithm",
                "break_estimate": "Secure against known quantum attacks",
                "recommendation": "No action needed - quantum resistant"
            },
            
            # Hashes - Grover's algorithm halves security
            CryptoAlgorithm.SHA256: {
                "threat_level": QuantumThreatLevel.LOW,
                "classical_bits": 256,
                "quantum_bits": 128,
                "attack": "Grover's Algorithm",
                "break_estimate": "Secure for hashing, pre-image still hard",
                "recommendation": "Consider SHA-384/512 for critical applications"
            },
            CryptoAlgorithm.SHA512: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 512,
                "quantum_bits": 256,
                "attack": "Grover's Algorithm",
                "break_estimate": "Secure against known quantum attacks",
                "recommendation": "No action needed - quantum resistant"
            },
            CryptoAlgorithm.SHA3_256: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 256,
                "quantum_bits": 128,
                "attack": "Grover's Algorithm",
                "break_estimate": "Secure - modern design",
                "recommendation": "Excellent choice for quantum readiness"
            },
            
            # Legacy - Already broken
            CryptoAlgorithm.MD5: {
                "threat_level": QuantumThreatLevel.CRITICAL,
                "classical_bits": 18,  # Effectively broken
                "quantum_bits": 0,
                "attack": "Classical collision attacks",
                "break_estimate": "Already broken",
                "recommendation": "Replace immediately with SHA-256 or better"
            },
            CryptoAlgorithm.SHA1: {
                "threat_level": QuantumThreatLevel.CRITICAL,
                "classical_bits": 63,  # Collision attacks
                "quantum_bits": 0,
                "attack": "Classical collision attacks",
                "break_estimate": "Already broken",
                "recommendation": "Replace immediately with SHA-256 or better"
            },
            CryptoAlgorithm.DES: {
                "threat_level": QuantumThreatLevel.CRITICAL,
                "classical_bits": 56,
                "quantum_bits": 0,
                "attack": "Brute force",
                "break_estimate": "Already broken",
                "recommendation": "Replace immediately with AES-256"
            },
            CryptoAlgorithm.TRIPLE_DES: {
                "threat_level": QuantumThreatLevel.HIGH,
                "classical_bits": 112,
                "quantum_bits": 56,
                "attack": "Sweet32 + Grover's",
                "break_estimate": "Deprecated, weak post-quantum",
                "recommendation": "Replace with AES-256"
            },
            CryptoAlgorithm.RC4: {
                "threat_level": QuantumThreatLevel.CRITICAL,
                "classical_bits": 0,
                "quantum_bits": 0,
                "attack": "Statistical attacks",
                "break_estimate": "Already broken",
                "recommendation": "Replace immediately with AES-GCM or ChaCha20-Poly1305"
            },
            
            # Post-Quantum - SECURE
            CryptoAlgorithm.KYBER_512: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 128,
                "quantum_bits": 128,
                "attack": "None known",
                "break_estimate": "Designed for quantum resistance",
                "recommendation": "NIST standardized - good for most uses"
            },
            CryptoAlgorithm.KYBER_768: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 192,
                "quantum_bits": 192,
                "attack": "None known",
                "break_estimate": "Designed for quantum resistance",
                "recommendation": "NIST standardized - recommended for high security"
            },
            CryptoAlgorithm.KYBER_1024: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 256,
                "quantum_bits": 256,
                "attack": "None known",
                "break_estimate": "Designed for quantum resistance",
                "recommendation": "NIST standardized - highest security level"
            },
            CryptoAlgorithm.DILITHIUM_2: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 128,
                "quantum_bits": 128,
                "attack": "None known",
                "break_estimate": "Designed for quantum resistance",
                "recommendation": "NIST standardized digital signature"
            },
            CryptoAlgorithm.DILITHIUM_3: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 192,
                "quantum_bits": 192,
                "attack": "None known",
                "break_estimate": "Designed for quantum resistance",
                "recommendation": "NIST standardized - recommended for most uses"
            },
            CryptoAlgorithm.DILITHIUM_5: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 256,
                "quantum_bits": 256,
                "attack": "None known",
                "break_estimate": "Designed for quantum resistance",
                "recommendation": "NIST standardized - highest security"
            },
            CryptoAlgorithm.FALCON_512: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 128,
                "quantum_bits": 128,
                "attack": "None known",
                "break_estimate": "Designed for quantum resistance",
                "recommendation": "NIST standardized - smaller signatures than Dilithium"
            },
            CryptoAlgorithm.SPHINCS_SHA256_128F: {
                "threat_level": QuantumThreatLevel.SECURE,
                "classical_bits": 128,
                "quantum_bits": 128,
                "attack": "None known",
                "break_estimate": "Stateless hash-based signatures",
                "recommendation": "Conservative choice - only relies on hash security"
            }
        }
    
    def _load_pqc_recommendations(self) -> Dict[str, Dict[str, Any]]:
        """Load NIST PQC recommendations and migration guidance."""
        return {
            "key_encapsulation": {
                "primary": CryptoAlgorithm.KYBER_768,
                "alternatives": [CryptoAlgorithm.KYBER_512, CryptoAlgorithm.KYBER_1024],
                "hybrid": "X25519 + Kyber-768 (recommended during transition)",
                "use_cases": ["TLS key exchange", "VPN", "Secure messaging"]
            },
            "digital_signatures": {
                "primary": CryptoAlgorithm.DILITHIUM_3,
                "alternatives": [CryptoAlgorithm.FALCON_512, CryptoAlgorithm.SPHINCS_SHA256_128F],
                "hybrid": "ECDSA-P256 + Dilithium-3 (recommended during transition)",
                "use_cases": ["Code signing", "Certificates", "Document signing"]
            },
            "symmetric_encryption": {
                "primary": CryptoAlgorithm.AES_256,
                "alternatives": [CryptoAlgorithm.CHACHA20],
                "note": "256-bit symmetric keys provide 128-bit quantum security",
                "use_cases": ["Data encryption", "Disk encryption", "Database encryption"]
            },
            "hashing": {
                "primary": CryptoAlgorithm.SHA3_256,
                "alternatives": [CryptoAlgorithm.SHA384, CryptoAlgorithm.SHA512, CryptoAlgorithm.BLAKE3],
                "note": "SHA-256 acceptable; SHA-3 preferred for new implementations",
                "use_cases": ["Integrity verification", "Password hashing", "Key derivation"]
            }
        }
    
    def _load_demo_assets(self):
        """Load demo cryptographic assets for demonstration."""
        demo_assets = [
            CryptoAsset(
                asset_id="cert-001",
                asset_type=AssetType.CERTIFICATE,
                location="api.example.com:443",
                algorithm=CryptoAlgorithm.RSA_2048,
                key_size=2048,
                usage="TLS server certificate",
                owner="Platform Team",
                expiry=datetime.now() + timedelta(days=365),
                metadata={"issuer": "DigiCert", "san": ["api.example.com", "*.example.com"]}
            ),
            CryptoAsset(
                asset_id="cert-002",
                asset_type=AssetType.CERTIFICATE,
                location="auth.example.com:443",
                algorithm=CryptoAlgorithm.ECDSA_P256,
                key_size=256,
                usage="TLS server certificate",
                owner="Security Team",
                expiry=datetime.now() + timedelta(days=180),
                metadata={"issuer": "Let's Encrypt"}
            ),
            CryptoAsset(
                asset_id="key-001",
                asset_type=AssetType.SSH_KEY,
                location="bastion.example.com",
                algorithm=CryptoAlgorithm.RSA_4096,
                key_size=4096,
                usage="SSH host key",
                owner="DevOps Team",
                metadata={"fingerprint": "SHA256:abc123..."}
            ),
            CryptoAsset(
                asset_id="key-002",
                asset_type=AssetType.SSH_KEY,
                location="dev-server.example.com",
                algorithm=CryptoAlgorithm.ED25519,
                key_size=256,
                usage="SSH user key",
                owner="Engineering",
                metadata={"users": 150}
            ),
            CryptoAsset(
                asset_id="vpn-001",
                asset_type=AssetType.VPN_CONFIG,
                location="vpn.example.com",
                algorithm=CryptoAlgorithm.DH_2048,
                key_size=2048,
                usage="VPN key exchange",
                owner="IT Infrastructure",
                metadata={"protocol": "IPsec", "users": 500}
            ),
            CryptoAsset(
                asset_id="db-001",
                asset_type=AssetType.DATABASE_ENCRYPTION,
                location="prod-db-cluster",
                algorithm=CryptoAlgorithm.AES_256,
                key_size=256,
                usage="Database TDE",
                owner="DBA Team",
                metadata={"database": "PostgreSQL", "tables_encrypted": 47}
            ),
            CryptoAsset(
                asset_id="sign-001",
                asset_type=AssetType.CODE_SIGNING,
                location="CI/CD Pipeline",
                algorithm=CryptoAlgorithm.RSA_2048,
                key_size=2048,
                usage="Code signing certificate",
                owner="Security Team",
                expiry=datetime.now() + timedelta(days=730),
                metadata={"artifacts_signed": 12000}
            ),
            CryptoAsset(
                asset_id="hash-001",
                asset_type=AssetType.PASSWORD_HASH,
                location="User Database",
                algorithm=CryptoAlgorithm.SHA256,
                key_size=256,
                usage="Password hashing (bcrypt with SHA-256)",
                owner="Identity Team",
                metadata={"users": 50000}
            ),
            CryptoAsset(
                asset_id="legacy-001",
                asset_type=AssetType.TLS_CONFIG,
                location="legacy-app.example.com",
                algorithm=CryptoAlgorithm.TRIPLE_DES,
                key_size=168,
                usage="Legacy TLS cipher",
                owner="Legacy Systems",
                metadata={"protocol": "TLS 1.0", "critical_system": True}
            ),
            CryptoAsset(
                asset_id="legacy-002",
                asset_type=AssetType.CERTIFICATE,
                location="internal.example.local",
                algorithm=CryptoAlgorithm.RSA_1024,
                key_size=1024,
                usage="Internal service certificate",
                owner="Internal IT",
                expiry=datetime.now() + timedelta(days=90),
                metadata={"note": "Scheduled for decommission"}
            )
        ]
        
        self.assets = demo_assets
    
    async def discover_assets(self, targets: List[str]) -> List[CryptoAsset]:
        """
        Discover cryptographic assets in target infrastructure.
        
        Args:
            targets: List of targets (hosts, IPs, paths)
        
        Returns:
            List of discovered cryptographic assets
        """
        discovered = []
        
        for target in targets:
            try:
                # TLS certificate discovery
                if ":" in target or target.startswith("http"):
                    asset = await self._scan_tls_endpoint(target)
                    if asset:
                        discovered.append(asset)
                
                # SSH key discovery
                if ":22" in target or "ssh" in target.lower():
                    asset = await self._scan_ssh_endpoint(target)
                    if asset:
                        discovered.append(asset)
                
            except Exception as e:
                logger.warning(f"Error scanning {target}: {e}")
        
        self.assets.extend(discovered)
        self.stats["assets_discovered"] += len(discovered)
        return discovered
    
    async def _scan_tls_endpoint(self, target: str) -> Optional[CryptoAsset]:
        """Scan TLS endpoint for certificate information."""
        try:
            # Parse target
            if "://" in target:
                host = target.split("://")[1].split("/")[0]
            else:
                host = target.split("/")[0]
            
            if ":" in host:
                hostname, port = host.split(":")
                port = int(port)
            else:
                hostname = host
                port = 443
            
            # Connect and get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    
                    # Parse certificate details (simplified)
                    # In production, use cryptography library for full parsing
                    algorithm = CryptoAlgorithm.RSA_2048  # Default assumption
                    key_size = 2048
                    
                    if cipher:
                        cipher_name = cipher[0]
                        if "ECDSA" in cipher_name or "ECDHE" in cipher_name:
                            algorithm = CryptoAlgorithm.ECDSA_P256
                            key_size = 256
                        elif "RSA" in cipher_name:
                            algorithm = CryptoAlgorithm.RSA_2048
                    
                    return CryptoAsset(
                        asset_id=f"discovered-{hashlib.md5(target.encode()).hexdigest()[:8]}",
                        asset_type=AssetType.CERTIFICATE,
                        location=f"{hostname}:{port}",
                        algorithm=algorithm,
                        key_size=key_size,
                        usage="TLS server certificate",
                        owner="Discovered",
                        metadata={"cipher": cipher_name if cipher else "Unknown"}
                    )
        
        except Exception as e:
            logger.debug(f"Could not scan TLS endpoint {target}: {e}")
            return None
    
    async def _scan_ssh_endpoint(self, target: str) -> Optional[CryptoAsset]:
        """Scan SSH endpoint for key information."""
        # Simplified SSH scanning - would use paramiko in production
        return None
    
    async def assess_asset(self, asset: CryptoAsset) -> QuantumVulnerability:
        """
        Assess quantum vulnerability of a cryptographic asset.
        
        Args:
            asset: Cryptographic asset to assess
        
        Returns:
            QuantumVulnerability assessment
        """
        threat_info = self.algorithm_threats.get(asset.algorithm)
        
        if not threat_info:
            return QuantumVulnerability(
                vuln_id=f"vuln-{asset.asset_id}",
                asset=asset,
                threat_level=QuantumThreatLevel.UNKNOWN,
                attack_vector="Unknown algorithm",
                quantum_break_estimate="Unable to determine",
                current_security_bits=0,
                post_quantum_security_bits=0,
                recommendation="Manual review required",
                migration_priority=MigrationPriority.HIGH,
                affected_data=["Unknown"],
                compliance_impact=["Requires investigation"]
            )
        
        # Determine migration priority
        if threat_info["threat_level"] == QuantumThreatLevel.CRITICAL:
            priority = MigrationPriority.IMMEDIATE
        elif threat_info["threat_level"] == QuantumThreatLevel.HIGH:
            priority = MigrationPriority.HIGH
        elif threat_info["threat_level"] == QuantumThreatLevel.MEDIUM:
            priority = MigrationPriority.MEDIUM
        elif threat_info["threat_level"] == QuantumThreatLevel.LOW:
            priority = MigrationPriority.LOW
        else:
            priority = MigrationPriority.MONITOR
        
        # Determine affected data based on asset type
        affected_data = self._determine_affected_data(asset)
        
        # Determine compliance impact
        compliance_impact = self._determine_compliance_impact(asset, threat_info["threat_level"])
        
        vuln = QuantumVulnerability(
            vuln_id=f"vuln-{asset.asset_id}",
            asset=asset,
            threat_level=threat_info["threat_level"],
            attack_vector=threat_info["attack"],
            quantum_break_estimate=threat_info["break_estimate"],
            current_security_bits=threat_info["classical_bits"],
            post_quantum_security_bits=threat_info["quantum_bits"],
            recommendation=threat_info["recommendation"],
            migration_priority=priority,
            affected_data=affected_data,
            compliance_impact=compliance_impact
        )
        
        if threat_info["threat_level"] in [QuantumThreatLevel.CRITICAL, QuantumThreatLevel.HIGH]:
            self.vulnerabilities.append(vuln)
            self.stats["vulnerabilities_found"] += 1
            if threat_info["threat_level"] == QuantumThreatLevel.CRITICAL:
                self.stats["critical_issues"] += 1
        
        return vuln
    
    def _determine_affected_data(self, asset: CryptoAsset) -> List[str]:
        """Determine what data is affected by this asset's vulnerability."""
        mapping = {
            AssetType.CERTIFICATE: ["TLS traffic", "API communications", "User sessions"],
            AssetType.PRIVATE_KEY: ["Encrypted data", "Signed artifacts", "Authentication"],
            AssetType.SSH_KEY: ["Server access", "Git operations", "Deployment pipelines"],
            AssetType.VPN_CONFIG: ["Remote access traffic", "Internal communications"],
            AssetType.DATABASE_ENCRYPTION: ["Customer data", "PII", "Financial records"],
            AssetType.CODE_SIGNING: ["Software integrity", "Update mechanism", "Trust chain"],
            AssetType.PASSWORD_HASH: ["User credentials", "Authentication system"]
        }
        return mapping.get(asset.asset_type, ["Unknown data"])
    
    def _determine_compliance_impact(self, asset: CryptoAsset, 
                                     threat_level: QuantumThreatLevel) -> List[str]:
        """Determine compliance implications of quantum vulnerability."""
        impacts = []
        
        if threat_level in [QuantumThreatLevel.CRITICAL, QuantumThreatLevel.HIGH]:
            impacts.extend([
                "NIST SP 800-131A: Algorithm deprecation requirements",
                "PCI DSS 4.0: Strong cryptography requirements",
                "HIPAA: PHI encryption requirements"
            ])
            
            if asset.asset_type in [AssetType.DATABASE_ENCRYPTION, AssetType.FILE_ENCRYPTION]:
                impacts.append("GDPR Article 32: Appropriate security measures")
            
            if asset.asset_type == AssetType.CODE_SIGNING:
                impacts.append("SLSA: Supply chain integrity requirements")
        
        elif threat_level == QuantumThreatLevel.MEDIUM:
            impacts.append("NIST: Plan for cryptographic agility")
        
        return impacts if impacts else ["No immediate compliance impact"]
    
    def generate_migration_path(self, source: CryptoAlgorithm, 
                                 use_case: str) -> MigrationPath:
        """
        Generate migration path from vulnerable to quantum-safe algorithm.
        
        Args:
            source: Current vulnerable algorithm
            use_case: How the algorithm is being used
        
        Returns:
            MigrationPath with detailed steps
        """
        # Determine target based on use case
        if use_case in ["key_exchange", "tls", "vpn"]:
            target = CryptoAlgorithm.KYBER_768
            hybrid = "X25519 + Kyber-768"
        elif use_case in ["signature", "code_signing", "certificate"]:
            target = CryptoAlgorithm.DILITHIUM_3
            hybrid = "ECDSA-P256 + Dilithium-3"
        elif use_case in ["encryption", "database"]:
            target = CryptoAlgorithm.AES_256
            hybrid = None
        else:
            target = CryptoAlgorithm.KYBER_768
            hybrid = "Hybrid mode recommended"
        
        # Generate migration steps
        steps = [
            f"1. Inventory all systems using {source.value}",
            "2. Assess dependencies and integration points",
            "3. Set up test environment with PQC libraries (liboqs, pqcrypto)",
            f"4. Implement hybrid mode: {hybrid}" if hybrid else "4. Implement new algorithm",
            "5. Run compatibility testing with all connected systems",
            "6. Performance benchmark (PQC algorithms have different profiles)",
            "7. Staged rollout: dev → staging → production",
            "8. Monitor for issues and maintain rollback capability",
            f"9. After validation, transition to pure {target.value}",
            "10. Decommission legacy algorithm support"
        ]
        
        # Estimate complexity and effort
        complexity = "High" if source in [CryptoAlgorithm.RSA_2048, CryptoAlgorithm.ECDSA_P256] else "Medium"
        effort = "4-8 weeks" if complexity == "High" else "2-4 weeks"
        
        path = MigrationPath(
            path_id=f"path-{source.value}-to-{target.value}",
            source_algorithm=source,
            target_algorithm=target,
            hybrid_option=hybrid,
            complexity=complexity,
            estimated_effort=effort,
            dependencies=[
                "OpenSSL 3.x with OQS provider",
                "Updated TLS libraries",
                "Client compatibility updates"
            ],
            steps=steps,
            rollback_plan=f"Maintain {source.value} support during transition period. Instant fallback via configuration.",
            testing_requirements=[
                "Interoperability testing with all clients",
                "Performance testing under load",
                "Security review of implementation",
                "Penetration testing of new configuration"
            ]
        )
        
        self.migration_plans[path.path_id] = path
        return path
    
    async def run_full_audit(self, organization: str = "Organization",
                             scope: Optional[List[str]] = None) -> AuditReport:
        """
        Run comprehensive quantum cryptographic audit.
        
        Args:
            organization: Organization name for report
            scope: Optional specific scope (uses all assets if None)
        
        Returns:
            Complete AuditReport
        """
        self.stats["scans_performed"] += 1
        
        # Assess all assets
        vulnerabilities = []
        migration_paths = []
        
        for asset in self.assets:
            vuln = await self.assess_asset(asset)
            if vuln.threat_level in [QuantumThreatLevel.CRITICAL, QuantumThreatLevel.HIGH, 
                                      QuantumThreatLevel.MEDIUM]:
                vulnerabilities.append(vuln)
                
                # Generate migration path for vulnerable assets
                use_case = self._map_asset_type_to_use_case(asset.asset_type)
                path = self.generate_migration_path(asset.algorithm, use_case)
                if path.path_id not in [p.path_id for p in migration_paths]:
                    migration_paths.append(path)
        
        # Count critical findings
        critical_count = sum(1 for v in vulnerabilities 
                            if v.threat_level == QuantumThreatLevel.CRITICAL)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        # Generate compliance status
        compliance_status = self._generate_compliance_status(vulnerabilities)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            len(self.assets), 
            len(vulnerabilities),
            critical_count,
            risk_score
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities)
        
        # Generate timeline
        timeline = {
            "Immediate (0-30 days)": "Address critical vulnerabilities (legacy algorithms)",
            "Short-term (1-6 months)": "Plan RSA/ECDSA migration to hybrid PQC",
            "Medium-term (6-18 months)": "Complete migration to hybrid cryptography",
            "Long-term (18-36 months)": "Transition to pure post-quantum cryptography"
        }
        
        report = AuditReport(
            report_id=f"QCA-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            generated_at=datetime.now(),
            organization=organization,
            scope=scope or ["All discovered assets"],
            total_assets=len(self.assets),
            vulnerable_assets=len(vulnerabilities),
            critical_findings=critical_count,
            vulnerabilities=vulnerabilities,
            migration_paths=migration_paths,
            compliance_status=compliance_status,
            risk_score=risk_score,
            executive_summary=executive_summary,
            recommendations=recommendations,
            timeline=timeline
        )
        
        return report
    
    def _map_asset_type_to_use_case(self, asset_type: AssetType) -> str:
        """Map asset type to use case for migration planning."""
        mapping = {
            AssetType.CERTIFICATE: "certificate",
            AssetType.PRIVATE_KEY: "signature",
            AssetType.PUBLIC_KEY: "signature",
            AssetType.TLS_CONFIG: "tls",
            AssetType.SSH_KEY: "signature",
            AssetType.VPN_CONFIG: "vpn",
            AssetType.DATABASE_ENCRYPTION: "database",
            AssetType.FILE_ENCRYPTION: "encryption",
            AssetType.KEY_EXCHANGE: "key_exchange",
            AssetType.DIGITAL_SIGNATURE: "signature",
            AssetType.CODE_SIGNING: "code_signing"
        }
        return mapping.get(asset_type, "key_exchange")
    
    def _calculate_risk_score(self, vulnerabilities: List[QuantumVulnerability]) -> float:
        """Calculate overall quantum risk score (0-100)."""
        if not vulnerabilities:
            return 0.0
        
        weights = {
            QuantumThreatLevel.CRITICAL: 100,
            QuantumThreatLevel.HIGH: 70,
            QuantumThreatLevel.MEDIUM: 40,
            QuantumThreatLevel.LOW: 15,
            QuantumThreatLevel.SECURE: 0
        }
        
        total_weight = sum(weights.get(v.threat_level, 50) for v in vulnerabilities)
        max_weight = len(vulnerabilities) * 100
        
        return min((total_weight / max_weight) * 100 if max_weight > 0 else 0, 100)
    
    def _generate_compliance_status(self, 
                                    vulnerabilities: List[QuantumVulnerability]) -> List[ComplianceRequirement]:
        """Generate compliance status for quantum readiness."""
        return [
            ComplianceRequirement(
                standard="NIST SP 800-131A Rev 2",
                requirement_id="Crypto-Algorithm-Transition",
                description="Transition to approved algorithms",
                deadline=datetime(2030, 12, 31),
                current_status="In Progress" if vulnerabilities else "Compliant",
                gaps=[v.recommendation for v in vulnerabilities[:3]] if vulnerabilities else []
            ),
            ComplianceRequirement(
                standard="CNSA 2.0",
                requirement_id="NSA-PQC-Timeline",
                description="NSA post-quantum cryptography requirements",
                deadline=datetime(2035, 12, 31),
                current_status="Planning Required",
                gaps=["Implement KYBER for key exchange", "Implement DILITHIUM for signatures"]
            ),
            ComplianceRequirement(
                standard="FIPS 140-3",
                requirement_id="Module-Validation",
                description="Cryptographic module validation",
                deadline=None,
                current_status="Review Required",
                gaps=["Ensure PQC modules are FIPS validated when available"]
            )
        ]
    
    def _generate_executive_summary(self, total: int, vulnerable: int, 
                                    critical: int, risk_score: float) -> str:
        """Generate executive summary for the audit report."""
        return f"""
QUANTUM CRYPTOGRAPHIC READINESS ASSESSMENT

This audit assessed {total} cryptographic assets for post-quantum security readiness.

KEY FINDINGS:
• {vulnerable} assets require attention for quantum readiness
• {critical} critical vulnerabilities requiring immediate action
• Overall Quantum Risk Score: {risk_score:.1f}/100

QUANTUM THREAT TIMELINE:
Cryptographically Relevant Quantum Computers (CRQC) are projected to be available 
between 2030-2035. Organizations must begin migration now due to:
• "Harvest Now, Decrypt Later" attacks on long-lived secrets
• Complex migration requiring years of planning and implementation
• Regulatory requirements emerging globally

IMMEDIATE ACTIONS REQUIRED:
1. Eliminate use of RSA-1024, MD5, SHA-1, DES, and RC4 immediately
2. Begin hybrid PQC deployment for sensitive communications
3. Inventory all cryptographic dependencies for migration planning
4. Update procurement policies to require PQC readiness
"""
    
    def _generate_recommendations(self, 
                                   vulnerabilities: List[QuantumVulnerability]) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = [
            "🔴 CRITICAL: Replace all legacy algorithms (MD5, SHA-1, DES, RC4, RSA-1024) immediately",
            "🟠 HIGH: Begin migration planning for RSA-2048/4096 and ECDSA to hybrid PQC",
            "🟡 MEDIUM: Upgrade AES-128 to AES-256 for quantum resistance",
            "🟢 PROACTIVE: Implement cryptographic agility across all systems",
            "📋 GOVERNANCE: Establish quantum-readiness program with executive sponsorship",
            "🔧 TECHNICAL: Deploy OQS provider for OpenSSL to enable hybrid cryptography",
            "📊 MONITORING: Implement continuous cryptographic inventory monitoring",
            "🎓 TRAINING: Educate development teams on PQC implementation best practices"
        ]
        
        return recommendations
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get auditor statistics."""
        threat_distribution = defaultdict(int)
        for asset in self.assets:
            threat_info = self.algorithm_threats.get(asset.algorithm)
            if threat_info:
                threat_distribution[threat_info["threat_level"].value] += 1
        
        return {
            "total_assets": len(self.assets),
            "scans_performed": self.stats["scans_performed"],
            "vulnerabilities_found": self.stats["vulnerabilities_found"],
            "critical_issues": self.stats["critical_issues"],
            "threat_distribution": dict(threat_distribution),
            "migration_plans": len(self.migration_plans)
        }


# Demo and testing
async def demo():
    """Demonstrate the Quantum-Safe Cryptographic Auditor."""
    print("=" * 70)
    print("Quantum-Safe Cryptographic Auditor - Demo")
    print("=" * 70)
    
    auditor = QuantumCryptoAuditor()
    
    # Show loaded assets
    print(f"\n[1] Loaded {len(auditor.assets)} demo cryptographic assets")
    for asset in auditor.assets[:3]:
        print(f"    • {asset.asset_id}: {asset.algorithm.value} at {asset.location}")
    
    # Assess individual asset
    print("\n[2] Assessing individual asset...")
    vuln = await auditor.assess_asset(auditor.assets[0])
    print(f"    Asset: {vuln.asset.asset_id}")
    print(f"    Algorithm: {vuln.asset.algorithm.value}")
    print(f"    Threat Level: {vuln.threat_level.value}")
    print(f"    Attack Vector: {vuln.attack_vector}")
    print(f"    Quantum Break Estimate: {vuln.quantum_break_estimate}")
    print(f"    Migration Priority: {vuln.migration_priority.value}")
    
    # Generate migration path
    print("\n[3] Generating migration path...")
    path = auditor.generate_migration_path(CryptoAlgorithm.RSA_2048, "certificate")
    print(f"    From: {path.source_algorithm.value}")
    print(f"    To: {path.target_algorithm.value}")
    print(f"    Hybrid Option: {path.hybrid_option}")
    print(f"    Complexity: {path.complexity}")
    print(f"    Estimated Effort: {path.estimated_effort}")
    
    # Run full audit
    print("\n[4] Running full audit...")
    report = await auditor.run_full_audit("Example Corp")
    print(f"    Report ID: {report.report_id}")
    print(f"    Total Assets: {report.total_assets}")
    print(f"    Vulnerable Assets: {report.vulnerable_assets}")
    print(f"    Critical Findings: {report.critical_findings}")
    print(f"    Risk Score: {report.risk_score:.1f}/100")
    
    # Show timeline
    print("\n[5] Migration Timeline:")
    for phase, action in report.timeline.items():
        print(f"    {phase}: {action}")
    
    # Statistics
    print("\n[6] Auditor Statistics:")
    stats = auditor.get_statistics()
    print(f"    Total Assets: {stats['total_assets']}")
    print(f"    Threat Distribution: {stats['threat_distribution']}")
    
    print("\n" + "=" * 70)
    print("Demo Complete!")


if __name__ == "__main__":
    asyncio.run(demo())
