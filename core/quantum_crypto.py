"""
Quantum-Resistant Cryptographic Analyzer for HydraRecon
Analyzes systems for post-quantum cryptographic readiness and vulnerabilities
"""

import asyncio
import hashlib
import json
import re
import math
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Set, Tuple
from enum import Enum, auto
from pathlib import Path
import sqlite3


class CryptoAlgorithm(Enum):
    """Cryptographic algorithms"""
    # Classical algorithms (vulnerable to quantum)
    RSA_1024 = auto()
    RSA_2048 = auto()
    RSA_4096 = auto()
    ECDSA_P256 = auto()
    ECDSA_P384 = auto()
    ECDSA_P521 = auto()
    DH_1024 = auto()
    DH_2048 = auto()
    DSA = auto()
    ECDH = auto()
    
    # Symmetric (quantum-resistant with larger keys)
    AES_128 = auto()
    AES_256 = auto()
    CHACHA20 = auto()
    
    # Hash functions
    MD5 = auto()
    SHA1 = auto()
    SHA256 = auto()
    SHA384 = auto()
    SHA512 = auto()
    SHA3_256 = auto()
    SHA3_512 = auto()
    BLAKE2 = auto()
    BLAKE3 = auto()
    
    # Post-quantum algorithms (NIST PQC winners)
    CRYSTALS_KYBER = auto()
    CRYSTALS_DILITHIUM = auto()
    FALCON = auto()
    SPHINCS_PLUS = auto()
    
    # Hybrid schemes
    HYBRID_RSA_KYBER = auto()
    HYBRID_ECDH_KYBER = auto()
    
    # Unknown/other
    UNKNOWN = auto()


class QuantumThreatLevel(Enum):
    """Threat level from quantum computers"""
    CRITICAL = auto()      # Broken by quantum computers
    HIGH = auto()          # Significantly weakened
    MEDIUM = auto()        # Somewhat weakened
    LOW = auto()           # Minimal impact
    QUANTUM_SAFE = auto()  # Resistant to quantum attacks


class CryptoUsage(Enum):
    """How cryptography is used"""
    KEY_EXCHANGE = auto()
    DIGITAL_SIGNATURE = auto()
    ENCRYPTION = auto()
    HASHING = auto()
    KEY_DERIVATION = auto()
    AUTHENTICATION = auto()
    TLS_HANDSHAKE = auto()
    CERTIFICATE = auto()
    CODE_SIGNING = auto()
    DISK_ENCRYPTION = auto()


class ReadinessLevel(Enum):
    """Post-quantum readiness level"""
    NOT_READY = auto()
    AWARENESS = auto()
    PLANNING = auto()
    IMPLEMENTING = auto()
    TESTING = auto()
    DEPLOYED = auto()


@dataclass
class CryptoAsset:
    """A cryptographic asset in the system"""
    asset_id: str
    name: str
    algorithm: CryptoAlgorithm
    key_size: int
    usage: CryptoUsage
    location: str
    quantum_threat: QuantumThreatLevel
    expiry_date: Optional[datetime] = None
    is_pqc_ready: bool = False
    migration_priority: str = "medium"
    dependencies: List[str] = field(default_factory=list)
    notes: str = ""
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class CryptoFinding:
    """Finding from cryptographic analysis"""
    finding_id: str
    asset_id: str
    severity: str
    title: str
    description: str
    quantum_impact: str
    recommendation: str
    remediation_effort: str = "medium"
    cwe_ids: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class MigrationPlan:
    """Plan for migrating to quantum-safe cryptography"""
    plan_id: str
    name: str
    description: str
    target_algorithms: List[CryptoAlgorithm]
    phases: List[Dict[str, Any]] = field(default_factory=list)
    estimated_duration: str = ""
    estimated_cost: str = ""
    risks: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    status: str = "draft"
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class CryptoInventory:
    """Inventory of cryptographic usage"""
    inventory_id: str
    target: str
    scan_date: datetime
    assets: List[CryptoAsset] = field(default_factory=list)
    findings: List[CryptoFinding] = field(default_factory=list)
    readiness_score: float = 0.0
    readiness_level: ReadinessLevel = ReadinessLevel.NOT_READY
    quantum_risk_score: float = 0.0
    statistics: Dict[str, Any] = field(default_factory=dict)


class QuantumCryptoAnalyzer:
    """
    Revolutionary quantum-resistant cryptographic analyzer
    Identifies vulnerable cryptography and plans PQC migration
    """
    
    def __init__(self, db_path: str = "quantum_crypto.db"):
        self.db_path = db_path
        self.inventories: Dict[str, CryptoInventory] = {}
        self.migration_plans: Dict[str, MigrationPlan] = {}
        self._init_database()
        self._load_algorithm_data()
    
    def _init_database(self):
        """Initialize the crypto analyzer database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inventories (
                inventory_id TEXT PRIMARY KEY,
                target TEXT,
                scan_date TIMESTAMP,
                readiness_score REAL,
                quantum_risk_score REAL,
                data TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS migration_plans (
                plan_id TEXT PRIMARY KEY,
                name TEXT,
                status TEXT,
                data TEXT,
                created_at TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_algorithm_data(self):
        """Load algorithm security data"""
        self.algorithm_data = {
            # RSA - vulnerable to Shor's algorithm
            CryptoAlgorithm.RSA_1024: {
                "name": "RSA-1024",
                "quantum_threat": QuantumThreatLevel.CRITICAL,
                "classical_bits": 80,
                "quantum_bits": 0,  # Completely broken
                "shor_vulnerable": True,
                "grover_impact": "N/A",
                "timeline_to_break": "Already weak, instant with quantum",
                "migration_urgency": "immediate"
            },
            CryptoAlgorithm.RSA_2048: {
                "name": "RSA-2048",
                "quantum_threat": QuantumThreatLevel.CRITICAL,
                "classical_bits": 112,
                "quantum_bits": 0,
                "shor_vulnerable": True,
                "grover_impact": "N/A",
                "timeline_to_break": "2030-2035 with CRQC",
                "migration_urgency": "high"
            },
            CryptoAlgorithm.RSA_4096: {
                "name": "RSA-4096",
                "quantum_threat": QuantumThreatLevel.CRITICAL,
                "classical_bits": 140,
                "quantum_bits": 0,
                "shor_vulnerable": True,
                "grover_impact": "N/A",
                "timeline_to_break": "2035-2040 with CRQC",
                "migration_urgency": "high"
            },
            
            # ECDSA - vulnerable to Shor's algorithm
            CryptoAlgorithm.ECDSA_P256: {
                "name": "ECDSA P-256",
                "quantum_threat": QuantumThreatLevel.CRITICAL,
                "classical_bits": 128,
                "quantum_bits": 0,
                "shor_vulnerable": True,
                "grover_impact": "N/A",
                "timeline_to_break": "2030-2035 with CRQC",
                "migration_urgency": "high"
            },
            CryptoAlgorithm.ECDSA_P384: {
                "name": "ECDSA P-384",
                "quantum_threat": QuantumThreatLevel.CRITICAL,
                "classical_bits": 192,
                "quantum_bits": 0,
                "shor_vulnerable": True,
                "grover_impact": "N/A",
                "timeline_to_break": "2032-2037 with CRQC",
                "migration_urgency": "high"
            },
            
            # Symmetric - Grover's algorithm halves effective key length
            CryptoAlgorithm.AES_128: {
                "name": "AES-128",
                "quantum_threat": QuantumThreatLevel.MEDIUM,
                "classical_bits": 128,
                "quantum_bits": 64,  # Halved by Grover
                "shor_vulnerable": False,
                "grover_impact": "Reduces to 64-bit security",
                "timeline_to_break": "May need upgrade to AES-256",
                "migration_urgency": "medium"
            },
            CryptoAlgorithm.AES_256: {
                "name": "AES-256",
                "quantum_threat": QuantumThreatLevel.LOW,
                "classical_bits": 256,
                "quantum_bits": 128,  # Halved but still strong
                "shor_vulnerable": False,
                "grover_impact": "Reduces to 128-bit security - still adequate",
                "timeline_to_break": "Remains secure",
                "migration_urgency": "low"
            },
            
            # Hash functions
            CryptoAlgorithm.SHA256: {
                "name": "SHA-256",
                "quantum_threat": QuantumThreatLevel.LOW,
                "classical_bits": 256,
                "quantum_bits": 128,
                "shor_vulnerable": False,
                "grover_impact": "Collision resistance reduced but adequate",
                "timeline_to_break": "Remains secure",
                "migration_urgency": "low"
            },
            CryptoAlgorithm.SHA3_256: {
                "name": "SHA3-256",
                "quantum_threat": QuantumThreatLevel.LOW,
                "classical_bits": 256,
                "quantum_bits": 128,
                "shor_vulnerable": False,
                "grover_impact": "Collision resistance reduced but adequate",
                "timeline_to_break": "Remains secure",
                "migration_urgency": "low"
            },
            
            # Weak/broken classical
            CryptoAlgorithm.MD5: {
                "name": "MD5",
                "quantum_threat": QuantumThreatLevel.CRITICAL,
                "classical_bits": 0,  # Already broken
                "quantum_bits": 0,
                "shor_vulnerable": False,
                "grover_impact": "N/A - already broken",
                "timeline_to_break": "Already broken",
                "migration_urgency": "immediate"
            },
            CryptoAlgorithm.SHA1: {
                "name": "SHA-1",
                "quantum_threat": QuantumThreatLevel.CRITICAL,
                "classical_bits": 0,  # Practically broken
                "quantum_bits": 0,
                "shor_vulnerable": False,
                "grover_impact": "N/A - already broken",
                "timeline_to_break": "Already broken",
                "migration_urgency": "immediate"
            },
            
            # Post-quantum algorithms (NIST PQC winners)
            CryptoAlgorithm.CRYSTALS_KYBER: {
                "name": "CRYSTALS-Kyber (ML-KEM)",
                "quantum_threat": QuantumThreatLevel.QUANTUM_SAFE,
                "classical_bits": 256,
                "quantum_bits": 256,
                "shor_vulnerable": False,
                "grover_impact": "Minimal",
                "timeline_to_break": "No known attacks",
                "migration_urgency": "none",
                "nist_level": 5,
                "type": "lattice-based KEM"
            },
            CryptoAlgorithm.CRYSTALS_DILITHIUM: {
                "name": "CRYSTALS-Dilithium (ML-DSA)",
                "quantum_threat": QuantumThreatLevel.QUANTUM_SAFE,
                "classical_bits": 256,
                "quantum_bits": 256,
                "shor_vulnerable": False,
                "grover_impact": "Minimal",
                "timeline_to_break": "No known attacks",
                "migration_urgency": "none",
                "nist_level": 5,
                "type": "lattice-based signature"
            },
            CryptoAlgorithm.FALCON: {
                "name": "FALCON",
                "quantum_threat": QuantumThreatLevel.QUANTUM_SAFE,
                "classical_bits": 256,
                "quantum_bits": 256,
                "shor_vulnerable": False,
                "grover_impact": "Minimal",
                "timeline_to_break": "No known attacks",
                "migration_urgency": "none",
                "nist_level": 5,
                "type": "lattice-based signature"
            },
            CryptoAlgorithm.SPHINCS_PLUS: {
                "name": "SPHINCS+",
                "quantum_threat": QuantumThreatLevel.QUANTUM_SAFE,
                "classical_bits": 256,
                "quantum_bits": 256,
                "shor_vulnerable": False,
                "grover_impact": "Minimal",
                "timeline_to_break": "No known attacks",
                "migration_urgency": "none",
                "nist_level": 5,
                "type": "hash-based signature"
            },
            
            # Hybrid schemes
            CryptoAlgorithm.HYBRID_RSA_KYBER: {
                "name": "Hybrid RSA + Kyber",
                "quantum_threat": QuantumThreatLevel.LOW,
                "classical_bits": 256,
                "quantum_bits": 256,
                "shor_vulnerable": False,
                "grover_impact": "Protected by PQC component",
                "timeline_to_break": "Secure against both classical and quantum",
                "migration_urgency": "none",
                "type": "hybrid KEM"
            },
        }
    
    async def analyze_system(
        self,
        target: str,
        scan_type: str = "comprehensive",
        include_dependencies: bool = True
    ) -> CryptoInventory:
        """
        Analyze a system for cryptographic vulnerabilities
        """
        inventory_id = hashlib.sha256(
            f"{target}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        inventory = CryptoInventory(
            inventory_id=inventory_id,
            target=target,
            scan_date=datetime.now()
        )
        
        # Discover cryptographic assets
        assets = await self._discover_crypto_assets(target, scan_type)
        inventory.assets = assets
        
        # Analyze for vulnerabilities
        findings = await self._analyze_vulnerabilities(assets)
        inventory.findings = findings
        
        # Calculate readiness and risk scores
        inventory.readiness_score = self._calculate_readiness_score(assets)
        inventory.readiness_level = self._determine_readiness_level(inventory.readiness_score)
        inventory.quantum_risk_score = self._calculate_quantum_risk(assets, findings)
        
        # Generate statistics
        inventory.statistics = self._generate_statistics(assets, findings)
        
        self.inventories[inventory_id] = inventory
        await self._save_inventory(inventory)
        
        return inventory
    
    async def _discover_crypto_assets(
        self,
        target: str,
        scan_type: str
    ) -> List[CryptoAsset]:
        """Discover cryptographic assets in the target"""
        assets = []
        
        # Simulate discovery of various crypto usage
        discovered = [
            # TLS/SSL certificates
            {
                "name": "TLS Certificate (Primary)",
                "algorithm": CryptoAlgorithm.RSA_2048,
                "key_size": 2048,
                "usage": CryptoUsage.TLS_HANDSHAKE,
                "location": "nginx/ssl/server.crt"
            },
            {
                "name": "TLS Certificate (Backup)",
                "algorithm": CryptoAlgorithm.ECDSA_P256,
                "key_size": 256,
                "usage": CryptoUsage.TLS_HANDSHAKE,
                "location": "nginx/ssl/server-ec.crt"
            },
            
            # Key exchange
            {
                "name": "TLS Key Exchange",
                "algorithm": CryptoAlgorithm.ECDH,
                "key_size": 256,
                "usage": CryptoUsage.KEY_EXCHANGE,
                "location": "TLS configuration"
            },
            
            # Encryption
            {
                "name": "Database Encryption",
                "algorithm": CryptoAlgorithm.AES_256,
                "key_size": 256,
                "usage": CryptoUsage.ENCRYPTION,
                "location": "database/encryption.conf"
            },
            {
                "name": "File Encryption",
                "algorithm": CryptoAlgorithm.AES_128,
                "key_size": 128,
                "usage": CryptoUsage.ENCRYPTION,
                "location": "storage/encryption"
            },
            
            # Hashing
            {
                "name": "Password Hashing",
                "algorithm": CryptoAlgorithm.SHA256,
                "key_size": 256,
                "usage": CryptoUsage.HASHING,
                "location": "auth/password_hash.py"
            },
            {
                "name": "Legacy Checksum",
                "algorithm": CryptoAlgorithm.MD5,
                "key_size": 128,
                "usage": CryptoUsage.HASHING,
                "location": "utils/checksum.py"
            },
            
            # Code signing
            {
                "name": "Code Signing Certificate",
                "algorithm": CryptoAlgorithm.RSA_4096,
                "key_size": 4096,
                "usage": CryptoUsage.CODE_SIGNING,
                "location": "build/signing.key"
            },
            
            # Authentication tokens
            {
                "name": "JWT Signing",
                "algorithm": CryptoAlgorithm.RSA_2048,
                "key_size": 2048,
                "usage": CryptoUsage.DIGITAL_SIGNATURE,
                "location": "auth/jwt_keys"
            },
        ]
        
        for item in discovered:
            asset_id = hashlib.sha256(
                f"{item['name']}{item['location']}".encode()
            ).hexdigest()[:12]
            
            algo = item["algorithm"]
            algo_data = self.algorithm_data.get(algo, {})
            
            asset = CryptoAsset(
                asset_id=asset_id,
                name=item["name"],
                algorithm=algo,
                key_size=item["key_size"],
                usage=item["usage"],
                location=item["location"],
                quantum_threat=algo_data.get("quantum_threat", QuantumThreatLevel.HIGH),
                is_pqc_ready=algo_data.get("quantum_threat") == QuantumThreatLevel.QUANTUM_SAFE,
                migration_priority=algo_data.get("migration_urgency", "medium")
            )
            
            assets.append(asset)
        
        return assets
    
    async def _analyze_vulnerabilities(
        self,
        assets: List[CryptoAsset]
    ) -> List[CryptoFinding]:
        """Analyze assets for cryptographic vulnerabilities"""
        findings = []
        
        for asset in assets:
            algo_data = self.algorithm_data.get(asset.algorithm, {})
            
            # Check for quantum vulnerability
            if algo_data.get("shor_vulnerable", False):
                finding = CryptoFinding(
                    finding_id=hashlib.sha256(
                        f"SHOR-{asset.asset_id}".encode()
                    ).hexdigest()[:12],
                    asset_id=asset.asset_id,
                    severity="critical",
                    title=f"Quantum-Vulnerable Algorithm: {algo_data.get('name', 'Unknown')}",
                    description=f"The algorithm {algo_data.get('name')} is vulnerable to Shor's algorithm. A cryptographically relevant quantum computer (CRQC) could break this in polynomial time.",
                    quantum_impact=f"Complete break of {asset.usage.name.lower()} security. Timeline: {algo_data.get('timeline_to_break', 'Unknown')}",
                    recommendation=self._get_pqc_recommendation(asset),
                    remediation_effort="high" if asset.usage in [CryptoUsage.TLS_HANDSHAKE, CryptoUsage.CERTIFICATE] else "medium",
                    cwe_ids=["CWE-327", "CWE-328"],
                    affected_systems=[asset.location]
                )
                findings.append(finding)
            
            # Check for weak classical algorithms
            if asset.algorithm in [CryptoAlgorithm.MD5, CryptoAlgorithm.SHA1, CryptoAlgorithm.RSA_1024]:
                finding = CryptoFinding(
                    finding_id=hashlib.sha256(
                        f"WEAK-{asset.asset_id}".encode()
                    ).hexdigest()[:12],
                    asset_id=asset.asset_id,
                    severity="critical",
                    title=f"Weak/Broken Algorithm: {algo_data.get('name', 'Unknown')}",
                    description=f"The algorithm {algo_data.get('name')} is already broken or severely weakened against classical attacks. This is an immediate security risk.",
                    quantum_impact="Already broken classically - quantum irrelevant",
                    recommendation=f"Immediately replace with modern algorithm. For hashing: SHA-256/SHA-3. For encryption: AES-256. For signatures: ECDSA-P384 or RSA-4096 minimum.",
                    remediation_effort="high",
                    cwe_ids=["CWE-327", "CWE-328", "CWE-916"],
                    affected_systems=[asset.location]
                )
                findings.append(finding)
            
            # Check for Grover vulnerability
            if asset.algorithm == CryptoAlgorithm.AES_128:
                finding = CryptoFinding(
                    finding_id=hashlib.sha256(
                        f"GROVER-{asset.asset_id}".encode()
                    ).hexdigest()[:12],
                    asset_id=asset.asset_id,
                    severity="medium",
                    title=f"Grover's Algorithm Impact: {algo_data.get('name', 'Unknown')}",
                    description=f"AES-128 provides 128-bit classical security but only 64-bit quantum security due to Grover's algorithm.",
                    quantum_impact="Effective security reduced from 128 to 64 bits. May be brute-forced by quantum computer.",
                    recommendation="Upgrade to AES-256 which maintains 128-bit security against quantum attacks.",
                    remediation_effort="medium",
                    cwe_ids=["CWE-326"],
                    affected_systems=[asset.location]
                )
                findings.append(finding)
            
            # Check for missing PQC in critical systems
            if asset.usage in [CryptoUsage.KEY_EXCHANGE, CryptoUsage.DIGITAL_SIGNATURE]:
                if asset.quantum_threat != QuantumThreatLevel.QUANTUM_SAFE:
                    finding = CryptoFinding(
                        finding_id=hashlib.sha256(
                            f"NOPQC-{asset.asset_id}".encode()
                        ).hexdigest()[:12],
                        asset_id=asset.asset_id,
                        severity="high",
                        title=f"No Post-Quantum Protection: {asset.name}",
                        description=f"Critical cryptographic operation ({asset.usage.name}) lacks post-quantum protection.",
                        quantum_impact="Data encrypted today can be harvested and decrypted when quantum computers become available (Harvest Now, Decrypt Later attack).",
                        recommendation="Implement hybrid cryptography combining classical with PQC algorithms (e.g., ECDH + Kyber for key exchange).",
                        remediation_effort="high",
                        cwe_ids=["CWE-327"],
                        affected_systems=[asset.location]
                    )
                    findings.append(finding)
        
        return findings
    
    def _get_pqc_recommendation(self, asset: CryptoAsset) -> str:
        """Get PQC migration recommendation for an asset"""
        recommendations = {
            CryptoUsage.KEY_EXCHANGE: "Migrate to CRYSTALS-Kyber (ML-KEM) or implement hybrid ECDH+Kyber",
            CryptoUsage.DIGITAL_SIGNATURE: "Migrate to CRYSTALS-Dilithium (ML-DSA) or FALCON for signatures",
            CryptoUsage.TLS_HANDSHAKE: "Enable TLS 1.3 with hybrid key exchange (X25519Kyber768)",
            CryptoUsage.CERTIFICATE: "Begin planning for PQC certificates; implement crypto-agility",
            CryptoUsage.CODE_SIGNING: "Prepare for dual-signing with classical and PQC signatures",
            CryptoUsage.ENCRYPTION: "Use AES-256; consider hybrid encryption for long-term secrets",
        }
        
        return recommendations.get(
            asset.usage,
            "Evaluate NIST PQC algorithms for replacement"
        )
    
    def _calculate_readiness_score(self, assets: List[CryptoAsset]) -> float:
        """Calculate PQC readiness score (0-100)"""
        if not assets:
            return 0.0
        
        pqc_ready_count = sum(1 for a in assets if a.is_pqc_ready)
        
        # Weight critical usage more heavily
        critical_usages = [CryptoUsage.KEY_EXCHANGE, CryptoUsage.DIGITAL_SIGNATURE, CryptoUsage.TLS_HANDSHAKE]
        critical_assets = [a for a in assets if a.usage in critical_usages]
        critical_ready = sum(1 for a in critical_assets if a.is_pqc_ready)
        
        base_score = (pqc_ready_count / len(assets)) * 50
        
        if critical_assets:
            critical_score = (critical_ready / len(critical_assets)) * 50
        else:
            critical_score = 50
        
        return round(base_score + critical_score, 1)
    
    def _determine_readiness_level(self, score: float) -> ReadinessLevel:
        """Determine PQC readiness level"""
        if score >= 90:
            return ReadinessLevel.DEPLOYED
        elif score >= 70:
            return ReadinessLevel.TESTING
        elif score >= 50:
            return ReadinessLevel.IMPLEMENTING
        elif score >= 30:
            return ReadinessLevel.PLANNING
        elif score >= 10:
            return ReadinessLevel.AWARENESS
        else:
            return ReadinessLevel.NOT_READY
    
    def _calculate_quantum_risk(
        self,
        assets: List[CryptoAsset],
        findings: List[CryptoFinding]
    ) -> float:
        """Calculate quantum risk score (0-100, higher = more risk)"""
        if not assets:
            return 0.0
        
        # Count vulnerable assets by threat level
        critical_count = sum(1 for a in assets if a.quantum_threat == QuantumThreatLevel.CRITICAL)
        high_count = sum(1 for a in assets if a.quantum_threat == QuantumThreatLevel.HIGH)
        medium_count = sum(1 for a in assets if a.quantum_threat == QuantumThreatLevel.MEDIUM)
        
        # Weight by severity
        weighted_risk = (critical_count * 10 + high_count * 6 + medium_count * 3)
        max_risk = len(assets) * 10
        
        # Add finding severity
        finding_risk = sum(
            10 if f.severity == "critical" else 6 if f.severity == "high" else 3
            for f in findings
        )
        
        total_risk = (weighted_risk + finding_risk) / (max_risk + len(findings) * 10 + 0.01) * 100
        
        return min(round(total_risk, 1), 100.0)
    
    def _generate_statistics(
        self,
        assets: List[CryptoAsset],
        findings: List[CryptoFinding]
    ) -> Dict[str, Any]:
        """Generate inventory statistics"""
        algo_distribution = {}
        usage_distribution = {}
        threat_distribution = {}
        
        for asset in assets:
            algo = asset.algorithm.name
            usage = asset.usage.name
            threat = asset.quantum_threat.name
            
            algo_distribution[algo] = algo_distribution.get(algo, 0) + 1
            usage_distribution[usage] = usage_distribution.get(usage, 0) + 1
            threat_distribution[threat] = threat_distribution.get(threat, 0) + 1
        
        finding_severity = {}
        for finding in findings:
            sev = finding.severity
            finding_severity[sev] = finding_severity.get(sev, 0) + 1
        
        return {
            "total_assets": len(assets),
            "total_findings": len(findings),
            "pqc_ready_assets": sum(1 for a in assets if a.is_pqc_ready),
            "algorithm_distribution": algo_distribution,
            "usage_distribution": usage_distribution,
            "threat_distribution": threat_distribution,
            "finding_severity": finding_severity,
            "immediate_action_required": sum(
                1 for a in assets if a.migration_priority == "immediate"
            ),
            "harvest_now_decrypt_later_risk": any(
                a.usage in [CryptoUsage.KEY_EXCHANGE, CryptoUsage.ENCRYPTION]
                and a.quantum_threat == QuantumThreatLevel.CRITICAL
                for a in assets
            )
        }
    
    async def create_migration_plan(
        self,
        inventory_id: str,
        target_date: Optional[datetime] = None
    ) -> MigrationPlan:
        """Create a PQC migration plan"""
        if inventory_id not in self.inventories:
            raise ValueError(f"Inventory not found: {inventory_id}")
        
        inventory = self.inventories[inventory_id]
        
        plan_id = hashlib.sha256(
            f"PLAN-{inventory_id}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]
        
        # Group assets by priority
        immediate = [a for a in inventory.assets if a.migration_priority == "immediate"]
        high = [a for a in inventory.assets if a.migration_priority == "high"]
        medium = [a for a in inventory.assets if a.migration_priority == "medium"]
        low = [a for a in inventory.assets if a.migration_priority == "low"]
        
        phases = []
        
        # Phase 1: Immediate fixes (broken algorithms)
        if immediate:
            phases.append({
                "phase": 1,
                "name": "Critical Remediation",
                "description": "Replace broken/deprecated algorithms",
                "duration": "1-3 months",
                "assets": [a.name for a in immediate],
                "actions": [
                    "Replace MD5 with SHA-256 or SHA-3",
                    "Replace SHA-1 with SHA-256 or SHA-3",
                    "Replace RSA-1024 with RSA-4096 or ECDSA",
                    "Update all affected code and configurations"
                ],
                "success_criteria": "No deprecated algorithms in use"
            })
        
        # Phase 2: Crypto agility
        phases.append({
            "phase": 2,
            "name": "Crypto Agility Implementation",
            "description": "Enable algorithm switching without code changes",
            "duration": "3-6 months",
            "assets": ["All cryptographic systems"],
            "actions": [
                "Abstract cryptographic operations behind interfaces",
                "Implement configuration-based algorithm selection",
                "Create testing framework for algorithm changes",
                "Document cryptographic dependencies"
            ],
            "success_criteria": "Algorithms can be changed via configuration"
        })
        
        # Phase 3: Hybrid implementation
        if high:
            phases.append({
                "phase": 3,
                "name": "Hybrid Cryptography Deployment",
                "description": "Deploy classical+PQC hybrid schemes",
                "duration": "6-12 months",
                "assets": [a.name for a in high],
                "actions": [
                    "Implement hybrid key exchange (ECDH + Kyber)",
                    "Deploy hybrid signatures where supported",
                    "Update TLS configurations for hybrid support",
                    "Test interoperability with external systems"
                ],
                "success_criteria": "Hybrid crypto active on critical systems"
            })
        
        # Phase 4: Full PQC migration
        phases.append({
            "phase": 4,
            "name": "Full PQC Migration",
            "description": "Complete transition to post-quantum algorithms",
            "duration": "12-24 months",
            "assets": ["All remaining assets"],
            "actions": [
                "Replace all classical asymmetric crypto with PQC",
                "Update all certificates to PQC",
                "Retire hybrid schemes where pure PQC is sufficient",
                "Complete security audit of PQC implementation"
            ],
            "success_criteria": "100% PQC coverage"
        })
        
        # Determine target algorithms
        target_algorithms = [
            CryptoAlgorithm.CRYSTALS_KYBER,
            CryptoAlgorithm.CRYSTALS_DILITHIUM,
            CryptoAlgorithm.AES_256,
            CryptoAlgorithm.SHA3_256,
            CryptoAlgorithm.HYBRID_ECDH_KYBER
        ]
        
        plan = MigrationPlan(
            plan_id=plan_id,
            name=f"PQC Migration Plan - {inventory.target}",
            description=f"Post-quantum cryptography migration plan for {inventory.target}",
            target_algorithms=target_algorithms,
            phases=phases,
            estimated_duration="24-36 months",
            estimated_cost=self._estimate_migration_cost(inventory),
            risks=[
                "Performance impact of PQC algorithms",
                "Interoperability with external systems",
                "Vendor support for PQC",
                "Regulatory requirements",
                "Key management complexity"
            ],
            dependencies=[
                "NIST PQC standardization completion",
                "Vendor library updates",
                "Hardware security module support",
                "Certificate authority PQC support"
            ],
            status="draft"
        )
        
        self.migration_plans[plan_id] = plan
        await self._save_migration_plan(plan)
        
        return plan
    
    def _estimate_migration_cost(self, inventory: CryptoInventory) -> str:
        """Estimate migration cost"""
        asset_count = len(inventory.assets)
        finding_count = len(inventory.findings)
        
        if asset_count > 20 or finding_count > 15:
            return "High ($500K-$2M)"
        elif asset_count > 10 or finding_count > 8:
            return "Medium ($100K-$500K)"
        else:
            return "Low ($50K-$100K)"
    
    async def get_quantum_timeline(self) -> Dict[str, Any]:
        """Get quantum computing threat timeline"""
        return {
            "current_state": {
                "year": 2025,
                "largest_quantum_computer": "1000+ qubits (IBM, Google)",
                "cryptographically_relevant": False,
                "recommendation": "Begin planning and implementing crypto-agility"
            },
            "near_term": {
                "years": "2025-2030",
                "expected_progress": "10,000+ qubit systems",
                "cryptographically_relevant": "Unlikely",
                "recommendation": "Implement hybrid cryptography for sensitive data"
            },
            "medium_term": {
                "years": "2030-2035",
                "expected_progress": "Early fault-tolerant systems",
                "cryptographically_relevant": "Possible for RSA-2048",
                "recommendation": "Complete PQC migration for critical systems"
            },
            "long_term": {
                "years": "2035-2040",
                "expected_progress": "Cryptographically relevant quantum computers",
                "cryptographically_relevant": "Likely",
                "recommendation": "All systems should be fully PQC-protected"
            },
            "harvest_now_decrypt_later": {
                "description": "Adversaries may collect encrypted data now to decrypt when quantum computers are available",
                "risk_period": "Data with >10 year secrecy requirement is at risk NOW",
                "affected_data": [
                    "State secrets",
                    "Medical records",
                    "Financial data",
                    "Personal identifiable information",
                    "Trade secrets",
                    "Military communications"
                ]
            },
            "nist_pqc_standards": {
                "finalized": ["CRYSTALS-Kyber (ML-KEM)", "CRYSTALS-Dilithium (ML-DSA)", "SPHINCS+"],
                "upcoming": ["FALCON"],
                "status": "Standards published, adoption beginning"
            }
        }
    
    async def _save_inventory(self, inventory: CryptoInventory):
        """Save inventory to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        data = {
            "assets": [
                {
                    "asset_id": a.asset_id,
                    "name": a.name,
                    "algorithm": a.algorithm.name,
                    "key_size": a.key_size,
                    "usage": a.usage.name,
                    "location": a.location,
                    "quantum_threat": a.quantum_threat.name,
                    "is_pqc_ready": a.is_pqc_ready
                }
                for a in inventory.assets
            ],
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description
                }
                for f in inventory.findings
            ],
            "statistics": inventory.statistics
        }
        
        cursor.execute('''
            INSERT OR REPLACE INTO inventories
            (inventory_id, target, scan_date, readiness_score, quantum_risk_score, data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            inventory.inventory_id,
            inventory.target,
            inventory.scan_date.isoformat(),
            inventory.readiness_score,
            inventory.quantum_risk_score,
            json.dumps(data)
        ))
        
        conn.commit()
        conn.close()
    
    async def _save_migration_plan(self, plan: MigrationPlan):
        """Save migration plan to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        data = {
            "description": plan.description,
            "target_algorithms": [a.name for a in plan.target_algorithms],
            "phases": plan.phases,
            "estimated_duration": plan.estimated_duration,
            "estimated_cost": plan.estimated_cost,
            "risks": plan.risks,
            "dependencies": plan.dependencies
        }
        
        cursor.execute('''
            INSERT OR REPLACE INTO migration_plans
            (plan_id, name, status, data, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            plan.plan_id,
            plan.name,
            plan.status,
            json.dumps(data),
            plan.created_at.isoformat()
        ))
        
        conn.commit()
        conn.close()


# Singleton instance
_crypto_analyzer: Optional[QuantumCryptoAnalyzer] = None


def get_crypto_analyzer() -> QuantumCryptoAnalyzer:
    """Get or create the crypto analyzer instance"""
    global _crypto_analyzer
    if _crypto_analyzer is None:
        _crypto_analyzer = QuantumCryptoAnalyzer()
    return _crypto_analyzer
