#!/usr/bin/env python3
"""
Vulnerability Correlation Engine
Advanced vulnerability correlation, deduplication, and prioritization.
"""

import asyncio
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import sqlite3
import logging
import re
from collections import defaultdict


class VulnerabilitySource(Enum):
    """Vulnerability data sources"""
    NMAP = "nmap"
    NESSUS = "nessus"
    OPENVAS = "openvas"
    QUALYS = "qualys"
    RAPID7 = "rapid7"
    BURP = "burp"
    ZAPP = "zap"
    NUCLEI = "nuclei"
    MANUAL = "manual"
    OSINT = "osint"
    CUSTOM = "custom"


class SeverityLevel(Enum):
    """Severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnStatus(Enum):
    """Vulnerability status"""
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"
    MITIGATED = "mitigated"
    PENDING = "pending"


class CorrelationType(Enum):
    """Types of correlation"""
    EXACT_MATCH = "exact_match"
    CVE_MATCH = "cve_match"
    SIMILAR_TITLE = "similar_title"
    SAME_HOST_PORT = "same_host_port"
    RELATED_VULN = "related_vuln"
    EXPLOIT_CHAIN = "exploit_chain"


@dataclass
class RawVulnerability:
    """Raw vulnerability from scanner"""
    id: str
    source: VulnerabilitySource
    title: str
    description: str
    host: str
    port: int = 0
    protocol: str = "tcp"
    service: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    cvss_score: float = 0.0
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    solution: str = ""
    evidence: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class CorrelatedVulnerability:
    """Correlated/deduplicated vulnerability"""
    id: str
    title: str
    description: str
    unified_severity: SeverityLevel
    unified_cvss: float
    affected_hosts: List[str] = field(default_factory=list)
    affected_ports: List[Tuple[str, int]] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    sources: List[VulnerabilitySource] = field(default_factory=list)
    source_vulns: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    solution: str = ""
    correlation_confidence: float = 0.0
    correlation_types: List[CorrelationType] = field(default_factory=list)
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    priority_score: float = 0.0
    status: VulnStatus = VulnStatus.OPEN
    asset_criticality: str = "medium"
    business_context: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExploitChain:
    """Attack chain/kill chain mapping"""
    id: str
    name: str
    description: str
    vulnerabilities: List[str] = field(default_factory=list)
    attack_path: List[Dict[str, Any]] = field(default_factory=list)
    entry_point: str = ""
    target: str = ""
    risk_score: float = 0.0
    likelihood: str = "medium"
    impact: str = "high"
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class AssetContext:
    """Asset context for prioritization"""
    host: str
    hostname: str = ""
    asset_type: str = "server"
    criticality: str = "medium"
    business_unit: str = ""
    data_classification: str = ""
    internet_facing: bool = False
    contains_pii: bool = False
    compliance_scope: List[str] = field(default_factory=list)
    owners: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class ThreatIntelContext:
    """Threat intelligence context"""
    cve_id: str
    exploit_available: bool = False
    exploit_maturity: str = "unknown"
    in_the_wild: bool = False
    ransomware_associated: bool = False
    apt_associated: List[str] = field(default_factory=list)
    epss_score: float = 0.0  # Exploit Prediction Scoring System
    cisa_kev: bool = False  # Known Exploited Vulnerabilities
    vendor_advisory: str = ""
    patch_available: bool = False
    patch_date: Optional[datetime] = None


class VulnCorrelationEngine:
    """
    Advanced Vulnerability Correlation Engine
    Provides deduplication, prioritization, and chain analysis.
    """
    
    def __init__(self, db_path: str = "vuln_correlation.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.raw_vulns: Dict[str, RawVulnerability] = {}
        self.correlated_vulns: Dict[str, CorrelatedVulnerability] = {}
        self.exploit_chains: Dict[str, ExploitChain] = {}
        self.asset_context: Dict[str, AssetContext] = {}
        self.threat_intel: Dict[str, ThreatIntelContext] = {}
        self._init_database()
    
    def _init_database(self):
        """Initialize database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS raw_vulnerabilities (
                id TEXT PRIMARY KEY,
                source TEXT,
                title TEXT,
                description TEXT,
                host TEXT,
                port INTEGER,
                protocol TEXT,
                service TEXT,
                severity TEXT,
                cvss_score REAL,
                cve_ids TEXT,
                data TEXT,
                discovered_at TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS correlated_vulnerabilities (
                id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                affected_hosts TEXT,
                cve_ids TEXT,
                sources TEXT,
                source_vulns TEXT,
                priority_score REAL,
                status TEXT,
                data TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS exploit_chains (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                vulnerabilities TEXT,
                attack_path TEXT,
                risk_score REAL,
                data TEXT
            );
            
            CREATE TABLE IF NOT EXISTS asset_context (
                host TEXT PRIMARY KEY,
                hostname TEXT,
                asset_type TEXT,
                criticality TEXT,
                data TEXT
            );
            
            CREATE TABLE IF NOT EXISTS threat_intel (
                cve_id TEXT PRIMARY KEY,
                exploit_available INTEGER,
                in_the_wild INTEGER,
                epss_score REAL,
                cisa_kev INTEGER,
                data TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_raw_host ON raw_vulnerabilities(host);
            CREATE INDEX IF NOT EXISTS idx_raw_cve ON raw_vulnerabilities(cve_ids);
            CREATE INDEX IF NOT EXISTS idx_correlated_severity ON correlated_vulnerabilities(severity);
            CREATE INDEX IF NOT EXISTS idx_correlated_status ON correlated_vulnerabilities(status);
        """)
        
        conn.commit()
        conn.close()
    
    async def ingest_vulnerability(
        self,
        source: VulnerabilitySource,
        title: str,
        description: str,
        host: str,
        **kwargs
    ) -> RawVulnerability:
        """Ingest raw vulnerability from scanner"""
        vuln_id = hashlib.md5(
            f"{source.value}_{title}_{host}_{kwargs.get('port', 0)}".encode()
        ).hexdigest()[:12]
        
        severity_str = kwargs.get("severity", "medium").lower()
        try:
            severity = SeverityLevel(severity_str)
        except ValueError:
            severity = SeverityLevel.MEDIUM
        
        vuln = RawVulnerability(
            id=vuln_id,
            source=source,
            title=title,
            description=description,
            host=host,
            port=kwargs.get("port", 0),
            protocol=kwargs.get("protocol", "tcp"),
            service=kwargs.get("service", ""),
            severity=severity,
            cvss_score=kwargs.get("cvss_score", 0.0),
            cve_ids=kwargs.get("cve_ids", []),
            cwe_ids=kwargs.get("cwe_ids", []),
            references=kwargs.get("references", []),
            solution=kwargs.get("solution", ""),
            evidence=kwargs.get("evidence", ""),
            raw_data=kwargs.get("raw_data", {})
        )
        
        self.raw_vulns[vuln_id] = vuln
        await self._save_raw_vuln(vuln)
        
        return vuln
    
    async def _save_raw_vuln(self, vuln: RawVulnerability):
        """Save raw vulnerability to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO raw_vulnerabilities
            (id, source, title, description, host, port, protocol, service, severity, cvss_score, cve_ids, data, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            vuln.id, vuln.source.value, vuln.title, vuln.description,
            vuln.host, vuln.port, vuln.protocol, vuln.service,
            vuln.severity.value, vuln.cvss_score,
            json.dumps(vuln.cve_ids),
            json.dumps({
                "cwe_ids": vuln.cwe_ids,
                "references": vuln.references,
                "solution": vuln.solution,
                "evidence": vuln.evidence,
                "raw_data": vuln.raw_data
            }),
            vuln.discovered_at
        ))
        
        conn.commit()
        conn.close()
    
    async def correlate_vulnerabilities(self) -> List[CorrelatedVulnerability]:
        """Correlate and deduplicate all raw vulnerabilities"""
        if not self.raw_vulns:
            return []
        
        # Group by correlation criteria
        groups: Dict[str, List[RawVulnerability]] = defaultdict(list)
        
        for vuln in self.raw_vulns.values():
            # Generate correlation keys
            keys = self._generate_correlation_keys(vuln)
            for key in keys:
                groups[key].append(vuln)
        
        # Merge groups with overlapping vulnerabilities
        merged_groups = self._merge_overlapping_groups(groups)
        
        # Create correlated vulnerabilities
        correlated = []
        for group_vulns in merged_groups:
            corr_vuln = self._create_correlated_vuln(group_vulns)
            self.correlated_vulns[corr_vuln.id] = corr_vuln
            correlated.append(corr_vuln)
        
        # Calculate priority scores
        await self._calculate_priority_scores(correlated)
        
        return correlated
    
    def _generate_correlation_keys(self, vuln: RawVulnerability) -> List[str]:
        """Generate correlation keys for vulnerability"""
        keys = []
        
        # CVE-based key (strongest correlation)
        for cve in vuln.cve_ids:
            keys.append(f"cve:{cve}")
        
        # Title-based key (normalized)
        normalized_title = self._normalize_title(vuln.title)
        keys.append(f"title:{normalized_title}")
        
        # Host+Port+Service key
        if vuln.port > 0:
            keys.append(f"hostport:{vuln.host}:{vuln.port}:{vuln.service}")
        
        # CWE-based key
        for cwe in vuln.cwe_ids:
            keys.append(f"cwe:{cwe}:{vuln.host}")
        
        return keys
    
    def _normalize_title(self, title: str) -> str:
        """Normalize vulnerability title for comparison"""
        # Remove version numbers, IPs, etc.
        normalized = title.lower()
        normalized = re.sub(r'\d+\.\d+\.\d+\.\d+', '', normalized)  # IP addresses
        normalized = re.sub(r'\d+\.\d+[\.\d]*', '', normalized)  # Version numbers
        normalized = re.sub(r'[^\w\s]', ' ', normalized)  # Special chars
        normalized = ' '.join(normalized.split())  # Normalize whitespace
        return hashlib.md5(normalized.encode()).hexdigest()[:16]
    
    def _merge_overlapping_groups(
        self,
        groups: Dict[str, List[RawVulnerability]]
    ) -> List[List[RawVulnerability]]:
        """Merge groups with overlapping vulnerabilities"""
        # Create sets of vulnerability IDs for each group
        vuln_to_groups: Dict[str, Set[str]] = defaultdict(set)
        
        for key, vulns in groups.items():
            for vuln in vulns:
                vuln_to_groups[vuln.id].add(key)
        
        # Union-find to merge overlapping groups
        parent: Dict[str, str] = {key: key for key in groups}
        
        def find(x: str) -> str:
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]
        
        def union(x: str, y: str):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py
        
        # Merge groups that share vulnerabilities
        for vuln_id, group_keys in vuln_to_groups.items():
            keys = list(group_keys)
            for i in range(1, len(keys)):
                union(keys[0], keys[i])
        
        # Collect merged groups
        merged: Dict[str, Set[str]] = defaultdict(set)
        for key in groups:
            root = find(key)
            for vuln in groups[key]:
                merged[root].add(vuln.id)
        
        # Convert back to vulnerability lists
        result = []
        for vuln_ids in merged.values():
            result.append([self.raw_vulns[vid] for vid in vuln_ids])
        
        return result
    
    def _create_correlated_vuln(
        self,
        vulns: List[RawVulnerability]
    ) -> CorrelatedVulnerability:
        """Create correlated vulnerability from group"""
        if not vulns:
            raise ValueError("Empty vulnerability group")
        
        # Generate ID from first CVE or title hash
        all_cves = set()
        for v in vulns:
            all_cves.update(v.cve_ids)
        
        if all_cves:
            base_id = sorted(all_cves)[0]
        else:
            base_id = vulns[0].title[:32]
        
        corr_id = hashlib.md5(base_id.encode()).hexdigest()[:12]
        
        # Aggregate data
        all_hosts = set()
        all_ports = set()
        all_cwes = set()
        all_refs = set()
        sources = set()
        source_ids = []
        solutions = []
        
        max_cvss = 0.0
        max_severity = SeverityLevel.INFO
        
        severity_order = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1
        }
        
        for vuln in vulns:
            all_hosts.add(vuln.host)
            if vuln.port > 0:
                all_ports.add((vuln.host, vuln.port))
            all_cwes.update(vuln.cwe_ids)
            all_refs.update(vuln.references)
            sources.add(vuln.source)
            source_ids.append(vuln.id)
            
            if vuln.solution:
                solutions.append(vuln.solution)
            
            if vuln.cvss_score > max_cvss:
                max_cvss = vuln.cvss_score
            
            if severity_order.get(vuln.severity, 0) > severity_order.get(max_severity, 0):
                max_severity = vuln.severity
        
        # Use best available title/description
        best_vuln = max(vulns, key=lambda v: len(v.description))
        
        # Determine correlation types
        corr_types = []
        if len(all_cves) > 0:
            corr_types.append(CorrelationType.CVE_MATCH)
        if len(sources) > 1:
            corr_types.append(CorrelationType.SIMILAR_TITLE)
        if len(all_ports) > 0:
            corr_types.append(CorrelationType.SAME_HOST_PORT)
        
        # Calculate correlation confidence
        confidence = min(1.0, len(sources) * 0.25 + (0.5 if all_cves else 0))
        
        return CorrelatedVulnerability(
            id=corr_id,
            title=best_vuln.title,
            description=best_vuln.description,
            unified_severity=max_severity,
            unified_cvss=max_cvss,
            affected_hosts=sorted(all_hosts),
            affected_ports=sorted(all_ports),
            cve_ids=sorted(all_cves),
            cwe_ids=sorted(all_cwes),
            sources=sorted(sources, key=lambda x: x.value),
            source_vulns=source_ids,
            references=sorted(all_refs),
            solution=solutions[0] if solutions else "",
            correlation_confidence=confidence,
            correlation_types=corr_types,
            first_seen=min(v.discovered_at for v in vulns),
            last_seen=max(v.discovered_at for v in vulns)
        )
    
    async def _calculate_priority_scores(
        self,
        vulns: List[CorrelatedVulnerability]
    ):
        """Calculate priority scores for vulnerabilities"""
        for vuln in vulns:
            score = 0.0
            
            # Base score from CVSS (0-10 normalized to 0-40)
            score += vuln.unified_cvss * 4
            
            # Severity modifier
            severity_scores = {
                SeverityLevel.CRITICAL: 25,
                SeverityLevel.HIGH: 15,
                SeverityLevel.MEDIUM: 8,
                SeverityLevel.LOW: 3,
                SeverityLevel.INFO: 0
            }
            score += severity_scores.get(vuln.unified_severity, 0)
            
            # Number of affected hosts
            host_count = len(vuln.affected_hosts)
            if host_count >= 10:
                score += 15
            elif host_count >= 5:
                score += 10
            elif host_count >= 2:
                score += 5
            
            # Threat intelligence enrichment
            for cve in vuln.cve_ids:
                intel = self.threat_intel.get(cve)
                if intel:
                    if intel.exploit_available:
                        score += 10
                    if intel.in_the_wild:
                        score += 15
                    if intel.cisa_kev:
                        score += 20
                    if intel.ransomware_associated:
                        score += 10
                    score += intel.epss_score * 10
            
            # Asset context
            for host in vuln.affected_hosts:
                context = self.asset_context.get(host)
                if context:
                    if context.criticality == "critical":
                        score += 10
                    elif context.criticality == "high":
                        score += 5
                    
                    if context.internet_facing:
                        score += 10
                    if context.contains_pii:
                        score += 5
            
            # Multiple sources confirmation
            if len(vuln.sources) >= 3:
                score += 5
            
            vuln.priority_score = min(100.0, score)
            
            # Calculate sub-scores
            vuln.exploitability_score = self._calculate_exploitability(vuln)
            vuln.impact_score = self._calculate_impact(vuln)
    
    def _calculate_exploitability(self, vuln: CorrelatedVulnerability) -> float:
        """Calculate exploitability score"""
        score = 0.0
        
        # Check for public exploits
        for cve in vuln.cve_ids:
            intel = self.threat_intel.get(cve)
            if intel:
                if intel.exploit_available:
                    score += 30
                if intel.exploit_maturity == "high":
                    score += 20
                elif intel.exploit_maturity == "functional":
                    score += 10
        
        # Network-accessible ports
        if vuln.affected_ports:
            common_ports = {21, 22, 23, 25, 80, 443, 445, 3389, 8080}
            for host, port in vuln.affected_ports:
                if port in common_ports:
                    score += 5
        
        return min(100.0, score)
    
    def _calculate_impact(self, vuln: CorrelatedVulnerability) -> float:
        """Calculate impact score"""
        score = 0.0
        
        # CVSS contribution
        score += vuln.unified_cvss * 5
        
        # Affected hosts
        score += min(30, len(vuln.affected_hosts) * 3)
        
        # Asset criticality
        for host in vuln.affected_hosts:
            context = self.asset_context.get(host)
            if context:
                criticality_scores = {
                    "critical": 15,
                    "high": 10,
                    "medium": 5,
                    "low": 2
                }
                score += criticality_scores.get(context.criticality, 0)
        
        return min(100.0, score)
    
    async def detect_exploit_chains(self) -> List[ExploitChain]:
        """Detect potential exploit chains"""
        chains = []
        
        # Group vulnerabilities by host
        host_vulns: Dict[str, List[CorrelatedVulnerability]] = defaultdict(list)
        for vuln in self.correlated_vulns.values():
            for host in vuln.affected_hosts:
                host_vulns[host].append(vuln)
        
        # Analyze each host for chains
        for host, vulns in host_vulns.items():
            if len(vulns) < 2:
                continue
            
            # Sort by severity for chain analysis
            sorted_vulns = sorted(
                vulns,
                key=lambda v: v.priority_score,
                reverse=True
            )
            
            # Look for privilege escalation chains
            priv_esc_chain = self._find_privilege_escalation_chain(host, sorted_vulns)
            if priv_esc_chain:
                chains.append(priv_esc_chain)
            
            # Look for lateral movement chains
            lateral_chain = self._find_lateral_movement_chain(host, sorted_vulns)
            if lateral_chain:
                chains.append(lateral_chain)
        
        # Analyze cross-host chains
        cross_host_chains = self._find_cross_host_chains()
        chains.extend(cross_host_chains)
        
        for chain in chains:
            self.exploit_chains[chain.id] = chain
        
        return chains
    
    def _find_privilege_escalation_chain(
        self,
        host: str,
        vulns: List[CorrelatedVulnerability]
    ) -> Optional[ExploitChain]:
        """Find privilege escalation chain"""
        # Look for initial access + privilege escalation pattern
        initial_access = []
        priv_esc = []
        
        priv_esc_keywords = [
            "privilege escalation", "local privilege", "root access",
            "admin access", "sudo", "setuid", "kernel"
        ]
        
        initial_keywords = [
            "remote code execution", "rce", "command injection",
            "authentication bypass", "default credentials"
        ]
        
        for vuln in vulns:
            title_lower = vuln.title.lower()
            desc_lower = vuln.description.lower()
            combined = title_lower + " " + desc_lower
            
            if any(kw in combined for kw in priv_esc_keywords):
                priv_esc.append(vuln)
            if any(kw in combined for kw in initial_keywords):
                initial_access.append(vuln)
        
        if initial_access and priv_esc:
            chain_id = hashlib.md5(f"privesc_{host}".encode()).hexdigest()[:12]
            
            return ExploitChain(
                id=chain_id,
                name=f"Privilege Escalation Chain on {host}",
                description="Initial access vulnerability combined with privilege escalation",
                vulnerabilities=[initial_access[0].id, priv_esc[0].id],
                attack_path=[
                    {"step": 1, "vuln": initial_access[0].id, "action": "Initial Access"},
                    {"step": 2, "vuln": priv_esc[0].id, "action": "Privilege Escalation"}
                ],
                entry_point=host,
                target=f"{host} (root/admin)",
                risk_score=min(100, initial_access[0].priority_score + priv_esc[0].priority_score * 0.5),
                likelihood="high" if initial_access[0].exploitability_score > 50 else "medium",
                impact="critical",
                mitre_tactics=["TA0001", "TA0004"],  # Initial Access, Privilege Escalation
                mitre_techniques=["T1190", "T1068"]  # Exploit Public-Facing App, Exploitation for Privilege Escalation
            )
        
        return None
    
    def _find_lateral_movement_chain(
        self,
        host: str,
        vulns: List[CorrelatedVulnerability]
    ) -> Optional[ExploitChain]:
        """Find lateral movement potential"""
        lateral_keywords = [
            "smb", "wmi", "psexec", "winrm", "ssh", "rdp",
            "pass the hash", "pass the ticket", "mimikatz"
        ]
        
        lateral_vulns = []
        for vuln in vulns:
            combined = (vuln.title + " " + vuln.description).lower()
            if any(kw in combined for kw in lateral_keywords):
                lateral_vulns.append(vuln)
        
        if lateral_vulns:
            chain_id = hashlib.md5(f"lateral_{host}".encode()).hexdigest()[:12]
            
            return ExploitChain(
                id=chain_id,
                name=f"Lateral Movement Potential from {host}",
                description="Vulnerabilities enabling lateral movement to other hosts",
                vulnerabilities=[v.id for v in lateral_vulns[:3]],
                attack_path=[
                    {"step": i+1, "vuln": v.id, "action": "Lateral Movement"}
                    for i, v in enumerate(lateral_vulns[:3])
                ],
                entry_point=host,
                target="Network-wide",
                risk_score=max(v.priority_score for v in lateral_vulns),
                likelihood="medium",
                impact="high",
                mitre_tactics=["TA0008"],  # Lateral Movement
                mitre_techniques=["T1021"]  # Remote Services
            )
        
        return None
    
    def _find_cross_host_chains(self) -> List[ExploitChain]:
        """Find cross-host attack chains"""
        chains = []
        
        # Group by CVE to find same vulnerability across hosts
        cve_hosts: Dict[str, Set[str]] = defaultdict(set)
        cve_vulns: Dict[str, CorrelatedVulnerability] = {}
        
        for vuln in self.correlated_vulns.values():
            for cve in vuln.cve_ids:
                for host in vuln.affected_hosts:
                    cve_hosts[cve].add(host)
                cve_vulns[cve] = vuln
        
        # Find CVEs affecting multiple hosts
        for cve, hosts in cve_hosts.items():
            if len(hosts) >= 3:
                vuln = cve_vulns[cve]
                chain_id = hashlib.md5(f"widespread_{cve}".encode()).hexdigest()[:12]
                
                chain = ExploitChain(
                    id=chain_id,
                    name=f"Widespread {cve} Exploitation",
                    description=f"CVE {cve} affects {len(hosts)} hosts - potential for mass exploitation",
                    vulnerabilities=[vuln.id],
                    attack_path=[
                        {"step": 1, "targets": list(hosts), "action": f"Exploit {cve}"}
                    ],
                    entry_point="Multiple",
                    target=f"{len(hosts)} hosts",
                    risk_score=vuln.priority_score * 1.5,
                    likelihood="high",
                    impact="critical" if len(hosts) >= 10 else "high",
                    mitre_tactics=["TA0001"],
                    mitre_techniques=["T1190"]
                )
                chains.append(chain)
        
        return chains
    
    async def add_asset_context(
        self,
        host: str,
        **kwargs
    ) -> AssetContext:
        """Add asset context for prioritization"""
        context = AssetContext(
            host=host,
            hostname=kwargs.get("hostname", ""),
            asset_type=kwargs.get("asset_type", "server"),
            criticality=kwargs.get("criticality", "medium"),
            business_unit=kwargs.get("business_unit", ""),
            data_classification=kwargs.get("data_classification", ""),
            internet_facing=kwargs.get("internet_facing", False),
            contains_pii=kwargs.get("contains_pii", False),
            compliance_scope=kwargs.get("compliance_scope", []),
            owners=kwargs.get("owners", []),
            tags=kwargs.get("tags", [])
        )
        
        self.asset_context[host] = context
        return context
    
    async def add_threat_intel(
        self,
        cve_id: str,
        **kwargs
    ) -> ThreatIntelContext:
        """Add threat intelligence for CVE"""
        intel = ThreatIntelContext(
            cve_id=cve_id,
            exploit_available=kwargs.get("exploit_available", False),
            exploit_maturity=kwargs.get("exploit_maturity", "unknown"),
            in_the_wild=kwargs.get("in_the_wild", False),
            ransomware_associated=kwargs.get("ransomware_associated", False),
            apt_associated=kwargs.get("apt_associated", []),
            epss_score=kwargs.get("epss_score", 0.0),
            cisa_kev=kwargs.get("cisa_kev", False),
            vendor_advisory=kwargs.get("vendor_advisory", ""),
            patch_available=kwargs.get("patch_available", False),
            patch_date=kwargs.get("patch_date")
        )
        
        self.threat_intel[cve_id] = intel
        return intel
    
    async def get_prioritized_vulnerabilities(
        self,
        limit: int = 100,
        min_priority: float = 0.0,
        severity_filter: List[SeverityLevel] = None,
        status_filter: List[VulnStatus] = None
    ) -> List[CorrelatedVulnerability]:
        """Get prioritized list of vulnerabilities"""
        vulns = list(self.correlated_vulns.values())
        
        # Apply filters
        if severity_filter:
            vulns = [v for v in vulns if v.unified_severity in severity_filter]
        
        if status_filter:
            vulns = [v for v in vulns if v.status in status_filter]
        
        vulns = [v for v in vulns if v.priority_score >= min_priority]
        
        # Sort by priority
        vulns.sort(key=lambda v: v.priority_score, reverse=True)
        
        return vulns[:limit]
    
    async def generate_report(self) -> Dict[str, Any]:
        """Generate correlation report"""
        vulns = list(self.correlated_vulns.values())
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_raw_vulns": len(self.raw_vulns),
                "total_correlated_vulns": len(vulns),
                "deduplication_rate": f"{(1 - len(vulns)/max(1, len(self.raw_vulns))) * 100:.1f}%",
                "exploit_chains_detected": len(self.exploit_chains),
                "assets_with_context": len(self.asset_context),
                "cves_with_intel": len(self.threat_intel)
            },
            "severity_distribution": {},
            "top_priorities": [],
            "affected_hosts": {},
            "exploit_chains": []
        }
        
        # Severity distribution
        for severity in SeverityLevel:
            count = sum(1 for v in vulns if v.unified_severity == severity)
            report["severity_distribution"][severity.value] = count
        
        # Top priorities
        top = sorted(vulns, key=lambda v: v.priority_score, reverse=True)[:10]
        for v in top:
            report["top_priorities"].append({
                "id": v.id,
                "title": v.title,
                "severity": v.unified_severity.value,
                "cvss": v.unified_cvss,
                "priority_score": v.priority_score,
                "affected_hosts": len(v.affected_hosts),
                "cve_ids": v.cve_ids
            })
        
        # Host impact
        host_counts: Dict[str, int] = defaultdict(int)
        host_critical: Dict[str, int] = defaultdict(int)
        
        for v in vulns:
            for host in v.affected_hosts:
                host_counts[host] += 1
                if v.unified_severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                    host_critical[host] += 1
        
        for host, count in sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
            report["affected_hosts"][host] = {
                "total_vulns": count,
                "critical_high": host_critical[host]
            }
        
        # Exploit chains
        for chain in self.exploit_chains.values():
            report["exploit_chains"].append({
                "id": chain.id,
                "name": chain.name,
                "risk_score": chain.risk_score,
                "entry_point": chain.entry_point,
                "target": chain.target,
                "vulns_count": len(chain.vulnerabilities)
            })
        
        return report
