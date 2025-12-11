"""
Threat Hunting Platform - Proactive threat detection and hunting
Capabilities: Hypothesis-based hunting, IOC sweeps, behavioral analytics, SIGMA rules
"""

import asyncio
import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Set
import logging
import hashlib

logger = logging.getLogger(__name__)


class HuntType(Enum):
    """Types of threat hunts"""
    IOC_SWEEP = "ioc_sweep"
    BEHAVIORAL = "behavioral"
    ANOMALY = "anomaly"
    HYPOTHESIS = "hypothesis"
    SIGMA = "sigma"
    YARA = "yara"


class ThreatCategory(Enum):
    """Threat categories"""
    APT = "apt"
    RANSOMWARE = "ransomware"
    CRYPTOMINER = "cryptominer"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    C2 = "c2"
    CREDENTIAL_ACCESS = "credential_access"
    DEFENSE_EVASION = "defense_evasion"
    DISCOVERY = "discovery"


class Severity(Enum):
    """Finding severity"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataSource(Enum):
    """Hunt data sources"""
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    REGISTRY = "registry"
    AUTHENTICATION = "authentication"
    DNS = "dns"
    HTTP = "http"
    ENDPOINT = "endpoint"


@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_type: str  # ip, domain, hash, url, file, registry
    value: str
    description: str = ""
    source: str = ""
    confidence: int = 0
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class SigmaRule:
    """SIGMA detection rule"""
    rule_id: str
    title: str
    status: str
    level: Severity
    description: str
    author: str
    logsource: Dict[str, str] = field(default_factory=dict)
    detection: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)


@dataclass
class HuntHypothesis:
    """Threat hunting hypothesis"""
    hypothesis_id: str
    name: str
    description: str
    category: ThreatCategory
    data_sources: List[DataSource] = field(default_factory=list)
    detection_logic: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    created: datetime = field(default_factory=datetime.now)


@dataclass
class HuntFinding:
    """Threat hunt finding"""
    finding_id: str
    hunt_id: str
    timestamp: datetime
    severity: Severity
    category: ThreatCategory
    title: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    affected_assets: List[str] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    false_positive_likelihood: str = "low"


@dataclass
class BehaviorPattern:
    """Behavioral pattern for detection"""
    pattern_id: str
    name: str
    description: str
    category: ThreatCategory
    sequence: List[Dict[str, Any]] = field(default_factory=list)
    timeframe: int = 3600  # seconds
    threshold: int = 1
    mitre_attack: List[str] = field(default_factory=list)


@dataclass
class AnomalyBaseline:
    """Baseline for anomaly detection"""
    metric: str
    mean: float
    std_dev: float
    min_val: float
    max_val: float
    sample_count: int
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class HuntSession:
    """Threat hunting session"""
    session_id: str
    name: str
    hunt_type: HuntType
    status: str = "active"
    started: datetime = field(default_factory=datetime.now)
    ended: Optional[datetime] = None
    hypotheses: List[HuntHypothesis] = field(default_factory=list)
    findings: List[HuntFinding] = field(default_factory=list)
    data_sources: List[DataSource] = field(default_factory=list)
    assets_scanned: int = 0
    events_processed: int = 0


class ThreatHuntingPlatform:
    """
    Threat Hunting Platform
    Proactive threat detection and hunting capabilities
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        # Callbacks
        self.progress_callback: Optional[Callable] = None
        self.log_callback: Optional[Callable] = None
        
        # Active sessions
        self.active_sessions: Dict[str, HuntSession] = {}
        
        # IOC database
        self.ioc_database: Dict[str, IOC] = {}
        
        # SIGMA rules
        self.sigma_rules: Dict[str, SigmaRule] = {}
        
        # Behavior patterns
        self.behavior_patterns: Dict[str, BehaviorPattern] = {}
        
        # Anomaly baselines
        self.baselines: Dict[str, AnomalyBaseline] = {}
        
        # Built-in hunting hypotheses
        self._init_hypotheses()
        
        # Built-in SIGMA rules
        self._init_sigma_rules()
        
        # Built-in behavior patterns
        self._init_behavior_patterns()
        
        self._log("Threat Hunting Platform initialized")
    
    def _log(self, message: str, level: str = "info"):
        """Log message"""
        if self.log_callback:
            self.log_callback(message, level)
        logger.log(getattr(logging, level.upper(), logging.INFO), message)
    
    def _update_progress(self, progress: int, status: str):
        """Update progress"""
        if self.progress_callback:
            self.progress_callback(progress, status)
    
    def _init_hypotheses(self):
        """Initialize built-in hunting hypotheses"""
        self.built_in_hypotheses = [
            HuntHypothesis(
                hypothesis_id="H001",
                name="PowerShell Empire C2",
                description="Detect PowerShell Empire command and control activity",
                category=ThreatCategory.C2,
                data_sources=[DataSource.PROCESS, DataSource.NETWORK],
                detection_logic="PowerShell with encoded commands and outbound HTTP/HTTPS",
                mitre_techniques=["T1059.001", "T1071.001"],
                indicators=["powershell", "-enc", "-encodedcommand", "invoke-empire"]
            ),
            HuntHypothesis(
                hypothesis_id="H002",
                name="Cobalt Strike Beacon",
                description="Detect Cobalt Strike beacon activity",
                category=ThreatCategory.C2,
                data_sources=[DataSource.NETWORK, DataSource.PROCESS],
                detection_logic="Named pipe communication, malleable C2 profiles",
                mitre_techniques=["T1071", "T1055"],
                indicators=["\\pipe\\msagent_", "beacon", "cobaltstrike"]
            ),
            HuntHypothesis(
                hypothesis_id="H003",
                name="Kerberoasting Attack",
                description="Detect Kerberos ticket requests for service accounts",
                category=ThreatCategory.CREDENTIAL_ACCESS,
                data_sources=[DataSource.AUTHENTICATION],
                detection_logic="Multiple TGS requests for SPNs in short timeframe",
                mitre_techniques=["T1558.003"],
                indicators=["rc4-hmac", "TGS-REQ", "service/"]
            ),
            HuntHypothesis(
                hypothesis_id="H004",
                name="Lateral Movement via PsExec",
                description="Detect PsExec-style lateral movement",
                category=ThreatCategory.LATERAL_MOVEMENT,
                data_sources=[DataSource.PROCESS, DataSource.NETWORK],
                detection_logic="Remote service installation and execution",
                mitre_techniques=["T1569.002", "T1021.002"],
                indicators=["psexec", "paexec", "remcom", "\\admin$", "\\c$"]
            ),
            HuntHypothesis(
                hypothesis_id="H005",
                name="Data Exfiltration via DNS",
                description="Detect data exfiltration using DNS tunneling",
                category=ThreatCategory.EXFILTRATION,
                data_sources=[DataSource.DNS],
                detection_logic="High-entropy DNS queries, unusual query lengths",
                mitre_techniques=["T1048.003"],
                indicators=["long subdomain", "base64", "hex encoding"]
            ),
            HuntHypothesis(
                hypothesis_id="H006",
                name="Ransomware Precursors",
                description="Detect early ransomware indicators",
                category=ThreatCategory.RANSOMWARE,
                data_sources=[DataSource.FILE, DataSource.PROCESS],
                detection_logic="Shadow copy deletion, encryption behavior",
                mitre_techniques=["T1490", "T1486"],
                indicators=["vssadmin", "wmic shadowcopy", "bcdedit", "recoveryenabled"]
            ),
            HuntHypothesis(
                hypothesis_id="H007",
                name="Persistence via Registry",
                description="Detect registry-based persistence mechanisms",
                category=ThreatCategory.PERSISTENCE,
                data_sources=[DataSource.REGISTRY],
                detection_logic="Modifications to run keys and startup locations",
                mitre_techniques=["T1547.001"],
                indicators=["Run", "RunOnce", "CurrentVersion\\Run", "Winlogon"]
            ),
            HuntHypothesis(
                hypothesis_id="H008",
                name="Living Off the Land",
                description="Detect abuse of legitimate system tools",
                category=ThreatCategory.DEFENSE_EVASION,
                data_sources=[DataSource.PROCESS],
                detection_logic="Suspicious use of LOLBins with network activity",
                mitre_techniques=["T1218"],
                indicators=["certutil", "mshta", "wmic", "regsvr32", "rundll32"]
            )
        ]
    
    def _init_sigma_rules(self):
        """Initialize built-in SIGMA rules"""
        rules = [
            SigmaRule(
                rule_id="SIGMA001",
                title="PowerShell Encoded Command",
                status="stable",
                level=Severity.HIGH,
                description="Detects PowerShell with encoded command execution",
                author="HydraRecon",
                logsource={"category": "process_creation", "product": "windows"},
                detection={
                    "selection": {
                        "Image|endswith": "\\powershell.exe",
                        "CommandLine|contains": ["-enc", "-encodedcommand", "-e "]
                    }
                },
                tags=["attack.execution", "attack.t1059.001"],
                mitre_attack=["T1059.001"]
            ),
            SigmaRule(
                rule_id="SIGMA002",
                title="Mimikatz Keywords in Command Line",
                status="stable",
                level=Severity.CRITICAL,
                description="Detects Mimikatz-related keywords in command lines",
                author="HydraRecon",
                logsource={"category": "process_creation", "product": "windows"},
                detection={
                    "selection": {
                        "CommandLine|contains": [
                            "sekurlsa", "kerberos::", "crypto::", "lsadump::",
                            "privilege::debug", "token::elevate"
                        ]
                    }
                },
                tags=["attack.credential_access", "attack.t1003"],
                mitre_attack=["T1003", "T1003.001"]
            ),
            SigmaRule(
                rule_id="SIGMA003",
                title="Suspicious Network Connection",
                status="stable",
                level=Severity.MEDIUM,
                description="Detects suspicious outbound network connections",
                author="HydraRecon",
                logsource={"category": "network_connection", "product": "windows"},
                detection={
                    "selection": {
                        "DestinationPort": [4444, 5555, 8080, 8443, 9001],
                        "Initiated": True
                    }
                },
                tags=["attack.command_and_control"],
                mitre_attack=["T1071"]
            ),
            SigmaRule(
                rule_id="SIGMA004",
                title="Shadow Copy Deletion",
                status="stable",
                level=Severity.CRITICAL,
                description="Detects deletion of shadow copies (ransomware indicator)",
                author="HydraRecon",
                logsource={"category": "process_creation", "product": "windows"},
                detection={
                    "selection": {
                        "CommandLine|contains|all": ["vssadmin", "delete", "shadows"]
                    }
                },
                tags=["attack.impact", "attack.t1490"],
                mitre_attack=["T1490"]
            ),
            SigmaRule(
                rule_id="SIGMA005",
                title="Scheduled Task Creation",
                status="stable",
                level=Severity.MEDIUM,
                description="Detects creation of scheduled tasks for persistence",
                author="HydraRecon",
                logsource={"category": "process_creation", "product": "windows"},
                detection={
                    "selection": {
                        "Image|endswith": ["\\schtasks.exe"],
                        "CommandLine|contains": ["/create", "-create"]
                    }
                },
                tags=["attack.persistence", "attack.t1053.005"],
                mitre_attack=["T1053.005"]
            )
        ]
        
        for rule in rules:
            self.sigma_rules[rule.rule_id] = rule
    
    def _init_behavior_patterns(self):
        """Initialize built-in behavior patterns"""
        patterns = [
            BehaviorPattern(
                pattern_id="BP001",
                name="Credential Dumping Sequence",
                description="Detect credential dumping tool execution sequence",
                category=ThreatCategory.CREDENTIAL_ACCESS,
                sequence=[
                    {"action": "process_create", "name_contains": ["procdump", "mimikatz", "sekurlsa"]},
                    {"action": "file_write", "path_contains": ["lsass", ".dmp", "credentials"]}
                ],
                timeframe=300,
                mitre_attack=["T1003"]
            ),
            BehaviorPattern(
                pattern_id="BP002",
                name="Lateral Movement Chain",
                description="Detect lateral movement pattern",
                category=ThreatCategory.LATERAL_MOVEMENT,
                sequence=[
                    {"action": "auth_success", "type": "network"},
                    {"action": "service_install", "remote": True},
                    {"action": "process_create", "remote": True}
                ],
                timeframe=600,
                mitre_attack=["T1021"]
            ),
            BehaviorPattern(
                pattern_id="BP003",
                name="Ransomware Deployment",
                description="Detect ransomware deployment sequence",
                category=ThreatCategory.RANSOMWARE,
                sequence=[
                    {"action": "process_create", "name_contains": ["vssadmin", "wbadmin"]},
                    {"action": "file_modify", "extension_change": True},
                    {"action": "file_create", "name_contains": ["readme", "decrypt", "ransom"]}
                ],
                timeframe=900,
                mitre_attack=["T1486", "T1490"]
            ),
            BehaviorPattern(
                pattern_id="BP004",
                name="Discovery and Exfiltration",
                description="Detect discovery followed by data exfiltration",
                category=ThreatCategory.EXFILTRATION,
                sequence=[
                    {"action": "process_create", "name_contains": ["whoami", "net user", "net group"]},
                    {"action": "file_access", "path_contains": ["documents", "downloads", "desktop"]},
                    {"action": "network_connect", "bytes_out_high": True}
                ],
                timeframe=1800,
                mitre_attack=["T1087", "T1048"]
            )
        ]
        
        for pattern in patterns:
            self.behavior_patterns[pattern.pattern_id] = pattern
    
    async def create_hunt_session(self, name: str, hunt_type: HuntType,
                                  hypotheses: Optional[List[str]] = None) -> HuntSession:
        """Create a new threat hunting session"""
        session_id = f"hunt_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(name.encode()).hexdigest()[:8]}"
        
        session = HuntSession(
            session_id=session_id,
            name=name,
            hunt_type=hunt_type
        )
        
        # Add selected hypotheses
        if hypotheses:
            for h_id in hypotheses:
                for h in self.built_in_hypotheses:
                    if h.hypothesis_id == h_id:
                        session.hypotheses.append(h)
                        session.data_sources.extend(h.data_sources)
        
        session.data_sources = list(set(session.data_sources))
        
        self.active_sessions[session_id] = session
        self._log(f"Created hunt session: {name} ({session_id})")
        
        return session
    
    async def run_ioc_sweep(self, iocs: List[IOC], 
                           targets: Optional[List[str]] = None) -> List[HuntFinding]:
        """Run IOC sweep across targets"""
        findings = []
        
        self._update_progress(0, "Starting IOC sweep...")
        self._log(f"Running IOC sweep with {len(iocs)} indicators")
        
        # Add IOCs to database
        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.value}"
            self.ioc_database[key] = ioc
        
        # Group IOCs by type
        ioc_groups = {}
        for ioc in iocs:
            if ioc.ioc_type not in ioc_groups:
                ioc_groups[ioc.ioc_type] = []
            ioc_groups[ioc.ioc_type].append(ioc)
        
        progress = 10
        total_types = len(ioc_groups)
        
        for i, (ioc_type, type_iocs) in enumerate(ioc_groups.items()):
            progress = 10 + int((i / total_types) * 80)
            self._update_progress(progress, f"Sweeping {ioc_type} indicators...")
            
            if ioc_type == "ip":
                type_findings = await self._sweep_ip_iocs(type_iocs, targets)
            elif ioc_type == "domain":
                type_findings = await self._sweep_domain_iocs(type_iocs, targets)
            elif ioc_type == "hash":
                type_findings = await self._sweep_hash_iocs(type_iocs, targets)
            elif ioc_type == "file":
                type_findings = await self._sweep_file_iocs(type_iocs, targets)
            elif ioc_type == "registry":
                type_findings = await self._sweep_registry_iocs(type_iocs, targets)
            else:
                type_findings = []
            
            findings.extend(type_findings)
        
        self._update_progress(100, f"IOC sweep complete: {len(findings)} findings")
        return findings
    
    async def _sweep_ip_iocs(self, iocs: List[IOC], 
                            targets: Optional[List[str]]) -> List[HuntFinding]:
        """Sweep for IP-based IOCs"""
        findings = []
        
        for ioc in iocs:
            # Check network connections
            try:
                # Use netstat or ss to check connections
                result = await asyncio.create_subprocess_exec(
                    "ss", "-tun", 
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await result.communicate()
                
                if ioc.value in stdout.decode():
                    findings.append(HuntFinding(
                        finding_id=f"IOC_{hashlib.md5(ioc.value.encode()).hexdigest()[:8]}",
                        hunt_id="ioc_sweep",
                        timestamp=datetime.now(),
                        severity=Severity.HIGH,
                        category=ThreatCategory.C2,
                        title=f"Malicious IP Connection Detected",
                        description=f"Active connection to known malicious IP: {ioc.value}",
                        evidence={"ip": ioc.value, "source": ioc.source},
                        iocs=[ioc],
                        mitre_attack=["T1071"]
                    ))
            except Exception as e:
                self._log(f"IP sweep error: {e}", "warning")
        
        return findings
    
    async def _sweep_domain_iocs(self, iocs: List[IOC],
                                targets: Optional[List[str]]) -> List[HuntFinding]:
        """Sweep for domain-based IOCs"""
        findings = []
        
        # Check DNS cache, hosts file, etc.
        for ioc in iocs:
            try:
                # Check hosts file
                hosts_path = Path("/etc/hosts")
                if hosts_path.exists():
                    content = hosts_path.read_text()
                    if ioc.value in content:
                        findings.append(HuntFinding(
                            finding_id=f"IOC_{hashlib.md5(ioc.value.encode()).hexdigest()[:8]}",
                            hunt_id="ioc_sweep",
                            timestamp=datetime.now(),
                            severity=Severity.MEDIUM,
                            category=ThreatCategory.C2,
                            title=f"Suspicious Domain in Hosts File",
                            description=f"Known malicious domain found in hosts: {ioc.value}",
                            evidence={"domain": ioc.value, "location": "/etc/hosts"},
                            iocs=[ioc]
                        ))
            except Exception as e:
                self._log(f"Domain sweep error: {e}", "warning")
        
        return findings
    
    async def _sweep_hash_iocs(self, iocs: List[IOC],
                              targets: Optional[List[str]]) -> List[HuntFinding]:
        """Sweep for file hash IOCs"""
        findings = []
        
        # Define paths to scan
        scan_paths = [
            "/tmp",
            "/var/tmp",
            str(Path.home()),
            "/usr/local/bin"
        ]
        
        if targets:
            scan_paths = targets
        
        hash_values = {ioc.value.lower(): ioc for ioc in iocs}
        
        for scan_path in scan_paths:
            try:
                path = Path(scan_path)
                if not path.exists():
                    continue
                
                for file_path in path.rglob("*"):
                    if file_path.is_file() and file_path.stat().st_size < 100_000_000:  # 100MB limit
                        try:
                            with open(file_path, "rb") as f:
                                data = f.read()
                            
                            file_md5 = hashlib.md5(data).hexdigest()
                            file_sha256 = hashlib.sha256(data).hexdigest()
                            
                            if file_md5 in hash_values:
                                ioc = hash_values[file_md5]
                                findings.append(HuntFinding(
                                    finding_id=f"IOC_{file_md5[:8]}",
                                    hunt_id="ioc_sweep",
                                    timestamp=datetime.now(),
                                    severity=Severity.CRITICAL,
                                    category=ThreatCategory.APT,
                                    title="Malicious File Hash Match",
                                    description=f"File matches known malicious hash: {file_path}",
                                    evidence={"file": str(file_path), "hash": file_md5},
                                    affected_assets=[str(file_path)],
                                    iocs=[ioc]
                                ))
                            
                            if file_sha256 in hash_values:
                                ioc = hash_values[file_sha256]
                                findings.append(HuntFinding(
                                    finding_id=f"IOC_{file_sha256[:8]}",
                                    hunt_id="ioc_sweep",
                                    timestamp=datetime.now(),
                                    severity=Severity.CRITICAL,
                                    category=ThreatCategory.APT,
                                    title="Malicious File Hash Match",
                                    description=f"File matches known malicious hash: {file_path}",
                                    evidence={"file": str(file_path), "hash": file_sha256},
                                    affected_assets=[str(file_path)],
                                    iocs=[ioc]
                                ))
                        except:
                            pass
            except Exception as e:
                self._log(f"Hash sweep error in {scan_path}: {e}", "warning")
        
        return findings
    
    async def _sweep_file_iocs(self, iocs: List[IOC],
                              targets: Optional[List[str]]) -> List[HuntFinding]:
        """Sweep for file path IOCs"""
        findings = []
        
        for ioc in iocs:
            path = Path(ioc.value)
            if path.exists():
                findings.append(HuntFinding(
                    finding_id=f"IOC_{hashlib.md5(ioc.value.encode()).hexdigest()[:8]}",
                    hunt_id="ioc_sweep",
                    timestamp=datetime.now(),
                    severity=Severity.HIGH,
                    category=ThreatCategory.APT,
                    title="Suspicious File Found",
                    description=f"Known malicious file path exists: {ioc.value}",
                    evidence={"path": ioc.value},
                    affected_assets=[ioc.value],
                    iocs=[ioc]
                ))
        
        return findings
    
    async def _sweep_registry_iocs(self, iocs: List[IOC],
                                  targets: Optional[List[str]]) -> List[HuntFinding]:
        """Sweep for registry IOCs (Windows-specific)"""
        # Registry sweeping would be Windows-specific
        return []
    
    async def run_behavioral_hunt(self, patterns: Optional[List[str]] = None,
                                 timeframe_hours: int = 24) -> List[HuntFinding]:
        """Run behavioral pattern detection"""
        findings = []
        
        self._update_progress(0, "Starting behavioral analysis...")
        
        # Use all patterns if none specified
        if not patterns:
            patterns = list(self.behavior_patterns.keys())
        
        for i, pattern_id in enumerate(patterns):
            progress = int((i / len(patterns)) * 100)
            pattern = self.behavior_patterns.get(pattern_id)
            
            if not pattern:
                continue
            
            self._update_progress(progress, f"Checking pattern: {pattern.name}")
            
            # Analyze behavior pattern
            pattern_findings = await self._analyze_behavior_pattern(pattern, timeframe_hours)
            findings.extend(pattern_findings)
        
        self._update_progress(100, f"Behavioral hunt complete: {len(findings)} findings")
        return findings
    
    async def _analyze_behavior_pattern(self, pattern: BehaviorPattern,
                                       timeframe_hours: int) -> List[HuntFinding]:
        """Analyze a specific behavior pattern"""
        findings = []
        
        # Collect events based on pattern sequence
        # This is a simplified implementation - real version would query SIEM/EDR
        
        self._log(f"Analyzing pattern: {pattern.name}")
        
        # Simulate pattern detection based on local analysis
        # Check for indicators on the local system
        
        indicators_found = []
        
        for step in pattern.sequence:
            action = step.get("action", "")
            
            if action == "process_create":
                # Check running processes
                try:
                    result = await asyncio.create_subprocess_exec(
                        "ps", "aux",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await result.communicate()
                    processes = stdout.decode()
                    
                    name_contains = step.get("name_contains", [])
                    for name in name_contains:
                        if name.lower() in processes.lower():
                            indicators_found.append({
                                "type": "process",
                                "pattern": name,
                                "found_in": "running processes"
                            })
                except:
                    pass
        
        if indicators_found:
            findings.append(HuntFinding(
                finding_id=f"BH_{pattern.pattern_id}_{datetime.now().strftime('%H%M%S')}",
                hunt_id="behavioral_hunt",
                timestamp=datetime.now(),
                severity=Severity.HIGH,
                category=pattern.category,
                title=f"Behavioral Pattern: {pattern.name}",
                description=pattern.description,
                evidence={"indicators": indicators_found},
                mitre_attack=pattern.mitre_attack,
                recommendations=[
                    "Investigate affected systems",
                    "Check for additional indicators",
                    "Preserve evidence for forensics"
                ]
            ))
        
        return findings
    
    async def run_sigma_hunt(self, rules: Optional[List[str]] = None) -> List[HuntFinding]:
        """Run SIGMA rule-based detection"""
        findings = []
        
        self._update_progress(0, "Starting SIGMA rule analysis...")
        
        # Use all rules if none specified
        if not rules:
            rules = list(self.sigma_rules.keys())
        
        for i, rule_id in enumerate(rules):
            progress = int((i / len(rules)) * 100)
            rule = self.sigma_rules.get(rule_id)
            
            if not rule:
                continue
            
            self._update_progress(progress, f"Checking rule: {rule.title}")
            
            # Analyze SIGMA rule
            rule_findings = await self._analyze_sigma_rule(rule)
            findings.extend(rule_findings)
        
        self._update_progress(100, f"SIGMA hunt complete: {len(findings)} findings")
        return findings
    
    async def _analyze_sigma_rule(self, rule: SigmaRule) -> List[HuntFinding]:
        """Analyze a SIGMA rule against available data"""
        findings = []
        
        # Get detection criteria
        detection = rule.detection
        selection = detection.get("selection", {})
        
        # Check process-based rules
        if rule.logsource.get("category") == "process_creation":
            try:
                result = await asyncio.create_subprocess_exec(
                    "ps", "aux",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await result.communicate()
                processes = stdout.decode()
                
                matched = False
                match_details = []
                
                for key, value in selection.items():
                    if "CommandLine|contains" in key:
                        for pattern in value if isinstance(value, list) else [value]:
                            if pattern.lower() in processes.lower():
                                matched = True
                                match_details.append(f"Pattern '{pattern}' found")
                
                if matched:
                    findings.append(HuntFinding(
                        finding_id=f"SIGMA_{rule.rule_id}_{datetime.now().strftime('%H%M%S')}",
                        hunt_id="sigma_hunt",
                        timestamp=datetime.now(),
                        severity=rule.level,
                        category=ThreatCategory.DEFENSE_EVASION,
                        title=f"SIGMA: {rule.title}",
                        description=rule.description,
                        evidence={"matches": match_details, "rule_id": rule.rule_id},
                        mitre_attack=rule.mitre_attack
                    ))
            except Exception as e:
                self._log(f"SIGMA rule error: {e}", "warning")
        
        return findings
    
    async def run_anomaly_detection(self, metrics: Optional[List[str]] = None) -> List[HuntFinding]:
        """Run anomaly-based detection"""
        findings = []
        
        self._update_progress(0, "Starting anomaly detection...")
        
        # Collect current metrics
        current_metrics = await self._collect_metrics()
        
        progress = 30
        self._update_progress(progress, "Comparing against baselines...")
        
        for metric_name, current_value in current_metrics.items():
            if metrics and metric_name not in metrics:
                continue
            
            baseline = self.baselines.get(metric_name)
            
            if baseline:
                # Check for anomaly (value outside 3 standard deviations)
                if current_value > baseline.mean + (3 * baseline.std_dev):
                    findings.append(HuntFinding(
                        finding_id=f"ANOM_{metric_name}_{datetime.now().strftime('%H%M%S')}",
                        hunt_id="anomaly_detection",
                        timestamp=datetime.now(),
                        severity=Severity.MEDIUM,
                        category=ThreatCategory.DISCOVERY,
                        title=f"Anomaly Detected: {metric_name}",
                        description=f"Metric '{metric_name}' is abnormally high: {current_value:.2f} (baseline: {baseline.mean:.2f})",
                        evidence={
                            "metric": metric_name,
                            "current": current_value,
                            "baseline_mean": baseline.mean,
                            "baseline_std": baseline.std_dev
                        }
                    ))
                elif current_value < baseline.mean - (3 * baseline.std_dev):
                    findings.append(HuntFinding(
                        finding_id=f"ANOM_{metric_name}_{datetime.now().strftime('%H%M%S')}",
                        hunt_id="anomaly_detection",
                        timestamp=datetime.now(),
                        severity=Severity.MEDIUM,
                        category=ThreatCategory.DISCOVERY,
                        title=f"Anomaly Detected: {metric_name}",
                        description=f"Metric '{metric_name}' is abnormally low: {current_value:.2f} (baseline: {baseline.mean:.2f})",
                        evidence={
                            "metric": metric_name,
                            "current": current_value,
                            "baseline_mean": baseline.mean,
                            "baseline_std": baseline.std_dev
                        }
                    ))
            else:
                # Create new baseline
                self.baselines[metric_name] = AnomalyBaseline(
                    metric=metric_name,
                    mean=current_value,
                    std_dev=current_value * 0.1,  # Initial estimate
                    min_val=current_value,
                    max_val=current_value,
                    sample_count=1
                )
        
        self._update_progress(100, f"Anomaly detection complete: {len(findings)} findings")
        return findings
    
    async def _collect_metrics(self) -> Dict[str, float]:
        """Collect system metrics for anomaly detection"""
        metrics = {}
        
        try:
            # Process count
            result = await asyncio.create_subprocess_exec(
                "ps", "aux",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            metrics["process_count"] = len(stdout.decode().strip().split('\n')) - 1
            
            # Network connections
            result = await asyncio.create_subprocess_exec(
                "ss", "-tun",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            metrics["network_connections"] = len(stdout.decode().strip().split('\n')) - 1
            
            # CPU load
            with open("/proc/loadavg", "r") as f:
                load = f.read().split()
                metrics["cpu_load_1m"] = float(load[0])
                metrics["cpu_load_5m"] = float(load[1])
            
            # Memory usage
            with open("/proc/meminfo", "r") as f:
                meminfo = f.read()
                total = int(re.search(r"MemTotal:\s+(\d+)", meminfo).group(1))
                available = int(re.search(r"MemAvailable:\s+(\d+)", meminfo).group(1))
                metrics["memory_usage_percent"] = ((total - available) / total) * 100
        except Exception as e:
            self._log(f"Metric collection error: {e}", "warning")
        
        return metrics
    
    def get_hypotheses(self) -> List[HuntHypothesis]:
        """Get all available hypotheses"""
        return self.built_in_hypotheses
    
    def get_sigma_rules(self) -> List[SigmaRule]:
        """Get all SIGMA rules"""
        return list(self.sigma_rules.values())
    
    def get_behavior_patterns(self) -> List[BehaviorPattern]:
        """Get all behavior patterns"""
        return list(self.behavior_patterns.values())
    
    async def generate_report(self, session: HuntSession, format: str = "json") -> str:
        """Generate hunt session report"""
        if format == "json":
            return json.dumps(self._session_to_dict(session), indent=2, default=str)
        elif format == "markdown":
            return self._session_to_markdown(session)
        else:
            return json.dumps(self._session_to_dict(session), indent=2, default=str)
    
    def _session_to_dict(self, session: HuntSession) -> Dict:
        """Convert session to dictionary"""
        return {
            "session_id": session.session_id,
            "name": session.name,
            "hunt_type": session.hunt_type.value,
            "status": session.status,
            "started": session.started.isoformat(),
            "ended": session.ended.isoformat() if session.ended else None,
            "findings_count": len(session.findings),
            "critical_findings": sum(1 for f in session.findings if f.severity == Severity.CRITICAL),
            "high_findings": sum(1 for f in session.findings if f.severity == Severity.HIGH),
            "findings": [
                {
                    "id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "description": f.description
                }
                for f in session.findings
            ]
        }
    
    def _session_to_markdown(self, session: HuntSession) -> str:
        """Generate markdown report"""
        md = f"""# Threat Hunting Report

## Session Information
- **Session ID:** {session.session_id}
- **Name:** {session.name}
- **Type:** {session.hunt_type.value}
- **Started:** {session.started}
- **Status:** {session.status}

## Summary
- **Total Findings:** {len(session.findings)}
- **Critical:** {sum(1 for f in session.findings if f.severity == Severity.CRITICAL)}
- **High:** {sum(1 for f in session.findings if f.severity == Severity.HIGH)}
- **Medium:** {sum(1 for f in session.findings if f.severity == Severity.MEDIUM)}
- **Low:** {sum(1 for f in session.findings if f.severity == Severity.LOW)}

## Findings
"""
        for finding in session.findings:
            md += f"""
### {finding.title}
- **Severity:** {finding.severity.value.upper()}
- **Category:** {finding.category.value}
- **Time:** {finding.timestamp}

{finding.description}

**MITRE ATT&CK:** {', '.join(finding.mitre_attack)}

---
"""
        return md
