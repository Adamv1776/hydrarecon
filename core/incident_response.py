#!/usr/bin/env python3
"""
HydraRecon Incident Response Module
████████████████████████████████████████████████████████████████████████████████
█  ENTERPRISE INCIDENT RESPONSE - Automated Playbooks, Case Management,        █
█  Evidence Collection, Timeline Analysis, and Coordinated Response            █
█  Workflow - BEYOND COMMERCIAL IR PLATFORMS                                    █
████████████████████████████████████████████████████████████████████████████████
"""

import asyncio
import json
import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
from enum import Enum
import logging
import uuid
import zipfile


class IncidentSeverity(Enum):
    """Incident severity levels"""
    CRITICAL = 1  # Immediate action required
    HIGH = 2      # Within 1 hour
    MEDIUM = 3    # Within 4 hours
    LOW = 4       # Within 24 hours
    INFO = 5      # Informational


class IncidentStatus(Enum):
    """Incident lifecycle status"""
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"
    REOPENED = "reopened"


class IncidentType(Enum):
    """Types of security incidents"""
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    PHISHING = "phishing"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DOS_DDOS = "dos_ddos"
    INSIDER_THREAT = "insider_threat"
    APT = "apt"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    CRYPTOMINING = "cryptomining"
    WEB_ATTACK = "web_attack"
    PHYSICAL_SECURITY = "physical_security"
    POLICY_VIOLATION = "policy_violation"
    OTHER = "other"


class EvidenceType(Enum):
    """Types of forensic evidence"""
    LOG_FILE = "log_file"
    MEMORY_DUMP = "memory_dump"
    DISK_IMAGE = "disk_image"
    NETWORK_CAPTURE = "network_capture"
    SCREENSHOT = "screenshot"
    MALWARE_SAMPLE = "malware_sample"
    EMAIL = "email"
    DOCUMENT = "document"
    REGISTRY = "registry"
    ARTIFACT = "artifact"
    IOC = "ioc"


class PlaybookAction(Enum):
    """Playbook action types"""
    COLLECT_EVIDENCE = "collect_evidence"
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    BLOCK_HASH = "block_hash"
    DISABLE_ACCOUNT = "disable_account"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    NOTIFY_TEAM = "notify_team"
    ESCALATE = "escalate"
    EXECUTE_SCRIPT = "execute_script"
    RUN_SCAN = "run_scan"
    CUSTOM = "custom"


@dataclass
class Evidence:
    """Forensic evidence item"""
    evidence_id: str
    evidence_type: EvidenceType
    name: str
    description: str
    file_path: Optional[str]
    hash_md5: Optional[str]
    hash_sha256: Optional[str]
    collected_at: datetime
    collected_by: str
    source_host: Optional[str]
    chain_of_custody: List[Dict] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_verified: bool = False


@dataclass
class TimelineEvent:
    """Incident timeline event"""
    event_id: str
    timestamp: datetime
    event_type: str
    description: str
    source: str
    host: Optional[str]
    user: Optional[str]
    indicators: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    is_malicious: bool = False
    confidence: float = 0.0


@dataclass
class PlaybookStep:
    """Playbook execution step"""
    step_id: str
    order: int
    action: PlaybookAction
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 300
    continue_on_failure: bool = False
    requires_approval: bool = False
    conditions: List[str] = field(default_factory=list)


@dataclass
class Playbook:
    """Incident response playbook"""
    playbook_id: str
    name: str
    description: str
    incident_types: List[IncidentType]
    severity_levels: List[IncidentSeverity]
    steps: List[PlaybookStep] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    author: str = "HydraRecon"
    version: str = "1.0"
    is_enabled: bool = True
    tags: List[str] = field(default_factory=list)


@dataclass
class IncidentTask:
    """Task within an incident"""
    task_id: str
    title: str
    description: str
    assigned_to: Optional[str]
    status: str  # pending, in_progress, completed, blocked
    priority: int  # 1-5
    due_date: Optional[datetime]
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class Incident:
    """Security incident"""
    incident_id: str
    title: str
    description: str
    incident_type: IncidentType
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    detected_at: datetime
    closed_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    reporter: Optional[str] = None
    affected_hosts: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    tasks: List[IncidentTask] = field(default_factory=list)
    playbooks_executed: List[str] = field(default_factory=list)
    containment_actions: List[Dict] = field(default_factory=list)
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None
    related_incidents: List[str] = field(default_factory=list)
    external_refs: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    sla_breach: bool = False
    is_false_positive: bool = False


@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_id: str
    ioc_type: str  # ip, domain, hash, url, email, filename
    value: str
    description: str
    source: str
    confidence: float  # 0-100
    first_seen: datetime
    last_seen: datetime
    is_active: bool = True
    related_incidents: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class EvidenceCollector:
    """Collect and manage forensic evidence"""
    
    def __init__(self, evidence_path: str = "./evidence"):
        self.evidence_path = evidence_path
        self.logger = logging.getLogger("EvidenceCollector")
        os.makedirs(evidence_path, exist_ok=True)
    
    def collect_file(self, source_path: str, incident_id: str,
                    description: str = "", collector: str = "HydraRecon") -> Optional[Evidence]:
        """Collect a file as evidence"""
        try:
            if not os.path.exists(source_path):
                self.logger.error(f"Source file not found: {source_path}")
                return None
            
            evidence_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
            
            # Calculate hashes
            md5_hash = self._calculate_hash(source_path, "md5")
            sha256_hash = self._calculate_hash(source_path, "sha256")
            
            # Create evidence directory
            incident_dir = os.path.join(self.evidence_path, incident_id)
            os.makedirs(incident_dir, exist_ok=True)
            
            # Copy file to evidence storage
            dest_path = os.path.join(incident_dir, f"{evidence_id}_{os.path.basename(source_path)}")
            shutil.copy2(source_path, dest_path)
            
            # Create evidence record
            evidence = Evidence(
                evidence_id=evidence_id,
                evidence_type=self._detect_evidence_type(source_path),
                name=os.path.basename(source_path),
                description=description,
                file_path=dest_path,
                hash_md5=md5_hash,
                hash_sha256=sha256_hash,
                collected_at=datetime.now(),
                collected_by=collector,
                source_host=None,
                chain_of_custody=[{
                    "action": "collected",
                    "by": collector,
                    "timestamp": datetime.now().isoformat(),
                    "notes": "Original file collected"
                }]
            )
            
            # Verify integrity
            evidence.is_verified = self._verify_integrity(dest_path, sha256_hash)
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Failed to collect evidence: {e}")
            return None
    
    def collect_memory_dump(self, host: str, incident_id: str,
                           collector: str = "HydraRecon") -> Optional[Evidence]:
        """Collect memory dump from host"""
        # This would integrate with volatility or similar tools
        evidence_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
        
        evidence = Evidence(
            evidence_id=evidence_id,
            evidence_type=EvidenceType.MEMORY_DUMP,
            name=f"memory_dump_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.raw",
            description=f"Memory dump from host {host}",
            file_path=None,  # Would be populated after actual collection
            hash_md5=None,
            hash_sha256=None,
            collected_at=datetime.now(),
            collected_by=collector,
            source_host=host,
            chain_of_custody=[{
                "action": "initiated",
                "by": collector,
                "timestamp": datetime.now().isoformat(),
                "notes": f"Memory dump collection initiated for {host}"
            }]
        )
        
        return evidence
    
    def collect_logs(self, log_paths: List[str], incident_id: str,
                    time_range: Tuple[datetime, datetime] = None) -> List[Evidence]:
        """Collect log files as evidence"""
        collected = []
        
        for log_path in log_paths:
            if os.path.exists(log_path):
                evidence = self.collect_file(
                    log_path, incident_id,
                    description=f"Log file collected for incident {incident_id}"
                )
                if evidence:
                    collected.append(evidence)
        
        return collected
    
    def _calculate_hash(self, file_path: str, algorithm: str) -> str:
        """Calculate file hash"""
        if algorithm == "md5":
            hasher = hashlib.md5()
        else:
            hasher = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def _detect_evidence_type(self, file_path: str) -> EvidenceType:
        """Detect evidence type from file"""
        ext = os.path.splitext(file_path)[1].lower()
        
        type_mapping = {
            ".log": EvidenceType.LOG_FILE,
            ".pcap": EvidenceType.NETWORK_CAPTURE,
            ".pcapng": EvidenceType.NETWORK_CAPTURE,
            ".raw": EvidenceType.MEMORY_DUMP,
            ".dmp": EvidenceType.MEMORY_DUMP,
            ".vmem": EvidenceType.MEMORY_DUMP,
            ".dd": EvidenceType.DISK_IMAGE,
            ".e01": EvidenceType.DISK_IMAGE,
            ".png": EvidenceType.SCREENSHOT,
            ".jpg": EvidenceType.SCREENSHOT,
            ".eml": EvidenceType.EMAIL,
            ".msg": EvidenceType.EMAIL,
            ".exe": EvidenceType.MALWARE_SAMPLE,
            ".dll": EvidenceType.MALWARE_SAMPLE,
            ".doc": EvidenceType.DOCUMENT,
            ".docx": EvidenceType.DOCUMENT,
            ".pdf": EvidenceType.DOCUMENT,
        }
        
        return type_mapping.get(ext, EvidenceType.ARTIFACT)
    
    def _verify_integrity(self, file_path: str, expected_hash: str) -> bool:
        """Verify file integrity"""
        actual_hash = self._calculate_hash(file_path, "sha256")
        return actual_hash == expected_hash
    
    def export_evidence_package(self, incident_id: str, output_path: str) -> Optional[str]:
        """Export all evidence for an incident as a ZIP package"""
        try:
            incident_dir = os.path.join(self.evidence_path, incident_id)
            if not os.path.exists(incident_dir):
                return None
            
            zip_path = os.path.join(output_path, f"evidence_{incident_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(incident_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, incident_dir)
                        zipf.write(file_path, arcname)
            
            return zip_path
            
        except Exception as e:
            self.logger.error(f"Failed to export evidence: {e}")
            return None


class TimelineAnalyzer:
    """Analyze and correlate incident timeline events"""
    
    def __init__(self):
        self.logger = logging.getLogger("TimelineAnalyzer")
    
    def create_event(self, timestamp: datetime, event_type: str,
                    description: str, source: str, **kwargs) -> TimelineEvent:
        """Create a timeline event"""
        return TimelineEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=timestamp,
            event_type=event_type,
            description=description,
            source=source,
            host=kwargs.get("host"),
            user=kwargs.get("user"),
            indicators=kwargs.get("indicators", []),
            evidence_ids=kwargs.get("evidence_ids", []),
            is_malicious=kwargs.get("is_malicious", False),
            confidence=kwargs.get("confidence", 0.0)
        )
    
    def analyze_timeline(self, events: List[TimelineEvent]) -> Dict[str, Any]:
        """Analyze timeline for patterns and anomalies"""
        if not events:
            return {"patterns": [], "anomalies": [], "summary": {}}
        
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        analysis = {
            "total_events": len(events),
            "time_span": {
                "start": sorted_events[0].timestamp.isoformat(),
                "end": sorted_events[-1].timestamp.isoformat(),
                "duration_hours": (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds() / 3600
            },
            "event_types": {},
            "hosts_involved": set(),
            "users_involved": set(),
            "patterns": [],
            "anomalies": [],
            "attack_phases": []
        }
        
        # Count event types
        for event in events:
            analysis["event_types"][event.event_type] = analysis["event_types"].get(event.event_type, 0) + 1
            if event.host:
                analysis["hosts_involved"].add(event.host)
            if event.user:
                analysis["users_involved"].add(event.user)
        
        analysis["hosts_involved"] = list(analysis["hosts_involved"])
        analysis["users_involved"] = list(analysis["users_involved"])
        
        # Detect patterns
        analysis["patterns"] = self._detect_patterns(sorted_events)
        
        # Detect anomalies
        analysis["anomalies"] = self._detect_anomalies(sorted_events)
        
        # Identify attack phases
        analysis["attack_phases"] = self._identify_attack_phases(sorted_events)
        
        return analysis
    
    def _detect_patterns(self, events: List[TimelineEvent]) -> List[Dict]:
        """Detect patterns in timeline"""
        patterns = []
        
        # Rapid succession pattern
        for i in range(len(events) - 1):
            time_diff = (events[i+1].timestamp - events[i].timestamp).total_seconds()
            if time_diff < 5 and events[i].host == events[i+1].host:
                patterns.append({
                    "type": "rapid_succession",
                    "description": f"Rapid events on {events[i].host}",
                    "events": [events[i].event_id, events[i+1].event_id],
                    "significance": "high"
                })
        
        # Lateral movement pattern
        hosts_in_order = []
        for event in events:
            if event.host and event.host not in hosts_in_order[-3:] if hosts_in_order else True:
                hosts_in_order.append(event.host)
        
        if len(set(hosts_in_order)) >= 3:
            patterns.append({
                "type": "lateral_movement",
                "description": f"Activity across multiple hosts: {', '.join(set(hosts_in_order[:5]))}",
                "hosts": list(set(hosts_in_order)),
                "significance": "critical"
            })
        
        return patterns
    
    def _detect_anomalies(self, events: List[TimelineEvent]) -> List[Dict]:
        """Detect anomalies in timeline"""
        anomalies = []
        
        # Time-based anomalies (after-hours activity)
        for event in events:
            hour = event.timestamp.hour
            if hour < 6 or hour > 22:
                anomalies.append({
                    "type": "after_hours",
                    "event_id": event.event_id,
                    "timestamp": event.timestamp.isoformat(),
                    "description": f"Activity detected at {hour}:00"
                })
        
        return anomalies
    
    def _identify_attack_phases(self, events: List[TimelineEvent]) -> List[Dict]:
        """Identify MITRE ATT&CK phases in timeline"""
        phases = []
        
        # Map event types to attack phases
        phase_mapping = {
            "reconnaissance": ["scan", "enumeration", "discovery"],
            "initial_access": ["login_failure", "login_success", "exploit"],
            "execution": ["process_start", "script_execution", "command_execution"],
            "persistence": ["registry_modification", "scheduled_task", "service_creation"],
            "privilege_escalation": ["privilege_escalation", "token_manipulation"],
            "defense_evasion": ["log_cleared", "av_disabled", "obfuscation"],
            "credential_access": ["credential_dump", "keylogging", "brute_force"],
            "discovery": ["network_discovery", "file_discovery", "account_discovery"],
            "lateral_movement": ["remote_access", "smb_movement", "pass_the_hash"],
            "collection": ["file_access", "screenshot", "keylog"],
            "command_control": ["c2_connection", "dns_tunnel", "http_beacon"],
            "exfiltration": ["data_transfer", "upload", "exfil"],
            "impact": ["ransomware", "data_destruction", "dos"]
        }
        
        for phase, keywords in phase_mapping.items():
            matching_events = [e for e in events if any(kw in e.event_type.lower() for kw in keywords)]
            if matching_events:
                phases.append({
                    "phase": phase,
                    "event_count": len(matching_events),
                    "first_seen": min(e.timestamp for e in matching_events).isoformat(),
                    "last_seen": max(e.timestamp for e in matching_events).isoformat()
                })
        
        return phases


class PlaybookEngine:
    """Execute incident response playbooks"""
    
    def __init__(self):
        self.logger = logging.getLogger("PlaybookEngine")
        self.playbooks: Dict[str, Playbook] = {}
        self.action_handlers: Dict[PlaybookAction, Callable] = {}
        self._load_default_playbooks()
        self._register_default_handlers()
    
    def _load_default_playbooks(self):
        """Load default incident response playbooks"""
        
        # Malware Response Playbook
        malware_playbook = Playbook(
            playbook_id="PB-MALWARE-001",
            name="Malware Incident Response",
            description="Standard response procedure for malware infections",
            incident_types=[IncidentType.MALWARE, IncidentType.RANSOMWARE],
            severity_levels=[IncidentSeverity.CRITICAL, IncidentSeverity.HIGH],
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    order=1,
                    action=PlaybookAction.ISOLATE_HOST,
                    description="Isolate infected host from network",
                    parameters={"isolation_type": "network"},
                    requires_approval=True
                ),
                PlaybookStep(
                    step_id="step-2",
                    order=2,
                    action=PlaybookAction.COLLECT_EVIDENCE,
                    description="Collect memory dump and disk artifacts",
                    parameters={"collect_memory": True, "collect_disk": True}
                ),
                PlaybookStep(
                    step_id="step-3",
                    order=3,
                    action=PlaybookAction.QUARANTINE_FILE,
                    description="Quarantine malicious files",
                    parameters={}
                ),
                PlaybookStep(
                    step_id="step-4",
                    order=4,
                    action=PlaybookAction.BLOCK_HASH,
                    description="Block malware hashes across environment",
                    parameters={"scope": "enterprise"}
                ),
                PlaybookStep(
                    step_id="step-5",
                    order=5,
                    action=PlaybookAction.RUN_SCAN,
                    description="Run IOC scan across environment",
                    parameters={"scan_type": "ioc_sweep"}
                ),
                PlaybookStep(
                    step_id="step-6",
                    order=6,
                    action=PlaybookAction.NOTIFY_TEAM,
                    description="Notify security team and stakeholders",
                    parameters={"teams": ["soc", "management"]}
                )
            ],
            tags=["malware", "containment", "eradication"]
        )
        self.playbooks[malware_playbook.playbook_id] = malware_playbook
        
        # Phishing Response Playbook
        phishing_playbook = Playbook(
            playbook_id="PB-PHISHING-001",
            name="Phishing Incident Response",
            description="Response procedure for phishing incidents",
            incident_types=[IncidentType.PHISHING],
            severity_levels=[IncidentSeverity.HIGH, IncidentSeverity.MEDIUM],
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    order=1,
                    action=PlaybookAction.BLOCK_IP,
                    description="Block phishing source IP/domain",
                    parameters={"block_type": "firewall"}
                ),
                PlaybookStep(
                    step_id="step-2",
                    order=2,
                    action=PlaybookAction.DISABLE_ACCOUNT,
                    description="Reset credentials for affected users",
                    parameters={"force_reset": True}
                ),
                PlaybookStep(
                    step_id="step-3",
                    order=3,
                    action=PlaybookAction.COLLECT_EVIDENCE,
                    description="Collect phishing email and attachments",
                    parameters={"collect_email": True}
                ),
                PlaybookStep(
                    step_id="step-4",
                    order=4,
                    action=PlaybookAction.RUN_SCAN,
                    description="Scan for related emails in environment",
                    parameters={"scan_type": "email_search"}
                ),
                PlaybookStep(
                    step_id="step-5",
                    order=5,
                    action=PlaybookAction.NOTIFY_TEAM,
                    description="Send user awareness notification",
                    parameters={"notification_type": "awareness"}
                )
            ],
            tags=["phishing", "email", "credentials"]
        )
        self.playbooks[phishing_playbook.playbook_id] = phishing_playbook
        
        # Unauthorized Access Playbook
        access_playbook = Playbook(
            playbook_id="PB-ACCESS-001",
            name="Unauthorized Access Response",
            description="Response procedure for unauthorized access incidents",
            incident_types=[IncidentType.UNAUTHORIZED_ACCESS, IncidentType.PRIVILEGE_ESCALATION],
            severity_levels=[IncidentSeverity.CRITICAL, IncidentSeverity.HIGH, IncidentSeverity.MEDIUM],
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    order=1,
                    action=PlaybookAction.DISABLE_ACCOUNT,
                    description="Disable compromised account",
                    parameters={"disable_related": True}
                ),
                PlaybookStep(
                    step_id="step-2",
                    order=2,
                    action=PlaybookAction.KILL_PROCESS,
                    description="Terminate suspicious processes",
                    parameters={}
                ),
                PlaybookStep(
                    step_id="step-3",
                    order=3,
                    action=PlaybookAction.COLLECT_EVIDENCE,
                    description="Collect authentication logs",
                    parameters={"log_types": ["auth", "access"]}
                ),
                PlaybookStep(
                    step_id="step-4",
                    order=4,
                    action=PlaybookAction.BLOCK_IP,
                    description="Block source IP addresses",
                    parameters={}
                ),
                PlaybookStep(
                    step_id="step-5",
                    order=5,
                    action=PlaybookAction.ESCALATE,
                    description="Escalate to senior analyst",
                    parameters={"escalation_level": 2}
                )
            ],
            tags=["access", "authentication", "credentials"]
        )
        self.playbooks[access_playbook.playbook_id] = access_playbook
        
        # Data Breach Playbook
        breach_playbook = Playbook(
            playbook_id="PB-BREACH-001",
            name="Data Breach Response",
            description="Response procedure for data breach incidents",
            incident_types=[IncidentType.DATA_BREACH, IncidentType.DATA_EXFILTRATION],
            severity_levels=[IncidentSeverity.CRITICAL],
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    order=1,
                    action=PlaybookAction.ISOLATE_HOST,
                    description="Isolate affected systems",
                    parameters={"isolation_type": "full"},
                    requires_approval=True
                ),
                PlaybookStep(
                    step_id="step-2",
                    order=2,
                    action=PlaybookAction.COLLECT_EVIDENCE,
                    description="Preserve all relevant evidence",
                    parameters={"preserve_chain": True}
                ),
                PlaybookStep(
                    step_id="step-3",
                    order=3,
                    action=PlaybookAction.ESCALATE,
                    description="Escalate to incident commander",
                    parameters={"escalation_level": 3}
                ),
                PlaybookStep(
                    step_id="step-4",
                    order=4,
                    action=PlaybookAction.NOTIFY_TEAM,
                    description="Notify legal and compliance",
                    parameters={"teams": ["legal", "compliance", "executive"]}
                )
            ],
            tags=["breach", "data", "legal", "compliance"]
        )
        self.playbooks[breach_playbook.playbook_id] = breach_playbook
    
    def _register_default_handlers(self):
        """Register default action handlers"""
        self.action_handlers[PlaybookAction.COLLECT_EVIDENCE] = self._handle_collect_evidence
        self.action_handlers[PlaybookAction.ISOLATE_HOST] = self._handle_isolate_host
        self.action_handlers[PlaybookAction.BLOCK_IP] = self._handle_block_ip
        self.action_handlers[PlaybookAction.BLOCK_HASH] = self._handle_block_hash
        self.action_handlers[PlaybookAction.DISABLE_ACCOUNT] = self._handle_disable_account
        self.action_handlers[PlaybookAction.KILL_PROCESS] = self._handle_kill_process
        self.action_handlers[PlaybookAction.QUARANTINE_FILE] = self._handle_quarantine_file
        self.action_handlers[PlaybookAction.NOTIFY_TEAM] = self._handle_notify_team
        self.action_handlers[PlaybookAction.ESCALATE] = self._handle_escalate
        self.action_handlers[PlaybookAction.RUN_SCAN] = self._handle_run_scan
    
    async def execute_playbook(self, playbook_id: str, incident: Incident,
                               context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a playbook for an incident"""
        if playbook_id not in self.playbooks:
            return {"success": False, "error": f"Playbook {playbook_id} not found"}
        
        playbook = self.playbooks[playbook_id]
        context = context or {}
        
        execution_log = {
            "playbook_id": playbook_id,
            "incident_id": incident.incident_id,
            "started_at": datetime.now().isoformat(),
            "steps": [],
            "success": True
        }
        
        sorted_steps = sorted(playbook.steps, key=lambda s: s.order)
        
        for step in sorted_steps:
            step_result = {
                "step_id": step.step_id,
                "action": step.action.value,
                "started_at": datetime.now().isoformat(),
                "status": "pending"
            }
            
            try:
                # Check conditions
                if step.conditions:
                    conditions_met = self._evaluate_conditions(step.conditions, context)
                    if not conditions_met:
                        step_result["status"] = "skipped"
                        step_result["reason"] = "Conditions not met"
                        execution_log["steps"].append(step_result)
                        continue
                
                # Execute action
                handler = self.action_handlers.get(step.action)
                if handler:
                    result = await handler(incident, step.parameters, context)
                    step_result["result"] = result
                    step_result["status"] = "success" if result.get("success") else "failed"
                else:
                    step_result["status"] = "skipped"
                    step_result["reason"] = f"No handler for action {step.action.value}"
                
            except Exception as e:
                step_result["status"] = "failed"
                step_result["error"] = str(e)
                
                if not step.continue_on_failure:
                    execution_log["success"] = False
                    execution_log["steps"].append(step_result)
                    break
            
            step_result["completed_at"] = datetime.now().isoformat()
            execution_log["steps"].append(step_result)
        
        execution_log["completed_at"] = datetime.now().isoformat()
        
        return execution_log
    
    def _evaluate_conditions(self, conditions: List[str], context: Dict) -> bool:
        """Evaluate step conditions"""
        # Simple condition evaluation
        for condition in conditions:
            if not context.get(condition):
                return False
        return True
    
    async def _handle_collect_evidence(self, incident: Incident, 
                                       params: Dict, context: Dict) -> Dict:
        """Handle evidence collection action"""
        return {
            "success": True,
            "action": "collect_evidence",
            "message": f"Evidence collection initiated for incident {incident.incident_id}"
        }
    
    async def _handle_isolate_host(self, incident: Incident,
                                   params: Dict, context: Dict) -> Dict:
        """Handle host isolation action"""
        hosts = incident.affected_hosts
        return {
            "success": True,
            "action": "isolate_host",
            "hosts_isolated": hosts,
            "message": f"Isolation initiated for {len(hosts)} hosts"
        }
    
    async def _handle_block_ip(self, incident: Incident,
                               params: Dict, context: Dict) -> Dict:
        """Handle IP blocking action"""
        return {
            "success": True,
            "action": "block_ip",
            "message": "IP blocking rules updated"
        }
    
    async def _handle_block_hash(self, incident: Incident,
                                 params: Dict, context: Dict) -> Dict:
        """Handle hash blocking action"""
        return {
            "success": True,
            "action": "block_hash",
            "message": "Hash blocking rules updated"
        }
    
    async def _handle_disable_account(self, incident: Incident,
                                      params: Dict, context: Dict) -> Dict:
        """Handle account disabling action"""
        users = incident.affected_users
        return {
            "success": True,
            "action": "disable_account",
            "accounts_affected": users,
            "message": f"Disabled {len(users)} accounts"
        }
    
    async def _handle_kill_process(self, incident: Incident,
                                   params: Dict, context: Dict) -> Dict:
        """Handle process termination action"""
        return {
            "success": True,
            "action": "kill_process",
            "message": "Process termination initiated"
        }
    
    async def _handle_quarantine_file(self, incident: Incident,
                                      params: Dict, context: Dict) -> Dict:
        """Handle file quarantine action"""
        return {
            "success": True,
            "action": "quarantine_file",
            "message": "File quarantine initiated"
        }
    
    async def _handle_notify_team(self, incident: Incident,
                                  params: Dict, context: Dict) -> Dict:
        """Handle team notification action"""
        teams = params.get("teams", [])
        return {
            "success": True,
            "action": "notify_team",
            "teams_notified": teams,
            "message": f"Notified teams: {', '.join(teams)}"
        }
    
    async def _handle_escalate(self, incident: Incident,
                               params: Dict, context: Dict) -> Dict:
        """Handle escalation action"""
        level = params.get("escalation_level", 1)
        return {
            "success": True,
            "action": "escalate",
            "escalation_level": level,
            "message": f"Escalated to level {level}"
        }
    
    async def _handle_run_scan(self, incident: Incident,
                               params: Dict, context: Dict) -> Dict:
        """Handle scan execution action"""
        scan_type = params.get("scan_type", "full")
        return {
            "success": True,
            "action": "run_scan",
            "scan_type": scan_type,
            "message": f"Initiated {scan_type} scan"
        }
    
    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        """Get a playbook by ID"""
        return self.playbooks.get(playbook_id)
    
    def list_playbooks(self, incident_type: IncidentType = None) -> List[Playbook]:
        """List available playbooks"""
        playbooks = list(self.playbooks.values())
        
        if incident_type:
            playbooks = [p for p in playbooks if incident_type in p.incident_types]
        
        return playbooks
    
    def add_playbook(self, playbook: Playbook):
        """Add a custom playbook"""
        self.playbooks[playbook.playbook_id] = playbook


class IncidentResponseEngine:
    """Main incident response engine"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger("IncidentResponseEngine")
        self.incidents: Dict[str, Incident] = {}
        self.iocs: Dict[str, IOC] = {}
        self.evidence_collector = EvidenceCollector(
            self.config.get("evidence_path", "./evidence")
        )
        self.timeline_analyzer = TimelineAnalyzer()
        self.playbook_engine = PlaybookEngine()
    
    def create_incident(self, title: str, description: str,
                       incident_type: IncidentType,
                       severity: IncidentSeverity,
                       **kwargs) -> Incident:
        """Create a new incident"""
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        
        incident = Incident(
            incident_id=incident_id,
            title=title,
            description=description,
            incident_type=incident_type,
            severity=severity,
            status=IncidentStatus.NEW,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            detected_at=kwargs.get("detected_at", datetime.now()),
            assigned_to=kwargs.get("assigned_to"),
            reporter=kwargs.get("reporter"),
            affected_hosts=kwargs.get("affected_hosts", []),
            affected_users=kwargs.get("affected_users", []),
            indicators=kwargs.get("indicators", []),
            tags=kwargs.get("tags", [])
        )
        
        # Calculate SLA
        incident.sla_breach = self._check_sla(incident)
        
        self.incidents[incident_id] = incident
        
        self.logger.info(f"Created incident {incident_id}: {title}")
        
        return incident
    
    def update_incident(self, incident_id: str, **kwargs) -> Optional[Incident]:
        """Update an incident"""
        if incident_id not in self.incidents:
            return None
        
        incident = self.incidents[incident_id]
        
        for key, value in kwargs.items():
            if hasattr(incident, key):
                setattr(incident, key, value)
        
        incident.updated_at = datetime.now()
        
        return incident
    
    def add_timeline_event(self, incident_id: str, timestamp: datetime,
                          event_type: str, description: str,
                          source: str, **kwargs) -> Optional[TimelineEvent]:
        """Add event to incident timeline"""
        if incident_id not in self.incidents:
            return None
        
        event = self.timeline_analyzer.create_event(
            timestamp, event_type, description, source, **kwargs
        )
        
        self.incidents[incident_id].timeline.append(event)
        self.incidents[incident_id].updated_at = datetime.now()
        
        return event
    
    def add_evidence(self, incident_id: str, source_path: str,
                    description: str = "") -> Optional[Evidence]:
        """Add evidence to incident"""
        if incident_id not in self.incidents:
            return None
        
        evidence = self.evidence_collector.collect_file(
            source_path, incident_id, description
        )
        
        if evidence:
            self.incidents[incident_id].evidence.append(evidence)
            self.incidents[incident_id].updated_at = datetime.now()
        
        return evidence
    
    def add_ioc(self, ioc_type: str, value: str, description: str,
               source: str, confidence: float = 50.0,
               incident_id: str = None) -> IOC:
        """Add an Indicator of Compromise"""
        ioc_id = f"IOC-{uuid.uuid4().hex[:8].upper()}"
        
        ioc = IOC(
            ioc_id=ioc_id,
            ioc_type=ioc_type,
            value=value,
            description=description,
            source=source,
            confidence=confidence,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            related_incidents=[incident_id] if incident_id else []
        )
        
        self.iocs[ioc_id] = ioc
        
        if incident_id and incident_id in self.incidents:
            self.incidents[incident_id].indicators.append(value)
        
        return ioc
    
    def add_task(self, incident_id: str, title: str, description: str,
                priority: int = 3, assigned_to: str = None,
                due_date: datetime = None) -> Optional[IncidentTask]:
        """Add task to incident"""
        if incident_id not in self.incidents:
            return None
        
        task = IncidentTask(
            task_id=f"TSK-{uuid.uuid4().hex[:6].upper()}",
            title=title,
            description=description,
            assigned_to=assigned_to,
            status="pending",
            priority=priority,
            due_date=due_date
        )
        
        self.incidents[incident_id].tasks.append(task)
        self.incidents[incident_id].updated_at = datetime.now()
        
        return task
    
    async def execute_playbook(self, incident_id: str, playbook_id: str,
                               context: Dict = None) -> Dict:
        """Execute playbook for incident"""
        if incident_id not in self.incidents:
            return {"success": False, "error": "Incident not found"}
        
        incident = self.incidents[incident_id]
        
        result = await self.playbook_engine.execute_playbook(
            playbook_id, incident, context
        )
        
        if result["success"]:
            incident.playbooks_executed.append(playbook_id)
            incident.updated_at = datetime.now()
        
        return result
    
    def analyze_timeline(self, incident_id: str) -> Dict:
        """Analyze incident timeline"""
        if incident_id not in self.incidents:
            return {}
        
        incident = self.incidents[incident_id]
        return self.timeline_analyzer.analyze_timeline(incident.timeline)
    
    def close_incident(self, incident_id: str, root_cause: str = None,
                      lessons_learned: str = None,
                      is_false_positive: bool = False) -> Optional[Incident]:
        """Close an incident"""
        if incident_id not in self.incidents:
            return None
        
        incident = self.incidents[incident_id]
        incident.status = IncidentStatus.CLOSED
        incident.closed_at = datetime.now()
        incident.updated_at = datetime.now()
        incident.root_cause = root_cause
        incident.lessons_learned = lessons_learned
        incident.is_false_positive = is_false_positive
        
        return incident
    
    def reopen_incident(self, incident_id: str, reason: str = None) -> Optional[Incident]:
        """Reopen a closed incident"""
        if incident_id not in self.incidents:
            return None
        
        incident = self.incidents[incident_id]
        incident.status = IncidentStatus.REOPENED
        incident.closed_at = None
        incident.updated_at = datetime.now()
        
        if reason:
            self.add_timeline_event(
                incident_id, datetime.now(), "reopen",
                f"Incident reopened: {reason}", "system"
            )
        
        return incident
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID"""
        return self.incidents.get(incident_id)
    
    def list_incidents(self, status: IncidentStatus = None,
                      severity: IncidentSeverity = None,
                      incident_type: IncidentType = None) -> List[Incident]:
        """List incidents with optional filters"""
        incidents = list(self.incidents.values())
        
        if status:
            incidents = [i for i in incidents if i.status == status]
        
        if severity:
            incidents = [i for i in incidents if i.severity == severity]
        
        if incident_type:
            incidents = [i for i in incidents if i.incident_type == incident_type]
        
        return sorted(incidents, key=lambda i: (i.severity.value, i.created_at))
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get incident response metrics"""
        all_incidents = list(self.incidents.values())
        
        if not all_incidents:
            return {"total": 0, "by_status": {}, "by_severity": {}, "mttr": 0}
        
        # Calculate MTTR (Mean Time to Resolution)
        closed = [i for i in all_incidents if i.status == IncidentStatus.CLOSED]
        mttr_hours = 0
        if closed:
            total_hours = sum(
                (i.closed_at - i.created_at).total_seconds() / 3600
                for i in closed if i.closed_at
            )
            mttr_hours = total_hours / len(closed)
        
        return {
            "total": len(all_incidents),
            "open": len([i for i in all_incidents if i.status not in [IncidentStatus.CLOSED]]),
            "closed": len(closed),
            "by_status": {
                status.value: len([i for i in all_incidents if i.status == status])
                for status in IncidentStatus
            },
            "by_severity": {
                severity.name: len([i for i in all_incidents if i.severity == severity])
                for severity in IncidentSeverity
            },
            "by_type": {
                itype.value: len([i for i in all_incidents if i.incident_type == itype])
                for itype in IncidentType
            },
            "mttr_hours": round(mttr_hours, 2),
            "sla_breaches": len([i for i in all_incidents if i.sla_breach]),
            "false_positives": len([i for i in all_incidents if i.is_false_positive]),
            "total_iocs": len(self.iocs),
            "playbooks_available": len(self.playbook_engine.playbooks)
        }
    
    def _check_sla(self, incident: Incident) -> bool:
        """Check if incident has breached SLA"""
        sla_hours = {
            IncidentSeverity.CRITICAL: 1,
            IncidentSeverity.HIGH: 4,
            IncidentSeverity.MEDIUM: 8,
            IncidentSeverity.LOW: 24,
            IncidentSeverity.INFO: 48
        }
        
        if incident.status == IncidentStatus.CLOSED:
            return False
        
        hours_since_creation = (datetime.now() - incident.created_at).total_seconds() / 3600
        allowed_hours = sla_hours.get(incident.severity, 24)
        
        return hours_since_creation > allowed_hours
    
    def export_incident_report(self, incident_id: str) -> Dict[str, Any]:
        """Export detailed incident report"""
        incident = self.get_incident(incident_id)
        if not incident:
            return {}
        
        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "description": incident.description,
            "type": incident.incident_type.value,
            "severity": incident.severity.name,
            "status": incident.status.value,
            "timeline": {
                "created": incident.created_at.isoformat(),
                "detected": incident.detected_at.isoformat(),
                "updated": incident.updated_at.isoformat(),
                "closed": incident.closed_at.isoformat() if incident.closed_at else None
            },
            "affected": {
                "hosts": incident.affected_hosts,
                "users": incident.affected_users
            },
            "indicators": incident.indicators,
            "evidence_count": len(incident.evidence),
            "timeline_events": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "type": e.event_type,
                    "description": e.description,
                    "source": e.source
                } for e in incident.timeline
            ],
            "tasks": [
                {
                    "id": t.task_id,
                    "title": t.title,
                    "status": t.status,
                    "assigned": t.assigned_to
                } for t in incident.tasks
            ],
            "playbooks_executed": incident.playbooks_executed,
            "root_cause": incident.root_cause,
            "lessons_learned": incident.lessons_learned,
            "is_false_positive": incident.is_false_positive,
            "tags": incident.tags
        }
