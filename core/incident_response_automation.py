#!/usr/bin/env python3
"""
HydraRecon Incident Response Automation Module
████████████████████████████████████████████████████████████████████████████████
█  ENTERPRISE INCIDENT RESPONSE - Automated Triage, Evidence Collection,       █
█  Containment Actions, Forensic Acquisition & Response Orchestration          █
████████████████████████████████████████████████████████████████████████████████
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import shutil
import socket
import struct
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from pathlib import Path
import threading


class IncidentSeverity(Enum):
    """Incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class IncidentStatus(Enum):
    """Incident lifecycle status"""
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentType(Enum):
    """Types of security incidents"""
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DOS_DDOS = "dos_ddos"
    INSIDER_THREAT = "insider_threat"
    APT = "apt"
    CRYPTOMINING = "cryptomining"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    C2_COMMUNICATION = "c2_communication"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    WEB_ATTACK = "web_attack"


class ContainmentAction(Enum):
    """Containment action types"""
    ISOLATE_HOST = "isolate_host"
    DISABLE_USER = "disable_user"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_HASH = "block_hash"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    REVOKE_TOKENS = "revoke_tokens"
    DISABLE_SERVICE = "disable_service"
    NETWORK_SEGMENT = "network_segment"


class EvidenceType(Enum):
    """Types of forensic evidence"""
    MEMORY_DUMP = "memory_dump"
    DISK_IMAGE = "disk_image"
    LOG_FILE = "log_file"
    NETWORK_CAPTURE = "network_capture"
    MALWARE_SAMPLE = "malware_sample"
    SCREENSHOT = "screenshot"
    PROCESS_LIST = "process_list"
    NETWORK_CONNECTIONS = "network_connections"
    REGISTRY_DUMP = "registry_dump"
    BROWSER_ARTIFACTS = "browser_artifacts"
    EMAIL_HEADERS = "email_headers"
    FILE_METADATA = "file_metadata"


@dataclass
class Evidence:
    """Forensic evidence item"""
    evidence_id: str
    evidence_type: EvidenceType
    source: str
    filename: str
    hash_md5: str
    hash_sha256: str
    size_bytes: int
    collected_at: datetime
    collected_by: str
    chain_of_custody: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TimelineEvent:
    """Timeline event for incident reconstruction"""
    timestamp: datetime
    event_type: str
    source: str
    description: str
    indicators: List[str]
    evidence_ids: List[str]
    severity: IncidentSeverity
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_id: str
    ioc_type: str  # ip, domain, hash, url, email, etc.
    value: str
    first_seen: datetime
    last_seen: datetime
    confidence: float
    source: str
    tags: List[str] = field(default_factory=list)
    related_incidents: List[str] = field(default_factory=list)


@dataclass
class Incident:
    """Security incident record"""
    incident_id: str
    title: str
    description: str
    incident_type: IncidentType
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    detected_by: str
    assigned_to: Optional[str]
    affected_assets: List[str]
    iocs: List[IOC]
    timeline: List[TimelineEvent]
    evidence: List[Evidence]
    containment_actions: List[Dict[str, Any]]
    notes: List[Dict[str, Any]]
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class PlaybookStep:
    """Incident response playbook step"""
    step_id: str
    name: str
    description: str
    action_type: str
    parameters: Dict[str, Any]
    conditions: Dict[str, Any]
    timeout_seconds: int = 300
    retry_count: int = 3
    on_failure: str = "continue"  # continue, abort, skip


@dataclass
class Playbook:
    """Incident response playbook"""
    playbook_id: str
    name: str
    description: str
    incident_types: List[IncidentType]
    severity_threshold: IncidentSeverity
    steps: List[PlaybookStep]
    auto_execute: bool = False
    version: str = "1.0"


class EvidenceCollector:
    """Automated evidence collection"""
    
    def __init__(self, evidence_path: str = "/tmp/evidence"):
        self.logger = logging.getLogger(__name__)
        self.evidence_path = Path(evidence_path)
        self.evidence_path.mkdir(parents=True, exist_ok=True)
    
    async def collect_memory_dump(
        self,
        target_host: str,
        incident_id: str
    ) -> Optional[Evidence]:
        """Collect memory dump from target host"""
        self.logger.info(f"Collecting memory dump from {target_host}")
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"memory_{target_host}_{timestamp}.raw"
            filepath = self.evidence_path / incident_id / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # In production, this would use tools like:
            # - WinPmem (Windows)
            # - LiME (Linux)
            # - osxpmem (macOS)
            
            # Placeholder for actual memory acquisition
            evidence = Evidence(
                evidence_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.MEMORY_DUMP,
                source=target_host,
                filename=filename,
                hash_md5="",
                hash_sha256="",
                size_bytes=0,
                collected_at=datetime.now(),
                collected_by="automated_collection",
                chain_of_custody=[{
                    "action": "collected",
                    "timestamp": datetime.now().isoformat(),
                    "actor": "system"
                }]
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Memory collection failed: {e}")
            return None
    
    async def collect_process_list(
        self,
        target_host: str,
        incident_id: str
    ) -> Optional[Evidence]:
        """Collect running processes from target host"""
        self.logger.info(f"Collecting process list from {target_host}")
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"processes_{target_host}_{timestamp}.json"
            filepath = self.evidence_path / incident_id / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # Collect local processes for demo
            if target_host == "localhost" or target_host == "127.0.0.1":
                processes = []
                
                try:
                    result = subprocess.run(
                        ["ps", "aux"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    lines = result.stdout.strip().split('\n')
                    headers = lines[0].split()
                    
                    for line in lines[1:]:
                        parts = line.split(None, len(headers) - 1)
                        if len(parts) >= len(headers):
                            processes.append({
                                "user": parts[0],
                                "pid": parts[1],
                                "cpu": parts[2],
                                "mem": parts[3],
                                "command": parts[-1] if len(parts) > 10 else ""
                            })
                except Exception:
                    pass
                
                # Save to file
                with open(filepath, 'w') as f:
                    json.dump(processes, f, indent=2)
                
                # Calculate hashes
                with open(filepath, 'rb') as f:
                    content = f.read()
                    md5_hash = hashlib.md5(content).hexdigest()
                    sha256_hash = hashlib.sha256(content).hexdigest()
                
                evidence = Evidence(
                    evidence_id=str(uuid.uuid4()),
                    evidence_type=EvidenceType.PROCESS_LIST,
                    source=target_host,
                    filename=filename,
                    hash_md5=md5_hash,
                    hash_sha256=sha256_hash,
                    size_bytes=len(content),
                    collected_at=datetime.now(),
                    collected_by="automated_collection",
                    chain_of_custody=[{
                        "action": "collected",
                        "timestamp": datetime.now().isoformat(),
                        "actor": "system"
                    }],
                    metadata={"process_count": len(processes)}
                )
                
                return evidence
            
        except Exception as e:
            self.logger.error(f"Process collection failed: {e}")
        
        return None
    
    async def collect_network_connections(
        self,
        target_host: str,
        incident_id: str
    ) -> Optional[Evidence]:
        """Collect active network connections"""
        self.logger.info(f"Collecting network connections from {target_host}")
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"netstat_{target_host}_{timestamp}.json"
            filepath = self.evidence_path / incident_id / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            connections = []
            
            if target_host == "localhost" or target_host == "127.0.0.1":
                try:
                    result = subprocess.run(
                        ["netstat", "-an"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    for line in result.stdout.strip().split('\n'):
                        if 'tcp' in line.lower() or 'udp' in line.lower():
                            parts = line.split()
                            if len(parts) >= 4:
                                connections.append({
                                    "protocol": parts[0],
                                    "local_address": parts[3] if len(parts) > 3 else "",
                                    "foreign_address": parts[4] if len(parts) > 4 else "",
                                    "state": parts[5] if len(parts) > 5 else ""
                                })
                except Exception:
                    pass
                
                with open(filepath, 'w') as f:
                    json.dump(connections, f, indent=2)
                
                with open(filepath, 'rb') as f:
                    content = f.read()
                    md5_hash = hashlib.md5(content).hexdigest()
                    sha256_hash = hashlib.sha256(content).hexdigest()
                
                evidence = Evidence(
                    evidence_id=str(uuid.uuid4()),
                    evidence_type=EvidenceType.NETWORK_CONNECTIONS,
                    source=target_host,
                    filename=filename,
                    hash_md5=md5_hash,
                    hash_sha256=sha256_hash,
                    size_bytes=len(content),
                    collected_at=datetime.now(),
                    collected_by="automated_collection",
                    chain_of_custody=[{
                        "action": "collected",
                        "timestamp": datetime.now().isoformat(),
                        "actor": "system"
                    }],
                    metadata={"connection_count": len(connections)}
                )
                
                return evidence
                
        except Exception as e:
            self.logger.error(f"Network connection collection failed: {e}")
        
        return None
    
    async def collect_log_files(
        self,
        target_host: str,
        incident_id: str,
        log_paths: List[str]
    ) -> List[Evidence]:
        """Collect specified log files"""
        self.logger.info(f"Collecting logs from {target_host}")
        
        collected = []
        
        for log_path in log_paths:
            try:
                if os.path.exists(log_path):
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    original_name = os.path.basename(log_path)
                    filename = f"log_{original_name}_{timestamp}"
                    
                    dest_path = self.evidence_path / incident_id / filename
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    shutil.copy2(log_path, dest_path)
                    
                    with open(dest_path, 'rb') as f:
                        content = f.read()
                        md5_hash = hashlib.md5(content).hexdigest()
                        sha256_hash = hashlib.sha256(content).hexdigest()
                    
                    evidence = Evidence(
                        evidence_id=str(uuid.uuid4()),
                        evidence_type=EvidenceType.LOG_FILE,
                        source=target_host,
                        filename=filename,
                        hash_md5=md5_hash,
                        hash_sha256=sha256_hash,
                        size_bytes=len(content),
                        collected_at=datetime.now(),
                        collected_by="automated_collection",
                        chain_of_custody=[{
                            "action": "collected",
                            "timestamp": datetime.now().isoformat(),
                            "actor": "system"
                        }],
                        metadata={"original_path": log_path}
                    )
                    
                    collected.append(evidence)
                    
            except Exception as e:
                self.logger.error(f"Failed to collect {log_path}: {e}")
        
        return collected
    
    async def quarantine_file(
        self,
        file_path: str,
        incident_id: str
    ) -> Optional[Evidence]:
        """Quarantine a malicious file"""
        self.logger.info(f"Quarantining file: {file_path}")
        
        try:
            if not os.path.exists(file_path):
                return None
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            original_name = os.path.basename(file_path)
            filename = f"quarantine_{original_name}_{timestamp}.zip"
            
            quarantine_path = self.evidence_path / incident_id / "quarantine"
            quarantine_path.mkdir(parents=True, exist_ok=True)
            
            # Calculate hashes before quarantine
            with open(file_path, 'rb') as f:
                content = f.read()
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
            
            # Create password-protected zip (in production)
            # For demo, just copy with .quarantine extension
            dest_path = quarantine_path / f"{original_name}.quarantine"
            shutil.copy2(file_path, dest_path)
            
            # Remove original
            os.remove(file_path)
            
            evidence = Evidence(
                evidence_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.MALWARE_SAMPLE,
                source="local",
                filename=filename,
                hash_md5=md5_hash,
                hash_sha256=sha256_hash,
                size_bytes=len(content),
                collected_at=datetime.now(),
                collected_by="automated_quarantine",
                chain_of_custody=[
                    {
                        "action": "quarantined",
                        "timestamp": datetime.now().isoformat(),
                        "actor": "system",
                        "original_path": file_path
                    }
                ]
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Quarantine failed: {e}")
            return None


class ContainmentEngine:
    """Automated containment actions"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.action_history: List[Dict[str, Any]] = []
    
    async def isolate_host(
        self,
        host: str,
        incident_id: str
    ) -> Dict[str, Any]:
        """Isolate host from network"""
        self.logger.info(f"Isolating host: {host}")
        
        result = {
            "action": ContainmentAction.ISOLATE_HOST.value,
            "target": host,
            "incident_id": incident_id,
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "details": {}
        }
        
        try:
            # In production, this would:
            # 1. Use EDR API to isolate endpoint
            # 2. Update firewall rules
            # 3. Disable switch port
            # 4. Update NAC policy
            
            # Placeholder for actual isolation
            result["success"] = True
            result["details"] = {
                "method": "edr_isolation",
                "rollback_available": True
            }
            
        except Exception as e:
            result["error"] = str(e)
        
        self.action_history.append(result)
        return result
    
    async def disable_user_account(
        self,
        username: str,
        domain: Optional[str],
        incident_id: str
    ) -> Dict[str, Any]:
        """Disable compromised user account"""
        self.logger.info(f"Disabling user: {username}")
        
        result = {
            "action": ContainmentAction.DISABLE_USER.value,
            "target": username,
            "domain": domain,
            "incident_id": incident_id,
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "details": {}
        }
        
        try:
            # In production, this would:
            # 1. Disable AD account
            # 2. Revoke OAuth tokens
            # 3. Terminate active sessions
            # 4. Reset MFA
            
            result["success"] = True
            result["details"] = {
                "method": "ad_disable",
                "sessions_terminated": 0,
                "tokens_revoked": 0
            }
            
        except Exception as e:
            result["error"] = str(e)
        
        self.action_history.append(result)
        return result
    
    async def block_ip(
        self,
        ip_address: str,
        incident_id: str,
        duration_hours: int = 24
    ) -> Dict[str, Any]:
        """Block malicious IP address"""
        self.logger.info(f"Blocking IP: {ip_address}")
        
        result = {
            "action": ContainmentAction.BLOCK_IP.value,
            "target": ip_address,
            "incident_id": incident_id,
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "details": {}
        }
        
        try:
            # In production, this would update:
            # 1. Firewall rules
            # 2. WAF blocklist
            # 3. IPS signatures
            # 4. DNS sinkhole
            
            result["success"] = True
            result["details"] = {
                "method": "firewall_block",
                "duration_hours": duration_hours,
                "expires_at": (datetime.now() + timedelta(hours=duration_hours)).isoformat()
            }
            
        except Exception as e:
            result["error"] = str(e)
        
        self.action_history.append(result)
        return result
    
    async def block_domain(
        self,
        domain: str,
        incident_id: str
    ) -> Dict[str, Any]:
        """Block malicious domain"""
        self.logger.info(f"Blocking domain: {domain}")
        
        result = {
            "action": ContainmentAction.BLOCK_DOMAIN.value,
            "target": domain,
            "incident_id": incident_id,
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "details": {}
        }
        
        try:
            # In production, this would:
            # 1. Add to DNS blocklist
            # 2. Update web proxy rules
            # 3. Update email gateway
            
            result["success"] = True
            result["details"] = {
                "method": "dns_sinkhole",
                "includes_subdomains": True
            }
            
        except Exception as e:
            result["error"] = str(e)
        
        self.action_history.append(result)
        return result
    
    async def kill_process(
        self,
        host: str,
        process_id: int,
        incident_id: str
    ) -> Dict[str, Any]:
        """Kill malicious process"""
        self.logger.info(f"Killing process {process_id} on {host}")
        
        result = {
            "action": ContainmentAction.KILL_PROCESS.value,
            "target": f"{host}:{process_id}",
            "incident_id": incident_id,
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "details": {}
        }
        
        try:
            if host == "localhost" or host == "127.0.0.1":
                # Kill local process
                subprocess.run(["kill", "-9", str(process_id)], check=True)
                result["success"] = True
            else:
                # In production, use EDR or remote execution
                result["success"] = True
            
            result["details"] = {"method": "signal_kill"}
            
        except Exception as e:
            result["error"] = str(e)
        
        self.action_history.append(result)
        return result
    
    async def rollback_action(
        self,
        action_id: str
    ) -> Dict[str, Any]:
        """Rollback a containment action"""
        # Find action in history
        for action in self.action_history:
            if action.get("id") == action_id:
                # Implement rollback based on action type
                return {
                    "success": True,
                    "action": "rollback",
                    "original_action": action
                }
        
        return {"success": False, "error": "Action not found"}


class IncidentTriager:
    """Automated incident triage and classification"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Severity scoring rules
        self.severity_indicators = {
            IncidentSeverity.CRITICAL: [
                "ransomware",
                "data_exfiltration",
                "domain_admin",
                "production_server",
                "pii_exposure",
                "active_attack"
            ],
            IncidentSeverity.HIGH: [
                "malware",
                "c2_communication",
                "credential_theft",
                "lateral_movement",
                "privileged_account"
            ],
            IncidentSeverity.MEDIUM: [
                "phishing",
                "suspicious_login",
                "policy_violation",
                "vulnerability_exploitation"
            ],
            IncidentSeverity.LOW: [
                "failed_login",
                "policy_warning",
                "reconnaissance"
            ]
        }
        
        # MITRE ATT&CK technique to type mapping
        self.mitre_mappings = {
            "T1486": IncidentType.RANSOMWARE,
            "T1566": IncidentType.PHISHING,
            "T1027": IncidentType.MALWARE,
            "T1078": IncidentType.UNAUTHORIZED_ACCESS,
            "T1071": IncidentType.C2_COMMUNICATION,
            "T1048": IncidentType.DATA_EXFILTRATION,
            "T1110": IncidentType.CREDENTIAL_THEFT,
            "T1021": IncidentType.LATERAL_MOVEMENT,
            "T1068": IncidentType.PRIVILEGE_ESCALATION
        }
    
    def classify_incident(
        self,
        alert_data: Dict[str, Any]
    ) -> Tuple[IncidentType, IncidentSeverity]:
        """Classify incident type and severity from alert data"""
        # Extract indicators
        description = alert_data.get("description", "").lower()
        tags = alert_data.get("tags", [])
        mitre_ids = alert_data.get("mitre_techniques", [])
        
        # Determine type from MITRE techniques
        incident_type = IncidentType.MALWARE  # Default
        for mitre_id in mitre_ids:
            if mitre_id in self.mitre_mappings:
                incident_type = self.mitre_mappings[mitre_id]
                break
        
        # Determine severity
        severity = IncidentSeverity.MEDIUM  # Default
        
        for sev, indicators in self.severity_indicators.items():
            for indicator in indicators:
                if indicator in description or indicator in tags:
                    severity = sev
                    break
        
        return incident_type, severity
    
    def enrich_incident(
        self,
        incident: Incident
    ) -> Incident:
        """Enrich incident with additional context"""
        # Add related MITRE techniques based on type
        type_mitre_mapping = {
            IncidentType.RANSOMWARE: ["T1486", "T1490", "T1489"],
            IncidentType.MALWARE: ["T1059", "T1027", "T1055"],
            IncidentType.PHISHING: ["T1566", "T1204"],
            IncidentType.C2_COMMUNICATION: ["T1071", "T1095"],
            IncidentType.DATA_EXFILTRATION: ["T1048", "T1041"],
            IncidentType.CREDENTIAL_THEFT: ["T1003", "T1110"],
            IncidentType.LATERAL_MOVEMENT: ["T1021", "T1076"]
        }
        
        if incident.incident_type in type_mitre_mapping:
            incident.mitre_techniques.extend(
                type_mitre_mapping[incident.incident_type]
            )
            incident.mitre_techniques = list(set(incident.mitre_techniques))
        
        return incident
    
    def calculate_priority_score(
        self,
        incident: Incident
    ) -> int:
        """Calculate priority score for incident queue ordering"""
        base_scores = {
            IncidentSeverity.CRITICAL: 100,
            IncidentSeverity.HIGH: 75,
            IncidentSeverity.MEDIUM: 50,
            IncidentSeverity.LOW: 25,
            IncidentSeverity.INFORMATIONAL: 10
        }
        
        score = base_scores.get(incident.severity, 50)
        
        # Adjust based on factors
        if len(incident.affected_assets) > 5:
            score += 15
        
        if incident.incident_type in [IncidentType.RANSOMWARE, IncidentType.APT]:
            score += 20
        
        # Escalate if not assigned
        if not incident.assigned_to:
            age_hours = (datetime.now() - incident.created_at).total_seconds() / 3600
            if age_hours > 1:
                score += int(age_hours * 5)
        
        return min(score, 100)


class PlaybookExecutor:
    """Execute incident response playbooks"""
    
    def __init__(
        self,
        evidence_collector: EvidenceCollector,
        containment_engine: ContainmentEngine
    ):
        self.logger = logging.getLogger(__name__)
        self.evidence_collector = evidence_collector
        self.containment_engine = containment_engine
        self.execution_history: List[Dict[str, Any]] = []
    
    async def execute_playbook(
        self,
        playbook: Playbook,
        incident: Incident
    ) -> Dict[str, Any]:
        """Execute playbook for incident"""
        self.logger.info(f"Executing playbook {playbook.name} for incident {incident.incident_id}")
        
        execution_result = {
            "playbook_id": playbook.playbook_id,
            "incident_id": incident.incident_id,
            "started_at": datetime.now().isoformat(),
            "steps": [],
            "success": True
        }
        
        for step in playbook.steps:
            step_result = await self._execute_step(step, incident)
            execution_result["steps"].append(step_result)
            
            if not step_result["success"]:
                if step.on_failure == "abort":
                    execution_result["success"] = False
                    break
        
        execution_result["completed_at"] = datetime.now().isoformat()
        self.execution_history.append(execution_result)
        
        return execution_result
    
    async def _execute_step(
        self,
        step: PlaybookStep,
        incident: Incident
    ) -> Dict[str, Any]:
        """Execute a single playbook step"""
        result = {
            "step_id": step.step_id,
            "name": step.name,
            "started_at": datetime.now().isoformat(),
            "success": False,
            "output": {}
        }
        
        try:
            if step.action_type == "collect_evidence":
                evidence = await self._collect_evidence(step.parameters, incident)
                result["output"]["evidence"] = evidence
                result["success"] = True
                
            elif step.action_type == "isolate_host":
                host = step.parameters.get("host")
                if host:
                    action_result = await self.containment_engine.isolate_host(
                        host, incident.incident_id
                    )
                    result["output"] = action_result
                    result["success"] = action_result["success"]
                    
            elif step.action_type == "block_ip":
                ip = step.parameters.get("ip")
                if ip:
                    action_result = await self.containment_engine.block_ip(
                        ip, incident.incident_id
                    )
                    result["output"] = action_result
                    result["success"] = action_result["success"]
                    
            elif step.action_type == "notify":
                result["success"] = await self._send_notification(
                    step.parameters, incident
                )
                
            elif step.action_type == "wait":
                seconds = step.parameters.get("seconds", 60)
                await asyncio.sleep(seconds)
                result["success"] = True
                
        except Exception as e:
            result["error"] = str(e)
        
        result["completed_at"] = datetime.now().isoformat()
        return result
    
    async def _collect_evidence(
        self,
        parameters: Dict[str, Any],
        incident: Incident
    ) -> List[str]:
        """Collect evidence based on parameters"""
        evidence_ids = []
        
        evidence_types = parameters.get("types", [])
        hosts = parameters.get("hosts", incident.affected_assets)
        
        for host in hosts:
            if "process_list" in evidence_types:
                evidence = await self.evidence_collector.collect_process_list(
                    host, incident.incident_id
                )
                if evidence:
                    incident.evidence.append(evidence)
                    evidence_ids.append(evidence.evidence_id)
            
            if "network_connections" in evidence_types:
                evidence = await self.evidence_collector.collect_network_connections(
                    host, incident.incident_id
                )
                if evidence:
                    incident.evidence.append(evidence)
                    evidence_ids.append(evidence.evidence_id)
        
        return evidence_ids
    
    async def _send_notification(
        self,
        parameters: Dict[str, Any],
        incident: Incident
    ) -> bool:
        """Send notification about incident"""
        # Placeholder for notification integration
        # In production: email, Slack, PagerDuty, etc.
        self.logger.info(
            f"Notification: {parameters.get('message', 'Incident update')} "
            f"for {incident.incident_id}"
        )
        return True


class TimelineBuilder:
    """Build incident timeline from evidence"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def build_timeline(
        self,
        incident: Incident
    ) -> List[TimelineEvent]:
        """Build timeline from incident data"""
        events = list(incident.timeline)
        
        # Add incident creation
        events.append(TimelineEvent(
            timestamp=incident.created_at,
            event_type="incident_created",
            source="system",
            description=f"Incident created: {incident.title}",
            indicators=[],
            evidence_ids=[],
            severity=incident.severity
        ))
        
        # Add IOC observations
        for ioc in incident.iocs:
            events.append(TimelineEvent(
                timestamp=ioc.first_seen,
                event_type="ioc_observed",
                source=ioc.source,
                description=f"IOC observed: {ioc.ioc_type} = {ioc.value}",
                indicators=[ioc.value],
                evidence_ids=[],
                severity=IncidentSeverity.MEDIUM
            ))
        
        # Add evidence collection
        for evidence in incident.evidence:
            events.append(TimelineEvent(
                timestamp=evidence.collected_at,
                event_type="evidence_collected",
                source=evidence.source,
                description=f"Evidence collected: {evidence.evidence_type.value}",
                indicators=[],
                evidence_ids=[evidence.evidence_id],
                severity=IncidentSeverity.INFORMATIONAL
            ))
        
        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)
        
        return events
    
    def export_timeline(
        self,
        events: List[TimelineEvent],
        format: str = "json"
    ) -> str:
        """Export timeline to specified format"""
        if format == "json":
            return json.dumps([
                {
                    "timestamp": e.timestamp.isoformat(),
                    "event_type": e.event_type,
                    "source": e.source,
                    "description": e.description,
                    "indicators": e.indicators,
                    "severity": e.severity.value
                }
                for e in events
            ], indent=2)
        
        return ""


class AdvancedIncidentResponse:
    """Main incident response automation engine"""
    
    def __init__(self, evidence_path: str = "/tmp/evidence"):
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.evidence_collector = EvidenceCollector(evidence_path)
        self.containment_engine = ContainmentEngine()
        self.triager = IncidentTriager()
        self.timeline_builder = TimelineBuilder()
        self.playbook_executor = PlaybookExecutor(
            self.evidence_collector,
            self.containment_engine
        )
        
        # Incident storage
        self.incidents: Dict[str, Incident] = {}
        self.playbooks: Dict[str, Playbook] = {}
        
        # Load default playbooks
        self._load_default_playbooks()
        
        # Statistics
        self.stats = {
            "incidents_created": 0,
            "incidents_resolved": 0,
            "evidence_collected": 0,
            "containment_actions": 0,
            "playbooks_executed": 0
        }
    
    def _load_default_playbooks(self):
        """Load default response playbooks"""
        # Malware response playbook
        malware_playbook = Playbook(
            playbook_id="pb-malware-001",
            name="Malware Response",
            description="Automated response to malware detection",
            incident_types=[IncidentType.MALWARE],
            severity_threshold=IncidentSeverity.MEDIUM,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Collect Evidence",
                    description="Collect process and network evidence",
                    action_type="collect_evidence",
                    parameters={
                        "types": ["process_list", "network_connections"]
                    },
                    conditions={}
                ),
                PlaybookStep(
                    step_id="step-2",
                    name="Isolate Host",
                    description="Isolate affected host",
                    action_type="isolate_host",
                    parameters={},
                    conditions={}
                ),
                PlaybookStep(
                    step_id="step-3",
                    name="Notify SOC",
                    description="Send notification to SOC team",
                    action_type="notify",
                    parameters={
                        "channel": "soc",
                        "message": "Malware incident - host isolated"
                    },
                    conditions={}
                )
            ],
            auto_execute=True
        )
        self.playbooks[malware_playbook.playbook_id] = malware_playbook
        
        # Ransomware response playbook
        ransomware_playbook = Playbook(
            playbook_id="pb-ransomware-001",
            name="Ransomware Response",
            description="Emergency response to ransomware",
            incident_types=[IncidentType.RANSOMWARE],
            severity_threshold=IncidentSeverity.CRITICAL,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Immediate Isolation",
                    description="Immediately isolate affected systems",
                    action_type="isolate_host",
                    parameters={},
                    conditions={},
                    on_failure="abort"
                ),
                PlaybookStep(
                    step_id="step-2",
                    name="Collect Memory",
                    description="Collect memory dump for analysis",
                    action_type="collect_evidence",
                    parameters={"types": ["memory_dump"]},
                    conditions={}
                ),
                PlaybookStep(
                    step_id="step-3",
                    name="Emergency Notification",
                    description="Notify executive team",
                    action_type="notify",
                    parameters={
                        "channel": "emergency",
                        "message": "RANSOMWARE DETECTED - IMMEDIATE ACTION REQUIRED"
                    },
                    conditions={}
                )
            ],
            auto_execute=True
        )
        self.playbooks[ransomware_playbook.playbook_id] = ransomware_playbook
    
    async def create_incident(
        self,
        title: str,
        description: str,
        alert_data: Dict[str, Any],
        affected_assets: List[str]
    ) -> Incident:
        """Create new incident from alert"""
        incident_type, severity = self.triager.classify_incident(alert_data)
        
        incident = Incident(
            incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
            title=title,
            description=description,
            incident_type=incident_type,
            severity=severity,
            status=IncidentStatus.NEW,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            detected_by=alert_data.get("source", "unknown"),
            assigned_to=None,
            affected_assets=affected_assets,
            iocs=[],
            timeline=[],
            evidence=[],
            containment_actions=[],
            notes=[]
        )
        
        # Enrich incident
        incident = self.triager.enrich_incident(incident)
        
        # Store incident
        self.incidents[incident.incident_id] = incident
        self.stats["incidents_created"] += 1
        
        # Auto-execute playbook if applicable
        await self._auto_execute_playbook(incident)
        
        return incident
    
    async def _auto_execute_playbook(self, incident: Incident):
        """Auto-execute matching playbook"""
        for playbook in self.playbooks.values():
            if (
                playbook.auto_execute and
                incident.incident_type in playbook.incident_types and
                self._severity_meets_threshold(
                    incident.severity,
                    playbook.severity_threshold
                )
            ):
                incident.status = IncidentStatus.CONTAINING
                await self.playbook_executor.execute_playbook(playbook, incident)
                self.stats["playbooks_executed"] += 1
                break
    
    def _severity_meets_threshold(
        self,
        severity: IncidentSeverity,
        threshold: IncidentSeverity
    ) -> bool:
        """Check if severity meets threshold"""
        severity_order = [
            IncidentSeverity.INFORMATIONAL,
            IncidentSeverity.LOW,
            IncidentSeverity.MEDIUM,
            IncidentSeverity.HIGH,
            IncidentSeverity.CRITICAL
        ]
        return severity_order.index(severity) >= severity_order.index(threshold)
    
    async def add_ioc(
        self,
        incident_id: str,
        ioc_type: str,
        value: str,
        source: str
    ) -> IOC:
        """Add IOC to incident"""
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident not found: {incident_id}")
        
        ioc = IOC(
            ioc_id=str(uuid.uuid4()),
            ioc_type=ioc_type,
            value=value,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            confidence=0.8,
            source=source,
            related_incidents=[incident_id]
        )
        
        incident.iocs.append(ioc)
        incident.updated_at = datetime.now()
        
        return ioc
    
    async def collect_evidence(
        self,
        incident_id: str,
        evidence_types: List[EvidenceType],
        target_host: str
    ) -> List[Evidence]:
        """Collect evidence for incident"""
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident not found: {incident_id}")
        
        collected = []
        
        for etype in evidence_types:
            evidence = None
            
            if etype == EvidenceType.PROCESS_LIST:
                evidence = await self.evidence_collector.collect_process_list(
                    target_host, incident_id
                )
            elif etype == EvidenceType.NETWORK_CONNECTIONS:
                evidence = await self.evidence_collector.collect_network_connections(
                    target_host, incident_id
                )
            elif etype == EvidenceType.MEMORY_DUMP:
                evidence = await self.evidence_collector.collect_memory_dump(
                    target_host, incident_id
                )
            
            if evidence:
                incident.evidence.append(evidence)
                collected.append(evidence)
                self.stats["evidence_collected"] += 1
        
        incident.updated_at = datetime.now()
        return collected
    
    async def execute_containment(
        self,
        incident_id: str,
        action: ContainmentAction,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute containment action"""
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident not found: {incident_id}")
        
        result = {}
        
        if action == ContainmentAction.ISOLATE_HOST:
            result = await self.containment_engine.isolate_host(
                parameters.get("host"),
                incident_id
            )
        elif action == ContainmentAction.BLOCK_IP:
            result = await self.containment_engine.block_ip(
                parameters.get("ip"),
                incident_id
            )
        elif action == ContainmentAction.DISABLE_USER:
            result = await self.containment_engine.disable_user_account(
                parameters.get("username"),
                parameters.get("domain"),
                incident_id
            )
        elif action == ContainmentAction.KILL_PROCESS:
            result = await self.containment_engine.kill_process(
                parameters.get("host"),
                parameters.get("pid"),
                incident_id
            )
        
        incident.containment_actions.append(result)
        incident.status = IncidentStatus.CONTAINING
        incident.updated_at = datetime.now()
        self.stats["containment_actions"] += 1
        
        return result
    
    def get_timeline(self, incident_id: str) -> List[TimelineEvent]:
        """Get incident timeline"""
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident not found: {incident_id}")
        
        return self.timeline_builder.build_timeline(incident)
    
    def close_incident(
        self,
        incident_id: str,
        resolution: str,
        false_positive: bool = False
    ):
        """Close incident"""
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident not found: {incident_id}")
        
        incident.status = (
            IncidentStatus.FALSE_POSITIVE if false_positive
            else IncidentStatus.CLOSED
        )
        incident.notes.append({
            "timestamp": datetime.now().isoformat(),
            "author": "system",
            "content": f"Incident closed: {resolution}"
        })
        incident.updated_at = datetime.now()
        self.stats["incidents_resolved"] += 1
    
    def generate_report(self, incident_id: str) -> Dict[str, Any]:
        """Generate incident report"""
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident not found: {incident_id}")
        
        timeline = self.get_timeline(incident_id)
        
        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "description": incident.description,
            "type": incident.incident_type.value,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "created_at": incident.created_at.isoformat(),
            "updated_at": incident.updated_at.isoformat(),
            "detected_by": incident.detected_by,
            "assigned_to": incident.assigned_to,
            "affected_assets": incident.affected_assets,
            "mitre_techniques": incident.mitre_techniques,
            "iocs": [
                {
                    "type": ioc.ioc_type,
                    "value": ioc.value,
                    "confidence": ioc.confidence
                }
                for ioc in incident.iocs
            ],
            "evidence_count": len(incident.evidence),
            "containment_actions_count": len(incident.containment_actions),
            "timeline_events": len(timeline),
            "notes": incident.notes
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get incident response statistics"""
        return {
            **self.stats,
            "active_incidents": sum(
                1 for i in self.incidents.values()
                if i.status not in [IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]
            ),
            "playbooks_loaded": len(self.playbooks)
        }


# Main execution
if __name__ == "__main__":
    import asyncio
    
    async def main():
        ir = AdvancedIncidentResponse()
        
        print("Incident Response Automation Engine")
        print("=" * 50)
        
        # Create test incident
        print("\nCreating test incident...")
        incident = await ir.create_incident(
            title="Malware Detected on Workstation",
            description="Antivirus detected suspicious executable",
            alert_data={
                "source": "edr",
                "tags": ["malware", "suspicious_process"],
                "mitre_techniques": ["T1059"]
            },
            affected_assets=["workstation-001"]
        )
        
        print(f"Created: {incident.incident_id}")
        print(f"Type: {incident.incident_type.value}")
        print(f"Severity: {incident.severity.value}")
        print(f"Status: {incident.status.value}")
        
        # Add IOC
        print("\nAdding IOC...")
        ioc = await ir.add_ioc(
            incident.incident_id,
            "hash_sha256",
            "a1b2c3d4e5f6...",
            "malware_analysis"
        )
        print(f"Added IOC: {ioc.ioc_type} = {ioc.value}")
        
        # Collect evidence
        print("\nCollecting evidence...")
        evidence = await ir.collect_evidence(
            incident.incident_id,
            [EvidenceType.PROCESS_LIST],
            "localhost"
        )
        print(f"Collected {len(evidence)} evidence items")
        
        # Generate report
        print("\nGenerating report...")
        report = ir.generate_report(incident.incident_id)
        print(f"Report generated with {report['timeline_events']} timeline events")
        
        # Print statistics
        print("\nStatistics:")
        stats = ir.get_statistics()
        for key, value in stats.items():
            print(f"  {key}: {value}")
    
    asyncio.run(main())
