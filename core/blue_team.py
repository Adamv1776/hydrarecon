#!/usr/bin/env python3
"""
HydraRecon Blue Team Detection Module
Defensive security monitoring, threat detection, and incident response.
"""

import asyncio
import json
import logging
import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Set
from datetime import datetime, timedelta
from enum import Enum
import subprocess


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    """Alert status"""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class EventType(Enum):
    """Security event types"""
    AUTHENTICATION = "authentication"
    PROCESS_CREATION = "process_creation"
    NETWORK_CONNECTION = "network_connection"
    FILE_OPERATION = "file_operation"
    REGISTRY_CHANGE = "registry_change"
    SERVICE_CHANGE = "service_change"
    SCHEDULED_TASK = "scheduled_task"
    POWERSHELL_EXECUTION = "powershell"
    WMI_ACTIVITY = "wmi"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class SecurityEvent:
    """Represents a security event"""
    event_id: str
    event_type: EventType
    timestamp: datetime
    source_host: str
    source_user: str
    target_host: str = ""
    target_user: str = ""
    process_name: str = ""
    process_commandline: str = ""
    parent_process: str = ""
    file_path: str = ""
    network_src_ip: str = ""
    network_dst_ip: str = ""
    network_dst_port: int = 0
    registry_key: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    matched_rules: List[str] = field(default_factory=list)


@dataclass
class DetectionRule:
    """Detection rule for security events"""
    rule_id: str
    name: str
    description: str
    severity: AlertSeverity
    event_types: List[EventType]
    mitre_techniques: List[str]
    detection_logic: Dict[str, Any]
    false_positive_notes: str = ""
    references: List[str] = field(default_factory=list)
    enabled: bool = True
    
    def matches(self, event: SecurityEvent) -> bool:
        """Check if event matches this rule"""
        if event.event_type not in self.event_types:
            return False
        
        logic = self.detection_logic
        
        # Process name matching
        if "process_name" in logic:
            pattern = logic["process_name"]
            if isinstance(pattern, list):
                if not any(re.search(p, event.process_name, re.I) for p in pattern):
                    return False
            elif not re.search(pattern, event.process_name, re.I):
                return False
        
        # Command line matching
        if "commandline_contains" in logic:
            patterns = logic["commandline_contains"]
            if isinstance(patterns, str):
                patterns = [patterns]
            if not any(p.lower() in event.process_commandline.lower() for p in patterns):
                return False
        
        if "commandline_regex" in logic:
            pattern = logic["commandline_regex"]
            if not re.search(pattern, event.process_commandline, re.I):
                return False
        
        # File path matching
        if "file_path_contains" in logic:
            patterns = logic["file_path_contains"]
            if isinstance(patterns, str):
                patterns = [patterns]
            if not any(p.lower() in event.file_path.lower() for p in patterns):
                return False
        
        # Network matching
        if "dst_port" in logic:
            ports = logic["dst_port"]
            if isinstance(ports, int):
                ports = [ports]
            if event.network_dst_port not in ports:
                return False
        
        # Parent process matching
        if "parent_process" in logic:
            pattern = logic["parent_process"]
            if not re.search(pattern, event.parent_process, re.I):
                return False
        
        return True


@dataclass
class Alert:
    """Security alert"""
    alert_id: str
    rule: DetectionRule
    event: SecurityEvent
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.NEW
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    assigned_to: str = ""
    notes: List[str] = field(default_factory=list)
    related_events: List[SecurityEvent] = field(default_factory=list)
    investigation_findings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IncidentCase:
    """Incident response case"""
    case_id: str
    title: str
    description: str
    severity: AlertSeverity
    status: str = "open"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    alerts: List[Alert] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    containment_actions: List[str] = field(default_factory=list)
    eradication_actions: List[str] = field(default_factory=list)
    recovery_actions: List[str] = field(default_factory=list)
    lessons_learned: str = ""
    iocs: List[Dict] = field(default_factory=list)


class SigmaRuleLoader:
    """Load and parse Sigma detection rules"""
    
    def __init__(self):
        self.logger = logging.getLogger("SigmaRuleLoader")
        self.rules: List[DetectionRule] = []
        self._load_builtin_rules()
    
    def _load_builtin_rules(self):
        """Load built-in detection rules"""
        
        # Mimikatz Detection
        self.rules.append(DetectionRule(
            rule_id="SIGMA-001",
            name="Mimikatz Command Line Execution",
            description="Detects Mimikatz execution via command line arguments",
            severity=AlertSeverity.CRITICAL,
            event_types=[EventType.PROCESS_CREATION],
            mitre_techniques=["T1003.001"],
            detection_logic={
                "commandline_contains": [
                    "sekurlsa::logonpasswords",
                    "sekurlsa::wdigest",
                    "lsadump::sam",
                    "lsadump::dcsync",
                    "kerberos::golden"
                ]
            }
        ))
        
        # PowerShell Encoded Command
        self.rules.append(DetectionRule(
            rule_id="SIGMA-002",
            name="PowerShell Encoded Command Execution",
            description="Detects encoded PowerShell commands often used in attacks",
            severity=AlertSeverity.HIGH,
            event_types=[EventType.POWERSHELL_EXECUTION, EventType.PROCESS_CREATION],
            mitre_techniques=["T1059.001", "T1027"],
            detection_logic={
                "process_name": ["powershell", "pwsh"],
                "commandline_contains": ["-enc", "-encodedcommand", "-e "]
            }
        ))
        
        # PsExec Remote Execution
        self.rules.append(DetectionRule(
            rule_id="SIGMA-003",
            name="PsExec Remote Execution",
            description="Detects PsExec or similar tools for remote execution",
            severity=AlertSeverity.HIGH,
            event_types=[EventType.PROCESS_CREATION, EventType.LATERAL_MOVEMENT],
            mitre_techniques=["T1021.002", "T1569.002"],
            detection_logic={
                "process_name": ["psexec", "psexesvc", "paexec"],
            }
        ))
        
        # Scheduled Task Creation
        self.rules.append(DetectionRule(
            rule_id="SIGMA-004",
            name="Suspicious Scheduled Task Creation",
            description="Detects creation of scheduled tasks for persistence",
            severity=AlertSeverity.MEDIUM,
            event_types=[EventType.SCHEDULED_TASK, EventType.PROCESS_CREATION],
            mitre_techniques=["T1053.005"],
            detection_logic={
                "process_name": ["schtasks"],
                "commandline_contains": ["/create"]
            }
        ))
        
        # LSASS Memory Access
        self.rules.append(DetectionRule(
            rule_id="SIGMA-005",
            name="LSASS Memory Access",
            description="Detects attempts to access LSASS process memory",
            severity=AlertSeverity.CRITICAL,
            event_types=[EventType.PROCESS_CREATION],
            mitre_techniques=["T1003.001"],
            detection_logic={
                "process_name": ["procdump", "rundll32"],
                "commandline_contains": ["lsass", "comsvcs.dll", "MiniDump"]
            }
        ))
        
        # Suspicious Outbound Connections
        self.rules.append(DetectionRule(
            rule_id="SIGMA-006",
            name="Suspicious Outbound Connection",
            description="Detects connections to suspicious ports",
            severity=AlertSeverity.MEDIUM,
            event_types=[EventType.NETWORK_CONNECTION],
            mitre_techniques=["T1571"],
            detection_logic={
                "dst_port": [4444, 5555, 6666, 8080, 9001, 1337]
            }
        ))
        
        # Registry Run Key Modification
        self.rules.append(DetectionRule(
            rule_id="SIGMA-007",
            name="Registry Run Key Persistence",
            description="Detects modifications to registry run keys",
            severity=AlertSeverity.MEDIUM,
            event_types=[EventType.REGISTRY_CHANGE, EventType.PROCESS_CREATION],
            mitre_techniques=["T1547.001"],
            detection_logic={
                "process_name": ["reg"],
                "commandline_contains": ["CurrentVersion\\Run", "CurrentVersion\\RunOnce"]
            }
        ))
        
        # WMI Execution
        self.rules.append(DetectionRule(
            rule_id="SIGMA-008",
            name="WMI Command Execution",
            description="Detects WMI-based command execution",
            severity=AlertSeverity.MEDIUM,
            event_types=[EventType.WMI_ACTIVITY, EventType.PROCESS_CREATION],
            mitre_techniques=["T1047"],
            detection_logic={
                "process_name": ["wmic", "wmiprvse"],
                "commandline_contains": ["process call create"]
            }
        ))
        
        # Certutil Download
        self.rules.append(DetectionRule(
            rule_id="SIGMA-009",
            name="Certutil Download",
            description="Detects use of certutil for downloading files",
            severity=AlertSeverity.HIGH,
            event_types=[EventType.PROCESS_CREATION],
            mitre_techniques=["T1105"],
            detection_logic={
                "process_name": ["certutil"],
                "commandline_contains": ["-urlcache", "-split", "http"]
            }
        ))
        
        # Suspicious Service Installation
        self.rules.append(DetectionRule(
            rule_id="SIGMA-010",
            name="Suspicious Service Installation",
            description="Detects installation of suspicious services",
            severity=AlertSeverity.HIGH,
            event_types=[EventType.SERVICE_CHANGE, EventType.PROCESS_CREATION],
            mitre_techniques=["T1543.003"],
            detection_logic={
                "process_name": ["sc"],
                "commandline_contains": ["create", "config"]
            }
        ))
    
    def load_sigma_file(self, filepath: str) -> Optional[DetectionRule]:
        """Load a Sigma rule from YAML file"""
        try:
            import yaml
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
            
            # Parse Sigma format to DetectionRule
            # Simplified - real implementation would be more comprehensive
            rule = DetectionRule(
                rule_id=data.get('id', os.path.basename(filepath)),
                name=data.get('title', 'Unknown'),
                description=data.get('description', ''),
                severity=AlertSeverity[data.get('level', 'medium').upper()],
                event_types=[EventType.PROCESS_CREATION],  # Simplified
                mitre_techniques=data.get('tags', []),
                detection_logic=data.get('detection', {})
            )
            
            self.rules.append(rule)
            return rule
            
        except Exception as e:
            self.logger.error(f"Failed to load Sigma rule: {e}")
            return None
    
    def get_rules(self, enabled_only: bool = True) -> List[DetectionRule]:
        """Get all detection rules"""
        if enabled_only:
            return [r for r in self.rules if r.enabled]
        return self.rules
    
    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Get rule by ID"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None


class ThreatDetectionEngine:
    """Main threat detection engine"""
    
    def __init__(self):
        self.logger = logging.getLogger("ThreatDetectionEngine")
        self.rule_loader = SigmaRuleLoader()
        self.alerts: List[Alert] = []
        self.events_processed = 0
        self.event_buffer: List[SecurityEvent] = []
        self.correlation_window = timedelta(minutes=5)
    
    def analyze_event(self, event: SecurityEvent) -> List[Alert]:
        """Analyze a security event against all rules"""
        new_alerts = []
        
        for rule in self.rule_loader.get_rules():
            if rule.matches(event):
                event.matched_rules.append(rule.rule_id)
                
                alert = Alert(
                    alert_id=hashlib.md5(
                        f"{rule.rule_id}_{event.event_id}_{datetime.now()}".encode()
                    ).hexdigest()[:12],
                    rule=rule,
                    event=event,
                    severity=rule.severity
                )
                
                new_alerts.append(alert)
                self.alerts.append(alert)
        
        self.events_processed += 1
        self.event_buffer.append(event)
        
        # Keep buffer limited
        if len(self.event_buffer) > 1000:
            self.event_buffer = self.event_buffer[-500:]
        
        return new_alerts
    
    def analyze_events(self, events: List[SecurityEvent],
                      callback: Optional[Callable] = None) -> List[Alert]:
        """Analyze multiple events"""
        all_alerts = []
        total = len(events)
        
        for i, event in enumerate(events):
            alerts = self.analyze_event(event)
            all_alerts.extend(alerts)
            
            if callback and i % 10 == 0:
                callback(f"Analyzed {i+1}/{total} events", (i+1) / total * 100)
        
        return all_alerts
    
    def correlate_alerts(self) -> List[Dict[str, Any]]:
        """Correlate related alerts"""
        correlations = []
        
        # Group alerts by source host
        by_host = {}
        for alert in self.alerts:
            host = alert.event.source_host
            if host not in by_host:
                by_host[host] = []
            by_host[host].append(alert)
        
        # Find attack chains
        for host, host_alerts in by_host.items():
            if len(host_alerts) >= 3:
                # Check for attack progression
                techniques = set()
                for alert in host_alerts:
                    techniques.update(alert.rule.mitre_techniques)
                
                if len(techniques) >= 2:
                    correlations.append({
                        "type": "attack_chain",
                        "host": host,
                        "alert_count": len(host_alerts),
                        "techniques": list(techniques),
                        "alerts": [a.alert_id for a in host_alerts]
                    })
        
        return correlations
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        stats = {
            "total_alerts": len(self.alerts),
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "by_status": {
                "new": 0,
                "investigating": 0,
                "confirmed": 0,
                "false_positive": 0,
                "resolved": 0
            },
            "events_processed": self.events_processed,
            "top_rules": {}
        }
        
        rule_counts = {}
        for alert in self.alerts:
            stats["by_severity"][alert.severity.value] += 1
            stats["by_status"][alert.status.value] += 1
            
            rule_id = alert.rule.rule_id
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
        
        # Top 5 rules
        sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        stats["top_rules"] = dict(sorted_rules)
        
        return stats
    
    def update_alert_status(self, alert_id: str, status: AlertStatus, 
                           notes: str = "") -> bool:
        """Update alert status"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.status = status
                alert.updated_at = datetime.now()
                if notes:
                    alert.notes.append(f"{datetime.now()}: {notes}")
                return True
        return False


class LogParser:
    """Parse various log formats"""
    
    def __init__(self):
        self.logger = logging.getLogger("LogParser")
    
    def parse_windows_event(self, event_data: Dict) -> SecurityEvent:
        """Parse Windows Security Event"""
        event_id = str(event_data.get('EventID', ''))
        
        # Map common Windows event IDs
        event_type_map = {
            '4624': EventType.AUTHENTICATION,  # Logon
            '4625': EventType.AUTHENTICATION,  # Failed logon
            '4688': EventType.PROCESS_CREATION,  # Process creation
            '4657': EventType.REGISTRY_CHANGE,  # Registry value modified
            '4697': EventType.SERVICE_CHANGE,  # Service installed
            '5140': EventType.FILE_OPERATION,  # Network share accessed
        }
        
        return SecurityEvent(
            event_id=event_data.get('EventRecordID', event_id),
            event_type=event_type_map.get(event_id, EventType.PROCESS_CREATION),
            timestamp=datetime.fromisoformat(event_data.get('TimeCreated', datetime.now().isoformat())),
            source_host=event_data.get('Computer', ''),
            source_user=event_data.get('SubjectUserName', ''),
            target_host=event_data.get('TargetServerName', ''),
            target_user=event_data.get('TargetUserName', ''),
            process_name=event_data.get('NewProcessName', ''),
            process_commandline=event_data.get('CommandLine', ''),
            parent_process=event_data.get('ParentProcessName', ''),
            raw_data=event_data
        )
    
    def parse_syslog(self, line: str) -> Optional[SecurityEvent]:
        """Parse syslog format"""
        try:
            # Basic syslog pattern
            pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s+(.+)'
            match = re.match(pattern, line)
            
            if match:
                timestamp_str, host, process, message = match.groups()
                
                return SecurityEvent(
                    event_id=hashlib.md5(line.encode()).hexdigest()[:12],
                    event_type=EventType.PROCESS_CREATION,
                    timestamp=datetime.now(),  # Would parse timestamp_str
                    source_host=host,
                    source_user="",
                    process_name=process,
                    process_commandline=message,
                    raw_data={"raw_line": line}
                )
        except Exception as e:
            self.logger.debug(f"Failed to parse syslog: {e}")
        
        return None
    
    def parse_json_log(self, json_str: str) -> Optional[SecurityEvent]:
        """Parse JSON formatted log"""
        try:
            data = json.loads(json_str)
            
            return SecurityEvent(
                event_id=data.get('id', hashlib.md5(json_str.encode()).hexdigest()[:12]),
                event_type=EventType[data.get('event_type', 'PROCESS_CREATION').upper()],
                timestamp=datetime.fromisoformat(data.get('timestamp', datetime.now().isoformat())),
                source_host=data.get('source_host', data.get('hostname', '')),
                source_user=data.get('user', data.get('username', '')),
                process_name=data.get('process', data.get('process_name', '')),
                process_commandline=data.get('commandline', data.get('command', '')),
                network_dst_ip=data.get('dest_ip', ''),
                network_dst_port=data.get('dest_port', 0),
                raw_data=data
            )
        except Exception as e:
            self.logger.debug(f"Failed to parse JSON log: {e}")
        
        return None


class IncidentResponseManager:
    """Manage incident response cases"""
    
    def __init__(self, detection_engine: ThreatDetectionEngine):
        self.logger = logging.getLogger("IncidentResponseManager")
        self.detection_engine = detection_engine
        self.cases: List[IncidentCase] = []
    
    def create_case(self, title: str, description: str, 
                   severity: AlertSeverity,
                   alert_ids: List[str] = None) -> IncidentCase:
        """Create a new incident case"""
        case_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{len(self.cases)+1:04d}"
        
        case = IncidentCase(
            case_id=case_id,
            title=title,
            description=description,
            severity=severity
        )
        
        # Link alerts
        if alert_ids:
            for alert_id in alert_ids:
                for alert in self.detection_engine.alerts:
                    if alert.alert_id == alert_id:
                        case.alerts.append(alert)
                        if alert.event.source_host not in case.affected_systems:
                            case.affected_systems.append(alert.event.source_host)
                        if alert.event.source_user and alert.event.source_user not in case.affected_users:
                            case.affected_users.append(alert.event.source_user)
        
        case.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "Case created",
            "details": description
        })
        
        self.cases.append(case)
        return case
    
    def add_containment_action(self, case_id: str, action: str) -> bool:
        """Add containment action to case"""
        case = self.get_case(case_id)
        if case:
            case.containment_actions.append(action)
            case.timeline.append({
                "timestamp": datetime.now().isoformat(),
                "action": "Containment action added",
                "details": action
            })
            case.updated_at = datetime.now()
            return True
        return False
    
    def add_ioc(self, case_id: str, ioc_type: str, value: str, 
               description: str = "") -> bool:
        """Add indicator of compromise to case"""
        case = self.get_case(case_id)
        if case:
            case.iocs.append({
                "type": ioc_type,
                "value": value,
                "description": description,
                "added_at": datetime.now().isoformat()
            })
            case.updated_at = datetime.now()
            return True
        return False
    
    def update_case_status(self, case_id: str, status: str) -> bool:
        """Update case status"""
        case = self.get_case(case_id)
        if case:
            old_status = case.status
            case.status = status
            case.updated_at = datetime.now()
            case.timeline.append({
                "timestamp": datetime.now().isoformat(),
                "action": "Status changed",
                "details": f"{old_status} -> {status}"
            })
            return True
        return False
    
    def get_case(self, case_id: str) -> Optional[IncidentCase]:
        """Get case by ID"""
        for case in self.cases:
            if case.case_id == case_id:
                return case
        return None
    
    def list_cases(self, status: str = None) -> List[Dict[str, Any]]:
        """List all cases"""
        cases = self.cases
        if status:
            cases = [c for c in cases if c.status == status]
        
        return [
            {
                "case_id": c.case_id,
                "title": c.title,
                "severity": c.severity.value,
                "status": c.status,
                "created_at": c.created_at.isoformat(),
                "alert_count": len(c.alerts),
                "affected_systems": len(c.affected_systems)
            }
            for c in cases
        ]
    
    def generate_case_report(self, case_id: str) -> Dict[str, Any]:
        """Generate comprehensive case report"""
        case = self.get_case(case_id)
        if not case:
            return {}
        
        return {
            "case_info": {
                "case_id": case.case_id,
                "title": case.title,
                "description": case.description,
                "severity": case.severity.value,
                "status": case.status,
                "created_at": case.created_at.isoformat(),
                "updated_at": case.updated_at.isoformat() if case.updated_at else None
            },
            "scope": {
                "affected_systems": case.affected_systems,
                "affected_users": case.affected_users
            },
            "timeline": case.timeline,
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "rule": a.rule.name,
                    "severity": a.severity.value,
                    "event_type": a.event.event_type.value,
                    "timestamp": a.created_at.isoformat()
                }
                for a in case.alerts
            ],
            "response": {
                "containment_actions": case.containment_actions,
                "eradication_actions": case.eradication_actions,
                "recovery_actions": case.recovery_actions
            },
            "indicators_of_compromise": case.iocs,
            "lessons_learned": case.lessons_learned
        }


class BlueTeamEngine:
    """Main Blue Team engine"""
    
    def __init__(self):
        self.logger = logging.getLogger("BlueTeamEngine")
        self.detection_engine = ThreatDetectionEngine()
        self.log_parser = LogParser()
        self.incident_manager = IncidentResponseManager(self.detection_engine)
        self.monitoring_active = False
    
    def analyze_log_file(self, filepath: str, 
                        callback: Optional[Callable] = None) -> List[Alert]:
        """Analyze a log file"""
        events = []
        
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                
                # Try JSON first
                event = self.log_parser.parse_json_log(line)
                if not event:
                    # Try syslog
                    event = self.log_parser.parse_syslog(line)
                
                if event:
                    events.append(event)
                
                if callback and i % 100 == 0:
                    callback(f"Parsed {i+1}/{len(lines)} lines", 
                            (i+1) / len(lines) * 50)
            
            # Analyze events
            alerts = self.detection_engine.analyze_events(events, callback)
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to analyze log file: {e}")
            return []
    
    def analyze_windows_events(self, events: List[Dict], 
                              callback: Optional[Callable] = None) -> List[Alert]:
        """Analyze Windows Security Events"""
        parsed_events = []
        
        for i, event_data in enumerate(events):
            event = self.log_parser.parse_windows_event(event_data)
            parsed_events.append(event)
            
            if callback and i % 10 == 0:
                callback(f"Parsed {i+1}/{len(events)} events", 
                        (i+1) / len(events) * 50)
        
        return self.detection_engine.analyze_events(parsed_events, callback)
    
    def get_detection_rules(self) -> List[Dict[str, Any]]:
        """Get all detection rules"""
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity.value,
                "mitre_techniques": r.mitre_techniques,
                "enabled": r.enabled
            }
            for r in self.detection_engine.rule_loader.get_rules(enabled_only=False)
        ]
    
    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a detection rule"""
        rule = self.detection_engine.rule_loader.get_rule(rule_id)
        if rule:
            rule.enabled = enabled
            return True
        return False
    
    def get_alerts(self, severity: str = None, 
                  status: str = None) -> List[Dict[str, Any]]:
        """Get alerts with optional filtering"""
        alerts = self.detection_engine.alerts
        
        if severity:
            alerts = [a for a in alerts if a.severity.value == severity]
        if status:
            alerts = [a for a in alerts if a.status.value == status]
        
        return [
            {
                "alert_id": a.alert_id,
                "rule_name": a.rule.name,
                "severity": a.severity.value,
                "status": a.status.value,
                "source_host": a.event.source_host,
                "event_type": a.event.event_type.value,
                "created_at": a.created_at.isoformat(),
                "mitre_techniques": a.rule.mitre_techniques
            }
            for a in alerts
        ]
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get data for dashboard display"""
        stats = self.detection_engine.get_alert_statistics()
        correlations = self.detection_engine.correlate_alerts()
        
        return {
            "statistics": stats,
            "correlations": correlations,
            "recent_alerts": self.get_alerts()[:10],
            "active_cases": len([c for c in self.incident_manager.cases if c.status != "closed"])
        }
    
    def export_alerts(self, format: str = "json") -> str:
        """Export all alerts"""
        alerts_data = self.get_alerts()
        
        if format == "json":
            return json.dumps(alerts_data, indent=2)
        
        return ""
