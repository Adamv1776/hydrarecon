#!/usr/bin/env python3
"""
HydraRecon Threat Hunting Automation Module
████████████████████████████████████████████████████████████████████████████████
█  ENTERPRISE THREAT HUNTING - Automated Hypothesis Testing, Behavioral        █
█  Analytics, Anomaly Detection, Hunt Queries & Threat Intelligence Fusion     █
████████████████████████████████████████████████████████████████████████████████
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid


class HuntStatus(Enum):
    """Hunt operation status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PAUSED = "paused"
    FAILED = "failed"


class HuntType(Enum):
    """Types of threat hunts"""
    HYPOTHESIS_DRIVEN = "hypothesis_driven"
    IOC_BASED = "ioc_based"
    BEHAVIORAL = "behavioral"
    ANOMALY_DETECTION = "anomaly_detection"
    TTP_BASED = "ttp_based"


class ThreatCategory(Enum):
    """Threat categories for hunting"""
    APT = "apt"
    RANSOMWARE = "ransomware"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    COMMAND_AND_CONTROL = "command_and_control"
    INSIDER_THREAT = "insider_threat"


class SeverityLevel(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Hypothesis:
    """Threat hunting hypothesis"""
    hypothesis_id: str
    title: str
    description: str
    category: ThreatCategory
    mitre_techniques: List[str]
    data_sources: List[str]
    queries: List[Dict[str, Any]]
    detection_logic: str
    false_positive_guidance: str
    priority: int = 5


@dataclass
class HuntResult:
    """Result from a hunting operation"""
    result_id: str
    hunt_id: str
    hypothesis_id: str
    timestamp: datetime
    severity: SeverityLevel
    title: str
    description: str
    indicators: List[Dict[str, Any]]
    affected_assets: List[str]
    evidence: Dict[str, Any]
    mitre_techniques: List[str]
    confidence: float
    recommended_actions: List[str]


@dataclass
class Hunt:
    """Threat hunt operation"""
    hunt_id: str
    name: str
    description: str
    hunt_type: HuntType
    hypotheses: List[Hypothesis]
    status: HuntStatus
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_by: str
    results: List[HuntResult]
    data_sources: List[str]
    scope: Dict[str, Any]


@dataclass
class BehaviorBaseline:
    """Behavioral baseline for anomaly detection"""
    entity_type: str  # user, host, process, network
    entity_id: str
    metrics: Dict[str, List[float]]
    statistics: Dict[str, Dict[str, float]]
    last_updated: datetime
    sample_count: int


@dataclass
class Anomaly:
    """Detected anomaly"""
    anomaly_id: str
    entity_type: str
    entity_id: str
    anomaly_type: str
    metric_name: str
    expected_value: float
    actual_value: float
    deviation_score: float
    timestamp: datetime
    context: Dict[str, Any]


class HypothesisLibrary:
    """Library of hunting hypotheses"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.hypotheses: Dict[str, Hypothesis] = {}
        self._load_default_hypotheses()
    
    def _load_default_hypotheses(self):
        """Load default hunting hypotheses"""
        
        # Lateral Movement Detection
        self.add_hypothesis(Hypothesis(
            hypothesis_id="hyp-lat-001",
            title="Unusual RDP Connections",
            description="Detect RDP connections from unusual sources or to unusual destinations",
            category=ThreatCategory.LATERAL_MOVEMENT,
            mitre_techniques=["T1021.001"],
            data_sources=["network_traffic", "windows_events"],
            queries=[
                {
                    "type": "sigma",
                    "query": """
                        logsource:
                            product: windows
                            service: security
                        detection:
                            selection:
                                EventID: 4624
                                LogonType: 10
                            condition: selection
                    """
                }
            ],
            detection_logic="Flag RDP connections from non-standard workstations to sensitive servers",
            false_positive_guidance="IT admin activities, remote support sessions",
            priority=3
        ))
        
        # Credential Dumping
        self.add_hypothesis(Hypothesis(
            hypothesis_id="hyp-cred-001",
            title="LSASS Memory Access",
            description="Detect processes accessing LSASS memory for credential theft",
            category=ThreatCategory.CREDENTIAL_ACCESS,
            mitre_techniques=["T1003.001"],
            data_sources=["sysmon", "edr"],
            queries=[
                {
                    "type": "sysmon",
                    "query": "EventID=10 AND TargetImage CONTAINS 'lsass.exe'"
                }
            ],
            detection_logic="Alert on non-standard processes accessing LSASS memory",
            false_positive_guidance="Security tools, AV products may legitimately access LSASS",
            priority=1
        ))
        
        # Data Exfiltration
        self.add_hypothesis(Hypothesis(
            hypothesis_id="hyp-exfil-001",
            title="Large DNS TXT Responses",
            description="Detect potential data exfiltration via DNS tunneling",
            category=ThreatCategory.DATA_EXFILTRATION,
            mitre_techniques=["T1048.003"],
            data_sources=["dns_logs", "network_traffic"],
            queries=[
                {
                    "type": "dns",
                    "query": "response_size > 512 AND record_type = 'TXT'"
                }
            ],
            detection_logic="Flag unusually large DNS responses that may indicate tunneling",
            false_positive_guidance="DKIM records, SPF records can be large",
            priority=2
        ))
        
        # Persistence via Services
        self.add_hypothesis(Hypothesis(
            hypothesis_id="hyp-pers-001",
            title="Suspicious Service Installation",
            description="Detect installation of potentially malicious Windows services",
            category=ThreatCategory.PERSISTENCE,
            mitre_techniques=["T1543.003"],
            data_sources=["sysmon", "windows_events"],
            queries=[
                {
                    "type": "sigma",
                    "query": """
                        detection:
                            selection:
                                EventID: 7045
                            filter_known:
                                ServiceName:
                                    - 'Microsoft*'
                                    - 'Windows*'
                            condition: selection and not filter_known
                    """
                }
            ],
            detection_logic="Alert on new services installed outside normal change windows",
            false_positive_guidance="Software installations, legitimate service updates",
            priority=2
        ))
        
        # Command and Control
        self.add_hypothesis(Hypothesis(
            hypothesis_id="hyp-c2-001",
            title="Beaconing Behavior",
            description="Detect regular interval network connections indicative of C2",
            category=ThreatCategory.COMMAND_AND_CONTROL,
            mitre_techniques=["T1071"],
            data_sources=["network_traffic", "proxy_logs", "firewall_logs"],
            queries=[
                {
                    "type": "behavioral",
                    "query": "connection_interval_std < 5 AND connection_count > 100"
                }
            ],
            detection_logic="Identify regular interval callbacks that suggest beacon behavior",
            false_positive_guidance="Update services, health checks, monitoring tools",
            priority=1
        ))
    
    def add_hypothesis(self, hypothesis: Hypothesis):
        """Add hypothesis to library"""
        self.hypotheses[hypothesis.hypothesis_id] = hypothesis
    
    def get_by_category(self, category: ThreatCategory) -> List[Hypothesis]:
        """Get hypotheses by threat category"""
        return [h for h in self.hypotheses.values() if h.category == category]
    
    def get_by_technique(self, technique_id: str) -> List[Hypothesis]:
        """Get hypotheses by MITRE technique"""
        return [
            h for h in self.hypotheses.values()
            if technique_id in h.mitre_techniques
        ]


class BehavioralAnalyzer:
    """Analyze behavioral patterns for anomaly detection"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.baselines: Dict[str, BehaviorBaseline] = {}
        
        # Anomaly detection parameters
        self.zscore_threshold = 3.0
        self.min_samples = 30
    
    def update_baseline(
        self,
        entity_type: str,
        entity_id: str,
        metrics: Dict[str, float]
    ):
        """Update behavioral baseline for entity"""
        key = f"{entity_type}:{entity_id}"
        
        if key not in self.baselines:
            self.baselines[key] = BehaviorBaseline(
                entity_type=entity_type,
                entity_id=entity_id,
                metrics={},
                statistics={},
                last_updated=datetime.now(),
                sample_count=0
            )
        
        baseline = self.baselines[key]
        
        for metric_name, value in metrics.items():
            if metric_name not in baseline.metrics:
                baseline.metrics[metric_name] = []
            
            baseline.metrics[metric_name].append(value)
            
            # Keep sliding window
            if len(baseline.metrics[metric_name]) > 1000:
                baseline.metrics[metric_name] = baseline.metrics[metric_name][-1000:]
        
        # Recalculate statistics
        self._calculate_statistics(baseline)
        baseline.sample_count += 1
        baseline.last_updated = datetime.now()
    
    def _calculate_statistics(self, baseline: BehaviorBaseline):
        """Calculate statistical measures for baseline"""
        for metric_name, values in baseline.metrics.items():
            if len(values) >= self.min_samples:
                baseline.statistics[metric_name] = {
                    "mean": statistics.mean(values),
                    "std": statistics.stdev(values) if len(values) > 1 else 0,
                    "median": statistics.median(values),
                    "min": min(values),
                    "max": max(values),
                    "count": len(values)
                }
    
    def detect_anomalies(
        self,
        entity_type: str,
        entity_id: str,
        current_metrics: Dict[str, float]
    ) -> List[Anomaly]:
        """Detect anomalies in current metrics"""
        anomalies = []
        key = f"{entity_type}:{entity_id}"
        
        if key not in self.baselines:
            return anomalies
        
        baseline = self.baselines[key]
        
        for metric_name, value in current_metrics.items():
            if metric_name not in baseline.statistics:
                continue
            
            stats = baseline.statistics[metric_name]
            if stats["std"] == 0:
                continue
            
            # Calculate z-score
            zscore = abs(value - stats["mean"]) / stats["std"]
            
            if zscore > self.zscore_threshold:
                anomaly = Anomaly(
                    anomaly_id=str(uuid.uuid4()),
                    entity_type=entity_type,
                    entity_id=entity_id,
                    anomaly_type="statistical_deviation",
                    metric_name=metric_name,
                    expected_value=stats["mean"],
                    actual_value=value,
                    deviation_score=zscore,
                    timestamp=datetime.now(),
                    context={
                        "baseline_std": stats["std"],
                        "baseline_min": stats["min"],
                        "baseline_max": stats["max"],
                        "sample_count": stats["count"]
                    }
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def get_entity_profile(
        self,
        entity_type: str,
        entity_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get behavioral profile for entity"""
        key = f"{entity_type}:{entity_id}"
        
        if key not in self.baselines:
            return None
        
        baseline = self.baselines[key]
        
        return {
            "entity_type": baseline.entity_type,
            "entity_id": baseline.entity_id,
            "statistics": baseline.statistics,
            "last_updated": baseline.last_updated.isoformat(),
            "sample_count": baseline.sample_count
        }


class BeaconDetector:
    """Detect command and control beaconing behavior"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.connection_history: Dict[str, List[datetime]] = {}
        
        # Detection parameters
        self.min_connections = 10
        self.max_jitter_percent = 15  # Allow 15% variation
        self.analysis_window = timedelta(hours=24)
    
    def add_connection(
        self,
        source_ip: str,
        dest_ip: str,
        dest_port: int,
        timestamp: datetime
    ):
        """Record a network connection"""
        key = f"{source_ip}:{dest_ip}:{dest_port}"
        
        if key not in self.connection_history:
            self.connection_history[key] = []
        
        self.connection_history[key].append(timestamp)
        
        # Cleanup old entries
        cutoff = datetime.now() - self.analysis_window
        self.connection_history[key] = [
            ts for ts in self.connection_history[key]
            if ts > cutoff
        ]
    
    def detect_beaconing(self) -> List[Dict[str, Any]]:
        """Detect beaconing patterns in connection data"""
        beacons = []
        
        for key, timestamps in self.connection_history.items():
            if len(timestamps) < self.min_connections:
                continue
            
            # Calculate intervals
            timestamps.sort()
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                if interval > 0:
                    intervals.append(interval)
            
            if len(intervals) < self.min_connections - 1:
                continue
            
            # Analyze interval consistency
            mean_interval = statistics.mean(intervals)
            std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
            
            # Calculate jitter percentage
            if mean_interval > 0:
                jitter_percent = (std_interval / mean_interval) * 100
            else:
                continue
            
            # Check if beaconing
            if jitter_percent <= self.max_jitter_percent:
                parts = key.split(':')
                beacons.append({
                    "source_ip": parts[0],
                    "dest_ip": parts[1],
                    "dest_port": int(parts[2]),
                    "connection_count": len(timestamps),
                    "mean_interval_seconds": mean_interval,
                    "jitter_percent": jitter_percent,
                    "confidence": 1 - (jitter_percent / 100),
                    "first_seen": timestamps[0].isoformat(),
                    "last_seen": timestamps[-1].isoformat()
                })
        
        return beacons


class TTPMatcher:
    """Match observed activity to known TTPs"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # TTP patterns (simplified MITRE ATT&CK mapping)
        self.ttp_patterns = {
            "T1059.001": {  # PowerShell
                "name": "PowerShell Execution",
                "patterns": [
                    r"powershell\.exe.*-enc",
                    r"powershell\.exe.*-nop",
                    r"powershell\.exe.*downloadstring",
                    r"powershell\.exe.*iex"
                ],
                "data_sources": ["process_creation", "command_line"]
            },
            "T1055": {  # Process Injection
                "name": "Process Injection",
                "patterns": [
                    r"VirtualAllocEx",
                    r"WriteProcessMemory",
                    r"CreateRemoteThread",
                    r"NtQueueApcThread"
                ],
                "data_sources": ["api_calls", "sysmon"]
            },
            "T1003.001": {  # LSASS Memory
                "name": "LSASS Memory Access",
                "patterns": [
                    r"lsass\.exe",
                    r"mimikatz",
                    r"sekurlsa",
                    r"procdump.*lsass"
                ],
                "data_sources": ["sysmon", "edr"]
            },
            "T1053.005": {  # Scheduled Task
                "name": "Scheduled Task Creation",
                "patterns": [
                    r"schtasks.*\/create",
                    r"at\.exe.*\/every",
                    r"Register-ScheduledTask"
                ],
                "data_sources": ["process_creation", "command_line"]
            },
            "T1087": {  # Account Discovery
                "name": "Account Discovery",
                "patterns": [
                    r"net\s+user",
                    r"net\s+localgroup",
                    r"Get-ADUser",
                    r"whoami\s+\/all"
                ],
                "data_sources": ["process_creation", "command_line"]
            },
            "T1070.001": {  # Clear Windows Event Logs
                "name": "Event Log Clearing",
                "patterns": [
                    r"wevtutil\s+cl",
                    r"Clear-EventLog",
                    r"EventID.*1102"
                ],
                "data_sources": ["process_creation", "windows_events"]
            }
        }
    
    def match_activity(
        self,
        activity_data: str,
        data_source: str = ""
    ) -> List[Dict[str, Any]]:
        """Match activity against TTP patterns"""
        matches = []
        
        for technique_id, ttp in self.ttp_patterns.items():
            if data_source and data_source not in ttp["data_sources"]:
                continue
            
            for pattern in ttp["patterns"]:
                if re.search(pattern, activity_data, re.IGNORECASE):
                    matches.append({
                        "technique_id": technique_id,
                        "technique_name": ttp["name"],
                        "matched_pattern": pattern,
                        "confidence": 0.8,
                        "mitre_url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
                    })
                    break  # Only one match per technique
        
        return matches


class HuntQueryEngine:
    """Execute hunting queries across data sources"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.data_connectors: Dict[str, Callable] = {}
    
    def register_connector(
        self,
        source_name: str,
        query_function: Callable
    ):
        """Register a data source connector"""
        self.data_connectors[source_name] = query_function
    
    async def execute_query(
        self,
        query: Dict[str, Any],
        time_range: Tuple[datetime, datetime]
    ) -> List[Dict[str, Any]]:
        """Execute a hunt query"""
        query_type = query.get("type", "")
        query_string = query.get("query", "")
        
        # Placeholder for actual query execution
        # In production, this would query SIEM, EDR, etc.
        
        results = []
        
        # Simulate query execution
        self.logger.info(f"Executing {query_type} query: {query_string[:50]}...")
        
        return results
    
    async def parallel_query(
        self,
        queries: List[Dict[str, Any]],
        time_range: Tuple[datetime, datetime]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Execute multiple queries in parallel"""
        results = {}
        
        tasks = []
        for i, query in enumerate(queries):
            task = asyncio.create_task(self.execute_query(query, time_range))
            tasks.append((f"query_{i}", task))
        
        for query_id, task in tasks:
            try:
                result = await task
                results[query_id] = result
            except Exception as e:
                self.logger.error(f"Query {query_id} failed: {e}")
                results[query_id] = []
        
        return results


class ThreatHuntingEngine:
    """Main threat hunting automation engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.hypothesis_library = HypothesisLibrary()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.beacon_detector = BeaconDetector()
        self.ttp_matcher = TTPMatcher()
        self.query_engine = HuntQueryEngine()
        
        # Hunt storage
        self.hunts: Dict[str, Hunt] = {}
        self.results: List[HuntResult] = []
        
        # Statistics
        self.stats = {
            "hunts_executed": 0,
            "findings_generated": 0,
            "hypotheses_tested": 0,
            "anomalies_detected": 0,
            "beacons_detected": 0
        }
    
    async def create_hunt(
        self,
        name: str,
        description: str,
        hunt_type: HuntType,
        hypothesis_ids: Optional[List[str]] = None,
        categories: Optional[List[ThreatCategory]] = None,
        scope: Optional[Dict[str, Any]] = None,
        created_by: str = "system"
    ) -> Hunt:
        """Create a new threat hunt"""
        # Gather hypotheses
        hypotheses = []
        
        if hypothesis_ids:
            for hid in hypothesis_ids:
                if hid in self.hypothesis_library.hypotheses:
                    hypotheses.append(self.hypothesis_library.hypotheses[hid])
        
        if categories:
            for category in categories:
                hypotheses.extend(self.hypothesis_library.get_by_category(category))
        
        # Remove duplicates
        seen_ids = set()
        unique_hypotheses = []
        for h in hypotheses:
            if h.hypothesis_id not in seen_ids:
                unique_hypotheses.append(h)
                seen_ids.add(h.hypothesis_id)
        
        # Collect data sources
        data_sources = set()
        for h in unique_hypotheses:
            data_sources.update(h.data_sources)
        
        hunt = Hunt(
            hunt_id=f"HUNT-{uuid.uuid4().hex[:8].upper()}",
            name=name,
            description=description,
            hunt_type=hunt_type,
            hypotheses=unique_hypotheses,
            status=HuntStatus.PENDING,
            created_at=datetime.now(),
            started_at=None,
            completed_at=None,
            created_by=created_by,
            results=[],
            data_sources=list(data_sources),
            scope=scope or {}
        )
        
        self.hunts[hunt.hunt_id] = hunt
        return hunt
    
    async def execute_hunt(
        self,
        hunt_id: str,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> Hunt:
        """Execute a threat hunt"""
        hunt = self.hunts.get(hunt_id)
        if not hunt:
            raise ValueError(f"Hunt not found: {hunt_id}")
        
        if not time_range:
            time_range = (
                datetime.now() - timedelta(days=7),
                datetime.now()
            )
        
        hunt.status = HuntStatus.RUNNING
        hunt.started_at = datetime.now()
        
        self.logger.info(f"Starting hunt: {hunt.name} ({hunt.hunt_id})")
        
        try:
            # Test each hypothesis
            for hypothesis in hunt.hypotheses:
                self.stats["hypotheses_tested"] += 1
                
                results = await self._test_hypothesis(
                    hunt, hypothesis, time_range
                )
                
                for result in results:
                    hunt.results.append(result)
                    self.results.append(result)
                    self.stats["findings_generated"] += 1
            
            hunt.status = HuntStatus.COMPLETED
            
        except Exception as e:
            self.logger.error(f"Hunt failed: {e}")
            hunt.status = HuntStatus.FAILED
        
        hunt.completed_at = datetime.now()
        self.stats["hunts_executed"] += 1
        
        return hunt
    
    async def _test_hypothesis(
        self,
        hunt: Hunt,
        hypothesis: Hypothesis,
        time_range: Tuple[datetime, datetime]
    ) -> List[HuntResult]:
        """Test a hunting hypothesis"""
        results = []
        
        self.logger.info(f"Testing hypothesis: {hypothesis.title}")
        
        # Execute queries
        query_results = await self.query_engine.parallel_query(
            hypothesis.queries,
            time_range
        )
        
        # Analyze results
        for query_id, data in query_results.items():
            if data:
                # Create finding for positive results
                result = HuntResult(
                    result_id=str(uuid.uuid4()),
                    hunt_id=hunt.hunt_id,
                    hypothesis_id=hypothesis.hypothesis_id,
                    timestamp=datetime.now(),
                    severity=self._calculate_severity(hypothesis, data),
                    title=f"Potential {hypothesis.title}",
                    description=hypothesis.description,
                    indicators=[],
                    affected_assets=[],
                    evidence={"query_results": data},
                    mitre_techniques=hypothesis.mitre_techniques,
                    confidence=0.7,
                    recommended_actions=[
                        "Investigate affected assets",
                        "Review false positive guidance",
                        hypothesis.false_positive_guidance
                    ]
                )
                results.append(result)
        
        return results
    
    def _calculate_severity(
        self,
        hypothesis: Hypothesis,
        data: List[Dict[str, Any]]
    ) -> SeverityLevel:
        """Calculate severity based on hypothesis and results"""
        # Map priority to severity
        priority_severity = {
            1: SeverityLevel.CRITICAL,
            2: SeverityLevel.HIGH,
            3: SeverityLevel.MEDIUM,
            4: SeverityLevel.LOW,
            5: SeverityLevel.INFORMATIONAL
        }
        
        base_severity = priority_severity.get(
            hypothesis.priority,
            SeverityLevel.MEDIUM
        )
        
        # Adjust based on result count
        if len(data) > 100:
            severity_order = [
                SeverityLevel.INFORMATIONAL,
                SeverityLevel.LOW,
                SeverityLevel.MEDIUM,
                SeverityLevel.HIGH,
                SeverityLevel.CRITICAL
            ]
            idx = severity_order.index(base_severity)
            if idx < len(severity_order) - 1:
                return severity_order[idx + 1]
        
        return base_severity
    
    async def run_behavioral_hunt(
        self,
        entity_type: str,
        current_data: List[Dict[str, Any]]
    ) -> List[Anomaly]:
        """Run behavioral anomaly detection hunt"""
        all_anomalies = []
        
        for data_point in current_data:
            entity_id = data_point.get("entity_id", "")
            metrics = {
                k: v for k, v in data_point.items()
                if isinstance(v, (int, float)) and k != "entity_id"
            }
            
            anomalies = self.behavioral_analyzer.detect_anomalies(
                entity_type,
                entity_id,
                metrics
            )
            
            all_anomalies.extend(anomalies)
        
        self.stats["anomalies_detected"] += len(all_anomalies)
        return all_anomalies
    
    async def run_beacon_hunt(
        self,
        network_connections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Run beacon detection hunt"""
        for conn in network_connections:
            self.beacon_detector.add_connection(
                conn.get("source_ip", ""),
                conn.get("dest_ip", ""),
                conn.get("dest_port", 0),
                conn.get("timestamp", datetime.now())
            )
        
        beacons = self.beacon_detector.detect_beaconing()
        self.stats["beacons_detected"] += len(beacons)
        
        return beacons
    
    async def run_ttp_hunt(
        self,
        activity_logs: List[str],
        data_source: str = ""
    ) -> List[Dict[str, Any]]:
        """Run TTP-based hunt"""
        all_matches = []
        
        for log_entry in activity_logs:
            matches = self.ttp_matcher.match_activity(log_entry, data_source)
            all_matches.extend(matches)
        
        return all_matches
    
    def get_hunt_summary(self, hunt_id: str) -> Dict[str, Any]:
        """Get summary of a hunt"""
        hunt = self.hunts.get(hunt_id)
        if not hunt:
            raise ValueError(f"Hunt not found: {hunt_id}")
        
        severity_counts = defaultdict(int)
        for result in hunt.results:
            severity_counts[result.severity.value] += 1
        
        return {
            "hunt_id": hunt.hunt_id,
            "name": hunt.name,
            "status": hunt.status.value,
            "hunt_type": hunt.hunt_type.value,
            "created_at": hunt.created_at.isoformat(),
            "started_at": hunt.started_at.isoformat() if hunt.started_at else None,
            "completed_at": hunt.completed_at.isoformat() if hunt.completed_at else None,
            "hypotheses_tested": len(hunt.hypotheses),
            "findings_count": len(hunt.results),
            "severity_breakdown": dict(severity_counts),
            "data_sources": hunt.data_sources
        }
    
    def generate_hunt_report(self, hunt_id: str) -> Dict[str, Any]:
        """Generate detailed hunt report"""
        hunt = self.hunts.get(hunt_id)
        if not hunt:
            raise ValueError(f"Hunt not found: {hunt_id}")
        
        return {
            "hunt": {
                "id": hunt.hunt_id,
                "name": hunt.name,
                "description": hunt.description,
                "type": hunt.hunt_type.value,
                "status": hunt.status.value,
                "created_by": hunt.created_by,
                "created_at": hunt.created_at.isoformat(),
                "completed_at": hunt.completed_at.isoformat() if hunt.completed_at else None
            },
            "hypotheses": [
                {
                    "id": h.hypothesis_id,
                    "title": h.title,
                    "category": h.category.value,
                    "mitre_techniques": h.mitre_techniques,
                    "priority": h.priority
                }
                for h in hunt.hypotheses
            ],
            "findings": [
                {
                    "id": r.result_id,
                    "hypothesis_id": r.hypothesis_id,
                    "severity": r.severity.value,
                    "title": r.title,
                    "description": r.description,
                    "confidence": r.confidence,
                    "mitre_techniques": r.mitre_techniques,
                    "affected_assets": r.affected_assets,
                    "recommended_actions": r.recommended_actions,
                    "timestamp": r.timestamp.isoformat()
                }
                for r in hunt.results
            ],
            "summary": {
                "total_findings": len(hunt.results),
                "critical_findings": sum(1 for r in hunt.results if r.severity == SeverityLevel.CRITICAL),
                "high_findings": sum(1 for r in hunt.results if r.severity == SeverityLevel.HIGH),
                "data_sources_used": hunt.data_sources
            }
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat hunting statistics"""
        return {
            **self.stats,
            "active_hunts": sum(
                1 for h in self.hunts.values()
                if h.status == HuntStatus.RUNNING
            ),
            "total_hunts": len(self.hunts),
            "hypotheses_available": len(self.hypothesis_library.hypotheses),
            "baselines_tracked": len(self.behavioral_analyzer.baselines)
        }


# Main execution
if __name__ == "__main__":
    import asyncio
    
    async def main():
        engine = ThreatHuntingEngine()
        
        print("Threat Hunting Automation Engine")
        print("=" * 50)
        
        # List available hypotheses
        print("\nAvailable Hypotheses:")
        for hyp_id, hyp in engine.hypothesis_library.hypotheses.items():
            print(f"  [{hyp.category.value}] {hyp.title}")
            print(f"    MITRE: {', '.join(hyp.mitre_techniques)}")
        
        # Create a hunt
        print("\nCreating threat hunt...")
        hunt = await engine.create_hunt(
            name="APT Detection Hunt",
            description="Hunt for APT indicators across endpoints",
            hunt_type=HuntType.HYPOTHESIS_DRIVEN,
            categories=[ThreatCategory.LATERAL_MOVEMENT, ThreatCategory.CREDENTIAL_ACCESS],
            created_by="analyst"
        )
        
        print(f"Created hunt: {hunt.hunt_id}")
        print(f"Hypotheses to test: {len(hunt.hypotheses)}")
        
        # Execute hunt
        print("\nExecuting hunt...")
        hunt = await engine.execute_hunt(hunt.hunt_id)
        
        print(f"Hunt status: {hunt.status.value}")
        print(f"Findings: {len(hunt.results)}")
        
        # Test TTP matching
        print("\nTesting TTP matching...")
        test_logs = [
            "powershell.exe -enc SGVsbG8gV29ybGQ=",
            "net user /domain",
            "cmd.exe /c dir"
        ]
        
        matches = await engine.run_ttp_hunt(test_logs)
        for match in matches:
            print(f"  Matched: {match['technique_id']} - {match['technique_name']}")
        
        # Print statistics
        print("\nStatistics:")
        stats = engine.get_statistics()
        for key, value in stats.items():
            print(f"  {key}: {value}")
    
    asyncio.run(main())
