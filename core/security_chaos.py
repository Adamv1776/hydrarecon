"""
HydraRecon Security Chaos Engineering
=====================================
Netflix-style chaos engineering for security testing.

Features:
- Random security control disabling
- Credential leak simulation
- Insider threat simulation
- Detection/response time measurement
- Security resilience scoring
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import random
import json


class ExperimentType(Enum):
    CONTROL_FAILURE = "control_failure"
    CREDENTIAL_LEAK = "credential_leak"
    INSIDER_THREAT = "insider_threat"
    NETWORK_ATTACK = "network_attack"
    DATA_EXFIL = "data_exfil"
    MALWARE_INJECTION = "malware_injection"
    CONFIG_DRIFT = "config_drift"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    C2_COMMUNICATION = "c2_communication"


class ExperimentStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"


class DetectionOutcome(Enum):
    DETECTED = "detected"
    PARTIALLY_DETECTED = "partially_detected"
    UNDETECTED = "undetected"
    BLOCKED = "blocked"


class ResponseOutcome(Enum):
    CONTAINED = "contained"
    PARTIALLY_CONTAINED = "partially_contained"
    NOT_CONTAINED = "not_contained"
    AUTO_REMEDIATED = "auto_remediated"


@dataclass
class ChaosExperiment:
    """A chaos engineering experiment"""
    experiment_id: str
    experiment_type: ExperimentType
    name: str
    description: str
    target_systems: List[str]
    duration_seconds: int
    blast_radius: str  # small, medium, large
    rollback_procedure: str
    safe_mode: bool  # If true, simulates without real impact
    prerequisites: List[str]
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class ExperimentResult:
    """Result of a chaos experiment"""
    experiment_id: str
    status: ExperimentStatus
    start_time: datetime
    end_time: Optional[datetime]
    detection_outcome: DetectionOutcome
    response_outcome: ResponseOutcome
    time_to_detect: Optional[timedelta]
    time_to_respond: Optional[timedelta]
    time_to_contain: Optional[timedelta]
    alerts_generated: List[Dict[str, Any]]
    actions_taken: List[str]
    impact_observed: List[str]
    lessons_learned: List[str]
    resilience_score: float  # 0-100


@dataclass
class SecurityControl:
    """A security control that can be tested"""
    control_id: str
    name: str
    control_type: str  # preventive, detective, responsive
    systems: List[str]
    effectiveness: float  # 0-1
    enabled: bool
    last_tested: Optional[datetime]
    failure_modes: List[str]


@dataclass
class GameDay:
    """A scheduled chaos game day"""
    gameday_id: str
    name: str
    scheduled_date: datetime
    duration_hours: int
    experiments: List[str]  # Experiment IDs
    participants: List[str]
    objectives: List[str]
    status: str  # scheduled, in_progress, completed, cancelled
    results: Optional[Dict[str, Any]] = None


@dataclass
class ResilienceMetric:
    """Security resilience metric"""
    metric_id: str
    name: str
    category: str
    current_value: float
    target_value: float
    trend: str  # improving, degrading, stable
    last_updated: datetime
    experiments_count: int


@dataclass
class ChaosReport:
    """Comprehensive chaos engineering report"""
    report_id: str
    period_start: datetime
    period_end: datetime
    experiments_run: int
    experiments_detected: int
    experiments_contained: int
    average_detection_time: timedelta
    average_response_time: timedelta
    resilience_score: float
    weakest_controls: List[str]
    recommendations: List[str]


class SecurityChaos:
    """
    Security Chaos Engineering - Netflix-style chaos for security.
    Continuously test your security controls under realistic attack conditions.
    """
    
    def __init__(self):
        self.experiments: Dict[str, ChaosExperiment] = {}
        self.results: List[ExperimentResult] = []
        self.controls: Dict[str, SecurityControl] = {}
        self.game_days: Dict[str, GameDay] = {}
        self.metrics: Dict[str, ResilienceMetric] = {}
        
        # Experiment library
        self.experiment_library = {
            ExperimentType.CONTROL_FAILURE: self._run_control_failure,
            ExperimentType.CREDENTIAL_LEAK: self._run_credential_leak,
            ExperimentType.INSIDER_THREAT: self._run_insider_threat,
            ExperimentType.NETWORK_ATTACK: self._run_network_attack,
            ExperimentType.DATA_EXFIL: self._run_data_exfil,
            ExperimentType.MALWARE_INJECTION: self._run_malware_injection,
            ExperimentType.CONFIG_DRIFT: self._run_config_drift,
            ExperimentType.PRIVILEGE_ESCALATION: self._run_privilege_escalation,
            ExperimentType.LATERAL_MOVEMENT: self._run_lateral_movement,
            ExperimentType.C2_COMMUNICATION: self._run_c2_communication,
        }
        
        self._initialize_controls()
        self._initialize_experiments()
        self._initialize_metrics()
        
    def _initialize_controls(self):
        """Initialize security controls to test"""
        
        controls_data = [
            ("ctrl-edr", "Endpoint Detection & Response", "detective",
             ["endpoints", "servers"], 0.85, True,
             ["signature_bypass", "memory_only", "process_injection"]),
            ("ctrl-siem", "SIEM Platform", "detective",
             ["all"], 0.75, True,
             ["log_deletion", "log_flooding", "alert_fatigue"]),
            ("ctrl-ngfw", "Next-Gen Firewall", "preventive",
             ["network"], 0.90, True,
             ["encryption_bypass", "allowed_ports", "fragmentation"]),
            ("ctrl-dlp", "Data Loss Prevention", "preventive",
             ["endpoints", "email", "cloud"], 0.70, True,
             ["encryption", "steganography", "chunking"]),
            ("ctrl-waf", "Web Application Firewall", "preventive",
             ["web_apps"], 0.80, True,
             ["encoding_bypass", "parameter_pollution", "http_smuggling"]),
            ("ctrl-mfa", "Multi-Factor Authentication", "preventive",
             ["identity"], 0.95, True,
             ["mfa_fatigue", "sim_swap", "phishing"]),
            ("ctrl-ndr", "Network Detection & Response", "detective",
             ["network"], 0.70, True,
             ["encrypted_c2", "dns_tunneling", "slow_exfil"]),
            ("ctrl-casb", "Cloud Access Security Broker", "preventive",
             ["cloud", "saas"], 0.75, True,
             ["shadow_it", "personal_accounts", "api_access"]),
            ("ctrl-deception", "Deception Technology", "detective",
             ["all"], 0.90, True,
             ["fingerprinting", "avoidance", "noise"]),
            ("ctrl-soar", "Security Orchestration", "responsive",
             ["all"], 0.80, True,
             ["playbook_gaps", "integration_failure", "rate_limiting"]),
        ]
        
        for data in controls_data:
            control = SecurityControl(
                control_id=data[0],
                name=data[1],
                control_type=data[2],
                systems=data[3],
                effectiveness=data[4],
                enabled=data[5],
                last_tested=datetime.now() - timedelta(days=random.randint(1, 90)),
                failure_modes=data[6]
            )
            self.controls[control.control_id] = control
            
    def _initialize_experiments(self):
        """Initialize chaos experiments"""
        
        experiments_data = [
            # Control Failure Experiments
            (ExperimentType.CONTROL_FAILURE, "EDR Blackout", 
             "Simulate EDR agent going offline on critical servers",
             ["server-01", "server-02"], 300, "medium", True,
             "Re-enable EDR agents via management console"),
             
            (ExperimentType.CONTROL_FAILURE, "SIEM Lag Spike",
             "Introduce 30-minute delay in SIEM log ingestion",
             ["siem-cluster"], 1800, "large", True,
             "Clear log queue and restore real-time ingestion"),
             
            # Credential Leak Experiments
            (ExperimentType.CREDENTIAL_LEAK, "AWS Keys on GitHub",
             "Simulate AWS access keys leaked to public GitHub repo",
             ["github-scanner", "aws-guardduty"], 600, "medium", True,
             "Rotate affected credentials, revoke leaked keys"),
             
            (ExperimentType.CREDENTIAL_LEAK, "Database Creds in Logs",
             "Inject database credentials into application logs",
             ["app-server", "log-aggregator"], 300, "small", True,
             "Redact credentials, rotate affected passwords"),
             
            # Insider Threat Experiments
            (ExperimentType.INSIDER_THREAT, "Mass Data Download",
             "Simulate employee downloading large amounts of data",
             ["file-server", "dlp-agent"], 900, "medium", True,
             "Block access, investigate download activity"),
             
            (ExperimentType.INSIDER_THREAT, "Privilege Abuse",
             "Simulate admin accessing unauthorized resources",
             ["ad-controller", "pam-system"], 600, "medium", True,
             "Revoke session, investigate access patterns"),
             
            # Network Attack Experiments
            (ExperimentType.NETWORK_ATTACK, "Port Scan Storm",
             "Simulate aggressive network reconnaissance",
             ["firewall", "ids-sensor"], 300, "small", True,
             "Block source IP, analyze scan patterns"),
             
            (ExperimentType.NETWORK_ATTACK, "DNS Tunneling",
             "Simulate data exfiltration via DNS queries",
             ["dns-server", "ndr-sensor"], 600, "medium", True,
             "Block DNS, investigate exfil data"),
             
            # Data Exfiltration Experiments
            (ExperimentType.DATA_EXFIL, "Cloud Storage Upload",
             "Simulate sensitive data upload to personal cloud",
             ["casb", "dlp-agent"], 600, "medium", True,
             "Block upload, quarantine data"),
             
            (ExperimentType.DATA_EXFIL, "Encrypted Exfil",
             "Simulate encrypted data exfiltration over HTTPS",
             ["proxy", "ndr-sensor"], 900, "large", True,
             "Block destination, investigate payload"),
             
            # Malware Experiments
            (ExperimentType.MALWARE_INJECTION, "Fileless Malware",
             "Simulate fileless malware execution in memory",
             ["endpoint-01", "edr-agent"], 300, "small", True,
             "Kill process, collect forensics"),
             
            (ExperimentType.MALWARE_INJECTION, "Ransomware Canary",
             "Simulate ransomware encryption behavior on decoy files",
             ["file-server", "deception-net"], 180, "small", True,
             "Isolate host, restore from backup"),
             
            # Privilege Escalation Experiments
            (ExperimentType.PRIVILEGE_ESCALATION, "Local Admin Exploit",
             "Simulate local privilege escalation attack",
             ["workstation-01", "edr-agent"], 300, "small", True,
             "Terminate session, patch vulnerability"),
             
            (ExperimentType.PRIVILEGE_ESCALATION, "Service Account Abuse",
             "Simulate service account token theft",
             ["kubernetes", "vault"], 600, "medium", True,
             "Rotate credentials, investigate access"),
             
            # Lateral Movement Experiments
            (ExperimentType.LATERAL_MOVEMENT, "Pass-the-Hash",
             "Simulate credential relay attack between systems",
             ["workstation", "server"], 600, "medium", True,
             "Reset credentials, enable additional auth"),
             
            (ExperimentType.LATERAL_MOVEMENT, "RDP Pivot",
             "Simulate lateral movement via RDP",
             ["jump-server", "internal-server"], 600, "medium", True,
             "Terminate sessions, review access logs"),
             
            # C2 Communication Experiments
            (ExperimentType.C2_COMMUNICATION, "Beacon Traffic",
             "Simulate periodic C2 beacon communication",
             ["infected-host", "firewall"], 900, "medium", True,
             "Block C2, isolate host, investigate"),
             
            (ExperimentType.C2_COMMUNICATION, "Domain Fronting",
             "Simulate C2 via domain fronting technique",
             ["proxy", "ndr-sensor"], 900, "large", True,
             "Block fronted domain, update detection"),
        ]
        
        for i, data in enumerate(experiments_data):
            exp = ChaosExperiment(
                experiment_id=f"CHAOS-{i+1:03d}",
                experiment_type=data[0],
                name=data[1],
                description=data[2],
                target_systems=data[3],
                duration_seconds=data[4],
                blast_radius=data[5],
                safe_mode=data[6],
                rollback_procedure=data[7],
                prerequisites=["approval_obtained", "monitoring_active", "rollback_ready"]
            )
            self.experiments[exp.experiment_id] = exp
            
    def _initialize_metrics(self):
        """Initialize resilience metrics"""
        
        metrics_data = [
            ("mttr", "Mean Time to Respond", "response", 15.0, 5.0, "improving"),
            ("mttd", "Mean Time to Detect", "detection", 10.0, 2.0, "stable"),
            ("mttc", "Mean Time to Contain", "containment", 45.0, 15.0, "improving"),
            ("detection_rate", "Detection Rate", "effectiveness", 75.0, 95.0, "improving"),
            ("false_positive_rate", "False Positive Rate", "accuracy", 15.0, 5.0, "improving"),
            ("automation_rate", "Automation Rate", "maturity", 40.0, 80.0, "improving"),
            ("coverage", "Control Coverage", "coverage", 85.0, 100.0, "stable"),
            ("resilience_index", "Overall Resilience", "composite", 68.0, 90.0, "improving"),
        ]
        
        for data in metrics_data:
            metric = ResilienceMetric(
                metric_id=data[0],
                name=data[1],
                category=data[2],
                current_value=data[3],
                target_value=data[4],
                trend=data[5],
                last_updated=datetime.now(),
                experiments_count=random.randint(5, 20)
            )
            self.metrics[metric.metric_id] = metric
            
    async def run_experiment(
        self,
        experiment_id: str,
        safe_mode: bool = True
    ) -> ExperimentResult:
        """Run a chaos experiment"""
        
        if experiment_id not in self.experiments:
            raise ValueError(f"Experiment {experiment_id} not found")
            
        experiment = self.experiments[experiment_id]
        start_time = datetime.now()
        
        # Get appropriate runner
        runner = self.experiment_library.get(experiment.experiment_type)
        
        if runner:
            result = await runner(experiment, safe_mode)
        else:
            result = await self._run_generic_experiment(experiment, safe_mode)
            
        self.results.append(result)
        self._update_metrics(result)
        
        return result
        
    async def _run_control_failure(self, experiment: ChaosExperiment, safe_mode: bool) -> ExperimentResult:
        """Run control failure experiment"""
        start_time = datetime.now()
        
        # Simulate control being disabled
        await asyncio.sleep(1.0)
        
        # Simulate detection
        detection_time = random.uniform(1, 10)  # minutes
        await asyncio.sleep(0.5)
        
        # Determine detection outcome
        if detection_time < 2:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.AUTO_REMEDIATED
            ttd = timedelta(minutes=detection_time)
            ttr = timedelta(minutes=detection_time + random.uniform(0.5, 2))
        elif detection_time < 5:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.CONTAINED
            ttd = timedelta(minutes=detection_time)
            ttr = timedelta(minutes=detection_time + random.uniform(2, 10))
        elif detection_time < 10:
            detection_outcome = DetectionOutcome.PARTIALLY_DETECTED
            response_outcome = ResponseOutcome.PARTIALLY_CONTAINED
            ttd = timedelta(minutes=detection_time)
            ttr = timedelta(minutes=detection_time + random.uniform(10, 30))
        else:
            detection_outcome = DetectionOutcome.UNDETECTED
            response_outcome = ResponseOutcome.NOT_CONTAINED
            ttd = None
            ttr = None
            
        alerts = [
            {"type": "control_health", "severity": "high", "message": f"Control offline: {experiment.target_systems[0]}"},
            {"type": "coverage_gap", "severity": "medium", "message": "Security coverage reduced"},
        ] if detection_outcome != DetectionOutcome.UNDETECTED else []
        
        resilience = 100 - (detection_time * 5) if detection_outcome != DetectionOutcome.UNDETECTED else 20
        
        return ExperimentResult(
            experiment_id=experiment.experiment_id,
            status=ExperimentStatus.COMPLETED,
            start_time=start_time,
            end_time=datetime.now(),
            detection_outcome=detection_outcome,
            response_outcome=response_outcome,
            time_to_detect=ttd,
            time_to_respond=ttr,
            time_to_contain=timedelta(minutes=random.uniform(5, 30)) if response_outcome != ResponseOutcome.NOT_CONTAINED else None,
            alerts_generated=alerts,
            actions_taken=["Alert generated", "On-call notified", "Control restored"] if detection_outcome != DetectionOutcome.UNDETECTED else [],
            impact_observed=["Temporary visibility gap", "Potential detection blind spot"],
            lessons_learned=["Improve control health monitoring", "Add redundant detection"],
            resilience_score=max(0, min(100, resilience))
        )
        
    async def _run_credential_leak(self, experiment: ChaosExperiment, safe_mode: bool) -> ExperimentResult:
        """Run credential leak experiment"""
        start_time = datetime.now()
        
        await asyncio.sleep(0.8)
        
        # Credential leaks should be detected quickly
        detection_time = random.uniform(0.5, 15)
        
        if detection_time < 5:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.AUTO_REMEDIATED
            alerts = [
                {"type": "secret_leak", "severity": "critical", "message": "Credentials detected in public location"},
                {"type": "credential_rotation", "severity": "high", "message": "Automatic credential rotation triggered"},
            ]
        elif detection_time < 10:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.CONTAINED
            alerts = [
                {"type": "secret_leak", "severity": "critical", "message": "Credentials detected in logs"},
            ]
        else:
            detection_outcome = DetectionOutcome.UNDETECTED
            response_outcome = ResponseOutcome.NOT_CONTAINED
            alerts = []
            
        resilience = 100 - (detection_time * 4)
        
        return ExperimentResult(
            experiment_id=experiment.experiment_id,
            status=ExperimentStatus.COMPLETED,
            start_time=start_time,
            end_time=datetime.now(),
            detection_outcome=detection_outcome,
            response_outcome=response_outcome,
            time_to_detect=timedelta(minutes=detection_time) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_respond=timedelta(minutes=detection_time + 2) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_contain=timedelta(minutes=5) if response_outcome in [ResponseOutcome.CONTAINED, ResponseOutcome.AUTO_REMEDIATED] else None,
            alerts_generated=alerts,
            actions_taken=["Credentials rotated", "Access reviewed", "Audit trail analyzed"] if alerts else [],
            impact_observed=["Credential exposure risk", "Potential unauthorized access window"],
            lessons_learned=["Implement credential scanning in CI/CD", "Enable secret rotation"],
            resilience_score=max(0, min(100, resilience))
        )
        
    async def _run_insider_threat(self, experiment: ChaosExperiment, safe_mode: bool) -> ExperimentResult:
        """Run insider threat experiment"""
        start_time = datetime.now()
        
        await asyncio.sleep(1.0)
        
        # Insider threats are harder to detect
        detection_time = random.uniform(5, 60)
        
        if detection_time < 15:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.CONTAINED
        elif detection_time < 30:
            detection_outcome = DetectionOutcome.PARTIALLY_DETECTED
            response_outcome = ResponseOutcome.PARTIALLY_CONTAINED
        else:
            detection_outcome = DetectionOutcome.UNDETECTED
            response_outcome = ResponseOutcome.NOT_CONTAINED
            
        alerts = [
            {"type": "ueba_anomaly", "severity": "high", "message": "Unusual data access pattern detected"},
            {"type": "dlp_alert", "severity": "medium", "message": "Large file download detected"},
        ] if detection_outcome != DetectionOutcome.UNDETECTED else []
        
        resilience = 100 - (detection_time * 1.5)
        
        return ExperimentResult(
            experiment_id=experiment.experiment_id,
            status=ExperimentStatus.COMPLETED,
            start_time=start_time,
            end_time=datetime.now(),
            detection_outcome=detection_outcome,
            response_outcome=response_outcome,
            time_to_detect=timedelta(minutes=detection_time) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_respond=timedelta(minutes=detection_time + 10) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_contain=timedelta(minutes=detection_time + 30) if response_outcome != ResponseOutcome.NOT_CONTAINED else None,
            alerts_generated=alerts,
            actions_taken=["Account suspended", "Session terminated", "Forensic capture initiated"] if alerts else [],
            impact_observed=["Data access during detection window", "Potential data exfiltration"],
            lessons_learned=["Enhance UEBA baselines", "Implement stricter DLP policies"],
            resilience_score=max(0, min(100, resilience))
        )
        
    async def _run_network_attack(self, experiment: ChaosExperiment, safe_mode: bool) -> ExperimentResult:
        """Run network attack experiment"""
        start_time = datetime.now()
        
        await asyncio.sleep(0.5)
        
        detection_time = random.uniform(0.5, 5)
        
        # Network attacks are usually detected quickly
        if detection_time < 1:
            detection_outcome = DetectionOutcome.BLOCKED
            response_outcome = ResponseOutcome.AUTO_REMEDIATED
        elif detection_time < 3:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.CONTAINED
        else:
            detection_outcome = DetectionOutcome.PARTIALLY_DETECTED
            response_outcome = ResponseOutcome.PARTIALLY_CONTAINED
            
        alerts = [
            {"type": "ids_alert", "severity": "high", "message": "Network scan detected"},
            {"type": "firewall_block", "severity": "medium", "message": "Source IP blocked"},
        ]
        
        resilience = 95 - (detection_time * 5)
        
        return ExperimentResult(
            experiment_id=experiment.experiment_id,
            status=ExperimentStatus.COMPLETED,
            start_time=start_time,
            end_time=datetime.now(),
            detection_outcome=detection_outcome,
            response_outcome=response_outcome,
            time_to_detect=timedelta(minutes=detection_time),
            time_to_respond=timedelta(minutes=detection_time + 1),
            time_to_contain=timedelta(minutes=detection_time + 2),
            alerts_generated=alerts,
            actions_taken=["Source blocked", "Threat intel updated", "Perimeter rules reviewed"],
            impact_observed=["Reconnaissance information leaked", "Attack surface mapped"],
            lessons_learned=["Reduce attack surface", "Implement port knocking"],
            resilience_score=max(0, min(100, resilience))
        )
        
    async def _run_data_exfil(self, experiment: ChaosExperiment, safe_mode: bool) -> ExperimentResult:
        """Run data exfiltration experiment"""
        start_time = datetime.now()
        
        await asyncio.sleep(0.8)
        
        detection_time = random.uniform(2, 30)
        
        if detection_time < 5:
            detection_outcome = DetectionOutcome.BLOCKED
            response_outcome = ResponseOutcome.AUTO_REMEDIATED
        elif detection_time < 15:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.CONTAINED
        elif detection_time < 25:
            detection_outcome = DetectionOutcome.PARTIALLY_DETECTED
            response_outcome = ResponseOutcome.PARTIALLY_CONTAINED
        else:
            detection_outcome = DetectionOutcome.UNDETECTED
            response_outcome = ResponseOutcome.NOT_CONTAINED
            
        alerts = [
            {"type": "dlp_alert", "severity": "critical", "message": "Sensitive data upload blocked"},
            {"type": "casb_alert", "severity": "high", "message": "Unauthorized cloud destination"},
        ] if detection_outcome != DetectionOutcome.UNDETECTED else []
        
        resilience = 100 - (detection_time * 3)
        
        return ExperimentResult(
            experiment_id=experiment.experiment_id,
            status=ExperimentStatus.COMPLETED,
            start_time=start_time,
            end_time=datetime.now(),
            detection_outcome=detection_outcome,
            response_outcome=response_outcome,
            time_to_detect=timedelta(minutes=detection_time) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_respond=timedelta(minutes=detection_time + 5) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_contain=timedelta(minutes=detection_time + 10) if response_outcome != ResponseOutcome.NOT_CONTAINED else None,
            alerts_generated=alerts,
            actions_taken=["Upload blocked", "User notified", "Incident created"] if alerts else [],
            impact_observed=["Potential data exposure during detection window"],
            lessons_learned=["Implement inline DLP", "Block personal cloud storage"],
            resilience_score=max(0, min(100, resilience))
        )
        
    async def _run_malware_injection(self, experiment: ChaosExperiment, safe_mode: bool) -> ExperimentResult:
        """Run malware injection experiment"""
        start_time = datetime.now()
        
        await asyncio.sleep(0.6)
        
        detection_time = random.uniform(0.1, 5)
        
        if detection_time < 0.5:
            detection_outcome = DetectionOutcome.BLOCKED
            response_outcome = ResponseOutcome.AUTO_REMEDIATED
        elif detection_time < 2:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.CONTAINED
        else:
            detection_outcome = DetectionOutcome.PARTIALLY_DETECTED
            response_outcome = ResponseOutcome.PARTIALLY_CONTAINED
            
        alerts = [
            {"type": "edr_alert", "severity": "critical", "message": "Malicious behavior detected"},
            {"type": "process_kill", "severity": "high", "message": "Malicious process terminated"},
        ]
        
        resilience = 98 - (detection_time * 8)
        
        return ExperimentResult(
            experiment_id=experiment.experiment_id,
            status=ExperimentStatus.COMPLETED,
            start_time=start_time,
            end_time=datetime.now(),
            detection_outcome=detection_outcome,
            response_outcome=response_outcome,
            time_to_detect=timedelta(seconds=detection_time * 60),
            time_to_respond=timedelta(seconds=detection_time * 60 + 30),
            time_to_contain=timedelta(seconds=detection_time * 60 + 60),
            alerts_generated=alerts,
            actions_taken=["Process terminated", "Host isolated", "Forensics collected"],
            impact_observed=["Temporary code execution", "Memory artifacts"],
            lessons_learned=["Enhance memory protection", "Improve behavioral detection"],
            resilience_score=max(0, min(100, resilience))
        )
        
    async def _run_config_drift(self, experiment: ChaosExperiment, safe_mode: bool) -> ExperimentResult:
        """Run configuration drift experiment"""
        start_time = datetime.now()
        
        await asyncio.sleep(0.5)
        
        detection_time = random.uniform(5, 120)  # Config drift often takes longer to detect
        
        if detection_time < 30:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.AUTO_REMEDIATED
        elif detection_time < 60:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.CONTAINED
        else:
            detection_outcome = DetectionOutcome.UNDETECTED
            response_outcome = ResponseOutcome.NOT_CONTAINED
            
        alerts = [
            {"type": "config_change", "severity": "medium", "message": "Configuration drift detected"},
        ] if detection_outcome != DetectionOutcome.UNDETECTED else []
        
        resilience = 100 - (detection_time * 0.7)
        
        return ExperimentResult(
            experiment_id=experiment.experiment_id,
            status=ExperimentStatus.COMPLETED,
            start_time=start_time,
            end_time=datetime.now(),
            detection_outcome=detection_outcome,
            response_outcome=response_outcome,
            time_to_detect=timedelta(minutes=detection_time) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_respond=timedelta(minutes=detection_time + 15) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_contain=timedelta(minutes=detection_time + 30) if response_outcome != ResponseOutcome.NOT_CONTAINED else None,
            alerts_generated=alerts,
            actions_taken=["Config restored", "Change audited"] if alerts else [],
            impact_observed=["Security control weakened during drift window"],
            lessons_learned=["Implement continuous compliance monitoring", "Enable config-as-code"],
            resilience_score=max(0, min(100, resilience))
        )
        
    async def _run_privilege_escalation(self, experiment: ChaosExperiment, safe_mode: bool) -> ExperimentResult:
        """Run privilege escalation experiment"""
        return await self._run_generic_experiment(experiment, safe_mode)
        
    async def _run_lateral_movement(self, experiment: ChaosExperiment, safe_mode: bool) -> ExperimentResult:
        """Run lateral movement experiment"""
        return await self._run_generic_experiment(experiment, safe_mode)
        
    async def _run_c2_communication(self, experiment: ChaosExperiment, safe_mode: bool) -> ExperimentResult:
        """Run C2 communication experiment"""
        start_time = datetime.now()
        
        await asyncio.sleep(0.7)
        
        detection_time = random.uniform(1, 30)
        
        if detection_time < 5:
            detection_outcome = DetectionOutcome.BLOCKED
            response_outcome = ResponseOutcome.AUTO_REMEDIATED
        elif detection_time < 15:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.CONTAINED
        else:
            detection_outcome = DetectionOutcome.UNDETECTED
            response_outcome = ResponseOutcome.NOT_CONTAINED
            
        alerts = [
            {"type": "c2_detection", "severity": "critical", "message": "C2 beacon traffic detected"},
            {"type": "host_isolation", "severity": "high", "message": "Host automatically isolated"},
        ] if detection_outcome != DetectionOutcome.UNDETECTED else []
        
        resilience = 100 - (detection_time * 2.5)
        
        return ExperimentResult(
            experiment_id=experiment.experiment_id,
            status=ExperimentStatus.COMPLETED,
            start_time=start_time,
            end_time=datetime.now(),
            detection_outcome=detection_outcome,
            response_outcome=response_outcome,
            time_to_detect=timedelta(minutes=detection_time) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_respond=timedelta(minutes=detection_time + 2) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_contain=timedelta(minutes=detection_time + 5) if response_outcome != ResponseOutcome.NOT_CONTAINED else None,
            alerts_generated=alerts,
            actions_taken=["Host isolated", "C2 blocked", "Investigation initiated"] if alerts else [],
            impact_observed=["Potential command execution during detection window"],
            lessons_learned=["Improve C2 traffic detection", "Deploy NDR with ML"],
            resilience_score=max(0, min(100, resilience))
        )
        
    async def _run_generic_experiment(self, experiment: ChaosExperiment, safe_mode: bool) -> ExperimentResult:
        """Run a generic experiment"""
        start_time = datetime.now()
        
        await asyncio.sleep(0.5)
        
        detection_time = random.uniform(2, 30)
        
        if detection_time < 10:
            detection_outcome = DetectionOutcome.DETECTED
            response_outcome = ResponseOutcome.CONTAINED
        elif detection_time < 20:
            detection_outcome = DetectionOutcome.PARTIALLY_DETECTED
            response_outcome = ResponseOutcome.PARTIALLY_CONTAINED
        else:
            detection_outcome = DetectionOutcome.UNDETECTED
            response_outcome = ResponseOutcome.NOT_CONTAINED
            
        alerts = [
            {"type": "security_alert", "severity": "medium", "message": f"Activity detected: {experiment.name}"},
        ] if detection_outcome != DetectionOutcome.UNDETECTED else []
        
        resilience = 100 - (detection_time * 2.5)
        
        return ExperimentResult(
            experiment_id=experiment.experiment_id,
            status=ExperimentStatus.COMPLETED,
            start_time=start_time,
            end_time=datetime.now(),
            detection_outcome=detection_outcome,
            response_outcome=response_outcome,
            time_to_detect=timedelta(minutes=detection_time) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_respond=timedelta(minutes=detection_time + 5) if detection_outcome != DetectionOutcome.UNDETECTED else None,
            time_to_contain=timedelta(minutes=detection_time + 15) if response_outcome != ResponseOutcome.NOT_CONTAINED else None,
            alerts_generated=alerts,
            actions_taken=["Alert reviewed", "Containment initiated"] if alerts else [],
            impact_observed=["Security control tested"],
            lessons_learned=["Review detection capabilities"],
            resilience_score=max(0, min(100, resilience))
        )
        
    def _update_metrics(self, result: ExperimentResult):
        """Update metrics based on experiment result"""
        if result.time_to_detect:
            self.metrics["mttd"].current_value = (
                self.metrics["mttd"].current_value * 0.9 +
                result.time_to_detect.total_seconds() / 60 * 0.1
            )
            
        if result.time_to_respond:
            self.metrics["mttr"].current_value = (
                self.metrics["mttr"].current_value * 0.9 +
                result.time_to_respond.total_seconds() / 60 * 0.1
            )
            
        if result.detection_outcome in [DetectionOutcome.DETECTED, DetectionOutcome.BLOCKED]:
            current_rate = self.metrics["detection_rate"].current_value
            self.metrics["detection_rate"].current_value = min(100, current_rate * 0.95 + 100 * 0.05)
        else:
            current_rate = self.metrics["detection_rate"].current_value
            self.metrics["detection_rate"].current_value = max(0, current_rate * 0.95 + 0 * 0.05)
            
        # Update resilience index
        self.metrics["resilience_index"].current_value = (
            self.metrics["resilience_index"].current_value * 0.9 +
            result.resilience_score * 0.1
        )
        
    async def run_game_day(self, gameday_id: str) -> Dict[str, Any]:
        """Run a chaos game day"""
        if gameday_id not in self.game_days:
            raise ValueError(f"Game day {gameday_id} not found")
            
        gameday = self.game_days[gameday_id]
        gameday.status = "in_progress"
        
        results = []
        for exp_id in gameday.experiments:
            if exp_id in self.experiments:
                result = await self.run_experiment(exp_id, safe_mode=True)
                results.append(result)
                
        # Aggregate results
        detected = sum(1 for r in results if r.detection_outcome in [DetectionOutcome.DETECTED, DetectionOutcome.BLOCKED])
        contained = sum(1 for r in results if r.response_outcome in [ResponseOutcome.CONTAINED, ResponseOutcome.AUTO_REMEDIATED])
        avg_resilience = sum(r.resilience_score for r in results) / max(len(results), 1)
        
        gameday.status = "completed"
        gameday.results = {
            "experiments_run": len(results),
            "detected": detected,
            "contained": contained,
            "average_resilience": round(avg_resilience, 1),
            "results": [r.experiment_id for r in results]
        }
        
        return gameday.results
        
    def schedule_game_day(
        self,
        name: str,
        scheduled_date: datetime,
        experiment_ids: List[str],
        participants: List[str] = None,
        objectives: List[str] = None
    ) -> GameDay:
        """Schedule a chaos game day"""
        gameday = GameDay(
            gameday_id=f"GD-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            name=name,
            scheduled_date=scheduled_date,
            duration_hours=4,
            experiments=experiment_ids,
            participants=participants or ["security-team"],
            objectives=objectives or ["Test detection capabilities", "Measure response times"],
            status="scheduled"
        )
        
        self.game_days[gameday.gameday_id] = gameday
        return gameday
        
    def generate_report(self, days: int = 30) -> ChaosReport:
        """Generate chaos engineering report"""
        period_start = datetime.now() - timedelta(days=days)
        period_end = datetime.now()
        
        # Filter results in period
        period_results = [r for r in self.results if r.start_time >= period_start]
        
        if not period_results:
            # Use demo data
            period_results = self.results
            
        detected = sum(1 for r in period_results if r.detection_outcome in [DetectionOutcome.DETECTED, DetectionOutcome.BLOCKED])
        contained = sum(1 for r in period_results if r.response_outcome in [ResponseOutcome.CONTAINED, ResponseOutcome.AUTO_REMEDIATED])
        
        detection_times = [r.time_to_detect.total_seconds() / 60 for r in period_results if r.time_to_detect]
        response_times = [r.time_to_respond.total_seconds() / 60 for r in period_results if r.time_to_respond]
        
        avg_detection = timedelta(minutes=sum(detection_times) / max(len(detection_times), 1))
        avg_response = timedelta(minutes=sum(response_times) / max(len(response_times), 1))
        
        resilience_scores = [r.resilience_score for r in period_results]
        avg_resilience = sum(resilience_scores) / max(len(resilience_scores), 1)
        
        # Find weakest controls
        control_failures = {}
        for result in period_results:
            if result.detection_outcome == DetectionOutcome.UNDETECTED:
                exp = self.experiments.get(result.experiment_id)
                if exp:
                    for system in exp.target_systems:
                        control_failures[system] = control_failures.get(system, 0) + 1
                        
        weakest = sorted(control_failures.items(), key=lambda x: x[1], reverse=True)[:5]
        
        recommendations = [
            f"Focus on improving detection in: {', '.join([w[0] for w in weakest[:3]])}",
            f"Current MTTD ({avg_detection.total_seconds()/60:.1f}m) exceeds target (5m) - implement faster detection",
            "Increase experiment frequency to improve resilience baseline",
            "Run more insider threat scenarios - historically underdetected",
        ]
        
        return ChaosReport(
            report_id=f"CHAOS-REPORT-{datetime.now().strftime('%Y%m%d')}",
            period_start=period_start,
            period_end=period_end,
            experiments_run=len(period_results),
            experiments_detected=detected,
            experiments_contained=contained,
            average_detection_time=avg_detection,
            average_response_time=avg_response,
            resilience_score=round(avg_resilience, 1),
            weakest_controls=[w[0] for w in weakest],
            recommendations=recommendations
        )
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get chaos engineering statistics"""
        return {
            "total_experiments": len(self.experiments),
            "experiments_run": len(self.results),
            "security_controls": len(self.controls),
            "active_controls": sum(1 for c in self.controls.values() if c.enabled),
            "scheduled_game_days": len([g for g in self.game_days.values() if g.status == "scheduled"]),
            "completed_game_days": len([g for g in self.game_days.values() if g.status == "completed"]),
            "detection_rate": self.metrics["detection_rate"].current_value,
            "mean_time_to_detect": self.metrics["mttd"].current_value,
            "resilience_index": self.metrics["resilience_index"].current_value,
        }


async def main():
    """Test the Security Chaos Engineering engine"""
    print("=" * 60)
    print("HydraRecon Security Chaos Engineering")
    print("=" * 60)
    
    chaos = SecurityChaos()
    
    # Get statistics
    stats = chaos.get_statistics()
    print(f"\n[*] Chaos Engineering Statistics:")
    print(f"    Total Experiments: {stats['total_experiments']}")
    print(f"    Security Controls: {stats['security_controls']} ({stats['active_controls']} active)")
    print(f"    Detection Rate: {stats['detection_rate']:.1f}%")
    print(f"    Mean Time to Detect: {stats['mean_time_to_detect']:.1f} minutes")
    
    # Run some experiments
    print(f"\n[*] Running Chaos Experiments...")
    
    experiments_to_run = ["CHAOS-001", "CHAOS-003", "CHAOS-005", "CHAOS-011"]
    
    for exp_id in experiments_to_run:
        if exp_id in chaos.experiments:
            exp = chaos.experiments[exp_id]
            result = await chaos.run_experiment(exp_id, safe_mode=True)
            
            detection_icon = {
                DetectionOutcome.DETECTED: "✅",
                DetectionOutcome.BLOCKED: "🛡️",
                DetectionOutcome.PARTIALLY_DETECTED: "⚠️",
                DetectionOutcome.UNDETECTED: "❌",
            }
            
            icon = detection_icon.get(result.detection_outcome, "❓")
            print(f"    {icon} {exp.name}")
            print(f"       Detection: {result.detection_outcome.value} | Response: {result.response_outcome.value}")
            if result.time_to_detect:
                print(f"       TTD: {result.time_to_detect.total_seconds()/60:.1f}m | Resilience: {result.resilience_score:.0f}/100")
                
    # Schedule a game day
    print(f"\n[*] Scheduling Chaos Game Day...")
    gameday = chaos.schedule_game_day(
        name="Q1 Security Resilience Game Day",
        scheduled_date=datetime.now() + timedelta(days=7),
        experiment_ids=["CHAOS-001", "CHAOS-003", "CHAOS-005", "CHAOS-007", "CHAOS-009"],
        participants=["security-team", "soc-team", "it-ops"],
        objectives=["Test detection < 5 minutes", "Validate auto-remediation", "Measure MTTC"]
    )
    print(f"    Game Day ID: {gameday.gameday_id}")
    print(f"    Scheduled: {gameday.scheduled_date}")
    print(f"    Experiments: {len(gameday.experiments)}")
    
    # Run the game day (simulation)
    print(f"\n[*] Simulating Game Day Execution...")
    gd_results = await chaos.run_game_day(gameday.gameday_id)
    print(f"    Experiments Run: {gd_results['experiments_run']}")
    print(f"    Detected: {gd_results['detected']}/{gd_results['experiments_run']}")
    print(f"    Contained: {gd_results['contained']}/{gd_results['experiments_run']}")
    print(f"    Average Resilience: {gd_results['average_resilience']}/100")
    
    # Generate report
    print(f"\n[*] Generating Chaos Engineering Report...")
    report = chaos.generate_report(days=30)
    print(f"    Report ID: {report.report_id}")
    print(f"    Experiments Run: {report.experiments_run}")
    print(f"    Detection Rate: {report.experiments_detected}/{report.experiments_run}")
    print(f"    Avg Detection Time: {report.average_detection_time.total_seconds()/60:.1f} minutes")
    print(f"    Avg Response Time: {report.average_response_time.total_seconds()/60:.1f} minutes")
    print(f"    Resilience Score: {report.resilience_score}/100")
    
    print(f"\n[*] Recommendations:")
    for i, rec in enumerate(report.recommendations[:3], 1):
        print(f"    {i}. {rec}")
        
    # Updated metrics
    updated_stats = chaos.get_statistics()
    print(f"\n[*] Updated Metrics:")
    print(f"    Detection Rate: {updated_stats['detection_rate']:.1f}%")
    print(f"    MTTD: {updated_stats['mean_time_to_detect']:.1f} minutes")
    print(f"    Resilience Index: {updated_stats['resilience_index']:.1f}/100")
    
    print("\n" + "=" * 60)
    print("Security Chaos Engineering Test Complete")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
