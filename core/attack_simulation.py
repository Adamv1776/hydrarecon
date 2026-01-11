"""
Attack Simulation Module for HydraRecon
Automated penetration testing scenarios and attack path analysis
"""

import asyncio
import json
import random
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import uuid
import logging

logger = logging.getLogger(__name__)


class AttackCategory(Enum):
    """Categories of attack simulations"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class SimulationStatus(Enum):
    """Status of attack simulation"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AttackResult(Enum):
    """Result of individual attack"""
    PENDING = "pending"
    SUCCESS = "success"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    DETECTED = "detected"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(Enum):
    """Severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AttackTechnique:
    """MITRE ATT&CK technique"""
    id: str  # e.g., T1059
    name: str
    tactic: AttackCategory
    description: str
    platforms: List[str] = field(default_factory=list)
    permissions_required: List[str] = field(default_factory=list)
    detection: str = ""
    mitigations: List[str] = field(default_factory=list)


@dataclass
class AttackStep:
    """Individual step in an attack scenario"""
    id: str
    name: str
    technique: AttackTechnique
    target: str
    command: str = ""
    expected_output: str = ""
    actual_output: str = ""
    result: AttackResult = AttackResult.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    detection_triggered: bool = False
    artifacts_created: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class AttackPath:
    """Attack path from initial access to objective"""
    id: str
    name: str
    description: str
    steps: List[AttackStep] = field(default_factory=list)
    success_probability: float = 0.0
    risk_score: float = 0.0
    mitigations: List[str] = field(default_factory=list)


@dataclass
class AttackScenario:
    """Complete attack simulation scenario"""
    id: str
    name: str
    description: str
    category: AttackCategory
    severity: Severity
    
    # Targets
    target_hosts: List[str] = field(default_factory=list)
    target_networks: List[str] = field(default_factory=list)
    target_services: List[str] = field(default_factory=list)
    
    # Attack configuration
    techniques: List[AttackTechnique] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    steps: List[AttackStep] = field(default_factory=list)
    
    # Execution
    status: SimulationStatus = SimulationStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    current_step: int = 0
    
    # Results
    total_steps: int = 0
    successful_steps: int = 0
    blocked_steps: int = 0
    detected_steps: int = 0
    
    # Cleanup
    cleanup_required: bool = True
    cleanup_completed: bool = False
    artifacts: List[str] = field(default_factory=list)
    
    # Tags
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""


@dataclass
class SimulationReport:
    """Report for completed simulation"""
    scenario_id: str
    scenario_name: str
    executive_summary: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    
    # Metrics
    total_techniques: int = 0
    successful_techniques: int = 0
    blocked_techniques: int = 0
    detected_techniques: int = 0
    detection_rate: float = 0.0
    success_rate: float = 0.0
    
    # Findings
    critical_findings: List[Dict] = field(default_factory=list)
    high_findings: List[Dict] = field(default_factory=list)
    medium_findings: List[Dict] = field(default_factory=list)
    low_findings: List[Dict] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Attack paths
    successful_paths: List[str] = field(default_factory=list)
    blocked_paths: List[str] = field(default_factory=list)


class AttackLibrary:
    """Library of predefined attack techniques and scenarios"""
    
    def __init__(self):
        self.techniques: Dict[str, AttackTechnique] = {}
        self.scenarios: Dict[str, Dict] = {}
        self._load_mitre_techniques()
        self._load_predefined_scenarios()
    
    def _load_mitre_techniques(self):
        """Load MITRE ATT&CK techniques"""
        techniques = [
            # Reconnaissance
            AttackTechnique(
                id="T1595",
                name="Active Scanning",
                tactic=AttackCategory.RECONNAISSANCE,
                description="Adversaries may execute active reconnaissance scans to gather information",
                platforms=["PRE"],
                detection="Monitor for suspicious network traffic patterns"
            ),
            AttackTechnique(
                id="T1592",
                name="Gather Victim Host Information",
                tactic=AttackCategory.RECONNAISSANCE,
                description="Gather information about victim hosts",
                platforms=["PRE"],
                detection="Monitor for external reconnaissance activity"
            ),
            
            # Initial Access
            AttackTechnique(
                id="T1566",
                name="Phishing",
                tactic=AttackCategory.INITIAL_ACCESS,
                description="Phishing attacks to gain initial access",
                platforms=["Windows", "macOS", "Linux"],
                detection="Email analysis and user training"
            ),
            AttackTechnique(
                id="T1190",
                name="Exploit Public-Facing Application",
                tactic=AttackCategory.INITIAL_ACCESS,
                description="Exploit vulnerabilities in internet-facing applications",
                platforms=["Windows", "Linux", "macOS"],
                detection="Web application firewall, intrusion detection"
            ),
            AttackTechnique(
                id="T1133",
                name="External Remote Services",
                tactic=AttackCategory.INITIAL_ACCESS,
                description="Leverage external-facing remote services",
                platforms=["Windows", "Linux"],
                detection="Monitor authentication logs for anomalies"
            ),
            
            # Execution
            AttackTechnique(
                id="T1059",
                name="Command and Scripting Interpreter",
                tactic=AttackCategory.EXECUTION,
                description="Use command-line interfaces or scripting",
                platforms=["Windows", "macOS", "Linux"],
                permissions_required=["User"],
                detection="Script block logging, command-line auditing"
            ),
            AttackTechnique(
                id="T1204",
                name="User Execution",
                tactic=AttackCategory.EXECUTION,
                description="Rely on user action to execute",
                platforms=["Windows", "macOS", "Linux"],
                detection="User behavior analytics"
            ),
            
            # Persistence
            AttackTechnique(
                id="T1547",
                name="Boot or Logon Autostart Execution",
                tactic=AttackCategory.PERSISTENCE,
                description="Configure system to run on startup",
                platforms=["Windows", "macOS", "Linux"],
                permissions_required=["User", "Administrator"],
                detection="Monitor startup locations"
            ),
            AttackTechnique(
                id="T1053",
                name="Scheduled Task/Job",
                tactic=AttackCategory.PERSISTENCE,
                description="Abuse task scheduling functionality",
                platforms=["Windows", "Linux", "macOS"],
                permissions_required=["Administrator", "User"],
                detection="Monitor scheduled task creation"
            ),
            
            # Privilege Escalation
            AttackTechnique(
                id="T1068",
                name="Exploitation for Privilege Escalation",
                tactic=AttackCategory.PRIVILEGE_ESCALATION,
                description="Exploit vulnerabilities to elevate privileges",
                platforms=["Windows", "Linux", "macOS"],
                detection="Endpoint detection and response"
            ),
            AttackTechnique(
                id="T1078",
                name="Valid Accounts",
                tactic=AttackCategory.PRIVILEGE_ESCALATION,
                description="Use valid accounts to escalate privileges",
                platforms=["Windows", "Linux", "macOS"],
                detection="Monitor account usage patterns"
            ),
            
            # Credential Access
            AttackTechnique(
                id="T1003",
                name="OS Credential Dumping",
                tactic=AttackCategory.CREDENTIAL_ACCESS,
                description="Dump credentials from operating system",
                platforms=["Windows", "Linux", "macOS"],
                permissions_required=["Administrator", "SYSTEM"],
                detection="Monitor for credential access tools"
            ),
            AttackTechnique(
                id="T1110",
                name="Brute Force",
                tactic=AttackCategory.CREDENTIAL_ACCESS,
                description="Systematically guess passwords",
                platforms=["Windows", "Linux", "macOS"],
                detection="Monitor for multiple failed authentication attempts"
            ),
            
            # Lateral Movement
            AttackTechnique(
                id="T1021",
                name="Remote Services",
                tactic=AttackCategory.LATERAL_MOVEMENT,
                description="Use remote services for lateral movement",
                platforms=["Windows", "Linux", "macOS"],
                detection="Monitor remote access activity"
            ),
            AttackTechnique(
                id="T1570",
                name="Lateral Tool Transfer",
                tactic=AttackCategory.LATERAL_MOVEMENT,
                description="Transfer tools between systems",
                platforms=["Windows", "Linux", "macOS"],
                detection="Monitor file transfers between internal systems"
            ),
            
            # Exfiltration
            AttackTechnique(
                id="T1048",
                name="Exfiltration Over Alternative Protocol",
                tactic=AttackCategory.EXFILTRATION,
                description="Steal data over non-C2 protocol",
                platforms=["Windows", "Linux", "macOS"],
                detection="Monitor for unusual outbound traffic"
            ),
            AttackTechnique(
                id="T1567",
                name="Exfiltration Over Web Service",
                tactic=AttackCategory.EXFILTRATION,
                description="Exfiltrate data to cloud storage",
                platforms=["Windows", "Linux", "macOS"],
                detection="Monitor cloud service access"
            ),
        ]
        
        for tech in techniques:
            self.techniques[tech.id] = tech
    
    def _load_predefined_scenarios(self):
        """Load predefined attack scenarios"""
        self.scenarios = {
            "ransomware_simulation": {
                "name": "Ransomware Attack Simulation",
                "description": "Simulates a ransomware attack chain from initial access to encryption",
                "category": AttackCategory.IMPACT,
                "severity": Severity.CRITICAL,
                "techniques": ["T1566", "T1059", "T1547", "T1003", "T1486"],
                "tags": ["ransomware", "malware", "encryption"]
            },
            "apt_simulation": {
                "name": "APT Simulation",
                "description": "Simulates advanced persistent threat attack patterns",
                "category": AttackCategory.PERSISTENCE,
                "severity": Severity.CRITICAL,
                "techniques": ["T1595", "T1190", "T1059", "T1053", "T1003", "T1021", "T1048"],
                "tags": ["apt", "advanced", "persistent"]
            },
            "credential_theft": {
                "name": "Credential Theft Campaign",
                "description": "Simulates credential harvesting and abuse",
                "category": AttackCategory.CREDENTIAL_ACCESS,
                "severity": Severity.HIGH,
                "techniques": ["T1566", "T1003", "T1110", "T1078"],
                "tags": ["credentials", "passwords", "authentication"]
            },
            "lateral_movement": {
                "name": "Lateral Movement Exercise",
                "description": "Tests ability to move laterally within network",
                "category": AttackCategory.LATERAL_MOVEMENT,
                "severity": Severity.HIGH,
                "techniques": ["T1078", "T1021", "T1570", "T1003"],
                "tags": ["lateral", "movement", "network"]
            },
            "data_exfiltration": {
                "name": "Data Exfiltration Simulation",
                "description": "Simulates data theft scenarios",
                "category": AttackCategory.EXFILTRATION,
                "severity": Severity.CRITICAL,
                "techniques": ["T1048", "T1567", "T1041"],
                "tags": ["data", "exfiltration", "theft"]
            },
            "insider_threat": {
                "name": "Insider Threat Simulation",
                "description": "Simulates malicious insider activity",
                "category": AttackCategory.COLLECTION,
                "severity": Severity.HIGH,
                "techniques": ["T1078", "T1083", "T1039", "T1567"],
                "tags": ["insider", "threat", "user"]
            },
            "phishing_campaign": {
                "name": "Phishing Campaign Simulation",
                "description": "Simulates phishing attack scenarios",
                "category": AttackCategory.INITIAL_ACCESS,
                "severity": Severity.MEDIUM,
                "techniques": ["T1566", "T1204", "T1059"],
                "tags": ["phishing", "email", "social"]
            },
            "privilege_escalation": {
                "name": "Privilege Escalation Test",
                "description": "Tests privilege escalation vulnerabilities",
                "category": AttackCategory.PRIVILEGE_ESCALATION,
                "severity": Severity.HIGH,
                "techniques": ["T1068", "T1078", "T1548"],
                "tags": ["privilege", "escalation", "elevation"]
            }
        }
    
    def get_technique(self, technique_id: str) -> Optional[AttackTechnique]:
        """Get technique by ID"""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: AttackCategory) -> List[AttackTechnique]:
        """Get all techniques for a tactic"""
        return [t for t in self.techniques.values() if t.tactic == tactic]
    
    def get_scenario_template(self, scenario_id: str) -> Optional[Dict]:
        """Get predefined scenario template"""
        return self.scenarios.get(scenario_id)
    
    def list_scenarios(self) -> List[Dict]:
        """List all available scenario templates"""
        return [
            {"id": k, **v}
            for k, v in self.scenarios.items()
        ]


class AttackSimulationEngine:
    """Main attack simulation engine"""
    
    def __init__(self):
        self.library = AttackLibrary()
        self.scenarios: Dict[str, AttackScenario] = {}
        self.active_scenario: Optional[str] = None
        self._callbacks: List[Callable] = []
        self._lock = asyncio.Lock()
        self._cancelled = False
    
    def add_callback(self, callback: Callable):
        """Add progress callback"""
        self._callbacks.append(callback)
    
    def _notify(self, event_type: str, data: Any):
        """Notify callbacks"""
        for callback in self._callbacks:
            try:
                callback(event_type, data)
            except Exception:
                pass
    
    def create_scenario(
        self,
        name: str,
        description: str,
        template_id: str = None,
        targets: List[str] = None,
        techniques: List[str] = None,
        category: AttackCategory = AttackCategory.RECONNAISSANCE,
        severity: Severity = Severity.MEDIUM
    ) -> AttackScenario:
        """Create a new attack scenario"""
        scenario_id = str(uuid.uuid4())
        
        # Load template if specified
        if template_id:
            template = self.library.get_scenario_template(template_id)
            if template:
                name = name or template["name"]
                description = description or template["description"]
                techniques = techniques or template.get("techniques", [])
                category = template.get("category", category)
                severity = template.get("severity", severity)
        
        # Build technique list
        attack_techniques = []
        steps = []
        
        for tech_id in (techniques or []):
            technique = self.library.get_technique(tech_id)
            if technique:
                attack_techniques.append(technique)
                
                # Create step for each technique
                step = AttackStep(
                    id=str(uuid.uuid4()),
                    name=f"Execute {technique.name}",
                    technique=technique,
                    target=targets[0] if targets else "localhost"
                )
                steps.append(step)
        
        scenario = AttackScenario(
            id=scenario_id,
            name=name,
            description=description,
            category=category,
            severity=severity,
            target_hosts=targets or [],
            techniques=attack_techniques,
            steps=steps,
            total_steps=len(steps)
        )
        
        self.scenarios[scenario_id] = scenario
        return scenario
    
    def create_custom_scenario(
        self,
        name: str,
        steps: List[Dict[str, Any]]
    ) -> AttackScenario:
        """Create custom scenario with specific steps"""
        scenario_id = str(uuid.uuid4())
        
        attack_steps = []
        for step_config in steps:
            tech_id = step_config.get("technique_id")
            technique = self.library.get_technique(tech_id)
            
            step = AttackStep(
                id=str(uuid.uuid4()),
                name=step_config.get("name", "Custom Step"),
                technique=technique,
                target=step_config.get("target", "localhost"),
                command=step_config.get("command", ""),
                expected_output=step_config.get("expected_output", "")
            )
            attack_steps.append(step)
        
        scenario = AttackScenario(
            id=scenario_id,
            name=name,
            description="Custom attack scenario",
            category=AttackCategory.EXECUTION,
            severity=Severity.HIGH,
            steps=attack_steps,
            total_steps=len(attack_steps)
        )
        
        self.scenarios[scenario_id] = scenario
        return scenario
    
    async def run_scenario(
        self,
        scenario_id: str,
        safe_mode: bool = True,
        callback: Callable = None
    ) -> SimulationReport:
        """Execute attack scenario"""
        if scenario_id not in self.scenarios:
            raise ValueError(f"Scenario {scenario_id} not found")
        
        scenario = self.scenarios[scenario_id]
        
        async with self._lock:
            self.active_scenario = scenario_id
            self._cancelled = False
            
            scenario.status = SimulationStatus.RUNNING
            scenario.start_time = datetime.now()
            
            self._notify("started", {"scenario_id": scenario_id})
            
            try:
                for i, step in enumerate(scenario.steps):
                    if self._cancelled:
                        scenario.status = SimulationStatus.CANCELLED
                        break
                    
                    scenario.current_step = i
                    self._notify("step_started", {
                        "step": i + 1,
                        "total": len(scenario.steps),
                        "name": step.name
                    })
                    
                    # Execute step
                    result = await self._execute_step(step, safe_mode)
                    
                    # Update counters
                    if result == AttackResult.SUCCESS:
                        scenario.successful_steps += 1
                    elif result == AttackResult.BLOCKED:
                        scenario.blocked_steps += 1
                    elif result == AttackResult.DETECTED:
                        scenario.detected_steps += 1
                    
                    self._notify("step_completed", {
                        "step": i + 1,
                        "result": result.value,
                        "name": step.name
                    })
                    
                    if callback:
                        callback(i + 1, len(scenario.steps), step, result)
                    
                    # Small delay between steps
                    await asyncio.sleep(0.5)
                
                if scenario.status != SimulationStatus.CANCELLED:
                    scenario.status = SimulationStatus.COMPLETED
                
            except Exception as e:
                scenario.status = SimulationStatus.FAILED
                logger.error(f"Scenario execution failed: {e}")
                self._notify("error", {"error": str(e)})
            
            scenario.end_time = datetime.now()
            self.active_scenario = None
        
        # Generate report
        report = self._generate_report(scenario)
        self._notify("completed", {"report": report})
        
        return report
    
    async def _execute_step(
        self,
        step: AttackStep,
        safe_mode: bool = True
    ) -> AttackResult:
        """Execute individual attack step"""
        step.start_time = datetime.now()
        
        try:
            if safe_mode:
                # In safe mode, simulate the attack without actually executing
                result = await self._simulate_step(step)
            else:
                # Actually execute the attack command
                result = await self._real_execute_step(step)
            
            step.result = result
            
        except Exception as e:
            step.result = AttackResult.FAILED
            step.notes = str(e)
            result = AttackResult.FAILED
        
        step.end_time = datetime.now()
        return result
    
    async def _simulate_step(self, step: AttackStep) -> AttackResult:
        """Simulate attack step (safe mode)"""
        # Simulate based on technique
        technique = step.technique
        
        if not technique:
            return AttackResult.SKIPPED
        
        # Simulate random outcomes based on typical success rates
        success_rates = {
            AttackCategory.RECONNAISSANCE: 0.9,
            AttackCategory.INITIAL_ACCESS: 0.6,
            AttackCategory.EXECUTION: 0.75,
            AttackCategory.PERSISTENCE: 0.65,
            AttackCategory.PRIVILEGE_ESCALATION: 0.5,
            AttackCategory.DEFENSE_EVASION: 0.7,
            AttackCategory.CREDENTIAL_ACCESS: 0.55,
            AttackCategory.DISCOVERY: 0.85,
            AttackCategory.LATERAL_MOVEMENT: 0.6,
            AttackCategory.COLLECTION: 0.8,
            AttackCategory.EXFILTRATION: 0.5,
            AttackCategory.IMPACT: 0.4
        }
        
        success_rate = success_rates.get(technique.tactic, 0.5)
        detection_rate = 1 - success_rate
        
        # Simulate with some randomness
        roll = random.random()
        
        if roll < success_rate * 0.8:
            step.actual_output = f"[SIMULATED] {technique.name} executed successfully"
            return AttackResult.SUCCESS
        elif roll < success_rate:
            step.actual_output = f"[SIMULATED] {technique.name} partially successful"
            return AttackResult.PARTIAL
        elif roll < success_rate + detection_rate * 0.5:
            step.detection_triggered = True
            step.actual_output = f"[SIMULATED] {technique.name} was detected"
            return AttackResult.DETECTED
        else:
            step.actual_output = f"[SIMULATED] {technique.name} was blocked"
            return AttackResult.BLOCKED
    
    async def _real_execute_step(self, step: AttackStep) -> AttackResult:
        """Actually execute attack step (dangerous!)"""
        if not step.command:
            return AttackResult.SKIPPED
        
        try:
            proc = await asyncio.create_subprocess_shell(
                step.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            
            step.actual_output = stdout.decode() + stderr.decode()
            
            if proc.returncode == 0:
                if step.expected_output and step.expected_output in step.actual_output:
                    return AttackResult.SUCCESS
                return AttackResult.PARTIAL
            else:
                return AttackResult.FAILED
                
        except asyncio.TimeoutError:
            step.notes = "Command timed out"
            return AttackResult.FAILED
        except Exception as e:
            step.notes = str(e)
            return AttackResult.FAILED
    
    def pause_scenario(self, scenario_id: str):
        """Pause running scenario"""
        if scenario_id in self.scenarios:
            scenario = self.scenarios[scenario_id]
            if scenario.status == SimulationStatus.RUNNING:
                scenario.status = SimulationStatus.PAUSED
    
    def cancel_scenario(self, scenario_id: str):
        """Cancel running scenario"""
        self._cancelled = True
        if scenario_id in self.scenarios:
            scenario = self.scenarios[scenario_id]
            scenario.status = SimulationStatus.CANCELLED
    
    def _generate_report(self, scenario: AttackScenario) -> SimulationReport:
        """Generate simulation report"""
        duration = 0.0
        if scenario.start_time and scenario.end_time:
            duration = (scenario.end_time - scenario.start_time).total_seconds()
        
        total = len(scenario.steps)
        detection_rate = scenario.detected_steps / total if total > 0 else 0
        success_rate = scenario.successful_steps / total if total > 0 else 0
        
        # Categorize findings
        critical_findings = []
        high_findings = []
        medium_findings = []
        low_findings = []
        
        for step in scenario.steps:
            if step.result == AttackResult.SUCCESS:
                finding = {
                    "technique": step.technique.id if step.technique else "Unknown",
                    "name": step.name,
                    "target": step.target,
                    "impact": "Successful execution indicates vulnerability"
                }
                
                if step.technique:
                    if step.technique.tactic in [AttackCategory.CREDENTIAL_ACCESS, 
                                                  AttackCategory.EXFILTRATION,
                                                  AttackCategory.IMPACT]:
                        critical_findings.append(finding)
                    elif step.technique.tactic in [AttackCategory.PRIVILEGE_ESCALATION,
                                                    AttackCategory.LATERAL_MOVEMENT]:
                        high_findings.append(finding)
                    elif step.technique.tactic in [AttackCategory.PERSISTENCE,
                                                    AttackCategory.DEFENSE_EVASION]:
                        medium_findings.append(finding)
                    else:
                        low_findings.append(finding)
        
        # Generate recommendations
        recommendations = []
        
        if scenario.successful_steps > 0:
            recommendations.append("Review and patch systems where attacks succeeded")
        
        if scenario.blocked_steps < total * 0.5:
            recommendations.append("Improve blocking controls and security configurations")
        
        if detection_rate < 0.5:
            recommendations.append("Enhance detection capabilities and monitoring")
        
        if critical_findings:
            recommendations.append("Prioritize remediation of critical findings immediately")
        
        # Generate executive summary
        summary = f"""
Attack simulation '{scenario.name}' completed with the following results:

- Total techniques tested: {total}
- Successful attacks: {scenario.successful_steps} ({success_rate*100:.1f}%)
- Blocked attacks: {scenario.blocked_steps}
- Detected attacks: {scenario.detected_steps} ({detection_rate*100:.1f}%)

Critical findings: {len(critical_findings)}
High severity findings: {len(high_findings)}
Medium severity findings: {len(medium_findings)}
Low severity findings: {len(low_findings)}

Overall security posture: {'Needs Improvement' if success_rate > 0.5 else 'Acceptable' if success_rate > 0.2 else 'Good'}
"""
        
        return SimulationReport(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            executive_summary=summary.strip(),
            start_time=scenario.start_time or datetime.now(),
            end_time=scenario.end_time or datetime.now(),
            duration_seconds=duration,
            total_techniques=total,
            successful_techniques=scenario.successful_steps,
            blocked_techniques=scenario.blocked_steps,
            detected_techniques=scenario.detected_steps,
            detection_rate=detection_rate,
            success_rate=success_rate,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            recommendations=recommendations
        )
    
    def get_scenario(self, scenario_id: str) -> Optional[AttackScenario]:
        """Get scenario by ID"""
        return self.scenarios.get(scenario_id)
    
    def list_scenarios(self) -> List[AttackScenario]:
        """List all scenarios"""
        return list(self.scenarios.values())
    
    def get_templates(self) -> List[Dict]:
        """Get available scenario templates"""
        return self.library.list_scenarios()
    
    def get_techniques(self, tactic: AttackCategory = None) -> List[AttackTechnique]:
        """Get available techniques"""
        if tactic:
            return self.library.get_techniques_by_tactic(tactic)
        return list(self.library.techniques.values())
    
    def analyze_attack_paths(self, target: str) -> List[AttackPath]:
        """Analyze potential attack paths to target"""
        paths = []
        
        # Generate common attack paths
        common_paths = [
            {
                "name": "External to Internal via Web App",
                "steps": ["T1595", "T1190", "T1059", "T1003", "T1021"],
                "description": "Attack path through web application vulnerability"
            },
            {
                "name": "Phishing to Domain Admin",
                "steps": ["T1566", "T1204", "T1059", "T1547", "T1003", "T1078"],
                "description": "Attack path from phishing to domain compromise"
            },
            {
                "name": "VPN Compromise",
                "steps": ["T1133", "T1078", "T1021", "T1570"],
                "description": "Attack path through VPN access"
            }
        ]
        
        for path_config in common_paths:
            steps = []
            for tech_id in path_config["steps"]:
                technique = self.library.get_technique(tech_id)
                if technique:
                    step = AttackStep(
                        id=str(uuid.uuid4()),
                        name=technique.name,
                        technique=technique,
                        target=target
                    )
                    steps.append(step)
            
            path = AttackPath(
                id=str(uuid.uuid4()),
                name=path_config["name"],
                description=path_config["description"],
                steps=steps,
                success_probability=random.uniform(0.3, 0.7),
                risk_score=random.uniform(5.0, 9.0)
            )
            paths.append(path)
        
        return paths
    
    def export_report(self, report: SimulationReport, format: str = "json") -> str:
        """Export simulation report"""
        if format == "json":
            return json.dumps({
                "scenario_id": report.scenario_id,
                "scenario_name": report.scenario_name,
                "executive_summary": report.executive_summary,
                "start_time": report.start_time.isoformat(),
                "end_time": report.end_time.isoformat(),
                "duration_seconds": report.duration_seconds,
                "metrics": {
                    "total_techniques": report.total_techniques,
                    "successful": report.successful_techniques,
                    "blocked": report.blocked_techniques,
                    "detected": report.detected_techniques,
                    "detection_rate": report.detection_rate,
                    "success_rate": report.success_rate
                },
                "findings": {
                    "critical": report.critical_findings,
                    "high": report.high_findings,
                    "medium": report.medium_findings,
                    "low": report.low_findings
                },
                "recommendations": report.recommendations
            }, indent=2)
        
        return ""
