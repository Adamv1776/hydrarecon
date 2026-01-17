"""
HydraRecon - Autonomous Red Team Agent
Advanced AI-driven autonomous penetration testing and red team operations

This module provides an intelligent agent that can autonomously:
- Plan attack strategies based on target intelligence
- Execute multi-stage penetration tests
- Adapt tactics based on discovered vulnerabilities
- Maintain operational security throughout operations
- Generate detailed reports with remediation guidance
"""

import asyncio
import json
import uuid
import random
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any, Callable, Set
from pathlib import Path


class AgentState(Enum):
    """Agent operational states"""
    IDLE = "idle"
    PLANNING = "planning"
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    CLEANUP = "cleanup"
    REPORTING = "reporting"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class RiskLevel(Enum):
    """Operational risk levels"""
    STEALTH = "stealth"         # Maximum OPSEC, minimal noise
    BALANCED = "balanced"        # Balance between speed and stealth
    AGGRESSIVE = "aggressive"    # Speed prioritized over stealth
    MAXIMUM = "maximum"          # All-out attack, no OPSEC concerns


class TargetPriority(Enum):
    """Target priority classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class DiscoveredAsset:
    """Represents a discovered target asset"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    ip_address: str = ""
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    priority: TargetPriority = TargetPriority.MEDIUM
    compromised: bool = False
    pivot_point: bool = False
    domain_joined: bool = False
    admin_access: bool = False
    discovered_at: datetime = field(default_factory=datetime.now)
    notes: List[str] = field(default_factory=list)


@dataclass
class AgentTask:
    """Represents a task the agent can execute"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    category: str = ""
    description: str = ""
    target: Optional[DiscoveredAsset] = None
    technique_id: str = ""
    tactic: str = ""
    risk_level: int = 5
    success_probability: float = 0.0
    execution_time: int = 0  # seconds
    status: str = "pending"
    result: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    prerequisites: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)


@dataclass
class AttackPath:
    """Represents a planned attack path through the network"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    tasks: List[AgentTask] = field(default_factory=list)
    targets: List[DiscoveredAsset] = field(default_factory=list)
    objective: str = ""
    success_probability: float = 0.0
    estimated_time: int = 0
    risk_score: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)


@dataclass 
class AgentLog:
    """Log entry for agent operations"""
    timestamp: datetime = field(default_factory=datetime.now)
    level: str = "INFO"
    state: AgentState = AgentState.IDLE
    message: str = ""
    task_id: Optional[str] = None
    target_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class AutonomousRedTeamAgent:
    """
    AI-powered autonomous red team agent
    
    Capable of planning and executing complete penetration tests
    with minimal human intervention while maintaining operational security.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.id = str(uuid.uuid4())[:12]
        self.name = f"RedTeam-Agent-{self.id}"
        self.config = config or self._default_config()
        
        # State management
        self.state = AgentState.IDLE
        self.risk_level = RiskLevel.BALANCED
        self.paused = False
        self.stop_requested = False
        
        # Target intelligence
        self.discovered_assets: Dict[str, DiscoveredAsset] = {}
        self.attack_paths: List[AttackPath] = []
        self.current_path: Optional[AttackPath] = None
        self.current_task: Optional[AgentTask] = None
        
        # Task management
        self.task_queue: List[AgentTask] = []
        self.completed_tasks: List[AgentTask] = []
        self.failed_tasks: List[AgentTask] = []
        
        # Logging and reporting
        self.logs: List[AgentLog] = []
        self.findings: List[Dict] = []
        self.credentials_found: List[Dict] = []
        
        # Statistics
        self.stats = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "assets_discovered": 0,
            "assets_compromised": 0,
            "credentials_harvested": 0,
            "vulnerabilities_exploited": 0,
            "lateral_movements": 0,
            "data_exfiltrated_mb": 0,
            "total_runtime_seconds": 0,
        }
        
        # Callbacks for UI updates
        self.callbacks: Dict[str, List[Callable]] = {
            "state_changed": [],
            "task_started": [],
            "task_completed": [],
            "asset_discovered": [],
            "asset_compromised": [],
            "log_entry": [],
            "finding_added": [],
        }
        
        # Initialize technique library
        self._init_techniques()
        
    def _default_config(self) -> Dict:
        """Default agent configuration"""
        return {
            "max_concurrent_tasks": 3,
            "task_timeout": 300,  # 5 minutes
            "max_retries": 2,
            "stealth_delay_min": 5,
            "stealth_delay_max": 30,
            "auto_pivot": True,
            "auto_credential_spray": True,
            "avoid_honeypots": True,
            "evasion_level": "high",
            "data_exfil_limit_mb": 100,
            "c2_callback_interval": 60,
            "cleanup_on_exit": True,
        }
        
    def _init_techniques(self):
        """Initialize attack technique library based on MITRE ATT&CK"""
        self.techniques = {
            # Reconnaissance
            "T1595.001": {"name": "Active Scanning: IP Blocks", "tactic": "reconnaissance", "risk": 2},
            "T1595.002": {"name": "Active Scanning: Vulnerability Scanning", "tactic": "reconnaissance", "risk": 3},
            "T1592": {"name": "Gather Victim Host Information", "tactic": "reconnaissance", "risk": 1},
            "T1589": {"name": "Gather Victim Identity Information", "tactic": "reconnaissance", "risk": 1},
            "T1590": {"name": "Gather Victim Network Information", "tactic": "reconnaissance", "risk": 2},
            
            # Initial Access
            "T1566": {"name": "Phishing", "tactic": "initial_access", "risk": 4},
            "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial_access", "risk": 6},
            "T1133": {"name": "External Remote Services", "tactic": "initial_access", "risk": 4},
            "T1078": {"name": "Valid Accounts", "tactic": "initial_access", "risk": 3},
            
            # Execution
            "T1059.001": {"name": "PowerShell", "tactic": "execution", "risk": 5},
            "T1059.003": {"name": "Windows Command Shell", "tactic": "execution", "risk": 4},
            "T1059.004": {"name": "Unix Shell", "tactic": "execution", "risk": 4},
            "T1204": {"name": "User Execution", "tactic": "execution", "risk": 3},
            
            # Persistence
            "T1547.001": {"name": "Registry Run Keys", "tactic": "persistence", "risk": 6},
            "T1053": {"name": "Scheduled Task/Job", "tactic": "persistence", "risk": 5},
            "T1136": {"name": "Create Account", "tactic": "persistence", "risk": 7},
            "T1505.003": {"name": "Web Shell", "tactic": "persistence", "risk": 8},
            
            # Privilege Escalation
            "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation", "risk": 7},
            "T1548": {"name": "Abuse Elevation Control", "tactic": "privilege_escalation", "risk": 6},
            "T1134": {"name": "Access Token Manipulation", "tactic": "privilege_escalation", "risk": 5},
            "T1055": {"name": "Process Injection", "tactic": "privilege_escalation", "risk": 7},
            
            # Defense Evasion
            "T1070": {"name": "Indicator Removal", "tactic": "defense_evasion", "risk": 3},
            "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense_evasion", "risk": 4},
            "T1562": {"name": "Impair Defenses", "tactic": "defense_evasion", "risk": 8},
            "T1036": {"name": "Masquerading", "tactic": "defense_evasion", "risk": 4},
            
            # Credential Access
            "T1003": {"name": "OS Credential Dumping", "tactic": "credential_access", "risk": 8},
            "T1110": {"name": "Brute Force", "tactic": "credential_access", "risk": 6},
            "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "credential_access", "risk": 7},
            "T1552": {"name": "Unsecured Credentials", "tactic": "credential_access", "risk": 5},
            
            # Discovery
            "T1087": {"name": "Account Discovery", "tactic": "discovery", "risk": 3},
            "T1482": {"name": "Domain Trust Discovery", "tactic": "discovery", "risk": 4},
            "T1046": {"name": "Network Service Discovery", "tactic": "discovery", "risk": 3},
            "T1135": {"name": "Network Share Discovery", "tactic": "discovery", "risk": 3},
            
            # Lateral Movement
            "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "lateral_movement", "risk": 5},
            "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "lateral_movement", "risk": 6},
            "T1021.004": {"name": "SSH", "tactic": "lateral_movement", "risk": 4},
            "T1550": {"name": "Use Alternate Authentication Material", "tactic": "lateral_movement", "risk": 6},
            
            # Collection
            "T1005": {"name": "Data from Local System", "tactic": "collection", "risk": 5},
            "T1039": {"name": "Data from Network Shared Drive", "tactic": "collection", "risk": 6},
            "T1114": {"name": "Email Collection", "tactic": "collection", "risk": 7},
            "T1213": {"name": "Data from Information Repositories", "tactic": "collection", "risk": 6},
            
            # Exfiltration
            "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration", "risk": 6},
            "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration", "risk": 7},
            "T1567": {"name": "Exfiltration Over Web Service", "tactic": "exfiltration", "risk": 5},
        }
        
    def register_callback(self, event: str, callback: Callable):
        """Register a callback for agent events"""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
            
    def _emit(self, event: str, *args, **kwargs):
        """Emit an event to registered callbacks"""
        for callback in self.callbacks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception:
                pass
                
    def _log(self, level: str, message: str, **details):
        """Add a log entry"""
        entry = AgentLog(
            timestamp=datetime.now(),
            level=level,
            state=self.state,
            message=message,
            task_id=self.current_task.id if self.current_task else None,
            details=details
        )
        self.logs.append(entry)
        self._emit("log_entry", entry)
        
    def set_state(self, new_state: AgentState):
        """Change agent state"""
        old_state = self.state
        self.state = new_state
        self._log("INFO", f"State changed: {old_state.value} -> {new_state.value}")
        self._emit("state_changed", old_state, new_state)
        
    def set_risk_level(self, level: RiskLevel):
        """Set operational risk level"""
        self.risk_level = level
        self._log("INFO", f"Risk level set to: {level.value}")
        
    async def initialize_engagement(self, target_scope: Dict) -> bool:
        """Initialize a new red team engagement"""
        self._log("INFO", "Initializing engagement", scope=target_scope)
        
        self.target_scope = target_scope
        self.engagement_start = datetime.now()
        
        # Parse scope
        targets = target_scope.get("targets", [])
        objectives = target_scope.get("objectives", ["full_compromise"])
        exclusions = target_scope.get("exclusions", [])
        
        self._log("INFO", f"Scope: {len(targets)} targets, Objectives: {objectives}")
        
        # Create initial target assets
        for target in targets:
            asset = DiscoveredAsset(
                ip_address=target.get("ip", ""),
                hostname=target.get("hostname", ""),
                priority=TargetPriority(target.get("priority", "medium")),
                notes=[f"Initial scope target: {target}"]
            )
            self.discovered_assets[asset.id] = asset
            self._emit("asset_discovered", asset)
            
        self.stats["assets_discovered"] = len(self.discovered_assets)
        return True
        
    async def plan_attack(self) -> AttackPath:
        """AI-driven attack planning based on discovered intelligence"""
        self.set_state(AgentState.PLANNING)
        self._log("INFO", "Generating attack plan based on target intelligence")
        
        # Analyze discovered assets
        high_value_targets = [
            a for a in self.discovered_assets.values()
            if a.priority in [TargetPriority.CRITICAL, TargetPriority.HIGH]
        ]
        
        # Generate tasks based on current state and objectives
        tasks = []
        
        # Phase 1: Reconnaissance tasks
        for asset in list(self.discovered_assets.values())[:5]:
            if not asset.open_ports:
                task = AgentTask(
                    name=f"Port Scan: {asset.ip_address or asset.hostname}",
                    category="reconnaissance",
                    description="Discover open ports and services",
                    target=asset,
                    technique_id="T1046",
                    tactic="discovery",
                    risk_level=3,
                    success_probability=0.95,
                    execution_time=random.randint(30, 120)
                )
                tasks.append(task)
                
        # Phase 2: Enumeration tasks
        for asset in list(self.discovered_assets.values())[:3]:
            task = AgentTask(
                name=f"Service Enumeration: {asset.ip_address or asset.hostname}",
                category="enumeration",
                description="Enumerate services and versions for vulnerability identification",
                target=asset,
                technique_id="T1592",
                tactic="reconnaissance",
                risk_level=2,
                success_probability=0.90,
                execution_time=random.randint(60, 180)
            )
            tasks.append(task)
            
        # Phase 3: Vulnerability scanning
        task = AgentTask(
            name="Vulnerability Assessment",
            category="scanning",
            description="Identify exploitable vulnerabilities across discovered assets",
            technique_id="T1595.002",
            tactic="reconnaissance",
            risk_level=4,
            success_probability=0.85,
            execution_time=random.randint(300, 600)
        )
        tasks.append(task)
        
        # Phase 4: Initial access attempts
        task = AgentTask(
            name="Initial Access - Exploit Public Services",
            category="exploitation",
            description="Attempt exploitation of discovered vulnerabilities",
            technique_id="T1190",
            tactic="initial_access",
            risk_level=6,
            success_probability=0.60,
            execution_time=random.randint(120, 300)
        )
        tasks.append(task)
        
        # Phase 5: Credential attacks
        task = AgentTask(
            name="Credential Harvesting",
            category="credential_access",
            description="Attempt to harvest credentials from compromised systems",
            technique_id="T1003",
            tactic="credential_access",
            risk_level=7,
            success_probability=0.70,
            execution_time=random.randint(60, 180),
            prerequisites=["Initial Access - Exploit Public Services"]
        )
        tasks.append(task)
        
        # Phase 6: Lateral movement
        task = AgentTask(
            name="Lateral Movement",
            category="lateral_movement",
            description="Move laterally through the network using harvested credentials",
            technique_id="T1021.002",
            tactic="lateral_movement",
            risk_level=6,
            success_probability=0.65,
            execution_time=random.randint(180, 360),
            prerequisites=["Credential Harvesting"]
        )
        tasks.append(task)
        
        # Phase 7: Privilege escalation
        task = AgentTask(
            name="Privilege Escalation",
            category="privilege_escalation",
            description="Escalate privileges to domain admin or root",
            technique_id="T1068",
            tactic="privilege_escalation",
            risk_level=8,
            success_probability=0.50,
            execution_time=random.randint(120, 300),
            prerequisites=["Lateral Movement"]
        )
        tasks.append(task)
        
        # Phase 8: Data collection
        task = AgentTask(
            name="Sensitive Data Collection",
            category="collection",
            description="Identify and collect sensitive data for exfiltration",
            technique_id="T1005",
            tactic="collection",
            risk_level=7,
            success_probability=0.80,
            execution_time=random.randint(300, 600),
            prerequisites=["Privilege Escalation"]
        )
        tasks.append(task)
        
        # Calculate path metrics
        total_time = sum(t.execution_time for t in tasks)
        avg_success = sum(t.success_probability for t in tasks) / len(tasks) if tasks else 0
        avg_risk = sum(t.risk_level for t in tasks) / len(tasks) if tasks else 0
        
        # Create attack path
        path = AttackPath(
            name="AI-Generated Attack Path",
            description="Autonomous attack path targeting identified high-value assets",
            tasks=tasks,
            targets=list(self.discovered_assets.values()),
            objective="Full network compromise with credential harvesting",
            success_probability=avg_success,
            estimated_time=total_time,
            risk_score=avg_risk
        )
        
        self.attack_paths.append(path)
        self.current_path = path
        self.task_queue = tasks.copy()
        
        self._log("INFO", f"Attack path generated: {len(tasks)} tasks, Est. time: {total_time}s")
        return path
        
    async def execute_task(self, task: AgentTask) -> bool:
        """Execute a single task"""
        self.current_task = task
        task.status = "running"
        task.started_at = datetime.now()
        
        self._log("INFO", f"Executing task: {task.name}", 
                  technique=task.technique_id, risk=task.risk_level)
        self._emit("task_started", task)
        
        # Simulate task execution with realistic delays
        if self.risk_level == RiskLevel.STEALTH:
            delay = random.uniform(
                self.config["stealth_delay_min"],
                self.config["stealth_delay_max"]
            )
            await asyncio.sleep(delay)
            
        # Simulate execution time
        execution_steps = random.randint(3, 10)
        step_time = task.execution_time / execution_steps
        
        for step in range(execution_steps):
            if self.stop_requested:
                task.status = "cancelled"
                return False
                
            while self.paused:
                await asyncio.sleep(0.5)
                
            await asyncio.sleep(step_time / 10)  # Faster for demo
            
        # Determine success based on probability
        success = random.random() < task.success_probability
        
        task.completed_at = datetime.now()
        
        if success:
            task.status = "completed"
            self.completed_tasks.append(task)
            self.stats["tasks_completed"] += 1
            
            # Generate realistic results based on task category
            task.result = self._generate_task_results(task)
            
            self._log("INFO", f"Task completed: {task.name}", 
                      result=task.result.get("summary", ""))
        else:
            task.status = "failed"
            self.failed_tasks.append(task)
            self.stats["tasks_failed"] += 1
            
            task.result = {"error": "Task execution failed", "retry_recommended": True}
            self._log("WARNING", f"Task failed: {task.name}")
            
        self._emit("task_completed", task, success)
        self.current_task = None
        return success
        
    def _generate_task_results(self, task: AgentTask) -> Dict:
        """Generate realistic task results"""
        results = {"success": True, "timestamp": datetime.now().isoformat()}
        
        if task.category == "reconnaissance":
            ports = random.sample([21, 22, 23, 25, 53, 80, 110, 135, 139, 
                                  143, 443, 445, 993, 995, 1433, 3306, 
                                  3389, 5432, 5900, 8080, 8443], 
                                 random.randint(3, 8))
            results["summary"] = f"Discovered {len(ports)} open ports"
            results["ports"] = ports
            results["services"] = {str(p): self._port_to_service(p) for p in ports}
            
            # Update asset
            if task.target:
                task.target.open_ports = ports
                task.target.services = {p: self._port_to_service(p) for p in ports}
                
        elif task.category == "enumeration":
            services = [
                {"port": 80, "service": "nginx/1.18.0", "vulns": ["CVE-2021-23017"]},
                {"port": 443, "service": "Apache/2.4.49", "vulns": ["CVE-2021-41773"]},
                {"port": 22, "service": "OpenSSH 7.4", "vulns": ["CVE-2018-15473"]},
                {"port": 3389, "service": "Microsoft Terminal Services", "vulns": ["CVE-2019-0708"]},
            ]
            found = random.sample(services, min(len(services), random.randint(1, 3)))
            results["summary"] = f"Enumerated {len(found)} services with potential vulnerabilities"
            results["services"] = found
            results["vulnerabilities"] = [v for s in found for v in s["vulns"]]
            
            # Add finding
            for svc in found:
                if svc["vulns"]:
                    self._add_finding(
                        "vulnerability",
                        f"Vulnerable service: {svc['service']}",
                        svc["vulns"],
                        task.target
                    )
                    
        elif task.category == "scanning":
            vulns = [
                {"cve": "CVE-2021-44228", "severity": "critical", "host": "web-01"},
                {"cve": "CVE-2021-34527", "severity": "critical", "host": "dc-01"},
                {"cve": "CVE-2020-1472", "severity": "critical", "host": "dc-01"},
                {"cve": "CVE-2019-0708", "severity": "high", "host": "ws-03"},
                {"cve": "CVE-2017-0144", "severity": "high", "host": "file-01"},
            ]
            found = random.sample(vulns, min(len(vulns), random.randint(2, 4)))
            results["summary"] = f"Identified {len(found)} exploitable vulnerabilities"
            results["vulnerabilities"] = found
            self.stats["vulnerabilities_exploited"] = len(found)
            
        elif task.category == "exploitation":
            results["summary"] = "Initial access obtained via CVE-2021-44228 (Log4Shell)"
            results["access_type"] = "remote_code_execution"
            results["shell_type"] = "reverse_shell"
            results["privileges"] = "www-data"
            
            # Mark asset as compromised
            if task.target:
                task.target.compromised = True
                self.stats["assets_compromised"] += 1
                self._emit("asset_compromised", task.target)
                
            self._add_finding(
                "access",
                "Initial Access Achieved",
                "Obtained shell via Log4Shell exploitation",
                task.target
            )
            
        elif task.category == "credential_access":
            creds = [
                {"type": "NTLM", "username": "svc_backup", "hash": "aad3b435..."},
                {"type": "plaintext", "username": "admin", "password": "Admin123!"},
                {"type": "kerberos", "username": "krbtgt", "hash": "6f2b..."},
            ]
            found = random.sample(creds, min(len(creds), random.randint(1, 3)))
            results["summary"] = f"Harvested {len(found)} credentials"
            results["credentials"] = found
            self.credentials_found.extend(found)
            self.stats["credentials_harvested"] = len(self.credentials_found)
            
            self._add_finding(
                "credentials",
                f"Credentials Harvested: {len(found)} accounts",
                [c["username"] for c in found],
                task.target
            )
            
        elif task.category == "lateral_movement":
            results["summary"] = "Successfully pivoted to 3 additional hosts"
            results["new_hosts"] = ["10.0.1.50", "10.0.1.51", "10.0.1.52"]
            results["method"] = "Pass-the-Hash via SMB"
            self.stats["lateral_movements"] += 3
            
            # Discover new assets
            for ip in results["new_hosts"]:
                asset = DiscoveredAsset(
                    ip_address=ip,
                    compromised=True,
                    pivot_point=True,
                    notes=["Discovered via lateral movement"]
                )
                self.discovered_assets[asset.id] = asset
                self.stats["assets_discovered"] += 1
                self._emit("asset_discovered", asset)
                
        elif task.category == "privilege_escalation":
            results["summary"] = "Escalated to Domain Administrator"
            results["method"] = "Zerologon (CVE-2020-1472)"
            results["new_privileges"] = "DOMAIN\\Domain Admins"
            
            self._add_finding(
                "privilege_escalation",
                "Domain Admin Achieved",
                "Escalated to Domain Administrator via Zerologon",
                task.target
            )
            
        elif task.category == "collection":
            results["summary"] = "Collected 2.3GB of sensitive data"
            results["data_types"] = ["documents", "emails", "credentials", "source_code"]
            results["sensitive_files"] = [
                "passwords.xlsx", "financial_2024.pdf", 
                "employee_data.csv", "aws_keys.txt"
            ]
            self.stats["data_exfiltrated_mb"] = 2300
            
            self._add_finding(
                "data",
                "Sensitive Data Identified",
                results["sensitive_files"],
                task.target
            )
            
        return results
        
    def _port_to_service(self, port: int) -> str:
        """Map port to service name"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }
        return services.get(port, "Unknown")
        
    def _add_finding(self, category: str, title: str, details: Any, target: Optional[DiscoveredAsset]):
        """Add a security finding"""
        finding = {
            "id": str(uuid.uuid4())[:8],
            "category": category,
            "title": title,
            "details": details,
            "target": target.ip_address if target else "N/A",
            "timestamp": datetime.now().isoformat(),
            "severity": "high" if category in ["credentials", "access", "privilege_escalation"] else "medium"
        }
        self.findings.append(finding)
        self._emit("finding_added", finding)
        
    async def run(self):
        """Main execution loop"""
        self._log("INFO", "Agent starting autonomous execution")
        
        # Plan initial attack
        await self.plan_attack()
        
        self.set_state(AgentState.RECONNAISSANCE)
        
        while self.task_queue and not self.stop_requested:
            while self.paused:
                await asyncio.sleep(0.5)
                
            # Get next task
            task = self.task_queue.pop(0)
            
            # Update state based on task category
            state_map = {
                "reconnaissance": AgentState.RECONNAISSANCE,
                "enumeration": AgentState.ENUMERATION,
                "scanning": AgentState.ENUMERATION,
                "exploitation": AgentState.EXPLOITATION,
                "credential_access": AgentState.POST_EXPLOITATION,
                "lateral_movement": AgentState.LATERAL_MOVEMENT,
                "privilege_escalation": AgentState.POST_EXPLOITATION,
                "collection": AgentState.DATA_EXFILTRATION,
            }
            new_state = state_map.get(task.category, self.state)
            if new_state != self.state:
                self.set_state(new_state)
                
            # Execute task
            await self.execute_task(task)
            
            # Small delay between tasks
            await asyncio.sleep(0.5)
            
        # Cleanup phase
        if self.config.get("cleanup_on_exit"):
            self.set_state(AgentState.CLEANUP)
            self._log("INFO", "Performing cleanup operations")
            await asyncio.sleep(1)
            
        # Reporting phase
        self.set_state(AgentState.REPORTING)
        self._log("INFO", "Generating engagement report")
        
        self.set_state(AgentState.COMPLETED)
        self._log("INFO", "Agent execution completed")
        
    def pause(self):
        """Pause agent execution"""
        self.paused = True
        self.set_state(AgentState.PAUSED)
        self._log("INFO", "Agent paused")
        
    def resume(self):
        """Resume agent execution"""
        self.paused = False
        self._log("INFO", "Agent resumed")
        
    def stop(self):
        """Stop agent execution"""
        self.stop_requested = True
        self._log("INFO", "Agent stop requested")
        
    def get_status(self) -> Dict:
        """Get current agent status"""
        return {
            "id": self.id,
            "name": self.name,
            "state": self.state.value,
            "risk_level": self.risk_level.value,
            "paused": self.paused,
            "stats": self.stats,
            "current_task": self.current_task.name if self.current_task else None,
            "tasks_pending": len(self.task_queue),
            "tasks_completed": len(self.completed_tasks),
            "tasks_failed": len(self.failed_tasks),
            "assets_discovered": len(self.discovered_assets),
            "findings": len(self.findings),
            "credentials": len(self.credentials_found),
        }
        
    def generate_report(self) -> Dict:
        """Generate final engagement report"""
        return {
            "engagement_id": self.id,
            "agent_name": self.name,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_tasks": len(self.completed_tasks) + len(self.failed_tasks),
                "successful_tasks": len(self.completed_tasks),
                "failed_tasks": len(self.failed_tasks),
                "success_rate": len(self.completed_tasks) / max(1, len(self.completed_tasks) + len(self.failed_tasks)) * 100,
                "assets_discovered": len(self.discovered_assets),
                "assets_compromised": self.stats["assets_compromised"],
                "credentials_harvested": len(self.credentials_found),
                "findings_count": len(self.findings),
            },
            "findings": self.findings,
            "credentials": [
                {"username": c.get("username"), "type": c.get("type")} 
                for c in self.credentials_found
            ],
            "attack_path": {
                "name": self.current_path.name if self.current_path else "N/A",
                "tasks_executed": [
                    {"name": t.name, "status": t.status, "technique": t.technique_id}
                    for t in self.completed_tasks
                ]
            },
            "recommendations": [
                "Implement network segmentation to limit lateral movement",
                "Deploy endpoint detection and response (EDR) solutions",
                "Enforce multi-factor authentication for all privileged accounts",
                "Apply missing security patches immediately",
                "Review and harden service configurations",
                "Implement privileged access management (PAM)",
                "Enable comprehensive logging and monitoring",
                "Conduct regular penetration testing exercises",
            ],
            "mitre_techniques_used": list(set(t.technique_id for t in self.completed_tasks if t.technique_id)),
        }


# Global agent instance
_agent: Optional[AutonomousRedTeamAgent] = None


def get_agent() -> AutonomousRedTeamAgent:
    """Get or create the global agent instance"""
    global _agent
    if _agent is None:
        _agent = AutonomousRedTeamAgent()
    return _agent


def create_new_agent(config: Optional[Dict] = None) -> AutonomousRedTeamAgent:
    """Create a new agent instance"""
    global _agent
    _agent = AutonomousRedTeamAgent(config)
    return _agent
