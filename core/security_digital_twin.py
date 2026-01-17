"""
HydraRecon Security Digital Twin
================================
Virtual replica of your entire network for unlimited attack simulations.

Features:
- Real-time infrastructure synchronization
- Unlimited attack simulation without production impact
- What-if scenario testing
- Patch impact prediction
- Red team training environment
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set
import random
import copy
import json


class AssetType(Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    FIREWALL = "firewall"
    DATABASE = "database"
    CONTAINER = "container"
    CLOUD_RESOURCE = "cloud_resource"
    IOT_DEVICE = "iot_device"
    MOBILE_DEVICE = "mobile_device"
    APPLICATION = "application"


class AssetState(Enum):
    HEALTHY = "healthy"
    COMPROMISED = "compromised"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    PATCHING = "patching"
    UNDER_ATTACK = "under_attack"


class SimulationType(Enum):
    RANSOMWARE = "ransomware"
    APT = "apt"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    DDOS = "ddos"
    INSIDER_THREAT = "insider_threat"
    ZERO_DAY = "zero_day"
    SUPPLY_CHAIN = "supply_chain"
    CUSTOM = "custom"


@dataclass
class VirtualAsset:
    """Virtual representation of a network asset"""
    asset_id: str
    name: str
    asset_type: AssetType
    ip_address: str
    hostname: str
    os: str
    os_version: str
    services: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    patches_installed: List[str]
    patches_pending: List[str]
    security_controls: List[str]
    connections: List[str]  # Connected asset IDs
    criticality: float  # 0-1
    state: AssetState = AssetState.HEALTHY
    last_sync: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VirtualNetwork:
    """Virtual network segment"""
    network_id: str
    name: str
    cidr: str
    vlan_id: int
    assets: List[str]  # Asset IDs
    firewall_rules: List[Dict[str, Any]]
    segmentation_level: str  # high, medium, low
    internet_facing: bool


@dataclass
class SecurityControl:
    """Virtual security control"""
    control_id: str
    name: str
    control_type: str  # firewall, edr, siem, dlp, etc.
    effectiveness: float  # 0-1
    coverage: List[str]  # Asset IDs covered
    enabled: bool
    configuration: Dict[str, Any]


@dataclass 
class SimulationStep:
    """A step in an attack simulation"""
    step_id: int
    technique: str
    mitre_id: str
    target_asset: str
    source_asset: Optional[str]
    success: bool
    detection_triggered: bool
    impact: str
    duration_seconds: int
    details: Dict[str, Any]


@dataclass
class SimulationResult:
    """Result of an attack simulation"""
    simulation_id: str
    simulation_type: SimulationType
    start_time: datetime
    end_time: datetime
    steps: List[SimulationStep]
    assets_compromised: List[str]
    data_accessed: List[str]
    lateral_movement_paths: List[List[str]]
    detection_rate: float
    time_to_detection: Optional[timedelta]
    impact_score: float
    recommendations: List[str]


@dataclass
class WhatIfScenario:
    """What-if scenario for testing changes"""
    scenario_id: str
    name: str
    description: str
    changes: List[Dict[str, Any]]  # patches, config changes, etc.
    baseline_risk: float
    modified_risk: float
    risk_reduction: float
    affected_assets: List[str]
    side_effects: List[str]


@dataclass
class TwinSnapshot:
    """Point-in-time snapshot of the digital twin"""
    snapshot_id: str
    timestamp: datetime
    assets: Dict[str, VirtualAsset]
    networks: Dict[str, VirtualNetwork]
    controls: Dict[str, SecurityControl]
    risk_score: float
    

class SecurityDigitalTwin:
    """
    Security Digital Twin - Virtual replica for attack simulation.
    Test unlimited attack scenarios without impacting production.
    """
    
    def __init__(self):
        self.assets: Dict[str, VirtualAsset] = {}
        self.networks: Dict[str, VirtualNetwork] = {}
        self.controls: Dict[str, SecurityControl] = {}
        self.snapshots: List[TwinSnapshot] = []
        self.simulation_history: List[SimulationResult] = []
        self.sync_status = "initialized"
        self.last_sync: Optional[datetime] = None
        
        # Attack simulation models
        self.attack_models = {
            SimulationType.RANSOMWARE: self._simulate_ransomware,
            SimulationType.APT: self._simulate_apt,
            SimulationType.LATERAL_MOVEMENT: self._simulate_lateral_movement,
            SimulationType.PRIVILEGE_ESCALATION: self._simulate_privilege_escalation,
            SimulationType.DATA_EXFILTRATION: self._simulate_data_exfil,
            SimulationType.DDOS: self._simulate_ddos,
            SimulationType.INSIDER_THREAT: self._simulate_insider,
            SimulationType.ZERO_DAY: self._simulate_zero_day,
        }
        
        # MITRE ATT&CK techniques for simulations
        self.mitre_techniques = {
            "initial_access": [
                ("T1566", "Phishing"),
                ("T1190", "Exploit Public-Facing Application"),
                ("T1133", "External Remote Services"),
            ],
            "execution": [
                ("T1059", "Command and Scripting Interpreter"),
                ("T1204", "User Execution"),
                ("T1053", "Scheduled Task/Job"),
            ],
            "persistence": [
                ("T1547", "Boot or Logon Autostart Execution"),
                ("T1543", "Create or Modify System Process"),
                ("T1136", "Create Account"),
            ],
            "privilege_escalation": [
                ("T1548", "Abuse Elevation Control Mechanism"),
                ("T1134", "Access Token Manipulation"),
                ("T1068", "Exploitation for Privilege Escalation"),
            ],
            "lateral_movement": [
                ("T1021", "Remote Services"),
                ("T1072", "Software Deployment Tools"),
                ("T1570", "Lateral Tool Transfer"),
            ],
            "exfiltration": [
                ("T1041", "Exfiltration Over C2 Channel"),
                ("T1048", "Exfiltration Over Alternative Protocol"),
                ("T1567", "Exfiltration Over Web Service"),
            ],
        }
        
        self._initialize_demo_environment()
        
    def _initialize_demo_environment(self):
        """Initialize a demo enterprise environment"""
        
        # Create virtual networks
        self.networks = {
            "dmz": VirtualNetwork(
                network_id="dmz",
                name="DMZ Network",
                cidr="10.0.1.0/24",
                vlan_id=10,
                assets=[],
                firewall_rules=[
                    {"rule": "ALLOW", "source": "any", "dest": "web-server", "port": 443},
                    {"rule": "DENY", "source": "dmz", "dest": "internal", "port": "any"},
                ],
                segmentation_level="high",
                internet_facing=True
            ),
            "internal": VirtualNetwork(
                network_id="internal",
                name="Internal Network",
                cidr="10.0.10.0/24",
                vlan_id=100,
                assets=[],
                firewall_rules=[
                    {"rule": "ALLOW", "source": "internal", "dest": "internal", "port": "any"},
                ],
                segmentation_level="medium",
                internet_facing=False
            ),
            "secure": VirtualNetwork(
                network_id="secure",
                name="Secure Zone",
                cidr="10.0.100.0/24",
                vlan_id=200,
                assets=[],
                firewall_rules=[
                    {"rule": "ALLOW", "source": "admin-vlan", "dest": "secure", "port": 22},
                    {"rule": "DENY", "source": "any", "dest": "secure", "port": "any"},
                ],
                segmentation_level="high",
                internet_facing=False
            ),
        }
        
        # Create virtual assets
        demo_assets = [
            ("web-server-01", "Web Server 1", AssetType.SERVER, "10.0.1.10", "web01.corp.local",
             "Ubuntu", "22.04 LTS", 
             [{"name": "nginx", "port": 443, "version": "1.24"}, {"name": "ssh", "port": 22}],
             [{"cve": "CVE-2024-1234", "cvss": 7.5}], 0.8, "dmz"),
             
            ("web-server-02", "Web Server 2", AssetType.SERVER, "10.0.1.11", "web02.corp.local",
             "Ubuntu", "22.04 LTS",
             [{"name": "apache", "port": 443, "version": "2.4"}, {"name": "ssh", "port": 22}],
             [], 0.8, "dmz"),
             
            ("api-gateway", "API Gateway", AssetType.SERVER, "10.0.1.20", "api.corp.local",
             "Linux", "RHEL 9",
             [{"name": "kong", "port": 8443}],
             [{"cve": "CVE-2024-5678", "cvss": 6.5}], 0.9, "dmz"),
             
            ("app-server-01", "Application Server 1", AssetType.SERVER, "10.0.10.10", "app01.corp.local",
             "Windows Server", "2022",
             [{"name": "iis", "port": 80}, {"name": "rdp", "port": 3389}],
             [{"cve": "CVE-2024-8888", "cvss": 8.1}], 0.7, "internal"),
             
            ("app-server-02", "Application Server 2", AssetType.SERVER, "10.0.10.11", "app02.corp.local",
             "Windows Server", "2022",
             [{"name": "iis", "port": 80}, {"name": "rdp", "port": 3389}],
             [], 0.7, "internal"),
             
            ("dc-01", "Domain Controller", AssetType.SERVER, "10.0.100.10", "dc01.corp.local",
             "Windows Server", "2022",
             [{"name": "ldap", "port": 389}, {"name": "kerberos", "port": 88}],
             [], 0.95, "secure"),
             
            ("db-primary", "Primary Database", AssetType.DATABASE, "10.0.100.20", "db01.corp.local",
             "Linux", "RHEL 9",
             [{"name": "postgresql", "port": 5432}],
             [], 0.95, "secure"),
             
            ("db-replica", "Database Replica", AssetType.DATABASE, "10.0.100.21", "db02.corp.local",
             "Linux", "RHEL 9",
             [{"name": "postgresql", "port": 5432}],
             [], 0.9, "secure"),
             
            ("workstation-it-01", "IT Workstation 1", AssetType.WORKSTATION, "10.0.10.100", "ws-it01.corp.local",
             "Windows", "11 Enterprise",
             [{"name": "rdp", "port": 3389}],
             [{"cve": "CVE-2024-2222", "cvss": 5.5}], 0.4, "internal"),
             
            ("workstation-hr-01", "HR Workstation", AssetType.WORKSTATION, "10.0.10.101", "ws-hr01.corp.local",
             "Windows", "11 Enterprise",
             [{"name": "rdp", "port": 3389}],
             [], 0.3, "internal"),
             
            ("file-server", "File Server", AssetType.SERVER, "10.0.10.50", "fs01.corp.local",
             "Windows Server", "2022",
             [{"name": "smb", "port": 445}],
             [], 0.85, "internal"),
             
            ("backup-server", "Backup Server", AssetType.SERVER, "10.0.100.30", "backup01.corp.local",
             "Linux", "Ubuntu 22.04",
             [{"name": "ssh", "port": 22}],
             [], 0.9, "secure"),
             
            ("mail-server", "Mail Server", AssetType.SERVER, "10.0.1.30", "mail.corp.local",
             "Linux", "RHEL 9",
             [{"name": "smtp", "port": 25}, {"name": "imap", "port": 993}],
             [{"cve": "CVE-2024-3333", "cvss": 7.0}], 0.85, "dmz"),
             
            ("vpn-gateway", "VPN Gateway", AssetType.NETWORK_DEVICE, "10.0.1.1", "vpn.corp.local",
             "FortiOS", "7.4",
             [{"name": "ipsec", "port": 500}, {"name": "ssl-vpn", "port": 443}],
             [], 0.9, "dmz"),
             
            ("fw-perimeter", "Perimeter Firewall", AssetType.FIREWALL, "10.0.0.1", "fw01.corp.local",
             "PAN-OS", "11.0",
             [],
             [], 0.95, "dmz"),
        ]
        
        for asset_data in demo_assets:
            asset = VirtualAsset(
                asset_id=asset_data[0],
                name=asset_data[1],
                asset_type=asset_data[2],
                ip_address=asset_data[3],
                hostname=asset_data[4],
                os=asset_data[5],
                os_version=asset_data[6],
                services=asset_data[7],
                vulnerabilities=asset_data[8],
                patches_installed=[f"KB{random.randint(100000, 999999)}" for _ in range(random.randint(5, 20))],
                patches_pending=[f"KB{random.randint(100000, 999999)}" for _ in range(random.randint(0, 3))],
                security_controls=["endpoint_protection", "logging"],
                connections=[],
                criticality=asset_data[9],
            )
            self.assets[asset.asset_id] = asset
            self.networks[asset_data[10]].assets.append(asset.asset_id)
            
        # Define asset connections (attack paths)
        connections = [
            ("web-server-01", ["api-gateway", "app-server-01"]),
            ("web-server-02", ["api-gateway", "app-server-02"]),
            ("api-gateway", ["app-server-01", "app-server-02", "db-primary"]),
            ("app-server-01", ["db-primary", "file-server", "dc-01"]),
            ("app-server-02", ["db-primary", "file-server", "dc-01"]),
            ("dc-01", ["db-primary", "file-server", "backup-server"]),
            ("db-primary", ["db-replica", "backup-server"]),
            ("workstation-it-01", ["dc-01", "file-server", "app-server-01"]),
            ("workstation-hr-01", ["file-server"]),
            ("mail-server", ["app-server-01", "dc-01"]),
            ("vpn-gateway", ["workstation-it-01", "app-server-01"]),
        ]
        
        for asset_id, conns in connections:
            if asset_id in self.assets:
                self.assets[asset_id].connections = conns
                
        # Create security controls
        self.controls = {
            "edr": SecurityControl(
                control_id="edr",
                name="Endpoint Detection & Response",
                control_type="edr",
                effectiveness=0.85,
                coverage=[a for a in self.assets if self.assets[a].asset_type in [AssetType.SERVER, AssetType.WORKSTATION]],
                enabled=True,
                configuration={"mode": "prevent", "cloud_enabled": True}
            ),
            "siem": SecurityControl(
                control_id="siem",
                name="SIEM Platform",
                control_type="siem",
                effectiveness=0.75,
                coverage=list(self.assets.keys()),
                enabled=True,
                configuration={"retention_days": 90, "real_time": True}
            ),
            "ngfw": SecurityControl(
                control_id="ngfw",
                name="Next-Gen Firewall",
                control_type="firewall",
                effectiveness=0.90,
                coverage=["fw-perimeter"],
                enabled=True,
                configuration={"ips_enabled": True, "threat_intel": True}
            ),
            "dlp": SecurityControl(
                control_id="dlp",
                name="Data Loss Prevention",
                control_type="dlp",
                effectiveness=0.70,
                coverage=["mail-server", "file-server", "db-primary"],
                enabled=True,
                configuration={"mode": "monitor"}
            ),
            "waf": SecurityControl(
                control_id="waf",
                name="Web Application Firewall",
                control_type="waf",
                effectiveness=0.80,
                coverage=["web-server-01", "web-server-02", "api-gateway"],
                enabled=True,
                configuration={"mode": "block", "ruleset": "OWASP"}
            ),
        }
        
        self.sync_status = "synchronized"
        self.last_sync = datetime.now()
        
    async def sync_with_production(self, discovery_results: Optional[Dict] = None) -> Dict[str, Any]:
        """Synchronize digital twin with production environment"""
        sync_start = datetime.now()
        
        # In production, this would pull from actual infrastructure
        # For demo, we update timestamps and simulate drift
        
        changes = []
        for asset_id, asset in self.assets.items():
            # Simulate state changes
            if random.random() > 0.9:
                old_state = asset.state
                asset.state = random.choice([AssetState.HEALTHY, AssetState.DEGRADED])
                if old_state != asset.state:
                    changes.append({"asset": asset_id, "change": "state", "from": old_state.value, "to": asset.state.value})
                    
            # Update sync time
            asset.last_sync = datetime.now()
            
        await asyncio.sleep(0.5)  # Simulate sync delay
        
        self.last_sync = datetime.now()
        self.sync_status = "synchronized"
        
        return {
            "sync_time": datetime.now(),
            "duration_ms": int((datetime.now() - sync_start).total_seconds() * 1000),
            "assets_synced": len(self.assets),
            "networks_synced": len(self.networks),
            "changes_detected": len(changes),
            "changes": changes
        }
        
    def create_snapshot(self, name: str = None) -> TwinSnapshot:
        """Create a point-in-time snapshot of the twin"""
        snapshot = TwinSnapshot(
            snapshot_id=f"SNAP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            timestamp=datetime.now(),
            assets=copy.deepcopy(self.assets),
            networks=copy.deepcopy(self.networks),
            controls=copy.deepcopy(self.controls),
            risk_score=self._calculate_risk_score()
        )
        self.snapshots.append(snapshot)
        return snapshot
        
    def restore_snapshot(self, snapshot_id: str) -> bool:
        """Restore twin state from a snapshot"""
        for snapshot in self.snapshots:
            if snapshot.snapshot_id == snapshot_id:
                self.assets = copy.deepcopy(snapshot.assets)
                self.networks = copy.deepcopy(snapshot.networks)
                self.controls = copy.deepcopy(snapshot.controls)
                return True
        return False
        
    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score for the twin"""
        vuln_score = 0
        for asset in self.assets.values():
            asset_vuln = sum(v.get("cvss", 5) for v in asset.vulnerabilities)
            asset_vuln *= asset.criticality
            vuln_score += asset_vuln
            
        # Normalize
        max_possible = len(self.assets) * 10 * 1.0  # All critical assets with CVSS 10
        risk = min(100, (vuln_score / max(max_possible, 1)) * 100)
        
        # Factor in security controls
        control_reduction = sum(c.effectiveness for c in self.controls.values() if c.enabled) / max(len(self.controls), 1)
        risk *= (1 - control_reduction * 0.3)  # Controls can reduce risk by up to 30%
        
        return round(risk, 1)
        
    async def run_simulation(
        self,
        simulation_type: SimulationType,
        entry_point: str = None,
        target_asset: str = None,
        custom_steps: List[Dict] = None
    ) -> SimulationResult:
        """Run an attack simulation on the digital twin"""
        
        # Create a working copy to avoid modifying the twin
        working_assets = copy.deepcopy(self.assets)
        
        start_time = datetime.now()
        steps = []
        compromised = set()
        data_accessed = []
        lateral_paths = []
        detections = 0
        
        # Get the appropriate simulation function
        if simulation_type in self.attack_models:
            sim_func = self.attack_models[simulation_type]
            steps, compromised, data_accessed, lateral_paths = await sim_func(
                working_assets, entry_point, target_asset
            )
        else:
            # Custom simulation
            steps = await self._simulate_custom(working_assets, custom_steps or [])
            
        end_time = datetime.now()
        
        # Calculate detection rate
        detections = sum(1 for s in steps if s.detection_triggered)
        detection_rate = detections / max(len(steps), 1)
        
        # Calculate time to first detection
        time_to_detection = None
        for i, step in enumerate(steps):
            if step.detection_triggered:
                time_to_detection = timedelta(seconds=sum(s.duration_seconds for s in steps[:i+1]))
                break
                
        # Calculate impact score
        impact_score = len(compromised) / max(len(self.assets), 1) * 100
        for asset_id in compromised:
            if asset_id in self.assets:
                impact_score += self.assets[asset_id].criticality * 20
                
        impact_score = min(100, impact_score)
        
        # Generate recommendations
        recommendations = self._generate_simulation_recommendations(steps, compromised)
        
        result = SimulationResult(
            simulation_id=f"SIM-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            simulation_type=simulation_type,
            start_time=start_time,
            end_time=end_time,
            steps=steps,
            assets_compromised=list(compromised),
            data_accessed=data_accessed,
            lateral_movement_paths=lateral_paths,
            detection_rate=round(detection_rate, 2),
            time_to_detection=time_to_detection,
            impact_score=round(impact_score, 1),
            recommendations=recommendations
        )
        
        self.simulation_history.append(result)
        return result
        
    async def _simulate_ransomware(
        self,
        assets: Dict[str, VirtualAsset],
        entry_point: str,
        target: str
    ) -> tuple:
        """Simulate a ransomware attack"""
        steps = []
        compromised = set()
        data_accessed = []
        lateral_paths = []
        
        # Entry point - usually phishing or RDP
        entry = entry_point or "workstation-it-01"
        
        # Step 1: Initial Access
        steps.append(SimulationStep(
            step_id=1,
            technique="Phishing",
            mitre_id="T1566",
            target_asset=entry,
            source_asset=None,
            success=True,
            detection_triggered=self._check_detection("edr", 0.3),
            impact="Initial foothold established",
            duration_seconds=random.randint(60, 300),
            details={"method": "malicious_attachment", "user": "user@corp.local"}
        ))
        compromised.add(entry)
        
        # Step 2: Execution
        steps.append(SimulationStep(
            step_id=2,
            technique="PowerShell Execution",
            mitre_id="T1059.001",
            target_asset=entry,
            source_asset=entry,
            success=True,
            detection_triggered=self._check_detection("edr", 0.6),
            impact="Malicious payload executed",
            duration_seconds=random.randint(10, 60),
            details={"command": "powershell -enc [base64]"}
        ))
        
        # Step 3: Privilege Escalation
        steps.append(SimulationStep(
            step_id=3,
            technique="Local Admin Exploitation",
            mitre_id="T1068",
            target_asset=entry,
            source_asset=entry,
            success=True,
            detection_triggered=self._check_detection("edr", 0.5),
            impact="Local admin privileges obtained",
            duration_seconds=random.randint(30, 120),
            details={"exploit": "CVE-2024-XXXX"}
        ))
        
        # Step 4: Lateral Movement
        if entry in assets and assets[entry].connections:
            for conn in assets[entry].connections[:3]:
                path = [entry, conn]
                lateral_paths.append(path)
                compromised.add(conn)
                
                steps.append(SimulationStep(
                    step_id=len(steps) + 1,
                    technique="SMB/RDP Lateral Movement",
                    mitre_id="T1021",
                    target_asset=conn,
                    source_asset=entry,
                    success=True,
                    detection_triggered=self._check_detection("siem", 0.4),
                    impact=f"Lateral movement to {conn}",
                    duration_seconds=random.randint(60, 180),
                    details={"protocol": "smb"}
                ))
                
        # Step 5: Domain Controller Compromise
        if "dc-01" in assets:
            steps.append(SimulationStep(
                step_id=len(steps) + 1,
                technique="DCSync Attack",
                mitre_id="T1003.006",
                target_asset="dc-01",
                source_asset=entry,
                success=True,
                detection_triggered=self._check_detection("siem", 0.7),
                impact="Domain admin credentials extracted",
                duration_seconds=random.randint(120, 300),
                details={"hashes_extracted": 150}
            ))
            compromised.add("dc-01")
            
        # Step 6: Encryption
        for asset_id in list(compromised):
            if assets[asset_id].asset_type in [AssetType.SERVER, AssetType.DATABASE]:
                steps.append(SimulationStep(
                    step_id=len(steps) + 1,
                    technique="Data Encrypted for Impact",
                    mitre_id="T1486",
                    target_asset=asset_id,
                    source_asset=entry,
                    success=True,
                    detection_triggered=self._check_detection("edr", 0.8),
                    impact=f"Files encrypted on {asset_id}",
                    duration_seconds=random.randint(300, 900),
                    details={"files_encrypted": random.randint(1000, 50000)}
                ))
                data_accessed.append(f"{asset_id}:encrypted")
                
        return steps, compromised, data_accessed, lateral_paths
        
    async def _simulate_apt(self, assets: Dict, entry: str, target: str) -> tuple:
        """Simulate an APT campaign"""
        steps = []
        compromised = set()
        data_accessed = []
        lateral_paths = []
        
        entry = entry or "web-server-01"
        target = target or "db-primary"
        
        # APT is slow and stealthy
        steps.append(SimulationStep(
            step_id=1,
            technique="Exploit Public-Facing Application",
            mitre_id="T1190",
            target_asset=entry,
            source_asset=None,
            success=True,
            detection_triggered=self._check_detection("waf", 0.4),
            impact="Web shell installed",
            duration_seconds=random.randint(3600, 7200),  # Hours
            details={"exploit": "zero-day", "persistence": "webshell"}
        ))
        compromised.add(entry)
        
        # Persistence
        steps.append(SimulationStep(
            step_id=2,
            technique="Scheduled Task",
            mitre_id="T1053",
            target_asset=entry,
            source_asset=entry,
            success=True,
            detection_triggered=self._check_detection("edr", 0.3),
            impact="Persistence established",
            duration_seconds=random.randint(600, 1800),
            details={"task_name": "SystemHealthCheck"}
        ))
        
        # Slow lateral movement
        current = entry
        path = [entry]
        for _ in range(3):
            if current in assets and assets[current].connections:
                next_hop = random.choice(assets[current].connections)
                path.append(next_hop)
                compromised.add(next_hop)
                current = next_hop
                
                steps.append(SimulationStep(
                    step_id=len(steps) + 1,
                    technique="Valid Accounts",
                    mitre_id="T1078",
                    target_asset=next_hop,
                    source_asset=path[-2],
                    success=True,
                    detection_triggered=self._check_detection("siem", 0.2),
                    impact=f"Access to {next_hop} via valid credentials",
                    duration_seconds=random.randint(7200, 14400),  # Very slow
                    details={"credentials": "harvested"}
                ))
                
        lateral_paths.append(path)
        
        # Data exfiltration
        if target in compromised or "db-primary" in compromised:
            steps.append(SimulationStep(
                step_id=len(steps) + 1,
                technique="Exfiltration Over C2 Channel",
                mitre_id="T1041",
                target_asset=target or "db-primary",
                source_asset=current,
                success=True,
                detection_triggered=self._check_detection("dlp", 0.5),
                impact="Sensitive data exfiltrated",
                duration_seconds=random.randint(3600, 86400),  # Hours to days
                details={"data_size_gb": random.uniform(0.5, 10)}
            ))
            data_accessed.append(f"{target}:customer_data")
            data_accessed.append(f"{target}:financial_records")
            
        return steps, compromised, data_accessed, lateral_paths
        
    async def _simulate_lateral_movement(self, assets: Dict, entry: str, target: str) -> tuple:
        """Simulate lateral movement attack"""
        steps = []
        compromised = set()
        lateral_paths = []
        
        entry = entry or "workstation-it-01"
        compromised.add(entry)
        
        # BFS to find all reachable assets
        visited = {entry}
        queue = [(entry, [entry])]
        
        while queue:
            current, path = queue.pop(0)
            if current in assets:
                for conn in assets[current].connections:
                    if conn not in visited:
                        visited.add(conn)
                        new_path = path + [conn]
                        queue.append((conn, new_path))
                        compromised.add(conn)
                        lateral_paths.append(new_path)
                        
                        steps.append(SimulationStep(
                            step_id=len(steps) + 1,
                            technique="Remote Services",
                            mitre_id="T1021",
                            target_asset=conn,
                            source_asset=current,
                            success=True,
                            detection_triggered=self._check_detection("siem", 0.35),
                            impact=f"Lateral movement: {current} → {conn}",
                            duration_seconds=random.randint(30, 180),
                            details={"method": random.choice(["smb", "rdp", "ssh", "wmi"])}
                        ))
                        
        return steps, compromised, [], lateral_paths
        
    async def _simulate_privilege_escalation(self, assets: Dict, entry: str, target: str) -> tuple:
        """Simulate privilege escalation"""
        steps = []
        compromised = set()
        
        entry = entry or "workstation-it-01"
        compromised.add(entry)
        
        escalation_techniques = [
            ("T1548", "Abuse Elevation Control Mechanism", "Bypassed UAC"),
            ("T1134", "Access Token Manipulation", "Impersonated SYSTEM"),
            ("T1068", "Exploitation for Privilege Escalation", "Exploited local vulnerability"),
            ("T1484", "Domain Policy Modification", "Modified GPO for admin access"),
        ]
        
        for i, (mitre_id, technique, impact) in enumerate(escalation_techniques):
            steps.append(SimulationStep(
                step_id=i + 1,
                technique=technique,
                mitre_id=mitre_id,
                target_asset=entry,
                source_asset=entry,
                success=True,
                detection_triggered=self._check_detection("edr", 0.5 + i*0.1),
                impact=impact,
                duration_seconds=random.randint(30, 300),
                details={"privilege_level": ["user", "admin", "system", "domain_admin"][min(i, 3)]}
            ))
            
        # Target domain controller
        if "dc-01" in assets:
            steps.append(SimulationStep(
                step_id=len(steps) + 1,
                technique="DCSync",
                mitre_id="T1003.006",
                target_asset="dc-01",
                source_asset=entry,
                success=True,
                detection_triggered=self._check_detection("siem", 0.7),
                impact="Extracted domain admin password hashes",
                duration_seconds=random.randint(60, 300),
                details={"accounts_compromised": random.randint(50, 200)}
            ))
            compromised.add("dc-01")
            
        return steps, compromised, [], []
        
    async def _simulate_data_exfil(self, assets: Dict, entry: str, target: str) -> tuple:
        """Simulate data exfiltration"""
        steps = []
        compromised = set()
        data_accessed = []
        
        entry = entry or "app-server-01"
        target = target or "db-primary"
        compromised.add(entry)
        
        # Discovery
        steps.append(SimulationStep(
            step_id=1,
            technique="Data from Local System",
            mitre_id="T1005",
            target_asset=entry,
            source_asset=entry,
            success=True,
            detection_triggered=self._check_detection("edr", 0.2),
            impact="Local data discovered",
            duration_seconds=random.randint(60, 300),
            details={"files_scanned": random.randint(1000, 10000)}
        ))
        
        # Collection
        steps.append(SimulationStep(
            step_id=2,
            technique="Data Staged",
            mitre_id="T1074",
            target_asset=entry,
            source_asset=entry,
            success=True,
            detection_triggered=self._check_detection("dlp", 0.4),
            impact="Sensitive data collected and staged",
            duration_seconds=random.randint(300, 900),
            details={"data_size_mb": random.randint(100, 5000)}
        ))
        data_accessed.append(f"{entry}:staged_data")
        
        # Archive
        steps.append(SimulationStep(
            step_id=3,
            technique="Archive Collected Data",
            mitre_id="T1560",
            target_asset=entry,
            source_asset=entry,
            success=True,
            detection_triggered=self._check_detection("edr", 0.3),
            impact="Data compressed and encrypted",
            duration_seconds=random.randint(60, 300),
            details={"archive_size_mb": random.randint(50, 1000)}
        ))
        
        # Exfiltration
        steps.append(SimulationStep(
            step_id=4,
            technique="Exfiltration Over Web Service",
            mitre_id="T1567",
            target_asset=entry,
            source_asset=entry,
            success=True,
            detection_triggered=self._check_detection("dlp", 0.6),
            impact="Data exfiltrated to cloud storage",
            duration_seconds=random.randint(600, 3600),
            details={"destination": "cloud_storage", "protocol": "https"}
        ))
        data_accessed.append(f"{entry}:exfiltrated")
        
        return steps, compromised, data_accessed, []
        
    async def _simulate_ddos(self, assets: Dict, entry: str, target: str) -> tuple:
        """Simulate DDoS attack"""
        steps = []
        compromised = set()
        
        targets = ["web-server-01", "web-server-02", "api-gateway"]
        
        for target_asset in targets:
            if target_asset in assets:
                steps.append(SimulationStep(
                    step_id=len(steps) + 1,
                    technique="Network Denial of Service",
                    mitre_id="T1498",
                    target_asset=target_asset,
                    source_asset=None,
                    success=True,
                    detection_triggered=self._check_detection("ngfw", 0.9),
                    impact=f"Service degradation on {target_asset}",
                    duration_seconds=random.randint(300, 3600),
                    details={"attack_type": "volumetric", "peak_gbps": random.randint(10, 100)}
                ))
                
        return steps, compromised, [], []
        
    async def _simulate_insider(self, assets: Dict, entry: str, target: str) -> tuple:
        """Simulate insider threat"""
        steps = []
        compromised = set()
        data_accessed = []
        
        entry = entry or "workstation-hr-01"
        compromised.add(entry)
        
        # Insider already has legitimate access
        steps.append(SimulationStep(
            step_id=1,
            technique="Valid Accounts",
            mitre_id="T1078",
            target_asset="file-server",
            source_asset=entry,
            success=True,
            detection_triggered=self._check_detection("siem", 0.1),  # Hard to detect
            impact="Accessed file server with valid credentials",
            duration_seconds=random.randint(10, 60),
            details={"user": "insider@corp.local", "access": "legitimate"}
        ))
        compromised.add("file-server")
        
        # Data collection
        steps.append(SimulationStep(
            step_id=2,
            technique="Data from Network Shared Drive",
            mitre_id="T1039",
            target_asset="file-server",
            source_asset=entry,
            success=True,
            detection_triggered=self._check_detection("dlp", 0.3),
            impact="Bulk download of sensitive files",
            duration_seconds=random.randint(300, 1800),
            details={"files_accessed": random.randint(100, 1000)}
        ))
        data_accessed.append("file-server:hr_records")
        data_accessed.append("file-server:salary_data")
        
        # Exfiltration via USB
        steps.append(SimulationStep(
            step_id=3,
            technique="Exfiltration Over Physical Medium",
            mitre_id="T1052",
            target_asset=entry,
            source_asset=entry,
            success=True,
            detection_triggered=self._check_detection("dlp", 0.5),
            impact="Data copied to USB device",
            duration_seconds=random.randint(60, 300),
            details={"medium": "usb_drive", "data_size_gb": random.uniform(1, 32)}
        ))
        data_accessed.append(f"{entry}:usb_exfil")
        
        return steps, compromised, data_accessed, []
        
    async def _simulate_zero_day(self, assets: Dict, entry: str, target: str) -> tuple:
        """Simulate zero-day exploitation"""
        steps = []
        compromised = set()
        
        entry = entry or "api-gateway"
        compromised.add(entry)
        
        # Zero-day exploitation
        steps.append(SimulationStep(
            step_id=1,
            technique="Exploitation for Client Execution",
            mitre_id="T1203",
            target_asset=entry,
            source_asset=None,
            success=True,
            detection_triggered=self._check_detection("waf", 0.2),  # Zero-day bypasses signatures
            impact="Zero-day vulnerability exploited",
            duration_seconds=random.randint(1, 10),
            details={"vulnerability": "0-day", "type": "memory_corruption"}
        ))
        
        # Rapid escalation
        steps.append(SimulationStep(
            step_id=2,
            technique="Exploitation for Privilege Escalation",
            mitre_id="T1068",
            target_asset=entry,
            source_asset=entry,
            success=True,
            detection_triggered=self._check_detection("edr", 0.3),
            impact="Root/SYSTEM privileges obtained",
            duration_seconds=random.randint(5, 30),
            details={"privilege": "root"}
        ))
        
        # Immediate lateral movement
        if entry in assets:
            for conn in assets[entry].connections[:2]:
                compromised.add(conn)
                steps.append(SimulationStep(
                    step_id=len(steps) + 1,
                    technique="Exploitation of Remote Services",
                    mitre_id="T1210",
                    target_asset=conn,
                    source_asset=entry,
                    success=True,
                    detection_triggered=self._check_detection("siem", 0.4),
                    impact=f"Chained exploitation to {conn}",
                    duration_seconds=random.randint(10, 60),
                    details={"method": "zero-day-chain"}
                ))
                
        return steps, compromised, [], []
        
    async def _simulate_custom(self, assets: Dict, custom_steps: List[Dict]) -> List[SimulationStep]:
        """Run custom simulation steps"""
        steps = []
        for i, step_config in enumerate(custom_steps):
            steps.append(SimulationStep(
                step_id=i + 1,
                technique=step_config.get("technique", "Custom"),
                mitre_id=step_config.get("mitre_id", "T0000"),
                target_asset=step_config.get("target", "unknown"),
                source_asset=step_config.get("source"),
                success=step_config.get("success", True),
                detection_triggered=random.random() > 0.5,
                impact=step_config.get("impact", "Unknown impact"),
                duration_seconds=step_config.get("duration", 60),
                details=step_config.get("details", {})
            ))
        return steps
        
    def _check_detection(self, control_id: str, base_probability: float) -> bool:
        """Check if a security control detects the activity"""
        if control_id not in self.controls:
            return False
            
        control = self.controls[control_id]
        if not control.enabled:
            return False
            
        detection_prob = base_probability * control.effectiveness
        return random.random() < detection_prob
        
    def _generate_simulation_recommendations(
        self,
        steps: List[SimulationStep],
        compromised: Set[str]
    ) -> List[str]:
        """Generate recommendations based on simulation results"""
        recommendations = []
        
        # Analyze detection gaps
        undetected_steps = [s for s in steps if not s.detection_triggered]
        if undetected_steps:
            techniques = set(s.technique for s in undetected_steps)
            recommendations.append(f"Improve detection for: {', '.join(list(techniques)[:3])}")
            
        # Check compromised critical assets
        for asset_id in compromised:
            if asset_id in self.assets and self.assets[asset_id].criticality > 0.8:
                recommendations.append(f"Critical asset '{asset_id}' was compromised - review segmentation")
                
        # General recommendations based on attack type
        recommendations.extend([
            "Enable enhanced logging on all critical systems",
            "Implement network segmentation to limit lateral movement",
            "Deploy deception technology (honeypots/honeytokens)",
            "Conduct regular attack simulation exercises",
        ])
        
        return recommendations[:6]
        
    async def what_if_analysis(
        self,
        changes: List[Dict[str, Any]],
        simulation_type: SimulationType = SimulationType.RANSOMWARE
    ) -> WhatIfScenario:
        """Analyze the impact of proposed security changes"""
        
        # Create snapshot before changes
        baseline_risk = self._calculate_risk_score()
        
        # Apply changes temporarily
        original_assets = copy.deepcopy(self.assets)
        original_controls = copy.deepcopy(self.controls)
        affected = []
        side_effects = []
        
        for change in changes:
            change_type = change.get("type")
            
            if change_type == "patch":
                # Apply patch - remove vulnerability
                asset_id = change.get("asset_id")
                cve = change.get("cve")
                if asset_id in self.assets:
                    self.assets[asset_id].vulnerabilities = [
                        v for v in self.assets[asset_id].vulnerabilities
                        if v.get("cve") != cve
                    ]
                    self.assets[asset_id].patches_installed.append(cve)
                    affected.append(asset_id)
                    
            elif change_type == "enable_control":
                control_id = change.get("control_id")
                if control_id in self.controls:
                    self.controls[control_id].enabled = True
                    affected.extend(self.controls[control_id].coverage)
                    
            elif change_type == "disable_control":
                control_id = change.get("control_id")
                if control_id in self.controls:
                    self.controls[control_id].enabled = False
                    affected.extend(self.controls[control_id].coverage)
                    side_effects.append(f"Disabling {control_id} removes protection from {len(self.controls[control_id].coverage)} assets")
                    
            elif change_type == "segment_network":
                # Remove connections between assets
                asset1 = change.get("asset1")
                asset2 = change.get("asset2")
                if asset1 in self.assets and asset2 in self.assets[asset1].connections:
                    self.assets[asset1].connections.remove(asset2)
                    affected.extend([asset1, asset2])
                    
            elif change_type == "add_control":
                # Add new security control
                control_config = change.get("control")
                if control_config:
                    new_control = SecurityControl(**control_config)
                    self.controls[new_control.control_id] = new_control
                    affected.extend(new_control.coverage)
                    
        # Calculate new risk
        modified_risk = self._calculate_risk_score()
        risk_reduction = baseline_risk - modified_risk
        
        # Run simulation with changes applied
        sim_result = await self.run_simulation(simulation_type)
        
        # Restore original state
        self.assets = original_assets
        self.controls = original_controls
        
        # Analyze side effects
        if risk_reduction < 0:
            side_effects.append(f"Warning: Changes INCREASE risk by {abs(risk_reduction):.1f} points")
        elif risk_reduction > 20:
            side_effects.append(f"Significant risk reduction achieved")
            
        scenario = WhatIfScenario(
            scenario_id=f"WHATIF-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            name=f"What-If Analysis: {len(changes)} changes",
            description=f"Analyzing impact of {len(changes)} proposed security changes",
            changes=changes,
            baseline_risk=baseline_risk,
            modified_risk=modified_risk,
            risk_reduction=risk_reduction,
            affected_assets=list(set(affected)),
            side_effects=side_effects
        )
        
        return scenario
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get digital twin statistics"""
        return {
            "total_assets": len(self.assets),
            "total_networks": len(self.networks),
            "security_controls": len(self.controls),
            "active_controls": sum(1 for c in self.controls.values() if c.enabled),
            "snapshots": len(self.snapshots),
            "simulations_run": len(self.simulation_history),
            "sync_status": self.sync_status,
            "last_sync": self.last_sync.isoformat() if self.last_sync else None,
            "current_risk_score": self._calculate_risk_score(),
            "vulnerable_assets": sum(1 for a in self.assets.values() if a.vulnerabilities),
            "critical_assets": sum(1 for a in self.assets.values() if a.criticality > 0.8),
        }


async def main():
    """Test the Security Digital Twin"""
    print("=" * 60)
    print("HydraRecon Security Digital Twin")
    print("=" * 60)
    
    twin = SecurityDigitalTwin()
    
    # Sync with production
    print("\n[*] Synchronizing with production environment...")
    sync_result = await twin.sync_with_production()
    print(f"    Assets synced: {sync_result['assets_synced']}")
    print(f"    Networks synced: {sync_result['networks_synced']}")
    print(f"    Duration: {sync_result['duration_ms']}ms")
    
    # Get current state
    stats = twin.get_statistics()
    print(f"\n[*] Digital Twin Statistics:")
    print(f"    Total Assets: {stats['total_assets']}")
    print(f"    Total Networks: {stats['total_networks']}")
    print(f"    Security Controls: {stats['security_controls']} ({stats['active_controls']} active)")
    print(f"    Current Risk Score: {stats['current_risk_score']}/100")
    print(f"    Vulnerable Assets: {stats['vulnerable_assets']}")
    
    # Create snapshot
    print("\n[*] Creating baseline snapshot...")
    snapshot = twin.create_snapshot("baseline")
    print(f"    Snapshot ID: {snapshot.snapshot_id}")
    print(f"    Risk Score: {snapshot.risk_score}")
    
    # Run ransomware simulation
    print("\n[*] Running Ransomware Attack Simulation...")
    sim1 = await twin.run_simulation(SimulationType.RANSOMWARE)
    print(f"    Simulation ID: {sim1.simulation_id}")
    print(f"    Attack Steps: {len(sim1.steps)}")
    print(f"    Assets Compromised: {len(sim1.assets_compromised)}")
    print(f"    Detection Rate: {sim1.detection_rate:.0%}")
    print(f"    Impact Score: {sim1.impact_score}/100")
    if sim1.time_to_detection:
        print(f"    Time to Detection: {sim1.time_to_detection.total_seconds():.0f}s")
        
    # Run APT simulation
    print("\n[*] Running APT Campaign Simulation...")
    sim2 = await twin.run_simulation(SimulationType.APT)
    print(f"    Attack Steps: {len(sim2.steps)}")
    print(f"    Assets Compromised: {len(sim2.assets_compromised)}")
    print(f"    Data Accessed: {len(sim2.data_accessed)}")
    print(f"    Detection Rate: {sim2.detection_rate:.0%}")
    
    # What-if analysis
    print("\n[*] Running What-If Analysis...")
    print("    Scenario: Patch CVE-2024-8888 on app-server-01")
    what_if = await twin.what_if_analysis([
        {"type": "patch", "asset_id": "app-server-01", "cve": "CVE-2024-8888"},
        {"type": "segment_network", "asset1": "web-server-01", "asset2": "dc-01"},
    ])
    print(f"    Baseline Risk: {what_if.baseline_risk:.1f}")
    print(f"    Modified Risk: {what_if.modified_risk:.1f}")
    print(f"    Risk Reduction: {what_if.risk_reduction:.1f} points")
    print(f"    Affected Assets: {len(what_if.affected_assets)}")
    
    # Recommendations
    print(f"\n[*] Recommendations from Simulations:")
    for i, rec in enumerate(sim1.recommendations[:4], 1):
        print(f"    {i}. {rec}")
        
    print("\n" + "=" * 60)
    print("Security Digital Twin Test Complete")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
