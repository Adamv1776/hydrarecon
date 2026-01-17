"""
HydraRecon - Breach Simulation Engine
Advanced breach scenario simulation and impact analysis
"""

import asyncio
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import json


class BreachVector(Enum):
    """Attack vector types"""
    PHISHING = "phishing"
    CREDENTIAL_STUFFING = "credential_stuffing"
    SUPPLY_CHAIN = "supply_chain"
    INSIDER_THREAT = "insider_threat"
    RANSOMWARE = "ransomware"
    ZERO_DAY = "zero_day"
    MISCONFIGURATION = "misconfiguration"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RCE = "rce"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    APT = "apt"


class SimulationPhase(Enum):
    """Simulation phase types"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class AssetType(Enum):
    """Asset classification"""
    WORKSTATION = "workstation"
    SERVER = "server"
    DATABASE = "database"
    DOMAIN_CONTROLLER = "domain_controller"
    EMAIL_SERVER = "email_server"
    WEB_SERVER = "web_server"
    FILE_SERVER = "file_server"
    CLOUD_INSTANCE = "cloud_instance"
    IOT_DEVICE = "iot_device"
    NETWORK_DEVICE = "network_device"
    SECURITY_APPLIANCE = "security_appliance"


@dataclass
class SimulatedAsset:
    """Represents an asset in the simulation"""
    id: str
    name: str
    asset_type: AssetType
    ip_address: str
    criticality: int  # 1-10
    contains_sensitive_data: bool = False
    is_internet_facing: bool = False
    vulnerabilities: List[str] = field(default_factory=list)
    security_controls: List[str] = field(default_factory=list)
    compromised: bool = False
    compromise_time: Optional[datetime] = None


@dataclass
class SimulationEvent:
    """Event during breach simulation"""
    id: str
    timestamp: datetime
    phase: SimulationPhase
    vector: BreachVector
    source_asset: Optional[str]
    target_asset: str
    technique: str
    mitre_id: str
    success: bool
    detection_probability: float
    detected: bool
    details: str
    impact_score: float = 0.0


@dataclass
class BreachScenario:
    """Breach simulation scenario"""
    id: str
    name: str
    description: str
    initial_vector: BreachVector
    objectives: List[str]
    ttps: List[str]
    difficulty: str  # easy, medium, hard, advanced
    estimated_duration_hours: int
    industry_relevance: List[str]


@dataclass
class SimulationResult:
    """Result of breach simulation"""
    id: str
    scenario: BreachScenario
    start_time: datetime
    end_time: Optional[datetime]
    events: List[SimulationEvent]
    compromised_assets: List[str]
    detected_events: List[str]
    total_impact: float
    detection_rate: float
    mean_time_to_detect: float  # hours
    recommendations: List[str]


class BreachSimulationEngine:
    """Advanced breach simulation engine"""
    
    def __init__(self):
        self.assets: Dict[str, SimulatedAsset] = {}
        self.scenarios: Dict[str, BreachScenario] = {}
        self.simulations: Dict[str, SimulationResult] = {}
        self.current_simulation: Optional[SimulationResult] = None
        
        # Initialize sample data
        self._initialize_scenarios()
        self._initialize_sample_environment()
        
    def _initialize_scenarios(self):
        """Initialize breach scenarios"""
        scenarios = [
            BreachScenario(
                id="SCN-001",
                name="Phishing to Ransomware",
                description="Simulates a phishing attack leading to ransomware deployment",
                initial_vector=BreachVector.PHISHING,
                objectives=["Initial Access", "Credential Theft", "Ransomware Deployment"],
                ttps=["T1566.001", "T1003", "T1486", "T1490", "T1489"],
                difficulty="medium",
                estimated_duration_hours=4,
                industry_relevance=["Healthcare", "Finance", "Manufacturing"]
            ),
            BreachScenario(
                id="SCN-002",
                name="Supply Chain Compromise",
                description="Simulates a software supply chain attack",
                initial_vector=BreachVector.SUPPLY_CHAIN,
                objectives=["Backdoor Installation", "Data Exfiltration", "Persistence"],
                ttps=["T1195.002", "T1059", "T1567", "T1071"],
                difficulty="advanced",
                estimated_duration_hours=8,
                industry_relevance=["Technology", "Government", "Defense"]
            ),
            BreachScenario(
                id="SCN-003",
                name="Insider Data Theft",
                description="Simulates a malicious insider stealing sensitive data",
                initial_vector=BreachVector.INSIDER_THREAT,
                objectives=["Data Discovery", "Data Collection", "Exfiltration"],
                ttps=["T1087", "T1083", "T1119", "T1048"],
                difficulty="easy",
                estimated_duration_hours=2,
                industry_relevance=["Finance", "Healthcare", "Technology"]
            ),
            BreachScenario(
                id="SCN-004",
                name="APT Campaign",
                description="Simulates an advanced persistent threat campaign",
                initial_vector=BreachVector.APT,
                objectives=["Long-term Access", "Intelligence Gathering", "Data Exfiltration"],
                ttps=["T1566", "T1055", "T1003", "T1087", "T1021", "T1567"],
                difficulty="advanced",
                estimated_duration_hours=24,
                industry_relevance=["Government", "Defense", "Energy"]
            ),
            BreachScenario(
                id="SCN-005",
                name="Zero-Day Exploitation",
                description="Simulates exploitation of an unknown vulnerability",
                initial_vector=BreachVector.ZERO_DAY,
                objectives=["Code Execution", "Privilege Escalation", "Lateral Movement"],
                ttps=["T1190", "T1068", "T1021", "T1078"],
                difficulty="advanced",
                estimated_duration_hours=6,
                industry_relevance=["All Industries"]
            ),
            BreachScenario(
                id="SCN-006",
                name="Cloud Misconfiguration Attack",
                description="Exploits cloud infrastructure misconfigurations",
                initial_vector=BreachVector.MISCONFIGURATION,
                objectives=["Cloud Access", "Data Access", "Resource Hijacking"],
                ttps=["T1078.004", "T1530", "T1496"],
                difficulty="medium",
                estimated_duration_hours=3,
                industry_relevance=["Technology", "Finance", "Healthcare"]
            ),
            BreachScenario(
                id="SCN-007",
                name="Credential Stuffing Attack",
                description="Large-scale credential stuffing leading to account takeover",
                initial_vector=BreachVector.CREDENTIAL_STUFFING,
                objectives=["Account Access", "Privilege Escalation", "Data Theft"],
                ttps=["T1110.004", "T1078", "T1087"],
                difficulty="easy",
                estimated_duration_hours=2,
                industry_relevance=["Retail", "Finance", "Healthcare"]
            ),
            BreachScenario(
                id="SCN-008",
                name="SQL Injection to Database Breach",
                description="SQL injection attack leading to database compromise",
                initial_vector=BreachVector.SQL_INJECTION,
                objectives=["Database Access", "Data Exfiltration", "Privilege Escalation"],
                ttps=["T1190", "T1505", "T1505.003"],
                difficulty="medium",
                estimated_duration_hours=3,
                industry_relevance=["E-commerce", "Finance", "Healthcare"]
            ),
        ]
        
        for scenario in scenarios:
            self.scenarios[scenario.id] = scenario
            
    def _initialize_sample_environment(self):
        """Initialize sample environment for simulation"""
        sample_assets = [
            SimulatedAsset(
                id="ASSET-001",
                name="DC-PRIMARY",
                asset_type=AssetType.DOMAIN_CONTROLLER,
                ip_address="10.0.0.10",
                criticality=10,
                contains_sensitive_data=True,
                vulnerabilities=["CVE-2021-34527", "CVE-2020-1472"],
                security_controls=["EDR", "SIEM", "MFA"]
            ),
            SimulatedAsset(
                id="ASSET-002",
                name="SQL-PROD-01",
                asset_type=AssetType.DATABASE,
                ip_address="10.0.1.20",
                criticality=9,
                contains_sensitive_data=True,
                vulnerabilities=["CVE-2019-1068"],
                security_controls=["Database Firewall", "Encryption"]
            ),
            SimulatedAsset(
                id="ASSET-003",
                name="WEB-FRONTEND",
                asset_type=AssetType.WEB_SERVER,
                ip_address="10.0.2.10",
                criticality=7,
                is_internet_facing=True,
                vulnerabilities=["CVE-2021-44228"],
                security_controls=["WAF", "CDN"]
            ),
            SimulatedAsset(
                id="ASSET-004",
                name="MAIL-SERVER",
                asset_type=AssetType.EMAIL_SERVER,
                ip_address="10.0.0.25",
                criticality=8,
                contains_sensitive_data=True,
                is_internet_facing=True,
                security_controls=["Email Gateway", "SPF", "DKIM", "DMARC"]
            ),
            SimulatedAsset(
                id="ASSET-005",
                name="FILE-SERVER-01",
                asset_type=AssetType.FILE_SERVER,
                ip_address="10.0.1.30",
                criticality=8,
                contains_sensitive_data=True,
                vulnerabilities=["SMBv1 Enabled"],
                security_controls=["DLP", "Backup"]
            ),
            SimulatedAsset(
                id="ASSET-006",
                name="WORKSTATION-HR-01",
                asset_type=AssetType.WORKSTATION,
                ip_address="10.0.5.101",
                criticality=6,
                contains_sensitive_data=True,
                security_controls=["EDR", "Full Disk Encryption"]
            ),
            SimulatedAsset(
                id="ASSET-007",
                name="CLOUD-AWS-PROD",
                asset_type=AssetType.CLOUD_INSTANCE,
                ip_address="10.100.0.5",
                criticality=9,
                contains_sensitive_data=True,
                vulnerabilities=["S3 Public Access"],
                security_controls=["CloudTrail", "GuardDuty"]
            ),
            SimulatedAsset(
                id="ASSET-008",
                name="FW-PERIMETER",
                asset_type=AssetType.SECURITY_APPLIANCE,
                ip_address="10.0.0.1",
                criticality=10,
                security_controls=["IPS", "Threat Intel"]
            ),
            SimulatedAsset(
                id="ASSET-009",
                name="IOT-HVAC",
                asset_type=AssetType.IOT_DEVICE,
                ip_address="10.0.10.50",
                criticality=4,
                vulnerabilities=["Default Credentials", "Unpatched Firmware"],
                security_controls=[]
            ),
            SimulatedAsset(
                id="ASSET-010",
                name="APP-SERVER-01",
                asset_type=AssetType.SERVER,
                ip_address="10.0.1.40",
                criticality=8,
                vulnerabilities=["CVE-2022-22965"],
                security_controls=["EDR", "Application Firewall"]
            ),
        ]
        
        for asset in sample_assets:
            self.assets[asset.id] = asset
            
    def get_all_scenarios(self) -> List[Dict]:
        """Get all available scenarios"""
        return [
            {
                "id": s.id,
                "name": s.name,
                "description": s.description,
                "vector": s.initial_vector.value,
                "difficulty": s.difficulty,
                "duration": s.estimated_duration_hours,
                "objectives": s.objectives,
                "ttps": s.ttps,
                "industries": s.industry_relevance,
            }
            for s in self.scenarios.values()
        ]
        
    def get_environment_summary(self) -> Dict:
        """Get simulation environment summary"""
        return {
            "total_assets": len(self.assets),
            "by_type": {
                t.value: sum(1 for a in self.assets.values() if a.asset_type == t)
                for t in AssetType
            },
            "vulnerable_assets": sum(1 for a in self.assets.values() if a.vulnerabilities),
            "critical_assets": sum(1 for a in self.assets.values() if a.criticality >= 8),
            "internet_facing": sum(1 for a in self.assets.values() if a.is_internet_facing),
            "sensitive_data": sum(1 for a in self.assets.values() if a.contains_sensitive_data),
        }
        
    async def run_simulation(self, scenario_id: str) -> SimulationResult:
        """Run a breach simulation"""
        scenario = self.scenarios.get(scenario_id)
        if not scenario:
            raise ValueError(f"Scenario {scenario_id} not found")
            
        # Reset asset compromise status
        for asset in self.assets.values():
            asset.compromised = False
            asset.compromise_time = None
            
        result = SimulationResult(
            id=f"SIM-{uuid.uuid4().hex[:8].upper()}",
            scenario=scenario,
            start_time=datetime.now(),
            end_time=None,
            events=[],
            compromised_assets=[],
            detected_events=[],
            total_impact=0.0,
            detection_rate=0.0,
            mean_time_to_detect=0.0,
            recommendations=[]
        )
        
        self.current_simulation = result
        
        # Run simulation phases
        await self._simulate_breach(result, scenario)
        
        # Calculate final metrics
        result.end_time = datetime.now()
        result.detection_rate = (
            len(result.detected_events) / len(result.events) * 100
            if result.events else 0
        )
        
        detected_times = [
            e.timestamp for e in result.events if e.detected
        ]
        if detected_times:
            first_event = min(e.timestamp for e in result.events)
            first_detection = min(detected_times)
            mttd = (first_detection - first_event).total_seconds() / 3600
            result.mean_time_to_detect = round(mttd, 2)
            
        # Generate recommendations
        result.recommendations = self._generate_recommendations(result)
        
        self.simulations[result.id] = result
        
        return result
        
    async def _simulate_breach(self, result: SimulationResult, scenario: BreachScenario):
        """Simulate the breach phases"""
        phases = list(SimulationPhase)
        
        # Determine entry point
        entry_asset = self._select_entry_point(scenario)
        current_assets = {entry_asset.id}
        
        for phase in phases[:8]:  # Simulate first 8 phases
            await asyncio.sleep(0.1)  # Simulation delay
            
            events = await self._simulate_phase(
                result, scenario, phase, list(current_assets)
            )
            
            result.events.extend(events)
            
            # Track compromised assets
            for event in events:
                if event.success:
                    current_assets.add(event.target_asset)
                    if event.target_asset not in result.compromised_assets:
                        result.compromised_assets.append(event.target_asset)
                        asset = self.assets.get(event.target_asset)
                        if asset:
                            asset.compromised = True
                            asset.compromise_time = event.timestamp
                            result.total_impact += asset.criticality * 10
                            
                if event.detected:
                    result.detected_events.append(event.id)
                    
    async def _simulate_phase(
        self,
        result: SimulationResult,
        scenario: BreachScenario,
        phase: SimulationPhase,
        source_assets: List[str]
    ) -> List[SimulationEvent]:
        """Simulate a single phase"""
        events = []
        
        # Get appropriate MITRE techniques for phase
        techniques = self._get_phase_techniques(phase, scenario)
        
        for technique, mitre_id in techniques:
            # Select target based on phase
            target = self._select_target(phase, source_assets)
            if not target:
                continue
                
            # Calculate success probability
            success_prob = self._calculate_success_probability(target, phase)
            success = random.random() < success_prob
            
            # Calculate detection probability
            detection_prob = self._calculate_detection_probability(target, phase)
            detected = random.random() < detection_prob
            
            event = SimulationEvent(
                id=f"EVT-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.now(),
                phase=phase,
                vector=scenario.initial_vector,
                source_asset=source_assets[0] if source_assets else None,
                target_asset=target.id,
                technique=technique,
                mitre_id=mitre_id,
                success=success,
                detection_probability=detection_prob,
                detected=detected,
                details=self._generate_event_details(phase, technique, target, success),
                impact_score=target.criticality * (1 if success else 0)
            )
            
            events.append(event)
            
        return events
        
    def _get_phase_techniques(
        self, phase: SimulationPhase, scenario: BreachScenario
    ) -> List[Tuple[str, str]]:
        """Get MITRE techniques for a phase"""
        phase_techniques = {
            SimulationPhase.INITIAL_ACCESS: [
                ("Phishing Attachment", "T1566.001"),
                ("Drive-by Compromise", "T1189"),
                ("Valid Accounts", "T1078"),
            ],
            SimulationPhase.EXECUTION: [
                ("PowerShell", "T1059.001"),
                ("Windows Command Shell", "T1059.003"),
                ("Scheduled Task", "T1053.005"),
            ],
            SimulationPhase.PERSISTENCE: [
                ("Registry Run Keys", "T1547.001"),
                ("Scheduled Task", "T1053.005"),
                ("Account Manipulation", "T1098"),
            ],
            SimulationPhase.PRIVILEGE_ESCALATION: [
                ("Token Impersonation", "T1134"),
                ("Process Injection", "T1055"),
                ("Exploitation for Privilege Escalation", "T1068"),
            ],
            SimulationPhase.DEFENSE_EVASION: [
                ("Masquerading", "T1036"),
                ("Obfuscated Files", "T1027"),
                ("Disable Security Tools", "T1562.001"),
            ],
            SimulationPhase.CREDENTIAL_ACCESS: [
                ("OS Credential Dumping", "T1003"),
                ("Brute Force", "T1110"),
                ("Input Capture", "T1056"),
            ],
            SimulationPhase.DISCOVERY: [
                ("Account Discovery", "T1087"),
                ("Network Service Scanning", "T1046"),
                ("File and Directory Discovery", "T1083"),
            ],
            SimulationPhase.LATERAL_MOVEMENT: [
                ("Remote Services", "T1021"),
                ("Remote Desktop Protocol", "T1021.001"),
                ("Windows Admin Shares", "T1021.002"),
            ],
        }
        
        return phase_techniques.get(phase, [])[:2]
        
    def _select_entry_point(self, scenario: BreachScenario) -> SimulatedAsset:
        """Select initial entry point based on scenario"""
        if scenario.initial_vector == BreachVector.PHISHING:
            workstations = [a for a in self.assets.values() if a.asset_type == AssetType.WORKSTATION]
            return random.choice(workstations) if workstations else list(self.assets.values())[0]
            
        if scenario.initial_vector in [BreachVector.SQL_INJECTION, BreachVector.XSS]:
            web_assets = [a for a in self.assets.values() if a.is_internet_facing]
            return random.choice(web_assets) if web_assets else list(self.assets.values())[0]
            
        if scenario.initial_vector == BreachVector.MISCONFIGURATION:
            cloud_assets = [a for a in self.assets.values() if a.asset_type == AssetType.CLOUD_INSTANCE]
            return random.choice(cloud_assets) if cloud_assets else list(self.assets.values())[0]
            
        # Default: random vulnerable asset
        vulnerable = [a for a in self.assets.values() if a.vulnerabilities]
        return random.choice(vulnerable) if vulnerable else list(self.assets.values())[0]
        
    def _select_target(
        self, phase: SimulationPhase, source_assets: List[str]
    ) -> Optional[SimulatedAsset]:
        """Select target for a phase"""
        candidates = [
            a for a in self.assets.values()
            if a.id not in source_assets and not a.compromised
        ]
        
        if not candidates:
            candidates = list(self.assets.values())
            
        # Prioritize by phase
        if phase == SimulationPhase.CREDENTIAL_ACCESS:
            dc = [a for a in candidates if a.asset_type == AssetType.DOMAIN_CONTROLLER]
            if dc:
                return random.choice(dc)
                
        if phase == SimulationPhase.COLLECTION:
            data_assets = [a for a in candidates if a.contains_sensitive_data]
            if data_assets:
                return random.choice(data_assets)
                
        return random.choice(candidates) if candidates else None
        
    def _calculate_success_probability(
        self, target: SimulatedAsset, phase: SimulationPhase
    ) -> float:
        """Calculate attack success probability"""
        base_prob = 0.7
        
        # Reduce for security controls
        base_prob -= len(target.security_controls) * 0.1
        
        # Increase for vulnerabilities
        base_prob += len(target.vulnerabilities) * 0.15
        
        # Adjust for asset criticality (better protected)
        if target.criticality >= 8:
            base_prob -= 0.2
            
        return max(0.1, min(0.95, base_prob))
        
    def _calculate_detection_probability(
        self, target: SimulatedAsset, phase: SimulationPhase
    ) -> float:
        """Calculate detection probability"""
        base_prob = 0.3
        
        # Increase for security controls
        if "EDR" in target.security_controls:
            base_prob += 0.25
        if "SIEM" in target.security_controls:
            base_prob += 0.2
        if "IPS" in target.security_controls:
            base_prob += 0.15
            
        # Noisy phases more likely detected
        if phase in [SimulationPhase.LATERAL_MOVEMENT, SimulationPhase.EXECUTION]:
            base_prob += 0.1
            
        return min(0.9, base_prob)
        
    def _generate_event_details(
        self,
        phase: SimulationPhase,
        technique: str,
        target: SimulatedAsset,
        success: bool
    ) -> str:
        """Generate event description"""
        result = "successful" if success else "failed"
        return f"{technique} attempt against {target.name} ({target.ip_address}) - {result}"
        
    def _generate_recommendations(self, result: SimulationResult) -> List[str]:
        """Generate security recommendations based on simulation"""
        recommendations = []
        
        # Analyze compromised assets
        for asset_id in result.compromised_assets:
            asset = self.assets.get(asset_id)
            if asset:
                if not asset.security_controls:
                    recommendations.append(
                        f"Deploy endpoint detection on {asset.name}"
                    )
                if asset.vulnerabilities:
                    recommendations.append(
                        f"Patch critical vulnerabilities on {asset.name}"
                    )
                    
        # Analyze detection rate
        if result.detection_rate < 50:
            recommendations.append(
                "Improve detection capabilities - consider deploying SIEM and EDR"
            )
            
        if result.mean_time_to_detect > 4:
            recommendations.append(
                "Reduce mean time to detect - implement real-time alerting"
            )
            
        # Scenario-specific recommendations
        if result.scenario.initial_vector == BreachVector.PHISHING:
            recommendations.append(
                "Enhance phishing awareness training for employees"
            )
            recommendations.append(
                "Implement email authentication (SPF, DKIM, DMARC)"
            )
            
        if result.scenario.initial_vector == BreachVector.CREDENTIAL_STUFFING:
            recommendations.append(
                "Enforce multi-factor authentication across all systems"
            )
            recommendations.append(
                "Implement credential monitoring and breach detection"
            )
            
        return recommendations[:10]
        
    def get_simulation_summary(self, simulation_id: str) -> Optional[Dict]:
        """Get simulation summary"""
        result = self.simulations.get(simulation_id)
        if not result:
            return None
            
        return {
            "id": result.id,
            "scenario": result.scenario.name,
            "start_time": result.start_time.isoformat(),
            "end_time": result.end_time.isoformat() if result.end_time else None,
            "total_events": len(result.events),
            "successful_attacks": sum(1 for e in result.events if e.success),
            "detected_events": len(result.detected_events),
            "compromised_assets": len(result.compromised_assets),
            "total_impact": result.total_impact,
            "detection_rate": result.detection_rate,
            "mean_time_to_detect": result.mean_time_to_detect,
            "recommendations": result.recommendations,
        }
        
    def get_attack_timeline(self, simulation_id: str) -> List[Dict]:
        """Get attack timeline for visualization"""
        result = self.simulations.get(simulation_id)
        if not result:
            return []
            
        return [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "phase": e.phase.value,
                "technique": e.technique,
                "mitre_id": e.mitre_id,
                "target": e.target_asset,
                "success": e.success,
                "detected": e.detected,
                "details": e.details,
            }
            for e in result.events
        ]
        
    @property
    def stats(self) -> Dict:
        """Get engine statistics"""
        return {
            "scenarios": len(self.scenarios),
            "assets": len(self.assets),
            "simulations_run": len(self.simulations),
            "last_simulation": (
                self.simulations[max(self.simulations.keys())].id
                if self.simulations else None
            ),
        }


# Global instance
_engine_instance: Optional[BreachSimulationEngine] = None


def get_breach_simulation_engine() -> BreachSimulationEngine:
    """Get or create breach simulation engine"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = BreachSimulationEngine()
    return _engine_instance
