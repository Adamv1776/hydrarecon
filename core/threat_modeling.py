"""
HydraRecon Threat Modeling Framework Module
Enterprise threat modeling and risk assessment framework
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ThreatCategory(Enum):
    """STRIDE threat categories"""
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class AssetType(Enum):
    """Asset types for threat modeling"""
    DATA = "data"
    PROCESS = "process"
    ACTOR = "actor"
    DATAFLOW = "dataflow"
    TRUST_BOUNDARY = "trust_boundary"
    EXTERNAL_ENTITY = "external_entity"
    DATASTORE = "datastore"


class ThreatStatus(Enum):
    """Threat analysis status"""
    IDENTIFIED = "identified"
    ANALYZING = "analyzing"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    TRANSFERRED = "transferred"
    DEFERRED = "deferred"


class MitigationStatus(Enum):
    """Mitigation implementation status"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    FAILED = "failed"


class SeverityLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ModelType(Enum):
    """Threat model types"""
    STRIDE = "stride"
    DREAD = "dread"
    PASTA = "pasta"
    OCTAVE = "octave"
    TRIKE = "trike"
    VAST = "vast"


@dataclass
class Asset:
    """System asset definition"""
    asset_id: str
    name: str
    description: str
    asset_type: AssetType
    sensitivity: str
    owner: str
    created_at: datetime = field(default_factory=datetime.now)
    
    data_classification: str = "Internal"
    connected_assets: List[str] = field(default_factory=list)
    trust_level: int = 0  # 0-100
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataFlow:
    """Data flow between assets"""
    flow_id: str
    name: str
    source_asset: str
    destination_asset: str
    protocol: str
    encrypted: bool
    authenticated: bool
    created_at: datetime = field(default_factory=datetime.now)
    
    data_types: List[str] = field(default_factory=list)
    volume: str = "Low"  # Low, Medium, High
    frequency: str = "Continuous"
    crosses_boundary: bool = False


@dataclass
class TrustBoundary:
    """Trust boundary definition"""
    boundary_id: str
    name: str
    description: str
    trust_level: int
    assets: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class Threat:
    """Identified threat"""
    threat_id: str
    name: str
    description: str
    category: ThreatCategory
    affected_assets: List[str]
    status: ThreatStatus
    severity: SeverityLevel
    created_at: datetime = field(default_factory=datetime.now)
    
    attack_vector: str = ""
    prerequisites: List[str] = field(default_factory=list)
    likelihood: float = 0.5  # 0.0 to 1.0
    impact: float = 0.5  # 0.0 to 1.0
    risk_score: float = 0.0
    
    mitigations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class Mitigation:
    """Threat mitigation"""
    mitigation_id: str
    name: str
    description: str
    threat_ids: List[str]
    status: MitigationStatus
    effectiveness: float  # 0.0 to 1.0
    cost: str
    owner: str
    created_at: datetime = field(default_factory=datetime.now)
    
    implementation_date: Optional[datetime] = None
    verification_date: Optional[datetime] = None
    residual_risk: float = 0.0
    notes: str = ""


@dataclass
class ThreatModel:
    """Complete threat model"""
    model_id: str
    name: str
    version: str
    model_type: ModelType
    scope: str
    status: str
    created_by: str
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    assets: List[str] = field(default_factory=list)
    dataflows: List[str] = field(default_factory=list)
    boundaries: List[str] = field(default_factory=list)
    threats: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    
    assumptions: List[str] = field(default_factory=list)
    external_dependencies: List[str] = field(default_factory=list)
    overall_risk_score: float = 0.0


@dataclass
class AttackTree:
    """Attack tree node"""
    node_id: str
    name: str
    description: str
    parent_id: Optional[str]
    node_type: str  # goal, subgoal, attack_step
    operator: str = "OR"  # AND, OR
    probability: float = 0.0
    cost: float = 0.0
    children: List[str] = field(default_factory=list)


@dataclass
class DREADScore:
    """DREAD risk scoring"""
    damage: int  # 1-10
    reproducibility: int  # 1-10
    exploitability: int  # 1-10
    affected_users: int  # 1-10
    discoverability: int  # 1-10
    
    @property
    def total_score(self) -> float:
        return (self.damage + self.reproducibility + self.exploitability + 
                self.affected_users + self.discoverability) / 5


class ThreatModelingEngine:
    """Enterprise Threat Modeling Engine"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "threat_models.db"
        self.assets: Dict[str, Asset] = {}
        self.dataflows: Dict[str, DataFlow] = {}
        self.boundaries: Dict[str, TrustBoundary] = {}
        self.threats: Dict[str, Threat] = {}
        self.mitigations: Dict[str, Mitigation] = {}
        self.models: Dict[str, ThreatModel] = {}
        self.attack_trees: Dict[str, AttackTree] = {}
        
        # STRIDE threat patterns
        self.stride_patterns = self._load_stride_patterns()
        
        # Common attack patterns (CAPEC)
        self.attack_patterns = self._load_attack_patterns()
    
    def _load_stride_patterns(self) -> Dict[str, List[Dict]]:
        """Load STRIDE threat patterns"""
        return {
            ThreatCategory.SPOOFING.value: [
                {
                    "name": "Credential Theft",
                    "description": "Attacker obtains valid credentials through phishing or keylogging",
                    "affected_types": [AssetType.ACTOR.value, AssetType.PROCESS.value],
                    "mitigations": ["Multi-factor authentication", "Credential monitoring"]
                },
                {
                    "name": "Session Hijacking",
                    "description": "Attacker takes over authenticated session",
                    "affected_types": [AssetType.DATAFLOW.value],
                    "mitigations": ["Session encryption", "Session timeout", "Token rotation"]
                },
                {
                    "name": "IP Spoofing",
                    "description": "Attacker forges source IP address",
                    "affected_types": [AssetType.DATAFLOW.value, AssetType.EXTERNAL_ENTITY.value],
                    "mitigations": ["Ingress filtering", "Source validation"]
                }
            ],
            ThreatCategory.TAMPERING.value: [
                {
                    "name": "Data Modification",
                    "description": "Unauthorized modification of data in transit or at rest",
                    "affected_types": [AssetType.DATA.value, AssetType.DATASTORE.value],
                    "mitigations": ["Integrity checks", "Digital signatures", "Access controls"]
                },
                {
                    "name": "SQL Injection",
                    "description": "Attacker injects malicious SQL to modify data",
                    "affected_types": [AssetType.DATASTORE.value, AssetType.PROCESS.value],
                    "mitigations": ["Parameterized queries", "Input validation", "WAF"]
                },
                {
                    "name": "Configuration Tampering",
                    "description": "Unauthorized changes to system configuration",
                    "affected_types": [AssetType.PROCESS.value],
                    "mitigations": ["Configuration management", "File integrity monitoring"]
                }
            ],
            ThreatCategory.REPUDIATION.value: [
                {
                    "name": "Log Deletion",
                    "description": "Attacker removes audit logs to hide activity",
                    "affected_types": [AssetType.DATASTORE.value],
                    "mitigations": ["Centralized logging", "Log integrity", "WORM storage"]
                },
                {
                    "name": "Transaction Denial",
                    "description": "User denies performing transaction",
                    "affected_types": [AssetType.PROCESS.value],
                    "mitigations": ["Digital signatures", "Audit trails", "Non-repudiation controls"]
                }
            ],
            ThreatCategory.INFORMATION_DISCLOSURE.value: [
                {
                    "name": "Data Exfiltration",
                    "description": "Unauthorized data transfer outside the organization",
                    "affected_types": [AssetType.DATA.value, AssetType.DATAFLOW.value],
                    "mitigations": ["DLP", "Network monitoring", "Encryption"]
                },
                {
                    "name": "Side Channel Attack",
                    "description": "Information leakage through timing, power, or EM",
                    "affected_types": [AssetType.PROCESS.value],
                    "mitigations": ["Constant-time operations", "Noise injection"]
                },
                {
                    "name": "Error Message Disclosure",
                    "description": "Sensitive information in error messages",
                    "affected_types": [AssetType.PROCESS.value],
                    "mitigations": ["Generic error messages", "Error handling review"]
                }
            ],
            ThreatCategory.DENIAL_OF_SERVICE.value: [
                {
                    "name": "Resource Exhaustion",
                    "description": "Consuming all available resources",
                    "affected_types": [AssetType.PROCESS.value],
                    "mitigations": ["Rate limiting", "Resource quotas", "Auto-scaling"]
                },
                {
                    "name": "DDoS Attack",
                    "description": "Distributed denial of service attack",
                    "affected_types": [AssetType.EXTERNAL_ENTITY.value, AssetType.PROCESS.value],
                    "mitigations": ["DDoS protection", "CDN", "Traffic analysis"]
                },
                {
                    "name": "Application DoS",
                    "description": "Exploit causing application crash",
                    "affected_types": [AssetType.PROCESS.value],
                    "mitigations": ["Input validation", "Exception handling", "Circuit breakers"]
                }
            ],
            ThreatCategory.ELEVATION_OF_PRIVILEGE.value: [
                {
                    "name": "Privilege Escalation",
                    "description": "Gaining higher privileges than authorized",
                    "affected_types": [AssetType.ACTOR.value, AssetType.PROCESS.value],
                    "mitigations": ["Least privilege", "Privilege separation", "PAM"]
                },
                {
                    "name": "Buffer Overflow",
                    "description": "Exploiting memory corruption for code execution",
                    "affected_types": [AssetType.PROCESS.value],
                    "mitigations": ["ASLR", "DEP", "Stack canaries", "Safe functions"]
                },
                {
                    "name": "Insecure Direct Object Reference",
                    "description": "Accessing unauthorized objects through ID manipulation",
                    "affected_types": [AssetType.DATA.value, AssetType.PROCESS.value],
                    "mitigations": ["Access control checks", "Indirect references"]
                }
            ]
        }
    
    def _load_attack_patterns(self) -> Dict[str, Dict]:
        """Load common attack patterns"""
        return {
            "CAPEC-66": {
                "name": "SQL Injection",
                "description": "Attack on database through SQL query manipulation",
                "prerequisites": ["SQL database", "User input to queries"],
                "consequences": ["Data breach", "Data modification", "Authentication bypass"]
            },
            "CAPEC-86": {
                "name": "XSS",
                "description": "Cross-site scripting attack",
                "prerequisites": ["Web application", "Reflected user input"],
                "consequences": ["Session theft", "Defacement", "Malware distribution"]
            },
            "CAPEC-115": {
                "name": "Authentication Bypass",
                "description": "Circumventing authentication mechanisms",
                "prerequisites": ["Authentication system", "Logic flaws"],
                "consequences": ["Unauthorized access", "Identity theft"]
            },
            "CAPEC-122": {
                "name": "Privilege Abuse",
                "description": "Misusing legitimate privileges",
                "prerequisites": ["Excessive privileges", "Weak monitoring"],
                "consequences": ["Data theft", "System compromise"]
            }
        }
    
    async def create_asset(self, asset: Asset) -> Asset:
        """Create a new asset"""
        self.assets[asset.asset_id] = asset
        return asset
    
    async def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Get asset by ID"""
        return self.assets.get(asset_id)
    
    async def list_assets(self, asset_type: Optional[AssetType] = None) -> List[Asset]:
        """List all assets, optionally filtered by type"""
        assets = list(self.assets.values())
        if asset_type:
            assets = [a for a in assets if a.asset_type == asset_type]
        return assets
    
    async def create_dataflow(self, dataflow: DataFlow) -> DataFlow:
        """Create a new data flow"""
        self.dataflows[dataflow.flow_id] = dataflow
        return dataflow
    
    async def get_dataflow(self, flow_id: str) -> Optional[DataFlow]:
        """Get data flow by ID"""
        return self.dataflows.get(flow_id)
    
    async def list_dataflows(self) -> List[DataFlow]:
        """List all data flows"""
        return list(self.dataflows.values())
    
    async def create_boundary(self, boundary: TrustBoundary) -> TrustBoundary:
        """Create a trust boundary"""
        self.boundaries[boundary.boundary_id] = boundary
        return boundary
    
    async def get_boundary(self, boundary_id: str) -> Optional[TrustBoundary]:
        """Get trust boundary by ID"""
        return self.boundaries.get(boundary_id)
    
    async def create_threat(self, threat: Threat) -> Threat:
        """Create a new threat"""
        # Calculate risk score
        threat.risk_score = self._calculate_risk(threat.likelihood, threat.impact)
        self.threats[threat.threat_id] = threat
        return threat
    
    async def get_threat(self, threat_id: str) -> Optional[Threat]:
        """Get threat by ID"""
        return self.threats.get(threat_id)
    
    async def update_threat(self, threat_id: str, updates: Dict[str, Any]) -> Optional[Threat]:
        """Update threat"""
        if threat_id in self.threats:
            threat = self.threats[threat_id]
            for key, value in updates.items():
                if hasattr(threat, key):
                    setattr(threat, key, value)
            # Recalculate risk
            threat.risk_score = self._calculate_risk(threat.likelihood, threat.impact)
            return threat
        return None
    
    async def list_threats(self, category: Optional[ThreatCategory] = None) -> List[Threat]:
        """List all threats, optionally filtered by category"""
        threats = list(self.threats.values())
        if category:
            threats = [t for t in threats if t.category == category]
        return threats
    
    async def create_mitigation(self, mitigation: Mitigation) -> Mitigation:
        """Create a new mitigation"""
        self.mitigations[mitigation.mitigation_id] = mitigation
        return mitigation
    
    async def get_mitigation(self, mitigation_id: str) -> Optional[Mitigation]:
        """Get mitigation by ID"""
        return self.mitigations.get(mitigation_id)
    
    async def update_mitigation(self, mitigation_id: str, updates: Dict[str, Any]) -> Optional[Mitigation]:
        """Update mitigation"""
        if mitigation_id in self.mitigations:
            mitigation = self.mitigations[mitigation_id]
            for key, value in updates.items():
                if hasattr(mitigation, key):
                    setattr(mitigation, key, value)
            return mitigation
        return None
    
    async def create_model(self, model: ThreatModel) -> ThreatModel:
        """Create a new threat model"""
        self.models[model.model_id] = model
        return model
    
    async def get_model(self, model_id: str) -> Optional[ThreatModel]:
        """Get threat model by ID"""
        return self.models.get(model_id)
    
    async def update_model(self, model_id: str, updates: Dict[str, Any]) -> Optional[ThreatModel]:
        """Update threat model"""
        if model_id in self.models:
            model = self.models[model_id]
            model.updated_at = datetime.now()
            for key, value in updates.items():
                if hasattr(model, key):
                    setattr(model, key, value)
            return model
        return None
    
    def _calculate_risk(self, likelihood: float, impact: float) -> float:
        """Calculate risk score from likelihood and impact"""
        return round(likelihood * impact * 100, 2)
    
    async def calculate_dread_score(self, threat_id: str, scores: DREADScore) -> Dict[str, Any]:
        """Calculate DREAD score for a threat"""
        threat = await self.get_threat(threat_id)
        if not threat:
            return {"error": "Threat not found"}
        
        total = scores.total_score
        
        # Map to severity
        if total >= 8:
            severity = SeverityLevel.CRITICAL
        elif total >= 6:
            severity = SeverityLevel.HIGH
        elif total >= 4:
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW
        
        return {
            "threat_id": threat_id,
            "dread_score": total,
            "severity": severity.value,
            "components": {
                "damage": scores.damage,
                "reproducibility": scores.reproducibility,
                "exploitability": scores.exploitability,
                "affected_users": scores.affected_users,
                "discoverability": scores.discoverability
            }
        }
    
    async def identify_stride_threats(self, asset_id: str) -> List[Dict[str, Any]]:
        """Identify potential STRIDE threats for an asset"""
        asset = await self.get_asset(asset_id)
        if not asset:
            return []
        
        identified_threats = []
        
        for category, patterns in self.stride_patterns.items():
            for pattern in patterns:
                if asset.asset_type.value in pattern["affected_types"]:
                    identified_threats.append({
                        "category": category,
                        "pattern_name": pattern["name"],
                        "description": pattern["description"],
                        "affected_asset": asset.name,
                        "suggested_mitigations": pattern["mitigations"]
                    })
        
        return identified_threats
    
    async def analyze_dataflow_threats(self, flow_id: str) -> List[Dict[str, Any]]:
        """Analyze threats for a data flow"""
        flow = await self.get_dataflow(flow_id)
        if not flow:
            return []
        
        threats = []
        
        # Check encryption
        if not flow.encrypted:
            threats.append({
                "category": ThreatCategory.INFORMATION_DISCLOSURE.value,
                "description": f"Data flow '{flow.name}' is not encrypted",
                "severity": SeverityLevel.HIGH.value,
                "recommendation": "Enable encryption for data in transit"
            })
        
        # Check authentication
        if not flow.authenticated:
            threats.append({
                "category": ThreatCategory.SPOOFING.value,
                "description": f"Data flow '{flow.name}' is not authenticated",
                "severity": SeverityLevel.MEDIUM.value,
                "recommendation": "Implement authentication for data flow"
            })
        
        # Check trust boundary crossing
        if flow.crosses_boundary:
            threats.append({
                "category": ThreatCategory.TAMPERING.value,
                "description": f"Data flow '{flow.name}' crosses trust boundary",
                "severity": SeverityLevel.MEDIUM.value,
                "recommendation": "Add integrity checks at trust boundary"
            })
        
        return threats
    
    async def generate_threat_report(self, model_id: str) -> Dict[str, Any]:
        """Generate comprehensive threat model report"""
        model = await self.get_model(model_id)
        if not model:
            return {"error": "Model not found"}
        
        # Get all related entities
        assets = [self.assets.get(a) for a in model.assets if a in self.assets]
        dataflows = [self.dataflows.get(d) for d in model.dataflows if d in self.dataflows]
        threats = [self.threats.get(t) for t in model.threats if t in self.threats]
        mitigations = [self.mitigations.get(m) for m in model.mitigations if m in self.mitigations]
        
        # Calculate statistics
        threat_by_category = {}
        threat_by_severity = {}
        threat_by_status = {}
        
        for threat in threats:
            if threat:
                cat = threat.category.value
                sev = threat.severity.value
                status = threat.status.value
                
                threat_by_category[cat] = threat_by_category.get(cat, 0) + 1
                threat_by_severity[sev] = threat_by_severity.get(sev, 0) + 1
                threat_by_status[status] = threat_by_status.get(status, 0) + 1
        
        # Calculate overall risk
        risk_scores = [t.risk_score for t in threats if t]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        # Mitigation coverage
        mitigated_threats = sum(1 for t in threats if t and t.status == ThreatStatus.MITIGATED)
        mitigation_coverage = (mitigated_threats / len(threats) * 100) if threats else 0
        
        return {
            "model_id": model_id,
            "model_name": model.name,
            "version": model.version,
            "model_type": model.model_type.value,
            "scope": model.scope,
            "created_by": model.created_by,
            "created_at": model.created_at.isoformat(),
            "updated_at": model.updated_at.isoformat(),
            "statistics": {
                "total_assets": len(assets),
                "total_dataflows": len(dataflows),
                "total_threats": len(threats),
                "total_mitigations": len(mitigations),
                "average_risk_score": round(avg_risk, 2),
                "mitigation_coverage": round(mitigation_coverage, 1)
            },
            "threat_distribution": {
                "by_category": threat_by_category,
                "by_severity": threat_by_severity,
                "by_status": threat_by_status
            },
            "high_priority_threats": [
                {
                    "id": t.threat_id,
                    "name": t.name,
                    "risk_score": t.risk_score,
                    "status": t.status.value
                }
                for t in threats if t and t.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
            ],
            "assumptions": model.assumptions,
            "external_dependencies": model.external_dependencies
        }
    
    async def create_attack_tree(self, root: AttackTree) -> AttackTree:
        """Create an attack tree"""
        self.attack_trees[root.node_id] = root
        return root
    
    async def add_attack_tree_node(self, parent_id: str, node: AttackTree) -> Optional[AttackTree]:
        """Add a node to attack tree"""
        if parent_id in self.attack_trees:
            parent = self.attack_trees[parent_id]
            node.parent_id = parent_id
            self.attack_trees[node.node_id] = node
            parent.children.append(node.node_id)
            return node
        return None
    
    async def calculate_attack_tree_probability(self, root_id: str) -> float:
        """Calculate probability of attack success"""
        def calc_probability(node_id: str) -> float:
            node = self.attack_trees.get(node_id)
            if not node:
                return 0.0
            
            if not node.children:
                return node.probability
            
            child_probs = [calc_probability(c) for c in node.children]
            
            if node.operator == "AND":
                # All children must succeed
                result = 1.0
                for p in child_probs:
                    result *= p
                return result
            else:  # OR
                # At least one child must succeed
                result = 0.0
                for p in child_probs:
                    result = result + p - (result * p)
                return result
        
        return calc_probability(root_id)
    
    async def suggest_mitigations(self, threat_id: str) -> List[Dict[str, Any]]:
        """Suggest mitigations for a threat"""
        threat = await self.get_threat(threat_id)
        if not threat:
            return []
        
        suggestions = []
        
        # Get STRIDE patterns for this category
        patterns = self.stride_patterns.get(threat.category.value, [])
        
        for pattern in patterns:
            for mitigation in pattern["mitigations"]:
                suggestions.append({
                    "name": mitigation,
                    "source": "STRIDE Pattern",
                    "effectiveness_estimate": 0.7
                })
        
        # Check existing mitigations
        existing = set()
        for mit_id in threat.mitigations:
            mit = self.mitigations.get(mit_id)
            if mit:
                existing.add(mit.name)
        
        # Filter out existing
        suggestions = [s for s in suggestions if s["name"] not in existing]
        
        return suggestions[:5]  # Return top 5 suggestions
    
    async def get_stride_patterns(self) -> Dict[str, List[Dict]]:
        """Get all STRIDE threat patterns"""
        return self.stride_patterns
    
    async def get_attack_patterns(self) -> Dict[str, Dict]:
        """Get common attack patterns"""
        return self.attack_patterns
    
    async def export_model(self, model_id: str, format: str = "json") -> str:
        """Export threat model"""
        report = await self.generate_threat_report(model_id)
        
        if format == "json":
            return json.dumps(report, indent=2)
        
        return json.dumps(report, indent=2)
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get threat modeling statistics"""
        threats_by_severity = {}
        for threat in self.threats.values():
            sev = threat.severity.value
            threats_by_severity[sev] = threats_by_severity.get(sev, 0) + 1
        
        mitigations_by_status = {}
        for mit in self.mitigations.values():
            status = mit.status.value
            mitigations_by_status[status] = mitigations_by_status.get(status, 0) + 1
        
        return {
            "total_models": len(self.models),
            "total_assets": len(self.assets),
            "total_dataflows": len(self.dataflows),
            "total_threats": len(self.threats),
            "total_mitigations": len(self.mitigations),
            "threats_by_severity": threats_by_severity,
            "mitigations_by_status": mitigations_by_status
        }
