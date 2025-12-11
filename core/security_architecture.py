"""
HydraRecon Security Architecture Review Module
Enterprise security architecture assessment and design review framework
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ArchitectureLayer(Enum):
    """Security architecture layers"""
    NETWORK = "network"
    APPLICATION = "application"
    DATA = "data"
    ENDPOINT = "endpoint"
    IDENTITY = "identity"
    PERIMETER = "perimeter"
    CLOUD = "cloud"
    PHYSICAL = "physical"


class ControlType(Enum):
    """Security control types"""
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    DETERRENT = "deterrent"
    COMPENSATING = "compensating"
    RECOVERY = "recovery"


class ReviewStatus(Enum):
    """Architecture review status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_REVISION = "needs_revision"


class RiskLevel(Enum):
    """Architecture risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceStatus(Enum):
    """Compliance alignment status"""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNDER_REVIEW = "under_review"


@dataclass
class SecurityControl:
    """Security control definition"""
    control_id: str
    name: str
    description: str
    layer: ArchitectureLayer
    control_type: ControlType
    effectiveness: float  # 0.0 to 1.0
    implementation_status: str
    owner: str
    created_at: datetime = field(default_factory=datetime.now)
    
    dependencies: List[str] = field(default_factory=list)
    compliance_mappings: Dict[str, str] = field(default_factory=dict)  # framework: control_id
    evidence: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class ArchitectureDiagram:
    """Security architecture diagram"""
    diagram_id: str
    name: str
    version: str
    layer: ArchitectureLayer
    components: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    security_zones: List[Dict[str, Any]]
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    annotations: List[Dict[str, Any]] = field(default_factory=list)
    risk_indicators: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ArchitectureReview:
    """Security architecture review record"""
    review_id: str
    name: str
    scope: str
    status: ReviewStatus
    reviewer: str
    created_at: datetime = field(default_factory=datetime.now)
    
    layers_reviewed: List[ArchitectureLayer] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    compliance_score: float = 0.0
    approval_chain: List[Dict[str, Any]] = field(default_factory=list)


@dataclass 
class ThreatVector:
    """Threat vector analysis"""
    vector_id: str
    name: str
    description: str
    attack_surface: str
    entry_points: List[str]
    mitigating_controls: List[str]
    residual_risk: RiskLevel
    likelihood: float
    impact: float
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class ComplianceMapping:
    """Compliance framework mapping"""
    mapping_id: str
    framework: str
    control_family: str
    control_id: str
    requirement: str
    status: ComplianceStatus
    evidence: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class ArchitecturePattern:
    """Security architecture pattern"""
    pattern_id: str
    name: str
    description: str
    category: str
    layers: List[ArchitectureLayer]
    components: List[Dict[str, Any]]
    benefits: List[str]
    limitations: List[str]
    use_cases: List[str]
    created_at: datetime = field(default_factory=datetime.now)


class SecurityArchitectureEngine:
    """Enterprise Security Architecture Review Engine"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "security_architecture.db"
        self.controls: Dict[str, SecurityControl] = {}
        self.diagrams: Dict[str, ArchitectureDiagram] = {}
        self.reviews: Dict[str, ArchitectureReview] = {}
        self.threat_vectors: Dict[str, ThreatVector] = {}
        self.compliance_mappings: Dict[str, ComplianceMapping] = {}
        self.patterns: Dict[str, ArchitecturePattern] = {}
        
        # Reference architectures
        self.reference_architectures: Dict[str, Dict] = {}
        
        # Compliance frameworks
        self.compliance_frameworks = {
            "NIST_CSF": self._load_nist_csf_controls(),
            "ISO_27001": self._load_iso_27001_controls(),
            "CIS": self._load_cis_controls(),
            "SABSA": self._load_sabsa_domains(),
            "TOGAF": self._load_togaf_security(),
            "ZERO_TRUST": self._load_zero_trust_pillars()
        }
        
        self._initialize_patterns()
    
    def _load_nist_csf_controls(self) -> Dict[str, Any]:
        """Load NIST Cybersecurity Framework"""
        return {
            "ID": {
                "name": "Identify",
                "categories": {
                    "ID.AM": "Asset Management",
                    "ID.BE": "Business Environment",
                    "ID.GV": "Governance",
                    "ID.RA": "Risk Assessment",
                    "ID.RM": "Risk Management Strategy",
                    "ID.SC": "Supply Chain Risk Management"
                }
            },
            "PR": {
                "name": "Protect",
                "categories": {
                    "PR.AC": "Identity Management and Access Control",
                    "PR.AT": "Awareness and Training",
                    "PR.DS": "Data Security",
                    "PR.IP": "Information Protection",
                    "PR.MA": "Maintenance",
                    "PR.PT": "Protective Technology"
                }
            },
            "DE": {
                "name": "Detect",
                "categories": {
                    "DE.AE": "Anomalies and Events",
                    "DE.CM": "Security Continuous Monitoring",
                    "DE.DP": "Detection Processes"
                }
            },
            "RS": {
                "name": "Respond",
                "categories": {
                    "RS.RP": "Response Planning",
                    "RS.CO": "Communications",
                    "RS.AN": "Analysis",
                    "RS.MI": "Mitigation",
                    "RS.IM": "Improvements"
                }
            },
            "RC": {
                "name": "Recover",
                "categories": {
                    "RC.RP": "Recovery Planning",
                    "RC.IM": "Improvements",
                    "RC.CO": "Communications"
                }
            }
        }
    
    def _load_iso_27001_controls(self) -> Dict[str, Any]:
        """Load ISO 27001 control domains"""
        return {
            "A.5": "Information Security Policies",
            "A.6": "Organization of Information Security",
            "A.7": "Human Resource Security",
            "A.8": "Asset Management",
            "A.9": "Access Control",
            "A.10": "Cryptography",
            "A.11": "Physical and Environmental Security",
            "A.12": "Operations Security",
            "A.13": "Communications Security",
            "A.14": "System Acquisition, Development and Maintenance",
            "A.15": "Supplier Relationships",
            "A.16": "Information Security Incident Management",
            "A.17": "Business Continuity Management",
            "A.18": "Compliance"
        }
    
    def _load_cis_controls(self) -> Dict[str, Any]:
        """Load CIS Critical Security Controls"""
        return {
            "CIS-1": "Inventory and Control of Enterprise Assets",
            "CIS-2": "Inventory and Control of Software Assets",
            "CIS-3": "Data Protection",
            "CIS-4": "Secure Configuration of Assets and Software",
            "CIS-5": "Account Management",
            "CIS-6": "Access Control Management",
            "CIS-7": "Continuous Vulnerability Management",
            "CIS-8": "Audit Log Management",
            "CIS-9": "Email and Web Browser Protections",
            "CIS-10": "Malware Defenses",
            "CIS-11": "Data Recovery",
            "CIS-12": "Network Infrastructure Management",
            "CIS-13": "Network Monitoring and Defense",
            "CIS-14": "Security Awareness and Skills Training",
            "CIS-15": "Service Provider Management",
            "CIS-16": "Application Software Security",
            "CIS-17": "Incident Response Management",
            "CIS-18": "Penetration Testing"
        }
    
    def _load_sabsa_domains(self) -> Dict[str, Any]:
        """Load SABSA security architecture domains"""
        return {
            "contextual": {
                "name": "Contextual Security Architecture",
                "views": ["Business View", "Architect's View"]
            },
            "conceptual": {
                "name": "Conceptual Security Architecture",
                "views": ["What", "Why", "How", "Who", "Where", "When"]
            },
            "logical": {
                "name": "Logical Security Architecture",
                "views": ["Entity Model", "Trust Model", "Privilege Model"]
            },
            "physical": {
                "name": "Physical Security Architecture",
                "views": ["Technology", "Tools", "Products"]
            },
            "component": {
                "name": "Component Security Architecture",
                "views": ["Detailed Design", "Build Specs"]
            },
            "operational": {
                "name": "Operational Security Architecture",
                "views": ["Run Time", "Monitor", "Manage"]
            }
        }
    
    def _load_togaf_security(self) -> Dict[str, Any]:
        """Load TOGAF security extension domains"""
        return {
            "security_architecture": [
                "Security Principles",
                "Security Patterns",
                "Security Standards",
                "Security Guidelines"
            ],
            "domains": [
                "Business Security Architecture",
                "Information Security Architecture",
                "Application Security Architecture",
                "Technology Security Architecture"
            ]
        }
    
    def _load_zero_trust_pillars(self) -> Dict[str, Any]:
        """Load Zero Trust architecture pillars"""
        return {
            "identity": {
                "name": "Identity",
                "controls": [
                    "Strong Authentication",
                    "Continuous Verification",
                    "Risk-Based Access"
                ]
            },
            "devices": {
                "name": "Devices",
                "controls": [
                    "Device Health Validation",
                    "Endpoint Detection and Response",
                    "Mobile Device Management"
                ]
            },
            "network": {
                "name": "Network",
                "controls": [
                    "Micro-Segmentation",
                    "Encrypted Communications",
                    "Network Access Control"
                ]
            },
            "applications": {
                "name": "Applications",
                "controls": [
                    "Application Proxies",
                    "API Security",
                    "Application Health Monitoring"
                ]
            },
            "data": {
                "name": "Data",
                "controls": [
                    "Data Classification",
                    "Data Encryption",
                    "Data Loss Prevention"
                ]
            },
            "visibility": {
                "name": "Visibility and Analytics",
                "controls": [
                    "Security Analytics",
                    "Threat Intelligence",
                    "User Behavior Analytics"
                ]
            },
            "automation": {
                "name": "Automation and Orchestration",
                "controls": [
                    "Security Orchestration",
                    "Automated Response",
                    "Policy Automation"
                ]
            }
        }
    
    def _initialize_patterns(self):
        """Initialize security architecture patterns"""
        patterns = [
            ArchitecturePattern(
                pattern_id="PAT-001",
                name="Defense in Depth",
                description="Layered security controls to protect assets",
                category="Perimeter",
                layers=[ArchitectureLayer.NETWORK, ArchitectureLayer.APPLICATION, ArchitectureLayer.DATA],
                components=[
                    {"type": "firewall", "layer": "perimeter"},
                    {"type": "waf", "layer": "application"},
                    {"type": "ids", "layer": "network"},
                    {"type": "encryption", "layer": "data"}
                ],
                benefits=["Redundant protection", "Attack complexity increase", "Defense resilience"],
                limitations=["Cost", "Complexity", "Performance overhead"],
                use_cases=["Enterprise networks", "Critical infrastructure", "Financial systems"]
            ),
            ArchitecturePattern(
                pattern_id="PAT-002",
                name="Zero Trust Network",
                description="Never trust, always verify network architecture",
                category="Modern Security",
                layers=[ArchitectureLayer.IDENTITY, ArchitectureLayer.NETWORK, ArchitectureLayer.APPLICATION],
                components=[
                    {"type": "identity_provider", "layer": "identity"},
                    {"type": "microsegmentation", "layer": "network"},
                    {"type": "proxy", "layer": "application"},
                    {"type": "analytics", "layer": "visibility"}
                ],
                benefits=["Reduced lateral movement", "Continuous verification", "Least privilege"],
                limitations=["Implementation complexity", "Legacy system challenges"],
                use_cases=["Cloud-native apps", "Remote workforce", "Multi-cloud environments"]
            ),
            ArchitecturePattern(
                pattern_id="PAT-003",
                name="Secure API Gateway",
                description="Centralized API security and management",
                category="Application",
                layers=[ArchitectureLayer.APPLICATION],
                components=[
                    {"type": "api_gateway", "layer": "application"},
                    {"type": "oauth_server", "layer": "identity"},
                    {"type": "rate_limiter", "layer": "application"},
                    {"type": "waf", "layer": "application"}
                ],
                benefits=["Centralized security", "Traffic management", "API visibility"],
                limitations=["Single point of failure risk", "Latency"],
                use_cases=["Microservices", "Mobile backends", "Partner APIs"]
            ),
            ArchitecturePattern(
                pattern_id="PAT-004",
                name="Data Encryption at Rest and Transit",
                description="Comprehensive data protection through encryption",
                category="Data Security",
                layers=[ArchitectureLayer.DATA],
                components=[
                    {"type": "kms", "layer": "data"},
                    {"type": "tls_termination", "layer": "network"},
                    {"type": "disk_encryption", "layer": "endpoint"},
                    {"type": "database_encryption", "layer": "data"}
                ],
                benefits=["Data confidentiality", "Compliance", "Breach mitigation"],
                limitations=["Key management complexity", "Performance impact"],
                use_cases=["Healthcare", "Financial", "Government systems"]
            ),
            ArchitecturePattern(
                pattern_id="PAT-005",
                name="Security Operations Center",
                description="Centralized security monitoring and response",
                category="Operations",
                layers=[ArchitectureLayer.NETWORK, ArchitectureLayer.APPLICATION, ArchitectureLayer.ENDPOINT],
                components=[
                    {"type": "siem", "layer": "operations"},
                    {"type": "soar", "layer": "operations"},
                    {"type": "edr", "layer": "endpoint"},
                    {"type": "ndr", "layer": "network"}
                ],
                benefits=["Centralized visibility", "Faster response", "Correlation"],
                limitations=["Cost", "Staffing requirements", "Alert fatigue"],
                use_cases=["Enterprise security", "Managed security services"]
            )
        ]
        
        for pattern in patterns:
            self.patterns[pattern.pattern_id] = pattern
    
    async def create_control(self, control: SecurityControl) -> SecurityControl:
        """Create a new security control"""
        self.controls[control.control_id] = control
        return control
    
    async def get_control(self, control_id: str) -> Optional[SecurityControl]:
        """Get security control by ID"""
        return self.controls.get(control_id)
    
    async def update_control(self, control_id: str, updates: Dict[str, Any]) -> Optional[SecurityControl]:
        """Update security control"""
        if control_id in self.controls:
            control = self.controls[control_id]
            for key, value in updates.items():
                if hasattr(control, key):
                    setattr(control, key, value)
            return control
        return None
    
    async def list_controls(self, layer: Optional[ArchitectureLayer] = None) -> List[SecurityControl]:
        """List all security controls, optionally filtered by layer"""
        controls = list(self.controls.values())
        if layer:
            controls = [c for c in controls if c.layer == layer]
        return controls
    
    async def create_diagram(self, diagram: ArchitectureDiagram) -> ArchitectureDiagram:
        """Create architecture diagram"""
        self.diagrams[diagram.diagram_id] = diagram
        return diagram
    
    async def get_diagram(self, diagram_id: str) -> Optional[ArchitectureDiagram]:
        """Get architecture diagram by ID"""
        return self.diagrams.get(diagram_id)
    
    async def update_diagram(self, diagram_id: str, updates: Dict[str, Any]) -> Optional[ArchitectureDiagram]:
        """Update architecture diagram"""
        if diagram_id in self.diagrams:
            diagram = self.diagrams[diagram_id]
            diagram.updated_at = datetime.now()
            for key, value in updates.items():
                if hasattr(diagram, key):
                    setattr(diagram, key, value)
            return diagram
        return None
    
    async def create_review(self, review: ArchitectureReview) -> ArchitectureReview:
        """Create architecture review"""
        self.reviews[review.review_id] = review
        return review
    
    async def get_review(self, review_id: str) -> Optional[ArchitectureReview]:
        """Get architecture review by ID"""
        return self.reviews.get(review_id)
    
    async def submit_review(self, review_id: str) -> Optional[ArchitectureReview]:
        """Submit review for approval"""
        if review_id in self.reviews:
            review = self.reviews[review_id]
            review.status = ReviewStatus.PENDING
            return review
        return None
    
    async def approve_review(self, review_id: str, approver: str, comments: str = "") -> Optional[ArchitectureReview]:
        """Approve architecture review"""
        if review_id in self.reviews:
            review = self.reviews[review_id]
            review.status = ReviewStatus.APPROVED
            review.approval_chain.append({
                "approver": approver,
                "action": "approved",
                "comments": comments,
                "timestamp": datetime.now().isoformat()
            })
            return review
        return None
    
    async def reject_review(self, review_id: str, rejector: str, reason: str) -> Optional[ArchitectureReview]:
        """Reject architecture review"""
        if review_id in self.reviews:
            review = self.reviews[review_id]
            review.status = ReviewStatus.REJECTED
            review.approval_chain.append({
                "approver": rejector,
                "action": "rejected",
                "reason": reason,
                "timestamp": datetime.now().isoformat()
            })
            return review
        return None
    
    async def add_threat_vector(self, threat: ThreatVector) -> ThreatVector:
        """Add threat vector analysis"""
        self.threat_vectors[threat.vector_id] = threat
        return threat
    
    async def get_threat_vector(self, vector_id: str) -> Optional[ThreatVector]:
        """Get threat vector by ID"""
        return self.threat_vectors.get(vector_id)
    
    async def list_threat_vectors(self) -> List[ThreatVector]:
        """List all threat vectors"""
        return list(self.threat_vectors.values())
    
    async def calculate_risk_score(self, threat: ThreatVector) -> float:
        """Calculate risk score for threat vector"""
        # Risk = Likelihood x Impact
        base_risk = threat.likelihood * threat.impact
        
        # Adjust based on mitigating controls
        mitigation_factor = len(threat.mitigating_controls) * 0.1
        adjusted_risk = base_risk * (1 - min(mitigation_factor, 0.7))
        
        return round(adjusted_risk, 2)
    
    async def add_compliance_mapping(self, mapping: ComplianceMapping) -> ComplianceMapping:
        """Add compliance framework mapping"""
        self.compliance_mappings[mapping.mapping_id] = mapping
        return mapping
    
    async def get_compliance_mappings(self, framework: Optional[str] = None) -> List[ComplianceMapping]:
        """Get compliance mappings, optionally filtered by framework"""
        mappings = list(self.compliance_mappings.values())
        if framework:
            mappings = [m for m in mappings if m.framework == framework]
        return mappings
    
    async def calculate_compliance_score(self, framework: str) -> Dict[str, Any]:
        """Calculate compliance score for framework"""
        mappings = await self.get_compliance_mappings(framework)
        
        if not mappings:
            return {"framework": framework, "score": 0, "total": 0}
        
        status_scores = {
            ComplianceStatus.COMPLIANT: 1.0,
            ComplianceStatus.PARTIALLY_COMPLIANT: 0.5,
            ComplianceStatus.NON_COMPLIANT: 0.0,
            ComplianceStatus.NOT_APPLICABLE: None,
            ComplianceStatus.UNDER_REVIEW: 0.25
        }
        
        applicable = [m for m in mappings if m.status != ComplianceStatus.NOT_APPLICABLE]
        if not applicable:
            return {"framework": framework, "score": 100, "total": len(mappings)}
        
        total_score = sum(status_scores[m.status] for m in applicable)
        percentage = (total_score / len(applicable)) * 100
        
        return {
            "framework": framework,
            "score": round(percentage, 1),
            "total": len(mappings),
            "applicable": len(applicable),
            "compliant": len([m for m in applicable if m.status == ComplianceStatus.COMPLIANT]),
            "partial": len([m for m in applicable if m.status == ComplianceStatus.PARTIALLY_COMPLIANT]),
            "non_compliant": len([m for m in applicable if m.status == ComplianceStatus.NON_COMPLIANT])
        }
    
    async def assess_architecture_layer(self, layer: ArchitectureLayer) -> Dict[str, Any]:
        """Assess security posture of architecture layer"""
        controls = await self.list_controls(layer)
        
        if not controls:
            return {
                "layer": layer.value,
                "control_count": 0,
                "effectiveness": 0,
                "gaps": ["No controls defined for this layer"],
                "recommendations": ["Define security controls for this layer"]
            }
        
        # Calculate average effectiveness
        avg_effectiveness = sum(c.effectiveness for c in controls) / len(controls)
        
        # Collect gaps
        all_gaps = []
        for control in controls:
            all_gaps.extend(control.gaps)
        
        # Collect recommendations
        all_recommendations = []
        for control in controls:
            all_recommendations.extend(control.recommendations)
        
        # Control type distribution
        type_distribution = {}
        for control in controls:
            ctype = control.control_type.value
            type_distribution[ctype] = type_distribution.get(ctype, 0) + 1
        
        return {
            "layer": layer.value,
            "control_count": len(controls),
            "effectiveness": round(avg_effectiveness * 100, 1),
            "type_distribution": type_distribution,
            "gaps": list(set(all_gaps)),
            "recommendations": list(set(all_recommendations))
        }
    
    async def generate_architecture_report(self, review_id: str) -> Dict[str, Any]:
        """Generate comprehensive architecture review report"""
        review = await self.get_review(review_id)
        if not review:
            return {"error": "Review not found"}
        
        # Assess all reviewed layers
        layer_assessments = {}
        for layer in review.layers_reviewed:
            assessment = await self.assess_architecture_layer(layer)
            layer_assessments[layer.value] = assessment
        
        # Calculate overall risk score
        all_threats = await self.list_threat_vectors()
        risk_scores = []
        for threat in all_threats:
            score = await self.calculate_risk_score(threat)
            risk_scores.append(score)
        
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        # Compliance summary
        compliance_summary = {}
        for framework in self.compliance_frameworks.keys():
            score = await self.calculate_compliance_score(framework)
            compliance_summary[framework] = score
        
        # Pattern recommendations
        pattern_recommendations = []
        for pattern in self.patterns.values():
            if any(layer in review.layers_reviewed for layer in pattern.layers):
                pattern_recommendations.append({
                    "pattern": pattern.name,
                    "description": pattern.description,
                    "benefits": pattern.benefits
                })
        
        return {
            "review_id": review_id,
            "review_name": review.name,
            "status": review.status.value,
            "reviewer": review.reviewer,
            "scope": review.scope,
            "created_at": review.created_at.isoformat(),
            "layer_assessments": layer_assessments,
            "overall_risk_score": round(avg_risk, 2),
            "compliance_summary": compliance_summary,
            "findings_count": len(review.findings),
            "recommendations_count": len(review.recommendations),
            "pattern_recommendations": pattern_recommendations,
            "approval_status": review.approval_chain
        }
    
    async def get_pattern(self, pattern_id: str) -> Optional[ArchitecturePattern]:
        """Get architecture pattern by ID"""
        return self.patterns.get(pattern_id)
    
    async def list_patterns(self, category: Optional[str] = None) -> List[ArchitecturePattern]:
        """List all architecture patterns"""
        patterns = list(self.patterns.values())
        if category:
            patterns = [p for p in patterns if p.category == category]
        return patterns
    
    async def recommend_patterns(self, requirements: List[str]) -> List[ArchitecturePattern]:
        """Recommend patterns based on requirements"""
        recommendations = []
        
        keyword_mapping = {
            "api": ["PAT-003"],
            "network": ["PAT-001", "PAT-002"],
            "data": ["PAT-004"],
            "encryption": ["PAT-004"],
            "monitoring": ["PAT-005"],
            "soc": ["PAT-005"],
            "zero trust": ["PAT-002"],
            "defense": ["PAT-001"],
            "layered": ["PAT-001"]
        }
        
        pattern_ids = set()
        for req in requirements:
            req_lower = req.lower()
            for keyword, patterns in keyword_mapping.items():
                if keyword in req_lower:
                    pattern_ids.update(patterns)
        
        for pid in pattern_ids:
            if pid in self.patterns:
                recommendations.append(self.patterns[pid])
        
        return recommendations
    
    async def validate_architecture(self, diagram_id: str) -> Dict[str, Any]:
        """Validate architecture diagram against best practices"""
        diagram = await self.get_diagram(diagram_id)
        if not diagram:
            return {"error": "Diagram not found"}
        
        issues = []
        recommendations = []
        
        # Check for security zones
        if not diagram.security_zones:
            issues.append({
                "severity": "high",
                "issue": "No security zones defined",
                "recommendation": "Define security zones to segment the network"
            })
        
        # Check for encryption in connections
        unencrypted = []
        for conn in diagram.connections:
            if not conn.get("encrypted", False):
                unencrypted.append(conn.get("name", "Unknown"))
        
        if unencrypted:
            issues.append({
                "severity": "medium",
                "issue": f"Unencrypted connections: {', '.join(unencrypted)}",
                "recommendation": "Enable encryption for all connections"
            })
        
        # Check component security settings
        for component in diagram.components:
            if not component.get("security_hardened", False):
                recommendations.append(f"Harden security for component: {component.get('name', 'Unknown')}")
        
        return {
            "diagram_id": diagram_id,
            "valid": len([i for i in issues if i["severity"] == "high"]) == 0,
            "issues": issues,
            "recommendations": recommendations,
            "validation_time": datetime.now().isoformat()
        }
    
    async def get_framework_controls(self, framework: str) -> Dict[str, Any]:
        """Get controls for a compliance framework"""
        return self.compliance_frameworks.get(framework, {})
    
    async def export_architecture(self, format: str = "json") -> str:
        """Export architecture data"""
        data = {
            "controls": [
                {
                    "control_id": c.control_id,
                    "name": c.name,
                    "layer": c.layer.value,
                    "type": c.control_type.value,
                    "effectiveness": c.effectiveness
                }
                for c in self.controls.values()
            ],
            "diagrams": [
                {
                    "diagram_id": d.diagram_id,
                    "name": d.name,
                    "layer": d.layer.value,
                    "components": len(d.components)
                }
                for d in self.diagrams.values()
            ],
            "reviews": [
                {
                    "review_id": r.review_id,
                    "name": r.name,
                    "status": r.status.value,
                    "risk_score": r.risk_score
                }
                for r in self.reviews.values()
            ],
            "patterns": [
                {
                    "pattern_id": p.pattern_id,
                    "name": p.name,
                    "category": p.category
                }
                for p in self.patterns.values()
            ],
            "export_time": datetime.now().isoformat()
        }
        
        return json.dumps(data, indent=2)
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get architecture statistics"""
        controls_by_layer = {}
        for control in self.controls.values():
            layer = control.layer.value
            controls_by_layer[layer] = controls_by_layer.get(layer, 0) + 1
        
        reviews_by_status = {}
        for review in self.reviews.values():
            status = review.status.value
            reviews_by_status[status] = reviews_by_status.get(status, 0) + 1
        
        threats_by_risk = {}
        for threat in self.threat_vectors.values():
            risk = threat.residual_risk.value
            threats_by_risk[risk] = threats_by_risk.get(risk, 0) + 1
        
        return {
            "total_controls": len(self.controls),
            "total_diagrams": len(self.diagrams),
            "total_reviews": len(self.reviews),
            "total_threats": len(self.threat_vectors),
            "total_patterns": len(self.patterns),
            "controls_by_layer": controls_by_layer,
            "reviews_by_status": reviews_by_status,
            "threats_by_risk": threats_by_risk
        }
