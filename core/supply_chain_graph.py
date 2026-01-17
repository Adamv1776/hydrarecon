"""
HydraRecon Supply Chain Attack Graph
====================================
Map your entire software supply chain and its security posture.

Features:
- Complete dependency mapping
- Vendor security scoring
- CVE propagation modeling
- Blast radius analysis
- SBOM (Software Bill of Materials) generation
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
import random
import json
import hashlib


class DependencyType(Enum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    DEV = "development"
    OPTIONAL = "optional"
    PEER = "peer"
    BUILD = "build"


class VendorTier(Enum):
    TIER1 = "tier1"  # Critical vendors
    TIER2 = "tier2"  # Important vendors
    TIER3 = "tier3"  # Standard vendors
    TIER4 = "tier4"  # Low-risk vendors
    OPEN_SOURCE = "open_source"


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class Dependency:
    """A software dependency"""
    dep_id: str
    name: str
    version: str
    dep_type: DependencyType
    ecosystem: str  # npm, pypi, maven, nuget, etc.
    license: str
    maintainer: str
    last_update: datetime
    downloads_monthly: int
    dependencies: List[str]  # IDs of transitive dependencies
    vulnerabilities: List[Dict[str, Any]]
    security_score: float  # 0-100
    verified: bool
    checksum: str


@dataclass
class Vendor:
    """A third-party vendor"""
    vendor_id: str
    name: str
    tier: VendorTier
    domain: str
    products: List[str]
    security_certifications: List[str]  # SOC2, ISO27001, etc.
    security_questionnaire_date: Optional[datetime]
    security_score: float
    incident_history: List[Dict[str, Any]]
    data_access: List[str]  # Types of data they can access
    api_access: bool
    network_access: bool


@dataclass
class SupplyChainNode:
    """A node in the supply chain graph"""
    node_id: str
    node_type: str  # dependency, vendor, service, api
    name: str
    version: Optional[str]
    risk_level: RiskLevel
    security_score: float
    upstream: List[str]  # Nodes this depends on
    downstream: List[str]  # Nodes that depend on this
    vulnerabilities: List[Dict[str, Any]]
    metadata: Dict[str, Any]


@dataclass
class BlastRadius:
    """Blast radius analysis for a compromised component"""
    component_id: str
    component_name: str
    directly_affected: List[str]
    transitively_affected: List[str]
    total_affected: int
    critical_assets_affected: List[str]
    data_at_risk: List[str]
    impact_score: float
    mitigation_options: List[str]


@dataclass
class CVEPropagation:
    """CVE propagation analysis"""
    cve_id: str
    cvss_score: float
    affected_component: str
    propagation_path: List[str]
    affected_applications: List[str]
    exploitation_likelihood: float
    patch_available: bool
    patch_version: Optional[str]
    days_since_disclosure: int


@dataclass
class SBOM:
    """Software Bill of Materials"""
    sbom_id: str
    application: str
    version: str
    generated_at: datetime
    format: str  # CycloneDX, SPDX
    components: List[Dict[str, Any]]
    vulnerabilities_count: int
    high_risk_count: int
    license_risks: List[str]
    compliance_status: Dict[str, bool]


@dataclass
class SupplyChainReport:
    """Complete supply chain analysis report"""
    report_id: str
    generated_at: datetime
    total_dependencies: int
    total_vendors: int
    critical_vulnerabilities: int
    high_risk_components: int
    average_security_score: float
    blast_radius_summary: Dict[str, int]
    vendor_risk_distribution: Dict[str, int]
    recommendations: List[str]
    sbom: SBOM


class SupplyChainGraph:
    """
    Supply Chain Attack Graph - Map and secure your entire supply chain.
    """
    
    def __init__(self):
        self.dependencies: Dict[str, Dependency] = {}
        self.vendors: Dict[str, Vendor] = {}
        self.nodes: Dict[str, SupplyChainNode] = {}
        self.applications: Dict[str, List[str]] = {}  # App -> dependency IDs
        
        # Known vulnerable packages (simulated)
        self.known_vulnerabilities = {
            "log4j": [{"cve": "CVE-2021-44228", "cvss": 10.0, "name": "Log4Shell"}],
            "lodash": [{"cve": "CVE-2020-8203", "cvss": 7.4, "name": "Prototype Pollution"}],
            "axios": [{"cve": "CVE-2021-3749", "cvss": 7.5, "name": "ReDoS"}],
            "minimist": [{"cve": "CVE-2020-7598", "cvss": 5.6, "name": "Prototype Pollution"}],
            "moment": [{"cve": "CVE-2022-24785", "cvss": 7.5, "name": "Path Traversal"}],
            "express": [{"cve": "CVE-2024-0001", "cvss": 6.1, "name": "Open Redirect"}],
            "django": [{"cve": "CVE-2024-0002", "cvss": 7.2, "name": "SQL Injection"}],
            "spring-core": [{"cve": "CVE-2022-22965", "cvss": 9.8, "name": "Spring4Shell"}],
            "jackson-databind": [{"cve": "CVE-2020-25649", "cvss": 7.5, "name": "XXE"}],
            "openssl": [{"cve": "CVE-2024-0003", "cvss": 8.1, "name": "Buffer Overflow"}],
        }
        
        self._initialize_demo_data()
        
    def _initialize_demo_data(self):
        """Initialize demo supply chain data"""
        
        # Create demo vendors
        demo_vendors = [
            Vendor(
                vendor_id="vendor-aws",
                name="Amazon Web Services",
                tier=VendorTier.TIER1,
                domain="aws.amazon.com",
                products=["EC2", "S3", "Lambda", "RDS"],
                security_certifications=["SOC2", "ISO27001", "PCI-DSS", "FedRAMP"],
                security_questionnaire_date=datetime.now() - timedelta(days=90),
                security_score=95.0,
                incident_history=[],
                data_access=["customer_data", "logs", "metrics"],
                api_access=True,
                network_access=True
            ),
            Vendor(
                vendor_id="vendor-datadog",
                name="Datadog",
                tier=VendorTier.TIER2,
                domain="datadoghq.com",
                products=["APM", "Logs", "Metrics"],
                security_certifications=["SOC2", "ISO27001"],
                security_questionnaire_date=datetime.now() - timedelta(days=180),
                security_score=88.0,
                incident_history=[],
                data_access=["logs", "metrics", "traces"],
                api_access=True,
                network_access=True
            ),
            Vendor(
                vendor_id="vendor-stripe",
                name="Stripe",
                tier=VendorTier.TIER1,
                domain="stripe.com",
                products=["Payments", "Billing"],
                security_certifications=["SOC2", "PCI-DSS Level 1"],
                security_questionnaire_date=datetime.now() - timedelta(days=60),
                security_score=98.0,
                incident_history=[],
                data_access=["payment_data"],
                api_access=True,
                network_access=False
            ),
            Vendor(
                vendor_id="vendor-github",
                name="GitHub",
                tier=VendorTier.TIER1,
                domain="github.com",
                products=["SCM", "Actions", "Packages"],
                security_certifications=["SOC2", "ISO27001"],
                security_questionnaire_date=datetime.now() - timedelta(days=120),
                security_score=92.0,
                incident_history=[{"date": "2024-01", "type": "outage", "duration": "2h"}],
                data_access=["source_code", "secrets"],
                api_access=True,
                network_access=True
            ),
            Vendor(
                vendor_id="vendor-slack",
                name="Slack",
                tier=VendorTier.TIER2,
                domain="slack.com",
                products=["Messaging", "Workflows"],
                security_certifications=["SOC2"],
                security_questionnaire_date=datetime.now() - timedelta(days=365),
                security_score=82.0,
                incident_history=[],
                data_access=["messages", "files"],
                api_access=True,
                network_access=False
            ),
            Vendor(
                vendor_id="vendor-acme-saas",
                name="ACME SaaS Corp",
                tier=VendorTier.TIER3,
                domain="acme-saas.com",
                products=["Analytics Widget"],
                security_certifications=[],
                security_questionnaire_date=None,
                security_score=45.0,
                incident_history=[{"date": "2025-06", "type": "breach", "records": 50000}],
                data_access=["user_behavior"],
                api_access=True,
                network_access=False
            ),
        ]
        
        for vendor in demo_vendors:
            self.vendors[vendor.vendor_id] = vendor
            
        # Create demo dependencies (simulated package ecosystem)
        demo_deps = [
            # Direct dependencies
            ("dep-react", "react", "18.2.0", DependencyType.DIRECT, "npm", "MIT", "facebook", 50000000),
            ("dep-express", "express", "4.18.2", DependencyType.DIRECT, "npm", "MIT", "expressjs", 30000000),
            ("dep-axios", "axios", "1.4.0", DependencyType.DIRECT, "npm", "MIT", "axios", 40000000),
            ("dep-lodash", "lodash", "4.17.21", DependencyType.DIRECT, "npm", "MIT", "lodash", 45000000),
            ("dep-django", "django", "4.2.0", DependencyType.DIRECT, "pypi", "BSD-3", "django", 5000000),
            ("dep-requests", "requests", "2.31.0", DependencyType.DIRECT, "pypi", "Apache-2.0", "psf", 10000000),
            ("dep-spring-boot", "spring-boot", "3.1.0", DependencyType.DIRECT, "maven", "Apache-2.0", "pivotal", 2000000),
            
            # Transitive dependencies
            ("dep-minimist", "minimist", "1.2.6", DependencyType.TRANSITIVE, "npm", "MIT", "substack", 100000000),
            ("dep-debug", "debug", "4.3.4", DependencyType.TRANSITIVE, "npm", "MIT", "debug-js", 90000000),
            ("dep-body-parser", "body-parser", "1.20.2", DependencyType.TRANSITIVE, "npm", "MIT", "expressjs", 30000000),
            ("dep-moment", "moment", "2.29.4", DependencyType.TRANSITIVE, "npm", "MIT", "moment", 15000000),
            ("dep-log4j", "log4j", "2.17.0", DependencyType.TRANSITIVE, "maven", "Apache-2.0", "apache", 5000000),
            ("dep-jackson", "jackson-databind", "2.15.0", DependencyType.TRANSITIVE, "maven", "Apache-2.0", "fasterxml", 3000000),
            ("dep-spring-core", "spring-core", "6.0.9", DependencyType.TRANSITIVE, "maven", "Apache-2.0", "pivotal", 2000000),
            ("dep-openssl", "openssl", "3.0.9", DependencyType.TRANSITIVE, "system", "Apache-2.0", "openssl", 1000000),
            
            # Dev dependencies
            ("dep-jest", "jest", "29.5.0", DependencyType.DEV, "npm", "MIT", "facebook", 20000000),
            ("dep-eslint", "eslint", "8.44.0", DependencyType.DEV, "npm", "MIT", "eslint", 25000000),
            ("dep-pytest", "pytest", "7.4.0", DependencyType.DEV, "pypi", "MIT", "pytest-dev", 8000000),
        ]
        
        for dep_data in demo_deps:
            # Check for known vulnerabilities
            vulns = []
            for vuln_pkg, vuln_list in self.known_vulnerabilities.items():
                if vuln_pkg.lower() in dep_data[1].lower():
                    vulns.extend(vuln_list)
                    
            # Calculate security score
            base_score = 80
            if vulns:
                max_cvss = max(v["cvss"] for v in vulns)
                base_score -= max_cvss * 5
            base_score = max(0, min(100, base_score + random.uniform(-10, 10)))
            
            dep = Dependency(
                dep_id=dep_data[0],
                name=dep_data[1],
                version=dep_data[2],
                dep_type=dep_data[3],
                ecosystem=dep_data[4],
                license=dep_data[5],
                maintainer=dep_data[6],
                last_update=datetime.now() - timedelta(days=random.randint(1, 365)),
                downloads_monthly=dep_data[7],
                dependencies=[],
                vulnerabilities=vulns,
                security_score=round(base_score, 1),
                verified=random.random() > 0.3,
                checksum=hashlib.sha256(f"{dep_data[1]}-{dep_data[2]}".encode()).hexdigest()[:16]
            )
            self.dependencies[dep.dep_id] = dep
            
        # Define dependency relationships
        self.dependencies["dep-express"].dependencies = ["dep-body-parser", "dep-debug"]
        self.dependencies["dep-react"].dependencies = ["dep-minimist"]
        self.dependencies["dep-axios"].dependencies = ["dep-debug"]
        self.dependencies["dep-spring-boot"].dependencies = ["dep-spring-core", "dep-jackson", "dep-log4j"]
        
        # Define applications
        self.applications = {
            "web-frontend": ["dep-react", "dep-axios", "dep-lodash", "dep-moment"],
            "api-server": ["dep-express", "dep-axios", "dep-body-parser"],
            "backend-python": ["dep-django", "dep-requests"],
            "java-service": ["dep-spring-boot", "dep-spring-core", "dep-jackson", "dep-log4j"],
        }
        
        # Build graph nodes
        self._build_graph()
        
    def _build_graph(self):
        """Build the supply chain graph from dependencies and vendors"""
        
        # Add dependency nodes
        for dep_id, dep in self.dependencies.items():
            risk = self._calculate_risk_level(dep)
            
            node = SupplyChainNode(
                node_id=dep_id,
                node_type="dependency",
                name=dep.name,
                version=dep.version,
                risk_level=risk,
                security_score=dep.security_score,
                upstream=dep.dependencies,
                downstream=[],
                vulnerabilities=dep.vulnerabilities,
                metadata={
                    "ecosystem": dep.ecosystem,
                    "license": dep.license,
                    "maintainer": dep.maintainer
                }
            )
            self.nodes[dep_id] = node
            
        # Add vendor nodes
        for vendor_id, vendor in self.vendors.items():
            risk = self._vendor_risk_level(vendor)
            
            node = SupplyChainNode(
                node_id=vendor_id,
                node_type="vendor",
                name=vendor.name,
                version=None,
                risk_level=risk,
                security_score=vendor.security_score,
                upstream=[],
                downstream=[],
                vulnerabilities=[],
                metadata={
                    "tier": vendor.tier.value,
                    "certifications": vendor.security_certifications,
                    "data_access": vendor.data_access
                }
            )
            self.nodes[vendor_id] = node
            
        # Calculate downstream dependencies
        for dep_id, dep in self.dependencies.items():
            for upstream_id in dep.dependencies:
                if upstream_id in self.nodes:
                    self.nodes[upstream_id].downstream.append(dep_id)
                    
    def _calculate_risk_level(self, dep: Dependency) -> RiskLevel:
        """Calculate risk level for a dependency"""
        if dep.vulnerabilities:
            max_cvss = max(v.get("cvss", 0) for v in dep.vulnerabilities)
            if max_cvss >= 9.0:
                return RiskLevel.CRITICAL
            elif max_cvss >= 7.0:
                return RiskLevel.HIGH
            elif max_cvss >= 4.0:
                return RiskLevel.MEDIUM
            else:
                return RiskLevel.LOW
        elif dep.security_score < 50:
            return RiskLevel.MEDIUM
        elif dep.security_score < 70:
            return RiskLevel.LOW
        return RiskLevel.MINIMAL
        
    def _vendor_risk_level(self, vendor: Vendor) -> RiskLevel:
        """Calculate risk level for a vendor"""
        if vendor.incident_history:
            breaches = [i for i in vendor.incident_history if i.get("type") == "breach"]
            if breaches:
                return RiskLevel.HIGH
                
        if vendor.security_score < 50:
            return RiskLevel.HIGH
        elif vendor.security_score < 70:
            return RiskLevel.MEDIUM
        elif vendor.security_score < 85:
            return RiskLevel.LOW
        return RiskLevel.MINIMAL
        
    def analyze_blast_radius(self, component_id: str) -> BlastRadius:
        """Analyze the blast radius if a component is compromised"""
        if component_id not in self.nodes:
            raise ValueError(f"Component {component_id} not found")
            
        node = self.nodes[component_id]
        directly_affected = set(node.downstream)
        transitively_affected = set()
        
        # BFS to find all transitively affected
        queue = list(directly_affected)
        while queue:
            current = queue.pop(0)
            if current in self.nodes:
                for downstream in self.nodes[current].downstream:
                    if downstream not in directly_affected and downstream not in transitively_affected:
                        transitively_affected.add(downstream)
                        queue.append(downstream)
                        
        # Find affected applications
        critical_assets = []
        for app_name, app_deps in self.applications.items():
            if component_id in app_deps or any(d in directly_affected | transitively_affected for d in app_deps):
                critical_assets.append(app_name)
                
        # Data at risk (from vendors)
        data_at_risk = []
        if node.node_type == "vendor" and component_id in self.vendors:
            data_at_risk = self.vendors[component_id].data_access
            
        # Calculate impact score
        total_affected = len(directly_affected) + len(transitively_affected)
        impact_score = min(100, (total_affected / max(len(self.nodes), 1)) * 100 + len(critical_assets) * 10)
        
        # Generate mitigation options
        mitigations = [
            f"Immediately update or remove {node.name}",
            "Implement network segmentation to limit blast radius",
            "Enable enhanced monitoring on affected components",
            "Review and rotate any credentials that may have been exposed",
        ]
        
        if node.vulnerabilities:
            mitigations.insert(0, f"Apply security patches for {len(node.vulnerabilities)} known vulnerabilities")
            
        return BlastRadius(
            component_id=component_id,
            component_name=node.name,
            directly_affected=list(directly_affected),
            transitively_affected=list(transitively_affected),
            total_affected=total_affected,
            critical_assets_affected=critical_assets,
            data_at_risk=data_at_risk,
            impact_score=round(impact_score, 1),
            mitigation_options=mitigations
        )
        
    def analyze_cve_propagation(self, cve_id: str) -> List[CVEPropagation]:
        """Analyze how a CVE propagates through the supply chain"""
        propagations = []
        
        for dep_id, dep in self.dependencies.items():
            for vuln in dep.vulnerabilities:
                if vuln.get("cve") == cve_id or cve_id.lower() in dep.name.lower():
                    # Find propagation path
                    blast = self.analyze_blast_radius(dep_id)
                    
                    affected_apps = []
                    for app_name, app_deps in self.applications.items():
                        if dep_id in app_deps:
                            affected_apps.append(app_name)
                        for affected in blast.directly_affected + blast.transitively_affected:
                            if affected in app_deps:
                                affected_apps.append(app_name)
                                
                    propagation = CVEPropagation(
                        cve_id=vuln.get("cve", cve_id),
                        cvss_score=vuln.get("cvss", 5.0),
                        affected_component=dep.name,
                        propagation_path=[dep_id] + blast.directly_affected[:5],
                        affected_applications=list(set(affected_apps)),
                        exploitation_likelihood=min(1.0, vuln.get("cvss", 5.0) / 10),
                        patch_available=True,
                        patch_version=f"{dep.version}-patched",
                        days_since_disclosure=random.randint(1, 365)
                    )
                    propagations.append(propagation)
                    
        return propagations
        
    def generate_sbom(self, application: str = None) -> SBOM:
        """Generate Software Bill of Materials"""
        if application and application not in self.applications:
            raise ValueError(f"Application {application} not found")
            
        # Get dependencies for this application or all
        if application:
            dep_ids = set(self.applications[application])
            # Add transitive dependencies
            for dep_id in list(dep_ids):
                if dep_id in self.dependencies:
                    dep_ids.update(self.dependencies[dep_id].dependencies)
        else:
            dep_ids = set(self.dependencies.keys())
            
        components = []
        vuln_count = 0
        high_risk_count = 0
        license_risks = []
        
        for dep_id in dep_ids:
            if dep_id in self.dependencies:
                dep = self.dependencies[dep_id]
                
                component = {
                    "bom-ref": dep_id,
                    "type": "library",
                    "name": dep.name,
                    "version": dep.version,
                    "purl": f"pkg:{dep.ecosystem}/{dep.name}@{dep.version}",
                    "licenses": [{"license": {"id": dep.license}}],
                    "hashes": [{"alg": "SHA-256", "content": dep.checksum}],
                    "supplier": {"name": dep.maintainer},
                }
                components.append(component)
                
                vuln_count += len(dep.vulnerabilities)
                if dep.vulnerabilities and max(v.get("cvss", 0) for v in dep.vulnerabilities) >= 7.0:
                    high_risk_count += 1
                    
                # Check for problematic licenses
                problematic_licenses = ["GPL-3.0", "AGPL-3.0", "SSPL"]
                if dep.license in problematic_licenses:
                    license_risks.append(f"{dep.name}: {dep.license}")
                    
        compliance_status = {
            "NIST": vuln_count == 0,
            "PCI-DSS": high_risk_count == 0,
            "SOC2": len(license_risks) == 0,
        }
        
        return SBOM(
            sbom_id=f"SBOM-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            application=application or "all",
            version="1.0.0",
            generated_at=datetime.now(),
            format="CycloneDX",
            components=components,
            vulnerabilities_count=vuln_count,
            high_risk_count=high_risk_count,
            license_risks=license_risks,
            compliance_status=compliance_status
        )
        
    def score_vendor(self, vendor_id: str) -> Dict[str, Any]:
        """Calculate detailed vendor security score"""
        if vendor_id not in self.vendors:
            raise ValueError(f"Vendor {vendor_id} not found")
            
        vendor = self.vendors[vendor_id]
        
        scores = {
            "certifications": 0,
            "questionnaire": 0,
            "incident_history": 100,
            "data_access": 0,
            "network_access": 0,
        }
        
        # Certification score
        cert_weights = {"SOC2": 25, "ISO27001": 25, "PCI-DSS": 25, "FedRAMP": 25, "HIPAA": 20}
        for cert in vendor.security_certifications:
            scores["certifications"] += cert_weights.get(cert, 10)
        scores["certifications"] = min(100, scores["certifications"])
        
        # Questionnaire freshness
        if vendor.security_questionnaire_date:
            days_since = (datetime.now() - vendor.security_questionnaire_date).days
            if days_since <= 90:
                scores["questionnaire"] = 100
            elif days_since <= 180:
                scores["questionnaire"] = 75
            elif days_since <= 365:
                scores["questionnaire"] = 50
            else:
                scores["questionnaire"] = 25
                
        # Incident history
        for incident in vendor.incident_history:
            if incident.get("type") == "breach":
                scores["incident_history"] -= 50
            elif incident.get("type") == "outage":
                scores["incident_history"] -= 10
        scores["incident_history"] = max(0, scores["incident_history"])
        
        # Data access risk
        sensitive_data = ["payment_data", "customer_data", "source_code", "secrets"]
        data_risk = sum(20 for d in vendor.data_access if d in sensitive_data)
        scores["data_access"] = 100 - min(100, data_risk)
        
        # Network access risk
        scores["network_access"] = 60 if vendor.network_access else 100
        
        # Overall score
        overall = sum(scores.values()) / len(scores)
        
        return {
            "vendor_id": vendor_id,
            "vendor_name": vendor.name,
            "scores": scores,
            "overall_score": round(overall, 1),
            "tier": vendor.tier.value,
            "recommendations": self._vendor_recommendations(vendor, scores)
        }
        
    def _vendor_recommendations(self, vendor: Vendor, scores: Dict[str, int]) -> List[str]:
        """Generate recommendations for vendor"""
        recs = []
        
        if scores["certifications"] < 50:
            recs.append(f"Request SOC2 or ISO27001 certification from {vendor.name}")
            
        if scores["questionnaire"] < 75:
            recs.append(f"Conduct updated security questionnaire (last: {vendor.security_questionnaire_date})")
            
        if scores["incident_history"] < 100:
            recs.append(f"Review incident response and remediation from {vendor.name}")
            
        if scores["data_access"] < 80:
            recs.append(f"Review and minimize data access permissions for {vendor.name}")
            
        if scores["network_access"] < 100:
            recs.append(f"Implement network segmentation for {vendor.name} access")
            
        return recs
        
    async def full_analysis(self) -> SupplyChainReport:
        """Run complete supply chain analysis"""
        
        # Count vulnerabilities and risks
        critical_vulns = 0
        high_risk = 0
        total_score = 0
        
        for dep in self.dependencies.values():
            total_score += dep.security_score
            for vuln in dep.vulnerabilities:
                if vuln.get("cvss", 0) >= 9.0:
                    critical_vulns += 1
            if dep.security_score < 50:
                high_risk += 1
                
        avg_score = total_score / max(len(self.dependencies), 1)
        
        # Blast radius summary
        blast_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for node_id in list(self.nodes.keys())[:10]:  # Sample analysis
            blast = self.analyze_blast_radius(node_id)
            if blast.impact_score >= 75:
                blast_summary["critical"] += 1
            elif blast.impact_score >= 50:
                blast_summary["high"] += 1
            elif blast.impact_score >= 25:
                blast_summary["medium"] += 1
            else:
                blast_summary["low"] += 1
                
        # Vendor risk distribution
        vendor_risk = {}
        for vendor in self.vendors.values():
            tier = vendor.tier.value
            vendor_risk[tier] = vendor_risk.get(tier, 0) + 1
            
        # Generate SBOM
        sbom = self.generate_sbom()
        
        # Recommendations
        recommendations = [
            f"Address {critical_vulns} critical vulnerabilities immediately",
            f"Review {high_risk} high-risk components for updates or replacements",
            "Implement automated dependency scanning in CI/CD pipeline",
            "Establish vendor security review cadence",
            "Enable SBOM generation for all releases",
        ]
        
        return SupplyChainReport(
            report_id=f"SC-REPORT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            generated_at=datetime.now(),
            total_dependencies=len(self.dependencies),
            total_vendors=len(self.vendors),
            critical_vulnerabilities=critical_vulns,
            high_risk_components=high_risk,
            average_security_score=round(avg_score, 1),
            blast_radius_summary=blast_summary,
            vendor_risk_distribution=vendor_risk,
            recommendations=recommendations,
            sbom=sbom
        )
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get supply chain statistics"""
        vuln_count = sum(len(d.vulnerabilities) for d in self.dependencies.values())
        
        return {
            "total_dependencies": len(self.dependencies),
            "direct_dependencies": len([d for d in self.dependencies.values() if d.dep_type == DependencyType.DIRECT]),
            "transitive_dependencies": len([d for d in self.dependencies.values() if d.dep_type == DependencyType.TRANSITIVE]),
            "total_vendors": len(self.vendors),
            "tier1_vendors": len([v for v in self.vendors.values() if v.tier == VendorTier.TIER1]),
            "total_vulnerabilities": vuln_count,
            "applications_tracked": len(self.applications),
            "graph_nodes": len(self.nodes),
            "ecosystems": list(set(d.ecosystem for d in self.dependencies.values())),
        }


async def main():
    """Test the Supply Chain Attack Graph"""
    print("=" * 60)
    print("HydraRecon Supply Chain Attack Graph")
    print("=" * 60)
    
    graph = SupplyChainGraph()
    
    # Get statistics
    stats = graph.get_statistics()
    print(f"\n[*] Supply Chain Statistics:")
    print(f"    Total Dependencies: {stats['total_dependencies']}")
    print(f"    Direct: {stats['direct_dependencies']}, Transitive: {stats['transitive_dependencies']}")
    print(f"    Total Vendors: {stats['total_vendors']} (Tier 1: {stats['tier1_vendors']})")
    print(f"    Total Vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"    Applications: {stats['applications_tracked']}")
    print(f"    Ecosystems: {', '.join(stats['ecosystems'])}")
    
    # Blast radius analysis
    print(f"\n[*] Blast Radius Analysis (log4j):")
    blast = graph.analyze_blast_radius("dep-log4j")
    print(f"    Component: {blast.component_name}")
    print(f"    Directly Affected: {len(blast.directly_affected)}")
    print(f"    Transitively Affected: {len(blast.transitively_affected)}")
    print(f"    Critical Assets: {', '.join(blast.critical_assets_affected)}")
    print(f"    Impact Score: {blast.impact_score}/100")
    
    # CVE propagation
    print(f"\n[*] CVE Propagation Analysis (Log4Shell):")
    propagations = graph.analyze_cve_propagation("CVE-2021-44228")
    for prop in propagations:
        print(f"    CVE: {prop.cve_id} (CVSS: {prop.cvss_score})")
        print(f"    Affected Component: {prop.affected_component}")
        print(f"    Affected Applications: {', '.join(prop.affected_applications)}")
        print(f"    Exploitation Likelihood: {prop.exploitation_likelihood:.0%}")
        
    # Vendor scoring
    print(f"\n[*] Vendor Security Scores:")
    for vendor_id in list(graph.vendors.keys())[:4]:
        score = graph.score_vendor(vendor_id)
        print(f"    {score['vendor_name']}: {score['overall_score']}/100 ({score['tier']})")
        
    # SBOM generation
    print(f"\n[*] Generating SBOM for 'api-server'...")
    sbom = graph.generate_sbom("api-server")
    print(f"    SBOM ID: {sbom.sbom_id}")
    print(f"    Components: {len(sbom.components)}")
    print(f"    Vulnerabilities: {sbom.vulnerabilities_count}")
    print(f"    High Risk: {sbom.high_risk_count}")
    print(f"    License Risks: {len(sbom.license_risks)}")
    
    # Full analysis
    print(f"\n[*] Running Full Supply Chain Analysis...")
    report = await graph.full_analysis()
    print(f"    Report ID: {report.report_id}")
    print(f"    Critical Vulnerabilities: {report.critical_vulnerabilities}")
    print(f"    High Risk Components: {report.high_risk_components}")
    print(f"    Average Security Score: {report.average_security_score}/100")
    print(f"\n[*] Top Recommendations:")
    for i, rec in enumerate(report.recommendations[:3], 1):
        print(f"    {i}. {rec}")
        
    print("\n" + "=" * 60)
    print("Supply Chain Attack Graph Test Complete")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
