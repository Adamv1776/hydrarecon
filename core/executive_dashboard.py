"""
HydraRecon - Executive Security Dashboard
C-Suite ready security metrics and business-aligned reporting
"""

import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple
import json


class RiskLevel(Enum):
    """Risk level classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class TrendDirection(Enum):
    """Trend direction"""
    IMPROVING = "improving"
    STABLE = "stable"
    DECLINING = "declining"


class SecurityDomain(Enum):
    """Security domain categories"""
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    IDENTITY_ACCESS = "identity_access"
    DATA_PROTECTION = "data_protection"
    NETWORK_SECURITY = "network_security"
    ENDPOINT_SECURITY = "endpoint_security"
    CLOUD_SECURITY = "cloud_security"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE = "compliance"
    THIRD_PARTY_RISK = "third_party_risk"
    SECURITY_AWARENESS = "security_awareness"


@dataclass
class SecurityKPI:
    """Key Performance Indicator for security"""
    id: str
    name: str
    domain: SecurityDomain
    current_value: float
    target_value: float
    unit: str
    trend: TrendDirection
    trend_percent: float
    risk_level: RiskLevel
    description: str
    last_updated: datetime


@dataclass
class RiskIndicator:
    """Risk indicator for executive dashboard"""
    id: str
    name: str
    category: str
    score: float  # 0-100
    weight: float
    trend: TrendDirection
    factors: List[str]
    mitigation_status: str


@dataclass
class ExecutiveMetric:
    """Executive-level metric"""
    name: str
    value: str
    change: float
    change_period: str
    icon: str
    color: str


@dataclass
class SecurityIncident:
    """Security incident summary"""
    id: str
    title: str
    severity: RiskLevel
    status: str
    impact: str
    detected_at: datetime
    resolved_at: Optional[datetime]
    mttr: Optional[float]  # hours


@dataclass
class ComplianceStatus:
    """Compliance framework status"""
    framework: str
    score: float
    controls_passed: int
    controls_failed: int
    controls_total: int
    last_audit: datetime
    next_audit: datetime


class ExecutiveDashboard:
    """Executive security dashboard engine"""
    
    def __init__(self):
        self.kpis: Dict[str, SecurityKPI] = {}
        self.risk_indicators: Dict[str, RiskIndicator] = {}
        self.incidents: List[SecurityIncident] = []
        self.compliance: Dict[str, ComplianceStatus] = {}
        
        self._initialize_kpis()
        self._initialize_risk_indicators()
        self._initialize_incidents()
        self._initialize_compliance()
        
    def _initialize_kpis(self):
        """Initialize security KPIs"""
        kpis = [
            SecurityKPI(
                id="KPI-001",
                name="Mean Time to Detect (MTTD)",
                domain=SecurityDomain.INCIDENT_RESPONSE,
                current_value=4.2,
                target_value=2.0,
                unit="hours",
                trend=TrendDirection.IMPROVING,
                trend_percent=-15.2,
                risk_level=RiskLevel.MEDIUM,
                description="Average time to detect security incidents",
                last_updated=datetime.now()
            ),
            SecurityKPI(
                id="KPI-002",
                name="Mean Time to Respond (MTTR)",
                domain=SecurityDomain.INCIDENT_RESPONSE,
                current_value=12.5,
                target_value=8.0,
                unit="hours",
                trend=TrendDirection.IMPROVING,
                trend_percent=-8.3,
                risk_level=RiskLevel.HIGH,
                description="Average time to respond to security incidents",
                last_updated=datetime.now()
            ),
            SecurityKPI(
                id="KPI-003",
                name="Critical Vulnerability Age",
                domain=SecurityDomain.VULNERABILITY_MANAGEMENT,
                current_value=18,
                target_value=7,
                unit="days",
                trend=TrendDirection.DECLINING,
                trend_percent=12.5,
                risk_level=RiskLevel.HIGH,
                description="Average age of unpatched critical vulnerabilities",
                last_updated=datetime.now()
            ),
            SecurityKPI(
                id="KPI-004",
                name="Patch Compliance Rate",
                domain=SecurityDomain.VULNERABILITY_MANAGEMENT,
                current_value=87.3,
                target_value=95.0,
                unit="%",
                trend=TrendDirection.IMPROVING,
                trend_percent=3.2,
                risk_level=RiskLevel.MEDIUM,
                description="Percentage of systems with current patches",
                last_updated=datetime.now()
            ),
            SecurityKPI(
                id="KPI-005",
                name="MFA Adoption Rate",
                domain=SecurityDomain.IDENTITY_ACCESS,
                current_value=92.1,
                target_value=100.0,
                unit="%",
                trend=TrendDirection.IMPROVING,
                trend_percent=5.1,
                risk_level=RiskLevel.LOW,
                description="Percentage of users with MFA enabled",
                last_updated=datetime.now()
            ),
            SecurityKPI(
                id="KPI-006",
                name="Privileged Account Ratio",
                domain=SecurityDomain.IDENTITY_ACCESS,
                current_value=8.2,
                target_value=5.0,
                unit="%",
                trend=TrendDirection.STABLE,
                trend_percent=-0.8,
                risk_level=RiskLevel.MEDIUM,
                description="Percentage of accounts with privileged access",
                last_updated=datetime.now()
            ),
            SecurityKPI(
                id="KPI-007",
                name="Data Classification Coverage",
                domain=SecurityDomain.DATA_PROTECTION,
                current_value=78.5,
                target_value=100.0,
                unit="%",
                trend=TrendDirection.IMPROVING,
                trend_percent=6.3,
                risk_level=RiskLevel.MEDIUM,
                description="Percentage of data assets classified",
                last_updated=datetime.now()
            ),
            SecurityKPI(
                id="KPI-008",
                name="Encryption at Rest",
                domain=SecurityDomain.DATA_PROTECTION,
                current_value=94.2,
                target_value=100.0,
                unit="%",
                trend=TrendDirection.IMPROVING,
                trend_percent=2.1,
                risk_level=RiskLevel.LOW,
                description="Percentage of sensitive data encrypted at rest",
                last_updated=datetime.now()
            ),
            SecurityKPI(
                id="KPI-009",
                name="Endpoint Protection Coverage",
                domain=SecurityDomain.ENDPOINT_SECURITY,
                current_value=98.5,
                target_value=100.0,
                unit="%",
                trend=TrendDirection.STABLE,
                trend_percent=0.3,
                risk_level=RiskLevel.LOW,
                description="Percentage of endpoints with protection agents",
                last_updated=datetime.now()
            ),
            SecurityKPI(
                id="KPI-010",
                name="Cloud Misconfigurations",
                domain=SecurityDomain.CLOUD_SECURITY,
                current_value=23,
                target_value=0,
                unit="count",
                trend=TrendDirection.IMPROVING,
                trend_percent=-18.2,
                risk_level=RiskLevel.HIGH,
                description="Number of cloud security misconfigurations",
                last_updated=datetime.now()
            ),
            SecurityKPI(
                id="KPI-011",
                name="Security Awareness Score",
                domain=SecurityDomain.SECURITY_AWARENESS,
                current_value=72.5,
                target_value=85.0,
                unit="%",
                trend=TrendDirection.IMPROVING,
                trend_percent=4.5,
                risk_level=RiskLevel.MEDIUM,
                description="Employee security awareness test scores",
                last_updated=datetime.now()
            ),
            SecurityKPI(
                id="KPI-012",
                name="Third-Party Risk Score",
                domain=SecurityDomain.THIRD_PARTY_RISK,
                current_value=68.3,
                target_value=80.0,
                unit="score",
                trend=TrendDirection.STABLE,
                trend_percent=-1.2,
                risk_level=RiskLevel.MEDIUM,
                description="Average security score of third-party vendors",
                last_updated=datetime.now()
            ),
        ]
        
        for kpi in kpis:
            self.kpis[kpi.id] = kpi
            
    def _initialize_risk_indicators(self):
        """Initialize risk indicators"""
        indicators = [
            RiskIndicator(
                id="RISK-001",
                name="Cyber Risk Score",
                category="Overall",
                score=72.5,
                weight=1.0,
                trend=TrendDirection.IMPROVING,
                factors=["Vulnerability exposure", "Threat landscape", "Control effectiveness"],
                mitigation_status="Active remediation in progress"
            ),
            RiskIndicator(
                id="RISK-002",
                name="Data Breach Likelihood",
                category="Data Protection",
                score=35.2,
                weight=0.25,
                trend=TrendDirection.IMPROVING,
                factors=["Encryption coverage", "Access controls", "DLP effectiveness"],
                mitigation_status="Below threshold"
            ),
            RiskIndicator(
                id="RISK-003",
                name="Ransomware Exposure",
                category="Endpoint",
                score=28.5,
                weight=0.20,
                trend=TrendDirection.IMPROVING,
                factors=["Backup integrity", "EDR coverage", "User training"],
                mitigation_status="Well controlled"
            ),
            RiskIndicator(
                id="RISK-004",
                name="Supply Chain Risk",
                category="Third Party",
                score=45.8,
                weight=0.15,
                trend=TrendDirection.STABLE,
                factors=["Vendor security posture", "Integration points", "Monitoring"],
                mitigation_status="Requires attention"
            ),
            RiskIndicator(
                id="RISK-005",
                name="Insider Threat Index",
                category="Identity",
                score=22.1,
                weight=0.15,
                trend=TrendDirection.STABLE,
                factors=["Access patterns", "Behavioral analytics", "DLP alerts"],
                mitigation_status="Within tolerance"
            ),
            RiskIndicator(
                id="RISK-006",
                name="Cloud Security Posture",
                category="Cloud",
                score=38.5,
                weight=0.25,
                trend=TrendDirection.IMPROVING,
                factors=["CSPM findings", "IAM hygiene", "Network exposure"],
                mitigation_status="Remediation planned"
            ),
        ]
        
        for indicator in indicators:
            self.risk_indicators[indicator.id] = indicator
            
    def _initialize_incidents(self):
        """Initialize recent incidents"""
        now = datetime.now()
        
        incidents = [
            SecurityIncident(
                id="INC-001",
                title="Phishing Campaign Detected",
                severity=RiskLevel.HIGH,
                status="Resolved",
                impact="15 users targeted, 2 clicked, 0 compromised",
                detected_at=now - timedelta(hours=72),
                resolved_at=now - timedelta(hours=68),
                mttr=4.0
            ),
            SecurityIncident(
                id="INC-002",
                title="Suspicious Login Activity",
                severity=RiskLevel.MEDIUM,
                status="Investigating",
                impact="3 accounts flagged for unusual access patterns",
                detected_at=now - timedelta(hours=6),
                resolved_at=None,
                mttr=None
            ),
            SecurityIncident(
                id="INC-003",
                title="Malware Detection on Endpoint",
                severity=RiskLevel.HIGH,
                status="Contained",
                impact="1 workstation isolated, no lateral movement",
                detected_at=now - timedelta(hours=24),
                resolved_at=now - timedelta(hours=20),
                mttr=4.0
            ),
            SecurityIncident(
                id="INC-004",
                title="DLP Alert: Sensitive Data Transfer",
                severity=RiskLevel.MEDIUM,
                status="Resolved",
                impact="Legitimate transfer verified with data owner",
                detected_at=now - timedelta(hours=48),
                resolved_at=now - timedelta(hours=44),
                mttr=4.0
            ),
            SecurityIncident(
                id="INC-005",
                title="Failed Authentication Spike",
                severity=RiskLevel.LOW,
                status="Resolved",
                impact="Password spray attempt blocked by MFA",
                detected_at=now - timedelta(hours=12),
                resolved_at=now - timedelta(hours=11),
                mttr=1.0
            ),
        ]
        
        self.incidents = incidents
        
    def _initialize_compliance(self):
        """Initialize compliance status"""
        now = datetime.now()
        
        frameworks = [
            ComplianceStatus(
                framework="SOC 2 Type II",
                score=94.5,
                controls_passed=85,
                controls_failed=5,
                controls_total=90,
                last_audit=now - timedelta(days=180),
                next_audit=now + timedelta(days=185)
            ),
            ComplianceStatus(
                framework="ISO 27001",
                score=91.2,
                controls_passed=102,
                controls_failed=10,
                controls_total=112,
                last_audit=now - timedelta(days=90),
                next_audit=now + timedelta(days=275)
            ),
            ComplianceStatus(
                framework="PCI DSS",
                score=96.8,
                controls_passed=248,
                controls_failed=8,
                controls_total=256,
                last_audit=now - timedelta(days=60),
                next_audit=now + timedelta(days=305)
            ),
            ComplianceStatus(
                framework="HIPAA",
                score=89.3,
                controls_passed=152,
                controls_failed=18,
                controls_total=170,
                last_audit=now - timedelta(days=120),
                next_audit=now + timedelta(days=245)
            ),
            ComplianceStatus(
                framework="GDPR",
                score=87.5,
                controls_passed=70,
                controls_failed=10,
                controls_total=80,
                last_audit=now - timedelta(days=200),
                next_audit=now + timedelta(days=165)
            ),
        ]
        
        for fw in frameworks:
            self.compliance[fw.framework] = fw
            
    def get_executive_summary(self) -> Dict:
        """Get executive summary metrics"""
        return {
            "overall_risk_score": self._calculate_overall_risk(),
            "risk_trend": "improving",
            "risk_change": -5.2,
            "active_incidents": sum(1 for i in self.incidents if i.status != "Resolved"),
            "critical_vulns": 12,
            "compliance_score": self._calculate_compliance_score(),
            "security_investment_roi": 340,  # percent
            "cyber_insurance_status": "Active",
            "last_updated": datetime.now().isoformat(),
        }
        
    def _calculate_overall_risk(self) -> float:
        """Calculate overall risk score"""
        total_weight = sum(r.weight for r in self.risk_indicators.values())
        weighted_score = sum(
            r.score * r.weight for r in self.risk_indicators.values()
        )
        return round(100 - (weighted_score / total_weight), 1)
        
    def _calculate_compliance_score(self) -> float:
        """Calculate average compliance score"""
        if not self.compliance:
            return 0.0
        return round(
            sum(c.score for c in self.compliance.values()) / len(self.compliance),
            1
        )
        
    def get_executive_metrics(self) -> List[ExecutiveMetric]:
        """Get key metrics for executive view"""
        return [
            ExecutiveMetric(
                name="Cyber Risk Score",
                value=f"{self._calculate_overall_risk():.0f}/100",
                change=-5.2,
                change_period="vs last quarter",
                icon="🛡️",
                color="#27ae60"
            ),
            ExecutiveMetric(
                name="Security Incidents (30d)",
                value="23",
                change=-15.0,
                change_period="vs previous 30d",
                icon="🚨",
                color="#f1c40f"
            ),
            ExecutiveMetric(
                name="Mean Time to Detect",
                value="4.2h",
                change=-22.0,
                change_period="vs last quarter",
                icon="⏱️",
                color="#27ae60"
            ),
            ExecutiveMetric(
                name="Critical Vulnerabilities",
                value="12",
                change=-40.0,
                change_period="vs last month",
                icon="🐛",
                color="#27ae60"
            ),
            ExecutiveMetric(
                name="Compliance Score",
                value=f"{self._calculate_compliance_score():.0f}%",
                change=3.2,
                change_period="vs last audit",
                icon="📋",
                color="#3498db"
            ),
            ExecutiveMetric(
                name="Security ROI",
                value="340%",
                change=45.0,
                change_period="vs previous year",
                icon="💰",
                color="#27ae60"
            ),
        ]
        
    def get_kpi_summary(self, domain: Optional[SecurityDomain] = None) -> List[Dict]:
        """Get KPI summary"""
        kpis = self.kpis.values()
        if domain:
            kpis = [k for k in kpis if k.domain == domain]
            
        return [
            {
                "id": k.id,
                "name": k.name,
                "domain": k.domain.value,
                "current": k.current_value,
                "target": k.target_value,
                "unit": k.unit,
                "trend": k.trend.value,
                "trend_percent": k.trend_percent,
                "risk": k.risk_level.value,
                "description": k.description,
            }
            for k in kpis
        ]
        
    def get_risk_posture(self) -> Dict:
        """Get risk posture summary"""
        return {
            "overall_score": self._calculate_overall_risk(),
            "indicators": [
                {
                    "name": r.name,
                    "category": r.category,
                    "score": r.score,
                    "trend": r.trend.value,
                    "status": r.mitigation_status,
                    "factors": r.factors,
                }
                for r in self.risk_indicators.values()
            ],
            "risk_distribution": {
                "critical": 2,
                "high": 5,
                "medium": 12,
                "low": 8,
            },
        }
        
    def get_incident_summary(self) -> Dict:
        """Get incident summary"""
        resolved = [i for i in self.incidents if i.status == "Resolved"]
        avg_mttr = (
            sum(i.mttr or 0 for i in resolved) / len(resolved)
            if resolved else 0
        )
        
        return {
            "total": len(self.incidents),
            "active": sum(1 for i in self.incidents if i.status != "Resolved"),
            "resolved_30d": len(resolved),
            "avg_mttr": round(avg_mttr, 1),
            "by_severity": {
                "critical": sum(1 for i in self.incidents if i.severity == RiskLevel.CRITICAL),
                "high": sum(1 for i in self.incidents if i.severity == RiskLevel.HIGH),
                "medium": sum(1 for i in self.incidents if i.severity == RiskLevel.MEDIUM),
                "low": sum(1 for i in self.incidents if i.severity == RiskLevel.LOW),
            },
            "incidents": [
                {
                    "id": i.id,
                    "title": i.title,
                    "severity": i.severity.value,
                    "status": i.status,
                    "impact": i.impact,
                    "detected_at": i.detected_at.isoformat(),
                }
                for i in self.incidents[:5]
            ],
        }
        
    def get_compliance_summary(self) -> Dict:
        """Get compliance summary"""
        return {
            "average_score": self._calculate_compliance_score(),
            "frameworks": [
                {
                    "name": c.framework,
                    "score": c.score,
                    "passed": c.controls_passed,
                    "failed": c.controls_failed,
                    "total": c.controls_total,
                    "last_audit": c.last_audit.isoformat(),
                    "next_audit": c.next_audit.isoformat(),
                    "days_until_audit": (c.next_audit - datetime.now()).days,
                }
                for c in self.compliance.values()
            ],
        }
        
    def get_trend_data(self, metric: str, period_days: int = 90) -> List[Dict]:
        """Get trend data for charting"""
        # Generate simulated trend data
        data = []
        base_value = random.uniform(60, 80)
        
        for i in range(period_days):
            date = datetime.now() - timedelta(days=period_days - i)
            # Add some randomness with overall improving trend
            value = base_value + (i * 0.1) + random.uniform(-5, 5)
            data.append({
                "date": date.strftime("%Y-%m-%d"),
                "value": round(max(0, min(100, value)), 1),
            })
            
        return data
        
    def generate_board_report(self) -> Dict:
        """Generate board-ready report"""
        return {
            "report_date": datetime.now().isoformat(),
            "period": "Q4 2024",
            "executive_summary": self.get_executive_summary(),
            "key_metrics": [m.__dict__ for m in self.get_executive_metrics()],
            "risk_posture": self.get_risk_posture(),
            "incidents": self.get_incident_summary(),
            "compliance": self.get_compliance_summary(),
            "key_initiatives": [
                {"name": "Zero Trust Architecture", "status": "In Progress", "completion": 65},
                {"name": "Cloud Security Enhancement", "status": "In Progress", "completion": 80},
                {"name": "Security Awareness Program", "status": "On Track", "completion": 90},
                {"name": "Third-Party Risk Program", "status": "Planning", "completion": 25},
            ],
            "budget_utilization": {
                "allocated": 2500000,
                "spent": 1875000,
                "remaining": 625000,
                "utilization_rate": 75.0,
            },
            "recommendations": [
                "Accelerate Zero Trust implementation to reduce attack surface",
                "Increase investment in cloud security monitoring tools",
                "Expand security awareness training to cover supply chain risks",
                "Consider cyber insurance policy enhancement given threat landscape",
            ],
        }
        
    @property
    def stats(self) -> Dict:
        """Get dashboard statistics"""
        return {
            "kpis": len(self.kpis),
            "risk_indicators": len(self.risk_indicators),
            "active_incidents": sum(1 for i in self.incidents if i.status != "Resolved"),
            "frameworks": len(self.compliance),
            "overall_risk": self._calculate_overall_risk(),
            "compliance_score": self._calculate_compliance_score(),
        }


# Global instance
_dashboard_instance: Optional[ExecutiveDashboard] = None


def get_executive_dashboard() -> ExecutiveDashboard:
    """Get or create executive dashboard"""
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = ExecutiveDashboard()
    return _dashboard_instance
