#!/usr/bin/env python3
"""
HydraRecon Security Metrics Module
Enterprise security KPIs, metrics tracking, and performance analytics.
"""

import asyncio
import json
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import uuid
import statistics


class MetricCategory(Enum):
    """Metric categories"""
    VULNERABILITY = "vulnerability"
    THREAT = "threat"
    COMPLIANCE = "compliance"
    INCIDENT = "incident"
    PATCHING = "patching"
    ACCESS = "access"
    DATA = "data"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    AWARENESS = "awareness"


class MetricTrend(Enum):
    """Metric trend direction"""
    IMPROVING = "improving"
    STABLE = "stable"
    DECLINING = "declining"
    CRITICAL = "critical"


class TimeFrame(Enum):
    """Time frame for metrics"""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"


class TargetStatus(Enum):
    """Target achievement status"""
    EXCEEDED = "exceeded"
    MET = "met"
    AT_RISK = "at_risk"
    MISSED = "missed"


@dataclass
class MetricDefinition:
    """Definition of a security metric"""
    id: str
    name: str
    description: str
    category: MetricCategory
    unit: str  # %, count, hours, days, etc.
    formula: str
    data_sources: List[str]
    target_value: float
    threshold_warning: float
    threshold_critical: float
    higher_is_better: bool
    reporting_frequency: TimeFrame
    owner: str
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricValue:
    """A single metric measurement"""
    id: str
    metric_id: str
    value: float
    timestamp: datetime
    period_start: datetime
    period_end: datetime
    data_points: int
    notes: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricTarget:
    """Target for a metric"""
    id: str
    metric_id: str
    target_value: float
    period: TimeFrame
    year: int
    quarter: Optional[int]
    month: Optional[int]
    status: TargetStatus
    actual_value: Optional[float]
    variance: Optional[float]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KPI:
    """Key Performance Indicator"""
    id: str
    name: str
    description: str
    category: MetricCategory
    metrics: List[str]  # Metric IDs that comprise this KPI
    weight_formula: str
    current_score: float
    target_score: float
    trend: MetricTrend
    trend_percentage: float
    last_updated: datetime
    owner: str
    stakeholders: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Dashboard:
    """Security dashboard configuration"""
    id: str
    name: str
    description: str
    widgets: List[Dict[str, Any]]
    kpis: List[str]
    metrics: List[str]
    refresh_interval: int  # seconds
    owner: str
    shared_with: List[str]
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class BenchmarkData:
    """Industry benchmark data"""
    id: str
    metric_id: str
    industry: str
    percentile_25: float
    percentile_50: float
    percentile_75: float
    percentile_90: float
    sample_size: int
    source: str
    period: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecurityMetricsEngine:
    """Enterprise security metrics engine"""
    
    def __init__(self, demo_mode: bool = False):
        """
        Initialize the security metrics engine.
        
        Args:
            demo_mode: If True, generates sample historical data for demonstration.
                      If False (default), metrics are calculated from real scan/vuln data.
        """
        self.metrics: Dict[str, MetricDefinition] = {}
        self.values: Dict[str, List[MetricValue]] = {}  # metric_id -> values
        self.targets: Dict[str, List[MetricTarget]] = {}
        self.kpis: Dict[str, KPI] = {}
        self.dashboards: Dict[str, Dashboard] = {}
        self.benchmarks: Dict[str, List[BenchmarkData]] = {}
        self.callbacks: List[callable] = []
        self.demo_mode = demo_mode
        
        self._init_standard_metrics()
        self._init_standard_kpis()
        
        # Only generate sample data in demo mode
        if demo_mode:
            self._generate_sample_data()
    
    def _init_standard_metrics(self):
        """Initialize industry-standard security metrics"""
        standard_metrics = [
            # Vulnerability Metrics
            {
                "name": "Mean Time to Remediate Critical Vulnerabilities",
                "description": "Average time to fix critical vulnerabilities from discovery",
                "category": MetricCategory.VULNERABILITY,
                "unit": "days",
                "formula": "avg(remediation_date - discovery_date) for critical vulns",
                "target_value": 7.0,
                "threshold_warning": 10.0,
                "threshold_critical": 14.0,
                "higher_is_better": False
            },
            {
                "name": "Vulnerability Density",
                "description": "Number of vulnerabilities per asset",
                "category": MetricCategory.VULNERABILITY,
                "unit": "vulns/asset",
                "formula": "total_vulnerabilities / total_assets",
                "target_value": 2.0,
                "threshold_warning": 5.0,
                "threshold_critical": 10.0,
                "higher_is_better": False
            },
            {
                "name": "Critical Vulnerability Count",
                "description": "Total number of unpatched critical vulnerabilities",
                "category": MetricCategory.VULNERABILITY,
                "unit": "count",
                "formula": "count(severity='critical' AND status='open')",
                "target_value": 0,
                "threshold_warning": 5,
                "threshold_critical": 10,
                "higher_is_better": False
            },
            {
                "name": "Vulnerability Scan Coverage",
                "description": "Percentage of assets scanned in the last 30 days",
                "category": MetricCategory.VULNERABILITY,
                "unit": "%",
                "formula": "(scanned_assets / total_assets) * 100",
                "target_value": 100.0,
                "threshold_warning": 90.0,
                "threshold_critical": 80.0,
                "higher_is_better": True
            },
            # Patching Metrics
            {
                "name": "Patch Compliance Rate",
                "description": "Percentage of systems with all critical patches applied",
                "category": MetricCategory.PATCHING,
                "unit": "%",
                "formula": "(patched_systems / total_systems) * 100",
                "target_value": 95.0,
                "threshold_warning": 90.0,
                "threshold_critical": 80.0,
                "higher_is_better": True
            },
            {
                "name": "Mean Time to Patch",
                "description": "Average time from patch release to deployment",
                "category": MetricCategory.PATCHING,
                "unit": "days",
                "formula": "avg(deployment_date - release_date)",
                "target_value": 14.0,
                "threshold_warning": 21.0,
                "threshold_critical": 30.0,
                "higher_is_better": False
            },
            {
                "name": "Patch Success Rate",
                "description": "Percentage of patch deployments that succeed",
                "category": MetricCategory.PATCHING,
                "unit": "%",
                "formula": "(successful_patches / total_patches) * 100",
                "target_value": 98.0,
                "threshold_warning": 95.0,
                "threshold_critical": 90.0,
                "higher_is_better": True
            },
            # Incident Metrics
            {
                "name": "Mean Time to Detect (MTTD)",
                "description": "Average time to detect security incidents",
                "category": MetricCategory.INCIDENT,
                "unit": "hours",
                "formula": "avg(detection_time - incident_start_time)",
                "target_value": 1.0,
                "threshold_warning": 4.0,
                "threshold_critical": 24.0,
                "higher_is_better": False
            },
            {
                "name": "Mean Time to Respond (MTTR)",
                "description": "Average time to respond to security incidents",
                "category": MetricCategory.INCIDENT,
                "unit": "hours",
                "formula": "avg(response_time - detection_time)",
                "target_value": 1.0,
                "threshold_warning": 2.0,
                "threshold_critical": 4.0,
                "higher_is_better": False
            },
            {
                "name": "Mean Time to Contain (MTTC)",
                "description": "Average time to contain security incidents",
                "category": MetricCategory.INCIDENT,
                "unit": "hours",
                "formula": "avg(containment_time - response_time)",
                "target_value": 4.0,
                "threshold_warning": 8.0,
                "threshold_critical": 24.0,
                "higher_is_better": False
            },
            {
                "name": "Incident Volume",
                "description": "Number of security incidents per month",
                "category": MetricCategory.INCIDENT,
                "unit": "count",
                "formula": "count(incidents) per month",
                "target_value": 10,
                "threshold_warning": 25,
                "threshold_critical": 50,
                "higher_is_better": False
            },
            {
                "name": "Incident Recurrence Rate",
                "description": "Percentage of incidents that recur within 90 days",
                "category": MetricCategory.INCIDENT,
                "unit": "%",
                "formula": "(recurring_incidents / total_incidents) * 100",
                "target_value": 5.0,
                "threshold_warning": 10.0,
                "threshold_critical": 20.0,
                "higher_is_better": False
            },
            # Threat Metrics
            {
                "name": "Blocked Threat Rate",
                "description": "Percentage of detected threats that were blocked",
                "category": MetricCategory.THREAT,
                "unit": "%",
                "formula": "(blocked_threats / detected_threats) * 100",
                "target_value": 99.0,
                "threshold_warning": 95.0,
                "threshold_critical": 90.0,
                "higher_is_better": True
            },
            {
                "name": "Malware Detection Rate",
                "description": "Percentage of known malware samples detected",
                "category": MetricCategory.THREAT,
                "unit": "%",
                "formula": "(detected_malware / known_malware) * 100",
                "target_value": 99.5,
                "threshold_warning": 98.0,
                "threshold_critical": 95.0,
                "higher_is_better": True
            },
            {
                "name": "Phishing Click Rate",
                "description": "Percentage of users who click phishing simulations",
                "category": MetricCategory.AWARENESS,
                "unit": "%",
                "formula": "(clicked_users / total_users) * 100",
                "target_value": 3.0,
                "threshold_warning": 10.0,
                "threshold_critical": 20.0,
                "higher_is_better": False
            },
            # Compliance Metrics
            {
                "name": "Compliance Score",
                "description": "Overall compliance percentage across frameworks",
                "category": MetricCategory.COMPLIANCE,
                "unit": "%",
                "formula": "(compliant_controls / total_controls) * 100",
                "target_value": 95.0,
                "threshold_warning": 85.0,
                "threshold_critical": 75.0,
                "higher_is_better": True
            },
            {
                "name": "Policy Violations",
                "description": "Number of security policy violations per month",
                "category": MetricCategory.COMPLIANCE,
                "unit": "count",
                "formula": "count(policy_violations) per month",
                "target_value": 0,
                "threshold_warning": 10,
                "threshold_critical": 25,
                "higher_is_better": False
            },
            {
                "name": "Audit Findings",
                "description": "Number of open audit findings",
                "category": MetricCategory.COMPLIANCE,
                "unit": "count",
                "formula": "count(findings WHERE status='open')",
                "target_value": 0,
                "threshold_warning": 5,
                "threshold_critical": 15,
                "higher_is_better": False
            },
            # Access Control Metrics
            {
                "name": "Privileged Account Ratio",
                "description": "Ratio of privileged accounts to total accounts",
                "category": MetricCategory.ACCESS,
                "unit": "%",
                "formula": "(privileged_accounts / total_accounts) * 100",
                "target_value": 5.0,
                "threshold_warning": 10.0,
                "threshold_critical": 15.0,
                "higher_is_better": False
            },
            {
                "name": "Orphaned Account Count",
                "description": "Number of accounts without active owners",
                "category": MetricCategory.ACCESS,
                "unit": "count",
                "formula": "count(accounts WHERE owner_status='inactive')",
                "target_value": 0,
                "threshold_warning": 10,
                "threshold_critical": 50,
                "higher_is_better": False
            },
            {
                "name": "MFA Coverage",
                "description": "Percentage of accounts with MFA enabled",
                "category": MetricCategory.ACCESS,
                "unit": "%",
                "formula": "(mfa_enabled_accounts / total_accounts) * 100",
                "target_value": 100.0,
                "threshold_warning": 95.0,
                "threshold_critical": 90.0,
                "higher_is_better": True
            },
            {
                "name": "Failed Login Attempts",
                "description": "Number of failed login attempts per day",
                "category": MetricCategory.ACCESS,
                "unit": "count",
                "formula": "count(failed_logins) per day",
                "target_value": 100,
                "threshold_warning": 500,
                "threshold_critical": 1000,
                "higher_is_better": False
            },
            # Data Protection Metrics
            {
                "name": "Data Encryption Coverage",
                "description": "Percentage of sensitive data that is encrypted",
                "category": MetricCategory.DATA,
                "unit": "%",
                "formula": "(encrypted_data / sensitive_data) * 100",
                "target_value": 100.0,
                "threshold_warning": 95.0,
                "threshold_critical": 90.0,
                "higher_is_better": True
            },
            {
                "name": "DLP Alerts",
                "description": "Number of data loss prevention alerts per month",
                "category": MetricCategory.DATA,
                "unit": "count",
                "formula": "count(dlp_alerts) per month",
                "target_value": 10,
                "threshold_warning": 50,
                "threshold_critical": 100,
                "higher_is_better": False
            },
            # Network Security Metrics
            {
                "name": "Firewall Rule Effectiveness",
                "description": "Percentage of firewall rules that block malicious traffic",
                "category": MetricCategory.NETWORK,
                "unit": "%",
                "formula": "(blocked_by_rules / malicious_attempts) * 100",
                "target_value": 99.0,
                "threshold_warning": 95.0,
                "threshold_critical": 90.0,
                "higher_is_better": True
            },
            {
                "name": "Network Segmentation Score",
                "description": "Effectiveness of network segmentation",
                "category": MetricCategory.NETWORK,
                "unit": "%",
                "formula": "segmentation_effectiveness_score",
                "target_value": 90.0,
                "threshold_warning": 75.0,
                "threshold_critical": 60.0,
                "higher_is_better": True
            },
            # Endpoint Security Metrics
            {
                "name": "Endpoint Protection Coverage",
                "description": "Percentage of endpoints with security agent installed",
                "category": MetricCategory.ENDPOINT,
                "unit": "%",
                "formula": "(protected_endpoints / total_endpoints) * 100",
                "target_value": 100.0,
                "threshold_warning": 98.0,
                "threshold_critical": 95.0,
                "higher_is_better": True
            },
            {
                "name": "Endpoint Compliance Rate",
                "description": "Percentage of endpoints meeting security baseline",
                "category": MetricCategory.ENDPOINT,
                "unit": "%",
                "formula": "(compliant_endpoints / total_endpoints) * 100",
                "target_value": 95.0,
                "threshold_warning": 90.0,
                "threshold_critical": 80.0,
                "higher_is_better": True
            },
            # Security Awareness
            {
                "name": "Security Training Completion",
                "description": "Percentage of employees who completed training",
                "category": MetricCategory.AWARENESS,
                "unit": "%",
                "formula": "(trained_employees / total_employees) * 100",
                "target_value": 100.0,
                "threshold_warning": 90.0,
                "threshold_critical": 80.0,
                "higher_is_better": True
            },
            {
                "name": "Security Awareness Score",
                "description": "Average score on security awareness assessments",
                "category": MetricCategory.AWARENESS,
                "unit": "%",
                "formula": "avg(assessment_scores)",
                "target_value": 85.0,
                "threshold_warning": 75.0,
                "threshold_critical": 65.0,
                "higher_is_better": True
            }
        ]
        
        for metric_data in standard_metrics:
            metric = MetricDefinition(
                id=str(uuid.uuid4()),
                name=metric_data["name"],
                description=metric_data["description"],
                category=metric_data["category"],
                unit=metric_data["unit"],
                formula=metric_data["formula"],
                data_sources=["security_tools", "logs", "assessments"],
                target_value=metric_data["target_value"],
                threshold_warning=metric_data["threshold_warning"],
                threshold_critical=metric_data["threshold_critical"],
                higher_is_better=metric_data["higher_is_better"],
                reporting_frequency=TimeFrame.MONTHLY,
                owner="Security Team"
            )
            self.metrics[metric.id] = metric
            self.values[metric.id] = []
    
    def _init_standard_kpis(self):
        """Initialize standard security KPIs"""
        # Get metric IDs by category
        vuln_metrics = [m.id for m in self.metrics.values() if m.category == MetricCategory.VULNERABILITY]
        incident_metrics = [m.id for m in self.metrics.values() if m.category == MetricCategory.INCIDENT]
        compliance_metrics = [m.id for m in self.metrics.values() if m.category == MetricCategory.COMPLIANCE]
        
        kpis = [
            {
                "name": "Security Posture Score",
                "description": "Overall security posture of the organization",
                "category": MetricCategory.VULNERABILITY,
                "current_score": 78.5,
                "target_score": 90.0
            },
            {
                "name": "Incident Response Efficiency",
                "description": "Effectiveness of incident response capabilities",
                "category": MetricCategory.INCIDENT,
                "current_score": 82.3,
                "target_score": 95.0
            },
            {
                "name": "Compliance Readiness",
                "description": "Readiness for regulatory compliance audits",
                "category": MetricCategory.COMPLIANCE,
                "current_score": 91.2,
                "target_score": 98.0
            },
            {
                "name": "Vulnerability Management Effectiveness",
                "description": "Effectiveness of vulnerability management program",
                "category": MetricCategory.VULNERABILITY,
                "current_score": 75.8,
                "target_score": 90.0
            },
            {
                "name": "Threat Detection Capability",
                "description": "Ability to detect and respond to threats",
                "category": MetricCategory.THREAT,
                "current_score": 85.4,
                "target_score": 95.0
            }
        ]
        
        for kpi_data in kpis:
            kpi = KPI(
                id=str(uuid.uuid4()),
                name=kpi_data["name"],
                description=kpi_data["description"],
                category=kpi_data["category"],
                metrics=[],
                weight_formula="equal_weight",
                current_score=kpi_data["current_score"],
                target_score=kpi_data["target_score"],
                trend=MetricTrend.IMPROVING if kpi_data["current_score"] > 75 else MetricTrend.DECLINING,
                trend_percentage=2.5,
                last_updated=datetime.now(),
                owner="CISO",
                stakeholders=["Security Team", "IT Leadership"]
            )
            self.kpis[kpi.id] = kpi
    
    def _generate_sample_data(self):
        """Generate sample historical data"""
        import random
        
        for metric_id, metric in self.metrics.items():
            values = []
            base_value = metric.target_value
            
            # Generate 12 months of data
            for i in range(12, 0, -1):
                period_end = datetime.now() - timedelta(days=30 * (i - 1))
                period_start = period_end - timedelta(days=30)
                
                # Add some variance
                variance = random.uniform(-0.2, 0.3) * base_value
                value = base_value + variance
                
                if not metric.higher_is_better:
                    value = max(0, value)
                else:
                    value = min(100, max(0, value))
                
                metric_value = MetricValue(
                    id=str(uuid.uuid4()),
                    metric_id=metric_id,
                    value=value,
                    timestamp=period_end,
                    period_start=period_start,
                    period_end=period_end,
                    data_points=random.randint(100, 1000),
                    notes=None
                )
                values.append(metric_value)
            
            self.values[metric_id] = values
    
    def register_callback(self, callback: callable):
        """Register event callback"""
        self.callbacks.append(callback)
    
    def _emit_event(self, event_type: str, data: Dict[str, Any]):
        """Emit event to callbacks"""
        for callback in self.callbacks:
            try:
                callback(event_type, data)
            except Exception:
                pass
    
    def get_metric_current_value(self, metric_id: str) -> Optional[MetricValue]:
        """Get the most recent value for a metric"""
        if metric_id not in self.values or not self.values[metric_id]:
            return None
        return self.values[metric_id][-1]
    
    def get_metric_trend(self, metric_id: str, periods: int = 6) -> Dict[str, Any]:
        """Calculate trend for a metric"""
        if metric_id not in self.values:
            return {"trend": MetricTrend.STABLE, "percentage": 0.0}
        
        values = self.values[metric_id][-periods:]
        if len(values) < 2:
            return {"trend": MetricTrend.STABLE, "percentage": 0.0}
        
        metric = self.metrics.get(metric_id)
        first_value = values[0].value
        last_value = values[-1].value
        
        if first_value == 0:
            percentage = 0.0
        else:
            percentage = ((last_value - first_value) / first_value) * 100
        
        # Determine trend based on direction and whether higher is better
        if abs(percentage) < 5:
            trend = MetricTrend.STABLE
        elif metric and metric.higher_is_better:
            trend = MetricTrend.IMPROVING if percentage > 0 else MetricTrend.DECLINING
        else:
            trend = MetricTrend.DECLINING if percentage > 0 else MetricTrend.IMPROVING
        
        # Check if critical
        if metric:
            current = last_value
            if metric.higher_is_better:
                if current < metric.threshold_critical:
                    trend = MetricTrend.CRITICAL
            else:
                if current > metric.threshold_critical:
                    trend = MetricTrend.CRITICAL
        
        return {
            "trend": trend,
            "percentage": round(percentage, 2),
            "first_value": first_value,
            "last_value": last_value,
            "data_points": len(values)
        }
    
    def get_metric_history(
        self,
        metric_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[MetricValue]:
        """Get historical values for a metric"""
        if metric_id not in self.values:
            return []
        
        values = self.values[metric_id]
        
        if start_date:
            values = [v for v in values if v.timestamp >= start_date]
        if end_date:
            values = [v for v in values if v.timestamp <= end_date]
        
        return values
    
    def record_metric_value(
        self,
        metric_id: str,
        value: float,
        period_start: datetime,
        period_end: datetime,
        data_points: int = 1,
        notes: Optional[str] = None
    ) -> MetricValue:
        """Record a new metric value"""
        if metric_id not in self.metrics:
            raise ValueError(f"Metric not found: {metric_id}")
        
        metric_value = MetricValue(
            id=str(uuid.uuid4()),
            metric_id=metric_id,
            value=value,
            timestamp=datetime.now(),
            period_start=period_start,
            period_end=period_end,
            data_points=data_points,
            notes=notes
        )
        
        if metric_id not in self.values:
            self.values[metric_id] = []
        
        self.values[metric_id].append(metric_value)
        
        self._emit_event("metric_recorded", {
            "metric_id": metric_id,
            "value": value,
            "timestamp": datetime.now().isoformat()
        })
        
        return metric_value
    
    def evaluate_metric_status(self, metric_id: str) -> Dict[str, Any]:
        """Evaluate current status of a metric"""
        if metric_id not in self.metrics:
            raise ValueError(f"Metric not found: {metric_id}")
        
        metric = self.metrics[metric_id]
        current = self.get_metric_current_value(metric_id)
        trend_data = self.get_metric_trend(metric_id)
        
        if not current:
            return {
                "status": "no_data",
                "metric": metric,
                "current_value": None,
                "trend": trend_data
            }
        
        value = current.value
        
        # Determine status
        if metric.higher_is_better:
            if value >= metric.target_value:
                status = TargetStatus.MET
            elif value >= metric.threshold_warning:
                status = TargetStatus.AT_RISK
            else:
                status = TargetStatus.MISSED
        else:
            if value <= metric.target_value:
                status = TargetStatus.MET
            elif value <= metric.threshold_warning:
                status = TargetStatus.AT_RISK
            else:
                status = TargetStatus.MISSED
        
        # Calculate variance from target
        variance = value - metric.target_value
        variance_pct = (variance / metric.target_value * 100) if metric.target_value != 0 else 0
        
        return {
            "status": status.value,
            "metric": metric,
            "current_value": value,
            "target_value": metric.target_value,
            "variance": variance,
            "variance_percentage": round(variance_pct, 2),
            "trend": trend_data,
            "timestamp": current.timestamp.isoformat()
        }
    
    def get_category_summary(self, category: MetricCategory) -> Dict[str, Any]:
        """Get summary of metrics in a category"""
        category_metrics = [m for m in self.metrics.values() if m.category == category]
        
        statuses = []
        for metric in category_metrics:
            status = self.evaluate_metric_status(metric.id)
            statuses.append(status)
        
        met = sum(1 for s in statuses if s["status"] == "met")
        at_risk = sum(1 for s in statuses if s["status"] == "at_risk")
        missed = sum(1 for s in statuses if s["status"] == "missed")
        no_data = sum(1 for s in statuses if s["status"] == "no_data")
        
        # Calculate overall score
        scores = []
        for s in statuses:
            if s["current_value"] is not None and s["metric"].target_value != 0:
                if s["metric"].higher_is_better:
                    score = min(100, (s["current_value"] / s["target_value"]) * 100)
                else:
                    score = min(100, (s["target_value"] / s["current_value"]) * 100) if s["current_value"] != 0 else 100
                scores.append(score)
        
        avg_score = statistics.mean(scores) if scores else 0
        
        return {
            "category": category.value,
            "total_metrics": len(category_metrics),
            "met": met,
            "at_risk": at_risk,
            "missed": missed,
            "no_data": no_data,
            "average_score": round(avg_score, 1),
            "metrics": statuses
        }
    
    def get_executive_summary(self) -> Dict[str, Any]:
        """Get executive-level summary of all metrics"""
        categories = {}
        for category in MetricCategory:
            categories[category.value] = self.get_category_summary(category)
        
        # Overall statistics
        total_metrics = len(self.metrics)
        all_statuses = []
        for cat_data in categories.values():
            all_statuses.extend(cat_data["metrics"])
        
        total_met = sum(1 for s in all_statuses if s["status"] == "met")
        total_at_risk = sum(1 for s in all_statuses if s["status"] == "at_risk")
        total_missed = sum(1 for s in all_statuses if s["status"] == "missed")
        
        # Calculate overall score
        all_scores = [cat["average_score"] for cat in categories.values() if cat["average_score"] > 0]
        overall_score = statistics.mean(all_scores) if all_scores else 0
        
        # Top concerns (missed targets)
        concerns = [s for s in all_statuses if s["status"] == "missed"]
        concerns.sort(key=lambda x: abs(x.get("variance_percentage", 0)), reverse=True)
        
        return {
            "generated_at": datetime.now().isoformat(),
            "overall_score": round(overall_score, 1),
            "total_metrics": total_metrics,
            "targets_met": total_met,
            "at_risk": total_at_risk,
            "targets_missed": total_missed,
            "categories": categories,
            "top_concerns": concerns[:5],
            "kpis": [
                {
                    "name": kpi.name,
                    "score": kpi.current_score,
                    "target": kpi.target_score,
                    "trend": kpi.trend.value
                }
                for kpi in self.kpis.values()
            ]
        }
    
    def compare_to_benchmark(
        self,
        metric_id: str,
        industry: str = "all"
    ) -> Dict[str, Any]:
        """Compare metric value to industry benchmarks"""
        current = self.get_metric_current_value(metric_id)
        if not current:
            return {"status": "no_data"}
        
        # Sample benchmark data (in production would come from external source)
        metric = self.metrics.get(metric_id)
        if not metric:
            return {"status": "metric_not_found"}
        
        # Generate synthetic benchmarks
        target = metric.target_value
        benchmarks = {
            "percentile_25": target * 0.7,
            "percentile_50": target * 0.85,
            "percentile_75": target * 1.0,
            "percentile_90": target * 1.15
        }
        
        # Determine percentile
        value = current.value
        if metric.higher_is_better:
            if value >= benchmarks["percentile_90"]:
                percentile = 95
            elif value >= benchmarks["percentile_75"]:
                percentile = 80
            elif value >= benchmarks["percentile_50"]:
                percentile = 60
            elif value >= benchmarks["percentile_25"]:
                percentile = 35
            else:
                percentile = 15
        else:
            if value <= benchmarks["percentile_90"]:
                percentile = 95
            elif value <= benchmarks["percentile_75"]:
                percentile = 80
            elif value <= benchmarks["percentile_50"]:
                percentile = 60
            elif value <= benchmarks["percentile_25"]:
                percentile = 35
            else:
                percentile = 15
        
        return {
            "metric_id": metric_id,
            "current_value": value,
            "industry": industry,
            "percentile": percentile,
            "benchmarks": benchmarks,
            "performance": "Above Average" if percentile > 50 else "Below Average"
        }
    
    def create_dashboard(
        self,
        name: str,
        description: str,
        metrics: List[str],
        kpis: List[str]
    ) -> Dashboard:
        """Create a new dashboard"""
        dashboard = Dashboard(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            widgets=[],
            kpis=kpis,
            metrics=metrics,
            refresh_interval=300,
            owner="Security Team",
            shared_with=[]
        )
        
        self.dashboards[dashboard.id] = dashboard
        return dashboard
    
    def generate_report(
        self,
        report_type: str = "executive",
        period: TimeFrame = TimeFrame.MONTHLY
    ) -> Dict[str, Any]:
        """Generate metrics report"""
        if report_type == "executive":
            return self.get_executive_summary()
        elif report_type == "detailed":
            return self._generate_detailed_report(period)
        elif report_type == "trend":
            return self._generate_trend_report(period)
        else:
            return self.get_executive_summary()
    
    def _generate_detailed_report(self, period: TimeFrame) -> Dict[str, Any]:
        """Generate detailed metrics report"""
        metrics_detail = []
        for metric_id, metric in self.metrics.items():
            status = self.evaluate_metric_status(metric_id)
            history = self.get_metric_history(metric_id)
            
            metrics_detail.append({
                "metric": {
                    "id": metric.id,
                    "name": metric.name,
                    "category": metric.category.value,
                    "unit": metric.unit
                },
                "status": status,
                "history": [
                    {"date": v.timestamp.isoformat(), "value": v.value}
                    for v in history[-6:]
                ]
            })
        
        return {
            "report_type": "detailed",
            "generated_at": datetime.now().isoformat(),
            "period": period.value,
            "metrics": metrics_detail
        }
    
    def _generate_trend_report(self, period: TimeFrame) -> Dict[str, Any]:
        """Generate trend analysis report"""
        trends = []
        for metric_id, metric in self.metrics.items():
            trend = self.get_metric_trend(metric_id)
            trends.append({
                "metric_name": metric.name,
                "category": metric.category.value,
                "trend": trend["trend"].value,
                "percentage": trend["percentage"]
            })
        
        # Sort by trend significance
        trends.sort(key=lambda x: abs(x["percentage"]), reverse=True)
        
        improving = [t for t in trends if t["trend"] == "improving"]
        declining = [t for t in trends if t["trend"] == "declining"]
        critical = [t for t in trends if t["trend"] == "critical"]
        
        return {
            "report_type": "trend",
            "generated_at": datetime.now().isoformat(),
            "period": period.value,
            "summary": {
                "improving": len(improving),
                "stable": len([t for t in trends if t["trend"] == "stable"]),
                "declining": len(declining),
                "critical": len(critical)
            },
            "improving_metrics": improving[:5],
            "declining_metrics": declining[:5],
            "critical_metrics": critical,
            "all_trends": trends
        }
    
    def export_data(self) -> Dict[str, Any]:
        """Export all metrics data"""
        return {
            "export_time": datetime.now().isoformat(),
            "metrics": [
                {
                    "id": m.id,
                    "name": m.name,
                    "category": m.category.value,
                    "target": m.target_value,
                    "current": self.get_metric_current_value(m.id).value if self.get_metric_current_value(m.id) else None
                }
                for m in self.metrics.values()
            ],
            "kpis": [
                {
                    "id": k.id,
                    "name": k.name,
                    "score": k.current_score,
                    "target": k.target_score
                }
                for k in self.kpis.values()
            ]
        }
