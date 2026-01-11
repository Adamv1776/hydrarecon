"""
Security Dashboard Module for HydraRecon
Real-time security posture monitoring and metrics
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import uuid
import random
import logging

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of security metrics"""
    VULNERABILITY = "vulnerability"
    THREAT = "threat"
    COMPLIANCE = "compliance"
    RISK = "risk"
    ATTACK = "attack"
    ASSET = "asset"
    INCIDENT = "incident"
    PERFORMANCE = "performance"


class TrendDirection(Enum):
    """Trend direction"""
    UP = "up"
    DOWN = "down"
    STABLE = "stable"


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    """Alert status"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


@dataclass
class SecurityMetric:
    """Individual security metric"""
    id: str
    name: str
    metric_type: MetricType
    value: float
    unit: str = ""
    target: Optional[float] = None
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    trend: TrendDirection = TrendDirection.STABLE
    change_percent: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)
    history: List[Dict] = field(default_factory=list)


@dataclass 
class SecurityAlert:
    """Security alert"""
    id: str
    title: str
    description: str
    severity: AlertSeverity
    status: AlertStatus
    source: str
    category: str
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    related_assets: List[str] = field(default_factory=list)
    remediation: str = ""
    false_positive: bool = False


@dataclass
class RiskScore:
    """Overall risk score"""
    score: float
    grade: str
    breakdown: Dict[str, float] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    last_calculated: datetime = field(default_factory=datetime.now)


@dataclass
class SecurityEvent:
    """Security event for timeline"""
    id: str
    event_type: str
    title: str
    description: str
    severity: AlertSeverity
    timestamp: datetime
    source: str
    details: Dict = field(default_factory=dict)


@dataclass
class DashboardWidget:
    """Dashboard widget configuration"""
    id: str
    widget_type: str
    title: str
    position: Dict[str, int]  # x, y, width, height
    config: Dict = field(default_factory=dict)
    refresh_interval: int = 60  # seconds


class SecurityDashboardEngine:
    """Main security dashboard engine"""
    
    def __init__(self):
        self.metrics: Dict[str, SecurityMetric] = {}
        self.alerts: Dict[str, SecurityAlert] = {}
        self.events: List[SecurityEvent] = []
        self.risk_score: Optional[RiskScore] = None
        self.widgets: Dict[str, DashboardWidget] = {}
        self._callbacks: List[Callable] = []
        self._running = False
        
        # Initialize default metrics
        self._init_default_metrics()
        self._init_default_widgets()
    
    def _init_default_metrics(self):
        """Initialize default security metrics"""
        default_metrics = [
            ("vuln_critical", "Critical Vulnerabilities", MetricType.VULNERABILITY, 0, "", None, 5, 10),
            ("vuln_high", "High Vulnerabilities", MetricType.VULNERABILITY, 0, "", None, 20, 50),
            ("vuln_medium", "Medium Vulnerabilities", MetricType.VULNERABILITY, 0, "", None, 50, 100),
            ("vuln_low", "Low Vulnerabilities", MetricType.VULNERABILITY, 0),
            ("total_assets", "Total Assets", MetricType.ASSET, 0),
            ("active_assets", "Active Assets", MetricType.ASSET, 0),
            ("unpatched_systems", "Unpatched Systems", MetricType.VULNERABILITY, 0, "", None, 5, 20),
            ("threats_detected", "Threats Detected", MetricType.THREAT, 0),
            ("attacks_blocked", "Attacks Blocked", MetricType.ATTACK, 0),
            ("open_incidents", "Open Incidents", MetricType.INCIDENT, 0, "", None, 5, 10),
            ("compliance_score", "Compliance Score", MetricType.COMPLIANCE, 100, "%", 90, 80, 60),
            ("risk_score", "Risk Score", MetricType.RISK, 0, "/10", None, 7, 9),
            ("mean_time_detect", "Mean Time to Detect", MetricType.PERFORMANCE, 0, "min", 15, 30, 60),
            ("mean_time_respond", "Mean Time to Respond", MetricType.PERFORMANCE, 0, "min", 60, 120, 240),
            ("patch_compliance", "Patch Compliance", MetricType.COMPLIANCE, 100, "%", 95, 85, 70),
            ("endpoint_coverage", "Endpoint Coverage", MetricType.ASSET, 100, "%", 100, 90, 80),
        ]
        
        for item in default_metrics:
            metric_id = item[0]
            name = item[1]
            metric_type = item[2]
            value = item[3]
            unit = item[4] if len(item) > 4 else ""
            target = item[5] if len(item) > 5 else None
            warn = item[6] if len(item) > 6 else None
            crit = item[7] if len(item) > 7 else None
            
            self.metrics[metric_id] = SecurityMetric(
                id=metric_id,
                name=name,
                metric_type=metric_type,
                value=value,
                unit=unit,
                target=target,
                threshold_warning=warn,
                threshold_critical=crit
            )
    
    def _init_default_widgets(self):
        """Initialize default dashboard widgets"""
        widgets = [
            ("risk_gauge", "gauge", "Overall Risk Score", {"x": 0, "y": 0, "w": 2, "h": 2}),
            ("vuln_chart", "chart", "Vulnerabilities by Severity", {"x": 2, "y": 0, "w": 3, "h": 2}),
            ("alerts_list", "list", "Recent Alerts", {"x": 5, "y": 0, "w": 3, "h": 2}),
            ("threat_map", "map", "Threat Map", {"x": 0, "y": 2, "w": 4, "h": 2}),
            ("timeline", "timeline", "Security Timeline", {"x": 4, "y": 2, "w": 4, "h": 2}),
            ("metrics_grid", "grid", "Key Metrics", {"x": 0, "y": 4, "w": 8, "h": 1}),
        ]
        
        for widget_id, widget_type, title, position in widgets:
            self.widgets[widget_id] = DashboardWidget(
                id=widget_id,
                widget_type=widget_type,
                title=title,
                position=position
            )
    
    def add_callback(self, callback: Callable):
        """Add update callback"""
        self._callbacks.append(callback)
    
    def _notify(self, event_type: str, data: Any):
        """Notify callbacks"""
        for callback in self._callbacks:
            try:
                callback(event_type, data)
            except Exception:
                pass
    
    def update_metric(self, metric_id: str, value: float, record_history: bool = True):
        """Update a metric value"""
        if metric_id not in self.metrics:
            return
        
        metric = self.metrics[metric_id]
        old_value = metric.value
        metric.value = value
        metric.last_updated = datetime.now()
        
        # Calculate trend
        if old_value > 0:
            change = ((value - old_value) / old_value) * 100
            metric.change_percent = change
            if change > 5:
                metric.trend = TrendDirection.UP
            elif change < -5:
                metric.trend = TrendDirection.DOWN
            else:
                metric.trend = TrendDirection.STABLE
        
        # Record history
        if record_history:
            metric.history.append({
                "timestamp": datetime.now().isoformat(),
                "value": value
            })
            # Keep last 100 entries
            if len(metric.history) > 100:
                metric.history = metric.history[-100:]
        
        self._notify("metric_updated", {"metric_id": metric_id, "value": value})
    
    def get_metric(self, metric_id: str) -> Optional[SecurityMetric]:
        """Get metric by ID"""
        return self.metrics.get(metric_id)
    
    def get_metrics_by_type(self, metric_type: MetricType) -> List[SecurityMetric]:
        """Get all metrics of a type"""
        return [m for m in self.metrics.values() if m.metric_type == metric_type]
    
    def create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        source: str,
        category: str,
        related_assets: List[str] = None
    ) -> SecurityAlert:
        """Create a new alert"""
        alert = SecurityAlert(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            severity=severity,
            status=AlertStatus.NEW,
            source=source,
            category=category,
            related_assets=related_assets or []
        )
        
        self.alerts[alert.id] = alert
        self._notify("alert_created", {"alert": alert})
        
        # Update incident count
        open_count = len([a for a in self.alerts.values() 
                         if a.status not in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]])
        self.update_metric("open_incidents", open_count)
        
        return alert
    
    def acknowledge_alert(self, alert_id: str, user: str):
        """Acknowledge an alert"""
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = user
            alert.updated_at = datetime.now()
            self._notify("alert_updated", {"alert": alert})
    
    def resolve_alert(self, alert_id: str, resolution: str = ""):
        """Resolve an alert"""
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.now()
            alert.updated_at = datetime.now()
            if resolution:
                alert.remediation = resolution
            self._notify("alert_updated", {"alert": alert})
    
    def dismiss_alert(self, alert_id: str, is_false_positive: bool = False):
        """Dismiss an alert"""
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.status = AlertStatus.DISMISSED
            alert.false_positive = is_false_positive
            alert.updated_at = datetime.now()
            self._notify("alert_updated", {"alert": alert})
    
    def get_alerts(
        self,
        severity: AlertSeverity = None,
        status: AlertStatus = None,
        limit: int = 50
    ) -> List[SecurityAlert]:
        """Get alerts with optional filters"""
        alerts = list(self.alerts.values())
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        if status:
            alerts = [a for a in alerts if a.status == status]
        
        # Sort by created_at desc
        alerts.sort(key=lambda a: a.created_at, reverse=True)
        
        return alerts[:limit]
    
    def add_event(
        self,
        event_type: str,
        title: str,
        description: str,
        severity: AlertSeverity,
        source: str,
        details: Dict = None
    ):
        """Add security event to timeline"""
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            event_type=event_type,
            title=title,
            description=description,
            severity=severity,
            timestamp=datetime.now(),
            source=source,
            details=details or {}
        )
        
        self.events.append(event)
        
        # Keep last 500 events
        if len(self.events) > 500:
            self.events = self.events[-500:]
        
        self._notify("event_added", {"event": event})
    
    def get_events(self, hours: int = 24, event_type: str = None) -> List[SecurityEvent]:
        """Get events from timeline"""
        cutoff = datetime.now() - timedelta(hours=hours)
        events = [e for e in self.events if e.timestamp >= cutoff]
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events
    
    def calculate_risk_score(self) -> RiskScore:
        """Calculate overall risk score"""
        # Component scores (0-10 scale)
        scores = {}
        
        # Vulnerability score
        vuln_crit = self.metrics.get("vuln_critical", SecurityMetric("", "", MetricType.VULNERABILITY, 0)).value
        vuln_high = self.metrics.get("vuln_high", SecurityMetric("", "", MetricType.VULNERABILITY, 0)).value
        vuln_score = min(10, (vuln_crit * 2 + vuln_high * 0.5))
        scores["vulnerabilities"] = vuln_score
        
        # Compliance score
        compliance = self.metrics.get("compliance_score", SecurityMetric("", "", MetricType.COMPLIANCE, 100)).value
        compliance_risk = 10 - (compliance / 10)
        scores["compliance"] = compliance_risk
        
        # Patch score
        patch = self.metrics.get("patch_compliance", SecurityMetric("", "", MetricType.COMPLIANCE, 100)).value
        patch_risk = 10 - (patch / 10)
        scores["patching"] = patch_risk
        
        # Threat score
        threats = self.metrics.get("threats_detected", SecurityMetric("", "", MetricType.THREAT, 0)).value
        threat_score = min(10, threats * 0.5)
        scores["threats"] = threat_score
        
        # Incident score
        incidents = self.metrics.get("open_incidents", SecurityMetric("", "", MetricType.INCIDENT, 0)).value
        incident_score = min(10, incidents)
        scores["incidents"] = incident_score
        
        # Calculate weighted average
        weights = {
            "vulnerabilities": 0.3,
            "compliance": 0.15,
            "patching": 0.2,
            "threats": 0.2,
            "incidents": 0.15
        }
        
        total_score = sum(scores[k] * weights[k] for k in scores)
        
        # Determine grade
        if total_score <= 2:
            grade = "A"
        elif total_score <= 4:
            grade = "B"
        elif total_score <= 6:
            grade = "C"
        elif total_score <= 8:
            grade = "D"
        else:
            grade = "F"
        
        # Generate recommendations
        recommendations = []
        if scores["vulnerabilities"] > 5:
            recommendations.append("Prioritize patching critical and high vulnerabilities")
        if scores["compliance"] > 5:
            recommendations.append("Address compliance gaps to meet regulatory requirements")
        if scores["patching"] > 5:
            recommendations.append("Improve patch management processes")
        if scores["threats"] > 5:
            recommendations.append("Investigate and remediate active threats")
        if scores["incidents"] > 5:
            recommendations.append("Allocate resources to resolve open incidents")
        
        self.risk_score = RiskScore(
            score=round(total_score, 1),
            grade=grade,
            breakdown=scores,
            recommendations=recommendations
        )
        
        # Update metric
        self.update_metric("risk_score", total_score)
        
        return self.risk_score
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get complete dashboard summary"""
        # Calculate risk if not done
        if not self.risk_score:
            self.calculate_risk_score()
        
        return {
            "risk_score": self.risk_score,
            "metrics": {k: {
                "value": v.value,
                "unit": v.unit,
                "trend": v.trend.value,
                "change": v.change_percent
            } for k, v in self.metrics.items()},
            "alert_counts": {
                "critical": len([a for a in self.alerts.values() if a.severity == AlertSeverity.CRITICAL and a.status not in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]]),
                "high": len([a for a in self.alerts.values() if a.severity == AlertSeverity.HIGH and a.status not in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]]),
                "medium": len([a for a in self.alerts.values() if a.severity == AlertSeverity.MEDIUM and a.status not in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]]),
                "low": len([a for a in self.alerts.values() if a.severity == AlertSeverity.LOW and a.status not in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]])
            },
            "recent_events": len(self.get_events(hours=24)),
            "widgets": list(self.widgets.values())
        }
    
    def get_trend_data(self, metric_id: str, days: int = 7) -> List[Dict]:
        """Get historical trend data for a metric"""
        metric = self.metrics.get(metric_id)
        if not metric or not metric.history:
            return []
        
        cutoff = datetime.now() - timedelta(days=days)
        return [
            h for h in metric.history
            if datetime.fromisoformat(h["timestamp"]) >= cutoff
        ]
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate security dashboard report"""
        summary = self.get_dashboard_summary()
        
        return {
            "generated_at": datetime.now().isoformat(),
            "risk_assessment": {
                "score": self.risk_score.score if self.risk_score else 0,
                "grade": self.risk_score.grade if self.risk_score else "N/A",
                "breakdown": self.risk_score.breakdown if self.risk_score else {},
                "recommendations": self.risk_score.recommendations if self.risk_score else []
            },
            "metrics_summary": summary["metrics"],
            "alert_summary": summary["alert_counts"],
            "recent_alerts": [
                {
                    "title": a.title,
                    "severity": a.severity.value,
                    "status": a.status.value,
                    "created": a.created_at.isoformat()
                }
                for a in self.get_alerts(limit=10)
            ],
            "recent_events": [
                {
                    "type": e.event_type,
                    "title": e.title,
                    "severity": e.severity.value,
                    "timestamp": e.timestamp.isoformat()
                }
                for e in self.get_events(hours=24)[:20]
            ]
        }
    
    async def start_monitoring(self, interval: int = 30):
        """Start real-time monitoring"""
        self._running = True
        
        while self._running:
            try:
                # Simulate metric updates (in real app, would pull from data sources)
                await self._update_from_sources()
                self.calculate_risk_score()
                self._notify("dashboard_updated", self.get_dashboard_summary())
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
            
            await asyncio.sleep(interval)
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self._running = False
    
    async def _update_from_sources(self):
        """Update metrics from various data sources"""
        # In a real implementation, this would query databases, APIs, etc.
        # For now, we'll simulate some changes
        
        # Simulate small random changes
        for metric_id in ["vuln_critical", "vuln_high", "threats_detected"]:
            metric = self.metrics.get(metric_id)
            if metric:
                change = random.randint(-1, 2)
                new_value = max(0, metric.value + change)
                self.update_metric(metric_id, new_value)
    
    def import_from_scanners(self, scan_results: Dict[str, Any]):
        """Import metrics from scanner results"""
        # Vulnerability counts
        if "vulnerabilities" in scan_results:
            vulns = scan_results["vulnerabilities"]
            self.update_metric("vuln_critical", vulns.get("critical", 0))
            self.update_metric("vuln_high", vulns.get("high", 0))
            self.update_metric("vuln_medium", vulns.get("medium", 0))
            self.update_metric("vuln_low", vulns.get("low", 0))
        
        # Asset counts
        if "assets" in scan_results:
            assets = scan_results["assets"]
            self.update_metric("total_assets", assets.get("total", 0))
            self.update_metric("active_assets", assets.get("active", 0))
        
        # Recalculate risk
        self.calculate_risk_score()
    
    def export_metrics(self, format: str = "json") -> str:
        """Export metrics data"""
        data = {
            "exported_at": datetime.now().isoformat(),
            "metrics": [
                {
                    "id": m.id,
                    "name": m.name,
                    "type": m.metric_type.value,
                    "value": m.value,
                    "unit": m.unit,
                    "trend": m.trend.value,
                    "change_percent": m.change_percent,
                    "history_count": len(m.history)
                }
                for m in self.metrics.values()
            ],
            "risk_score": {
                "score": self.risk_score.score,
                "grade": self.risk_score.grade
            } if self.risk_score else None
        }
        
        return json.dumps(data, indent=2)
