#!/usr/bin/env python3
"""
HydraRecon Audit Log Management Module
Enterprise security event logging, correlation, and forensic analysis.
"""

import asyncio
import json
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from enum import Enum
import uuid
import re


class LogLevel(Enum):
    """Log severity levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventCategory(Enum):
    """Event categories"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ACCESS = "access"
    CHANGE = "change"
    SECURITY = "security"
    SYSTEM = "system"
    NETWORK = "network"
    DATA = "data"
    APPLICATION = "application"
    COMPLIANCE = "compliance"


class EventOutcome(Enum):
    """Event outcomes"""
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Represents an audit log event"""
    id: str
    timestamp: datetime
    event_type: str
    category: EventCategory
    level: LogLevel
    outcome: EventOutcome
    source_ip: Optional[str]
    source_host: Optional[str]
    destination_ip: Optional[str]
    destination_host: Optional[str]
    user: Optional[str]
    user_domain: Optional[str]
    action: str
    target: Optional[str]
    target_type: Optional[str]
    description: str
    raw_log: Optional[str]
    log_source: str
    tags: List[str]
    correlation_id: Optional[str]
    session_id: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LogSource:
    """Log source configuration"""
    id: str
    name: str
    source_type: str  # syslog, windows_event, cloud, application, etc.
    host: str
    port: Optional[int]
    protocol: str  # tcp, udp, https, etc.
    format: str  # json, syslog, cef, leef, etc.
    enabled: bool
    parser_config: Dict[str, Any]
    filter_rules: List[Dict[str, Any]]
    last_event: Optional[datetime]
    events_count: int
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelationRule:
    """Event correlation rule"""
    id: str
    name: str
    description: str
    enabled: bool
    conditions: List[Dict[str, Any]]
    time_window: int  # seconds
    threshold: int  # number of events to trigger
    severity: AlertSeverity
    alert_title: str
    alert_description: str
    response_actions: List[str]
    tags: List[str]
    created_at: datetime = field(default_factory=datetime.now)
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityAlert:
    """Security alert from correlation"""
    id: str
    rule_id: str
    rule_name: str
    severity: AlertSeverity
    title: str
    description: str
    events: List[str]  # Event IDs
    first_seen: datetime
    last_seen: datetime
    event_count: int
    status: str  # new, investigating, resolved, false_positive
    assigned_to: Optional[str]
    resolution_notes: Optional[str]
    resolved_at: Optional[datetime]
    tags: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RetentionPolicy:
    """Log retention policy"""
    id: str
    name: str
    description: str
    log_sources: List[str]
    event_categories: List[EventCategory]
    retention_days: int
    archive_enabled: bool
    archive_location: Optional[str]
    compression_enabled: bool
    encryption_enabled: bool
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditReport:
    """Audit report"""
    id: str
    name: str
    description: str
    report_type: str  # activity, security, compliance, forensic
    time_range_start: datetime
    time_range_end: datetime
    filters: Dict[str, Any]
    generated_at: datetime
    generated_by: str
    event_count: int
    summary: Dict[str, Any]
    data: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)


class AuditLogEngine:
    """Enterprise audit log management engine"""
    
    def __init__(self, demo_mode: bool = False):
        """
        Initialize the audit log engine.
        
        Args:
            demo_mode: If True, generates sample data for demonstration.
                      If False (default), starts with empty log store for real data ingestion.
        """
        self.events: Dict[str, AuditEvent] = {}
        self.log_sources: Dict[str, LogSource] = {}
        self.correlation_rules: Dict[str, CorrelationRule] = {}
        self.alerts: Dict[str, SecurityAlert] = {}
        self.retention_policies: Dict[str, RetentionPolicy] = {}
        self.reports: Dict[str, AuditReport] = {}
        self.callbacks: List[callable] = []
        self.demo_mode = demo_mode
        
        self._init_log_sources()
        self._init_correlation_rules()
        
        # Only generate sample data in demo mode
        if demo_mode:
            self._generate_sample_events()
    
    def _init_log_sources(self):
        """Initialize sample log sources"""
        sources = [
            {
                "name": "Domain Controllers",
                "source_type": "windows_event",
                "host": "dc01.corp.local",
                "protocol": "wef",
                "format": "windows_xml"
            },
            {
                "name": "Linux Servers",
                "source_type": "syslog",
                "host": "syslog.corp.local",
                "port": 514,
                "protocol": "udp",
                "format": "syslog"
            },
            {
                "name": "Firewall Logs",
                "source_type": "syslog",
                "host": "fw01.corp.local",
                "port": 514,
                "protocol": "tcp",
                "format": "cef"
            },
            {
                "name": "AWS CloudTrail",
                "source_type": "cloud",
                "host": "s3://audit-logs/cloudtrail",
                "protocol": "https",
                "format": "json"
            },
            {
                "name": "Azure AD",
                "source_type": "cloud",
                "host": "graph.microsoft.com",
                "protocol": "https",
                "format": "json"
            },
            {
                "name": "Web Application",
                "source_type": "application",
                "host": "webapp01.corp.local",
                "port": 8080,
                "protocol": "https",
                "format": "json"
            }
        ]
        
        for source_data in sources:
            source = LogSource(
                id=str(uuid.uuid4()),
                name=source_data["name"],
                source_type=source_data["source_type"],
                host=source_data["host"],
                port=source_data.get("port"),
                protocol=source_data["protocol"],
                format=source_data["format"],
                enabled=True,
                parser_config={},
                filter_rules=[],
                last_event=datetime.now() - timedelta(minutes=5),
                events_count=0
            )
            self.log_sources[source.id] = source
    
    def _init_correlation_rules(self):
        """Initialize correlation rules"""
        rules = [
            {
                "name": "Brute Force Detection",
                "description": "Detects multiple failed login attempts from same source",
                "conditions": [
                    {"field": "event_type", "operator": "equals", "value": "login_failed"},
                    {"field": "outcome", "operator": "equals", "value": "failure"}
                ],
                "time_window": 300,  # 5 minutes
                "threshold": 5,
                "severity": AlertSeverity.HIGH,
                "alert_title": "Potential Brute Force Attack",
                "alert_description": "Multiple failed login attempts detected from {source_ip}"
            },
            {
                "name": "Privilege Escalation",
                "description": "Detects unauthorized privilege changes",
                "conditions": [
                    {"field": "event_type", "operator": "equals", "value": "privilege_change"},
                    {"field": "category", "operator": "equals", "value": "authorization"}
                ],
                "time_window": 60,
                "threshold": 1,
                "severity": AlertSeverity.CRITICAL,
                "alert_title": "Privilege Escalation Detected",
                "alert_description": "User {user} performed privilege escalation on {target}"
            },
            {
                "name": "Lateral Movement",
                "description": "Detects potential lateral movement activity",
                "conditions": [
                    {"field": "event_type", "operator": "in", "value": ["remote_login", "service_access"]},
                    {"field": "category", "operator": "equals", "value": "access"}
                ],
                "time_window": 600,
                "threshold": 3,
                "severity": AlertSeverity.HIGH,
                "alert_title": "Potential Lateral Movement",
                "alert_description": "User {user} accessing multiple systems from {source_ip}"
            },
            {
                "name": "Data Exfiltration",
                "description": "Detects large data transfers",
                "conditions": [
                    {"field": "event_type", "operator": "equals", "value": "data_transfer"},
                    {"field": "metadata.bytes", "operator": "greater_than", "value": 10485760}
                ],
                "time_window": 3600,
                "threshold": 1,
                "severity": AlertSeverity.CRITICAL,
                "alert_title": "Potential Data Exfiltration",
                "alert_description": "Large data transfer detected from {source_host}"
            },
            {
                "name": "After Hours Access",
                "description": "Detects access outside business hours",
                "conditions": [
                    {"field": "event_type", "operator": "equals", "value": "login_success"},
                    {"field": "metadata.hour", "operator": "not_between", "value": [8, 18]}
                ],
                "time_window": 0,
                "threshold": 1,
                "severity": AlertSeverity.MEDIUM,
                "alert_title": "After Hours Access",
                "alert_description": "User {user} logged in at {timestamp}"
            },
            {
                "name": "Account Lockout",
                "description": "Detects account lockouts",
                "conditions": [
                    {"field": "event_type", "operator": "equals", "value": "account_locked"}
                ],
                "time_window": 0,
                "threshold": 1,
                "severity": AlertSeverity.MEDIUM,
                "alert_title": "Account Locked Out",
                "alert_description": "Account {user} has been locked out"
            },
            {
                "name": "Sensitive File Access",
                "description": "Detects access to sensitive files",
                "conditions": [
                    {"field": "event_type", "operator": "equals", "value": "file_access"},
                    {"field": "metadata.sensitivity", "operator": "in", "value": ["confidential", "restricted"]}
                ],
                "time_window": 0,
                "threshold": 1,
                "severity": AlertSeverity.HIGH,
                "alert_title": "Sensitive File Accessed",
                "alert_description": "User {user} accessed {target}"
            },
            {
                "name": "Configuration Change",
                "description": "Detects security configuration changes",
                "conditions": [
                    {"field": "event_type", "operator": "equals", "value": "config_change"},
                    {"field": "category", "operator": "equals", "value": "security"}
                ],
                "time_window": 0,
                "threshold": 1,
                "severity": AlertSeverity.MEDIUM,
                "alert_title": "Security Configuration Changed",
                "alert_description": "Security configuration changed by {user}"
            }
        ]
        
        for rule_data in rules:
            rule = CorrelationRule(
                id=str(uuid.uuid4()),
                name=rule_data["name"],
                description=rule_data["description"],
                enabled=True,
                conditions=rule_data["conditions"],
                time_window=rule_data["time_window"],
                threshold=rule_data["threshold"],
                severity=rule_data["severity"],
                alert_title=rule_data["alert_title"],
                alert_description=rule_data["alert_description"],
                response_actions=["create_ticket", "notify_soc"],
                tags=["security", "detection"]
            )
            self.correlation_rules[rule.id] = rule
    
    def _generate_sample_events(self):
        """Generate sample audit events"""
        import random
        
        event_templates = [
            {
                "event_type": "login_success",
                "category": EventCategory.AUTHENTICATION,
                "level": LogLevel.INFO,
                "outcome": EventOutcome.SUCCESS,
                "action": "User Login",
                "description": "User successfully logged in"
            },
            {
                "event_type": "login_failed",
                "category": EventCategory.AUTHENTICATION,
                "level": LogLevel.WARNING,
                "outcome": EventOutcome.FAILURE,
                "action": "User Login Failed",
                "description": "Failed login attempt"
            },
            {
                "event_type": "file_access",
                "category": EventCategory.ACCESS,
                "level": LogLevel.INFO,
                "outcome": EventOutcome.SUCCESS,
                "action": "File Access",
                "description": "User accessed file"
            },
            {
                "event_type": "privilege_change",
                "category": EventCategory.AUTHORIZATION,
                "level": LogLevel.WARNING,
                "outcome": EventOutcome.SUCCESS,
                "action": "Privilege Change",
                "description": "User privileges modified"
            },
            {
                "event_type": "config_change",
                "category": EventCategory.CHANGE,
                "level": LogLevel.INFO,
                "outcome": EventOutcome.SUCCESS,
                "action": "Configuration Change",
                "description": "System configuration modified"
            },
            {
                "event_type": "firewall_block",
                "category": EventCategory.NETWORK,
                "level": LogLevel.WARNING,
                "outcome": EventOutcome.SUCCESS,
                "action": "Connection Blocked",
                "description": "Firewall blocked connection"
            },
            {
                "event_type": "service_start",
                "category": EventCategory.SYSTEM,
                "level": LogLevel.INFO,
                "outcome": EventOutcome.SUCCESS,
                "action": "Service Started",
                "description": "System service started"
            },
            {
                "event_type": "account_locked",
                "category": EventCategory.SECURITY,
                "level": LogLevel.WARNING,
                "outcome": EventOutcome.FAILURE,
                "action": "Account Lockout",
                "description": "Account locked due to failed attempts"
            }
        ]
        
        users = ["admin", "jsmith", "mwilson", "agarcia", "blee", "cjohnson", "service_account"]
        hosts = ["dc01", "web01", "db01", "app01", "workstation01", "workstation02"]
        ips = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.100", "203.0.113.50"]
        
        # Generate 500 sample events
        for i in range(500):
            template = random.choice(event_templates)
            timestamp = datetime.now() - timedelta(hours=random.randint(0, 168))  # Last week
            
            event = AuditEvent(
                id=str(uuid.uuid4()),
                timestamp=timestamp,
                event_type=template["event_type"],
                category=template["category"],
                level=template["level"],
                outcome=template["outcome"],
                source_ip=random.choice(ips),
                source_host=random.choice(hosts),
                destination_ip=random.choice(ips) if random.random() > 0.3 else None,
                destination_host=random.choice(hosts) if random.random() > 0.3 else None,
                user=random.choice(users),
                user_domain="CORP",
                action=template["action"],
                target=f"/path/to/resource_{random.randint(1, 100)}" if "file" in template["event_type"] else None,
                target_type="file" if "file" in template["event_type"] else "system",
                description=template["description"],
                raw_log=None,
                log_source=random.choice(list(self.log_sources.keys())),
                tags=[template["category"].value],
                correlation_id=None,
                session_id=f"session_{random.randint(1000, 9999)}"
            )
            self.events[event.id] = event
        
        # Update log source counts
        for source_id in self.log_sources:
            self.log_sources[source_id].events_count = sum(
                1 for e in self.events.values() if e.log_source == source_id
            )
        
        # Generate some alerts
        self._generate_sample_alerts()
    
    def _generate_sample_alerts(self):
        """Generate sample security alerts"""
        import random
        
        alert_templates = [
            {
                "severity": AlertSeverity.CRITICAL,
                "title": "Potential Brute Force Attack",
                "description": "Multiple failed login attempts detected from 203.0.113.50"
            },
            {
                "severity": AlertSeverity.HIGH,
                "title": "Lateral Movement Detected",
                "description": "User admin accessing multiple systems in short timeframe"
            },
            {
                "severity": AlertSeverity.MEDIUM,
                "title": "After Hours Access",
                "description": "User jsmith logged in at 02:30 AM"
            },
            {
                "severity": AlertSeverity.HIGH,
                "title": "Sensitive File Accessed",
                "description": "Confidential file accessed by unauthorized user"
            }
        ]
        
        rules = list(self.correlation_rules.values())
        
        for template in alert_templates:
            rule = random.choice(rules)
            event_ids = random.sample(list(self.events.keys()), min(5, len(self.events)))
            
            alert = SecurityAlert(
                id=str(uuid.uuid4()),
                rule_id=rule.id,
                rule_name=rule.name,
                severity=template["severity"],
                title=template["title"],
                description=template["description"],
                events=event_ids,
                first_seen=datetime.now() - timedelta(hours=random.randint(1, 24)),
                last_seen=datetime.now() - timedelta(minutes=random.randint(5, 120)),
                event_count=len(event_ids),
                status=random.choice(["new", "investigating", "resolved"]),
                assigned_to="soc_analyst" if random.random() > 0.5 else None,
                resolution_notes=None,
                resolved_at=None,
                tags=["detection", "investigation"]
            )
            self.alerts[alert.id] = alert
    
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
    
    def ingest_event(self, event_data: Dict[str, Any]) -> AuditEvent:
        """Ingest a new audit event"""
        event = AuditEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            event_type=event_data.get("event_type", "unknown"),
            category=EventCategory(event_data.get("category", "system")),
            level=LogLevel(event_data.get("level", "info")),
            outcome=EventOutcome(event_data.get("outcome", "unknown")),
            source_ip=event_data.get("source_ip"),
            source_host=event_data.get("source_host"),
            destination_ip=event_data.get("destination_ip"),
            destination_host=event_data.get("destination_host"),
            user=event_data.get("user"),
            user_domain=event_data.get("user_domain"),
            action=event_data.get("action", ""),
            target=event_data.get("target"),
            target_type=event_data.get("target_type"),
            description=event_data.get("description", ""),
            raw_log=event_data.get("raw_log"),
            log_source=event_data.get("log_source", ""),
            tags=event_data.get("tags", []),
            correlation_id=event_data.get("correlation_id"),
            session_id=event_data.get("session_id"),
            metadata=event_data.get("metadata", {})
        )
        
        self.events[event.id] = event
        
        # Check correlation rules
        self._check_correlations(event)
        
        self._emit_event("event_ingested", {"event_id": event.id})
        
        return event
    
    def _check_correlations(self, event: AuditEvent):
        """Check event against correlation rules"""
        for rule in self.correlation_rules.values():
            if not rule.enabled:
                continue
            
            # Check if event matches conditions
            if self._event_matches_rule(event, rule):
                # Get related events within time window
                related = self._get_related_events(event, rule)
                
                if len(related) >= rule.threshold:
                    self._create_alert(rule, related)
    
    def _event_matches_rule(self, event: AuditEvent, rule: CorrelationRule) -> bool:
        """Check if event matches rule conditions"""
        for condition in rule.conditions:
            field = condition["field"]
            operator = condition["operator"]
            value = condition["value"]
            
            # Get field value from event
            event_value = None
            if hasattr(event, field):
                event_value = getattr(event, field)
                if hasattr(event_value, "value"):
                    event_value = event_value.value
            elif field.startswith("metadata."):
                meta_field = field.split(".", 1)[1]
                event_value = event.metadata.get(meta_field)
            
            # Check condition
            if operator == "equals" and event_value != value:
                return False
            elif operator == "in" and event_value not in value:
                return False
            elif operator == "greater_than" and event_value <= value:
                return False
        
        return True
    
    def _get_related_events(
        self,
        event: AuditEvent,
        rule: CorrelationRule
    ) -> List[AuditEvent]:
        """Get events related to the triggering event"""
        time_window = timedelta(seconds=rule.time_window)
        start_time = event.timestamp - time_window
        
        related = []
        for e in self.events.values():
            if e.timestamp >= start_time and e.timestamp <= event.timestamp:
                if self._event_matches_rule(e, rule):
                    related.append(e)
        
        return related
    
    def _create_alert(self, rule: CorrelationRule, events: List[AuditEvent]):
        """Create security alert from correlation"""
        alert = SecurityAlert(
            id=str(uuid.uuid4()),
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            title=rule.alert_title,
            description=rule.alert_description,
            events=[e.id for e in events],
            first_seen=min(e.timestamp for e in events),
            last_seen=max(e.timestamp for e in events),
            event_count=len(events),
            status="new",
            assigned_to=None,
            resolution_notes=None,
            resolved_at=None,
            tags=rule.tags
        )
        
        self.alerts[alert.id] = alert
        rule.last_triggered = datetime.now()
        rule.trigger_count += 1
        
        self._emit_event("alert_created", {
            "alert_id": alert.id,
            "severity": alert.severity.value,
            "title": alert.title
        })
    
    def search_events(
        self,
        query: str = None,
        category: EventCategory = None,
        level: LogLevel = None,
        user: str = None,
        source_ip: str = None,
        start_time: datetime = None,
        end_time: datetime = None,
        limit: int = 100
    ) -> List[AuditEvent]:
        """Search audit events"""
        results = list(self.events.values())
        
        if query:
            query_lower = query.lower()
            results = [
                e for e in results
                if query_lower in e.description.lower() or
                query_lower in e.action.lower() or
                query_lower in e.event_type.lower() or
                (e.user and query_lower in e.user.lower())
            ]
        
        if category:
            results = [e for e in results if e.category == category]
        
        if level:
            results = [e for e in results if e.level == level]
        
        if user:
            results = [e for e in results if e.user and user.lower() in e.user.lower()]
        
        if source_ip:
            results = [e for e in results if e.source_ip == source_ip]
        
        if start_time:
            results = [e for e in results if e.timestamp >= start_time]
        
        if end_time:
            results = [e for e in results if e.timestamp <= end_time]
        
        # Sort by timestamp descending
        results.sort(key=lambda e: e.timestamp, reverse=True)
        
        return results[:limit]
    
    def get_event_timeline(
        self,
        correlation_id: str = None,
        session_id: str = None,
        user: str = None
    ) -> List[AuditEvent]:
        """Get timeline of related events"""
        events = list(self.events.values())
        
        if correlation_id:
            events = [e for e in events if e.correlation_id == correlation_id]
        elif session_id:
            events = [e for e in events if e.session_id == session_id]
        elif user:
            events = [e for e in events if e.user == user]
        else:
            return []
        
        return sorted(events, key=lambda e: e.timestamp)
    
    def get_statistics(
        self,
        time_range: str = "24h"
    ) -> Dict[str, Any]:
        """Get event statistics"""
        # Parse time range
        if time_range == "1h":
            start = datetime.now() - timedelta(hours=1)
        elif time_range == "24h":
            start = datetime.now() - timedelta(hours=24)
        elif time_range == "7d":
            start = datetime.now() - timedelta(days=7)
        elif time_range == "30d":
            start = datetime.now() - timedelta(days=30)
        else:
            start = datetime.now() - timedelta(hours=24)
        
        events = [e for e in self.events.values() if e.timestamp >= start]
        
        # Category breakdown
        by_category = {}
        for cat in EventCategory:
            by_category[cat.value] = sum(1 for e in events if e.category == cat)
        
        # Level breakdown
        by_level = {}
        for level in LogLevel:
            by_level[level.value] = sum(1 for e in events if e.level == level)
        
        # Outcome breakdown
        by_outcome = {}
        for outcome in EventOutcome:
            by_outcome[outcome.value] = sum(1 for e in events if e.outcome == outcome)
        
        # Top users
        user_counts = {}
        for e in events:
            if e.user:
                user_counts[e.user] = user_counts.get(e.user, 0) + 1
        top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Top source IPs
        ip_counts = {}
        for e in events:
            if e.source_ip:
                ip_counts[e.source_ip] = ip_counts.get(e.source_ip, 0) + 1
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Events per hour
        hourly = {}
        for e in events:
            hour = e.timestamp.strftime("%Y-%m-%d %H:00")
            hourly[hour] = hourly.get(hour, 0) + 1
        
        return {
            "time_range": time_range,
            "total_events": len(events),
            "by_category": by_category,
            "by_level": by_level,
            "by_outcome": by_outcome,
            "top_users": top_users,
            "top_source_ips": top_ips,
            "hourly_distribution": hourly,
            "active_alerts": len([a for a in self.alerts.values() if a.status == "new"]),
            "log_sources": len(self.log_sources)
        }
    
    def get_user_activity(self, user: str) -> Dict[str, Any]:
        """Get activity summary for a user"""
        events = [e for e in self.events.values() if e.user == user]
        
        if not events:
            return {"user": user, "events": 0}
        
        return {
            "user": user,
            "total_events": len(events),
            "first_activity": min(e.timestamp for e in events).isoformat(),
            "last_activity": max(e.timestamp for e in events).isoformat(),
            "login_success": sum(1 for e in events if e.event_type == "login_success"),
            "login_failed": sum(1 for e in events if e.event_type == "login_failed"),
            "file_access": sum(1 for e in events if e.event_type == "file_access"),
            "unique_sources": len(set(e.source_ip for e in events if e.source_ip)),
            "unique_hosts": len(set(e.source_host for e in events if e.source_host))
        }
    
    def update_alert_status(
        self,
        alert_id: str,
        status: str,
        assigned_to: str = None,
        resolution_notes: str = None
    ) -> SecurityAlert:
        """Update alert status"""
        if alert_id not in self.alerts:
            raise ValueError(f"Alert not found: {alert_id}")
        
        alert = self.alerts[alert_id]
        alert.status = status
        
        if assigned_to:
            alert.assigned_to = assigned_to
        
        if resolution_notes:
            alert.resolution_notes = resolution_notes
        
        if status == "resolved":
            alert.resolved_at = datetime.now()
        
        self._emit_event("alert_updated", {
            "alert_id": alert_id,
            "status": status
        })
        
        return alert
    
    def generate_report(
        self,
        report_type: str,
        start_time: datetime,
        end_time: datetime,
        filters: Dict[str, Any] = None
    ) -> AuditReport:
        """Generate audit report"""
        events = self.search_events(
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )
        
        if filters:
            if "category" in filters:
                events = [e for e in events if e.category.value == filters["category"]]
            if "user" in filters:
                events = [e for e in events if e.user == filters["user"]]
        
        # Generate summary
        summary = {
            "total_events": len(events),
            "unique_users": len(set(e.user for e in events if e.user)),
            "unique_sources": len(set(e.source_ip for e in events if e.source_ip)),
            "failed_attempts": sum(1 for e in events if e.outcome == EventOutcome.FAILURE),
            "security_events": sum(1 for e in events if e.category == EventCategory.SECURITY)
        }
        
        # Prepare data
        data = [
            {
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "user": e.user,
                "source_ip": e.source_ip,
                "action": e.action,
                "outcome": e.outcome.value
            }
            for e in events[:1000]
        ]
        
        report = AuditReport(
            id=str(uuid.uuid4()),
            name=f"{report_type.title()} Report",
            description=f"Audit report from {start_time} to {end_time}",
            report_type=report_type,
            time_range_start=start_time,
            time_range_end=end_time,
            filters=filters or {},
            generated_at=datetime.now(),
            generated_by="system",
            event_count=len(events),
            summary=summary,
            data=data
        )
        
        self.reports[report.id] = report
        return report
    
    def export_events(
        self,
        format: str = "json",
        start_time: datetime = None,
        end_time: datetime = None
    ) -> str:
        """Export events in specified format"""
        events = self.search_events(
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )
        
        if format == "json":
            return json.dumps([
                {
                    "timestamp": e.timestamp.isoformat(),
                    "event_type": e.event_type,
                    "category": e.category.value,
                    "level": e.level.value,
                    "outcome": e.outcome.value,
                    "user": e.user,
                    "source_ip": e.source_ip,
                    "action": e.action,
                    "description": e.description
                }
                for e in events
            ], indent=2)
        elif format == "csv":
            lines = ["timestamp,event_type,category,level,user,source_ip,action"]
            for e in events:
                lines.append(
                    f"{e.timestamp.isoformat()},{e.event_type},{e.category.value},"
                    f"{e.level.value},{e.user or ''},{e.source_ip or ''},{e.action}"
                )
            return "\n".join(lines)
        else:
            return json.dumps({"error": "Unsupported format"})
