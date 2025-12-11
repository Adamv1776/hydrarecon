#!/usr/bin/env python3
"""
HydraRecon Vulnerability Remediation Tracking Engine
Enterprise-grade remediation workflow and tracking system.
"""

import asyncio
import json
import hashlib
import sqlite3
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum
from pathlib import Path


class RemediationStatus(Enum):
    """Remediation status states"""
    IDENTIFIED = "identified"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    PENDING_VERIFICATION = "pending_verification"
    VERIFIED = "verified"
    CLOSED = "closed"
    REOPENED = "reopened"
    DEFERRED = "deferred"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


class RemediationPriority(Enum):
    """Remediation priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class RemediationType(Enum):
    """Types of remediation"""
    PATCH = "patch"
    CONFIGURATION = "configuration"
    CODE_FIX = "code_fix"
    NETWORK_CHANGE = "network_change"
    POLICY_UPDATE = "policy_update"
    COMPENSATING_CONTROL = "compensating_control"
    VENDOR_FIX = "vendor_fix"
    ARCHITECTURE_CHANGE = "architecture_change"
    DECOMMISSION = "decommission"
    MONITOR = "monitor"


class VerificationMethod(Enum):
    """Verification methods"""
    RESCAN = "rescan"
    MANUAL_TEST = "manual_test"
    AUTOMATED_TEST = "automated_test"
    PEER_REVIEW = "peer_review"
    VENDOR_CONFIRMATION = "vendor_confirmation"
    LOG_ANALYSIS = "log_analysis"


@dataclass
class RemediationTask:
    """Remediation task data"""
    id: str
    vulnerability_id: str
    vulnerability_name: str
    asset_id: str
    asset_name: str
    severity: str
    priority: RemediationPriority
    status: RemediationStatus
    remediation_type: RemediationType
    description: str
    remediation_steps: List[str]
    assigned_to: str
    assigned_by: str
    assigned_date: datetime
    due_date: datetime
    sla_hours: int
    estimated_effort: str
    actual_effort: Optional[str] = None
    start_date: Optional[datetime] = None
    completion_date: Optional[datetime] = None
    verification_method: Optional[VerificationMethod] = None
    verified_by: Optional[str] = None
    verification_date: Optional[datetime] = None
    verification_notes: Optional[str] = None
    notes: List[Dict[str, Any]] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    related_tasks: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    business_impact: str = ""
    technical_details: str = ""
    rollback_plan: str = ""
    change_ticket: str = ""


@dataclass
class RemediationWorkflow:
    """Workflow configuration"""
    id: str
    name: str
    description: str
    stages: List[Dict[str, Any]]
    auto_assign_rules: List[Dict[str, Any]]
    escalation_rules: List[Dict[str, Any]]
    sla_rules: Dict[str, int]
    notification_rules: List[Dict[str, Any]]
    approval_required: bool = False
    approval_stages: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class SLAMetric:
    """SLA tracking metric"""
    priority: RemediationPriority
    sla_hours: int
    warning_threshold_percent: int
    total_tasks: int
    on_time_tasks: int
    breached_tasks: int
    average_resolution_hours: float
    compliance_percent: float


@dataclass
class RemediationReport:
    """Remediation report data"""
    id: str
    name: str
    generated_date: datetime
    period_start: datetime
    period_end: datetime
    total_vulnerabilities: int
    remediated_count: int
    pending_count: int
    overdue_count: int
    by_priority: Dict[str, int]
    by_status: Dict[str, int]
    by_type: Dict[str, int]
    sla_metrics: List[SLAMetric]
    top_owners: List[Dict[str, Any]]
    aging_analysis: Dict[str, int]
    trend_data: List[Dict[str, Any]]


class RemediationTrackingEngine:
    """Enterprise vulnerability remediation tracking"""
    
    def __init__(self, db_path: str = "remediation.db"):
        self.db_path = db_path
        self.tasks: Dict[str, RemediationTask] = {}
        self.workflows: Dict[str, RemediationWorkflow] = {}
        self.callbacks: Dict[str, List[Callable]] = {}
        self._init_database()
        self._init_default_workflow()
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS remediation_tasks (
                id TEXT PRIMARY KEY,
                vulnerability_id TEXT,
                vulnerability_name TEXT,
                asset_id TEXT,
                asset_name TEXT,
                severity TEXT,
                priority TEXT,
                status TEXT,
                remediation_type TEXT,
                description TEXT,
                remediation_steps TEXT,
                assigned_to TEXT,
                assigned_by TEXT,
                assigned_date TEXT,
                due_date TEXT,
                sla_hours INTEGER,
                estimated_effort TEXT,
                actual_effort TEXT,
                start_date TEXT,
                completion_date TEXT,
                verification_method TEXT,
                verified_by TEXT,
                verification_date TEXT,
                verification_notes TEXT,
                notes TEXT,
                attachments TEXT,
                related_tasks TEXT,
                cvss_score REAL,
                cve_ids TEXT,
                tags TEXT,
                compliance_frameworks TEXT,
                business_impact TEXT,
                technical_details TEXT,
                rollback_plan TEXT,
                change_ticket TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS task_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT,
                action TEXT,
                old_value TEXT,
                new_value TEXT,
                changed_by TEXT,
                changed_at TEXT,
                notes TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS workflows (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                config TEXT,
                enabled INTEGER,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _init_default_workflow(self):
        """Initialize default remediation workflow"""
        default_workflow = RemediationWorkflow(
            id="default",
            name="Standard Remediation Workflow",
            description="Default vulnerability remediation workflow",
            stages=[
                {"name": "identified", "next": ["assigned", "false_positive", "risk_accepted"]},
                {"name": "assigned", "next": ["in_progress", "deferred"]},
                {"name": "in_progress", "next": ["pending_verification"]},
                {"name": "pending_verification", "next": ["verified", "reopened"]},
                {"name": "verified", "next": ["closed"]},
                {"name": "closed", "next": ["reopened"]},
                {"name": "reopened", "next": ["in_progress"]},
                {"name": "deferred", "next": ["assigned"]},
                {"name": "risk_accepted", "next": ["assigned"]},
                {"name": "false_positive", "next": []}
            ],
            auto_assign_rules=[
                {"condition": {"severity": "critical"}, "assign_to": "security_lead"},
                {"condition": {"asset_type": "database"}, "assign_to": "dba_team"},
                {"condition": {"asset_type": "network"}, "assign_to": "network_team"}
            ],
            escalation_rules=[
                {"condition": "sla_warning", "notify": ["manager"], "threshold_percent": 75},
                {"condition": "sla_breach", "notify": ["manager", "director"], "threshold_percent": 100}
            ],
            sla_rules={
                "critical": 24,
                "high": 72,
                "medium": 168,
                "low": 720,
                "informational": 2160
            },
            notification_rules=[
                {"event": "assigned", "notify": ["assignee"]},
                {"event": "status_change", "notify": ["assignee", "reporter"]},
                {"event": "comment_added", "notify": ["assignee"]},
                {"event": "due_soon", "notify": ["assignee"], "hours_before": 24}
            ]
        )
        self.workflows["default"] = default_workflow
    
    async def create_task(
        self,
        vulnerability_id: str,
        vulnerability_name: str,
        asset_id: str,
        asset_name: str,
        severity: str,
        description: str,
        remediation_steps: List[str],
        assigned_to: str = "",
        assigned_by: str = "system",
        cvss_score: Optional[float] = None,
        cve_ids: Optional[List[str]] = None,
        compliance_frameworks: Optional[List[str]] = None
    ) -> RemediationTask:
        """Create a new remediation task"""
        task_id = hashlib.sha256(
            f"{vulnerability_id}:{asset_id}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Determine priority from severity
        priority_map = {
            "critical": RemediationPriority.CRITICAL,
            "high": RemediationPriority.HIGH,
            "medium": RemediationPriority.MEDIUM,
            "low": RemediationPriority.LOW,
            "info": RemediationPriority.INFORMATIONAL
        }
        priority = priority_map.get(severity.lower(), RemediationPriority.MEDIUM)
        
        # Get SLA from workflow
        workflow = self.workflows.get("default")
        sla_hours = workflow.sla_rules.get(priority.value, 168) if workflow else 168
        
        # Calculate due date
        due_date = datetime.now() + timedelta(hours=sla_hours)
        
        # Auto-assign if rules match
        if not assigned_to and workflow:
            assigned_to = self._auto_assign(vulnerability_name, asset_name, severity)
        
        task = RemediationTask(
            id=task_id,
            vulnerability_id=vulnerability_id,
            vulnerability_name=vulnerability_name,
            asset_id=asset_id,
            asset_name=asset_name,
            severity=severity,
            priority=priority,
            status=RemediationStatus.ASSIGNED if assigned_to else RemediationStatus.IDENTIFIED,
            remediation_type=RemediationType.PATCH,
            description=description,
            remediation_steps=remediation_steps,
            assigned_to=assigned_to,
            assigned_by=assigned_by,
            assigned_date=datetime.now() if assigned_to else None,
            due_date=due_date,
            sla_hours=sla_hours,
            estimated_effort=self._estimate_effort(severity),
            cvss_score=cvss_score,
            cve_ids=cve_ids or [],
            compliance_frameworks=compliance_frameworks or []
        )
        
        self.tasks[task_id] = task
        await self._save_task(task)
        await self._log_history(task_id, "created", "", "Task created", assigned_by)
        await self._trigger_callback("task_created", task)
        
        return task
    
    def _auto_assign(self, vuln_name: str, asset_name: str, severity: str) -> str:
        """Auto-assign task based on rules"""
        workflow = self.workflows.get("default")
        if not workflow:
            return ""
        
        for rule in workflow.auto_assign_rules:
            condition = rule.get("condition", {})
            if condition.get("severity") == severity:
                return rule.get("assign_to", "")
        
        return ""
    
    def _estimate_effort(self, severity: str) -> str:
        """Estimate remediation effort"""
        effort_map = {
            "critical": "4-8 hours",
            "high": "2-4 hours",
            "medium": "1-2 hours",
            "low": "30 minutes - 1 hour",
            "info": "15-30 minutes"
        }
        return effort_map.get(severity.lower(), "1-2 hours")
    
    async def update_status(
        self,
        task_id: str,
        new_status: RemediationStatus,
        updated_by: str,
        notes: str = ""
    ) -> Optional[RemediationTask]:
        """Update task status"""
        task = self.tasks.get(task_id)
        if not task:
            return None
        
        old_status = task.status.value
        task.status = new_status
        
        # Update timestamps based on status
        if new_status == RemediationStatus.IN_PROGRESS:
            task.start_date = datetime.now()
        elif new_status in [RemediationStatus.VERIFIED, RemediationStatus.CLOSED]:
            task.completion_date = datetime.now()
        
        if notes:
            task.notes.append({
                "date": datetime.now().isoformat(),
                "user": updated_by,
                "content": notes
            })
        
        await self._save_task(task)
        await self._log_history(task_id, "status_change", old_status, new_status.value, updated_by, notes)
        await self._trigger_callback("status_changed", task)
        
        return task
    
    async def assign_task(
        self,
        task_id: str,
        assigned_to: str,
        assigned_by: str
    ) -> Optional[RemediationTask]:
        """Assign task to user"""
        task = self.tasks.get(task_id)
        if not task:
            return None
        
        old_assignee = task.assigned_to
        task.assigned_to = assigned_to
        task.assigned_by = assigned_by
        task.assigned_date = datetime.now()
        
        if task.status == RemediationStatus.IDENTIFIED:
            task.status = RemediationStatus.ASSIGNED
        
        await self._save_task(task)
        await self._log_history(task_id, "assigned", old_assignee, assigned_to, assigned_by)
        await self._trigger_callback("task_assigned", task)
        
        return task
    
    async def verify_remediation(
        self,
        task_id: str,
        verified_by: str,
        verification_method: VerificationMethod,
        verified: bool,
        notes: str = ""
    ) -> Optional[RemediationTask]:
        """Verify remediation was successful"""
        task = self.tasks.get(task_id)
        if not task:
            return None
        
        task.verified_by = verified_by
        task.verification_date = datetime.now()
        task.verification_method = verification_method
        task.verification_notes = notes
        
        if verified:
            task.status = RemediationStatus.VERIFIED
        else:
            task.status = RemediationStatus.REOPENED
        
        await self._save_task(task)
        await self._log_history(
            task_id,
            "verified" if verified else "reopened",
            "",
            f"Verification: {verification_method.value}",
            verified_by,
            notes
        )
        await self._trigger_callback("task_verified" if verified else "task_reopened", task)
        
        return task
    
    async def add_note(
        self,
        task_id: str,
        user: str,
        content: str
    ) -> Optional[RemediationTask]:
        """Add note to task"""
        task = self.tasks.get(task_id)
        if not task:
            return None
        
        task.notes.append({
            "date": datetime.now().isoformat(),
            "user": user,
            "content": content
        })
        
        await self._save_task(task)
        await self._log_history(task_id, "note_added", "", content[:100], user)
        
        return task
    
    async def bulk_assign(
        self,
        task_ids: List[str],
        assigned_to: str,
        assigned_by: str
    ) -> List[RemediationTask]:
        """Bulk assign tasks"""
        updated = []
        for task_id in task_ids:
            task = await self.assign_task(task_id, assigned_to, assigned_by)
            if task:
                updated.append(task)
        return updated
    
    async def bulk_update_status(
        self,
        task_ids: List[str],
        new_status: RemediationStatus,
        updated_by: str,
        notes: str = ""
    ) -> List[RemediationTask]:
        """Bulk update task status"""
        updated = []
        for task_id in task_ids:
            task = await self.update_status(task_id, new_status, updated_by, notes)
            if task:
                updated.append(task)
        return updated
    
    async def get_tasks_by_status(
        self,
        status: RemediationStatus
    ) -> List[RemediationTask]:
        """Get tasks by status"""
        return [t for t in self.tasks.values() if t.status == status]
    
    async def get_tasks_by_assignee(
        self,
        assignee: str
    ) -> List[RemediationTask]:
        """Get tasks assigned to user"""
        return [t for t in self.tasks.values() if t.assigned_to == assignee]
    
    async def get_overdue_tasks(self) -> List[RemediationTask]:
        """Get overdue tasks"""
        now = datetime.now()
        return [
            t for t in self.tasks.values()
            if t.due_date < now and t.status not in [
                RemediationStatus.CLOSED,
                RemediationStatus.VERIFIED,
                RemediationStatus.FALSE_POSITIVE,
                RemediationStatus.RISK_ACCEPTED
            ]
        ]
    
    async def get_sla_at_risk_tasks(self, threshold_percent: int = 75) -> List[RemediationTask]:
        """Get tasks at risk of SLA breach"""
        now = datetime.now()
        at_risk = []
        
        for task in self.tasks.values():
            if task.status in [
                RemediationStatus.CLOSED,
                RemediationStatus.VERIFIED,
                RemediationStatus.FALSE_POSITIVE,
                RemediationStatus.RISK_ACCEPTED
            ]:
                continue
            
            if task.assigned_date:
                elapsed = (now - task.assigned_date).total_seconds() / 3600
                threshold = task.sla_hours * (threshold_percent / 100)
                if elapsed >= threshold and elapsed < task.sla_hours:
                    at_risk.append(task)
        
        return at_risk
    
    async def get_sla_metrics(self) -> List[SLAMetric]:
        """Calculate SLA metrics by priority"""
        metrics = []
        
        for priority in RemediationPriority:
            priority_tasks = [
                t for t in self.tasks.values()
                if t.priority == priority
            ]
            
            if not priority_tasks:
                continue
            
            total = len(priority_tasks)
            
            # Calculate completed tasks
            completed = [
                t for t in priority_tasks
                if t.status in [RemediationStatus.CLOSED, RemediationStatus.VERIFIED]
            ]
            
            # On-time vs breached
            on_time = 0
            breached = 0
            total_hours = 0
            
            for task in completed:
                if task.completion_date and task.assigned_date:
                    resolution_hours = (task.completion_date - task.assigned_date).total_seconds() / 3600
                    total_hours += resolution_hours
                    
                    if resolution_hours <= task.sla_hours:
                        on_time += 1
                    else:
                        breached += 1
            
            workflow = self.workflows.get("default")
            sla_hours = workflow.sla_rules.get(priority.value, 168) if workflow else 168
            
            avg_resolution = total_hours / len(completed) if completed else 0
            compliance = (on_time / len(completed) * 100) if completed else 100
            
            metrics.append(SLAMetric(
                priority=priority,
                sla_hours=sla_hours,
                warning_threshold_percent=75,
                total_tasks=total,
                on_time_tasks=on_time,
                breached_tasks=breached,
                average_resolution_hours=round(avg_resolution, 2),
                compliance_percent=round(compliance, 2)
            ))
        
        return metrics
    
    async def generate_report(
        self,
        period_start: datetime,
        period_end: datetime,
        name: str = "Remediation Report"
    ) -> RemediationReport:
        """Generate remediation report"""
        report_id = hashlib.sha256(
            f"report:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Filter tasks by period
        period_tasks = [
            t for t in self.tasks.values()
            if t.assigned_date and period_start <= t.assigned_date <= period_end
        ]
        
        # Calculate metrics
        by_priority = {}
        by_status = {}
        by_type = {}
        
        for task in period_tasks:
            by_priority[task.priority.value] = by_priority.get(task.priority.value, 0) + 1
            by_status[task.status.value] = by_status.get(task.status.value, 0) + 1
            by_type[task.remediation_type.value] = by_type.get(task.remediation_type.value, 0) + 1
        
        # Remediation counts
        remediated = len([
            t for t in period_tasks
            if t.status in [RemediationStatus.CLOSED, RemediationStatus.VERIFIED]
        ])
        
        pending = len([
            t for t in period_tasks
            if t.status in [RemediationStatus.IDENTIFIED, RemediationStatus.ASSIGNED, RemediationStatus.IN_PROGRESS]
        ])
        
        now = datetime.now()
        overdue = len([
            t for t in period_tasks
            if t.due_date < now and t.status not in [
                RemediationStatus.CLOSED,
                RemediationStatus.VERIFIED,
                RemediationStatus.FALSE_POSITIVE,
                RemediationStatus.RISK_ACCEPTED
            ]
        ])
        
        # Top owners
        owner_counts = {}
        for task in period_tasks:
            if task.assigned_to:
                owner_counts[task.assigned_to] = owner_counts.get(task.assigned_to, 0) + 1
        
        top_owners = [
            {"owner": k, "count": v}
            for k, v in sorted(owner_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Aging analysis
        aging = {"0-7 days": 0, "8-14 days": 0, "15-30 days": 0, "30+ days": 0}
        for task in period_tasks:
            if task.status in [RemediationStatus.CLOSED, RemediationStatus.VERIFIED]:
                continue
            
            if task.assigned_date:
                age = (now - task.assigned_date).days
                if age <= 7:
                    aging["0-7 days"] += 1
                elif age <= 14:
                    aging["8-14 days"] += 1
                elif age <= 30:
                    aging["15-30 days"] += 1
                else:
                    aging["30+ days"] += 1
        
        # Get SLA metrics
        sla_metrics = await self.get_sla_metrics()
        
        return RemediationReport(
            id=report_id,
            name=name,
            generated_date=datetime.now(),
            period_start=period_start,
            period_end=period_end,
            total_vulnerabilities=len(period_tasks),
            remediated_count=remediated,
            pending_count=pending,
            overdue_count=overdue,
            by_priority=by_priority,
            by_status=by_status,
            by_type=by_type,
            sla_metrics=sla_metrics,
            top_owners=top_owners,
            aging_analysis=aging,
            trend_data=[]
        )
    
    async def get_task_history(self, task_id: str) -> List[Dict[str, Any]]:
        """Get task history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT action, old_value, new_value, changed_by, changed_at, notes
            FROM task_history
            WHERE task_id = ?
            ORDER BY changed_at DESC
        """, (task_id,))
        
        history = []
        for row in cursor.fetchall():
            history.append({
                "action": row[0],
                "old_value": row[1],
                "new_value": row[2],
                "changed_by": row[3],
                "changed_at": row[4],
                "notes": row[5]
            })
        
        conn.close()
        return history
    
    async def search_tasks(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[RemediationTask]:
        """Search tasks"""
        results = []
        query_lower = query.lower()
        
        for task in self.tasks.values():
            # Text search
            if query_lower in task.vulnerability_name.lower() or \
               query_lower in task.asset_name.lower() or \
               query_lower in task.description.lower():
                
                # Apply filters
                if filters:
                    if "status" in filters and task.status.value != filters["status"]:
                        continue
                    if "priority" in filters and task.priority.value != filters["priority"]:
                        continue
                    if "assignee" in filters and task.assigned_to != filters["assignee"]:
                        continue
                
                results.append(task)
        
        return results
    
    async def export_tasks(
        self,
        format_type: str = "json",
        task_ids: Optional[List[str]] = None
    ) -> str:
        """Export tasks"""
        tasks_to_export = [
            self.tasks[tid] for tid in task_ids
        ] if task_ids else list(self.tasks.values())
        
        if format_type == "json":
            return json.dumps([
                {
                    "id": t.id,
                    "vulnerability_id": t.vulnerability_id,
                    "vulnerability_name": t.vulnerability_name,
                    "asset_name": t.asset_name,
                    "severity": t.severity,
                    "priority": t.priority.value,
                    "status": t.status.value,
                    "assigned_to": t.assigned_to,
                    "due_date": t.due_date.isoformat() if t.due_date else None,
                    "cvss_score": t.cvss_score
                }
                for t in tasks_to_export
            ], indent=2)
        elif format_type == "csv":
            lines = ["ID,Vulnerability,Asset,Severity,Priority,Status,Assigned To,Due Date,CVSS"]
            for t in tasks_to_export:
                lines.append(
                    f"{t.id},{t.vulnerability_name},{t.asset_name},{t.severity},"
                    f"{t.priority.value},{t.status.value},{t.assigned_to},"
                    f"{t.due_date.isoformat() if t.due_date else ''},{t.cvss_score or ''}"
                )
            return "\n".join(lines)
        
        return ""
    
    def register_callback(self, event: str, callback: Callable):
        """Register callback for events"""
        if event not in self.callbacks:
            self.callbacks[event] = []
        self.callbacks[event].append(callback)
    
    async def _trigger_callback(self, event: str, data: Any):
        """Trigger callbacks for event"""
        for callback in self.callbacks.get(event, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)
            except Exception as e:
                print(f"Callback error: {e}")
    
    async def _save_task(self, task: RemediationTask):
        """Save task to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO remediation_tasks VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            task.id,
            task.vulnerability_id,
            task.vulnerability_name,
            task.asset_id,
            task.asset_name,
            task.severity,
            task.priority.value,
            task.status.value,
            task.remediation_type.value,
            task.description,
            json.dumps(task.remediation_steps),
            task.assigned_to,
            task.assigned_by,
            task.assigned_date.isoformat() if task.assigned_date else None,
            task.due_date.isoformat() if task.due_date else None,
            task.sla_hours,
            task.estimated_effort,
            task.actual_effort,
            task.start_date.isoformat() if task.start_date else None,
            task.completion_date.isoformat() if task.completion_date else None,
            task.verification_method.value if task.verification_method else None,
            task.verified_by,
            task.verification_date.isoformat() if task.verification_date else None,
            task.verification_notes,
            json.dumps(task.notes),
            json.dumps(task.attachments),
            json.dumps(task.related_tasks),
            task.cvss_score,
            json.dumps(task.cve_ids),
            json.dumps(task.tags),
            json.dumps(task.compliance_frameworks),
            task.business_impact,
            task.technical_details,
            task.rollback_plan,
            task.change_ticket,
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def _log_history(
        self,
        task_id: str,
        action: str,
        old_value: str,
        new_value: str,
        changed_by: str,
        notes: str = ""
    ):
        """Log task history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO task_history (task_id, action, old_value, new_value, changed_by, changed_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (task_id, action, old_value, new_value, changed_by, datetime.now().isoformat(), notes))
        
        conn.commit()
        conn.close()
    
    async def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics"""
        now = datetime.now()
        
        # Count by status
        status_counts = {}
        for status in RemediationStatus:
            status_counts[status.value] = len([
                t for t in self.tasks.values() if t.status == status
            ])
        
        # Count by priority
        priority_counts = {}
        for priority in RemediationPriority:
            priority_counts[priority.value] = len([
                t for t in self.tasks.values() if t.priority == priority
            ])
        
        # Overdue and at-risk
        overdue_tasks = await self.get_overdue_tasks()
        at_risk_tasks = await self.get_sla_at_risk_tasks()
        
        # This week stats
        week_ago = now - timedelta(days=7)
        created_this_week = len([
            t for t in self.tasks.values()
            if t.assigned_date and t.assigned_date >= week_ago
        ])
        
        closed_this_week = len([
            t for t in self.tasks.values()
            if t.completion_date and t.completion_date >= week_ago
        ])
        
        return {
            "total_tasks": len(self.tasks),
            "status_counts": status_counts,
            "priority_counts": priority_counts,
            "overdue_count": len(overdue_tasks),
            "at_risk_count": len(at_risk_tasks),
            "created_this_week": created_this_week,
            "closed_this_week": closed_this_week
        }
