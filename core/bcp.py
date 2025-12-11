#!/usr/bin/env python3
"""
Business Continuity Planning Engine
Comprehensive BCP/DR planning, testing, and management.
"""

import asyncio
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import sqlite3
import logging
from pathlib import Path


class BCPStatus(Enum):
    """BCP plan status"""
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    ACTIVE = "active"
    TESTING = "testing"
    OUTDATED = "outdated"
    ARCHIVED = "archived"


class RecoveryPriority(Enum):
    """Recovery priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DEFERRED = "deferred"


class DisasterType(Enum):
    """Types of disasters"""
    NATURAL = "natural"
    CYBER_ATTACK = "cyber_attack"
    POWER_OUTAGE = "power_outage"
    NETWORK_FAILURE = "network_failure"
    HARDWARE_FAILURE = "hardware_failure"
    DATA_CORRUPTION = "data_corruption"
    PANDEMIC = "pandemic"
    FACILITY_DAMAGE = "facility_damage"
    VENDOR_FAILURE = "vendor_failure"
    HUMAN_ERROR = "human_error"


class TestType(Enum):
    """BCP test types"""
    TABLETOP = "tabletop"
    WALKTHROUGH = "walkthrough"
    SIMULATION = "simulation"
    PARALLEL = "parallel"
    FULL_INTERRUPTION = "full_interruption"
    CHECKLIST = "checklist"


class TestResult(Enum):
    """Test result outcomes"""
    PASSED = "passed"
    PASSED_WITH_ISSUES = "passed_with_issues"
    FAILED = "failed"
    INCOMPLETE = "incomplete"
    CANCELLED = "cancelled"


@dataclass
class BusinessProcess:
    """Business process definition"""
    id: str
    name: str
    description: str
    department: str
    owner: str
    priority: RecoveryPriority
    rto_hours: int  # Recovery Time Objective
    rpo_hours: int  # Recovery Point Objective
    mto_hours: int  # Maximum Tolerable Outage
    dependencies: List[str] = field(default_factory=list)
    systems: List[str] = field(default_factory=list)
    personnel: List[str] = field(default_factory=list)
    vendors: List[str] = field(default_factory=list)
    revenue_impact_per_hour: float = 0.0
    compliance_requirements: List[str] = field(default_factory=list)
    recovery_procedures: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CriticalSystem:
    """Critical system for recovery"""
    id: str
    name: str
    description: str
    type: str  # application, database, infrastructure, etc.
    environment: str
    priority: RecoveryPriority
    rto_hours: int
    rpo_hours: int
    dependencies: List[str] = field(default_factory=list)
    backup_strategy: str = ""
    recovery_procedure: str = ""
    failover_target: str = ""
    data_classification: str = ""
    owner: str = ""
    vendor: str = ""
    sla_requirements: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RecoveryTeam:
    """Recovery team definition"""
    id: str
    name: str
    description: str
    role: str
    lead: str
    members: List[Dict[str, str]] = field(default_factory=list)  # name, role, contact
    responsibilities: List[str] = field(default_factory=list)
    escalation_path: List[str] = field(default_factory=list)
    alternate_lead: str = ""
    contact_methods: Dict[str, str] = field(default_factory=dict)
    assembly_location: str = ""
    remote_access: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RecoverySite:
    """Alternate recovery site"""
    id: str
    name: str
    type: str  # hot, warm, cold, mobile
    location: str
    capacity: Dict[str, int] = field(default_factory=dict)
    available_systems: List[str] = field(default_factory=list)
    network_capability: str = ""
    power_capacity: str = ""
    activation_time_hours: int = 0
    contract_details: Dict[str, Any] = field(default_factory=dict)
    last_tested: Optional[datetime] = None
    status: str = "active"


@dataclass
class BCPPlan:
    """Business Continuity Plan"""
    id: str
    name: str
    version: str
    description: str
    scope: str
    status: BCPStatus
    effective_date: datetime
    review_date: datetime
    owner: str
    approvers: List[str] = field(default_factory=list)
    disaster_scenarios: List[DisasterType] = field(default_factory=list)
    processes: List[str] = field(default_factory=list)
    systems: List[str] = field(default_factory=list)
    teams: List[str] = field(default_factory=list)
    sites: List[str] = field(default_factory=list)
    activation_criteria: List[str] = field(default_factory=list)
    notification_procedures: List[Dict[str, Any]] = field(default_factory=list)
    recovery_phases: List[Dict[str, Any]] = field(default_factory=list)
    communication_plan: Dict[str, Any] = field(default_factory=dict)
    resource_requirements: Dict[str, Any] = field(default_factory=dict)
    test_schedule: List[Dict[str, Any]] = field(default_factory=list)
    document_references: List[str] = field(default_factory=list)
    change_history: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BCPTest:
    """BCP test execution"""
    id: str
    plan_id: str
    name: str
    type: TestType
    scenario: DisasterType
    description: str
    scheduled_date: datetime
    actual_date: Optional[datetime] = None
    duration_hours: float = 0.0
    participants: List[str] = field(default_factory=list)
    objectives: List[str] = field(default_factory=list)
    scope: List[str] = field(default_factory=list)
    result: Optional[TestResult] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)
    action_items: List[Dict[str, Any]] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    report: str = ""
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class Incident:
    """BCP activation incident"""
    id: str
    plan_id: str
    name: str
    type: DisasterType
    severity: str
    description: str
    declared_at: datetime
    declared_by: str
    status: str = "active"
    resolved_at: Optional[datetime] = None
    impact_assessment: Dict[str, Any] = field(default_factory=dict)
    affected_processes: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    activated_teams: List[str] = field(default_factory=list)
    recovery_actions: List[Dict[str, Any]] = field(default_factory=list)
    communications: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    root_cause: str = ""
    post_incident_review: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """BCP risk assessment"""
    id: str
    plan_id: str
    name: str
    assessment_date: datetime
    assessor: str
    threats: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_scenarios: List[Dict[str, Any]] = field(default_factory=list)
    impact_analysis: Dict[str, Any] = field(default_factory=dict)
    mitigation_strategies: List[Dict[str, Any]] = field(default_factory=list)
    residual_risks: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    next_review: datetime = field(default_factory=datetime.now)


class BCPEngine:
    """
    Business Continuity Planning Engine
    Comprehensive BCP/DR planning and management.
    """
    
    def __init__(self, db_path: str = "bcp.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.plans: Dict[str, BCPPlan] = {}
        self.processes: Dict[str, BusinessProcess] = {}
        self.systems: Dict[str, CriticalSystem] = {}
        self.teams: Dict[str, RecoveryTeam] = {}
        self.sites: Dict[str, RecoverySite] = {}
        self.tests: Dict[str, BCPTest] = {}
        self.incidents: Dict[str, Incident] = {}
        self.assessments: Dict[str, RiskAssessment] = {}
        self._init_database()
    
    def _init_database(self):
        """Initialize database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS plans (
                id TEXT PRIMARY KEY,
                name TEXT,
                version TEXT,
                description TEXT,
                scope TEXT,
                status TEXT,
                effective_date TIMESTAMP,
                review_date TIMESTAMP,
                owner TEXT,
                data TEXT,
                created_at TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS processes (
                id TEXT PRIMARY KEY,
                plan_id TEXT,
                name TEXT,
                department TEXT,
                priority TEXT,
                rto_hours INTEGER,
                rpo_hours INTEGER,
                data TEXT,
                FOREIGN KEY (plan_id) REFERENCES plans(id)
            );
            
            CREATE TABLE IF NOT EXISTS systems (
                id TEXT PRIMARY KEY,
                plan_id TEXT,
                name TEXT,
                type TEXT,
                priority TEXT,
                rto_hours INTEGER,
                rpo_hours INTEGER,
                data TEXT,
                FOREIGN KEY (plan_id) REFERENCES plans(id)
            );
            
            CREATE TABLE IF NOT EXISTS teams (
                id TEXT PRIMARY KEY,
                plan_id TEXT,
                name TEXT,
                role TEXT,
                lead TEXT,
                data TEXT,
                FOREIGN KEY (plan_id) REFERENCES plans(id)
            );
            
            CREATE TABLE IF NOT EXISTS sites (
                id TEXT PRIMARY KEY,
                name TEXT,
                type TEXT,
                location TEXT,
                status TEXT,
                data TEXT
            );
            
            CREATE TABLE IF NOT EXISTS tests (
                id TEXT PRIMARY KEY,
                plan_id TEXT,
                name TEXT,
                type TEXT,
                scenario TEXT,
                scheduled_date TIMESTAMP,
                result TEXT,
                data TEXT,
                created_at TIMESTAMP,
                FOREIGN KEY (plan_id) REFERENCES plans(id)
            );
            
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                plan_id TEXT,
                name TEXT,
                type TEXT,
                severity TEXT,
                declared_at TIMESTAMP,
                status TEXT,
                data TEXT,
                FOREIGN KEY (plan_id) REFERENCES plans(id)
            );
            
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                plan_id TEXT,
                name TEXT,
                assessment_date TIMESTAMP,
                assessor TEXT,
                data TEXT,
                FOREIGN KEY (plan_id) REFERENCES plans(id)
            );
            
            CREATE INDEX IF NOT EXISTS idx_processes_plan ON processes(plan_id);
            CREATE INDEX IF NOT EXISTS idx_systems_plan ON systems(plan_id);
            CREATE INDEX IF NOT EXISTS idx_tests_plan ON tests(plan_id);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
        """)
        
        conn.commit()
        conn.close()
    
    async def create_plan(
        self,
        name: str,
        description: str,
        scope: str,
        owner: str,
        **kwargs
    ) -> BCPPlan:
        """Create new BCP plan"""
        plan_id = hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        plan = BCPPlan(
            id=plan_id,
            name=name,
            version="1.0",
            description=description,
            scope=scope,
            status=BCPStatus.DRAFT,
            effective_date=datetime.now(),
            review_date=datetime.now() + timedelta(days=365),
            owner=owner,
            approvers=kwargs.get("approvers", []),
            disaster_scenarios=kwargs.get("disaster_scenarios", []),
            activation_criteria=kwargs.get("activation_criteria", [])
        )
        
        self.plans[plan_id] = plan
        await self._save_plan(plan)
        
        return plan
    
    async def _save_plan(self, plan: BCPPlan):
        """Save plan to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO plans 
            (id, name, version, description, scope, status, effective_date, review_date, owner, data, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            plan.id, plan.name, plan.version, plan.description, plan.scope,
            plan.status.value, plan.effective_date, plan.review_date, plan.owner,
            json.dumps({
                "approvers": plan.approvers,
                "disaster_scenarios": [d.value for d in plan.disaster_scenarios],
                "processes": plan.processes,
                "systems": plan.systems,
                "teams": plan.teams,
                "sites": plan.sites,
                "activation_criteria": plan.activation_criteria,
                "notification_procedures": plan.notification_procedures,
                "recovery_phases": plan.recovery_phases,
                "communication_plan": plan.communication_plan,
                "resource_requirements": plan.resource_requirements,
                "test_schedule": plan.test_schedule,
                "document_references": plan.document_references,
                "change_history": plan.change_history,
                "metadata": plan.metadata
            }),
            plan.created_at
        ))
        
        conn.commit()
        conn.close()
    
    async def add_business_process(
        self,
        plan_id: str,
        name: str,
        description: str,
        department: str,
        owner: str,
        priority: RecoveryPriority,
        rto_hours: int,
        rpo_hours: int,
        mto_hours: int,
        **kwargs
    ) -> BusinessProcess:
        """Add business process to plan"""
        process_id = hashlib.md5(f"{plan_id}_{name}".encode()).hexdigest()[:12]
        
        process = BusinessProcess(
            id=process_id,
            name=name,
            description=description,
            department=department,
            owner=owner,
            priority=priority,
            rto_hours=rto_hours,
            rpo_hours=rpo_hours,
            mto_hours=mto_hours,
            dependencies=kwargs.get("dependencies", []),
            systems=kwargs.get("systems", []),
            personnel=kwargs.get("personnel", []),
            vendors=kwargs.get("vendors", []),
            revenue_impact_per_hour=kwargs.get("revenue_impact_per_hour", 0.0),
            compliance_requirements=kwargs.get("compliance_requirements", []),
            recovery_procedures=kwargs.get("recovery_procedures", [])
        )
        
        self.processes[process_id] = process
        
        if plan_id in self.plans:
            self.plans[plan_id].processes.append(process_id)
        
        await self._save_process(plan_id, process)
        
        return process
    
    async def _save_process(self, plan_id: str, process: BusinessProcess):
        """Save process to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO processes 
            (id, plan_id, name, department, priority, rto_hours, rpo_hours, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            process.id, plan_id, process.name, process.department,
            process.priority.value, process.rto_hours, process.rpo_hours,
            json.dumps({
                "description": process.description,
                "owner": process.owner,
                "mto_hours": process.mto_hours,
                "dependencies": process.dependencies,
                "systems": process.systems,
                "personnel": process.personnel,
                "vendors": process.vendors,
                "revenue_impact_per_hour": process.revenue_impact_per_hour,
                "compliance_requirements": process.compliance_requirements,
                "recovery_procedures": process.recovery_procedures,
                "metadata": process.metadata
            })
        ))
        
        conn.commit()
        conn.close()
    
    async def add_critical_system(
        self,
        plan_id: str,
        name: str,
        description: str,
        system_type: str,
        environment: str,
        priority: RecoveryPriority,
        rto_hours: int,
        rpo_hours: int,
        **kwargs
    ) -> CriticalSystem:
        """Add critical system to plan"""
        system_id = hashlib.md5(f"{plan_id}_{name}".encode()).hexdigest()[:12]
        
        system = CriticalSystem(
            id=system_id,
            name=name,
            description=description,
            type=system_type,
            environment=environment,
            priority=priority,
            rto_hours=rto_hours,
            rpo_hours=rpo_hours,
            dependencies=kwargs.get("dependencies", []),
            backup_strategy=kwargs.get("backup_strategy", ""),
            recovery_procedure=kwargs.get("recovery_procedure", ""),
            failover_target=kwargs.get("failover_target", ""),
            data_classification=kwargs.get("data_classification", ""),
            owner=kwargs.get("owner", ""),
            vendor=kwargs.get("vendor", "")
        )
        
        self.systems[system_id] = system
        
        if plan_id in self.plans:
            self.plans[plan_id].systems.append(system_id)
        
        return system
    
    async def add_recovery_team(
        self,
        plan_id: str,
        name: str,
        description: str,
        role: str,
        lead: str,
        **kwargs
    ) -> RecoveryTeam:
        """Add recovery team to plan"""
        team_id = hashlib.md5(f"{plan_id}_{name}".encode()).hexdigest()[:12]
        
        team = RecoveryTeam(
            id=team_id,
            name=name,
            description=description,
            role=role,
            lead=lead,
            members=kwargs.get("members", []),
            responsibilities=kwargs.get("responsibilities", []),
            escalation_path=kwargs.get("escalation_path", []),
            alternate_lead=kwargs.get("alternate_lead", ""),
            contact_methods=kwargs.get("contact_methods", {}),
            assembly_location=kwargs.get("assembly_location", ""),
            remote_access=kwargs.get("remote_access", {})
        )
        
        self.teams[team_id] = team
        
        if plan_id in self.plans:
            self.plans[plan_id].teams.append(team_id)
        
        return team
    
    async def add_recovery_site(
        self,
        name: str,
        site_type: str,
        location: str,
        **kwargs
    ) -> RecoverySite:
        """Add recovery site"""
        site_id = hashlib.md5(f"{name}_{location}".encode()).hexdigest()[:12]
        
        site = RecoverySite(
            id=site_id,
            name=name,
            type=site_type,
            location=location,
            capacity=kwargs.get("capacity", {}),
            available_systems=kwargs.get("available_systems", []),
            network_capability=kwargs.get("network_capability", ""),
            power_capacity=kwargs.get("power_capacity", ""),
            activation_time_hours=kwargs.get("activation_time_hours", 0),
            contract_details=kwargs.get("contract_details", {})
        )
        
        self.sites[site_id] = site
        
        return site
    
    async def schedule_test(
        self,
        plan_id: str,
        name: str,
        test_type: TestType,
        scenario: DisasterType,
        description: str,
        scheduled_date: datetime,
        **kwargs
    ) -> BCPTest:
        """Schedule BCP test"""
        test_id = hashlib.md5(f"{plan_id}_{name}_{scheduled_date.isoformat()}".encode()).hexdigest()[:12]
        
        test = BCPTest(
            id=test_id,
            plan_id=plan_id,
            name=name,
            type=test_type,
            scenario=scenario,
            description=description,
            scheduled_date=scheduled_date,
            participants=kwargs.get("participants", []),
            objectives=kwargs.get("objectives", []),
            scope=kwargs.get("scope", [])
        )
        
        self.tests[test_id] = test
        
        return test
    
    async def execute_test(
        self,
        test_id: str,
        actual_date: datetime,
        duration_hours: float,
        result: TestResult,
        findings: List[Dict[str, Any]],
        **kwargs
    ) -> BCPTest:
        """Record test execution"""
        test = self.tests.get(test_id)
        if not test:
            raise ValueError(f"Test {test_id} not found")
        
        test.actual_date = actual_date
        test.duration_hours = duration_hours
        test.result = result
        test.findings = findings
        test.lessons_learned = kwargs.get("lessons_learned", [])
        test.action_items = kwargs.get("action_items", [])
        test.metrics = kwargs.get("metrics", {})
        test.report = kwargs.get("report", "")
        
        return test
    
    async def declare_incident(
        self,
        plan_id: str,
        name: str,
        incident_type: DisasterType,
        severity: str,
        description: str,
        declared_by: str,
        **kwargs
    ) -> Incident:
        """Declare BCP activation incident"""
        incident_id = hashlib.md5(f"{plan_id}_{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        incident = Incident(
            id=incident_id,
            plan_id=plan_id,
            name=name,
            type=incident_type,
            severity=severity,
            description=description,
            declared_at=datetime.now(),
            declared_by=declared_by,
            impact_assessment=kwargs.get("impact_assessment", {}),
            affected_processes=kwargs.get("affected_processes", []),
            affected_systems=kwargs.get("affected_systems", [])
        )
        
        self.incidents[incident_id] = incident
        
        # Log timeline entry
        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "event": "Incident Declared",
            "details": f"Declared by {declared_by}",
            "severity": severity
        })
        
        return incident
    
    async def update_incident(
        self,
        incident_id: str,
        action: str,
        details: str,
        user: str
    ) -> Incident:
        """Update incident with action"""
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        
        incident.recovery_actions.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details,
            "performed_by": user
        })
        
        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "event": action,
            "details": details,
            "user": user
        })
        
        return incident
    
    async def resolve_incident(
        self,
        incident_id: str,
        root_cause: str,
        resolved_by: str
    ) -> Incident:
        """Resolve incident"""
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        
        incident.status = "resolved"
        incident.resolved_at = datetime.now()
        incident.root_cause = root_cause
        
        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "event": "Incident Resolved",
            "details": f"Root cause: {root_cause}",
            "user": resolved_by
        })
        
        return incident
    
    async def conduct_risk_assessment(
        self,
        plan_id: str,
        name: str,
        assessor: str,
        threats: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
        **kwargs
    ) -> RiskAssessment:
        """Conduct risk assessment"""
        assessment_id = hashlib.md5(f"{plan_id}_{name}_{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        assessment = RiskAssessment(
            id=assessment_id,
            plan_id=plan_id,
            name=name,
            assessment_date=datetime.now(),
            assessor=assessor,
            threats=threats,
            vulnerabilities=vulnerabilities,
            risk_scenarios=kwargs.get("risk_scenarios", []),
            impact_analysis=kwargs.get("impact_analysis", {}),
            mitigation_strategies=kwargs.get("mitigation_strategies", []),
            residual_risks=kwargs.get("residual_risks", []),
            recommendations=kwargs.get("recommendations", []),
            next_review=kwargs.get("next_review", datetime.now() + timedelta(days=180))
        )
        
        self.assessments[assessment_id] = assessment
        
        return assessment
    
    async def calculate_business_impact(
        self,
        plan_id: str
    ) -> Dict[str, Any]:
        """Calculate business impact analysis"""
        plan = self.plans.get(plan_id)
        if not plan:
            return {"error": "Plan not found"}
        
        analysis = {
            "plan_id": plan_id,
            "plan_name": plan.name,
            "analysis_date": datetime.now().isoformat(),
            "processes": [],
            "systems": [],
            "total_rto": 0,
            "total_rpo": 0,
            "critical_path": [],
            "financial_impact": {
                "hourly": 0.0,
                "daily": 0.0,
                "weekly": 0.0
            },
            "recovery_sequence": []
        }
        
        # Analyze processes
        for process_id in plan.processes:
            process = self.processes.get(process_id)
            if process:
                impact = {
                    "id": process.id,
                    "name": process.name,
                    "priority": process.priority.value,
                    "rto_hours": process.rto_hours,
                    "rpo_hours": process.rpo_hours,
                    "mto_hours": process.mto_hours,
                    "revenue_impact": process.revenue_impact_per_hour,
                    "dependencies": len(process.dependencies),
                    "criticality_score": self._calculate_criticality(process)
                }
                analysis["processes"].append(impact)
                analysis["financial_impact"]["hourly"] += process.revenue_impact_per_hour
        
        # Analyze systems
        for system_id in plan.systems:
            system = self.systems.get(system_id)
            if system:
                impact = {
                    "id": system.id,
                    "name": system.name,
                    "type": system.type,
                    "priority": system.priority.value,
                    "rto_hours": system.rto_hours,
                    "rpo_hours": system.rpo_hours,
                    "dependencies": len(system.dependencies)
                }
                analysis["systems"].append(impact)
        
        # Calculate daily and weekly impact
        analysis["financial_impact"]["daily"] = analysis["financial_impact"]["hourly"] * 24
        analysis["financial_impact"]["weekly"] = analysis["financial_impact"]["daily"] * 7
        
        # Determine recovery sequence based on priority and dependencies
        analysis["recovery_sequence"] = self._calculate_recovery_sequence(plan)
        
        return analysis
    
    def _calculate_criticality(self, process: BusinessProcess) -> float:
        """Calculate process criticality score"""
        priority_scores = {
            RecoveryPriority.CRITICAL: 10,
            RecoveryPriority.HIGH: 7,
            RecoveryPriority.MEDIUM: 5,
            RecoveryPriority.LOW: 3,
            RecoveryPriority.DEFERRED: 1
        }
        
        base_score = priority_scores.get(process.priority, 5)
        
        # Adjust for RTO (shorter RTO = higher criticality)
        if process.rto_hours <= 1:
            base_score *= 1.5
        elif process.rto_hours <= 4:
            base_score *= 1.3
        elif process.rto_hours <= 24:
            base_score *= 1.1
        
        # Adjust for revenue impact
        if process.revenue_impact_per_hour >= 100000:
            base_score *= 1.5
        elif process.revenue_impact_per_hour >= 10000:
            base_score *= 1.2
        
        return min(base_score, 15.0)
    
    def _calculate_recovery_sequence(self, plan: BCPPlan) -> List[Dict[str, Any]]:
        """Calculate optimal recovery sequence"""
        sequence = []
        
        # Get all processes and systems with priorities
        items = []
        
        for process_id in plan.processes:
            process = self.processes.get(process_id)
            if process:
                items.append({
                    "type": "process",
                    "id": process.id,
                    "name": process.name,
                    "priority": process.priority,
                    "rto": process.rto_hours,
                    "dependencies": process.dependencies
                })
        
        for system_id in plan.systems:
            system = self.systems.get(system_id)
            if system:
                items.append({
                    "type": "system",
                    "id": system.id,
                    "name": system.name,
                    "priority": system.priority,
                    "rto": system.rto_hours,
                    "dependencies": system.dependencies
                })
        
        # Sort by priority and RTO
        priority_order = {
            RecoveryPriority.CRITICAL: 0,
            RecoveryPriority.HIGH: 1,
            RecoveryPriority.MEDIUM: 2,
            RecoveryPriority.LOW: 3,
            RecoveryPriority.DEFERRED: 4
        }
        
        items.sort(key=lambda x: (priority_order.get(x["priority"], 5), x["rto"]))
        
        for idx, item in enumerate(items):
            sequence.append({
                "order": idx + 1,
                "type": item["type"],
                "id": item["id"],
                "name": item["name"],
                "target_rto": item["rto"]
            })
        
        return sequence
    
    async def generate_plan_report(
        self,
        plan_id: str
    ) -> Dict[str, Any]:
        """Generate comprehensive BCP report"""
        plan = self.plans.get(plan_id)
        if not plan:
            return {"error": "Plan not found"}
        
        report = {
            "plan": {
                "id": plan.id,
                "name": plan.name,
                "version": plan.version,
                "status": plan.status.value,
                "owner": plan.owner,
                "effective_date": plan.effective_date.isoformat(),
                "review_date": plan.review_date.isoformat()
            },
            "scope": plan.scope,
            "disaster_scenarios": [d.value for d in plan.disaster_scenarios],
            "statistics": {
                "total_processes": len(plan.processes),
                "total_systems": len(plan.systems),
                "total_teams": len(plan.teams),
                "total_sites": len(plan.sites)
            },
            "processes": [],
            "systems": [],
            "teams": [],
            "sites": [],
            "test_history": [],
            "incident_history": [],
            "risk_assessments": []
        }
        
        # Add processes
        for process_id in plan.processes:
            process = self.processes.get(process_id)
            if process:
                report["processes"].append({
                    "name": process.name,
                    "department": process.department,
                    "priority": process.priority.value,
                    "rto": f"{process.rto_hours}h",
                    "rpo": f"{process.rpo_hours}h"
                })
        
        # Add systems
        for system_id in plan.systems:
            system = self.systems.get(system_id)
            if system:
                report["systems"].append({
                    "name": system.name,
                    "type": system.type,
                    "priority": system.priority.value,
                    "rto": f"{system.rto_hours}h",
                    "rpo": f"{system.rpo_hours}h"
                })
        
        # Add teams
        for team_id in plan.teams:
            team = self.teams.get(team_id)
            if team:
                report["teams"].append({
                    "name": team.name,
                    "role": team.role,
                    "lead": team.lead,
                    "members": len(team.members)
                })
        
        # Add test history
        for test in self.tests.values():
            if test.plan_id == plan_id:
                report["test_history"].append({
                    "name": test.name,
                    "type": test.type.value,
                    "date": test.scheduled_date.isoformat(),
                    "result": test.result.value if test.result else "pending"
                })
        
        # Add incident history
        for incident in self.incidents.values():
            if incident.plan_id == plan_id:
                report["incident_history"].append({
                    "name": incident.name,
                    "type": incident.type.value,
                    "severity": incident.severity,
                    "declared": incident.declared_at.isoformat(),
                    "status": incident.status
                })
        
        return report
    
    async def check_plan_compliance(
        self,
        plan_id: str
    ) -> Dict[str, Any]:
        """Check plan compliance and readiness"""
        plan = self.plans.get(plan_id)
        if not plan:
            return {"error": "Plan not found"}
        
        compliance = {
            "plan_id": plan_id,
            "check_date": datetime.now().isoformat(),
            "overall_score": 0.0,
            "categories": {},
            "gaps": [],
            "recommendations": []
        }
        
        checks = {
            "documentation": 0.0,
            "testing": 0.0,
            "teams": 0.0,
            "systems": 0.0,
            "recovery_sites": 0.0,
            "communication": 0.0
        }
        
        # Check documentation
        doc_score = 0
        if plan.description:
            doc_score += 20
        if plan.activation_criteria:
            doc_score += 20
        if plan.recovery_phases:
            doc_score += 20
        if plan.notification_procedures:
            doc_score += 20
        if plan.document_references:
            doc_score += 20
        checks["documentation"] = doc_score
        
        # Check testing
        recent_tests = [t for t in self.tests.values() 
                       if t.plan_id == plan_id and 
                       t.actual_date and 
                       t.actual_date > datetime.now() - timedelta(days=365)]
        
        if recent_tests:
            passed_tests = sum(1 for t in recent_tests if t.result == TestResult.PASSED)
            checks["testing"] = (passed_tests / len(recent_tests)) * 100
        else:
            compliance["gaps"].append("No tests conducted in the past year")
        
        # Check teams
        if plan.teams:
            teams_with_contacts = sum(1 for tid in plan.teams 
                                     if tid in self.teams and self.teams[tid].contact_methods)
            checks["teams"] = (teams_with_contacts / len(plan.teams)) * 100 if plan.teams else 0
        else:
            compliance["gaps"].append("No recovery teams defined")
        
        # Check systems
        if plan.systems:
            systems_with_backup = sum(1 for sid in plan.systems 
                                     if sid in self.systems and self.systems[sid].backup_strategy)
            checks["systems"] = (systems_with_backup / len(plan.systems)) * 100
        else:
            compliance["gaps"].append("No critical systems identified")
        
        # Check recovery sites
        if plan.sites:
            active_sites = sum(1 for sid in plan.sites 
                              if sid in self.sites and self.sites[sid].status == "active")
            checks["recovery_sites"] = (active_sites / len(plan.sites)) * 100
        else:
            compliance["gaps"].append("No recovery sites configured")
        
        # Check communication plan
        if plan.communication_plan:
            checks["communication"] = 100.0
        else:
            compliance["gaps"].append("No communication plan defined")
            checks["communication"] = 0.0
        
        compliance["categories"] = checks
        compliance["overall_score"] = sum(checks.values()) / len(checks)
        
        # Generate recommendations
        if checks["testing"] < 50:
            compliance["recommendations"].append("Schedule and conduct BCP tests")
        if checks["documentation"] < 80:
            compliance["recommendations"].append("Complete missing documentation sections")
        if compliance["overall_score"] < 70:
            compliance["recommendations"].append("Review and update BCP plan comprehensively")
        
        return compliance
