#!/usr/bin/env python3
"""
HydraRecon Backup & DR Assessment Module
Enterprise backup security and disaster recovery assessment.
"""

import asyncio
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
import logging
import json


class BackupType(Enum):
    """Types of backups"""
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"
    SNAPSHOT = "snapshot"
    CONTINUOUS = "continuous"
    SYNTHETIC = "synthetic"


class StorageType(Enum):
    """Backup storage types"""
    LOCAL = "local"
    NAS = "nas"
    SAN = "san"
    CLOUD = "cloud"
    TAPE = "tape"
    HYBRID = "hybrid"
    OFFSITE = "offsite"


class BackupStatus(Enum):
    """Backup job status"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    FAILED = "failed"
    RUNNING = "running"
    UNKNOWN = "unknown"


class EncryptionStatus(Enum):
    """Backup encryption status"""
    ENCRYPTED = "encrypted"
    UNENCRYPTED = "unencrypted"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class ComplianceStatus(Enum):
    """Compliance status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_ASSESSED = "not_assessed"


class RiskLevel(Enum):
    """Risk assessment levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BackupTarget:
    """System being backed up"""
    id: str
    name: str
    hostname: str
    ip_address: str
    os: str
    criticality: str  # critical, high, medium, low
    data_classification: str
    backup_schedule: str
    retention_policy: str
    last_backup: Optional[datetime] = None
    backup_size_gb: float = 0.0
    rpo_hours: int = 24  # Recovery Point Objective
    rto_hours: int = 4   # Recovery Time Objective
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BackupJob:
    """Backup job record"""
    id: str
    target_id: str
    target_name: str
    backup_type: BackupType
    storage_type: StorageType
    start_time: datetime
    end_time: Optional[datetime] = None
    status: BackupStatus = BackupStatus.UNKNOWN
    size_bytes: int = 0
    files_count: int = 0
    duration_seconds: int = 0
    success: bool = True
    error_message: Optional[str] = None
    encryption: EncryptionStatus = EncryptionStatus.UNKNOWN
    verified: bool = False
    storage_location: str = ""
    retention_days: int = 30
    checksum: Optional[str] = None


@dataclass
class BackupStorage:
    """Backup storage location"""
    id: str
    name: str
    storage_type: StorageType
    location: str
    capacity_gb: float
    used_gb: float
    encryption: EncryptionStatus
    accessible: bool = True
    last_verified: Optional[datetime] = None
    compliance_status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
    air_gapped: bool = False
    immutable: bool = False
    replication_enabled: bool = False
    replication_target: Optional[str] = None


@dataclass
class DRPlan:
    """Disaster Recovery Plan"""
    id: str
    name: str
    description: str
    scope: List[str] = field(default_factory=list)  # Systems covered
    rpo_target: int = 24  # hours
    rto_target: int = 4   # hours
    steps: List[Dict[str, Any]] = field(default_factory=list)
    last_tested: Optional[datetime] = None
    test_results: Optional[Dict[str, Any]] = None
    status: str = "active"
    owner: str = ""
    contacts: List[Dict[str, str]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class AssessmentFinding:
    """Backup assessment finding"""
    id: str
    category: str
    title: str
    description: str
    risk_level: RiskLevel
    affected_systems: List[str] = field(default_factory=list)
    recommendation: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    compliance_reference: Optional[str] = None
    detected_at: datetime = field(default_factory=datetime.now)
    resolved: bool = False
    resolved_at: Optional[datetime] = None


@dataclass
class RecoveryTest:
    """Recovery test record"""
    id: str
    name: str
    dr_plan_id: str
    test_type: str  # tabletop, partial, full
    start_time: datetime
    end_time: Optional[datetime] = None
    systems_tested: List[str] = field(default_factory=list)
    actual_rto: Optional[int] = None  # minutes
    actual_rpo: Optional[int] = None  # minutes
    success: bool = False
    issues_found: List[str] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)
    participants: List[str] = field(default_factory=list)
    documentation: Optional[str] = None


class BackupAssessmentEngine:
    """Enterprise Backup & DR Assessment Engine"""
    
    def __init__(self):
        self.logger = logging.getLogger("BackupAssessmentEngine")
        self.targets: Dict[str, BackupTarget] = {}
        self.jobs: List[BackupJob] = []
        self.storage: Dict[str, BackupStorage] = {}
        self.dr_plans: Dict[str, DRPlan] = {}
        self.findings: List[AssessmentFinding] = []
        self.tests: List[RecoveryTest] = []
        self._init_compliance_rules()
    
    def _init_compliance_rules(self):
        """Initialize compliance check rules"""
        self.compliance_rules = {
            "encryption_required": {
                "description": "All backups must be encrypted",
                "check": lambda job: job.encryption == EncryptionStatus.ENCRYPTED,
                "frameworks": ["HIPAA", "PCI-DSS", "SOC2", "GDPR"]
            },
            "offsite_copy": {
                "description": "Critical systems must have offsite backup copies",
                "check": lambda target: any(
                    s.storage_type in [StorageType.CLOUD, StorageType.OFFSITE]
                    for s in self.storage.values()
                ),
                "frameworks": ["ISO27001", "NIST", "SOC2"]
            },
            "retention_minimum": {
                "description": "Minimum retention period of 30 days",
                "check": lambda job: job.retention_days >= 30,
                "frameworks": ["SOC2", "GDPR", "HIPAA"]
            },
            "backup_verification": {
                "description": "Backups must be verified after completion",
                "check": lambda job: job.verified,
                "frameworks": ["ISO27001", "NIST", "SOC2"]
            },
            "air_gapped_storage": {
                "description": "Air-gapped storage for ransomware protection",
                "check": lambda storage: storage.air_gapped,
                "frameworks": ["NIST", "CISA"]
            },
            "immutable_backups": {
                "description": "Immutable backup copies for ransomware protection",
                "check": lambda storage: storage.immutable,
                "frameworks": ["NIST", "CISA", "ISO27001"]
            },
            "dr_testing_annual": {
                "description": "DR plans must be tested annually",
                "check": lambda plan: plan.last_tested and 
                         (datetime.now() - plan.last_tested).days <= 365,
                "frameworks": ["SOC2", "ISO27001", "HIPAA"]
            },
            "rpo_compliance": {
                "description": "Backup frequency meets RPO requirements",
                "check": self._check_rpo_compliance,
                "frameworks": ["SOC2", "ISO27001"]
            }
        }
    
    def _check_rpo_compliance(self, target: BackupTarget) -> bool:
        """Check if backup frequency meets RPO"""
        if not target.last_backup:
            return False
        hours_since = (datetime.now() - target.last_backup).total_seconds() / 3600
        return hours_since <= target.rpo_hours
    
    async def add_backup_target(
        self,
        name: str,
        hostname: str,
        ip_address: str,
        os: str,
        criticality: str,
        data_classification: str,
        backup_schedule: str,
        retention_policy: str,
        rpo_hours: int = 24,
        rto_hours: int = 4
    ) -> BackupTarget:
        """Add a backup target system"""
        target_id = hashlib.sha256(
            f"{hostname}{ip_address}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        target = BackupTarget(
            id=target_id,
            name=name,
            hostname=hostname,
            ip_address=ip_address,
            os=os,
            criticality=criticality,
            data_classification=data_classification,
            backup_schedule=backup_schedule,
            retention_policy=retention_policy,
            rpo_hours=rpo_hours,
            rto_hours=rto_hours
        )
        
        self.targets[target_id] = target
        return target
    
    async def record_backup_job(
        self,
        target_id: str,
        backup_type: BackupType,
        storage_type: StorageType,
        storage_location: str,
        size_bytes: int,
        files_count: int,
        duration_seconds: int,
        success: bool,
        encryption: EncryptionStatus,
        verified: bool = False,
        error_message: Optional[str] = None
    ) -> BackupJob:
        """Record a backup job"""
        if target_id not in self.targets:
            raise ValueError(f"Unknown target: {target_id}")
        
        target = self.targets[target_id]
        
        job_id = hashlib.sha256(
            f"{target_id}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        job = BackupJob(
            id=job_id,
            target_id=target_id,
            target_name=target.name,
            backup_type=backup_type,
            storage_type=storage_type,
            start_time=datetime.now() - timedelta(seconds=duration_seconds),
            end_time=datetime.now(),
            status=BackupStatus.HEALTHY if success else BackupStatus.FAILED,
            size_bytes=size_bytes,
            files_count=files_count,
            duration_seconds=duration_seconds,
            success=success,
            error_message=error_message,
            encryption=encryption,
            verified=verified,
            storage_location=storage_location,
            checksum=hashlib.sha256(f"{job_id}{size_bytes}".encode()).hexdigest()
        )
        
        self.jobs.append(job)
        
        # Update target's last backup time
        if success:
            target.last_backup = datetime.now()
            target.backup_size_gb = size_bytes / (1024**3)
        
        return job
    
    async def add_storage(
        self,
        name: str,
        storage_type: StorageType,
        location: str,
        capacity_gb: float,
        used_gb: float,
        encryption: EncryptionStatus,
        air_gapped: bool = False,
        immutable: bool = False
    ) -> BackupStorage:
        """Add backup storage location"""
        storage_id = hashlib.sha256(
            f"{name}{location}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        storage = BackupStorage(
            id=storage_id,
            name=name,
            storage_type=storage_type,
            location=location,
            capacity_gb=capacity_gb,
            used_gb=used_gb,
            encryption=encryption,
            air_gapped=air_gapped,
            immutable=immutable,
            last_verified=datetime.now()
        )
        
        self.storage[storage_id] = storage
        return storage
    
    async def create_dr_plan(
        self,
        name: str,
        description: str,
        scope: List[str],
        rpo_target: int,
        rto_target: int,
        owner: str,
        contacts: List[Dict[str, str]]
    ) -> DRPlan:
        """Create a disaster recovery plan"""
        plan_id = hashlib.sha256(
            f"{name}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Generate default DR steps
        steps = self._generate_dr_steps(scope)
        
        plan = DRPlan(
            id=plan_id,
            name=name,
            description=description,
            scope=scope,
            rpo_target=rpo_target,
            rto_target=rto_target,
            steps=steps,
            owner=owner,
            contacts=contacts
        )
        
        self.dr_plans[plan_id] = plan
        return plan
    
    def _generate_dr_steps(self, scope: List[str]) -> List[Dict[str, Any]]:
        """Generate default DR steps"""
        return [
            {
                "order": 1,
                "name": "Incident Declaration",
                "description": "Declare disaster and activate DR plan",
                "responsible": "IT Manager",
                "estimated_time_minutes": 15
            },
            {
                "order": 2,
                "name": "Notification",
                "description": "Notify stakeholders and DR team",
                "responsible": "Communications Lead",
                "estimated_time_minutes": 30
            },
            {
                "order": 3,
                "name": "Assessment",
                "description": "Assess damage and determine recovery scope",
                "responsible": "Technical Lead",
                "estimated_time_minutes": 60
            },
            {
                "order": 4,
                "name": "Infrastructure Recovery",
                "description": "Restore critical infrastructure components",
                "responsible": "Infrastructure Team",
                "estimated_time_minutes": 120
            },
            {
                "order": 5,
                "name": "Data Recovery",
                "description": "Restore data from backups",
                "responsible": "Backup Team",
                "estimated_time_minutes": 180
            },
            {
                "order": 6,
                "name": "Application Recovery",
                "description": "Restore and verify applications",
                "responsible": "Application Team",
                "estimated_time_minutes": 120
            },
            {
                "order": 7,
                "name": "Validation",
                "description": "Validate recovery and test functionality",
                "responsible": "QA Team",
                "estimated_time_minutes": 60
            },
            {
                "order": 8,
                "name": "Resumption",
                "description": "Resume normal operations",
                "responsible": "IT Manager",
                "estimated_time_minutes": 30
            }
        ]
    
    async def run_assessment(self) -> Dict[str, Any]:
        """Run comprehensive backup and DR assessment"""
        findings = []
        
        # Check backup jobs
        for job in self.jobs[-100:]:  # Last 100 jobs
            # Check encryption
            if job.encryption != EncryptionStatus.ENCRYPTED:
                findings.append(AssessmentFinding(
                    id=hashlib.sha256(f"enc_{job.id}".encode()).hexdigest()[:16],
                    category="Encryption",
                    title="Unencrypted Backup Detected",
                    description=f"Backup job {job.id} for {job.target_name} is not encrypted",
                    risk_level=RiskLevel.HIGH,
                    affected_systems=[job.target_name],
                    recommendation="Enable encryption for all backup jobs",
                    compliance_reference="PCI-DSS 3.4, HIPAA §164.312(a)(2)(iv)"
                ))
            
            # Check verification
            if not job.verified and job.success:
                findings.append(AssessmentFinding(
                    id=hashlib.sha256(f"ver_{job.id}".encode()).hexdigest()[:16],
                    category="Verification",
                    title="Unverified Backup",
                    description=f"Backup job {job.id} completed but not verified",
                    risk_level=RiskLevel.MEDIUM,
                    affected_systems=[job.target_name],
                    recommendation="Enable automatic backup verification"
                ))
        
        # Check targets
        for target in self.targets.values():
            # Check RPO compliance
            if not self._check_rpo_compliance(target):
                findings.append(AssessmentFinding(
                    id=hashlib.sha256(f"rpo_{target.id}".encode()).hexdigest()[:16],
                    category="RPO Compliance",
                    title="RPO Violation",
                    description=f"System {target.name} has not been backed up within RPO window ({target.rpo_hours}h)",
                    risk_level=RiskLevel.CRITICAL,
                    affected_systems=[target.name],
                    recommendation=f"Ensure backups run at least every {target.rpo_hours} hours"
                ))
            
            # Check critical systems
            if target.criticality == "critical" and not target.last_backup:
                findings.append(AssessmentFinding(
                    id=hashlib.sha256(f"crit_{target.id}".encode()).hexdigest()[:16],
                    category="Critical Systems",
                    title="Critical System Without Backup",
                    description=f"Critical system {target.name} has no recorded backups",
                    risk_level=RiskLevel.CRITICAL,
                    affected_systems=[target.name],
                    recommendation="Immediately configure and run backup for critical systems"
                ))
        
        # Check storage
        for storage in self.storage.values():
            # Check capacity
            usage_percent = (storage.used_gb / storage.capacity_gb) * 100 if storage.capacity_gb > 0 else 0
            if usage_percent > 85:
                findings.append(AssessmentFinding(
                    id=hashlib.sha256(f"cap_{storage.id}".encode()).hexdigest()[:16],
                    category="Storage Capacity",
                    title="Storage Capacity Warning",
                    description=f"Storage {storage.name} is {usage_percent:.1f}% full",
                    risk_level=RiskLevel.HIGH if usage_percent > 95 else RiskLevel.MEDIUM,
                    affected_systems=[storage.name],
                    recommendation="Expand storage capacity or implement data retention policies"
                ))
            
            # Check air-gap and immutability for ransomware protection
            if not storage.air_gapped and not storage.immutable:
                findings.append(AssessmentFinding(
                    id=hashlib.sha256(f"rw_{storage.id}".encode()).hexdigest()[:16],
                    category="Ransomware Protection",
                    title="Missing Ransomware Protection",
                    description=f"Storage {storage.name} lacks air-gap or immutability protection",
                    risk_level=RiskLevel.HIGH,
                    affected_systems=[storage.name],
                    recommendation="Implement air-gapped or immutable backup copies"
                ))
        
        # Check DR plans
        for plan in self.dr_plans.values():
            # Check testing
            if not plan.last_tested:
                findings.append(AssessmentFinding(
                    id=hashlib.sha256(f"dr_test_{plan.id}".encode()).hexdigest()[:16],
                    category="DR Testing",
                    title="DR Plan Never Tested",
                    description=f"DR Plan '{plan.name}' has never been tested",
                    risk_level=RiskLevel.CRITICAL,
                    affected_systems=plan.scope,
                    recommendation="Schedule and execute DR test immediately"
                ))
            elif (datetime.now() - plan.last_tested).days > 365:
                findings.append(AssessmentFinding(
                    id=hashlib.sha256(f"dr_old_{plan.id}".encode()).hexdigest()[:16],
                    category="DR Testing",
                    title="DR Plan Testing Overdue",
                    description=f"DR Plan '{plan.name}' has not been tested in over a year",
                    risk_level=RiskLevel.HIGH,
                    affected_systems=plan.scope,
                    recommendation="Schedule DR test within 30 days"
                ))
        
        self.findings = findings
        
        # Calculate overall health score
        health_score = self._calculate_health_score(findings)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "health_score": health_score,
            "total_findings": len(findings),
            "by_severity": {
                "critical": sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL),
                "high": sum(1 for f in findings if f.risk_level == RiskLevel.HIGH),
                "medium": sum(1 for f in findings if f.risk_level == RiskLevel.MEDIUM),
                "low": sum(1 for f in findings if f.risk_level == RiskLevel.LOW)
            },
            "by_category": self._group_findings_by_category(findings),
            "findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "title": f.title,
                    "risk_level": f.risk_level.value,
                    "affected_systems": f.affected_systems,
                    "recommendation": f.recommendation
                }
                for f in findings
            ]
        }
    
    def _calculate_health_score(self, findings: List[AssessmentFinding]) -> float:
        """Calculate backup health score (0-100)"""
        if not findings:
            return 100.0
        
        deductions = {
            RiskLevel.CRITICAL: 25,
            RiskLevel.HIGH: 15,
            RiskLevel.MEDIUM: 5,
            RiskLevel.LOW: 2
        }
        
        total_deduction = sum(deductions[f.risk_level] for f in findings)
        return max(0, 100 - total_deduction)
    
    def _group_findings_by_category(self, findings: List[AssessmentFinding]) -> Dict[str, int]:
        """Group findings by category"""
        result = {}
        for f in findings:
            result[f.category] = result.get(f.category, 0) + 1
        return result
    
    async def record_recovery_test(
        self,
        name: str,
        dr_plan_id: str,
        test_type: str,
        systems_tested: List[str],
        actual_rto_minutes: int,
        actual_rpo_minutes: int,
        success: bool,
        issues_found: List[str],
        lessons_learned: List[str],
        participants: List[str]
    ) -> RecoveryTest:
        """Record a DR recovery test"""
        if dr_plan_id not in self.dr_plans:
            raise ValueError(f"Unknown DR plan: {dr_plan_id}")
        
        test_id = hashlib.sha256(
            f"{dr_plan_id}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        test = RecoveryTest(
            id=test_id,
            name=name,
            dr_plan_id=dr_plan_id,
            test_type=test_type,
            start_time=datetime.now() - timedelta(minutes=actual_rto_minutes),
            end_time=datetime.now(),
            systems_tested=systems_tested,
            actual_rto=actual_rto_minutes,
            actual_rpo=actual_rpo_minutes,
            success=success,
            issues_found=issues_found,
            lessons_learned=lessons_learned,
            participants=participants
        )
        
        self.tests.append(test)
        
        # Update DR plan
        plan = self.dr_plans[dr_plan_id]
        plan.last_tested = datetime.now()
        plan.test_results = {
            "test_id": test_id,
            "success": success,
            "actual_rto": actual_rto_minutes,
            "actual_rpo": actual_rpo_minutes,
            "met_rto": actual_rto_minutes <= plan.rto_target * 60,
            "met_rpo": actual_rpo_minutes <= plan.rpo_target * 60
        }
        
        return test
    
    async def get_backup_summary(self) -> Dict[str, Any]:
        """Get backup infrastructure summary"""
        # Calculate job statistics
        recent_jobs = [j for j in self.jobs if 
                      (datetime.now() - j.start_time).days <= 30]
        
        success_rate = (
            sum(1 for j in recent_jobs if j.success) / len(recent_jobs) * 100
            if recent_jobs else 0
        )
        
        total_size = sum(j.size_bytes for j in recent_jobs if j.success)
        
        # Calculate storage usage
        total_capacity = sum(s.capacity_gb for s in self.storage.values())
        total_used = sum(s.used_gb for s in self.storage.values())
        
        # Critical systems status
        critical_systems = [t for t in self.targets.values() if t.criticality == "critical"]
        critical_protected = sum(
            1 for t in critical_systems if t.last_backup and
            (datetime.now() - t.last_backup).total_seconds() / 3600 <= t.rpo_hours
        )
        
        return {
            "timestamp": datetime.now().isoformat(),
            "targets": {
                "total": len(self.targets),
                "critical": len(critical_systems),
                "critical_protected": critical_protected
            },
            "jobs": {
                "total_30_days": len(recent_jobs),
                "success_rate": round(success_rate, 1),
                "total_size_gb": round(total_size / (1024**3), 2),
                "failed_last_24h": sum(
                    1 for j in recent_jobs if not j.success and
                    (datetime.now() - j.start_time).days < 1
                )
            },
            "storage": {
                "locations": len(self.storage),
                "total_capacity_gb": round(total_capacity, 2),
                "used_gb": round(total_used, 2),
                "utilization_percent": round(total_used / total_capacity * 100, 1) if total_capacity > 0 else 0,
                "encrypted": sum(1 for s in self.storage.values() if s.encryption == EncryptionStatus.ENCRYPTED),
                "air_gapped": sum(1 for s in self.storage.values() if s.air_gapped),
                "immutable": sum(1 for s in self.storage.values() if s.immutable)
            },
            "dr_plans": {
                "total": len(self.dr_plans),
                "tested_this_year": sum(
                    1 for p in self.dr_plans.values()
                    if p.last_tested and (datetime.now() - p.last_tested).days <= 365
                )
            },
            "findings": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.risk_level == RiskLevel.CRITICAL),
                "unresolved": sum(1 for f in self.findings if not f.resolved)
            }
        }
    
    async def generate_compliance_report(
        self,
        frameworks: List[str]
    ) -> Dict[str, Any]:
        """Generate backup compliance report for specified frameworks"""
        results = {}
        
        for framework in frameworks:
            framework_results = {
                "framework": framework,
                "checks": [],
                "compliant": 0,
                "non_compliant": 0
            }
            
            for rule_name, rule in self.compliance_rules.items():
                if framework in rule.get("frameworks", []):
                    # Run check based on rule type
                    passed = True
                    details = []
                    
                    # Check all relevant objects
                    if "job" in rule_name or "verification" in rule_name or "retention" in rule_name:
                        for job in self.jobs[-50:]:
                            if not rule["check"](job):
                                passed = False
                                details.append(f"Job {job.id} failed check")
                    
                    elif "storage" in rule_name or "air_gap" in rule_name or "immutable" in rule_name:
                        for storage in self.storage.values():
                            if not rule["check"](storage):
                                passed = False
                                details.append(f"Storage {storage.name} failed check")
                    
                    elif "dr_testing" in rule_name:
                        for plan in self.dr_plans.values():
                            if not rule["check"](plan):
                                passed = False
                                details.append(f"DR Plan {plan.name} failed check")
                    
                    elif "rpo" in rule_name:
                        for target in self.targets.values():
                            if not rule["check"](target):
                                passed = False
                                details.append(f"Target {target.name} failed RPO check")
                    
                    framework_results["checks"].append({
                        "rule": rule_name,
                        "description": rule["description"],
                        "passed": passed,
                        "details": details[:5]  # Limit details
                    })
                    
                    if passed:
                        framework_results["compliant"] += 1
                    else:
                        framework_results["non_compliant"] += 1
            
            total_checks = framework_results["compliant"] + framework_results["non_compliant"]
            framework_results["compliance_score"] = round(
                framework_results["compliant"] / total_checks * 100 if total_checks > 0 else 0, 1
            )
            
            results[framework] = framework_results
        
        return {
            "generated_at": datetime.now().isoformat(),
            "frameworks_assessed": frameworks,
            "results": results
        }
