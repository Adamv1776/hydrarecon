"""
HydraRecon Configuration Baseline Manager Module
Enterprise configuration baseline management and compliance checking
"""

import asyncio
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class BaselineType(Enum):
    """Configuration baseline types"""
    CIS = "cis"
    STIG = "stig"
    NIST = "nist"
    CUSTOM = "custom"
    VENDOR = "vendor"
    INDUSTRY = "industry"


class ComplianceLevel(Enum):
    """Compliance levels"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class Severity(Enum):
    """Configuration finding severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AssetCategory(Enum):
    """Asset categories for baselines"""
    OPERATING_SYSTEM = "operating_system"
    DATABASE = "database"
    WEB_SERVER = "web_server"
    NETWORK_DEVICE = "network_device"
    CONTAINER = "container"
    CLOUD = "cloud"
    APPLICATION = "application"
    ENDPOINT = "endpoint"


class CheckType(Enum):
    """Configuration check types"""
    REGISTRY = "registry"
    FILE = "file"
    SERVICE = "service"
    PROCESS = "process"
    NETWORK = "network"
    USER = "user"
    PERMISSION = "permission"
    POLICY = "policy"
    COMMAND = "command"


class RemediationStatus(Enum):
    """Remediation status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    DEFERRED = "deferred"
    ACCEPTED_RISK = "accepted_risk"


@dataclass
class ConfigurationCheck:
    """Configuration check definition"""
    check_id: str
    name: str
    description: str
    check_type: CheckType
    severity: Severity
    baseline_type: BaselineType
    category: AssetCategory
    created_at: datetime = field(default_factory=datetime.now)
    
    expected_value: Any = None
    check_command: str = ""
    remediation_command: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cis_control: str = ""
    nist_control: str = ""
    rationale: str = ""


@dataclass
class BaselineProfile:
    """Configuration baseline profile"""
    profile_id: str
    name: str
    version: str
    baseline_type: BaselineType
    category: AssetCategory
    description: str
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    checks: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    author: str = ""
    applicable_versions: List[str] = field(default_factory=list)


@dataclass
class ConfigurationResult:
    """Configuration check result"""
    result_id: str
    check_id: str
    asset_id: str
    status: ComplianceLevel
    actual_value: Any
    expected_value: Any
    scan_time: datetime = field(default_factory=datetime.now)
    
    message: str = ""
    evidence: str = ""
    remediation_status: RemediationStatus = RemediationStatus.PENDING


@dataclass
class BaselineScan:
    """Baseline scan record"""
    scan_id: str
    profile_id: str
    asset_id: str
    asset_name: str
    status: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    
    results: List[str] = field(default_factory=list)
    compliant_count: int = 0
    non_compliant_count: int = 0
    partial_count: int = 0
    error_count: int = 0
    compliance_score: float = 0.0


@dataclass
class RemediationTask:
    """Remediation task"""
    task_id: str
    result_id: str
    check_id: str
    asset_id: str
    status: RemediationStatus
    priority: Severity
    assigned_to: str
    created_at: datetime = field(default_factory=datetime.now)
    
    due_date: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    notes: str = ""
    verification_result: Optional[str] = None


@dataclass
class ComplianceReport:
    """Compliance report"""
    report_id: str
    name: str
    scan_ids: List[str]
    generated_at: datetime = field(default_factory=datetime.now)
    
    overall_score: float = 0.0
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, float] = field(default_factory=dict)
    trending: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class ConfigurationBaselineEngine:
    """Enterprise Configuration Baseline Manager"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "config_baselines.db"
        self.checks: Dict[str, ConfigurationCheck] = {}
        self.profiles: Dict[str, BaselineProfile] = {}
        self.results: Dict[str, ConfigurationResult] = {}
        self.scans: Dict[str, BaselineScan] = {}
        self.tasks: Dict[str, RemediationTask] = {}
        self.reports: Dict[str, ComplianceReport] = {}
        
        # Load default baseline checks
        self._initialize_default_checks()
    
    def _initialize_default_checks(self):
        """Initialize default configuration checks"""
        # Windows CIS checks
        windows_checks = [
            ConfigurationCheck(
                check_id="CIS-WIN-1.1.1",
                name="Password History",
                description="Ensure 'Enforce password history' is set to '24 or more password(s)'",
                check_type=CheckType.POLICY,
                severity=Severity.MEDIUM,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                expected_value=24,
                cis_control="CIS-5.1",
                nist_control="IA-5",
                rationale="Password history reduces the effectiveness of password reuse attacks"
            ),
            ConfigurationCheck(
                check_id="CIS-WIN-1.1.2",
                name="Maximum Password Age",
                description="Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
                check_type=CheckType.POLICY,
                severity=Severity.MEDIUM,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                expected_value=365,
                cis_control="CIS-5.1",
                nist_control="IA-5"
            ),
            ConfigurationCheck(
                check_id="CIS-WIN-1.1.3",
                name="Minimum Password Age",
                description="Ensure 'Minimum password age' is set to '1 or more day(s)'",
                check_type=CheckType.POLICY,
                severity=Severity.MEDIUM,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                expected_value=1,
                cis_control="CIS-5.1"
            ),
            ConfigurationCheck(
                check_id="CIS-WIN-1.1.4",
                name="Minimum Password Length",
                description="Ensure 'Minimum password length' is set to '14 or more character(s)'",
                check_type=CheckType.POLICY,
                severity=Severity.HIGH,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                expected_value=14,
                cis_control="CIS-5.1",
                nist_control="IA-5"
            ),
            ConfigurationCheck(
                check_id="CIS-WIN-2.3.1",
                name="Guest Account Status",
                description="Ensure 'Accounts: Guest account status' is set to 'Disabled'",
                check_type=CheckType.POLICY,
                severity=Severity.HIGH,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                expected_value="Disabled",
                cis_control="CIS-5.3"
            ),
            ConfigurationCheck(
                check_id="CIS-WIN-9.1.1",
                name="Windows Firewall Domain Profile",
                description="Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'",
                check_type=CheckType.SERVICE,
                severity=Severity.HIGH,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                expected_value="On",
                cis_control="CIS-13.1"
            ),
            ConfigurationCheck(
                check_id="CIS-WIN-17.1.1",
                name="Credential Validation Audit",
                description="Ensure 'Audit Credential Validation' is set to 'Success and Failure'",
                check_type=CheckType.POLICY,
                severity=Severity.MEDIUM,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                expected_value="Success and Failure",
                cis_control="CIS-8.2"
            )
        ]
        
        # Linux CIS checks
        linux_checks = [
            ConfigurationCheck(
                check_id="CIS-LNX-1.1.1",
                name="Cramfs Disabled",
                description="Ensure mounting of cramfs filesystems is disabled",
                check_type=CheckType.FILE,
                severity=Severity.LOW,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                check_command="modprobe -n -v cramfs",
                expected_value="install /bin/true"
            ),
            ConfigurationCheck(
                check_id="CIS-LNX-1.4.1",
                name="GRUB Bootloader Password",
                description="Ensure bootloader password is set",
                check_type=CheckType.FILE,
                severity=Severity.HIGH,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                check_command="grep 'password' /boot/grub/grub.cfg"
            ),
            ConfigurationCheck(
                check_id="CIS-LNX-4.1.1",
                name="Auditd Enabled",
                description="Ensure auditd is installed and enabled",
                check_type=CheckType.SERVICE,
                severity=Severity.HIGH,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                expected_value="enabled",
                cis_control="CIS-8.2"
            ),
            ConfigurationCheck(
                check_id="CIS-LNX-5.2.1",
                name="SSH Protocol Version",
                description="Ensure SSH Protocol is set to 2",
                check_type=CheckType.FILE,
                severity=Severity.HIGH,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                check_command="grep '^Protocol' /etc/ssh/sshd_config",
                expected_value="Protocol 2"
            ),
            ConfigurationCheck(
                check_id="CIS-LNX-5.2.2",
                name="SSH Root Login",
                description="Ensure SSH root login is disabled",
                check_type=CheckType.FILE,
                severity=Severity.HIGH,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                check_command="grep '^PermitRootLogin' /etc/ssh/sshd_config",
                expected_value="PermitRootLogin no"
            ),
            ConfigurationCheck(
                check_id="CIS-LNX-5.4.1",
                name="Password Expiration",
                description="Ensure password expiration is 365 days or less",
                check_type=CheckType.FILE,
                severity=Severity.MEDIUM,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                check_command="grep PASS_MAX_DAYS /etc/login.defs",
                expected_value="365"
            )
        ]
        
        # Database checks
        db_checks = [
            ConfigurationCheck(
                check_id="CIS-SQL-1.1",
                name="SQL Server Authentication Mode",
                description="Ensure SQL Server Authentication is disabled",
                check_type=CheckType.COMMAND,
                severity=Severity.HIGH,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.DATABASE,
                expected_value="Windows Authentication"
            ),
            ConfigurationCheck(
                check_id="CIS-SQL-2.1",
                name="SA Account Disabled",
                description="Ensure 'sa' account is disabled",
                check_type=CheckType.USER,
                severity=Severity.CRITICAL,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.DATABASE,
                expected_value="Disabled"
            ),
            ConfigurationCheck(
                check_id="CIS-SQL-3.1",
                name="Database Backup Encryption",
                description="Ensure database backups are encrypted",
                check_type=CheckType.POLICY,
                severity=Severity.HIGH,
                baseline_type=BaselineType.CIS,
                category=AssetCategory.DATABASE,
                expected_value="Enabled"
            )
        ]
        
        # Add all checks
        for check in windows_checks + linux_checks + db_checks:
            self.checks[check.check_id] = check
        
        # Create default profiles
        self._create_default_profiles()
    
    def _create_default_profiles(self):
        """Create default baseline profiles"""
        profiles = [
            BaselineProfile(
                profile_id="PROF-WIN-CIS-L1",
                name="CIS Windows Server 2019 Level 1",
                version="1.2.0",
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                description="CIS Benchmark for Windows Server 2019 - Level 1",
                checks=[c for c in self.checks.keys() if c.startswith("CIS-WIN")],
                applicable_versions=["Windows Server 2019", "Windows Server 2022"]
            ),
            BaselineProfile(
                profile_id="PROF-LNX-CIS-L1",
                name="CIS Linux Level 1",
                version="2.0.0",
                baseline_type=BaselineType.CIS,
                category=AssetCategory.OPERATING_SYSTEM,
                description="CIS Benchmark for Linux distributions - Level 1",
                checks=[c for c in self.checks.keys() if c.startswith("CIS-LNX")]
            ),
            BaselineProfile(
                profile_id="PROF-SQL-CIS",
                name="CIS SQL Server Benchmark",
                version="1.4.0",
                baseline_type=BaselineType.CIS,
                category=AssetCategory.DATABASE,
                description="CIS Benchmark for SQL Server",
                checks=[c for c in self.checks.keys() if c.startswith("CIS-SQL")]
            )
        ]
        
        for profile in profiles:
            self.profiles[profile.profile_id] = profile
    
    async def create_check(self, check: ConfigurationCheck) -> ConfigurationCheck:
        """Create a new configuration check"""
        self.checks[check.check_id] = check
        return check
    
    async def get_check(self, check_id: str) -> Optional[ConfigurationCheck]:
        """Get configuration check by ID"""
        return self.checks.get(check_id)
    
    async def list_checks(self, 
                          baseline_type: Optional[BaselineType] = None,
                          category: Optional[AssetCategory] = None,
                          severity: Optional[Severity] = None) -> List[ConfigurationCheck]:
        """List configuration checks with optional filters"""
        checks = list(self.checks.values())
        
        if baseline_type:
            checks = [c for c in checks if c.baseline_type == baseline_type]
        if category:
            checks = [c for c in checks if c.category == category]
        if severity:
            checks = [c for c in checks if c.severity == severity]
        
        return checks
    
    async def create_profile(self, profile: BaselineProfile) -> BaselineProfile:
        """Create a new baseline profile"""
        self.profiles[profile.profile_id] = profile
        return profile
    
    async def get_profile(self, profile_id: str) -> Optional[BaselineProfile]:
        """Get baseline profile by ID"""
        return self.profiles.get(profile_id)
    
    async def list_profiles(self, 
                            baseline_type: Optional[BaselineType] = None,
                            category: Optional[AssetCategory] = None) -> List[BaselineProfile]:
        """List baseline profiles with optional filters"""
        profiles = list(self.profiles.values())
        
        if baseline_type:
            profiles = [p for p in profiles if p.baseline_type == baseline_type]
        if category:
            profiles = [p for p in profiles if p.category == category]
        
        return profiles
    
    async def run_scan(self, profile_id: str, asset_id: str, asset_name: str) -> BaselineScan:
        """Run baseline scan against an asset"""
        profile = await self.get_profile(profile_id)
        if not profile:
            raise ValueError(f"Profile not found: {profile_id}")
        
        scan = BaselineScan(
            scan_id=f"SCAN-{datetime.now().strftime('%Y%m%d%H%M%S')}-{asset_id[:8]}",
            profile_id=profile_id,
            asset_id=asset_id,
            asset_name=asset_name,
            status="running"
        )
        
        self.scans[scan.scan_id] = scan
        
        # Simulate check execution
        for check_id in profile.checks:
            if check_id in profile.exclusions:
                continue
            
            check = self.checks.get(check_id)
            if not check:
                continue
            
            # Simulate result (in real implementation, would execute actual checks)
            result = await self._execute_check(check, asset_id)
            self.results[result.result_id] = result
            scan.results.append(result.result_id)
            
            if result.status == ComplianceLevel.COMPLIANT:
                scan.compliant_count += 1
            elif result.status == ComplianceLevel.NON_COMPLIANT:
                scan.non_compliant_count += 1
            elif result.status == ComplianceLevel.PARTIAL:
                scan.partial_count += 1
            else:
                scan.error_count += 1
        
        # Calculate compliance score
        total = scan.compliant_count + scan.non_compliant_count + scan.partial_count
        if total > 0:
            scan.compliance_score = (scan.compliant_count + (scan.partial_count * 0.5)) / total * 100
        
        scan.end_time = datetime.now()
        scan.status = "completed"
        
        return scan
    
    async def _execute_check(self, check: ConfigurationCheck, asset_id: str) -> ConfigurationResult:
        """Execute a configuration check (simulated)"""
        import random
        
        # Simulate compliance status
        rand = random.random()
        if rand < 0.7:
            status = ComplianceLevel.COMPLIANT
            actual = check.expected_value
        elif rand < 0.9:
            status = ComplianceLevel.NON_COMPLIANT
            actual = "Non-compliant value"
        else:
            status = ComplianceLevel.PARTIAL
            actual = "Partial compliance"
        
        result = ConfigurationResult(
            result_id=f"RES-{check.check_id}-{asset_id[:8]}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            check_id=check.check_id,
            asset_id=asset_id,
            status=status,
            actual_value=actual,
            expected_value=check.expected_value,
            message=f"Check {check.name}: {status.value}"
        )
        
        return result
    
    async def get_scan(self, scan_id: str) -> Optional[BaselineScan]:
        """Get scan by ID"""
        return self.scans.get(scan_id)
    
    async def list_scans(self, asset_id: Optional[str] = None) -> List[BaselineScan]:
        """List scans, optionally filtered by asset"""
        scans = list(self.scans.values())
        if asset_id:
            scans = [s for s in scans if s.asset_id == asset_id]
        return sorted(scans, key=lambda s: s.start_time, reverse=True)
    
    async def get_result(self, result_id: str) -> Optional[ConfigurationResult]:
        """Get configuration result by ID"""
        return self.results.get(result_id)
    
    async def get_scan_results(self, scan_id: str) -> List[ConfigurationResult]:
        """Get all results for a scan"""
        scan = await self.get_scan(scan_id)
        if not scan:
            return []
        
        return [self.results[r] for r in scan.results if r in self.results]
    
    async def get_non_compliant_results(self, scan_id: str) -> List[ConfigurationResult]:
        """Get non-compliant results for a scan"""
        results = await self.get_scan_results(scan_id)
        return [r for r in results if r.status == ComplianceLevel.NON_COMPLIANT]
    
    async def create_remediation_task(self, result_id: str, assigned_to: str, 
                                       due_date: Optional[datetime] = None) -> RemediationTask:
        """Create remediation task for non-compliant result"""
        result = await self.get_result(result_id)
        if not result:
            raise ValueError(f"Result not found: {result_id}")
        
        check = self.checks.get(result.check_id)
        
        task = RemediationTask(
            task_id=f"TASK-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            result_id=result_id,
            check_id=result.check_id,
            asset_id=result.asset_id,
            status=RemediationStatus.PENDING,
            priority=check.severity if check else Severity.MEDIUM,
            assigned_to=assigned_to,
            due_date=due_date
        )
        
        self.tasks[task.task_id] = task
        return task
    
    async def update_task_status(self, task_id: str, status: RemediationStatus, 
                                  notes: str = "") -> Optional[RemediationTask]:
        """Update remediation task status"""
        task = self.tasks.get(task_id)
        if not task:
            return None
        
        task.status = status
        task.notes = notes
        
        if status == RemediationStatus.COMPLETED:
            task.completed_at = datetime.now()
        
        return task
    
    async def get_pending_tasks(self, assigned_to: Optional[str] = None) -> List[RemediationTask]:
        """Get pending remediation tasks"""
        tasks = [t for t in self.tasks.values() 
                 if t.status in [RemediationStatus.PENDING, RemediationStatus.IN_PROGRESS]]
        
        if assigned_to:
            tasks = [t for t in tasks if t.assigned_to == assigned_to]
        
        return sorted(tasks, key=lambda t: (t.priority.value, t.created_at))
    
    async def generate_compliance_report(self, scan_ids: List[str]) -> ComplianceReport:
        """Generate compliance report from scans"""
        report = ComplianceReport(
            report_id=f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            name=f"Compliance Report - {datetime.now().strftime('%Y-%m-%d')}",
            scan_ids=scan_ids
        )
        
        total_compliant = 0
        total_non_compliant = 0
        total_partial = 0
        severity_counts = {s.value: 0 for s in Severity}
        
        for scan_id in scan_ids:
            scan = await self.get_scan(scan_id)
            if not scan:
                continue
            
            total_compliant += scan.compliant_count
            total_non_compliant += scan.non_compliant_count
            total_partial += scan.partial_count
            
            # Count by severity for non-compliant
            for result_id in scan.results:
                result = self.results.get(result_id)
                if result and result.status == ComplianceLevel.NON_COMPLIANT:
                    check = self.checks.get(result.check_id)
                    if check:
                        severity_counts[check.severity.value] += 1
        
        total = total_compliant + total_non_compliant + total_partial
        if total > 0:
            report.overall_score = (total_compliant + (total_partial * 0.5)) / total * 100
        
        report.by_severity = severity_counts
        
        # Generate recommendations
        if severity_counts.get("critical", 0) > 0:
            report.recommendations.append("Address critical findings immediately")
        if severity_counts.get("high", 0) > 0:
            report.recommendations.append("Prioritize high severity findings within 30 days")
        if report.overall_score < 80:
            report.recommendations.append("Compliance score below target - remediation plan needed")
        
        self.reports[report.report_id] = report
        return report
    
    async def get_asset_compliance_history(self, asset_id: str) -> List[Dict[str, Any]]:
        """Get compliance history for an asset"""
        scans = await self.list_scans(asset_id)
        
        history = []
        for scan in scans:
            history.append({
                "scan_id": scan.scan_id,
                "date": scan.start_time.isoformat(),
                "score": round(scan.compliance_score, 1),
                "compliant": scan.compliant_count,
                "non_compliant": scan.non_compliant_count
            })
        
        return history
    
    async def compare_scans(self, scan_id_1: str, scan_id_2: str) -> Dict[str, Any]:
        """Compare two scans to identify changes"""
        scan1 = await self.get_scan(scan_id_1)
        scan2 = await self.get_scan(scan_id_2)
        
        if not scan1 or not scan2:
            return {"error": "Scan not found"}
        
        results1 = {self.results[r].check_id: self.results[r] 
                    for r in scan1.results if r in self.results}
        results2 = {self.results[r].check_id: self.results[r] 
                    for r in scan2.results if r in self.results}
        
        improved = []
        regressed = []
        unchanged = []
        
        all_checks = set(results1.keys()) | set(results2.keys())
        
        for check_id in all_checks:
            r1 = results1.get(check_id)
            r2 = results2.get(check_id)
            
            if r1 and r2:
                if r1.status != r2.status:
                    if r2.status == ComplianceLevel.COMPLIANT:
                        improved.append(check_id)
                    elif r1.status == ComplianceLevel.COMPLIANT:
                        regressed.append(check_id)
                else:
                    unchanged.append(check_id)
        
        return {
            "scan_1": scan_id_1,
            "scan_2": scan_id_2,
            "score_change": scan2.compliance_score - scan1.compliance_score,
            "improved": improved,
            "regressed": regressed,
            "unchanged_count": len(unchanged),
            "summary": f"Score changed from {scan1.compliance_score:.1f}% to {scan2.compliance_score:.1f}%"
        }
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get configuration baseline statistics"""
        checks_by_severity = {}
        for check in self.checks.values():
            sev = check.severity.value
            checks_by_severity[sev] = checks_by_severity.get(sev, 0) + 1
        
        tasks_by_status = {}
        for task in self.tasks.values():
            status = task.status.value
            tasks_by_status[status] = tasks_by_status.get(status, 0) + 1
        
        recent_scans = sorted(self.scans.values(), key=lambda s: s.start_time, reverse=True)[:5]
        avg_score = sum(s.compliance_score for s in recent_scans) / len(recent_scans) if recent_scans else 0
        
        return {
            "total_checks": len(self.checks),
            "total_profiles": len(self.profiles),
            "total_scans": len(self.scans),
            "total_results": len(self.results),
            "total_tasks": len(self.tasks),
            "checks_by_severity": checks_by_severity,
            "tasks_by_status": tasks_by_status,
            "average_compliance_score": round(avg_score, 1)
        }
    
    async def export_profile(self, profile_id: str, format: str = "json") -> str:
        """Export baseline profile"""
        profile = await self.get_profile(profile_id)
        if not profile:
            return json.dumps({"error": "Profile not found"})
        
        checks = [self.checks.get(c) for c in profile.checks if c in self.checks]
        
        data = {
            "profile": {
                "id": profile.profile_id,
                "name": profile.name,
                "version": profile.version,
                "type": profile.baseline_type.value,
                "category": profile.category.value,
                "description": profile.description
            },
            "checks": [
                {
                    "id": c.check_id,
                    "name": c.name,
                    "severity": c.severity.value,
                    "description": c.description
                }
                for c in checks if c
            ],
            "export_time": datetime.now().isoformat()
        }
        
        return json.dumps(data, indent=2)
