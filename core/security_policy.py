"""
HydraRecon Security Policy Manager Module
Enterprise security policy creation, enforcement, and compliance tracking
"""

import asyncio
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import sqlite3
import logging


class PolicyType(Enum):
    """Security policy types"""
    ACCEPTABLE_USE = "acceptable_use"
    ACCESS_CONTROL = "access_control"
    PASSWORD = "password"
    DATA_CLASSIFICATION = "data_classification"
    DATA_RETENTION = "data_retention"
    ENCRYPTION = "encryption"
    NETWORK_SECURITY = "network_security"
    ENDPOINT_SECURITY = "endpoint_security"
    INCIDENT_RESPONSE = "incident_response"
    BUSINESS_CONTINUITY = "business_continuity"
    DISASTER_RECOVERY = "disaster_recovery"
    VENDOR_MANAGEMENT = "vendor_management"
    CHANGE_MANAGEMENT = "change_management"
    PHYSICAL_SECURITY = "physical_security"
    REMOTE_ACCESS = "remote_access"
    MOBILE_DEVICE = "mobile_device"
    BYOD = "byod"
    CLOUD_SECURITY = "cloud_security"
    PRIVACY = "privacy"
    SECURITY_AWARENESS = "security_awareness"


class PolicyStatus(Enum):
    """Policy lifecycle status"""
    DRAFT = "draft"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    PUBLISHED = "published"
    ACTIVE = "active"
    UNDER_REVISION = "under_revision"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class ComplianceStatus(Enum):
    """Compliance check status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    PENDING_REVIEW = "pending_review"
    EXCEPTION_GRANTED = "exception_granted"


class EnforcementLevel(Enum):
    """Policy enforcement levels"""
    MANDATORY = "mandatory"
    RECOMMENDED = "recommended"
    OPTIONAL = "optional"
    ADVISORY = "advisory"


class RiskLevel(Enum):
    """Policy violation risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class PolicyControl:
    """Individual policy control/requirement"""
    control_id: str
    title: str
    description: str
    enforcement: EnforcementLevel
    
    # Technical implementation
    technical_controls: List[str] = field(default_factory=list)
    automated_check: bool = False
    check_script: str = ""
    
    # Compliance mapping
    compliance_frameworks: Dict[str, str] = field(default_factory=dict)  # framework: control_id
    cis_control: str = ""
    nist_control: str = ""
    iso_control: str = ""
    pci_requirement: str = ""
    
    # Assessment
    testing_procedure: str = ""
    evidence_required: List[str] = field(default_factory=list)
    verification_method: str = ""
    
    # Risk
    risk_if_not_implemented: RiskLevel = RiskLevel.MEDIUM
    
    # Status
    implementation_status: str = "not_started"
    last_assessed: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "enforcement": self.enforcement.value,
            "automated_check": self.automated_check,
            "risk_if_not_implemented": self.risk_if_not_implemented.value,
            "implementation_status": self.implementation_status
        }


@dataclass
class SecurityPolicy:
    """Security policy document"""
    policy_id: str
    name: str
    policy_type: PolicyType
    version: str
    status: PolicyStatus
    
    # Content
    purpose: str = ""
    scope: str = ""
    policy_statement: str = ""
    definitions: Dict[str, str] = field(default_factory=dict)
    
    # Controls
    controls: List[PolicyControl] = field(default_factory=list)
    
    # Ownership
    owner: str = ""
    author: str = ""
    reviewers: List[str] = field(default_factory=list)
    approvers: List[str] = field(default_factory=list)
    
    # Applicability
    applies_to: List[str] = field(default_factory=list)  # Departments, roles, systems
    exceptions: List[str] = field(default_factory=list)
    
    # Dates
    effective_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # Related policies
    related_policies: List[str] = field(default_factory=list)
    parent_policy: str = ""
    
    # Compliance
    compliance_frameworks: List[str] = field(default_factory=list)
    regulatory_requirements: List[str] = field(default_factory=list)
    
    # Violations
    violation_consequences: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "policy_type": self.policy_type.value,
            "version": self.version,
            "status": self.status.value,
            "purpose": self.purpose,
            "owner": self.owner,
            "effective_date": self.effective_date.isoformat() if self.effective_date else None,
            "review_date": self.review_date.isoformat() if self.review_date else None,
            "control_count": len(self.controls),
            "compliance_frameworks": self.compliance_frameworks
        }


@dataclass
class PolicyException:
    """Policy exception request"""
    exception_id: str
    policy_id: str
    control_id: str
    requestor: str
    
    # Request details
    business_justification: str = ""
    risk_assessment: str = ""
    compensating_controls: List[str] = field(default_factory=list)
    
    # Approval
    status: str = "pending"
    approved_by: str = ""
    approval_date: Optional[datetime] = None
    
    # Duration
    start_date: datetime = field(default_factory=datetime.now)
    end_date: Optional[datetime] = None
    is_permanent: bool = False
    
    # Review
    review_frequency: str = "quarterly"
    last_review: Optional[datetime] = None
    next_review: Optional[datetime] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "exception_id": self.exception_id,
            "policy_id": self.policy_id,
            "control_id": self.control_id,
            "requestor": self.requestor,
            "status": self.status,
            "start_date": self.start_date.isoformat(),
            "end_date": self.end_date.isoformat() if self.end_date else None
        }


@dataclass
class ComplianceCheck:
    """Policy compliance check result"""
    check_id: str
    policy_id: str
    control_id: str
    target: str  # System, department, etc.
    
    # Result
    status: ComplianceStatus = ComplianceStatus.PENDING_REVIEW
    evidence: List[str] = field(default_factory=list)
    findings: str = ""
    
    # Assessment
    assessed_by: str = ""
    assessed_at: datetime = field(default_factory=datetime.now)
    assessment_method: str = ""  # manual, automated, hybrid
    
    # Remediation
    remediation_required: bool = False
    remediation_plan: str = ""
    remediation_deadline: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "policy_id": self.policy_id,
            "control_id": self.control_id,
            "target": self.target,
            "status": self.status.value,
            "assessed_at": self.assessed_at.isoformat()
        }


@dataclass
class PolicyViolation:
    """Policy violation incident"""
    violation_id: str
    policy_id: str
    control_id: str
    violator: str  # User, system, department
    
    # Details
    description: str = ""
    severity: RiskLevel = RiskLevel.MEDIUM
    evidence: List[str] = field(default_factory=list)
    
    # Detection
    detected_at: datetime = field(default_factory=datetime.now)
    detected_by: str = ""  # automated, manual, reported
    detection_method: str = ""
    
    # Response
    status: str = "open"
    assigned_to: str = ""
    investigation_notes: str = ""
    
    # Resolution
    resolution: str = ""
    resolved_at: Optional[datetime] = None
    disciplinary_action: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "violation_id": self.violation_id,
            "policy_id": self.policy_id,
            "violator": self.violator,
            "severity": self.severity.value,
            "status": self.status,
            "detected_at": self.detected_at.isoformat()
        }


@dataclass
class PolicyMetrics:
    """Policy management metrics"""
    total_policies: int = 0
    active_policies: int = 0
    policies_under_review: int = 0
    overdue_reviews: int = 0
    
    total_controls: int = 0
    automated_controls: int = 0
    manual_controls: int = 0
    
    compliance_rate: float = 0.0
    non_compliant_items: int = 0
    
    active_exceptions: int = 0
    pending_exceptions: int = 0
    
    open_violations: int = 0
    resolved_violations: int = 0
    
    # By framework
    compliance_by_framework: Dict[str, float] = field(default_factory=dict)


class SecurityPolicyEngine:
    """Security Policy Management Engine"""
    
    def __init__(self, db_path: str = "security_policies.db"):
        self.db_path = db_path
        self.logger = logging.getLogger("SecurityPolicyEngine")
        self.policies: Dict[str, SecurityPolicy] = {}
        self.exceptions: Dict[str, PolicyException] = {}
        self.compliance_checks: Dict[str, ComplianceCheck] = {}
        self.violations: Dict[str, PolicyViolation] = {}
        
        # Initialize database
        self._init_database()
        self._init_default_policies()
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Policies table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                policy_type TEXT NOT NULL,
                version TEXT,
                status TEXT NOT NULL,
                purpose TEXT,
                scope TEXT,
                policy_statement TEXT,
                definitions TEXT,
                owner TEXT,
                author TEXT,
                reviewers TEXT,
                approvers TEXT,
                applies_to TEXT,
                exceptions TEXT,
                effective_date TIMESTAMP,
                review_date TIMESTAMP,
                expiry_date TIMESTAMP,
                related_policies TEXT,
                parent_policy TEXT,
                compliance_frameworks TEXT,
                regulatory_requirements TEXT,
                violation_consequences TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        """)
        
        # Controls table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policy_controls (
                control_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                enforcement TEXT,
                technical_controls TEXT,
                automated_check INTEGER,
                check_script TEXT,
                compliance_frameworks TEXT,
                cis_control TEXT,
                nist_control TEXT,
                iso_control TEXT,
                pci_requirement TEXT,
                testing_procedure TEXT,
                evidence_required TEXT,
                verification_method TEXT,
                risk_if_not_implemented TEXT,
                implementation_status TEXT,
                last_assessed TIMESTAMP,
                FOREIGN KEY (policy_id) REFERENCES security_policies(policy_id)
            )
        """)
        
        # Exceptions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policy_exceptions (
                exception_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                control_id TEXT NOT NULL,
                requestor TEXT NOT NULL,
                business_justification TEXT,
                risk_assessment TEXT,
                compensating_controls TEXT,
                status TEXT,
                approved_by TEXT,
                approval_date TIMESTAMP,
                start_date TIMESTAMP,
                end_date TIMESTAMP,
                is_permanent INTEGER,
                review_frequency TEXT,
                last_review TIMESTAMP,
                next_review TIMESTAMP,
                created_at TIMESTAMP,
                FOREIGN KEY (policy_id) REFERENCES security_policies(policy_id)
            )
        """)
        
        # Compliance checks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_checks (
                check_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                control_id TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT,
                evidence TEXT,
                findings TEXT,
                assessed_by TEXT,
                assessed_at TIMESTAMP,
                assessment_method TEXT,
                remediation_required INTEGER,
                remediation_plan TEXT,
                remediation_deadline TIMESTAMP,
                FOREIGN KEY (policy_id) REFERENCES security_policies(policy_id)
            )
        """)
        
        # Violations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policy_violations (
                violation_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                control_id TEXT NOT NULL,
                violator TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                evidence TEXT,
                detected_at TIMESTAMP,
                detected_by TEXT,
                detection_method TEXT,
                status TEXT,
                assigned_to TEXT,
                investigation_notes TEXT,
                resolution TEXT,
                resolved_at TIMESTAMP,
                disciplinary_action TEXT,
                FOREIGN KEY (policy_id) REFERENCES security_policies(policy_id)
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_type ON security_policies(policy_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_status ON security_policies(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_control_policy ON policy_controls(policy_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_exception_status ON policy_exceptions(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_violation_status ON policy_violations(status)")
        
        conn.commit()
        conn.close()
    
    def _init_default_policies(self):
        """Initialize default security policies"""
        # Password Policy
        password_policy = SecurityPolicy(
            policy_id="POL-001",
            name="Password Security Policy",
            policy_type=PolicyType.PASSWORD,
            version="1.0",
            status=PolicyStatus.ACTIVE,
            purpose="Establish requirements for creating and managing passwords to protect organizational systems and data.",
            scope="All employees, contractors, and third-party users with access to organizational systems.",
            owner="CISO",
            effective_date=datetime.now(),
            review_date=datetime.now() + timedelta(days=365),
            compliance_frameworks=["NIST 800-53", "PCI-DSS", "ISO 27001"]
        )
        
        # Add controls
        password_policy.controls = [
            PolicyControl(
                control_id="POL-001-C01",
                title="Minimum Password Length",
                description="Passwords must be at least 12 characters in length.",
                enforcement=EnforcementLevel.MANDATORY,
                automated_check=True,
                nist_control="IA-5",
                pci_requirement="8.2.3",
                risk_if_not_implemented=RiskLevel.HIGH
            ),
            PolicyControl(
                control_id="POL-001-C02",
                title="Password Complexity",
                description="Passwords must contain uppercase, lowercase, numbers, and special characters.",
                enforcement=EnforcementLevel.MANDATORY,
                automated_check=True,
                nist_control="IA-5",
                risk_if_not_implemented=RiskLevel.HIGH
            ),
            PolicyControl(
                control_id="POL-001-C03",
                title="Password Expiration",
                description="Passwords must be changed every 90 days.",
                enforcement=EnforcementLevel.MANDATORY,
                automated_check=True,
                pci_requirement="8.2.4",
                risk_if_not_implemented=RiskLevel.MEDIUM
            ),
            PolicyControl(
                control_id="POL-001-C04",
                title="Password History",
                description="Users cannot reuse any of their last 12 passwords.",
                enforcement=EnforcementLevel.MANDATORY,
                automated_check=True,
                pci_requirement="8.2.5",
                risk_if_not_implemented=RiskLevel.MEDIUM
            ),
            PolicyControl(
                control_id="POL-001-C05",
                title="Multi-Factor Authentication",
                description="MFA is required for all privileged access and remote connections.",
                enforcement=EnforcementLevel.MANDATORY,
                automated_check=True,
                nist_control="IA-2(1)",
                pci_requirement="8.3",
                risk_if_not_implemented=RiskLevel.CRITICAL
            )
        ]
        
        self.policies["POL-001"] = password_policy
        
        # Access Control Policy
        access_policy = SecurityPolicy(
            policy_id="POL-002",
            name="Access Control Policy",
            policy_type=PolicyType.ACCESS_CONTROL,
            version="1.0",
            status=PolicyStatus.ACTIVE,
            purpose="Define access control requirements to ensure authorized access to systems and data.",
            scope="All organizational systems, applications, and data repositories.",
            owner="CISO",
            effective_date=datetime.now(),
            review_date=datetime.now() + timedelta(days=365),
            compliance_frameworks=["NIST 800-53", "ISO 27001", "SOC 2"]
        )
        
        access_policy.controls = [
            PolicyControl(
                control_id="POL-002-C01",
                title="Principle of Least Privilege",
                description="Users must be granted only the minimum access required to perform their job functions.",
                enforcement=EnforcementLevel.MANDATORY,
                nist_control="AC-6",
                iso_control="A.9.2.3",
                risk_if_not_implemented=RiskLevel.HIGH
            ),
            PolicyControl(
                control_id="POL-002-C02",
                title="Role-Based Access Control",
                description="Access must be assigned based on user roles defined in the access matrix.",
                enforcement=EnforcementLevel.MANDATORY,
                nist_control="AC-2",
                risk_if_not_implemented=RiskLevel.HIGH
            ),
            PolicyControl(
                control_id="POL-002-C03",
                title="Access Review",
                description="User access must be reviewed quarterly by system owners.",
                enforcement=EnforcementLevel.MANDATORY,
                nist_control="AC-2(3)",
                pci_requirement="7.1.2",
                risk_if_not_implemented=RiskLevel.MEDIUM
            ),
            PolicyControl(
                control_id="POL-002-C04",
                title="Termination Access Removal",
                description="Access must be revoked within 24 hours of employee termination.",
                enforcement=EnforcementLevel.MANDATORY,
                automated_check=True,
                nist_control="AC-2(2)",
                risk_if_not_implemented=RiskLevel.CRITICAL
            )
        ]
        
        self.policies["POL-002"] = access_policy
        
        # Data Classification Policy
        data_policy = SecurityPolicy(
            policy_id="POL-003",
            name="Data Classification Policy",
            policy_type=PolicyType.DATA_CLASSIFICATION,
            version="1.0",
            status=PolicyStatus.ACTIVE,
            purpose="Establish a framework for classifying and protecting organizational data based on sensitivity.",
            scope="All data created, stored, processed, or transmitted by the organization.",
            owner="Data Protection Officer",
            effective_date=datetime.now(),
            review_date=datetime.now() + timedelta(days=365),
            compliance_frameworks=["GDPR", "HIPAA", "PCI-DSS"]
        )
        
        data_policy.controls = [
            PolicyControl(
                control_id="POL-003-C01",
                title="Data Classification Levels",
                description="All data must be classified as Public, Internal, Confidential, or Restricted.",
                enforcement=EnforcementLevel.MANDATORY,
                risk_if_not_implemented=RiskLevel.HIGH
            ),
            PolicyControl(
                control_id="POL-003-C02",
                title="Data Labeling",
                description="Confidential and Restricted data must be clearly labeled.",
                enforcement=EnforcementLevel.MANDATORY,
                risk_if_not_implemented=RiskLevel.MEDIUM
            ),
            PolicyControl(
                control_id="POL-003-C03",
                title="Data Encryption at Rest",
                description="Confidential and Restricted data must be encrypted when stored.",
                enforcement=EnforcementLevel.MANDATORY,
                automated_check=True,
                nist_control="SC-28",
                risk_if_not_implemented=RiskLevel.CRITICAL
            ),
            PolicyControl(
                control_id="POL-003-C04",
                title="Data Encryption in Transit",
                description="All data must be encrypted during transmission using TLS 1.2 or higher.",
                enforcement=EnforcementLevel.MANDATORY,
                automated_check=True,
                nist_control="SC-8",
                pci_requirement="4.1",
                risk_if_not_implemented=RiskLevel.CRITICAL
            )
        ]
        
        self.policies["POL-003"] = data_policy
    
    async def create_policy(self, policy: SecurityPolicy) -> SecurityPolicy:
        """Create a new security policy"""
        policy.created_at = datetime.now()
        policy.updated_at = datetime.now()
        
        self.policies[policy.policy_id] = policy
        await self._save_policy_to_db(policy)
        
        self.logger.info(f"Created policy: {policy.name}")
        return policy
    
    async def _save_policy_to_db(self, policy: SecurityPolicy):
        """Save policy to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO security_policies (
                policy_id, name, policy_type, version, status, purpose, scope,
                policy_statement, definitions, owner, author, reviewers, approvers,
                applies_to, exceptions, effective_date, review_date, expiry_date,
                related_policies, parent_policy, compliance_frameworks,
                regulatory_requirements, violation_consequences, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            policy.policy_id, policy.name, policy.policy_type.value, policy.version,
            policy.status.value, policy.purpose, policy.scope, policy.policy_statement,
            json.dumps(policy.definitions), policy.owner, policy.author,
            json.dumps(policy.reviewers), json.dumps(policy.approvers),
            json.dumps(policy.applies_to), json.dumps(policy.exceptions),
            policy.effective_date.isoformat() if policy.effective_date else None,
            policy.review_date.isoformat() if policy.review_date else None,
            policy.expiry_date.isoformat() if policy.expiry_date else None,
            json.dumps(policy.related_policies), policy.parent_policy,
            json.dumps(policy.compliance_frameworks), json.dumps(policy.regulatory_requirements),
            policy.violation_consequences, policy.created_at.isoformat(),
            policy.updated_at.isoformat()
        ))
        
        # Save controls
        for control in policy.controls:
            cursor.execute("""
                INSERT OR REPLACE INTO policy_controls (
                    control_id, policy_id, title, description, enforcement,
                    technical_controls, automated_check, check_script,
                    compliance_frameworks, cis_control, nist_control, iso_control,
                    pci_requirement, testing_procedure, evidence_required,
                    verification_method, risk_if_not_implemented, implementation_status,
                    last_assessed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                control.control_id, policy.policy_id, control.title, control.description,
                control.enforcement.value, json.dumps(control.technical_controls),
                int(control.automated_check), control.check_script,
                json.dumps(control.compliance_frameworks), control.cis_control,
                control.nist_control, control.iso_control, control.pci_requirement,
                control.testing_procedure, json.dumps(control.evidence_required),
                control.verification_method, control.risk_if_not_implemented.value,
                control.implementation_status,
                control.last_assessed.isoformat() if control.last_assessed else None
            ))
        
        conn.commit()
        conn.close()
    
    async def update_policy(self, policy_id: str, updates: Dict[str, Any]) -> Optional[SecurityPolicy]:
        """Update an existing policy"""
        if policy_id not in self.policies:
            return None
        
        policy = self.policies[policy_id]
        
        for key, value in updates.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        
        policy.updated_at = datetime.now()
        policy.version = self._increment_version(policy.version)
        
        await self._save_policy_to_db(policy)
        
        return policy
    
    def _increment_version(self, version: str) -> str:
        """Increment version number"""
        parts = version.split(".")
        if len(parts) >= 2:
            parts[-1] = str(int(parts[-1]) + 1)
        return ".".join(parts)
    
    async def approve_policy(self, policy_id: str, approver: str) -> bool:
        """Approve a policy"""
        if policy_id not in self.policies:
            return False
        
        policy = self.policies[policy_id]
        policy.status = PolicyStatus.APPROVED
        policy.updated_at = datetime.now()
        
        if approver not in policy.approvers:
            policy.approvers.append(approver)
        
        await self._save_policy_to_db(policy)
        return True
    
    async def publish_policy(self, policy_id: str) -> bool:
        """Publish an approved policy"""
        if policy_id not in self.policies:
            return False
        
        policy = self.policies[policy_id]
        
        if policy.status != PolicyStatus.APPROVED:
            return False
        
        policy.status = PolicyStatus.PUBLISHED
        policy.effective_date = datetime.now()
        policy.updated_at = datetime.now()
        
        await self._save_policy_to_db(policy)
        return True
    
    async def request_exception(self, exception: PolicyException) -> PolicyException:
        """Request a policy exception"""
        exception.created_at = datetime.now()
        exception.status = "pending"
        
        self.exceptions[exception.exception_id] = exception
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO policy_exceptions (
                exception_id, policy_id, control_id, requestor, business_justification,
                risk_assessment, compensating_controls, status, start_date, end_date,
                is_permanent, review_frequency, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            exception.exception_id, exception.policy_id, exception.control_id,
            exception.requestor, exception.business_justification, exception.risk_assessment,
            json.dumps(exception.compensating_controls), exception.status,
            exception.start_date.isoformat(),
            exception.end_date.isoformat() if exception.end_date else None,
            int(exception.is_permanent), exception.review_frequency,
            exception.created_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return exception
    
    async def approve_exception(self, exception_id: str, approver: str) -> bool:
        """Approve a policy exception"""
        if exception_id not in self.exceptions:
            return False
        
        exception = self.exceptions[exception_id]
        exception.status = "approved"
        exception.approved_by = approver
        exception.approval_date = datetime.now()
        exception.next_review = datetime.now() + timedelta(days=90)
        
        return True
    
    async def check_compliance(self, policy_id: str, target: str) -> List[ComplianceCheck]:
        """Check compliance for a specific policy and target"""
        if policy_id not in self.policies:
            return []
        
        policy = self.policies[policy_id]
        checks = []
        
        for control in policy.controls:
            check_id = hashlib.sha256(
                f"{policy_id}{control.control_id}{target}{datetime.now().isoformat()}".encode()
            ).hexdigest()[:16]
            
            # Simulate compliance check
            status = ComplianceStatus.COMPLIANT  # Default to compliant for demo
            
            check = ComplianceCheck(
                check_id=check_id,
                policy_id=policy_id,
                control_id=control.control_id,
                target=target,
                status=status,
                assessed_by="automated",
                assessment_method="automated" if control.automated_check else "manual"
            )
            
            checks.append(check)
            self.compliance_checks[check_id] = check
        
        return checks
    
    async def report_violation(self, violation: PolicyViolation) -> PolicyViolation:
        """Report a policy violation"""
        violation.detected_at = datetime.now()
        violation.status = "open"
        
        self.violations[violation.violation_id] = violation
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO policy_violations (
                violation_id, policy_id, control_id, violator, description,
                severity, evidence, detected_at, detected_by, detection_method,
                status, assigned_to
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            violation.violation_id, violation.policy_id, violation.control_id,
            violation.violator, violation.description, violation.severity.value,
            json.dumps(violation.evidence), violation.detected_at.isoformat(),
            violation.detected_by, violation.detection_method, violation.status,
            violation.assigned_to
        ))
        
        conn.commit()
        conn.close()
        
        self.logger.warning(f"Policy violation reported: {violation.violation_id}")
        return violation
    
    async def get_policy_metrics(self) -> PolicyMetrics:
        """Get policy management metrics"""
        metrics = PolicyMetrics()
        
        # Policy counts
        metrics.total_policies = len(self.policies)
        metrics.active_policies = sum(
            1 for p in self.policies.values() if p.status == PolicyStatus.ACTIVE
        )
        metrics.policies_under_review = sum(
            1 for p in self.policies.values() if p.status == PolicyStatus.UNDER_REVIEW
        )
        
        # Overdue reviews
        now = datetime.now()
        for policy in self.policies.values():
            if policy.review_date and policy.review_date < now:
                metrics.overdue_reviews += 1
        
        # Control counts
        for policy in self.policies.values():
            metrics.total_controls += len(policy.controls)
            metrics.automated_controls += sum(1 for c in policy.controls if c.automated_check)
            metrics.manual_controls += sum(1 for c in policy.controls if not c.automated_check)
        
        # Compliance rate
        total_checks = len(self.compliance_checks)
        compliant_checks = sum(
            1 for c in self.compliance_checks.values() if c.status == ComplianceStatus.COMPLIANT
        )
        metrics.compliance_rate = (compliant_checks / total_checks * 100) if total_checks > 0 else 100.0
        metrics.non_compliant_items = sum(
            1 for c in self.compliance_checks.values() if c.status == ComplianceStatus.NON_COMPLIANT
        )
        
        # Exceptions
        metrics.active_exceptions = sum(
            1 for e in self.exceptions.values() if e.status == "approved"
        )
        metrics.pending_exceptions = sum(
            1 for e in self.exceptions.values() if e.status == "pending"
        )
        
        # Violations
        metrics.open_violations = sum(
            1 for v in self.violations.values() if v.status == "open"
        )
        metrics.resolved_violations = sum(
            1 for v in self.violations.values() if v.status == "resolved"
        )
        
        return metrics
    
    async def search_policies(self, query: str = "", policy_type: Optional[PolicyType] = None,
                             status: Optional[PolicyStatus] = None) -> List[SecurityPolicy]:
        """Search security policies"""
        results = []
        
        for policy in self.policies.values():
            if policy_type and policy.policy_type != policy_type:
                continue
            if status and policy.status != status:
                continue
            if query:
                query_lower = query.lower()
                if not any([
                    query_lower in policy.name.lower(),
                    query_lower in policy.purpose.lower(),
                    query_lower in policy.scope.lower()
                ]):
                    continue
            
            results.append(policy)
        
        return results
    
    async def export_policy(self, policy_id: str, format: str = "json") -> str:
        """Export a policy"""
        if policy_id not in self.policies:
            return ""
        
        policy = self.policies[policy_id]
        
        if format == "json":
            data = {
                "policy": policy.to_dict(),
                "controls": [c.to_dict() for c in policy.controls],
                "exported_at": datetime.now().isoformat()
            }
            return json.dumps(data, indent=2)
        
        return ""


# Create singleton instance
security_policy_engine = SecurityPolicyEngine()
