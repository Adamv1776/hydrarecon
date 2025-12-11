#!/usr/bin/env python3
"""
HydraRecon Third-Party Risk Management Engine
Enterprise vendor security assessment and risk management.
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
import re


class VendorTier(Enum):
    """Vendor criticality tiers"""
    TIER_1 = "tier_1"  # Critical - data access, core systems
    TIER_2 = "tier_2"  # Important - significant access
    TIER_3 = "tier_3"  # Moderate - limited access
    TIER_4 = "tier_4"  # Low - minimal risk


class RiskLevel(Enum):
    """Risk level classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ACCEPTABLE = "acceptable"


class AssessmentStatus(Enum):
    """Assessment status"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class VendorStatus(Enum):
    """Vendor relationship status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    ONBOARDING = "onboarding"
    OFFBOARDING = "offboarding"
    TERMINATED = "terminated"


class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    HIGHLY_RESTRICTED = "highly_restricted"


class ComplianceFramework(Enum):
    """Compliance frameworks"""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    CCPA = "ccpa"
    NIST = "nist"
    FEDRAMP = "fedramp"


@dataclass
class Vendor:
    """Vendor profile data"""
    id: str
    name: str
    description: str
    tier: VendorTier
    status: VendorStatus
    risk_level: RiskLevel
    risk_score: float
    primary_contact: str
    contact_email: str
    contact_phone: str
    website: str
    industry: str
    country: str
    services_provided: List[str]
    data_types_accessed: List[DataClassification]
    integration_points: List[str]
    contract_start: datetime
    contract_end: datetime
    last_assessment: Optional[datetime] = None
    next_assessment: Optional[datetime] = None
    certifications: List[str] = field(default_factory=list)
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    security_contacts: List[Dict[str, str]] = field(default_factory=list)
    subprocessors: List[str] = field(default_factory=list)
    data_locations: List[str] = field(default_factory=list)
    encryption_in_transit: bool = True
    encryption_at_rest: bool = True
    incident_history: List[Dict[str, Any]] = field(default_factory=list)
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AssessmentQuestion:
    """Assessment questionnaire question"""
    id: str
    category: str
    question: str
    description: str
    weight: float
    required: bool = True
    question_type: str = "yes_no"  # yes_no, rating, text, multi_select
    options: List[str] = field(default_factory=list)
    compliance_mappings: List[str] = field(default_factory=list)


@dataclass
class AssessmentResponse:
    """Response to assessment question"""
    question_id: str
    response: str
    score: float
    evidence: List[str] = field(default_factory=list)
    notes: str = ""
    reviewer_notes: str = ""


@dataclass
class SecurityAssessment:
    """Vendor security assessment"""
    id: str
    vendor_id: str
    vendor_name: str
    assessment_type: str
    status: AssessmentStatus
    created_date: datetime
    due_date: datetime
    completed_date: Optional[datetime] = None
    assessor: str = ""
    reviewer: str = ""
    responses: List[AssessmentResponse] = field(default_factory=list)
    overall_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    remediation_required: bool = False
    remediation_items: List[Dict[str, Any]] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    approval_history: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class RiskFinding:
    """Risk finding from assessment"""
    id: str
    vendor_id: str
    assessment_id: str
    category: str
    title: str
    description: str
    severity: RiskLevel
    likelihood: str
    impact: str
    risk_score: float
    remediation_required: bool
    remediation_recommendation: str
    remediation_deadline: Optional[datetime] = None
    remediation_status: str = "open"
    compensating_controls: List[str] = field(default_factory=list)
    risk_accepted: bool = False
    accepted_by: str = ""
    accepted_date: Optional[datetime] = None
    acceptance_justification: str = ""


@dataclass
class VendorIncident:
    """Vendor security incident"""
    id: str
    vendor_id: str
    incident_date: datetime
    reported_date: datetime
    incident_type: str
    description: str
    severity: RiskLevel
    data_impacted: bool
    data_types_affected: List[DataClassification]
    root_cause: str
    remediation_actions: List[str]
    status: str
    resolution_date: Optional[datetime] = None
    lessons_learned: str = ""
    contract_impact: str = ""


class ThirdPartyRiskEngine:
    """Enterprise third-party risk management"""
    
    def __init__(self, db_path: str = "tprm.db"):
        self.db_path = db_path
        self.vendors: Dict[str, Vendor] = {}
        self.assessments: Dict[str, SecurityAssessment] = {}
        self.findings: Dict[str, RiskFinding] = {}
        self.incidents: Dict[str, VendorIncident] = {}
        self.questionnaire: List[AssessmentQuestion] = []
        self.callbacks: Dict[str, List[Callable]] = {}
        self._init_database()
        self._init_default_questionnaire()
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vendors (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                tier TEXT,
                status TEXT,
                risk_level TEXT,
                risk_score REAL,
                primary_contact TEXT,
                contact_email TEXT,
                contact_phone TEXT,
                website TEXT,
                industry TEXT,
                country TEXT,
                services_provided TEXT,
                data_types_accessed TEXT,
                integration_points TEXT,
                contract_start TEXT,
                contract_end TEXT,
                last_assessment TEXT,
                next_assessment TEXT,
                certifications TEXT,
                compliance_frameworks TEXT,
                security_contacts TEXT,
                subprocessors TEXT,
                data_locations TEXT,
                encryption_in_transit INTEGER,
                encryption_at_rest INTEGER,
                incident_history TEXT,
                notes TEXT,
                tags TEXT,
                custom_fields TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                vendor_id TEXT,
                vendor_name TEXT,
                assessment_type TEXT,
                status TEXT,
                created_date TEXT,
                due_date TEXT,
                completed_date TEXT,
                assessor TEXT,
                reviewer TEXT,
                responses TEXT,
                overall_score REAL,
                risk_level TEXT,
                findings TEXT,
                recommendations TEXT,
                remediation_required INTEGER,
                remediation_items TEXT,
                attachments TEXT,
                approval_history TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_findings (
                id TEXT PRIMARY KEY,
                vendor_id TEXT,
                assessment_id TEXT,
                category TEXT,
                title TEXT,
                description TEXT,
                severity TEXT,
                likelihood TEXT,
                impact TEXT,
                risk_score REAL,
                remediation_required INTEGER,
                remediation_recommendation TEXT,
                remediation_deadline TEXT,
                remediation_status TEXT,
                compensating_controls TEXT,
                risk_accepted INTEGER,
                accepted_by TEXT,
                accepted_date TEXT,
                acceptance_justification TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vendor_incidents (
                id TEXT PRIMARY KEY,
                vendor_id TEXT,
                incident_date TEXT,
                reported_date TEXT,
                incident_type TEXT,
                description TEXT,
                severity TEXT,
                data_impacted INTEGER,
                data_types_affected TEXT,
                root_cause TEXT,
                remediation_actions TEXT,
                status TEXT,
                resolution_date TEXT,
                lessons_learned TEXT,
                contract_impact TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _init_default_questionnaire(self):
        """Initialize default security questionnaire"""
        questions = [
            # Access Control
            AssessmentQuestion(
                id="ac_001",
                category="Access Control",
                question="Does your organization implement multi-factor authentication for all user access?",
                description="MFA should be required for all system access",
                weight=1.5,
                required=True,
                question_type="yes_no",
                compliance_mappings=["SOC2-CC6.1", "ISO27001-A.9.4.2"]
            ),
            AssessmentQuestion(
                id="ac_002",
                category="Access Control",
                question="Do you have a formal access control policy?",
                description="Document governing user access management",
                weight=1.0,
                required=True,
                question_type="yes_no",
                compliance_mappings=["SOC2-CC6.1", "ISO27001-A.9.1.1"]
            ),
            AssessmentQuestion(
                id="ac_003",
                category="Access Control",
                question="How often do you review user access privileges?",
                description="Regular access reviews are essential",
                weight=1.0,
                required=True,
                question_type="multi_select",
                options=["Monthly", "Quarterly", "Annually", "Ad-hoc", "Never"],
                compliance_mappings=["SOC2-CC6.2", "ISO27001-A.9.2.5"]
            ),
            # Data Protection
            AssessmentQuestion(
                id="dp_001",
                category="Data Protection",
                question="Is data encrypted in transit using TLS 1.2 or higher?",
                description="All data in transit must be encrypted",
                weight=2.0,
                required=True,
                question_type="yes_no",
                compliance_mappings=["SOC2-CC6.7", "PCI-DSS-4.1"]
            ),
            AssessmentQuestion(
                id="dp_002",
                category="Data Protection",
                question="Is data encrypted at rest using AES-256 or equivalent?",
                description="Sensitive data must be encrypted at rest",
                weight=2.0,
                required=True,
                question_type="yes_no",
                compliance_mappings=["SOC2-CC6.7", "PCI-DSS-3.4"]
            ),
            AssessmentQuestion(
                id="dp_003",
                category="Data Protection",
                question="Do you have a data classification policy?",
                description="Data should be classified by sensitivity",
                weight=1.0,
                required=True,
                question_type="yes_no",
                compliance_mappings=["ISO27001-A.8.2.1"]
            ),
            # Incident Response
            AssessmentQuestion(
                id="ir_001",
                category="Incident Response",
                question="Do you have a documented incident response plan?",
                description="Formal IR plan should exist",
                weight=1.5,
                required=True,
                question_type="yes_no",
                compliance_mappings=["SOC2-CC7.3", "ISO27001-A.16.1.1"]
            ),
            AssessmentQuestion(
                id="ir_002",
                category="Incident Response",
                question="What is your SLA for reporting security incidents to customers?",
                description="Notification timeline for security incidents",
                weight=1.0,
                required=True,
                question_type="multi_select",
                options=["24 hours", "48 hours", "72 hours", "1 week", "No defined SLA"],
                compliance_mappings=["GDPR-33", "SOC2-CC7.4"]
            ),
            AssessmentQuestion(
                id="ir_003",
                category="Incident Response",
                question="How often do you conduct incident response tabletop exercises?",
                description="Regular testing of IR capabilities",
                weight=1.0,
                required=True,
                question_type="multi_select",
                options=["Monthly", "Quarterly", "Annually", "Never"],
                compliance_mappings=["SOC2-CC7.3", "ISO27001-A.16.1.1"]
            ),
            # Business Continuity
            AssessmentQuestion(
                id="bc_001",
                category="Business Continuity",
                question="Do you have a business continuity plan?",
                description="Documented BCP should exist",
                weight=1.5,
                required=True,
                question_type="yes_no",
                compliance_mappings=["ISO27001-A.17.1.1"]
            ),
            AssessmentQuestion(
                id="bc_002",
                category="Business Continuity",
                question="What is your Recovery Time Objective (RTO)?",
                description="Maximum acceptable downtime",
                weight=1.0,
                required=True,
                question_type="multi_select",
                options=["< 1 hour", "1-4 hours", "4-24 hours", "24-72 hours", "> 72 hours"],
                compliance_mappings=["ISO27001-A.17.2.1"]
            ),
            # Vulnerability Management
            AssessmentQuestion(
                id="vm_001",
                category="Vulnerability Management",
                question="Do you perform regular vulnerability scans?",
                description="Automated scanning should be performed",
                weight=1.5,
                required=True,
                question_type="yes_no",
                compliance_mappings=["PCI-DSS-11.2", "SOC2-CC7.1"]
            ),
            AssessmentQuestion(
                id="vm_002",
                category="Vulnerability Management",
                question="Do you conduct annual penetration testing?",
                description="Third-party pen testing recommended",
                weight=1.5,
                required=True,
                question_type="yes_no",
                compliance_mappings=["PCI-DSS-11.3", "SOC2-CC7.1"]
            ),
            AssessmentQuestion(
                id="vm_003",
                category="Vulnerability Management",
                question="What is your SLA for remediating critical vulnerabilities?",
                description="Timeline for fixing critical issues",
                weight=1.0,
                required=True,
                question_type="multi_select",
                options=["24 hours", "48 hours", "1 week", "1 month", "No defined SLA"],
                compliance_mappings=["PCI-DSS-6.1"]
            ),
            # Compliance & Certifications
            AssessmentQuestion(
                id="cc_001",
                category="Compliance",
                question="Which security certifications does your organization hold?",
                description="Industry certifications and attestations",
                weight=1.5,
                required=True,
                question_type="multi_select",
                options=["SOC 2 Type II", "ISO 27001", "PCI DSS", "HIPAA", "FedRAMP", "None"],
                compliance_mappings=[]
            ),
            AssessmentQuestion(
                id="cc_002",
                category="Compliance",
                question="When was your last SOC 2 audit completed?",
                description="Recent audit reports should be available",
                weight=1.0,
                required=False,
                question_type="multi_select",
                options=["Within 6 months", "6-12 months", "1-2 years", "Never", "Not applicable"],
                compliance_mappings=["SOC2"]
            ),
            # Network Security
            AssessmentQuestion(
                id="ns_001",
                category="Network Security",
                question="Do you segment your network to isolate customer data?",
                description="Network segmentation reduces blast radius",
                weight=1.5,
                required=True,
                question_type="yes_no",
                compliance_mappings=["PCI-DSS-1.3", "SOC2-CC6.6"]
            ),
            AssessmentQuestion(
                id="ns_002",
                category="Network Security",
                question="Do you use a Web Application Firewall (WAF)?",
                description="WAF protects web applications",
                weight=1.0,
                required=True,
                question_type="yes_no",
                compliance_mappings=["PCI-DSS-6.6"]
            ),
            # Security Monitoring
            AssessmentQuestion(
                id="sm_001",
                category="Security Monitoring",
                question="Do you have 24/7 security monitoring?",
                description="Continuous monitoring for threats",
                weight=1.5,
                required=True,
                question_type="yes_no",
                compliance_mappings=["SOC2-CC7.2", "ISO27001-A.12.4.1"]
            ),
            AssessmentQuestion(
                id="sm_002",
                category="Security Monitoring",
                question="Do you use a SIEM solution?",
                description="Centralized log management and correlation",
                weight=1.0,
                required=True,
                question_type="yes_no",
                compliance_mappings=["PCI-DSS-10.6", "SOC2-CC7.2"]
            ),
            # Employee Security
            AssessmentQuestion(
                id="es_001",
                category="Employee Security",
                question="Do you conduct background checks on employees with access to customer data?",
                description="Pre-employment screening",
                weight=1.0,
                required=True,
                question_type="yes_no",
                compliance_mappings=["SOC2-CC1.4", "ISO27001-A.7.1.1"]
            ),
            AssessmentQuestion(
                id="es_002",
                category="Employee Security",
                question="Do you provide security awareness training to all employees?",
                description="Regular security training program",
                weight=1.0,
                required=True,
                question_type="yes_no",
                compliance_mappings=["SOC2-CC1.4", "ISO27001-A.7.2.2"]
            )
        ]
        self.questionnaire = questions
    
    async def add_vendor(
        self,
        name: str,
        description: str,
        tier: VendorTier,
        primary_contact: str,
        contact_email: str,
        services_provided: List[str],
        data_types_accessed: List[DataClassification],
        contract_start: datetime,
        contract_end: datetime,
        **kwargs
    ) -> Vendor:
        """Add a new vendor"""
        vendor_id = hashlib.sha256(
            f"{name}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Calculate initial risk based on tier and data access
        initial_risk_score = self._calculate_initial_risk(tier, data_types_accessed)
        risk_level = self._score_to_risk_level(initial_risk_score)
        
        # Calculate next assessment date based on tier
        assessment_interval = {
            VendorTier.TIER_1: 90,
            VendorTier.TIER_2: 180,
            VendorTier.TIER_3: 365,
            VendorTier.TIER_4: 730
        }
        next_assessment = datetime.now() + timedelta(days=assessment_interval[tier])
        
        vendor = Vendor(
            id=vendor_id,
            name=name,
            description=description,
            tier=tier,
            status=VendorStatus.ONBOARDING,
            risk_level=risk_level,
            risk_score=initial_risk_score,
            primary_contact=primary_contact,
            contact_email=contact_email,
            contact_phone=kwargs.get("contact_phone", ""),
            website=kwargs.get("website", ""),
            industry=kwargs.get("industry", ""),
            country=kwargs.get("country", ""),
            services_provided=services_provided,
            data_types_accessed=data_types_accessed,
            integration_points=kwargs.get("integration_points", []),
            contract_start=contract_start,
            contract_end=contract_end,
            next_assessment=next_assessment,
            certifications=kwargs.get("certifications", []),
            compliance_frameworks=kwargs.get("compliance_frameworks", []),
            security_contacts=kwargs.get("security_contacts", []),
            subprocessors=kwargs.get("subprocessors", []),
            data_locations=kwargs.get("data_locations", []),
            encryption_in_transit=kwargs.get("encryption_in_transit", True),
            encryption_at_rest=kwargs.get("encryption_at_rest", True),
            tags=kwargs.get("tags", [])
        )
        
        self.vendors[vendor_id] = vendor
        await self._save_vendor(vendor)
        await self._trigger_callback("vendor_added", vendor)
        
        return vendor
    
    def _calculate_initial_risk(
        self,
        tier: VendorTier,
        data_types: List[DataClassification]
    ) -> float:
        """Calculate initial risk score"""
        tier_scores = {
            VendorTier.TIER_1: 70,
            VendorTier.TIER_2: 50,
            VendorTier.TIER_3: 30,
            VendorTier.TIER_4: 10
        }
        
        data_scores = {
            DataClassification.HIGHLY_RESTRICTED: 30,
            DataClassification.RESTRICTED: 20,
            DataClassification.CONFIDENTIAL: 15,
            DataClassification.INTERNAL: 5,
            DataClassification.PUBLIC: 0
        }
        
        base_score = tier_scores[tier]
        data_score = max([data_scores.get(dt, 0) for dt in data_types]) if data_types else 0
        
        return min(100, base_score + data_score)
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert score to risk level"""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.ACCEPTABLE
    
    async def create_assessment(
        self,
        vendor_id: str,
        assessment_type: str = "full",
        due_date: Optional[datetime] = None,
        assessor: str = ""
    ) -> Optional[SecurityAssessment]:
        """Create a new security assessment"""
        vendor = self.vendors.get(vendor_id)
        if not vendor:
            return None
        
        assessment_id = hashlib.sha256(
            f"{vendor_id}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        if not due_date:
            due_date = datetime.now() + timedelta(days=30)
        
        assessment = SecurityAssessment(
            id=assessment_id,
            vendor_id=vendor_id,
            vendor_name=vendor.name,
            assessment_type=assessment_type,
            status=AssessmentStatus.NOT_STARTED,
            created_date=datetime.now(),
            due_date=due_date,
            assessor=assessor
        )
        
        self.assessments[assessment_id] = assessment
        await self._save_assessment(assessment)
        await self._trigger_callback("assessment_created", assessment)
        
        return assessment
    
    async def submit_assessment_response(
        self,
        assessment_id: str,
        question_id: str,
        response: str,
        evidence: Optional[List[str]] = None,
        notes: str = ""
    ) -> Optional[SecurityAssessment]:
        """Submit response to assessment question"""
        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return None
        
        # Find question
        question = next((q for q in self.questionnaire if q.id == question_id), None)
        if not question:
            return None
        
        # Calculate score based on response
        score = self._calculate_response_score(question, response)
        
        # Create response object
        response_obj = AssessmentResponse(
            question_id=question_id,
            response=response,
            score=score,
            evidence=evidence or [],
            notes=notes
        )
        
        # Update or add response
        existing_idx = next(
            (i for i, r in enumerate(assessment.responses) if r.question_id == question_id),
            None
        )
        
        if existing_idx is not None:
            assessment.responses[existing_idx] = response_obj
        else:
            assessment.responses.append(response_obj)
        
        # Update status if first response
        if assessment.status == AssessmentStatus.NOT_STARTED:
            assessment.status = AssessmentStatus.IN_PROGRESS
        
        # Check if all required questions answered
        required_questions = [q.id for q in self.questionnaire if q.required]
        answered = [r.question_id for r in assessment.responses]
        if all(q in answered for q in required_questions):
            # Calculate overall score
            assessment.overall_score = self._calculate_overall_score(assessment)
            assessment.risk_level = self._score_to_risk_level(100 - assessment.overall_score)
            assessment.status = AssessmentStatus.PENDING_REVIEW
            assessment.completed_date = datetime.now()
        
        await self._save_assessment(assessment)
        
        return assessment
    
    def _calculate_response_score(
        self,
        question: AssessmentQuestion,
        response: str
    ) -> float:
        """Calculate score for a response"""
        if question.question_type == "yes_no":
            return 100 if response.lower() == "yes" else 0
        elif question.question_type == "rating":
            try:
                return float(response)
            except ValueError:
                return 50
        elif question.question_type == "multi_select":
            # Score based on best option selected
            if question.id == "ac_003":  # Access review frequency
                scores = {"Monthly": 100, "Quarterly": 80, "Annually": 50, "Ad-hoc": 20, "Never": 0}
            elif question.id == "ir_002":  # Incident notification SLA
                scores = {"24 hours": 100, "48 hours": 80, "72 hours": 60, "1 week": 30, "No defined SLA": 0}
            elif question.id == "bc_002":  # RTO
                scores = {"< 1 hour": 100, "1-4 hours": 80, "4-24 hours": 60, "24-72 hours": 40, "> 72 hours": 20}
            elif question.id == "vm_003":  # Vuln remediation SLA
                scores = {"24 hours": 100, "48 hours": 90, "1 week": 70, "1 month": 40, "No defined SLA": 0}
            elif question.id == "cc_001":  # Certifications
                certs = response.split(",") if response else []
                return min(100, len(certs) * 25) if "None" not in certs else 0
            elif question.id == "ir_003":  # IR exercises
                scores = {"Monthly": 100, "Quarterly": 80, "Annually": 50, "Never": 0}
            else:
                return 50
            
            return scores.get(response.strip(), 50)
        
        return 50
    
    def _calculate_overall_score(self, assessment: SecurityAssessment) -> float:
        """Calculate overall assessment score"""
        if not assessment.responses:
            return 0
        
        total_weight = 0
        weighted_score = 0
        
        for response in assessment.responses:
            question = next((q for q in self.questionnaire if q.id == response.question_id), None)
            if question:
                total_weight += question.weight
                weighted_score += response.score * question.weight
        
        return round(weighted_score / total_weight, 2) if total_weight > 0 else 0
    
    async def approve_assessment(
        self,
        assessment_id: str,
        reviewer: str,
        notes: str = ""
    ) -> Optional[SecurityAssessment]:
        """Approve a completed assessment"""
        assessment = self.assessments.get(assessment_id)
        if not assessment or assessment.status != AssessmentStatus.PENDING_REVIEW:
            return None
        
        assessment.status = AssessmentStatus.APPROVED
        assessment.reviewer = reviewer
        assessment.approval_history.append({
            "action": "approved",
            "reviewer": reviewer,
            "date": datetime.now().isoformat(),
            "notes": notes
        })
        
        # Update vendor risk based on assessment
        vendor = self.vendors.get(assessment.vendor_id)
        if vendor:
            vendor.last_assessment = datetime.now()
            vendor.risk_score = 100 - assessment.overall_score
            vendor.risk_level = assessment.risk_level
            
            # Calculate next assessment based on tier
            interval = {
                VendorTier.TIER_1: 90,
                VendorTier.TIER_2: 180,
                VendorTier.TIER_3: 365,
                VendorTier.TIER_4: 730
            }
            vendor.next_assessment = datetime.now() + timedelta(days=interval[vendor.tier])
            
            if vendor.status == VendorStatus.ONBOARDING:
                vendor.status = VendorStatus.ACTIVE
            
            await self._save_vendor(vendor)
        
        await self._save_assessment(assessment)
        await self._trigger_callback("assessment_approved", assessment)
        
        return assessment
    
    async def create_finding(
        self,
        vendor_id: str,
        assessment_id: str,
        category: str,
        title: str,
        description: str,
        severity: RiskLevel,
        likelihood: str,
        impact: str,
        remediation_recommendation: str,
        remediation_required: bool = True,
        remediation_deadline: Optional[datetime] = None
    ) -> RiskFinding:
        """Create a risk finding"""
        finding_id = hashlib.sha256(
            f"{vendor_id}:{title}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Calculate risk score
        severity_scores = {
            RiskLevel.CRITICAL: 5,
            RiskLevel.HIGH: 4,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 2,
            RiskLevel.ACCEPTABLE: 1
        }
        likelihood_scores = {"very_high": 5, "high": 4, "medium": 3, "low": 2, "very_low": 1}
        impact_scores = {"critical": 5, "high": 4, "medium": 3, "low": 2, "minimal": 1}
        
        risk_score = (
            severity_scores.get(severity, 3) *
            likelihood_scores.get(likelihood.lower(), 3) *
            impact_scores.get(impact.lower(), 3)
        ) / 25 * 100
        
        if not remediation_deadline:
            deadline_days = {
                RiskLevel.CRITICAL: 7,
                RiskLevel.HIGH: 30,
                RiskLevel.MEDIUM: 90,
                RiskLevel.LOW: 180,
                RiskLevel.ACCEPTABLE: 365
            }
            remediation_deadline = datetime.now() + timedelta(days=deadline_days[severity])
        
        finding = RiskFinding(
            id=finding_id,
            vendor_id=vendor_id,
            assessment_id=assessment_id,
            category=category,
            title=title,
            description=description,
            severity=severity,
            likelihood=likelihood,
            impact=impact,
            risk_score=round(risk_score, 2),
            remediation_required=remediation_required,
            remediation_recommendation=remediation_recommendation,
            remediation_deadline=remediation_deadline
        )
        
        self.findings[finding_id] = finding
        await self._save_finding(finding)
        await self._trigger_callback("finding_created", finding)
        
        return finding
    
    async def record_incident(
        self,
        vendor_id: str,
        incident_date: datetime,
        incident_type: str,
        description: str,
        severity: RiskLevel,
        data_impacted: bool,
        data_types_affected: List[DataClassification],
        root_cause: str = "",
        remediation_actions: Optional[List[str]] = None
    ) -> Optional[VendorIncident]:
        """Record a vendor security incident"""
        vendor = self.vendors.get(vendor_id)
        if not vendor:
            return None
        
        incident_id = hashlib.sha256(
            f"{vendor_id}:{incident_date.isoformat()}:{incident_type}".encode()
        ).hexdigest()[:16]
        
        incident = VendorIncident(
            id=incident_id,
            vendor_id=vendor_id,
            incident_date=incident_date,
            reported_date=datetime.now(),
            incident_type=incident_type,
            description=description,
            severity=severity,
            data_impacted=data_impacted,
            data_types_affected=data_types_affected,
            root_cause=root_cause,
            remediation_actions=remediation_actions or [],
            status="open"
        )
        
        self.incidents[incident_id] = incident
        
        # Update vendor incident history
        vendor.incident_history.append({
            "id": incident_id,
            "date": incident_date.isoformat(),
            "type": incident_type,
            "severity": severity.value
        })
        
        # Adjust vendor risk
        severity_impact = {
            RiskLevel.CRITICAL: 30,
            RiskLevel.HIGH: 20,
            RiskLevel.MEDIUM: 10,
            RiskLevel.LOW: 5,
            RiskLevel.ACCEPTABLE: 2
        }
        vendor.risk_score = min(100, vendor.risk_score + severity_impact[severity])
        vendor.risk_level = self._score_to_risk_level(vendor.risk_score)
        
        await self._save_vendor(vendor)
        await self._save_incident(incident)
        await self._trigger_callback("incident_recorded", incident)
        
        return incident
    
    async def get_vendors_by_tier(self, tier: VendorTier) -> List[Vendor]:
        """Get vendors by tier"""
        return [v for v in self.vendors.values() if v.tier == tier]
    
    async def get_vendors_requiring_assessment(self) -> List[Vendor]:
        """Get vendors requiring assessment"""
        now = datetime.now()
        return [
            v for v in self.vendors.values()
            if v.next_assessment and v.next_assessment <= now
        ]
    
    async def get_high_risk_vendors(self) -> List[Vendor]:
        """Get high and critical risk vendors"""
        return [
            v for v in self.vendors.values()
            if v.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
        ]
    
    async def get_open_findings(self, vendor_id: Optional[str] = None) -> List[RiskFinding]:
        """Get open findings"""
        findings = list(self.findings.values())
        if vendor_id:
            findings = [f for f in findings if f.vendor_id == vendor_id]
        return [f for f in findings if f.remediation_status == "open"]
    
    async def get_overdue_findings(self) -> List[RiskFinding]:
        """Get overdue findings"""
        now = datetime.now()
        return [
            f for f in self.findings.values()
            if f.remediation_status == "open" and
               f.remediation_deadline and
               f.remediation_deadline < now
        ]
    
    async def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get TPRM dashboard statistics"""
        vendors = list(self.vendors.values())
        
        # Vendor counts
        by_tier = {}
        for tier in VendorTier:
            by_tier[tier.value] = len([v for v in vendors if v.tier == tier])
        
        by_risk = {}
        for risk in RiskLevel:
            by_risk[risk.value] = len([v for v in vendors if v.risk_level == risk])
        
        by_status = {}
        for status in VendorStatus:
            by_status[status.value] = len([v for v in vendors if v.status == status])
        
        # Assessment stats
        assessments_pending = len([
            a for a in self.assessments.values()
            if a.status in [AssessmentStatus.NOT_STARTED, AssessmentStatus.IN_PROGRESS]
        ])
        
        vendors_needing_assessment = len(await self.get_vendors_requiring_assessment())
        
        # Finding stats
        open_findings = len(await self.get_open_findings())
        overdue_findings = len(await self.get_overdue_findings())
        
        # Incident stats
        active_incidents = len([
            i for i in self.incidents.values()
            if i.status == "open"
        ])
        
        # Average risk score
        avg_risk = sum(v.risk_score for v in vendors) / len(vendors) if vendors else 0
        
        return {
            "total_vendors": len(vendors),
            "by_tier": by_tier,
            "by_risk_level": by_risk,
            "by_status": by_status,
            "assessments_pending": assessments_pending,
            "vendors_needing_assessment": vendors_needing_assessment,
            "open_findings": open_findings,
            "overdue_findings": overdue_findings,
            "active_incidents": active_incidents,
            "average_risk_score": round(avg_risk, 2)
        }
    
    async def export_vendor_report(
        self,
        vendor_id: str,
        format_type: str = "json"
    ) -> str:
        """Export vendor report"""
        vendor = self.vendors.get(vendor_id)
        if not vendor:
            return ""
        
        # Get assessments
        vendor_assessments = [
            a for a in self.assessments.values()
            if a.vendor_id == vendor_id
        ]
        
        # Get findings
        vendor_findings = [
            f for f in self.findings.values()
            if f.vendor_id == vendor_id
        ]
        
        # Get incidents
        vendor_incidents = [
            i for i in self.incidents.values()
            if i.vendor_id == vendor_id
        ]
        
        report = {
            "vendor": {
                "id": vendor.id,
                "name": vendor.name,
                "tier": vendor.tier.value,
                "status": vendor.status.value,
                "risk_level": vendor.risk_level.value,
                "risk_score": vendor.risk_score,
                "services": vendor.services_provided,
                "data_access": [d.value for d in vendor.data_types_accessed],
                "certifications": vendor.certifications,
                "contract_end": vendor.contract_end.isoformat() if vendor.contract_end else None
            },
            "assessments": [
                {
                    "id": a.id,
                    "type": a.assessment_type,
                    "status": a.status.value,
                    "score": a.overall_score,
                    "date": a.completed_date.isoformat() if a.completed_date else None
                }
                for a in vendor_assessments
            ],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "status": f.remediation_status
                }
                for f in vendor_findings
            ],
            "incidents": [
                {
                    "id": i.id,
                    "type": i.incident_type,
                    "severity": i.severity.value,
                    "date": i.incident_date.isoformat(),
                    "status": i.status
                }
                for i in vendor_incidents
            ]
        }
        
        return json.dumps(report, indent=2)
    
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
    
    async def _save_vendor(self, vendor: Vendor):
        """Save vendor to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO vendors VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            vendor.id, vendor.name, vendor.description,
            vendor.tier.value, vendor.status.value, vendor.risk_level.value, vendor.risk_score,
            vendor.primary_contact, vendor.contact_email, vendor.contact_phone,
            vendor.website, vendor.industry, vendor.country,
            json.dumps(vendor.services_provided),
            json.dumps([d.value for d in vendor.data_types_accessed]),
            json.dumps(vendor.integration_points),
            vendor.contract_start.isoformat() if vendor.contract_start else None,
            vendor.contract_end.isoformat() if vendor.contract_end else None,
            vendor.last_assessment.isoformat() if vendor.last_assessment else None,
            vendor.next_assessment.isoformat() if vendor.next_assessment else None,
            json.dumps(vendor.certifications),
            json.dumps([f.value for f in vendor.compliance_frameworks]),
            json.dumps(vendor.security_contacts),
            json.dumps(vendor.subprocessors),
            json.dumps(vendor.data_locations),
            1 if vendor.encryption_in_transit else 0,
            1 if vendor.encryption_at_rest else 0,
            json.dumps(vendor.incident_history),
            vendor.notes,
            json.dumps(vendor.tags),
            json.dumps(vendor.custom_fields),
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def _save_assessment(self, assessment: SecurityAssessment):
        """Save assessment to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO assessments VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            assessment.id, assessment.vendor_id, assessment.vendor_name,
            assessment.assessment_type, assessment.status.value,
            assessment.created_date.isoformat(),
            assessment.due_date.isoformat() if assessment.due_date else None,
            assessment.completed_date.isoformat() if assessment.completed_date else None,
            assessment.assessor, assessment.reviewer,
            json.dumps([{
                "question_id": r.question_id,
                "response": r.response,
                "score": r.score,
                "evidence": r.evidence,
                "notes": r.notes
            } for r in assessment.responses]),
            assessment.overall_score, assessment.risk_level.value,
            json.dumps(assessment.findings),
            json.dumps(assessment.recommendations),
            1 if assessment.remediation_required else 0,
            json.dumps(assessment.remediation_items),
            json.dumps(assessment.attachments),
            json.dumps(assessment.approval_history),
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def _save_finding(self, finding: RiskFinding):
        """Save finding to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO risk_findings VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            finding.id, finding.vendor_id, finding.assessment_id,
            finding.category, finding.title, finding.description,
            finding.severity.value, finding.likelihood, finding.impact,
            finding.risk_score, 1 if finding.remediation_required else 0,
            finding.remediation_recommendation,
            finding.remediation_deadline.isoformat() if finding.remediation_deadline else None,
            finding.remediation_status,
            json.dumps(finding.compensating_controls),
            1 if finding.risk_accepted else 0,
            finding.accepted_by,
            finding.accepted_date.isoformat() if finding.accepted_date else None,
            finding.acceptance_justification,
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def _save_incident(self, incident: VendorIncident):
        """Save incident to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO vendor_incidents VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            incident.id, incident.vendor_id,
            incident.incident_date.isoformat(),
            incident.reported_date.isoformat(),
            incident.incident_type, incident.description,
            incident.severity.value, 1 if incident.data_impacted else 0,
            json.dumps([d.value for d in incident.data_types_affected]),
            incident.root_cause,
            json.dumps(incident.remediation_actions),
            incident.status,
            incident.resolution_date.isoformat() if incident.resolution_date else None,
            incident.lessons_learned, incident.contract_impact,
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
