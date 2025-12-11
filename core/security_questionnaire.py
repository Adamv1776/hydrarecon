"""
Security Questionnaire Module for HydraRecon
Comprehensive security assessment questionnaires and vendor risk evaluation
"""

import asyncio
import json
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Set
from enum import Enum, auto
from pathlib import Path
import sqlite3


class QuestionnaireType(Enum):
    """Types of security questionnaires"""
    VENDOR_RISK = auto()
    SELF_ASSESSMENT = auto()
    COMPLIANCE_AUDIT = auto()
    SECURITY_REVIEW = auto()
    THIRD_PARTY = auto()
    DUE_DILIGENCE = auto()
    INCIDENT_REVIEW = auto()
    ACCESS_REQUEST = auto()
    DATA_CLASSIFICATION = auto()
    PRIVACY_IMPACT = auto()


class QuestionType(Enum):
    """Types of questions"""
    YES_NO = auto()
    MULTIPLE_CHOICE = auto()
    MULTI_SELECT = auto()
    TEXT = auto()
    NUMERIC = auto()
    DATE = auto()
    FILE_UPLOAD = auto()
    RATING_SCALE = auto()
    MATRIX = auto()
    CONDITIONAL = auto()


class ResponseStatus(Enum):
    """Status of questionnaire responses"""
    NOT_STARTED = auto()
    IN_PROGRESS = auto()
    SUBMITTED = auto()
    UNDER_REVIEW = auto()
    APPROVED = auto()
    REJECTED = auto()
    REQUIRES_FOLLOWUP = auto()
    COMPLETED = auto()


class RiskRating(Enum):
    """Risk rating levels"""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    MINIMAL = auto()
    NOT_APPLICABLE = auto()


class ComplianceFramework(Enum):
    """Compliance frameworks for questionnaires"""
    SOC2 = auto()
    ISO27001 = auto()
    NIST_CSF = auto()
    PCI_DSS = auto()
    HIPAA = auto()
    GDPR = auto()
    CCPA = auto()
    FedRAMP = auto()
    CIS_CONTROLS = auto()
    CUSTOM = auto()


@dataclass
class Question:
    """Security assessment question"""
    question_id: str
    text: str
    question_type: QuestionType
    category: str
    required: bool = True
    weight: float = 1.0
    options: List[str] = field(default_factory=list)
    correct_answers: List[str] = field(default_factory=list)
    risk_weights: Dict[str, float] = field(default_factory=dict)
    help_text: str = ""
    evidence_required: bool = False
    conditional_on: Optional[str] = None
    conditional_value: Optional[str] = None
    framework_mappings: List[str] = field(default_factory=list)
    order: int = 0
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class Response:
    """Answer to a security question"""
    response_id: str
    question_id: str
    questionnaire_id: str
    answer: Any
    evidence_files: List[str] = field(default_factory=list)
    notes: str = ""
    risk_score: float = 0.0
    reviewer_notes: str = ""
    reviewed_by: str = ""
    reviewed_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class Questionnaire:
    """Security questionnaire template"""
    questionnaire_id: str
    name: str
    description: str
    questionnaire_type: QuestionnaireType
    framework: ComplianceFramework
    version: str = "1.0"
    questions: List[Question] = field(default_factory=list)
    sections: List[Dict[str, Any]] = field(default_factory=list)
    passing_score: float = 70.0
    review_required: bool = True
    expiry_days: int = 365
    tags: List[str] = field(default_factory=list)
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class Assessment:
    """Completed questionnaire assessment"""
    assessment_id: str
    questionnaire_id: str
    respondent: str
    organization: str
    status: ResponseStatus
    responses: List[Response] = field(default_factory=list)
    overall_score: float = 0.0
    risk_rating: RiskRating = RiskRating.NOT_APPLICABLE
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    due_date: Optional[datetime] = None
    submitted_at: Optional[datetime] = None
    reviewed_by: str = ""
    reviewed_at: Optional[datetime] = None
    approval_notes: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class VendorProfile:
    """Vendor risk profile"""
    vendor_id: str
    name: str
    description: str
    contact_email: str
    contact_phone: str = ""
    industry: str = ""
    data_classification: str = ""
    criticality: str = "medium"
    assessments: List[str] = field(default_factory=list)
    certifications: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_rating: RiskRating = RiskRating.NOT_APPLICABLE
    contract_end_date: Optional[datetime] = None
    last_assessment_date: Optional[datetime] = None
    next_assessment_date: Optional[datetime] = None
    notes: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class SecurityQuestionnaireEngine:
    """Engine for managing security questionnaires and assessments"""
    
    def __init__(self, db_path: str = "questionnaires.db"):
        self.db_path = db_path
        self.questionnaires: Dict[str, Questionnaire] = {}
        self.assessments: Dict[str, Assessment] = {}
        self.vendors: Dict[str, VendorProfile] = {}
        self.question_library: Dict[str, Question] = {}
        self._init_database()
        self._load_standard_questions()
    
    def _init_database(self):
        """Initialize the questionnaire database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS questionnaires (
                questionnaire_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                questionnaire_type TEXT,
                framework TEXT,
                version TEXT,
                data TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY,
                questionnaire_id TEXT,
                respondent TEXT,
                organization TEXT,
                status TEXT,
                overall_score REAL,
                risk_rating TEXT,
                data TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vendors (
                vendor_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                contact_email TEXT,
                risk_score REAL,
                risk_rating TEXT,
                data TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS responses (
                response_id TEXT PRIMARY KEY,
                question_id TEXT,
                questionnaire_id TEXT,
                assessment_id TEXT,
                answer TEXT,
                risk_score REAL,
                data TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_standard_questions(self):
        """Load standard security assessment questions"""
        standard_questions = [
            # Access Control
            Question(
                question_id="AC001",
                text="Do you enforce multi-factor authentication (MFA) for all user accounts?",
                question_type=QuestionType.YES_NO,
                category="Access Control",
                weight=2.0,
                risk_weights={"Yes": 0.0, "No": 10.0},
                framework_mappings=["SOC2-CC6.1", "ISO27001-A.9", "NIST-PR.AC"],
                help_text="MFA provides additional security beyond passwords"
            ),
            Question(
                question_id="AC002",
                text="What is your password policy minimum length requirement?",
                question_type=QuestionType.NUMERIC,
                category="Access Control",
                weight=1.5,
                help_text="Industry standard recommends 12+ characters",
                framework_mappings=["SOC2-CC6.1", "ISO27001-A.9.4.3", "NIST-PR.AC-1"]
            ),
            Question(
                question_id="AC003",
                text="How frequently are access reviews conducted?",
                question_type=QuestionType.MULTIPLE_CHOICE,
                category="Access Control",
                options=["Monthly", "Quarterly", "Semi-annually", "Annually", "Never"],
                risk_weights={"Monthly": 0.0, "Quarterly": 2.0, "Semi-annually": 5.0, "Annually": 7.0, "Never": 10.0},
                framework_mappings=["SOC2-CC6.2", "ISO27001-A.9.2.5"]
            ),
            
            # Data Protection
            Question(
                question_id="DP001",
                text="Is sensitive data encrypted at rest?",
                question_type=QuestionType.YES_NO,
                category="Data Protection",
                weight=2.5,
                risk_weights={"Yes": 0.0, "No": 10.0},
                evidence_required=True,
                framework_mappings=["SOC2-CC6.7", "ISO27001-A.10.1", "PCI-DSS-3.4"]
            ),
            Question(
                question_id="DP002",
                text="Is data encrypted in transit using TLS 1.2 or higher?",
                question_type=QuestionType.YES_NO,
                category="Data Protection",
                weight=2.5,
                risk_weights={"Yes": 0.0, "No": 10.0},
                framework_mappings=["SOC2-CC6.7", "ISO27001-A.13.2", "PCI-DSS-4.1"]
            ),
            Question(
                question_id="DP003",
                text="What encryption algorithms are used for data protection?",
                question_type=QuestionType.MULTI_SELECT,
                category="Data Protection",
                options=["AES-256", "AES-128", "RSA-2048+", "SHA-256+", "3DES", "Other"],
                framework_mappings=["SOC2-CC6.7", "ISO27001-A.10.1.1"]
            ),
            
            # Incident Response
            Question(
                question_id="IR001",
                text="Do you have a documented incident response plan?",
                question_type=QuestionType.YES_NO,
                category="Incident Response",
                weight=2.0,
                risk_weights={"Yes": 0.0, "No": 10.0},
                evidence_required=True,
                framework_mappings=["SOC2-CC7.3", "ISO27001-A.16.1", "NIST-RS.RP"]
            ),
            Question(
                question_id="IR002",
                text="How quickly can you notify customers of a data breach?",
                question_type=QuestionType.MULTIPLE_CHOICE,
                category="Incident Response",
                options=["Within 24 hours", "Within 72 hours", "Within 1 week", "Within 30 days", "No defined timeline"],
                risk_weights={"Within 24 hours": 0.0, "Within 72 hours": 2.0, "Within 1 week": 5.0, "Within 30 days": 8.0, "No defined timeline": 10.0},
                framework_mappings=["GDPR-Art.33", "HIPAA-164.404"]
            ),
            
            # Business Continuity
            Question(
                question_id="BC001",
                text="Do you have a documented business continuity plan?",
                question_type=QuestionType.YES_NO,
                category="Business Continuity",
                weight=2.0,
                risk_weights={"Yes": 0.0, "No": 10.0},
                evidence_required=True,
                framework_mappings=["SOC2-A1.2", "ISO27001-A.17.1"]
            ),
            Question(
                question_id="BC002",
                text="What is your Recovery Time Objective (RTO)?",
                question_type=QuestionType.MULTIPLE_CHOICE,
                category="Business Continuity",
                options=["< 1 hour", "1-4 hours", "4-24 hours", "1-3 days", "> 3 days", "Not defined"],
                framework_mappings=["SOC2-A1.2", "ISO27001-A.17.1.1"]
            ),
            Question(
                question_id="BC003",
                text="How frequently are backups tested?",
                question_type=QuestionType.MULTIPLE_CHOICE,
                category="Business Continuity",
                options=["Daily", "Weekly", "Monthly", "Quarterly", "Annually", "Never"],
                risk_weights={"Daily": 0.0, "Weekly": 1.0, "Monthly": 3.0, "Quarterly": 5.0, "Annually": 7.0, "Never": 10.0},
                framework_mappings=["SOC2-A1.3", "ISO27001-A.12.3"]
            ),
            
            # Network Security
            Question(
                question_id="NS001",
                text="Do you use firewalls to protect network perimeters?",
                question_type=QuestionType.YES_NO,
                category="Network Security",
                weight=2.0,
                risk_weights={"Yes": 0.0, "No": 10.0},
                framework_mappings=["SOC2-CC6.6", "ISO27001-A.13.1", "PCI-DSS-1.1"]
            ),
            Question(
                question_id="NS002",
                text="Is network traffic monitored for suspicious activity?",
                question_type=QuestionType.YES_NO,
                category="Network Security",
                weight=1.5,
                risk_weights={"Yes": 0.0, "No": 8.0},
                framework_mappings=["SOC2-CC7.2", "ISO27001-A.12.4", "NIST-DE.CM"]
            ),
            Question(
                question_id="NS003",
                text="Are network segments isolated based on data sensitivity?",
                question_type=QuestionType.YES_NO,
                category="Network Security",
                weight=1.5,
                risk_weights={"Yes": 0.0, "No": 7.0},
                framework_mappings=["PCI-DSS-1.3", "ISO27001-A.13.1.3"]
            ),
            
            # Vulnerability Management
            Question(
                question_id="VM001",
                text="How frequently are vulnerability scans performed?",
                question_type=QuestionType.MULTIPLE_CHOICE,
                category="Vulnerability Management",
                options=["Continuous", "Weekly", "Monthly", "Quarterly", "Annually", "Never"],
                weight=2.0,
                risk_weights={"Continuous": 0.0, "Weekly": 1.0, "Monthly": 3.0, "Quarterly": 5.0, "Annually": 8.0, "Never": 10.0},
                framework_mappings=["SOC2-CC7.1", "ISO27001-A.12.6", "PCI-DSS-11.2"]
            ),
            Question(
                question_id="VM002",
                text="What is your SLA for patching critical vulnerabilities?",
                question_type=QuestionType.MULTIPLE_CHOICE,
                category="Vulnerability Management",
                options=["24 hours", "72 hours", "1 week", "30 days", "No defined SLA"],
                risk_weights={"24 hours": 0.0, "72 hours": 2.0, "1 week": 5.0, "30 days": 8.0, "No defined SLA": 10.0},
                framework_mappings=["SOC2-CC7.1", "ISO27001-A.12.6.1"]
            ),
            Question(
                question_id="VM003",
                text="Do you conduct penetration testing?",
                question_type=QuestionType.YES_NO,
                category="Vulnerability Management",
                weight=1.5,
                risk_weights={"Yes": 0.0, "No": 7.0},
                evidence_required=True,
                framework_mappings=["SOC2-CC4.1", "ISO27001-A.18.2.3", "PCI-DSS-11.3"]
            ),
            
            # Compliance & Governance
            Question(
                question_id="CG001",
                text="Which security certifications do you hold?",
                question_type=QuestionType.MULTI_SELECT,
                category="Compliance & Governance",
                options=["SOC 2 Type II", "ISO 27001", "PCI DSS", "FedRAMP", "HIPAA", "SOC 1", "None"],
                framework_mappings=["SOC2-CC1.1", "ISO27001-A.18.1"]
            ),
            Question(
                question_id="CG002",
                text="Do you have a dedicated security team or CISO?",
                question_type=QuestionType.YES_NO,
                category="Compliance & Governance",
                weight=1.5,
                risk_weights={"Yes": 0.0, "No": 5.0},
                framework_mappings=["SOC2-CC1.1", "ISO27001-A.6.1.1"]
            ),
            Question(
                question_id="CG003",
                text="Are security policies reviewed and updated annually?",
                question_type=QuestionType.YES_NO,
                category="Compliance & Governance",
                weight=1.0,
                risk_weights={"Yes": 0.0, "No": 5.0},
                framework_mappings=["SOC2-CC1.4", "ISO27001-A.5.1.2"]
            ),
            
            # Physical Security
            Question(
                question_id="PS001",
                text="Are data centers physically secured with access controls?",
                question_type=QuestionType.YES_NO,
                category="Physical Security",
                weight=1.5,
                risk_weights={"Yes": 0.0, "No": 8.0},
                framework_mappings=["SOC2-CC6.4", "ISO27001-A.11.1"]
            ),
            Question(
                question_id="PS002",
                text="Do you use cloud infrastructure providers?",
                question_type=QuestionType.MULTIPLE_CHOICE,
                category="Physical Security",
                options=["AWS", "Azure", "GCP", "On-premises only", "Multiple providers", "Other"],
                framework_mappings=["SOC2-CC6.4"]
            ),
            
            # Employee Security
            Question(
                question_id="ES001",
                text="Do employees receive security awareness training?",
                question_type=QuestionType.YES_NO,
                category="Employee Security",
                weight=1.5,
                risk_weights={"Yes": 0.0, "No": 6.0},
                framework_mappings=["SOC2-CC1.4", "ISO27001-A.7.2.2"]
            ),
            Question(
                question_id="ES002",
                text="How frequently is security training conducted?",
                question_type=QuestionType.MULTIPLE_CHOICE,
                category="Employee Security",
                options=["Onboarding + Quarterly", "Onboarding + Annually", "Onboarding only", "As needed", "Never"],
                conditional_on="ES001",
                conditional_value="Yes",
                risk_weights={"Onboarding + Quarterly": 0.0, "Onboarding + Annually": 2.0, "Onboarding only": 5.0, "As needed": 6.0, "Never": 10.0},
                framework_mappings=["SOC2-CC1.4", "ISO27001-A.7.2.2"]
            ),
            Question(
                question_id="ES003",
                text="Are background checks performed for employees with access to sensitive data?",
                question_type=QuestionType.YES_NO,
                category="Employee Security",
                weight=1.0,
                risk_weights={"Yes": 0.0, "No": 5.0},
                framework_mappings=["SOC2-CC1.4", "ISO27001-A.7.1.1"]
            ),
        ]
        
        for q in standard_questions:
            self.question_library[q.question_id] = q
    
    async def create_questionnaire(
        self,
        name: str,
        description: str,
        questionnaire_type: QuestionnaireType,
        framework: ComplianceFramework,
        question_ids: Optional[List[str]] = None
    ) -> Questionnaire:
        """Create a new questionnaire"""
        questionnaire_id = hashlib.sha256(
            f"{name}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        questions = []
        if question_ids:
            for qid in question_ids:
                if qid in self.question_library:
                    questions.append(self.question_library[qid])
        
        # Group questions into sections
        sections = self._organize_sections(questions)
        
        questionnaire = Questionnaire(
            questionnaire_id=questionnaire_id,
            name=name,
            description=description,
            questionnaire_type=questionnaire_type,
            framework=framework,
            questions=questions,
            sections=sections
        )
        
        self.questionnaires[questionnaire_id] = questionnaire
        await self._save_questionnaire(questionnaire)
        
        return questionnaire
    
    def _organize_sections(self, questions: List[Question]) -> List[Dict[str, Any]]:
        """Organize questions into sections by category"""
        sections_map: Dict[str, List[str]] = {}
        
        for q in questions:
            if q.category not in sections_map:
                sections_map[q.category] = []
            sections_map[q.category].append(q.question_id)
        
        sections = []
        for idx, (category, q_ids) in enumerate(sections_map.items()):
            sections.append({
                "section_id": f"section_{idx}",
                "name": category,
                "description": f"Questions related to {category}",
                "question_ids": q_ids,
                "order": idx
            })
        
        return sections
    
    async def create_vendor_questionnaire(
        self,
        name: str,
        vendor_criticality: str = "medium"
    ) -> Questionnaire:
        """Create a vendor risk assessment questionnaire"""
        # Select questions based on vendor criticality
        if vendor_criticality == "critical":
            question_ids = list(self.question_library.keys())
        elif vendor_criticality == "high":
            question_ids = [
                "AC001", "AC002", "AC003",
                "DP001", "DP002", "DP003",
                "IR001", "IR002",
                "BC001", "BC002", "BC003",
                "NS001", "NS002", "NS003",
                "VM001", "VM002", "VM003",
                "CG001", "CG002", "CG003",
                "ES001", "ES002", "ES003"
            ]
        elif vendor_criticality == "medium":
            question_ids = [
                "AC001", "AC003",
                "DP001", "DP002",
                "IR001",
                "BC001", "BC002",
                "NS001",
                "VM001", "VM002",
                "CG001", "CG002",
                "ES001"
            ]
        else:
            question_ids = [
                "AC001",
                "DP001", "DP002",
                "IR001",
                "BC001",
                "NS001",
                "VM001",
                "CG001",
                "ES001"
            ]
        
        return await self.create_questionnaire(
            name=name,
            description=f"Vendor Risk Assessment - {vendor_criticality.upper()} criticality",
            questionnaire_type=QuestionnaireType.VENDOR_RISK,
            framework=ComplianceFramework.SOC2,
            question_ids=question_ids
        )
    
    async def start_assessment(
        self,
        questionnaire_id: str,
        respondent: str,
        organization: str,
        due_date: Optional[datetime] = None
    ) -> Assessment:
        """Start a new questionnaire assessment"""
        if questionnaire_id not in self.questionnaires:
            raise ValueError(f"Questionnaire not found: {questionnaire_id}")
        
        assessment_id = hashlib.sha256(
            f"{questionnaire_id}{respondent}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        assessment = Assessment(
            assessment_id=assessment_id,
            questionnaire_id=questionnaire_id,
            respondent=respondent,
            organization=organization,
            status=ResponseStatus.NOT_STARTED,
            due_date=due_date or datetime.now() + timedelta(days=30)
        )
        
        self.assessments[assessment_id] = assessment
        await self._save_assessment(assessment)
        
        return assessment
    
    async def submit_response(
        self,
        assessment_id: str,
        question_id: str,
        answer: Any,
        evidence_files: Optional[List[str]] = None,
        notes: str = ""
    ) -> Response:
        """Submit a response to a question"""
        if assessment_id not in self.assessments:
            raise ValueError(f"Assessment not found: {assessment_id}")
        
        assessment = self.assessments[assessment_id]
        questionnaire = self.questionnaires.get(assessment.questionnaire_id)
        
        if not questionnaire:
            raise ValueError("Questionnaire not found")
        
        # Find the question
        question = None
        for q in questionnaire.questions:
            if q.question_id == question_id:
                question = q
                break
        
        if not question:
            raise ValueError(f"Question not found: {question_id}")
        
        # Calculate risk score for this response
        risk_score = self._calculate_response_risk(question, answer)
        
        response_id = hashlib.sha256(
            f"{assessment_id}{question_id}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        response = Response(
            response_id=response_id,
            question_id=question_id,
            questionnaire_id=assessment.questionnaire_id,
            answer=answer,
            evidence_files=evidence_files or [],
            notes=notes,
            risk_score=risk_score
        )
        
        # Update assessment
        assessment.responses.append(response)
        if assessment.status == ResponseStatus.NOT_STARTED:
            assessment.status = ResponseStatus.IN_PROGRESS
        assessment.updated_at = datetime.now()
        
        # Recalculate overall score
        await self._recalculate_assessment_score(assessment)
        
        await self._save_assessment(assessment)
        
        return response
    
    def _calculate_response_risk(self, question: Question, answer: Any) -> float:
        """Calculate risk score for a response"""
        if question.risk_weights and isinstance(answer, str):
            return question.risk_weights.get(answer, 5.0) * question.weight
        elif question.question_type == QuestionType.NUMERIC:
            # For password length, higher is better
            if "password" in question.text.lower() and "length" in question.text.lower():
                try:
                    length = int(answer)
                    if length >= 16:
                        return 0.0
                    elif length >= 12:
                        return 2.0 * question.weight
                    elif length >= 8:
                        return 5.0 * question.weight
                    else:
                        return 10.0 * question.weight
                except (ValueError, TypeError):
                    return 5.0 * question.weight
        
        return 5.0 * question.weight
    
    async def _recalculate_assessment_score(self, assessment: Assessment):
        """Recalculate overall assessment score"""
        questionnaire = self.questionnaires.get(assessment.questionnaire_id)
        if not questionnaire:
            return
        
        total_weight = sum(q.weight for q in questionnaire.questions)
        total_risk = sum(r.risk_score for r in assessment.responses)
        max_risk = total_weight * 10.0
        
        # Score is inverse of risk (higher score = lower risk)
        if max_risk > 0:
            assessment.overall_score = max(0, 100 - (total_risk / max_risk * 100))
        else:
            assessment.overall_score = 100.0
        
        # Determine risk rating
        if assessment.overall_score >= 90:
            assessment.risk_rating = RiskRating.MINIMAL
        elif assessment.overall_score >= 75:
            assessment.risk_rating = RiskRating.LOW
        elif assessment.overall_score >= 50:
            assessment.risk_rating = RiskRating.MEDIUM
        elif assessment.overall_score >= 25:
            assessment.risk_rating = RiskRating.HIGH
        else:
            assessment.risk_rating = RiskRating.CRITICAL
    
    async def submit_assessment(self, assessment_id: str) -> Assessment:
        """Submit an assessment for review"""
        if assessment_id not in self.assessments:
            raise ValueError(f"Assessment not found: {assessment_id}")
        
        assessment = self.assessments[assessment_id]
        questionnaire = self.questionnaires.get(assessment.questionnaire_id)
        
        if not questionnaire:
            raise ValueError("Questionnaire not found")
        
        # Check if all required questions are answered
        required_questions = {q.question_id for q in questionnaire.questions if q.required}
        answered_questions = {r.question_id for r in assessment.responses}
        
        missing = required_questions - answered_questions
        if missing:
            raise ValueError(f"Required questions not answered: {missing}")
        
        # Generate findings
        assessment.findings = await self._generate_findings(assessment, questionnaire)
        assessment.recommendations = await self._generate_recommendations(assessment)
        
        assessment.status = ResponseStatus.SUBMITTED
        assessment.submitted_at = datetime.now()
        assessment.updated_at = datetime.now()
        
        await self._save_assessment(assessment)
        
        return assessment
    
    async def _generate_findings(
        self,
        assessment: Assessment,
        questionnaire: Questionnaire
    ) -> List[Dict[str, Any]]:
        """Generate findings from assessment responses"""
        findings = []
        
        for response in assessment.responses:
            question = next(
                (q for q in questionnaire.questions if q.question_id == response.question_id),
                None
            )
            
            if not question:
                continue
            
            # High risk responses become findings
            if response.risk_score >= 5.0 * question.weight:
                severity = "critical" if response.risk_score >= 8.0 * question.weight else \
                          "high" if response.risk_score >= 6.0 * question.weight else "medium"
                
                findings.append({
                    "finding_id": f"F-{response.response_id[:8]}",
                    "question_id": question.question_id,
                    "category": question.category,
                    "description": question.text,
                    "response": response.answer,
                    "severity": severity,
                    "risk_score": response.risk_score,
                    "framework_mappings": question.framework_mappings,
                    "evidence_required": question.evidence_required and not response.evidence_files
                })
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: severity_order.get(f["severity"], 4))
        
        return findings
    
    async def _generate_recommendations(self, assessment: Assessment) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        categories_with_issues: Set[str] = set()
        for finding in assessment.findings:
            categories_with_issues.add(finding["category"])
        
        recommendation_map = {
            "Access Control": [
                "Implement multi-factor authentication for all user accounts",
                "Strengthen password policies with minimum 12+ character requirements",
                "Conduct quarterly access reviews and remove unnecessary privileges"
            ],
            "Data Protection": [
                "Enable encryption at rest using AES-256 for all sensitive data",
                "Ensure TLS 1.2+ is enforced for all data in transit",
                "Implement data classification and handling procedures"
            ],
            "Incident Response": [
                "Develop and document an incident response plan",
                "Establish breach notification procedures within 72 hours",
                "Conduct tabletop exercises quarterly"
            ],
            "Business Continuity": [
                "Document and test business continuity plan annually",
                "Define RTO/RPO objectives for critical systems",
                "Perform regular backup restoration tests"
            ],
            "Network Security": [
                "Implement network segmentation for sensitive environments",
                "Deploy intrusion detection/prevention systems",
                "Enable comprehensive network traffic monitoring"
            ],
            "Vulnerability Management": [
                "Conduct vulnerability scans at least weekly",
                "Define SLAs for patching critical vulnerabilities (24-72 hours)",
                "Perform annual penetration testing by qualified third party"
            ],
            "Compliance & Governance": [
                "Consider SOC 2 Type II certification",
                "Establish dedicated security leadership (CISO)",
                "Review and update security policies annually"
            ],
            "Employee Security": [
                "Implement security awareness training program",
                "Conduct phishing simulations regularly",
                "Perform background checks for employees handling sensitive data"
            ],
            "Physical Security": [
                "Ensure data centers have appropriate physical access controls",
                "Implement visitor management procedures",
                "Use cloud providers with strong physical security certifications"
            ]
        }
        
        for category in categories_with_issues:
            if category in recommendation_map:
                recommendations.extend(recommendation_map[category])
        
        return list(set(recommendations))
    
    async def review_assessment(
        self,
        assessment_id: str,
        reviewer: str,
        approved: bool,
        notes: str = ""
    ) -> Assessment:
        """Review and approve/reject an assessment"""
        if assessment_id not in self.assessments:
            raise ValueError(f"Assessment not found: {assessment_id}")
        
        assessment = self.assessments[assessment_id]
        
        assessment.reviewed_by = reviewer
        assessment.reviewed_at = datetime.now()
        assessment.approval_notes = notes
        
        if approved:
            if assessment.overall_score >= assessment.findings:
                assessment.status = ResponseStatus.APPROVED
            else:
                assessment.status = ResponseStatus.APPROVED
        else:
            if assessment.findings:
                assessment.status = ResponseStatus.REQUIRES_FOLLOWUP
            else:
                assessment.status = ResponseStatus.REJECTED
        
        assessment.updated_at = datetime.now()
        await self._save_assessment(assessment)
        
        return assessment
    
    async def create_vendor(
        self,
        name: str,
        description: str,
        contact_email: str,
        criticality: str = "medium",
        **kwargs
    ) -> VendorProfile:
        """Create a vendor profile"""
        vendor_id = hashlib.sha256(
            f"{name}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        vendor = VendorProfile(
            vendor_id=vendor_id,
            name=name,
            description=description,
            contact_email=contact_email,
            criticality=criticality,
            **kwargs
        )
        
        self.vendors[vendor_id] = vendor
        await self._save_vendor(vendor)
        
        return vendor
    
    async def assess_vendor(
        self,
        vendor_id: str,
        questionnaire_id: Optional[str] = None
    ) -> Assessment:
        """Create an assessment for a vendor"""
        if vendor_id not in self.vendors:
            raise ValueError(f"Vendor not found: {vendor_id}")
        
        vendor = self.vendors[vendor_id]
        
        # Create questionnaire if not provided
        if not questionnaire_id:
            questionnaire = await self.create_vendor_questionnaire(
                f"Vendor Assessment - {vendor.name}",
                vendor.criticality
            )
            questionnaire_id = questionnaire.questionnaire_id
        
        assessment = await self.start_assessment(
            questionnaire_id=questionnaire_id,
            respondent=vendor.contact_email,
            organization=vendor.name
        )
        
        vendor.assessments.append(assessment.assessment_id)
        vendor.updated_at = datetime.now()
        await self._save_vendor(vendor)
        
        return assessment
    
    async def get_vendor_risk_summary(self, vendor_id: str) -> Dict[str, Any]:
        """Get vendor risk summary"""
        if vendor_id not in self.vendors:
            raise ValueError(f"Vendor not found: {vendor_id}")
        
        vendor = self.vendors[vendor_id]
        
        assessments = [
            self.assessments[aid] 
            for aid in vendor.assessments 
            if aid in self.assessments
        ]
        
        latest_assessment = None
        if assessments:
            assessments.sort(key=lambda a: a.created_at, reverse=True)
            latest_assessment = assessments[0]
        
        return {
            "vendor_id": vendor_id,
            "vendor_name": vendor.name,
            "criticality": vendor.criticality,
            "total_assessments": len(assessments),
            "latest_assessment": {
                "assessment_id": latest_assessment.assessment_id,
                "status": latest_assessment.status.name,
                "score": latest_assessment.overall_score,
                "risk_rating": latest_assessment.risk_rating.name,
                "findings_count": len(latest_assessment.findings),
                "submitted_at": latest_assessment.submitted_at.isoformat() if latest_assessment.submitted_at else None
            } if latest_assessment else None,
            "certifications": vendor.certifications,
            "contract_end_date": vendor.contract_end_date.isoformat() if vendor.contract_end_date else None,
            "next_assessment_date": vendor.next_assessment_date.isoformat() if vendor.next_assessment_date else None
        }
    
    async def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get questionnaire dashboard metrics"""
        total_questionnaires = len(self.questionnaires)
        total_assessments = len(self.assessments)
        total_vendors = len(self.vendors)
        
        # Assessment status breakdown
        status_breakdown = {}
        risk_breakdown = {}
        
        for assessment in self.assessments.values():
            status = assessment.status.name
            status_breakdown[status] = status_breakdown.get(status, 0) + 1
            
            risk = assessment.risk_rating.name
            risk_breakdown[risk] = risk_breakdown.get(risk, 0) + 1
        
        # Overdue assessments
        overdue_count = sum(
            1 for a in self.assessments.values()
            if a.due_date and a.due_date < datetime.now() and a.status not in [
                ResponseStatus.COMPLETED, ResponseStatus.APPROVED
            ]
        )
        
        # Average scores
        scores = [a.overall_score for a in self.assessments.values() if a.overall_score > 0]
        avg_score = sum(scores) / len(scores) if scores else 0.0
        
        return {
            "total_questionnaires": total_questionnaires,
            "total_assessments": total_assessments,
            "total_vendors": total_vendors,
            "status_breakdown": status_breakdown,
            "risk_breakdown": risk_breakdown,
            "overdue_assessments": overdue_count,
            "average_score": round(avg_score, 1),
            "pending_reviews": sum(
                1 for a in self.assessments.values()
                if a.status == ResponseStatus.SUBMITTED
            ),
            "high_risk_vendors": sum(
                1 for v in self.vendors.values()
                if v.risk_rating in [RiskRating.CRITICAL, RiskRating.HIGH]
            )
        }
    
    async def export_assessment_report(
        self,
        assessment_id: str,
        format: str = "json"
    ) -> Dict[str, Any]:
        """Export assessment as a report"""
        if assessment_id not in self.assessments:
            raise ValueError(f"Assessment not found: {assessment_id}")
        
        assessment = self.assessments[assessment_id]
        questionnaire = self.questionnaires.get(assessment.questionnaire_id)
        
        report = {
            "report_generated_at": datetime.now().isoformat(),
            "assessment": {
                "assessment_id": assessment.assessment_id,
                "organization": assessment.organization,
                "respondent": assessment.respondent,
                "status": assessment.status.name,
                "overall_score": assessment.overall_score,
                "risk_rating": assessment.risk_rating.name,
                "submitted_at": assessment.submitted_at.isoformat() if assessment.submitted_at else None,
                "reviewed_by": assessment.reviewed_by,
                "reviewed_at": assessment.reviewed_at.isoformat() if assessment.reviewed_at else None
            },
            "questionnaire": {
                "name": questionnaire.name if questionnaire else "Unknown",
                "framework": questionnaire.framework.name if questionnaire else "Unknown",
                "total_questions": len(questionnaire.questions) if questionnaire else 0
            },
            "responses": [
                {
                    "question": next(
                        (q.text for q in questionnaire.questions if q.question_id == r.question_id),
                        "Unknown"
                    ) if questionnaire else "Unknown",
                    "category": next(
                        (q.category for q in questionnaire.questions if q.question_id == r.question_id),
                        "Unknown"
                    ) if questionnaire else "Unknown",
                    "answer": r.answer,
                    "risk_score": r.risk_score,
                    "evidence_provided": len(r.evidence_files) > 0
                }
                for r in assessment.responses
            ],
            "findings": assessment.findings,
            "recommendations": assessment.recommendations
        }
        
        return report
    
    async def _save_questionnaire(self, questionnaire: Questionnaire):
        """Save questionnaire to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        data = {
            "questions": [
                {
                    "question_id": q.question_id,
                    "text": q.text,
                    "question_type": q.question_type.name,
                    "category": q.category,
                    "required": q.required,
                    "weight": q.weight,
                    "options": q.options,
                    "risk_weights": q.risk_weights,
                    "framework_mappings": q.framework_mappings
                }
                for q in questionnaire.questions
            ],
            "sections": questionnaire.sections,
            "tags": questionnaire.tags
        }
        
        cursor.execute('''
            INSERT OR REPLACE INTO questionnaires
            (questionnaire_id, name, description, questionnaire_type, framework, version, data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            questionnaire.questionnaire_id,
            questionnaire.name,
            questionnaire.description,
            questionnaire.questionnaire_type.name,
            questionnaire.framework.name,
            questionnaire.version,
            json.dumps(data),
            questionnaire.created_at.isoformat(),
            questionnaire.updated_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def _save_assessment(self, assessment: Assessment):
        """Save assessment to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        data = {
            "responses": [
                {
                    "response_id": r.response_id,
                    "question_id": r.question_id,
                    "answer": r.answer,
                    "evidence_files": r.evidence_files,
                    "notes": r.notes,
                    "risk_score": r.risk_score
                }
                for r in assessment.responses
            ],
            "findings": assessment.findings,
            "recommendations": assessment.recommendations
        }
        
        cursor.execute('''
            INSERT OR REPLACE INTO assessments
            (assessment_id, questionnaire_id, respondent, organization, status, overall_score, risk_rating, data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            assessment.assessment_id,
            assessment.questionnaire_id,
            assessment.respondent,
            assessment.organization,
            assessment.status.name,
            assessment.overall_score,
            assessment.risk_rating.name,
            json.dumps(data),
            assessment.created_at.isoformat(),
            assessment.updated_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def _save_vendor(self, vendor: VendorProfile):
        """Save vendor to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        data = {
            "contact_phone": vendor.contact_phone,
            "industry": vendor.industry,
            "data_classification": vendor.data_classification,
            "criticality": vendor.criticality,
            "assessments": vendor.assessments,
            "certifications": vendor.certifications,
            "notes": vendor.notes
        }
        
        cursor.execute('''
            INSERT OR REPLACE INTO vendors
            (vendor_id, name, description, contact_email, risk_score, risk_rating, data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            vendor.vendor_id,
            vendor.name,
            vendor.description,
            vendor.contact_email,
            vendor.risk_score,
            vendor.risk_rating.name,
            json.dumps(data),
            vendor.created_at.isoformat(),
            vendor.updated_at.isoformat()
        ))
        
        conn.commit()
        conn.close()


# Singleton instance
_questionnaire_engine: Optional[SecurityQuestionnaireEngine] = None


def get_questionnaire_engine() -> SecurityQuestionnaireEngine:
    """Get or create the questionnaire engine instance"""
    global _questionnaire_engine
    if _questionnaire_engine is None:
        _questionnaire_engine = SecurityQuestionnaireEngine()
    return _questionnaire_engine
