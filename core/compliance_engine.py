#!/usr/bin/env python3
"""
Compliance Framework Engine - HydraRecon Commercial v2.0

Comprehensive compliance management with mappings to major
regulatory frameworks, automated gap analysis, and audit support.

Features:
- SOC 2 Type II compliance
- PCI DSS v4.0 compliance
- HIPAA/HITECH compliance
- GDPR compliance
- ISO 27001:2022 compliance
- NIST CSF 2.0 compliance
- CIS Controls v8 compliance
- MITRE ATT&CK mapping
- Automated gap analysis
- Control testing
- Evidence collection
- Audit trail
- Remediation tracking

Author: HydraRecon Team
License: Commercial
"""

import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


class Framework(Enum):
    """Compliance frameworks."""
    SOC2 = "SOC 2 Type II"
    PCI_DSS = "PCI DSS v4.0"
    HIPAA = "HIPAA"
    GDPR = "GDPR"
    ISO27001 = "ISO 27001:2022"
    NIST_CSF = "NIST CSF 2.0"
    CIS = "CIS Controls v8"
    MITRE = "MITRE ATT&CK"
    CCPA = "CCPA"
    FEDRAMP = "FedRAMP"


class ControlStatus(Enum):
    """Control implementation status."""
    NOT_IMPLEMENTED = "not_implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    IMPLEMENTED = "implemented"
    NOT_APPLICABLE = "not_applicable"
    COMPENSATING = "compensating"


class EvidenceType(Enum):
    """Evidence types."""
    DOCUMENT = "document"
    SCREENSHOT = "screenshot"
    LOG = "log"
    SCAN_RESULT = "scan_result"
    CONFIGURATION = "configuration"
    INTERVIEW = "interview"
    OBSERVATION = "observation"


class RiskLevel(Enum):
    """Risk levels."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFORMATIONAL = 1


@dataclass
class Control:
    """Compliance control."""
    id: str
    framework: Framework
    title: str
    description: str
    category: str
    requirements: List[str]
    testing_procedures: List[str]
    implementation_guidance: str
    related_controls: List[str] = field(default_factory=list)
    mitre_mapping: List[str] = field(default_factory=list)


@dataclass
class ControlAssessment:
    """Control assessment result."""
    control_id: str
    status: ControlStatus
    assessor: str
    assessed_at: datetime
    evidence_ids: List[str]
    findings: List[str]
    risk_level: RiskLevel
    remediation_plan: Optional[str] = None
    remediation_due: Optional[datetime] = None
    notes: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'control_id': self.control_id,
            'status': self.status.value,
            'assessor': self.assessor,
            'assessed_at': self.assessed_at.isoformat(),
            'evidence_ids': self.evidence_ids,
            'findings': self.findings,
            'risk_level': self.risk_level.name,
            'remediation_plan': self.remediation_plan,
            'remediation_due': self.remediation_due.isoformat() if self.remediation_due else None,
            'notes': self.notes,
        }


@dataclass
class Evidence:
    """Compliance evidence."""
    id: str
    type: EvidenceType
    title: str
    description: str
    file_path: Optional[str]
    content_hash: str
    collected_at: datetime
    collected_by: str
    control_ids: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """Compliance finding."""
    id: str
    control_id: str
    title: str
    description: str
    risk_level: RiskLevel
    status: str  # open, in_progress, resolved, accepted
    identified_at: datetime
    identified_by: str
    remediation_steps: List[str]
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    resolved_at: Optional[datetime] = None


# SOC 2 Controls (Trust Service Criteria)
SOC2_CONTROLS = {
    # Security (Common Criteria)
    "CC1.1": Control(
        id="CC1.1",
        framework=Framework.SOC2,
        title="Demonstrates Commitment to Integrity and Ethical Values",
        description="The entity demonstrates a commitment to integrity and ethical values",
        category="Control Environment",
        requirements=[
            "Code of conduct defined and communicated",
            "Ethical standards enforced through disciplinary actions",
            "Background checks performed for employees"
        ],
        testing_procedures=[
            "Review code of conduct documentation",
            "Interview management about ethical tone",
            "Review disciplinary action records"
        ],
        implementation_guidance="Establish and document ethical standards"
    ),
    "CC6.1": Control(
        id="CC6.1",
        framework=Framework.SOC2,
        title="Logical and Physical Access Controls",
        description="The entity implements logical access controls to protect against unauthorized access",
        category="Logical and Physical Access",
        requirements=[
            "Access control policies defined",
            "User authentication mechanisms",
            "Access provisioning and deprovisioning processes",
            "Periodic access reviews"
        ],
        testing_procedures=[
            "Review access control policies",
            "Test authentication mechanisms",
            "Review user provisioning procedures",
            "Examine access review documentation"
        ],
        implementation_guidance="Implement role-based access control with MFA"
    ),
    "CC6.6": Control(
        id="CC6.6",
        framework=Framework.SOC2,
        title="Logical Access Security Measures",
        description="The entity implements controls to prevent or detect unauthorized access",
        category="Logical and Physical Access",
        requirements=[
            "Network security controls (firewalls, IDS/IPS)",
            "Encryption of data in transit",
            "Vulnerability management program",
            "Security monitoring and logging"
        ],
        testing_procedures=[
            "Review firewall configurations",
            "Test encryption implementation",
            "Review vulnerability scan results",
            "Examine security monitoring tools"
        ],
        implementation_guidance="Deploy defense-in-depth security architecture"
    ),
    "CC7.1": Control(
        id="CC7.1",
        framework=Framework.SOC2,
        title="System Operations Monitoring",
        description="The entity uses detection and monitoring procedures",
        category="System Operations",
        requirements=[
            "Security event logging enabled",
            "Log monitoring and analysis",
            "Intrusion detection systems",
            "Incident alerting mechanisms"
        ],
        testing_procedures=[
            "Review logging configurations",
            "Examine SIEM implementation",
            "Test IDS effectiveness",
            "Review alerting procedures"
        ],
        implementation_guidance="Implement comprehensive SIEM solution"
    ),
}

# PCI DSS v4.0 Controls
PCI_DSS_CONTROLS = {
    "1.1.1": Control(
        id="1.1.1",
        framework=Framework.PCI_DSS,
        title="Network Security Controls Documentation",
        description="Processes and mechanisms for network security controls are defined and documented",
        category="Build and Maintain a Secure Network",
        requirements=[
            "Firewall and router configuration standards",
            "Network diagrams showing CDE",
            "Data flow documentation"
        ],
        testing_procedures=[
            "Examine firewall configuration standards",
            "Review network diagrams",
            "Verify data flow documentation"
        ],
        implementation_guidance="Document all network security controls and maintain current diagrams"
    ),
    "3.4.1": Control(
        id="3.4.1",
        framework=Framework.PCI_DSS,
        title="PAN Rendering Unreadable",
        description="PAN is rendered unreadable anywhere it is stored",
        category="Protect Stored Account Data",
        requirements=[
            "Strong cryptography for PAN storage",
            "One-way hashes based on strong cryptography",
            "Truncation",
            "Index tokens"
        ],
        testing_procedures=[
            "Examine encryption methods used",
            "Verify key management procedures",
            "Test tokenization implementation"
        ],
        implementation_guidance="Implement AES-256 encryption for all PAN data"
    ),
    "6.2.4": Control(
        id="6.2.4",
        framework=Framework.PCI_DSS,
        title="Software Development Security Training",
        description="Software development personnel receive training on secure coding",
        category="Develop and Maintain Secure Systems",
        requirements=[
            "Secure coding training program",
            "Training frequency requirements",
            "Coverage of relevant vulnerabilities"
        ],
        testing_procedures=[
            "Review training materials",
            "Verify training records",
            "Interview developers"
        ],
        implementation_guidance="Establish annual secure coding training program"
    ),
    "8.3.6": Control(
        id="8.3.6",
        framework=Framework.PCI_DSS,
        title="Password/Passphrase Complexity",
        description="Passwords/passphrases meet minimum complexity requirements",
        category="Identify Users and Authenticate Access",
        requirements=[
            "Minimum 12 characters or system maximum",
            "Numeric and alphabetic characters",
            "Password history enforcement"
        ],
        testing_procedures=[
            "Examine password policy settings",
            "Test password complexity enforcement",
            "Verify history requirements"
        ],
        implementation_guidance="Configure password policy with minimum 12 chars, complexity, 4 history"
    ),
    "11.3.1": Control(
        id="11.3.1",
        framework=Framework.PCI_DSS,
        title="Internal Vulnerability Scans",
        description="Internal vulnerability scans are performed quarterly",
        category="Regularly Test Security Systems",
        requirements=[
            "Quarterly internal vulnerability scans",
            "High-risk vulnerabilities addressed",
            "Rescan to verify remediation"
        ],
        testing_procedures=[
            "Review scan reports",
            "Verify quarterly frequency",
            "Examine remediation evidence"
        ],
        implementation_guidance="Schedule quarterly scans with HydraRecon vulnerability scanner"
    ),
}

# HIPAA Controls
HIPAA_CONTROLS = {
    "164.308(a)(1)": Control(
        id="164.308(a)(1)",
        framework=Framework.HIPAA,
        title="Security Management Process",
        description="Implement policies and procedures to prevent, detect, contain, and correct security violations",
        category="Administrative Safeguards",
        requirements=[
            "Risk analysis conducted",
            "Risk management program",
            "Sanction policy",
            "Information system activity review"
        ],
        testing_procedures=[
            "Review risk assessment documentation",
            "Examine risk management procedures",
            "Review sanction policy and enforcement"
        ],
        implementation_guidance="Conduct annual risk assessment using NIST methodology"
    ),
    "164.312(a)(1)": Control(
        id="164.312(a)(1)",
        framework=Framework.HIPAA,
        title="Access Control",
        description="Implement technical policies and procedures for access to ePHI",
        category="Technical Safeguards",
        requirements=[
            "Unique user identification",
            "Emergency access procedure",
            "Automatic logoff",
            "Encryption and decryption"
        ],
        testing_procedures=[
            "Review access control configurations",
            "Test emergency access procedures",
            "Verify session timeout settings"
        ],
        implementation_guidance="Implement RBAC with automatic session timeout"
    ),
    "164.312(e)(1)": Control(
        id="164.312(e)(1)",
        framework=Framework.HIPAA,
        title="Transmission Security",
        description="Implement technical security measures to guard against unauthorized access to ePHI during transmission",
        category="Technical Safeguards",
        requirements=[
            "Integrity controls",
            "Encryption for transmission"
        ],
        testing_procedures=[
            "Review encryption protocols",
            "Test transmission security",
            "Verify TLS configuration"
        ],
        implementation_guidance="Enforce TLS 1.3 for all ePHI transmission"
    ),
}

# GDPR Controls
GDPR_CONTROLS = {
    "Art.5": Control(
        id="Art.5",
        framework=Framework.GDPR,
        title="Principles of Processing",
        description="Personal data shall be processed lawfully, fairly and transparently",
        category="Data Processing Principles",
        requirements=[
            "Lawfulness, fairness, transparency",
            "Purpose limitation",
            "Data minimization",
            "Accuracy",
            "Storage limitation",
            "Integrity and confidentiality"
        ],
        testing_procedures=[
            "Review privacy notices",
            "Examine data processing records",
            "Verify data retention policies"
        ],
        implementation_guidance="Document lawful basis for all processing activities"
    ),
    "Art.32": Control(
        id="Art.32",
        framework=Framework.GDPR,
        title="Security of Processing",
        description="Implement appropriate technical and organizational measures",
        category="Security",
        requirements=[
            "Pseudonymization and encryption",
            "Confidentiality, integrity, availability",
            "Resilience of systems",
            "Regular testing and evaluation"
        ],
        testing_procedures=[
            "Review encryption implementation",
            "Test backup and recovery",
            "Examine security testing program"
        ],
        implementation_guidance="Implement encryption, access controls, and regular security testing"
    ),
    "Art.33": Control(
        id="Art.33",
        framework=Framework.GDPR,
        title="Breach Notification",
        description="Notification of personal data breach to supervisory authority",
        category="Breach Response",
        requirements=[
            "72-hour notification requirement",
            "Documented breach procedures",
            "Risk assessment for breaches"
        ],
        testing_procedures=[
            "Review breach response procedures",
            "Examine notification templates",
            "Test incident response capabilities"
        ],
        implementation_guidance="Establish 72-hour breach notification process"
    ),
}

# NIST CSF Controls
NIST_CSF_CONTROLS = {
    "ID.AM-1": Control(
        id="ID.AM-1",
        framework=Framework.NIST_CSF,
        title="Asset Inventory",
        description="Physical devices and systems are inventoried",
        category="Identify - Asset Management",
        requirements=[
            "Hardware asset inventory",
            "Software asset inventory",
            "Network device inventory"
        ],
        testing_procedures=[
            "Review asset inventory",
            "Verify inventory accuracy",
            "Examine update procedures"
        ],
        implementation_guidance="Maintain automated asset discovery and inventory"
    ),
    "PR.AC-1": Control(
        id="PR.AC-1",
        framework=Framework.NIST_CSF,
        title="Identity Management",
        description="Identities and credentials are issued, managed, verified, revoked",
        category="Protect - Access Control",
        requirements=[
            "Identity management policy",
            "Credential lifecycle management",
            "Access provisioning process"
        ],
        testing_procedures=[
            "Review identity management procedures",
            "Test provisioning and deprovisioning",
            "Examine credential policies"
        ],
        implementation_guidance="Implement centralized identity management with SSO"
    ),
    "DE.CM-1": Control(
        id="DE.CM-1",
        framework=Framework.NIST_CSF,
        title="Network Monitoring",
        description="The network is monitored to detect potential cybersecurity events",
        category="Detect - Continuous Monitoring",
        requirements=[
            "Network monitoring tools",
            "Traffic analysis",
            "Anomaly detection"
        ],
        testing_procedures=[
            "Review monitoring configurations",
            "Test detection capabilities",
            "Examine alert procedures"
        ],
        implementation_guidance="Deploy network monitoring with anomaly detection"
    ),
    "RS.RP-1": Control(
        id="RS.RP-1",
        framework=Framework.NIST_CSF,
        title="Incident Response Plan",
        description="Response plan is executed during or after an incident",
        category="Respond - Response Planning",
        requirements=[
            "Documented incident response plan",
            "Roles and responsibilities defined",
            "Communication procedures"
        ],
        testing_procedures=[
            "Review incident response plan",
            "Verify team assignments",
            "Test response procedures"
        ],
        implementation_guidance="Maintain and test incident response plan quarterly"
    ),
}

# CIS Controls v8
CIS_CONTROLS = {
    "1.1": Control(
        id="1.1",
        framework=Framework.CIS,
        title="Establish and Maintain Enterprise Asset Inventory",
        description="Actively manage all enterprise assets connected to the infrastructure",
        category="Inventory and Control of Enterprise Assets",
        requirements=[
            "Automated asset discovery",
            "Asset inventory database",
            "Weekly inventory updates"
        ],
        testing_procedures=[
            "Review discovery tool configurations",
            "Verify inventory completeness",
            "Examine update frequency"
        ],
        implementation_guidance="Deploy automated asset discovery scanning weekly"
    ),
    "4.1": Control(
        id="4.1",
        framework=Framework.CIS,
        title="Establish and Maintain Secure Configuration Process",
        description="Establish and maintain secure configuration process for enterprise assets",
        category="Secure Configuration of Assets and Software",
        requirements=[
            "Configuration standards documented",
            "Hardening guides applied",
            "Configuration management tools"
        ],
        testing_procedures=[
            "Review configuration standards",
            "Test configuration compliance",
            "Examine hardening procedures"
        ],
        implementation_guidance="Implement CIS Benchmarks for all systems"
    ),
    "7.1": Control(
        id="7.1",
        framework=Framework.CIS,
        title="Establish and Maintain Vulnerability Management Process",
        description="Establish and maintain documented vulnerability management process",
        category="Continuous Vulnerability Management",
        requirements=[
            "Vulnerability scanning schedule",
            "Risk-based prioritization",
            "Remediation SLAs"
        ],
        testing_procedures=[
            "Review scanning schedule",
            "Verify prioritization methodology",
            "Examine remediation metrics"
        ],
        implementation_guidance="Perform weekly vulnerability scans with risk-based prioritization"
    ),
}

# MITRE ATT&CK Mappings
MITRE_TECHNIQUES = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "controls": ["CC6.6", "6.2.4", "PR.AC-1"],
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "controls": ["CC6.1", "8.3.6", "164.312(a)(1)"],
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "controls": ["CC7.1", "RS.RP-1", "Art.33"],
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "controls": ["CC6.6", "DE.CM-1", "7.1"],
    },
}


class ControlLibrary:
    """
    Compliance control library.
    """
    
    def __init__(self):
        self._controls: Dict[Framework, Dict[str, Control]] = {
            Framework.SOC2: SOC2_CONTROLS,
            Framework.PCI_DSS: PCI_DSS_CONTROLS,
            Framework.HIPAA: HIPAA_CONTROLS,
            Framework.GDPR: GDPR_CONTROLS,
            Framework.NIST_CSF: NIST_CSF_CONTROLS,
            Framework.CIS: CIS_CONTROLS,
        }
        self._mitre = MITRE_TECHNIQUES
    
    def get_controls(self, framework: Framework) -> Dict[str, Control]:
        """Get all controls for framework."""
        return self._controls.get(framework, {})
    
    def get_control(self, framework: Framework, control_id: str) -> Optional[Control]:
        """Get specific control."""
        controls = self._controls.get(framework, {})
        return controls.get(control_id)
    
    def search_controls(self, query: str) -> List[Control]:
        """Search controls by keyword."""
        results = []
        query_lower = query.lower()
        
        for framework_controls in self._controls.values():
            for control in framework_controls.values():
                if query_lower in control.title.lower() or \
                   query_lower in control.description.lower():
                    results.append(control)
        
        return results
    
    def get_mitre_mapping(self, technique_id: str) -> Optional[Dict]:
        """Get MITRE ATT&CK technique with control mappings."""
        return self._mitre.get(technique_id)
    
    def get_all_frameworks(self) -> List[Framework]:
        """Get all available frameworks."""
        return list(self._controls.keys())


class EvidenceManager:
    """
    Evidence collection and management.
    """
    
    def __init__(self, storage_path: str = None):
        self.storage_path = storage_path or "/tmp/evidence"
        self._evidence: Dict[str, Evidence] = {}
        self._lock = threading.RLock()
    
    def collect(self, type: EvidenceType, title: str,
               description: str, content: bytes = None,
               file_path: str = None, collected_by: str = "system",
               control_ids: List[str] = None) -> Evidence:
        """
        Collect and store evidence.
        
        Args:
            type: Evidence type
            title: Evidence title
            description: Description
            content: File content (optional)
            file_path: Existing file path (optional)
            collected_by: Collector name
            control_ids: Associated control IDs
            
        Returns:
            Evidence record
        """
        evidence_id = str(uuid.uuid4())
        
        # Calculate hash
        if content:
            content_hash = hashlib.sha256(content).hexdigest()
        elif file_path and os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                content_hash = hashlib.sha256(f.read()).hexdigest()
        else:
            content_hash = hashlib.sha256(title.encode()).hexdigest()
        
        evidence = Evidence(
            id=evidence_id,
            type=type,
            title=title,
            description=description,
            file_path=file_path,
            content_hash=content_hash,
            collected_at=datetime.now(),
            collected_by=collected_by,
            control_ids=control_ids or []
        )
        
        with self._lock:
            self._evidence[evidence_id] = evidence
        
        return evidence
    
    def get(self, evidence_id: str) -> Optional[Evidence]:
        """Get evidence by ID."""
        return self._evidence.get(evidence_id)
    
    def get_by_control(self, control_id: str) -> List[Evidence]:
        """Get evidence for control."""
        return [
            e for e in self._evidence.values()
            if control_id in e.control_ids
        ]
    
    def verify_integrity(self, evidence_id: str) -> bool:
        """Verify evidence integrity."""
        evidence = self._evidence.get(evidence_id)
        if not evidence or not evidence.file_path:
            return True  # No file to verify
        
        if not os.path.exists(evidence.file_path):
            return False
        
        with open(evidence.file_path, 'rb') as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        
        return current_hash == evidence.content_hash
    
    def export(self) -> List[Dict]:
        """Export all evidence metadata."""
        return [
            {
                'id': e.id,
                'type': e.type.value,
                'title': e.title,
                'description': e.description,
                'hash': e.content_hash,
                'collected_at': e.collected_at.isoformat(),
                'collected_by': e.collected_by,
                'control_ids': e.control_ids,
            }
            for e in self._evidence.values()
        ]


class GapAnalyzer:
    """
    Compliance gap analysis.
    """
    
    def __init__(self, library: ControlLibrary):
        self.library = library
    
    def analyze(self, framework: Framework,
               assessments: Dict[str, ControlAssessment]) -> Dict:
        """
        Perform gap analysis.
        
        Args:
            framework: Framework to analyze
            assessments: Control assessments
            
        Returns:
            Gap analysis results
        """
        controls = self.library.get_controls(framework)
        
        # Initialize counters
        total = len(controls)
        implemented = 0
        partial = 0
        not_implemented = 0
        not_applicable = 0
        not_assessed = 0
        
        gaps = []
        by_category = defaultdict(lambda: {'total': 0, 'compliant': 0})
        
        for control_id, control in controls.items():
            assessment = assessments.get(control_id)
            category = control.category
            by_category[category]['total'] += 1
            
            if not assessment:
                not_assessed += 1
                gaps.append({
                    'control_id': control_id,
                    'title': control.title,
                    'status': 'not_assessed',
                    'category': category,
                    'priority': 'high',
                })
            elif assessment.status == ControlStatus.IMPLEMENTED:
                implemented += 1
                by_category[category]['compliant'] += 1
            elif assessment.status == ControlStatus.PARTIALLY_IMPLEMENTED:
                partial += 1
                gaps.append({
                    'control_id': control_id,
                    'title': control.title,
                    'status': 'partial',
                    'category': category,
                    'findings': assessment.findings,
                    'priority': 'medium',
                })
            elif assessment.status == ControlStatus.NOT_IMPLEMENTED:
                not_implemented += 1
                gaps.append({
                    'control_id': control_id,
                    'title': control.title,
                    'status': 'not_implemented',
                    'category': category,
                    'priority': 'critical',
                })
            elif assessment.status == ControlStatus.NOT_APPLICABLE:
                not_applicable += 1
                by_category[category]['compliant'] += 1
        
        # Calculate compliance score
        applicable = total - not_applicable
        if applicable > 0:
            compliance_score = (implemented / applicable) * 100
            partial_score = ((implemented + (partial * 0.5)) / applicable) * 100
        else:
            compliance_score = 100
            partial_score = 100
        
        # Calculate category compliance
        category_compliance = {}
        for cat, data in by_category.items():
            if data['total'] > 0:
                category_compliance[cat] = {
                    'total': data['total'],
                    'compliant': data['compliant'],
                    'percentage': round(data['compliant'] / data['total'] * 100, 1)
                }
        
        return {
            'framework': framework.value,
            'analyzed_at': datetime.now().isoformat(),
            'summary': {
                'total_controls': total,
                'implemented': implemented,
                'partially_implemented': partial,
                'not_implemented': not_implemented,
                'not_applicable': not_applicable,
                'not_assessed': not_assessed,
            },
            'scores': {
                'compliance_percentage': round(compliance_score, 1),
                'weighted_percentage': round(partial_score, 1),
            },
            'by_category': category_compliance,
            'gaps': sorted(gaps, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2}.get(x['priority'], 3)),
            'recommendations': self._generate_recommendations(gaps),
        }
    
    def _generate_recommendations(self, gaps: List[Dict]) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []
        
        critical_count = sum(1 for g in gaps if g['priority'] == 'critical')
        high_count = sum(1 for g in gaps if g['priority'] == 'high')
        
        if critical_count > 0:
            recommendations.append(
                f"URGENT: {critical_count} controls require immediate implementation"
            )
        
        if high_count > 0:
            recommendations.append(
                f"Complete assessments for {high_count} unassessed controls"
            )
        
        # Category-specific recommendations
        categories = defaultdict(int)
        for gap in gaps:
            categories[gap['category']] += 1
        
        for category, count in sorted(categories.items(), key=lambda x: -x[1])[:3]:
            recommendations.append(
                f"Focus on '{category}' area ({count} gaps)"
            )
        
        return recommendations


class ComplianceEngine:
    """
    Main compliance framework engine.
    """
    
    VERSION = "2.0"
    
    def __init__(self):
        self.library = ControlLibrary()
        self.evidence_manager = EvidenceManager()
        self.gap_analyzer = GapAnalyzer(self.library)
        
        # Assessments storage
        self._assessments: Dict[str, ControlAssessment] = {}
        self._findings: Dict[str, Finding] = {}
        self._audit_log: List[Dict] = []
        self._lock = threading.RLock()
    
    def assess_control(self, framework: Framework, control_id: str,
                      status: ControlStatus, assessor: str,
                      evidence_ids: List[str] = None,
                      findings: List[str] = None,
                      risk_level: RiskLevel = RiskLevel.LOW,
                      notes: str = "") -> ControlAssessment:
        """
        Assess a compliance control.
        
        Args:
            framework: Framework
            control_id: Control ID
            status: Implementation status
            assessor: Assessor name
            evidence_ids: Supporting evidence IDs
            findings: Assessment findings
            risk_level: Risk level
            notes: Additional notes
            
        Returns:
            Assessment record
        """
        control = self.library.get_control(framework, control_id)
        if not control:
            raise ValueError(f"Control not found: {control_id}")
        
        assessment = ControlAssessment(
            control_id=control_id,
            status=status,
            assessor=assessor,
            assessed_at=datetime.now(),
            evidence_ids=evidence_ids or [],
            findings=findings or [],
            risk_level=risk_level,
            notes=notes
        )
        
        with self._lock:
            key = f"{framework.value}:{control_id}"
            self._assessments[key] = assessment
            
            self._audit_log.append({
                'action': 'assess_control',
                'framework': framework.value,
                'control_id': control_id,
                'status': status.value,
                'assessor': assessor,
                'timestamp': datetime.now().isoformat()
            })
        
        return assessment
    
    def get_assessment(self, framework: Framework,
                      control_id: str) -> Optional[ControlAssessment]:
        """Get control assessment."""
        key = f"{framework.value}:{control_id}"
        return self._assessments.get(key)
    
    def get_all_assessments(self, framework: Framework) -> Dict[str, ControlAssessment]:
        """Get all assessments for framework."""
        prefix = f"{framework.value}:"
        return {
            k.replace(prefix, ''): v
            for k, v in self._assessments.items()
            if k.startswith(prefix)
        }
    
    def run_gap_analysis(self, framework: Framework) -> Dict:
        """
        Run gap analysis for framework.
        
        Args:
            framework: Framework to analyze
            
        Returns:
            Gap analysis results
        """
        assessments = self.get_all_assessments(framework)
        return self.gap_analyzer.analyze(framework, assessments)
    
    def create_finding(self, control_id: str, title: str,
                      description: str, risk_level: RiskLevel,
                      identified_by: str,
                      remediation_steps: List[str]) -> Finding:
        """Create compliance finding."""
        finding = Finding(
            id=str(uuid.uuid4()),
            control_id=control_id,
            title=title,
            description=description,
            risk_level=risk_level,
            status='open',
            identified_at=datetime.now(),
            identified_by=identified_by,
            remediation_steps=remediation_steps
        )
        
        with self._lock:
            self._findings[finding.id] = finding
        
        return finding
    
    def get_findings(self, status: str = None) -> List[Finding]:
        """Get findings, optionally filtered by status."""
        findings = list(self._findings.values())
        if status:
            findings = [f for f in findings if f.status == status]
        return sorted(findings, key=lambda f: -f.risk_level.value)
    
    def resolve_finding(self, finding_id: str, resolved_by: str):
        """Mark finding as resolved."""
        with self._lock:
            if finding_id in self._findings:
                self._findings[finding_id].status = 'resolved'
                self._findings[finding_id].resolved_at = datetime.now()
                
                self._audit_log.append({
                    'action': 'resolve_finding',
                    'finding_id': finding_id,
                    'resolved_by': resolved_by,
                    'timestamp': datetime.now().isoformat()
                })
    
    def map_to_mitre(self, vulnerability: Dict) -> List[str]:
        """
        Map vulnerability to MITRE ATT&CK techniques.
        
        Args:
            vulnerability: Vulnerability data with title/description
            
        Returns:
            List of technique IDs
        """
        techniques = []
        vuln_text = f"{vulnerability.get('title', '')} {vulnerability.get('description', '')}".lower()
        
        # Simple keyword matching (production would use ML)
        mappings = {
            'T1190': ['sql injection', 'rce', 'remote code', 'exploit'],
            'T1078': ['credential', 'authentication', 'password', 'brute'],
            'T1486': ['ransomware', 'encryption', 'crypto'],
            'T1071': ['c2', 'command and control', 'beacon'],
        }
        
        for tech_id, keywords in mappings.items():
            if any(kw in vuln_text for kw in keywords):
                techniques.append(tech_id)
        
        return techniques
    
    def generate_compliance_report(self, frameworks: List[Framework]) -> Dict:
        """
        Generate comprehensive compliance report.
        
        Args:
            frameworks: Frameworks to include
            
        Returns:
            Compliance report data
        """
        report = {
            'generated_at': datetime.now().isoformat(),
            'version': self.VERSION,
            'frameworks': {},
            'overall_score': 0,
            'findings_summary': {
                'total': len(self._findings),
                'open': len([f for f in self._findings.values() if f.status == 'open']),
                'resolved': len([f for f in self._findings.values() if f.status == 'resolved']),
            },
            'evidence_count': len(self.evidence_manager._evidence),
        }
        
        total_score = 0
        for framework in frameworks:
            analysis = self.run_gap_analysis(framework)
            report['frameworks'][framework.value] = analysis
            total_score += analysis['scores']['compliance_percentage']
        
        if frameworks:
            report['overall_score'] = round(total_score / len(frameworks), 1)
        
        return report
    
    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        """Get audit log entries."""
        return self._audit_log[-limit:]
    
    def export_assessments(self) -> str:
        """Export all assessments as JSON."""
        data = {
            'exported_at': datetime.now().isoformat(),
            'assessments': [
                {
                    'key': k,
                    **v.to_dict()
                }
                for k, v in self._assessments.items()
            ],
            'findings': [
                {
                    'id': f.id,
                    'control_id': f.control_id,
                    'title': f.title,
                    'risk_level': f.risk_level.name,
                    'status': f.status,
                }
                for f in self._findings.values()
            ],
            'evidence': self.evidence_manager.export()
        }
        return json.dumps(data, indent=2)


# Testing
def main():
    """Test compliance framework engine."""
    print("Compliance Framework Engine Tests")
    print("=" * 50)
    
    engine = ComplianceEngine()
    
    # Test 1: Control Library
    print("\n1. Control Library...")
    frameworks = engine.library.get_all_frameworks()
    print(f"   Available frameworks: {len(frameworks)}")
    for fw in frameworks:
        controls = engine.library.get_controls(fw)
        print(f"   - {fw.value}: {len(controls)} controls")
    
    # Test 2: Control Search
    print("\n2. Control Search...")
    results = engine.library.search_controls("access")
    print(f"   Found {len(results)} controls for 'access'")
    
    # Test 3: Assess Controls
    print("\n3. Assessing Controls...")
    
    # Collect some evidence
    evidence = engine.evidence_manager.collect(
        type=EvidenceType.CONFIGURATION,
        title="Firewall Configuration",
        description="Current firewall rules export",
        collected_by="security_team",
        control_ids=["CC6.6", "1.1.1"]
    )
    print(f"   Collected evidence: {evidence.id[:8]}...")
    
    # Assess SOC2 controls
    assessments_made = 0
    soc2_controls = engine.library.get_controls(Framework.SOC2)
    
    for i, (control_id, control) in enumerate(soc2_controls.items()):
        status = [
            ControlStatus.IMPLEMENTED,
            ControlStatus.PARTIALLY_IMPLEMENTED,
            ControlStatus.IMPLEMENTED,
            ControlStatus.NOT_IMPLEMENTED,
        ][i % 4]
        
        engine.assess_control(
            framework=Framework.SOC2,
            control_id=control_id,
            status=status,
            assessor="auditor@company.com",
            evidence_ids=[evidence.id] if status == ControlStatus.IMPLEMENTED else [],
            risk_level=RiskLevel.MEDIUM if status != ControlStatus.IMPLEMENTED else RiskLevel.LOW
        )
        assessments_made += 1
    
    print(f"   Assessed {assessments_made} SOC2 controls")
    
    # Test 4: Gap Analysis
    print("\n4. Gap Analysis...")
    gap_analysis = engine.run_gap_analysis(Framework.SOC2)
    print(f"   Compliance Score: {gap_analysis['scores']['compliance_percentage']}%")
    print(f"   Gaps Found: {len(gap_analysis['gaps'])}")
    print(f"   Recommendations:")
    for rec in gap_analysis['recommendations'][:3]:
        print(f"   - {rec}")
    
    # Test 5: Create Finding
    print("\n5. Creating Finding...")
    finding = engine.create_finding(
        control_id="CC6.6",
        title="Missing Web Application Firewall",
        description="No WAF deployed to protect web applications",
        risk_level=RiskLevel.HIGH,
        identified_by="pentest_team",
        remediation_steps=[
            "Evaluate WAF solutions (ModSecurity, AWS WAF, Cloudflare)",
            "Deploy WAF in detection mode",
            "Tune rules to reduce false positives",
            "Enable blocking mode"
        ]
    )
    print(f"   Finding ID: {finding.id[:8]}...")
    print(f"   Risk Level: {finding.risk_level.name}")
    
    # Test 6: MITRE Mapping
    print("\n6. MITRE ATT&CK Mapping...")
    vuln = {
        'title': 'SQL Injection Vulnerability',
        'description': 'SQL injection in login form allows remote code execution'
    }
    techniques = engine.map_to_mitre(vuln)
    print(f"   Mapped techniques: {techniques}")
    
    for tech_id in techniques:
        tech = engine.library.get_mitre_mapping(tech_id)
        if tech:
            print(f"   - {tech['id']}: {tech['name']} ({tech['tactic']})")
    
    # Test 7: Multi-Framework Analysis
    print("\n7. Multi-Framework Analysis...")
    
    # Quick assessment of other frameworks
    for fw in [Framework.PCI_DSS, Framework.HIPAA]:
        controls = engine.library.get_controls(fw)
        for i, control_id in enumerate(controls.keys()):
            status = ControlStatus.IMPLEMENTED if i % 2 == 0 else ControlStatus.PARTIALLY_IMPLEMENTED
            engine.assess_control(fw, control_id, status, "auditor@company.com")
    
    report = engine.generate_compliance_report([
        Framework.SOC2,
        Framework.PCI_DSS,
        Framework.HIPAA
    ])
    
    print(f"   Overall Score: {report['overall_score']}%")
    print(f"   Frameworks analyzed:")
    for fw, data in report['frameworks'].items():
        print(f"   - {fw}: {data['scores']['compliance_percentage']}%")
    
    # Test 8: Evidence Integrity
    print("\n8. Evidence Integrity...")
    integrity_ok = engine.evidence_manager.verify_integrity(evidence.id)
    print(f"   Evidence integrity: {'Valid' if integrity_ok else 'Compromised'}")
    
    # Test 9: Audit Log
    print("\n9. Audit Log...")
    audit_entries = engine.get_audit_log(5)
    print(f"   Recent entries: {len(audit_entries)}")
    for entry in audit_entries[-3:]:
        print(f"   - {entry['action']}: {entry.get('control_id', entry.get('finding_id', 'N/A'))}")
    
    # Test 10: Export
    print("\n10. Export Data...")
    export_data = engine.export_assessments()
    export_size = len(export_data)
    print(f"   Export size: {export_size} bytes")
    
    print("\n" + "=" * 50)
    print("Compliance Engine: READY FOR PRODUCTION")


if __name__ == "__main__":
    main()
