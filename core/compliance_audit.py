#!/usr/bin/env python3
"""
HydraRecon Compliance Audit Module
Security compliance assessment for various regulatory frameworks.
"""

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Callable
from datetime import datetime
from enum import Enum
import subprocess


class ComplianceFramework(Enum):
    """Compliance frameworks"""
    NIST_CSF = "nist_csf"
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOX = "sox"
    GDPR = "gdpr"
    SOC2 = "soc2"
    CIS_CONTROLS = "cis_controls"
    CCPA = "ccpa"
    FEDRAMP = "fedramp"
    CMMC = "cmmc"


class ControlStatus(Enum):
    """Control implementation status"""
    NOT_ASSESSED = "not_assessed"
    NOT_IMPLEMENTED = "not_implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    FULLY_IMPLEMENTED = "fully_implemented"
    NOT_APPLICABLE = "not_applicable"


class FindingSeverity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class ComplianceControl:
    """Compliance control definition"""
    control_id: str
    title: str
    description: str
    framework: ComplianceFramework
    category: str
    requirements: List[str] = field(default_factory=list)
    test_procedures: List[str] = field(default_factory=list)
    evidence_required: List[str] = field(default_factory=list)


@dataclass
class ControlAssessment:
    """Control assessment result"""
    control: ComplianceControl
    status: ControlStatus
    score: float = 0.0  # 0-100
    findings: List[str] = field(default_factory=list)
    evidence_collected: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)
    assessed_at: datetime = field(default_factory=datetime.now)


@dataclass
class ComplianceFinding:
    """Compliance finding"""
    finding_id: str
    control_id: str
    title: str
    description: str
    severity: FindingSeverity
    impact: str
    likelihood: str
    risk_score: float
    affected_systems: List[str] = field(default_factory=list)
    remediation: str = ""
    due_date: Optional[datetime] = None
    status: str = "open"


@dataclass
class ComplianceReport:
    """Compliance assessment report"""
    report_id: str
    framework: ComplianceFramework
    assessment_date: datetime
    organization: str = ""
    scope: str = ""
    overall_score: float = 0.0
    controls_assessed: int = 0
    controls_passed: int = 0
    controls_failed: int = 0
    controls_partial: int = 0
    findings: List[ComplianceFinding] = field(default_factory=list)
    assessments: List[ControlAssessment] = field(default_factory=list)
    executive_summary: str = ""
    recommendations: List[str] = field(default_factory=list)


class NISTCSFControls:
    """NIST Cybersecurity Framework controls"""
    
    def __init__(self):
        self.controls = self._load_controls()
    
    def _load_controls(self) -> List[ComplianceControl]:
        """Load NIST CSF controls"""
        controls = []
        
        # IDENTIFY Function
        identify_controls = [
            ("ID.AM-1", "Asset Management", 
             "Physical devices and systems within the organization are inventoried",
             ["Maintain hardware inventory", "Track asset locations", "Document asset ownership"]),
            ("ID.AM-2", "Asset Management",
             "Software platforms and applications within the organization are inventoried",
             ["Software inventory", "License tracking", "Version control"]),
            ("ID.GV-1", "Governance",
             "Organizational cybersecurity policy is established and communicated",
             ["Security policy documentation", "Policy review process", "Employee acknowledgment"]),
            ("ID.RA-1", "Risk Assessment",
             "Asset vulnerabilities are identified and documented",
             ["Vulnerability scanning", "Penetration testing", "Risk assessment"]),
        ]
        
        for ctrl_id, category, desc, reqs in identify_controls:
            controls.append(ComplianceControl(
                control_id=ctrl_id,
                title=category,
                description=desc,
                framework=ComplianceFramework.NIST_CSF,
                category="IDENTIFY",
                requirements=reqs
            ))
        
        # PROTECT Function
        protect_controls = [
            ("PR.AC-1", "Access Control",
             "Identities and credentials are issued, managed, verified, revoked, and audited",
             ["Identity management", "Password policies", "Access reviews"]),
            ("PR.AC-4", "Access Control",
             "Access permissions and authorizations are managed with least privilege",
             ["RBAC implementation", "Permission reviews", "Segregation of duties"]),
            ("PR.DS-1", "Data Security",
             "Data-at-rest is protected",
             ["Encryption at rest", "Key management", "Access controls"]),
            ("PR.DS-2", "Data Security",
             "Data-in-transit is protected",
             ["TLS/SSL", "VPN", "Encrypted communications"]),
            ("PR.PT-1", "Protective Technology",
             "Audit/log records are determined, documented, implemented",
             ["Logging policy", "Log retention", "Log protection"]),
        ]
        
        for ctrl_id, category, desc, reqs in protect_controls:
            controls.append(ComplianceControl(
                control_id=ctrl_id,
                title=category,
                description=desc,
                framework=ComplianceFramework.NIST_CSF,
                category="PROTECT",
                requirements=reqs
            ))
        
        # DETECT Function
        detect_controls = [
            ("DE.AE-1", "Anomalies and Events",
             "A baseline of network operations and expected data flows is established",
             ["Network monitoring", "Baseline documentation", "Traffic analysis"]),
            ("DE.CM-1", "Security Continuous Monitoring",
             "The network is monitored to detect potential cybersecurity events",
             ["IDS/IPS", "SIEM", "Network monitoring tools"]),
            ("DE.CM-4", "Security Continuous Monitoring",
             "Malicious code is detected",
             ["Antivirus", "EDR", "Malware analysis"]),
        ]
        
        for ctrl_id, category, desc, reqs in detect_controls:
            controls.append(ComplianceControl(
                control_id=ctrl_id,
                title=category,
                description=desc,
                framework=ComplianceFramework.NIST_CSF,
                category="DETECT",
                requirements=reqs
            ))
        
        # RESPOND Function
        respond_controls = [
            ("RS.RP-1", "Response Planning",
             "Response plan is executed during or after an incident",
             ["Incident response plan", "Playbooks", "Communication procedures"]),
            ("RS.AN-1", "Analysis",
             "Notifications from detection systems are investigated",
             ["Alert triage", "Investigation procedures", "Forensic capabilities"]),
        ]
        
        for ctrl_id, category, desc, reqs in respond_controls:
            controls.append(ComplianceControl(
                control_id=ctrl_id,
                title=category,
                description=desc,
                framework=ComplianceFramework.NIST_CSF,
                category="RESPOND",
                requirements=reqs
            ))
        
        # RECOVER Function
        recover_controls = [
            ("RC.RP-1", "Recovery Planning",
             "Recovery plan is executed during or after a cybersecurity incident",
             ["Disaster recovery plan", "Business continuity", "Backup procedures"]),
            ("RC.IM-1", "Improvements",
             "Recovery plans incorporate lessons learned",
             ["Post-incident review", "Plan updates", "Continuous improvement"]),
        ]
        
        for ctrl_id, category, desc, reqs in recover_controls:
            controls.append(ComplianceControl(
                control_id=ctrl_id,
                title=category,
                description=desc,
                framework=ComplianceFramework.NIST_CSF,
                category="RECOVER",
                requirements=reqs
            ))
        
        return controls
    
    def get_controls(self) -> List[ComplianceControl]:
        """Get all NIST CSF controls"""
        return self.controls
    
    def get_controls_by_category(self, category: str) -> List[ComplianceControl]:
        """Get controls by category"""
        return [c for c in self.controls if c.category == category]


class PCIDSSControls:
    """PCI DSS v4.0 controls"""
    
    def __init__(self):
        self.controls = self._load_controls()
    
    def _load_controls(self) -> List[ComplianceControl]:
        """Load PCI DSS controls"""
        controls = []
        
        # Requirement 1: Network Security Controls
        req1 = [
            ("1.1", "Network Security Controls",
             "Processes and mechanisms for installing and maintaining network security controls",
             ["Firewall rules documented", "Change control process", "Network diagram"]),
            ("1.2", "Network Security Controls",
             "Network security controls are configured and maintained",
             ["Firewall configuration", "Inbound/outbound rules", "Default deny"]),
        ]
        
        for ctrl_id, title, desc, reqs in req1:
            controls.append(ComplianceControl(
                control_id=f"PCI-{ctrl_id}",
                title=title,
                description=desc,
                framework=ComplianceFramework.PCI_DSS,
                category="Requirement 1",
                requirements=reqs
            ))
        
        # Requirement 3: Protect Stored Data
        req3 = [
            ("3.1", "Protect Stored Account Data",
             "Account data storage is kept to a minimum",
             ["Data retention policy", "Quarterly reviews", "Data disposal"]),
            ("3.4", "Protect Stored Account Data",
             "PAN is masked when displayed",
             ["Masking rules", "First six/last four", "Role-based access"]),
            ("3.5", "Protect Stored Account Data",
             "PAN is secured wherever it is stored",
             ["Encryption", "Hashing", "Truncation"]),
        ]
        
        for ctrl_id, title, desc, reqs in req3:
            controls.append(ComplianceControl(
                control_id=f"PCI-{ctrl_id}",
                title=title,
                description=desc,
                framework=ComplianceFramework.PCI_DSS,
                category="Requirement 3",
                requirements=reqs
            ))
        
        # Requirement 6: Develop Secure Systems
        req6 = [
            ("6.2", "Develop Secure Systems",
             "Bespoke and custom software are developed securely",
             ["Secure coding standards", "Code review", "Security testing"]),
            ("6.3", "Develop Secure Systems",
             "Security vulnerabilities are identified and addressed",
             ["Vulnerability management", "Patching", "Remediation SLAs"]),
        ]
        
        for ctrl_id, title, desc, reqs in req6:
            controls.append(ComplianceControl(
                control_id=f"PCI-{ctrl_id}",
                title=title,
                description=desc,
                framework=ComplianceFramework.PCI_DSS,
                category="Requirement 6",
                requirements=reqs
            ))
        
        # Requirement 8: User Access
        req8 = [
            ("8.2", "Identify Users",
             "User identification and authentication for users is implemented",
             ["Unique IDs", "Strong authentication", "MFA for remote access"]),
            ("8.3", "Strong Authentication",
             "Strong authentication for users and administrators",
             ["Password complexity", "MFA", "Authentication policies"]),
        ]
        
        for ctrl_id, title, desc, reqs in req8:
            controls.append(ComplianceControl(
                control_id=f"PCI-{ctrl_id}",
                title=title,
                description=desc,
                framework=ComplianceFramework.PCI_DSS,
                category="Requirement 8",
                requirements=reqs
            ))
        
        # Requirement 11: Test Security
        req11 = [
            ("11.3", "External Vulnerability Scans",
             "External and internal vulnerabilities are regularly identified",
             ["Quarterly ASV scans", "Internal scans", "Remediation verification"]),
            ("11.4", "Penetration Testing",
             "Penetration testing is regularly performed",
             ["Annual pen tests", "Internal/external testing", "Segmentation tests"]),
        ]
        
        for ctrl_id, title, desc, reqs in req11:
            controls.append(ComplianceControl(
                control_id=f"PCI-{ctrl_id}",
                title=title,
                description=desc,
                framework=ComplianceFramework.PCI_DSS,
                category="Requirement 11",
                requirements=reqs
            ))
        
        return controls
    
    def get_controls(self) -> List[ComplianceControl]:
        """Get all PCI DSS controls"""
        return self.controls


class CISControls:
    """CIS Critical Security Controls v8"""
    
    def __init__(self):
        self.controls = self._load_controls()
    
    def _load_controls(self) -> List[ComplianceControl]:
        """Load CIS controls"""
        controls = []
        
        cis_controls = [
            ("CIS-1", "Inventory and Control of Enterprise Assets",
             "Actively manage all enterprise assets connected to the infrastructure",
             ["Asset discovery", "Hardware inventory", "Unauthorized asset detection"]),
            ("CIS-2", "Inventory and Control of Software Assets",
             "Actively manage all software on the network",
             ["Software inventory", "Authorized software list", "Software removal"]),
            ("CIS-3", "Data Protection",
             "Develop processes and technical controls to identify, classify, and protect data",
             ["Data classification", "Access controls", "Data encryption"]),
            ("CIS-4", "Secure Configuration",
             "Establish and maintain secure configuration of enterprise assets",
             ["Security baselines", "Configuration management", "Hardening guides"]),
            ("CIS-5", "Account Management",
             "Use processes and tools to assign and manage authorization to credentials",
             ["Account inventory", "Access reviews", "Privileged access management"]),
            ("CIS-6", "Access Control Management",
             "Use processes and tools to create, assign, manage access",
             ["RBAC", "Least privilege", "Access certifications"]),
            ("CIS-7", "Continuous Vulnerability Management",
             "Develop a plan to continuously assess and track vulnerabilities",
             ["Vulnerability scanning", "Risk-based remediation", "Patch management"]),
            ("CIS-8", "Audit Log Management",
             "Collect, alert, review, and retain audit logs",
             ["Centralized logging", "Log retention", "Alert correlation"]),
        ]
        
        for ctrl_id, title, desc, reqs in cis_controls:
            controls.append(ComplianceControl(
                control_id=ctrl_id,
                title=title,
                description=desc,
                framework=ComplianceFramework.CIS_CONTROLS,
                category="Critical Security Controls",
                requirements=reqs
            ))
        
        return controls
    
    def get_controls(self) -> List[ComplianceControl]:
        """Get all CIS controls"""
        return self.controls


class AutomatedScanner:
    """Automated compliance scanning"""
    
    def __init__(self):
        self.logger = logging.getLogger("AutomatedScanner")
    
    async def scan_network_controls(self, target: str) -> Dict[str, Any]:
        """Scan network security controls"""
        results = {
            "firewall_detected": False,
            "open_ports": [],
            "ssl_tls_issues": [],
            "network_segmentation": False
        }
        
        try:
            # Port scan
            cmd = ["nmap", "-sT", "-p", "1-1000", target, "-oX", "-"]
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            # Parse results (simplified)
            output = stdout.decode()
            if "filtered" in output:
                results["firewall_detected"] = True
            
            # Find open ports
            import re
            ports = re.findall(r'portid="(\d+)".*state="open"', output)
            results["open_ports"] = [int(p) for p in ports]
            
        except Exception as e:
            self.logger.error(f"Network scan error: {e}")
        
        return results
    
    async def scan_ssl_configuration(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Scan SSL/TLS configuration"""
        results = {
            "ssl_enabled": False,
            "protocols": [],
            "cipher_suites": [],
            "certificate_valid": False,
            "issues": []
        }
        
        try:
            # Use openssl to check SSL
            cmd = ["openssl", "s_client", "-connect", f"{target}:{port}", "-brief"]
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
            
            output = stdout.decode() + stderr.decode()
            
            if "Verification: OK" in output:
                results["certificate_valid"] = True
            
            results["ssl_enabled"] = "CONNECTED" in output or "TLS" in output
            
            # Check for weak protocols
            weak_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
            for proto in weak_protocols:
                if proto in output:
                    results["issues"].append(f"Weak protocol detected: {proto}")
                    
        except asyncio.TimeoutError:
            results["issues"].append("SSL connection timeout")
        except Exception as e:
            self.logger.error(f"SSL scan error: {e}")
        
        return results
    
    async def scan_authentication(self, target: str) -> Dict[str, Any]:
        """Scan authentication mechanisms"""
        results = {
            "mfa_enabled": False,
            "password_policy": {},
            "lockout_policy": {},
            "findings": []
        }
        
        # This would integrate with actual authentication testing
        # For now, return placeholder
        
        return results
    
    async def scan_logging(self, target: str) -> Dict[str, Any]:
        """Scan logging configuration"""
        results = {
            "centralized_logging": False,
            "log_retention": "unknown",
            "log_protection": False,
            "findings": []
        }
        
        return results


class ComplianceAuditEngine:
    """Main compliance audit engine"""
    
    def __init__(self):
        self.logger = logging.getLogger("ComplianceAuditEngine")
        self.scanner = AutomatedScanner()
        
        # Load control frameworks
        self.frameworks = {
            ComplianceFramework.NIST_CSF: NISTCSFControls(),
            ComplianceFramework.PCI_DSS: PCIDSSControls(),
            ComplianceFramework.CIS_CONTROLS: CISControls()
        }
        
        self.reports: List[ComplianceReport] = []
    
    def get_framework_controls(self, framework: ComplianceFramework) -> List[ComplianceControl]:
        """Get controls for a framework"""
        if framework in self.frameworks:
            return self.frameworks[framework].get_controls()
        return []
    
    async def assess_control(self, control: ComplianceControl,
                            target: str = None) -> ControlAssessment:
        """Assess a single control"""
        
        assessment = ControlAssessment(
            control=control,
            status=ControlStatus.NOT_ASSESSED,
            score=0.0
        )
        
        # Automated scanning for certain controls
        if target and "network" in control.title.lower():
            scan_results = await self.scanner.scan_network_controls(target)
            
            if scan_results.get("firewall_detected"):
                assessment.evidence_collected.append("Firewall detected")
                assessment.score += 30
            
            if not scan_results.get("open_ports"):
                assessment.evidence_collected.append("No unnecessary open ports")
                assessment.score += 20
            else:
                assessment.findings.append(f"Open ports: {scan_results['open_ports']}")
        
        if target and ("ssl" in control.description.lower() or 
                       "tls" in control.description.lower() or
                       "transit" in control.description.lower()):
            ssl_results = await self.scanner.scan_ssl_configuration(target)
            
            if ssl_results.get("ssl_enabled"):
                assessment.evidence_collected.append("SSL/TLS enabled")
                assessment.score += 25
            
            if ssl_results.get("certificate_valid"):
                assessment.evidence_collected.append("Valid SSL certificate")
                assessment.score += 25
            
            for issue in ssl_results.get("issues", []):
                assessment.findings.append(issue)
                assessment.score -= 10
        
        # Determine status based on score
        if assessment.score >= 80:
            assessment.status = ControlStatus.FULLY_IMPLEMENTED
        elif assessment.score >= 50:
            assessment.status = ControlStatus.PARTIALLY_IMPLEMENTED
        else:
            assessment.status = ControlStatus.NOT_IMPLEMENTED
        
        assessment.score = max(0, min(100, assessment.score))
        
        return assessment
    
    async def run_assessment(self, framework: ComplianceFramework,
                            target: str = None,
                            organization: str = "",
                            scope: str = "",
                            callback: Optional[Callable] = None) -> ComplianceReport:
        """Run full compliance assessment"""
        
        import hashlib
        report_id = hashlib.md5(f"{framework}{datetime.now()}".encode()).hexdigest()[:12]
        
        report = ComplianceReport(
            report_id=report_id,
            framework=framework,
            assessment_date=datetime.now(),
            organization=organization,
            scope=scope
        )
        
        controls = self.get_framework_controls(framework)
        total_controls = len(controls)
        
        if callback:
            callback(f"Starting {framework.value} assessment...", 0)
        
        for i, control in enumerate(controls):
            if callback and i % 5 == 0:
                progress = (i / total_controls) * 100
                callback(f"Assessing {control.control_id}...", progress)
            
            assessment = await self.assess_control(control, target)
            report.assessments.append(assessment)
            
            # Generate findings
            for finding_text in assessment.findings:
                severity = FindingSeverity.MEDIUM
                if "critical" in finding_text.lower():
                    severity = FindingSeverity.CRITICAL
                elif "high" in finding_text.lower() or "weak" in finding_text.lower():
                    severity = FindingSeverity.HIGH
                
                finding = ComplianceFinding(
                    finding_id=f"F-{report_id}-{len(report.findings)+1:04d}",
                    control_id=control.control_id,
                    title=f"Finding for {control.control_id}",
                    description=finding_text,
                    severity=severity,
                    impact="Security control not fully implemented",
                    likelihood="Medium",
                    risk_score=0.6 if severity == FindingSeverity.HIGH else 0.4
                )
                report.findings.append(finding)
        
        # Calculate statistics
        report.controls_assessed = len(report.assessments)
        report.controls_passed = sum(1 for a in report.assessments 
                                    if a.status == ControlStatus.FULLY_IMPLEMENTED)
        report.controls_failed = sum(1 for a in report.assessments 
                                    if a.status == ControlStatus.NOT_IMPLEMENTED)
        report.controls_partial = sum(1 for a in report.assessments 
                                     if a.status == ControlStatus.PARTIALLY_IMPLEMENTED)
        
        # Calculate overall score
        if report.controls_assessed > 0:
            total_score = sum(a.score for a in report.assessments)
            report.overall_score = total_score / report.controls_assessed
        
        # Generate executive summary
        report.executive_summary = self._generate_summary(report)
        report.recommendations = self._generate_recommendations(report)
        
        self.reports.append(report)
        
        if callback:
            callback("Assessment complete", 100)
        
        return report
    
    def _generate_summary(self, report: ComplianceReport) -> str:
        """Generate executive summary"""
        passed_pct = (report.controls_passed / max(1, report.controls_assessed)) * 100
        
        summary = f"""
{report.framework.value.upper()} Compliance Assessment Summary

Organization: {report.organization or 'Not specified'}
Scope: {report.scope or 'Full assessment'}
Assessment Date: {report.assessment_date.strftime('%Y-%m-%d')}

Overall Score: {report.overall_score:.1f}%

Control Assessment Results:
- Controls Assessed: {report.controls_assessed}
- Fully Implemented: {report.controls_passed} ({passed_pct:.1f}%)
- Partially Implemented: {report.controls_partial}
- Not Implemented: {report.controls_failed}

Findings Summary:
- Total Findings: {len(report.findings)}
- Critical: {sum(1 for f in report.findings if f.severity == FindingSeverity.CRITICAL)}
- High: {sum(1 for f in report.findings if f.severity == FindingSeverity.HIGH)}
- Medium: {sum(1 for f in report.findings if f.severity == FindingSeverity.MEDIUM)}
- Low: {sum(1 for f in report.findings if f.severity == FindingSeverity.LOW)}
"""
        return summary
    
    def _generate_recommendations(self, report: ComplianceReport) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        # Priority based on findings
        critical_count = sum(1 for f in report.findings if f.severity == FindingSeverity.CRITICAL)
        high_count = sum(1 for f in report.findings if f.severity == FindingSeverity.HIGH)
        
        if critical_count > 0:
            recommendations.append(
                f"URGENT: Address {critical_count} critical findings immediately"
            )
        
        if high_count > 0:
            recommendations.append(
                f"HIGH PRIORITY: Remediate {high_count} high-severity findings within 30 days"
            )
        
        if report.controls_failed > report.controls_assessed * 0.3:
            recommendations.append(
                "Consider implementing a comprehensive security program improvement initiative"
            )
        
        if report.overall_score < 50:
            recommendations.append(
                "Current compliance posture is below acceptable levels. Engage security consultants."
            )
        
        # Framework-specific recommendations
        if report.framework == ComplianceFramework.PCI_DSS:
            recommendations.append(
                "Ensure quarterly ASV scans and annual penetration testing are scheduled"
            )
        
        if report.framework == ComplianceFramework.NIST_CSF:
            recommendations.append(
                "Consider developing a detailed implementation plan aligned with NIST CSF tiers"
            )
        
        return recommendations
    
    def export_report(self, report_id: str, format: str = "json") -> str:
        """Export compliance report"""
        for report in self.reports:
            if report.report_id == report_id:
                if format == "json":
                    return json.dumps({
                        "report_id": report.report_id,
                        "framework": report.framework.value,
                        "assessment_date": report.assessment_date.isoformat(),
                        "organization": report.organization,
                        "overall_score": report.overall_score,
                        "controls_assessed": report.controls_assessed,
                        "controls_passed": report.controls_passed,
                        "controls_failed": report.controls_failed,
                        "findings": [
                            {
                                "id": f.finding_id,
                                "control": f.control_id,
                                "title": f.title,
                                "severity": f.severity.value,
                                "description": f.description
                            }
                            for f in report.findings
                        ],
                        "executive_summary": report.executive_summary,
                        "recommendations": report.recommendations
                    }, indent=2)
        return ""
    
    def get_gap_analysis(self, report: ComplianceReport) -> Dict[str, Any]:
        """Generate gap analysis from report"""
        gaps = []
        
        for assessment in report.assessments:
            if assessment.status in [ControlStatus.NOT_IMPLEMENTED, 
                                    ControlStatus.PARTIALLY_IMPLEMENTED]:
                gaps.append({
                    "control_id": assessment.control.control_id,
                    "control_title": assessment.control.title,
                    "status": assessment.status.value,
                    "current_score": assessment.score,
                    "gap_description": assessment.control.description,
                    "requirements": assessment.control.requirements,
                    "remediation_steps": assessment.remediation_steps or 
                                        assessment.control.requirements
                })
        
        return {
            "total_gaps": len(gaps),
            "gaps": gaps,
            "priority_gaps": [g for g in gaps if g["current_score"] < 30]
        }
