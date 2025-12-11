#!/usr/bin/env python3
"""
HydraRecon Vulnerability Management Module
Comprehensive vulnerability tracking, prioritization, and lifecycle management.
"""

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Callable
from datetime import datetime, timedelta
from enum import Enum
import subprocess
import hashlib


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class VulnerabilityStatus(Enum):
    """Vulnerability lifecycle status"""
    NEW = "new"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    REOPENED = "reopened"


class AssetType(Enum):
    """Asset types"""
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    APPLICATION = "application"
    DATABASE = "database"
    CONTAINER = "container"
    CLOUD_RESOURCE = "cloud_resource"
    IOT_DEVICE = "iot_device"


@dataclass
class CVSS:
    """CVSS score details"""
    version: str = "3.1"
    base_score: float = 0.0
    temporal_score: float = 0.0
    environmental_score: float = 0.0
    vector: str = ""
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""


@dataclass
class Asset:
    """Asset definition"""
    asset_id: str
    name: str
    asset_type: AssetType
    ip_address: str = ""
    hostname: str = ""
    os: str = ""
    criticality: int = 5  # 1-10
    owner: str = ""
    environment: str = ""  # prod, dev, staging
    tags: List[str] = field(default_factory=list)
    last_scanned: Optional[datetime] = None


@dataclass
class Vulnerability:
    """Vulnerability definition"""
    vuln_id: str
    cve_id: str = ""
    title: str = ""
    description: str = ""
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    status: VulnerabilityStatus = VulnerabilityStatus.NEW
    cvss: Optional[CVSS] = None
    affected_assets: List[str] = field(default_factory=list)
    discovered_date: datetime = field(default_factory=datetime.now)
    due_date: Optional[datetime] = None
    remediated_date: Optional[datetime] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_details: str = ""
    plugin_id: str = ""
    solution: str = ""
    risk_score: float = 0.0
    assigned_to: str = ""
    comments: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ScanResult:
    """Vulnerability scan result"""
    scan_id: str
    scan_type: str  # nessus, qualys, openvas, nmap
    start_time: datetime
    end_time: Optional[datetime] = None
    target: str = ""
    vulnerabilities_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class RemediationPlan:
    """Remediation plan for vulnerabilities"""
    plan_id: str
    title: str
    description: str
    vulnerabilities: List[str]  # vuln_ids
    priority: int = 5  # 1-10
    effort_hours: float = 0.0
    owner: str = ""
    status: str = "planned"
    start_date: Optional[datetime] = None
    target_date: Optional[datetime] = None
    completion_date: Optional[datetime] = None
    steps: List[Dict[str, Any]] = field(default_factory=list)


class CVSSCalculator:
    """Calculate CVSS scores"""
    
    def __init__(self):
        self.logger = logging.getLogger("CVSSCalculator")
    
    def calculate_base_score(self, attack_vector: str, attack_complexity: str,
                            privileges_required: str, user_interaction: str,
                            scope: str, confidentiality: str, integrity: str,
                            availability: str) -> float:
        """Calculate CVSS 3.1 base score"""
        
        # Attack Vector values
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        
        # Attack Complexity values
        ac_values = {"L": 0.77, "H": 0.44}
        
        # Privileges Required (with scope)
        pr_values_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_values_changed = {"N": 0.85, "L": 0.68, "H": 0.5}
        
        # User Interaction
        ui_values = {"N": 0.85, "R": 0.62}
        
        # CIA Impact
        impact_values = {"N": 0, "L": 0.22, "H": 0.56}
        
        try:
            av = av_values.get(attack_vector, 0.85)
            ac = ac_values.get(attack_complexity, 0.77)
            ui = ui_values.get(user_interaction, 0.85)
            
            scope_changed = scope == "C"
            pr_values = pr_values_changed if scope_changed else pr_values_unchanged
            pr = pr_values.get(privileges_required, 0.85)
            
            c = impact_values.get(confidentiality, 0.22)
            i = impact_values.get(integrity, 0.22)
            a = impact_values.get(availability, 0.22)
            
            # Calculate Impact
            isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
            
            if scope_changed:
                impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
            else:
                impact = 6.42 * isc_base
            
            # Calculate Exploitability
            exploitability = 8.22 * av * ac * pr * ui
            
            # Calculate Base Score
            if impact <= 0:
                return 0.0
            
            if scope_changed:
                base_score = min(1.08 * (impact + exploitability), 10)
            else:
                base_score = min(impact + exploitability, 10)
            
            # Round up to 1 decimal
            return round(base_score * 10) / 10
            
        except Exception as e:
            self.logger.error(f"Error calculating CVSS: {e}")
            return 5.0
    
    def get_severity_from_score(self, score: float) -> VulnerabilitySeverity:
        """Get severity level from CVSS score"""
        if score >= 9.0:
            return VulnerabilitySeverity.CRITICAL
        elif score >= 7.0:
            return VulnerabilitySeverity.HIGH
        elif score >= 4.0:
            return VulnerabilitySeverity.MEDIUM
        elif score >= 0.1:
            return VulnerabilitySeverity.LOW
        else:
            return VulnerabilitySeverity.INFORMATIONAL


class VulnerabilityScanner:
    """Interface with vulnerability scanners"""
    
    def __init__(self):
        self.logger = logging.getLogger("VulnerabilityScanner")
    
    async def run_nmap_scan(self, target: str,
                           callback: Optional[Callable] = None) -> ScanResult:
        """Run Nmap vulnerability scan"""
        
        scan_id = hashlib.md5(f"{target}{datetime.now()}".encode()).hexdigest()[:12]
        
        result = ScanResult(
            scan_id=scan_id,
            scan_type="nmap",
            start_time=datetime.now(),
            target=target
        )
        
        try:
            if callback:
                callback("Running Nmap vulnerability scan...", 10)
            
            # Run nmap with vulnerability scripts
            cmd = [
                "nmap", "-sV", "--script=vuln",
                "-oX", "-", target
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)
            
            if callback:
                callback("Parsing results...", 80)
            
            # Parse XML output
            output = stdout.decode()
            result.vulnerabilities = self._parse_nmap_output(output, scan_id)
            
            # Count by severity
            for vuln in result.vulnerabilities:
                if vuln.severity == VulnerabilitySeverity.CRITICAL:
                    result.critical_count += 1
                elif vuln.severity == VulnerabilitySeverity.HIGH:
                    result.high_count += 1
                elif vuln.severity == VulnerabilitySeverity.MEDIUM:
                    result.medium_count += 1
                else:
                    result.low_count += 1
            
            result.vulnerabilities_found = len(result.vulnerabilities)
            result.end_time = datetime.now()
            
        except asyncio.TimeoutError:
            self.logger.error("Nmap scan timed out")
        except Exception as e:
            self.logger.error(f"Nmap scan error: {e}")
        
        return result
    
    def _parse_nmap_output(self, xml_output: str, scan_id: str) -> List[Vulnerability]:
        """Parse Nmap XML output for vulnerabilities"""
        vulnerabilities = []
        
        # Simple regex parsing (would use xml.etree in production)
        script_pattern = r'<script id="([^"]+)"[^>]*>(.*?)</script>'
        
        for match in re.finditer(script_pattern, xml_output, re.DOTALL):
            script_id = match.group(1)
            script_output = match.group(2)
            
            # Check if it's a vulnerability finding
            if "VULNERABLE" in script_output.upper():
                vuln_id = f"{scan_id}-{len(vulnerabilities)+1:04d}"
                
                # Try to extract CVE
                cve_match = re.search(r'CVE-\d{4}-\d+', script_output)
                cve_id = cve_match.group(0) if cve_match else ""
                
                vuln = Vulnerability(
                    vuln_id=vuln_id,
                    cve_id=cve_id,
                    title=script_id.replace("-", " ").title(),
                    description=script_output[:500],
                    severity=VulnerabilitySeverity.MEDIUM,
                    plugin_id=script_id
                )
                
                # Adjust severity based on keywords
                output_lower = script_output.lower()
                if "critical" in output_lower or "remote code execution" in output_lower:
                    vuln.severity = VulnerabilitySeverity.CRITICAL
                elif "high" in output_lower or "denial of service" in output_lower:
                    vuln.severity = VulnerabilitySeverity.HIGH
                
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def import_nessus(self, filepath: str,
                           callback: Optional[Callable] = None) -> ScanResult:
        """Import Nessus scan results"""
        
        scan_id = hashlib.md5(f"{filepath}{datetime.now()}".encode()).hexdigest()[:12]
        
        result = ScanResult(
            scan_id=scan_id,
            scan_type="nessus",
            start_time=datetime.now()
        )
        
        try:
            if callback:
                callback("Parsing Nessus file...", 20)
            
            # Parse Nessus XML
            import xml.etree.ElementTree as ET
            tree = ET.parse(filepath)
            root = tree.getroot()
            
            for report_host in root.findall(".//ReportHost"):
                host_name = report_host.get("name", "")
                
                for report_item in report_host.findall("ReportItem"):
                    plugin_id = report_item.get("pluginID", "")
                    plugin_name = report_item.get("pluginName", "")
                    severity = int(report_item.get("severity", "0"))
                    
                    # Get CVE if available
                    cve_elem = report_item.find("cve")
                    cve_id = cve_elem.text if cve_elem is not None else ""
                    
                    # Get description
                    desc_elem = report_item.find("description")
                    description = desc_elem.text if desc_elem is not None else ""
                    
                    # Get solution
                    sol_elem = report_item.find("solution")
                    solution = sol_elem.text if sol_elem is not None else ""
                    
                    # Map severity
                    severity_map = {
                        0: VulnerabilitySeverity.INFORMATIONAL,
                        1: VulnerabilitySeverity.LOW,
                        2: VulnerabilitySeverity.MEDIUM,
                        3: VulnerabilitySeverity.HIGH,
                        4: VulnerabilitySeverity.CRITICAL
                    }
                    
                    vuln = Vulnerability(
                        vuln_id=f"{scan_id}-{len(result.vulnerabilities)+1:04d}",
                        cve_id=cve_id,
                        title=plugin_name,
                        description=description[:1000] if description else "",
                        severity=severity_map.get(severity, VulnerabilitySeverity.MEDIUM),
                        plugin_id=plugin_id,
                        solution=solution[:500] if solution else "",
                        affected_assets=[host_name]
                    )
                    
                    result.vulnerabilities.append(vuln)
                    
                    # Count by severity
                    if vuln.severity == VulnerabilitySeverity.CRITICAL:
                        result.critical_count += 1
                    elif vuln.severity == VulnerabilitySeverity.HIGH:
                        result.high_count += 1
                    elif vuln.severity == VulnerabilitySeverity.MEDIUM:
                        result.medium_count += 1
                    else:
                        result.low_count += 1
            
            result.vulnerabilities_found = len(result.vulnerabilities)
            result.end_time = datetime.now()
            
            if callback:
                callback("Import complete", 100)
                
        except Exception as e:
            self.logger.error(f"Error importing Nessus file: {e}")
        
        return result


class RiskCalculator:
    """Calculate risk scores"""
    
    def __init__(self):
        self.logger = logging.getLogger("RiskCalculator")
    
    def calculate_risk(self, vuln: Vulnerability, asset: Optional[Asset] = None) -> float:
        """Calculate risk score for vulnerability"""
        
        # Base risk from CVSS
        if vuln.cvss:
            base_risk = vuln.cvss.base_score
        else:
            # Default based on severity
            severity_scores = {
                VulnerabilitySeverity.CRITICAL: 9.0,
                VulnerabilitySeverity.HIGH: 7.5,
                VulnerabilitySeverity.MEDIUM: 5.0,
                VulnerabilitySeverity.LOW: 2.5,
                VulnerabilitySeverity.INFORMATIONAL: 0.5
            }
            base_risk = severity_scores.get(vuln.severity, 5.0)
        
        # Modifiers
        risk_score = base_risk
        
        # Exploit available modifier (+2)
        if vuln.exploit_available:
            risk_score += 2.0
        
        # Asset criticality modifier
        if asset:
            criticality_modifier = (asset.criticality - 5) * 0.2
            risk_score += criticality_modifier
            
            # Production environment modifier
            if asset.environment == "prod":
                risk_score += 1.0
        
        # Age modifier (older vulns get higher priority)
        age_days = (datetime.now() - vuln.discovered_date).days
        if age_days > 90:
            risk_score += 1.0
        elif age_days > 30:
            risk_score += 0.5
        
        # Cap at 10
        return min(10.0, max(0.0, risk_score))
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Vulnerability],
                                  assets: Dict[str, Asset] = None) -> List[Vulnerability]:
        """Prioritize vulnerabilities by risk score"""
        
        for vuln in vulnerabilities:
            # Find associated asset
            asset = None
            if assets and vuln.affected_assets:
                asset = assets.get(vuln.affected_assets[0])
            
            vuln.risk_score = self.calculate_risk(vuln, asset)
        
        # Sort by risk score (highest first)
        return sorted(vulnerabilities, key=lambda v: v.risk_score, reverse=True)


class RemediationTracker:
    """Track remediation efforts"""
    
    def __init__(self):
        self.logger = logging.getLogger("RemediationTracker")
        self.plans: Dict[str, RemediationPlan] = {}
    
    def create_plan(self, title: str, vulnerabilities: List[str],
                   priority: int = 5, owner: str = "",
                   target_date: Optional[datetime] = None) -> RemediationPlan:
        """Create a remediation plan"""
        
        plan_id = hashlib.md5(f"{title}{datetime.now()}".encode()).hexdigest()[:12]
        
        plan = RemediationPlan(
            plan_id=plan_id,
            title=title,
            description=f"Remediation plan for {len(vulnerabilities)} vulnerabilities",
            vulnerabilities=vulnerabilities,
            priority=priority,
            owner=owner,
            target_date=target_date
        )
        
        self.plans[plan_id] = plan
        return plan
    
    def calculate_sla(self, severity: VulnerabilitySeverity) -> timedelta:
        """Calculate SLA based on severity"""
        sla_days = {
            VulnerabilitySeverity.CRITICAL: 7,
            VulnerabilitySeverity.HIGH: 30,
            VulnerabilitySeverity.MEDIUM: 90,
            VulnerabilitySeverity.LOW: 180,
            VulnerabilitySeverity.INFORMATIONAL: 365
        }
        return timedelta(days=sla_days.get(severity, 90))
    
    def get_overdue_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Get vulnerabilities past their SLA"""
        overdue = []
        
        for vuln in vulnerabilities:
            if vuln.status in [VulnerabilityStatus.NEW, VulnerabilityStatus.CONFIRMED,
                               VulnerabilityStatus.IN_PROGRESS]:
                sla = self.calculate_sla(vuln.severity)
                if datetime.now() - vuln.discovered_date > sla:
                    overdue.append(vuln)
        
        return overdue


class VulnerabilityManagementEngine:
    """Main vulnerability management engine"""
    
    def __init__(self):
        self.logger = logging.getLogger("VulnerabilityManagementEngine")
        self.scanner = VulnerabilityScanner()
        self.cvss_calc = CVSSCalculator()
        self.risk_calc = RiskCalculator()
        self.remediation = RemediationTracker()
        
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.assets: Dict[str, Asset] = {}
        self.scans: List[ScanResult] = []
    
    async def run_scan(self, target: str, scan_type: str = "nmap",
                      callback: Optional[Callable] = None) -> ScanResult:
        """Run a vulnerability scan"""
        
        if scan_type == "nmap":
            result = await self.scanner.run_nmap_scan(target, callback)
        else:
            result = ScanResult(
                scan_id=hashlib.md5(f"{target}".encode()).hexdigest()[:12],
                scan_type=scan_type,
                start_time=datetime.now()
            )
        
        # Add vulnerabilities to database
        for vuln in result.vulnerabilities:
            self.vulnerabilities[vuln.vuln_id] = vuln
        
        self.scans.append(result)
        return result
    
    async def import_scan(self, filepath: str, scan_type: str = "nessus",
                         callback: Optional[Callable] = None) -> ScanResult:
        """Import scan results from file"""
        
        if scan_type == "nessus":
            result = await self.scanner.import_nessus(filepath, callback)
        else:
            result = ScanResult(
                scan_id=hashlib.md5(f"{filepath}".encode()).hexdigest()[:12],
                scan_type=scan_type,
                start_time=datetime.now()
            )
        
        # Add vulnerabilities to database
        for vuln in result.vulnerabilities:
            self.vulnerabilities[vuln.vuln_id] = vuln
        
        self.scans.append(result)
        return result
    
    def add_asset(self, name: str, asset_type: AssetType,
                 ip_address: str = "", hostname: str = "",
                 os: str = "", criticality: int = 5) -> Asset:
        """Add an asset to inventory"""
        
        asset_id = hashlib.md5(f"{name}{ip_address}".encode()).hexdigest()[:12]
        
        asset = Asset(
            asset_id=asset_id,
            name=name,
            asset_type=asset_type,
            ip_address=ip_address,
            hostname=hostname,
            os=os,
            criticality=criticality
        )
        
        self.assets[asset_id] = asset
        return asset
    
    def update_vulnerability_status(self, vuln_id: str, status: VulnerabilityStatus,
                                    comment: str = "") -> bool:
        """Update vulnerability status"""
        
        if vuln_id not in self.vulnerabilities:
            return False
        
        vuln = self.vulnerabilities[vuln_id]
        vuln.status = status
        
        if status in [VulnerabilityStatus.REMEDIATED, VulnerabilityStatus.MITIGATED]:
            vuln.remediated_date = datetime.now()
        
        if comment:
            vuln.comments.append({
                "timestamp": datetime.now().isoformat(),
                "status": status.value,
                "comment": comment
            })
        
        return True
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get vulnerability dashboard statistics"""
        
        total = len(self.vulnerabilities)
        open_vulns = [v for v in self.vulnerabilities.values() 
                     if v.status not in [VulnerabilityStatus.REMEDIATED,
                                         VulnerabilityStatus.MITIGATED,
                                         VulnerabilityStatus.FALSE_POSITIVE,
                                         VulnerabilityStatus.ACCEPTED]]
        
        overdue = self.remediation.get_overdue_vulnerabilities(list(self.vulnerabilities.values()))
        
        severity_counts = {s.value: 0 for s in VulnerabilitySeverity}
        for vuln in open_vulns:
            severity_counts[vuln.severity.value] += 1
        
        return {
            "total_vulnerabilities": total,
            "open_vulnerabilities": len(open_vulns),
            "remediated": total - len(open_vulns),
            "overdue": len(overdue),
            "by_severity": severity_counts,
            "critical_open": severity_counts.get("critical", 0),
            "high_open": severity_counts.get("high", 0),
            "mean_time_to_remediate": self._calculate_mttr(),
            "total_assets": len(self.assets)
        }
    
    def _calculate_mttr(self) -> float:
        """Calculate mean time to remediate (in days)"""
        remediated = [v for v in self.vulnerabilities.values()
                     if v.status == VulnerabilityStatus.REMEDIATED and v.remediated_date]
        
        if not remediated:
            return 0.0
        
        total_days = sum(
            (v.remediated_date - v.discovered_date).days
            for v in remediated
        )
        
        return total_days / len(remediated)
    
    def get_prioritized_list(self) -> List[Vulnerability]:
        """Get prioritized list of open vulnerabilities"""
        
        open_vulns = [v for v in self.vulnerabilities.values()
                     if v.status not in [VulnerabilityStatus.REMEDIATED,
                                         VulnerabilityStatus.MITIGATED,
                                         VulnerabilityStatus.FALSE_POSITIVE,
                                         VulnerabilityStatus.ACCEPTED]]
        
        return self.risk_calc.prioritize_vulnerabilities(open_vulns, self.assets)
    
    def export_report(self, format: str = "json") -> str:
        """Export vulnerability report"""
        
        stats = self.get_dashboard_stats()
        prioritized = self.get_prioritized_list()
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "statistics": stats,
            "vulnerabilities": [
                {
                    "id": v.vuln_id,
                    "cve": v.cve_id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "status": v.status.value,
                    "risk_score": v.risk_score,
                    "affected_assets": v.affected_assets,
                    "discovered": v.discovered_date.isoformat(),
                    "solution": v.solution
                }
                for v in prioritized[:50]  # Top 50
            ]
        }
        
        if format == "json":
            return json.dumps(report, indent=2)
        
        return ""
