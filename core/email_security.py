#!/usr/bin/env python3
"""
HydraRecon Email Security Analyzer
Comprehensive SPF, DKIM, DMARC validation and email spoofing testing.
"""

import asyncio
import json
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import aiodns


class EmailSecurityLevel(Enum):
    """Overall email security rating."""
    EXCELLENT = "Excellent"
    GOOD = "Good"
    MODERATE = "Moderate"
    WEAK = "Weak"
    CRITICAL = "Critical"


class FindingSeverity(Enum):
    """Finding severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class SPFRecord:
    """Parsed SPF record."""
    raw: str
    version: str
    mechanisms: List[str]
    modifiers: Dict[str, str]
    includes: List[str]
    all_qualifier: str  # +all, -all, ~all, ?all
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    lookup_count: int = 0


@dataclass
class DKIMRecord:
    """Parsed DKIM record."""
    selector: str
    raw: str
    version: str
    key_type: str
    public_key: str
    flags: List[str]
    hash_algorithms: List[str]
    service_types: List[str]
    is_valid: bool
    key_length: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class DMARCRecord:
    """Parsed DMARC record."""
    raw: str
    version: str
    policy: str  # none, quarantine, reject
    subdomain_policy: str
    pct: int  # percentage
    rua: List[str]  # aggregate report URIs
    ruf: List[str]  # forensic report URIs
    adkim: str  # DKIM alignment (r=relaxed, s=strict)
    aspf: str  # SPF alignment
    fo: str  # failure reporting options
    rf: str  # report format
    ri: int  # reporting interval
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class MTASTSRecord:
    """MTA-STS record."""
    version: str
    id: str
    is_valid: bool
    policy_mode: Optional[str] = None  # enforce, testing, none
    max_age: Optional[int] = None
    mx_hosts: List[str] = field(default_factory=list)


@dataclass
class TLSRPTRecord:
    """TLS-RPT record."""
    version: str
    rua: List[str]
    is_valid: bool


@dataclass
class BIMIRecord:
    """BIMI record."""
    version: str
    location: str  # SVG logo URL
    authority: Optional[str] = None  # VMC certificate URL
    is_valid: bool = False


@dataclass
class EmailSecurityFinding:
    """Security finding for email configuration."""
    id: str
    category: str
    severity: FindingSeverity
    title: str
    description: str
    impact: str
    remediation: str
    references: List[str] = field(default_factory=list)
    evidence: str = ""


@dataclass
class EmailSecurityReport:
    """Complete email security analysis report."""
    domain: str
    scan_time: datetime
    overall_score: int  # 0-100
    security_level: EmailSecurityLevel
    spf: Optional[SPFRecord]
    dkim: Dict[str, DKIMRecord]  # selector -> record
    dmarc: Optional[DMARCRecord]
    mta_sts: Optional[MTASTSRecord]
    tls_rpt: Optional[TLSRPTRecord]
    bimi: Optional[BIMIRecord]
    mx_records: List[str]
    findings: List[EmailSecurityFinding]
    spoofing_possible: bool
    spoofing_risk: str


class EmailSecurityAnalyzer:
    """Comprehensive email security analyzer."""
    
    # Common DKIM selectors to check
    COMMON_SELECTORS = [
        "default", "google", "selector1", "selector2", "k1", "k2",
        "mail", "email", "dkim", "s1", "s2", "mx", "smtp", "postfix",
        "mailjet", "mandrill", "amazonses", "sendgrid", "mailchimp",
        "mailgun", "sparkpost", "postmark", "sendinblue", "zoho",
        "protonmail", "fastmail", "mimecast", "barracuda", "cisco",
        "google2048", "everlytickey1", "everlytickey2", "cm", "turbo-smtp"
    ]
    
    def __init__(self):
        self.resolver: Optional[aiodns.DNSResolver] = None
        self.findings: List[EmailSecurityFinding] = []
        self.finding_count = 0
    
    async def initialize(self):
        """Initialize DNS resolver."""
        self.resolver = aiodns.DNSResolver()
    
    def generate_finding_id(self) -> str:
        """Generate unique finding ID."""
        self.finding_count += 1
        return f"EMAIL-{datetime.now().strftime('%Y%m%d')}-{self.finding_count:04d}"
    
    async def resolve_txt(self, domain: str) -> List[str]:
        """Resolve TXT records for a domain."""
        if not self.resolver:
            await self.initialize()
        
        try:
            result = await self.resolver.query(domain, "TXT")
            return [r.text for r in result]
        except Exception:
            return []
    
    async def resolve_mx(self, domain: str) -> List[str]:
        """Resolve MX records for a domain."""
        if not self.resolver:
            await self.initialize()
        
        try:
            result = await self.resolver.query(domain, "MX")
            return sorted([r.host for r in result], key=lambda x: x)
        except Exception:
            return []
    
    async def check_spf(self, domain: str) -> Optional[SPFRecord]:
        """Check and parse SPF record."""
        txt_records = await self.resolve_txt(domain)
        
        spf_record = None
        for record in txt_records:
            if record.startswith("v=spf1"):
                spf_record = record
                break
        
        if not spf_record:
            self.findings.append(EmailSecurityFinding(
                id=self.generate_finding_id(),
                category="SPF",
                severity=FindingSeverity.HIGH,
                title="No SPF Record Found",
                description=f"No SPF record exists for {domain}",
                impact="Attackers can easily spoof emails from this domain",
                remediation="Add an SPF TXT record to your DNS: v=spf1 include:_spf.google.com ~all",
                references=["https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/"]
            ))
            return None
        
        # Parse SPF record
        spf = SPFRecord(
            raw=spf_record,
            version="spf1",
            mechanisms=[],
            modifiers={},
            includes=[],
            all_qualifier="",
            is_valid=True
        )
        
        parts = spf_record.split()
        
        for part in parts[1:]:  # Skip v=spf1
            # Check for all qualifier
            if part in ["+all", "-all", "~all", "?all", "all"]:
                spf.all_qualifier = part
            # Check for include
            elif part.startswith("include:"):
                spf.includes.append(part[8:])
                spf.lookup_count += 1
            # Check for redirect
            elif part.startswith("redirect="):
                spf.modifiers["redirect"] = part[9:]
                spf.lookup_count += 1
            # Other mechanisms
            elif ":" in part or part.startswith(("ip4:", "ip6:", "a", "mx", "ptr")):
                spf.mechanisms.append(part)
                if part.startswith(("a", "mx", "ptr", "exists")):
                    spf.lookup_count += 1
        
        # Check for issues
        if spf.all_qualifier in ["+all", "?all"]:
            spf.warnings.append("Permissive all qualifier allows any server to send email")
            self.findings.append(EmailSecurityFinding(
                id=self.generate_finding_id(),
                category="SPF",
                severity=FindingSeverity.CRITICAL,
                title="SPF Record Too Permissive",
                description=f"SPF uses '{spf.all_qualifier}' which allows any server",
                impact="Any email server can send emails claiming to be from this domain",
                remediation="Change to '-all' (hard fail) or '~all' (soft fail)",
                evidence=spf_record
            ))
        
        if spf.lookup_count > 10:
            spf.warnings.append(f"Too many DNS lookups ({spf.lookup_count}/10)")
            self.findings.append(EmailSecurityFinding(
                id=self.generate_finding_id(),
                category="SPF",
                severity=FindingSeverity.MEDIUM,
                title="SPF Lookup Limit Exceeded",
                description=f"SPF requires {spf.lookup_count} DNS lookups (max 10)",
                impact="SPF validation may fail due to exceeding lookup limit",
                remediation="Reduce includes and use IP addresses directly where possible"
            ))
        
        if not spf.all_qualifier:
            spf.warnings.append("No 'all' qualifier - implicit +all")
            self.findings.append(EmailSecurityFinding(
                id=self.generate_finding_id(),
                category="SPF",
                severity=FindingSeverity.HIGH,
                title="SPF Missing 'all' Qualifier",
                description="SPF record has no 'all' qualifier",
                impact="Implicit +all allows any server to send email",
                remediation="Add '-all' at the end of your SPF record"
            ))
        
        return spf
    
    async def check_dkim(self, domain: str, 
                         selectors: List[str] = None) -> Dict[str, DKIMRecord]:
        """Check DKIM records for common selectors."""
        selectors = selectors or self.COMMON_SELECTORS
        dkim_records = {}
        
        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            txt_records = await self.resolve_txt(dkim_domain)
            
            for record in txt_records:
                if "v=DKIM1" in record or "k=rsa" in record:
                    dkim = self._parse_dkim(selector, record)
                    dkim_records[selector] = dkim
                    break
        
        if not dkim_records:
            self.findings.append(EmailSecurityFinding(
                id=self.generate_finding_id(),
                category="DKIM",
                severity=FindingSeverity.MEDIUM,
                title="No DKIM Records Found",
                description=f"No DKIM records found for common selectors on {domain}",
                impact="Email authenticity cannot be cryptographically verified",
                remediation="Configure DKIM signing in your email server and publish the public key",
                references=["https://www.cloudflare.com/learning/dns/dns-records/dns-dkim-record/"]
            ))
        
        return dkim_records
    
    def _parse_dkim(self, selector: str, record: str) -> DKIMRecord:
        """Parse a DKIM record."""
        dkim = DKIMRecord(
            selector=selector,
            raw=record,
            version="DKIM1",
            key_type="rsa",
            public_key="",
            flags=[],
            hash_algorithms=[],
            service_types=[],
            is_valid=True
        )
        
        # Parse tags
        tags = {}
        for part in record.replace(" ", "").split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                tags[key.strip()] = value.strip()
        
        dkim.version = tags.get("v", "DKIM1")
        dkim.key_type = tags.get("k", "rsa")
        dkim.public_key = tags.get("p", "")
        
        if "t" in tags:
            dkim.flags = tags["t"].split(":")
        if "h" in tags:
            dkim.hash_algorithms = tags["h"].split(":")
        if "s" in tags:
            dkim.service_types = tags["s"].split(":")
        
        # Check key length (approximate from base64)
        if dkim.public_key:
            # Rough estimate: base64 length * 6 / 8 = bytes, * 8 = bits
            approx_bits = len(dkim.public_key) * 6
            dkim.key_length = approx_bits
            
            if approx_bits < 1024:
                dkim.warnings.append("Key length appears to be less than 1024 bits")
                self.findings.append(EmailSecurityFinding(
                    id=self.generate_finding_id(),
                    category="DKIM",
                    severity=FindingSeverity.HIGH,
                    title=f"Weak DKIM Key for Selector '{selector}'",
                    description=f"DKIM key appears to be less than 1024 bits",
                    impact="Weak keys can potentially be factored/cracked",
                    remediation="Generate a new DKIM key pair with at least 2048 bits"
                ))
        
        if not dkim.public_key:
            dkim.is_valid = False
            dkim.errors.append("No public key found in DKIM record")
        
        return dkim
    
    async def check_dmarc(self, domain: str) -> Optional[DMARCRecord]:
        """Check and parse DMARC record."""
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = await self.resolve_txt(dmarc_domain)
        
        dmarc_record = None
        for record in txt_records:
            if record.startswith("v=DMARC1"):
                dmarc_record = record
                break
        
        if not dmarc_record:
            self.findings.append(EmailSecurityFinding(
                id=self.generate_finding_id(),
                category="DMARC",
                severity=FindingSeverity.HIGH,
                title="No DMARC Record Found",
                description=f"No DMARC record exists for {domain}",
                impact="No policy for handling failed SPF/DKIM checks",
                remediation="Add DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
                references=["https://dmarc.org/overview/"]
            ))
            return None
        
        # Parse DMARC record
        dmarc = DMARCRecord(
            raw=dmarc_record,
            version="DMARC1",
            policy="none",
            subdomain_policy="",
            pct=100,
            rua=[],
            ruf=[],
            adkim="r",
            aspf="r",
            fo="0",
            rf="afrf",
            ri=86400,
            is_valid=True
        )
        
        # Parse tags
        tags = {}
        for part in dmarc_record.split(";"):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                tags[key.strip()] = value.strip()
        
        dmarc.policy = tags.get("p", "none")
        dmarc.subdomain_policy = tags.get("sp", dmarc.policy)
        dmarc.pct = int(tags.get("pct", "100"))
        dmarc.adkim = tags.get("adkim", "r")
        dmarc.aspf = tags.get("aspf", "r")
        dmarc.fo = tags.get("fo", "0")
        dmarc.ri = int(tags.get("ri", "86400"))
        
        if "rua" in tags:
            dmarc.rua = [uri.strip() for uri in tags["rua"].split(",")]
        if "ruf" in tags:
            dmarc.ruf = [uri.strip() for uri in tags["ruf"].split(",")]
        
        # Check for issues
        if dmarc.policy == "none":
            self.findings.append(EmailSecurityFinding(
                id=self.generate_finding_id(),
                category="DMARC",
                severity=FindingSeverity.MEDIUM,
                title="DMARC Policy Set to 'none'",
                description="DMARC policy is set to 'none' (monitoring only)",
                impact="Failed emails are not rejected or quarantined",
                remediation="Change policy to 'quarantine' or 'reject' after monitoring",
                evidence=dmarc_record
            ))
        
        if dmarc.pct < 100:
            dmarc.warnings.append(f"Only {dmarc.pct}% of emails are subject to DMARC policy")
        
        if not dmarc.rua:
            dmarc.warnings.append("No aggregate reporting URI configured")
            self.findings.append(EmailSecurityFinding(
                id=self.generate_finding_id(),
                category="DMARC",
                severity=FindingSeverity.LOW,
                title="DMARC Missing Aggregate Reports",
                description="No rua (aggregate report) URI configured",
                impact="You won't receive DMARC aggregate reports",
                remediation="Add rua=mailto:dmarc-reports@example.com to DMARC record"
            ))
        
        return dmarc
    
    async def check_mta_sts(self, domain: str) -> Optional[MTASTSRecord]:
        """Check MTA-STS configuration."""
        mta_sts_domain = f"_mta-sts.{domain}"
        txt_records = await self.resolve_txt(mta_sts_domain)
        
        mta_sts_record = None
        for record in txt_records:
            if "v=STSv1" in record:
                mta_sts_record = record
                break
        
        if not mta_sts_record:
            return None
        
        mta_sts = MTASTSRecord(
            version="STSv1",
            id="",
            is_valid=True
        )
        
        for part in mta_sts_record.split(";"):
            part = part.strip()
            if part.startswith("id="):
                mta_sts.id = part[3:]
        
        # TODO: Fetch and parse the policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt
        
        return mta_sts
    
    async def check_tls_rpt(self, domain: str) -> Optional[TLSRPTRecord]:
        """Check TLS-RPT configuration."""
        tls_rpt_domain = f"_smtp._tls.{domain}"
        txt_records = await self.resolve_txt(tls_rpt_domain)
        
        for record in txt_records:
            if "v=TLSRPTv1" in record:
                tls_rpt = TLSRPTRecord(
                    version="TLSRPTv1",
                    rua=[],
                    is_valid=True
                )
                
                for part in record.split(";"):
                    part = part.strip()
                    if part.startswith("rua="):
                        tls_rpt.rua = [uri.strip() for uri in part[4:].split(",")]
                
                return tls_rpt
        
        return None
    
    async def check_bimi(self, domain: str) -> Optional[BIMIRecord]:
        """Check BIMI configuration."""
        bimi_domain = f"default._bimi.{domain}"
        txt_records = await self.resolve_txt(bimi_domain)
        
        for record in txt_records:
            if "v=BIMI1" in record:
                bimi = BIMIRecord(
                    version="BIMI1",
                    location="",
                    is_valid=True
                )
                
                for part in record.split(";"):
                    part = part.strip()
                    if part.startswith("l="):
                        bimi.location = part[2:]
                    elif part.startswith("a="):
                        bimi.authority = part[2:]
                
                return bimi
        
        return None
    
    def calculate_score(self, spf: SPFRecord, dkim: Dict[str, DKIMRecord],
                        dmarc: DMARCRecord, mta_sts: MTASTSRecord) -> int:
        """Calculate overall email security score."""
        score = 0
        
        # SPF (25 points max)
        if spf:
            score += 10
            if spf.all_qualifier == "-all":
                score += 15
            elif spf.all_qualifier == "~all":
                score += 10
            elif spf.all_qualifier == "?all":
                score += 5
        
        # DKIM (25 points max)
        if dkim:
            score += 15
            for selector, record in dkim.items():
                if record.key_length >= 2048:
                    score += 5
                    break
                elif record.key_length >= 1024:
                    score += 3
                    break
        
        # DMARC (35 points max)
        if dmarc:
            score += 10
            if dmarc.policy == "reject":
                score += 20
            elif dmarc.policy == "quarantine":
                score += 15
            elif dmarc.policy == "none":
                score += 5
            
            if dmarc.rua:
                score += 5
        
        # MTA-STS (10 points max)
        if mta_sts:
            score += 10
        
        # TLS-RPT (5 points)
        # BIMI is bonus, doesn't affect score
        
        return min(score, 100)
    
    def determine_security_level(self, score: int) -> EmailSecurityLevel:
        """Determine security level from score."""
        if score >= 85:
            return EmailSecurityLevel.EXCELLENT
        elif score >= 70:
            return EmailSecurityLevel.GOOD
        elif score >= 50:
            return EmailSecurityLevel.MODERATE
        elif score >= 30:
            return EmailSecurityLevel.WEAK
        else:
            return EmailSecurityLevel.CRITICAL
    
    def assess_spoofing_risk(self, spf: SPFRecord, dmarc: DMARCRecord) -> Tuple[bool, str]:
        """Assess email spoofing risk."""
        if not spf and not dmarc:
            return True, "CRITICAL: No email authentication - trivial to spoof"
        
        if not dmarc:
            if spf and spf.all_qualifier in ["+all", "?all"]:
                return True, "HIGH: SPF too permissive, no DMARC"
            elif spf and spf.all_qualifier == "~all":
                return True, "MEDIUM: Soft-fail SPF, no DMARC enforcement"
            elif spf and spf.all_qualifier == "-all":
                return False, "LOW: Hard-fail SPF but no DMARC"
        
        if dmarc:
            if dmarc.policy == "none":
                return True, "MEDIUM: DMARC in monitoring mode only"
            elif dmarc.policy == "quarantine":
                return False, "LOW: DMARC quarantine policy"
            elif dmarc.policy == "reject":
                return False, "MINIMAL: DMARC reject policy active"
        
        return True, "MEDIUM: Incomplete email authentication"
    
    async def full_analysis(self, domain: str, 
                            dkim_selectors: List[str] = None) -> EmailSecurityReport:
        """Perform complete email security analysis."""
        self.findings = []
        
        # Run all checks
        spf = await self.check_spf(domain)
        dkim = await self.check_dkim(domain, dkim_selectors)
        dmarc = await self.check_dmarc(domain)
        mta_sts = await self.check_mta_sts(domain)
        tls_rpt = await self.check_tls_rpt(domain)
        bimi = await self.check_bimi(domain)
        mx_records = await self.resolve_mx(domain)
        
        # Calculate score
        score = self.calculate_score(spf, dkim, dmarc, mta_sts)
        security_level = self.determine_security_level(score)
        
        # Assess spoofing risk
        spoofing_possible, spoofing_risk = self.assess_spoofing_risk(spf, dmarc)
        
        return EmailSecurityReport(
            domain=domain,
            scan_time=datetime.now(),
            overall_score=score,
            security_level=security_level,
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            mta_sts=mta_sts,
            tls_rpt=tls_rpt,
            bimi=bimi,
            mx_records=mx_records,
            findings=self.findings,
            spoofing_possible=spoofing_possible,
            spoofing_risk=spoofing_risk
        )
    
    def export_report(self, report: EmailSecurityReport, 
                      format: str = "json") -> str:
        """Export analysis report."""
        if format == "json":
            return json.dumps({
                "domain": report.domain,
                "scan_time": report.scan_time.isoformat(),
                "overall_score": report.overall_score,
                "security_level": report.security_level.value,
                "spoofing_possible": report.spoofing_possible,
                "spoofing_risk": report.spoofing_risk,
                "mx_records": report.mx_records,
                "spf": {
                    "exists": report.spf is not None,
                    "record": report.spf.raw if report.spf else None,
                    "all_qualifier": report.spf.all_qualifier if report.spf else None
                },
                "dkim": {
                    "selectors_found": list(report.dkim.keys()),
                    "count": len(report.dkim)
                },
                "dmarc": {
                    "exists": report.dmarc is not None,
                    "policy": report.dmarc.policy if report.dmarc else None,
                    "record": report.dmarc.raw if report.dmarc else None
                },
                "mta_sts": report.mta_sts is not None,
                "tls_rpt": report.tls_rpt is not None,
                "bimi": report.bimi is not None,
                "findings": [{
                    "id": f.id,
                    "category": f.category,
                    "severity": f.severity.value,
                    "title": f.title,
                    "remediation": f.remediation
                } for f in report.findings]
            }, indent=2)
        
        elif format == "markdown":
            md = f"""# Email Security Report for {report.domain}

## Overview
| Metric | Value |
|--------|-------|
| **Overall Score** | {report.overall_score}/100 |
| **Security Level** | {report.security_level.value} |
| **Spoofing Risk** | {report.spoofing_risk} |
| **Scan Time** | {report.scan_time.strftime('%Y-%m-%d %H:%M:%S')} |

## MX Records
"""
            for mx in report.mx_records:
                md += f"- {mx}\n"
            
            md += f"""
## SPF Record
**Status:** {'✅ Found' if report.spf else '❌ Missing'}
"""
            if report.spf:
                md += f"```\n{report.spf.raw}\n```\n"
                md += f"- **All Qualifier:** {report.spf.all_qualifier}\n"
                md += f"- **Includes:** {', '.join(report.spf.includes) or 'None'}\n"
            
            md += f"""
## DKIM Records
**Selectors Found:** {len(report.dkim)}
"""
            for selector, dkim in report.dkim.items():
                md += f"- **{selector}**: {dkim.key_type}, ~{dkim.key_length} bits\n"
            
            md += f"""
## DMARC Record
**Status:** {'✅ Found' if report.dmarc else '❌ Missing'}
"""
            if report.dmarc:
                md += f"```\n{report.dmarc.raw}\n```\n"
                md += f"- **Policy:** {report.dmarc.policy}\n"
                md += f"- **Subdomain Policy:** {report.dmarc.subdomain_policy}\n"
                md += f"- **Percentage:** {report.dmarc.pct}%\n"
            
            md += f"""
## Additional Protocols
- **MTA-STS:** {'✅ Configured' if report.mta_sts else '❌ Not Found'}
- **TLS-RPT:** {'✅ Configured' if report.tls_rpt else '❌ Not Found'}
- **BIMI:** {'✅ Configured' if report.bimi else '❌ Not Found'}

## Security Findings ({len(report.findings)})
"""
            for finding in report.findings:
                icon = "🔴" if finding.severity == FindingSeverity.CRITICAL else "🟠" if finding.severity == FindingSeverity.HIGH else "🟡"
                md += f"\n### {icon} {finding.title}\n"
                md += f"**Severity:** {finding.severity.value}\n"
                md += f"**Category:** {finding.category}\n\n"
                md += f"{finding.description}\n\n"
                md += f"**Remediation:** {finding.remediation}\n"
            
            return md
        
        return ""
