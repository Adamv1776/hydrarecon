#!/usr/bin/env python3
"""
HydraRecon Bug Bounty Copilot
AI-powered bug bounty report generation with PoC, impact analysis, and CVSS scoring.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pathlib import Path
import hashlib


class VulnerabilityType(Enum):
    """Common vulnerability types for bug bounties."""
    XSS_REFLECTED = "Cross-Site Scripting (Reflected)"
    XSS_STORED = "Cross-Site Scripting (Stored)"
    XSS_DOM = "Cross-Site Scripting (DOM-based)"
    SQLI = "SQL Injection"
    SQLI_BLIND = "Blind SQL Injection"
    SSRF = "Server-Side Request Forgery"
    IDOR = "Insecure Direct Object Reference"
    BROKEN_AUTH = "Broken Authentication"
    BROKEN_ACCESS = "Broken Access Control"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    XXE = "XML External Entity"
    RCE = "Remote Code Execution"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    OPEN_REDIRECT = "Open Redirect"
    CSRF = "Cross-Site Request Forgery"
    CORS = "CORS Misconfiguration"
    SUBDOMAIN_TAKEOVER = "Subdomain Takeover"
    INFO_DISCLOSURE = "Information Disclosure"
    RATE_LIMITING = "Missing Rate Limiting"
    BUSINESS_LOGIC = "Business Logic Flaw"
    GRAPHQL = "GraphQL Vulnerability"
    API_SECURITY = "API Security Issue"
    SECRETS_LEAK = "Secrets/Credentials Leak"
    JWT_WEAKNESS = "JWT Implementation Weakness"
    PROTOTYPE_POLLUTION = "Prototype Pollution"
    CACHE_POISONING = "Cache Poisoning"
    SSTI = "Server-Side Template Injection"
    DESERIALIZATION = "Insecure Deserialization"
    PATH_TRAVERSAL = "Path Traversal"
    COMMAND_INJECTION = "Command Injection"
    HEADER_INJECTION = "Header Injection"
    CRLF_INJECTION = "CRLF Injection"
    HOST_HEADER = "Host Header Injection"
    CLICKJACKING = "Clickjacking"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    OTHER = "Other"


class Severity(Enum):
    """CVSS-based severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


@dataclass
class CVSSVector:
    """CVSS 3.1 Vector components."""
    # Base Metrics
    attack_vector: str = "N"  # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L"  # L=Low, H=High
    privileges_required: str = "N"  # N=None, L=Low, H=High
    user_interaction: str = "N"  # N=None, R=Required
    scope: str = "U"  # U=Unchanged, C=Changed
    confidentiality: str = "N"  # N=None, L=Low, H=High
    integrity: str = "N"  # N=None, L=Low, H=High
    availability: str = "N"  # N=None, L=Low, H=High
    
    def to_string(self) -> str:
        """Generate CVSS vector string."""
        return (f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
                f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
                f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/"
                f"A:{self.availability}")
    
    def calculate_score(self) -> float:
        """Calculate CVSS 3.1 base score."""
        # Impact weights
        av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_weights = {"L": 0.77, "H": 0.44}
        pr_weights_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_weights_changed = {"N": 0.85, "L": 0.68, "H": 0.5}
        ui_weights = {"N": 0.85, "R": 0.62}
        cia_weights = {"N": 0, "L": 0.22, "H": 0.56}
        
        # Calculate exploitability
        pr_weight = (pr_weights_changed if self.scope == "C" 
                     else pr_weights_unchanged).get(self.privileges_required, 0.85)
        
        exploitability = (8.22 * av_weights.get(self.attack_vector, 0.85) *
                          ac_weights.get(self.attack_complexity, 0.77) *
                          pr_weight *
                          ui_weights.get(self.user_interaction, 0.85))
        
        # Calculate impact
        isc_base = 1 - ((1 - cia_weights.get(self.confidentiality, 0)) *
                        (1 - cia_weights.get(self.integrity, 0)) *
                        (1 - cia_weights.get(self.availability, 0)))
        
        if self.scope == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
        
        if impact <= 0:
            return 0.0
        
        if self.scope == "U":
            score = min(impact + exploitability, 10)
        else:
            score = min(1.08 * (impact + exploitability), 10)
        
        return round(score, 1)
    
    def get_severity(self) -> Severity:
        """Get severity based on CVSS score."""
        score = self.calculate_score()
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score >= 0.1:
            return Severity.LOW
        return Severity.INFO


@dataclass
class ProofOfConcept:
    """Proof of Concept details."""
    type: str  # curl, script, browser, burp, etc.
    code: str
    description: str
    steps: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    video_url: Optional[str] = None


@dataclass
class BugBountyReport:
    """Complete bug bounty report structure."""
    id: str
    title: str
    vulnerability_type: VulnerabilityType
    severity: Severity
    cvss_vector: CVSSVector
    cvss_score: float
    target: str
    endpoint: str
    parameter: Optional[str]
    description: str
    impact: str
    steps_to_reproduce: List[str]
    poc: ProofOfConcept
    remediation: str
    references: List[str]
    created_at: datetime
    researcher: str = "HydraRecon"
    status: str = "Draft"
    bounty_estimate: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)


class BugBountyCopilot:
    """AI-powered bug bounty report generator."""
    
    # Vulnerability templates with CVSS presets
    VULN_TEMPLATES = {
        VulnerabilityType.XSS_REFLECTED: {
            "cvss": CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="R", scope="C", confidentiality="L", integrity="L", availability="N"
            ),
            "impact_template": """An attacker can execute arbitrary JavaScript in the context of the victim's browser session. This could lead to:
- Session hijacking through cookie theft
- Keylogging and credential theft  
- Phishing attacks via DOM manipulation
- Performing actions on behalf of the victim
- Defacement of the web application""",
            "remediation": """1. Implement proper output encoding/escaping based on context (HTML, JavaScript, URL, CSS)
2. Use Content Security Policy (CSP) headers to restrict script execution
3. Enable HttpOnly and Secure flags on session cookies
4. Implement input validation using allowlists
5. Consider using templating engines with auto-escaping""",
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/cross-site-scripting"
            ]
        },
        VulnerabilityType.SQLI: {
            "cvss": CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H"
            ),
            "impact_template": """This SQL injection vulnerability allows an attacker to:
- Extract sensitive data from the database (user credentials, PII, financial data)
- Modify or delete database records
- Bypass authentication mechanisms
- Execute administrative operations on the database
- Potentially achieve Remote Code Execution via xp_cmdshell or similar""",
            "remediation": """1. Use parameterized queries (prepared statements) for all database operations
2. Implement stored procedures with parameterized inputs
3. Apply principle of least privilege to database accounts
4. Enable WAF rules for SQL injection protection
5. Implement input validation and sanitization
6. Use ORM frameworks that handle parameterization automatically""",
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/sql-injection"
            ]
        },
        VulnerabilityType.SSRF: {
            "cvss": CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="C", confidentiality="H", integrity="L", availability="L"
            ),
            "impact_template": """This SSRF vulnerability enables an attacker to:
- Access internal services not exposed to the internet
- Read cloud metadata endpoints (AWS, GCP, Azure) potentially exposing credentials
- Scan and enumerate internal network infrastructure
- Bypass firewall restrictions and access controls
- Potentially pivot to internal systems for further attacks
- Access localhost-only services and admin interfaces""",
            "remediation": """1. Implement strict allowlist validation for URLs/hostnames
2. Block requests to private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x)
3. Block cloud metadata endpoints (169.254.169.254, metadata.google.internal)
4. Disable unnecessary URL schemes (file://, gopher://, dict://)
5. Use a proxy/gateway for outbound requests with strict controls
6. Implement network segmentation to limit impact""",
            "references": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/ssrf"
            ]
        },
        VulnerabilityType.IDOR: {
            "cvss": CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="L",
                user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"
            ),
            "impact_template": """This IDOR vulnerability allows an attacker to:
- Access other users' private data and resources
- Modify or delete other users' information
- Escalate privileges by accessing admin resources
- Perform unauthorized actions on behalf of other users
- Potentially compromise entire user accounts""",
            "remediation": """1. Implement proper authorization checks for every resource access
2. Use indirect reference maps (GUIDs/UUIDs instead of sequential IDs)
3. Validate user ownership before allowing operations
4. Implement access control at the data layer, not just presentation
5. Log and monitor for access pattern anomalies
6. Use session-based authorization tokens""",
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/access-control/idor"
            ]
        },
        VulnerabilityType.RCE: {
            "cvss": CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"
            ),
            "impact_template": """This Remote Code Execution vulnerability is CRITICAL and allows:
- Complete server compromise with ability to execute arbitrary commands
- Access to all data stored on the server
- Lateral movement to other systems in the network
- Installation of backdoors, malware, or ransomware
- Data exfiltration and destruction
- Use of compromised server for further attacks""",
            "remediation": """1. IMMEDIATE: Patch or disable the vulnerable component
2. Implement strict input validation and sanitization
3. Use sandboxing/containerization for code execution
4. Apply principle of least privilege for application processes
5. Implement application-level firewalls and monitoring
6. Conduct security code review and penetration testing
7. Enable runtime application self-protection (RASP)""",
            "references": [
                "https://owasp.org/www-community/attacks/Code_Injection",
                "https://cwe.mitre.org/data/definitions/94.html",
                "https://nvd.nist.gov/"
            ]
        },
        VulnerabilityType.SUBDOMAIN_TAKEOVER: {
            "cvss": CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="L"
            ),
            "impact_template": """This subdomain takeover vulnerability allows an attacker to:
- Host malicious content on a trusted subdomain
- Steal cookies scoped to the parent domain
- Conduct phishing attacks with high credibility
- Bypass Content Security Policy if subdomain is whitelisted
- Send emails from the subdomain (SPF/DKIM bypass)
- Damage brand reputation and user trust""",
            "remediation": """1. Remove dangling DNS records pointing to decommissioned services
2. Implement monitoring for DNS record changes
3. Use strict domain/subdomain cookie scoping
4. Regularly audit DNS records and cloud resources
5. Implement process for proper service decommissioning
6. Consider using DNS CAA records""",
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                "https://github.com/EdOverflow/can-i-take-over-xyz",
                "https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers"
            ]
        },
        VulnerabilityType.SECRETS_LEAK: {
            "cvss": CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="L"
            ),
            "impact_template": """Exposed secrets/credentials enable an attacker to:
- Access internal systems using leaked API keys
- Compromise cloud infrastructure with exposed cloud credentials
- Access databases and exfiltrate sensitive data
- Impersonate services and bypass authentication
- Escalate privileges using admin credentials
- Potentially compromise the entire infrastructure""",
            "remediation": """1. IMMEDIATE: Rotate all exposed credentials
2. Remove secrets from source code and configuration files
3. Use secret management solutions (Vault, AWS Secrets Manager)
4. Implement pre-commit hooks to prevent secret commits
5. Scan repositories for historical secret exposure
6. Enable audit logging for credential usage
7. Apply principle of least privilege for all credentials""",
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                "https://docs.github.com/en/code-security/secret-scanning"
            ]
        },
        VulnerabilityType.GRAPHQL: {
            "cvss": CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="H", integrity="L", availability="L"
            ),
            "impact_template": """This GraphQL vulnerability allows an attacker to:
- Extract the entire API schema through introspection
- Access unauthorized data through broken access controls
- Cause denial of service via deeply nested queries
- Bypass rate limiting with query batching
- Inject malicious payloads through query parameters
- Enumerate sensitive fields and relationships""",
            "remediation": """1. Disable introspection in production environments
2. Implement query depth and complexity limits
3. Add proper authentication and authorization for all resolvers
4. Enable query cost analysis and rate limiting
5. Validate and sanitize all input arguments
6. Implement field-level access controls
7. Monitor and log GraphQL query patterns""",
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                "https://portswigger.net/web-security/graphql"
            ]
        }
    }
    
    # Bounty estimates by severity (HackerOne ranges)
    BOUNTY_ESTIMATES = {
        Severity.CRITICAL: "$5,000 - $50,000+",
        Severity.HIGH: "$1,000 - $10,000",
        Severity.MEDIUM: "$250 - $2,000",
        Severity.LOW: "$50 - $500",
        Severity.INFO: "Recognition / Swag"
    }
    
    def __init__(self):
        self.reports: List[BugBountyReport] = []
        self.report_templates: Dict[str, str] = {}
        
    def generate_report_id(self, target: str, vuln_type: VulnerabilityType) -> str:
        """Generate unique report ID."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        hash_input = f"{target}{vuln_type.value}{timestamp}"
        short_hash = hashlib.md5(hash_input.encode()).hexdigest()[:8]
        return f"HR-{timestamp[:8]}-{short_hash.upper()}"
    
    def get_vuln_template(self, vuln_type: VulnerabilityType) -> Dict:
        """Get vulnerability template with defaults."""
        return self.VULN_TEMPLATES.get(vuln_type, {
            "cvss": CVSSVector(),
            "impact_template": "This vulnerability may allow unauthorized access or actions.",
            "remediation": "Implement proper security controls and follow security best practices.",
            "references": ["https://owasp.org/"]
        })
    
    def generate_title(self, vuln_type: VulnerabilityType, target: str, 
                       endpoint: str, parameter: Optional[str] = None) -> str:
        """Generate professional bug bounty report title."""
        vuln_name = vuln_type.value
        
        if parameter:
            return f"{vuln_name} in {endpoint} via '{parameter}' parameter on {target}"
        else:
            return f"{vuln_name} in {endpoint} on {target}"
    
    def generate_poc_curl(self, method: str, url: str, headers: Dict[str, str] = None,
                          data: str = None, description: str = "") -> ProofOfConcept:
        """Generate cURL-based proof of concept."""
        curl_parts = ["curl"]
        
        if method != "GET":
            curl_parts.append(f"-X {method}")
        
        if headers:
            for key, value in headers.items():
                curl_parts.append(f"-H '{key}: {value}'")
        
        if data:
            curl_parts.append(f"-d '{data}'")
        
        curl_parts.append(f"'{url}'")
        
        curl_command = " \\\n  ".join(curl_parts)
        
        return ProofOfConcept(
            type="curl",
            code=curl_command,
            description=description or f"Execute the following cURL command to reproduce the vulnerability:",
            steps=[
                "Open a terminal",
                "Copy and execute the cURL command below",
                "Observe the response indicating successful exploitation"
            ]
        )
    
    def generate_poc_python(self, code: str, description: str = "") -> ProofOfConcept:
        """Generate Python-based proof of concept."""
        return ProofOfConcept(
            type="python",
            code=code,
            description=description or "Execute the following Python script to reproduce the vulnerability:",
            steps=[
                "Save the script to a file (e.g., poc.py)",
                "Install required dependencies: pip install requests",
                "Run: python poc.py",
                "Observe the output confirming exploitation"
            ]
        )
    
    def generate_poc_browser(self, url: str, payload: str, 
                             description: str = "") -> ProofOfConcept:
        """Generate browser-based proof of concept."""
        return ProofOfConcept(
            type="browser",
            code=f"Navigate to:\n{url}\n\nPayload used:\n{payload}",
            description=description or "Follow these steps in a web browser to reproduce the vulnerability:",
            steps=[
                "Open a modern web browser (Chrome/Firefox recommended)",
                f"Navigate to the URL provided",
                "Observe the vulnerability trigger (e.g., alert box, behavior change)",
                "Check browser developer console for additional confirmation"
            ]
        )
    
    def create_report(
        self,
        target: str,
        endpoint: str,
        vuln_type: VulnerabilityType,
        description: str,
        poc: ProofOfConcept,
        parameter: Optional[str] = None,
        custom_cvss: Optional[CVSSVector] = None,
        custom_impact: Optional[str] = None,
        custom_remediation: Optional[str] = None,
        additional_references: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        researcher: str = "HydraRecon"
    ) -> BugBountyReport:
        """Create a complete bug bounty report."""
        template = self.get_vuln_template(vuln_type)
        
        cvss = custom_cvss or template.get("cvss", CVSSVector())
        cvss_score = cvss.calculate_score()
        severity = cvss.get_severity()
        
        report = BugBountyReport(
            id=self.generate_report_id(target, vuln_type),
            title=self.generate_title(vuln_type, target, endpoint, parameter),
            vulnerability_type=vuln_type,
            severity=severity,
            cvss_vector=cvss,
            cvss_score=cvss_score,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
            description=description,
            impact=custom_impact or template.get("impact_template", ""),
            steps_to_reproduce=poc.steps,
            poc=poc,
            remediation=custom_remediation or template.get("remediation", ""),
            references=template.get("references", []) + (additional_references or []),
            created_at=datetime.now(),
            researcher=researcher,
            bounty_estimate=self.BOUNTY_ESTIMATES.get(severity),
            tags=tags or [vuln_type.value.lower().replace(" ", "-")]
        )
        
        self.reports.append(report)
        return report
    
    def format_markdown(self, report: BugBountyReport) -> str:
        """Format report as Markdown for bug bounty platforms."""
        md = f"""# {report.title}

## Summary
| Field | Value |
|-------|-------|
| **Report ID** | `{report.id}` |
| **Severity** | {report.severity.value} |
| **CVSS Score** | {report.cvss_score} |
| **CVSS Vector** | `{report.cvss_vector.to_string()}` |
| **Target** | {report.target} |
| **Endpoint** | `{report.endpoint}` |
| **Parameter** | `{report.parameter or 'N/A'}` |
| **Bounty Estimate** | {report.bounty_estimate} |

## Vulnerability Type
**{report.vulnerability_type.value}**

## Description
{report.description}

## Impact
{report.impact}

## Steps to Reproduce
"""
        for i, step in enumerate(report.steps_to_reproduce, 1):
            md += f"{i}. {step}\n"
        
        md += f"""
## Proof of Concept
{report.poc.description}

```{report.poc.type}
{report.poc.code}
```
"""
        
        if report.poc.screenshots:
            md += "\n### Screenshots\n"
            for i, screenshot in enumerate(report.poc.screenshots, 1):
                md += f"![Screenshot {i}]({screenshot})\n"
        
        if report.poc.video_url:
            md += f"\n### Video PoC\n[Watch Video PoC]({report.poc.video_url})\n"
        
        md += f"""
## Remediation
{report.remediation}

## References
"""
        for ref in report.references:
            md += f"- {ref}\n"
        
        md += f"""
---
*Report generated by {report.researcher} on {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}*
*Tags: {', '.join(report.tags)}*
"""
        return md
    
    def format_json(self, report: BugBountyReport) -> str:
        """Format report as JSON for API submission."""
        return json.dumps({
            "id": report.id,
            "title": report.title,
            "vulnerability_type": report.vulnerability_type.value,
            "severity": report.severity.value,
            "cvss_score": report.cvss_score,
            "cvss_vector": report.cvss_vector.to_string(),
            "target": report.target,
            "endpoint": report.endpoint,
            "parameter": report.parameter,
            "description": report.description,
            "impact": report.impact,
            "steps_to_reproduce": report.steps_to_reproduce,
            "poc": {
                "type": report.poc.type,
                "code": report.poc.code,
                "description": report.poc.description
            },
            "remediation": report.remediation,
            "references": report.references,
            "created_at": report.created_at.isoformat(),
            "researcher": report.researcher,
            "bounty_estimate": report.bounty_estimate,
            "tags": report.tags
        }, indent=2)
    
    def format_hackerone(self, report: BugBountyReport) -> str:
        """Format for HackerOne submission."""
        return f"""## Summary:
{report.description}

## Steps To Reproduce:
{"".join(f'{i}. {step}\\n' for i, step in enumerate(report.steps_to_reproduce, 1))}

## Supporting Material/References:
{report.poc.description}

```
{report.poc.code}
```

## Impact
{report.impact}

---
CVSS: {report.cvss_score} ({report.cvss_vector.to_string()})
"""
    
    def format_bugcrowd(self, report: BugBountyReport) -> str:
        """Format for Bugcrowd submission."""
        return f"""### Title
{report.title}

### Vulnerability Details
**Type:** {report.vulnerability_type.value}
**Severity:** {report.severity.value}
**CVSS Score:** {report.cvss_score}

### Description
{report.description}

### Proof of Concept
{report.poc.description}

```
{report.poc.code}
```

### Steps to Reproduce
{"".join(f'{i}. {step}\\n' for i, step in enumerate(report.steps_to_reproduce, 1))}

### Business Impact
{report.impact}

### Remediation
{report.remediation}
"""
    
    def export_report(self, report: BugBountyReport, format: str = "markdown", 
                      output_path: Optional[Path] = None) -> str:
        """Export report in specified format."""
        formatters = {
            "markdown": self.format_markdown,
            "json": self.format_json,
            "hackerone": self.format_hackerone,
            "bugcrowd": self.format_bugcrowd
        }
        
        formatter = formatters.get(format, self.format_markdown)
        content = formatter(report)
        
        if output_path:
            ext = ".md" if format == "markdown" else ".json" if format == "json" else ".txt"
            file_path = output_path / f"{report.id}{ext}"
            file_path.write_text(content)
        
        return content
    
    async def auto_generate_from_finding(self, finding: Dict[str, Any]) -> Optional[BugBountyReport]:
        """Auto-generate report from a scanner finding."""
        # Map finding severity to vulnerability type
        vuln_type_map = {
            "xss": VulnerabilityType.XSS_REFLECTED,
            "sqli": VulnerabilityType.SQLI,
            "sql injection": VulnerabilityType.SQLI,
            "ssrf": VulnerabilityType.SSRF,
            "idor": VulnerabilityType.IDOR,
            "rce": VulnerabilityType.RCE,
            "open redirect": VulnerabilityType.OPEN_REDIRECT,
            "csrf": VulnerabilityType.CSRF,
            "cors": VulnerabilityType.CORS,
            "subdomain takeover": VulnerabilityType.SUBDOMAIN_TAKEOVER,
            "secret": VulnerabilityType.SECRETS_LEAK,
            "api key": VulnerabilityType.SECRETS_LEAK,
            "graphql": VulnerabilityType.GRAPHQL,
        }
        
        finding_title = finding.get("title", "").lower()
        finding_desc = finding.get("description", "").lower()
        
        vuln_type = VulnerabilityType.OTHER
        for keyword, vtype in vuln_type_map.items():
            if keyword in finding_title or keyword in finding_desc:
                vuln_type = vtype
                break
        
        poc = self.generate_poc_curl(
            method="GET",
            url=finding.get("url", finding.get("target", "")),
            description=f"Reproduce finding: {finding.get('title', '')}"
        )
        
        report = self.create_report(
            target=finding.get("target", "Unknown"),
            endpoint=finding.get("url", finding.get("endpoint", "/")),
            vuln_type=vuln_type,
            description=finding.get("description", "Vulnerability detected by automated scanner."),
            poc=poc,
            parameter=finding.get("parameter"),
            tags=finding.get("tags", [])
        )
        
        return report
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about generated reports."""
        severity_counts = {}
        vuln_type_counts = {}
        total_bounty_low = 0
        total_bounty_high = 0
        
        for report in self.reports:
            sev = report.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            vtype = report.vulnerability_type.value
            vuln_type_counts[vtype] = vuln_type_counts.get(vtype, 0) + 1
        
        return {
            "total_reports": len(self.reports),
            "by_severity": severity_counts,
            "by_type": vuln_type_counts,
            "critical_count": severity_counts.get("Critical", 0),
            "high_count": severity_counts.get("High", 0)
        }
