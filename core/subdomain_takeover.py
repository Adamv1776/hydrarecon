#!/usr/bin/env python3
"""
HydraRecon Subdomain Takeover Scanner
Detects vulnerable subdomains that can be taken over.
"""

import asyncio
import json
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
import aiohttp
import aiodns


class TakeoverType(Enum):
    """Types of subdomain takeover vulnerabilities."""
    CNAME_DANGLING = "Dangling CNAME"
    NS_TAKEOVER = "NS Takeover"
    AZURE_CLOUDAPP = "Azure CloudApp"
    AWS_S3 = "AWS S3 Bucket"
    AWS_CLOUDFRONT = "AWS CloudFront"
    AWS_ELASTIC_BEANSTALK = "AWS Elastic Beanstalk"
    AWS_LOAD_BALANCER = "AWS Load Balancer"
    GITHUB_PAGES = "GitHub Pages"
    HEROKU = "Heroku"
    SHOPIFY = "Shopify"
    TUMBLR = "Tumblr"
    WORDPRESS = "WordPress.com"
    ZENDESK = "Zendesk"
    HELPJUICE = "Helpjuice"
    HELPSCOUT = "HelpScout"
    CARGO = "Cargo"
    FEEDPRESS = "FeedPress"
    GHOST = "Ghost"
    HELPRACE = "Helprace"
    INTERCOM = "Intercom"
    PANTHEON = "Pantheon"
    FASTLY = "Fastly"
    SURGE = "Surge.sh"
    USERVOICE = "UserVoice"
    BITBUCKET = "Bitbucket"
    UNBOUNCE = "Unbounce"
    SMARTJOB = "SmartJobBoard"
    TICTAIL = "Tictail"
    CAMPAIGNMONITOR = "Campaign Monitor"
    ACQUIA = "Acquia"
    PROPOSIFY = "Proposify"
    SIMPLEBOOKLET = "SimpleBooklet"
    GETRESPONSE = "GetResponse"
    VEND = "Vend"
    FRONTIFY = "Frontify"
    BRIGHTCOVE = "Brightcove"
    BIGCARTEL = "BigCartel"
    ACTIVECOMPAIGN = "ActiveCampaign"
    REAMAZE = "Reamaze"
    AFTERSHIP = "AfterShip"
    DESK = "Desk.com"
    MASHERY = "Mashery"
    PINGDOM = "Pingdom"
    TAVE = "Tave"
    WEBFLOW = "Webflow"
    WISHPOND = "Wishpond"
    SMUGMUG = "SmugMug"
    STRIKINGLY = "Strikingly"
    LAUNCHROCK = "LaunchRock"
    AZURE_WEBSITES = "Azure Websites"
    NETLIFY = "Netlify"
    VERCEL = "Vercel"
    FLY_IO = "Fly.io"
    RENDER = "Render"
    CUSTOM = "Custom Service"


class Severity(Enum):
    """Vulnerability severity."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class ServiceFingerprint:
    """Fingerprint for detecting takeover-vulnerable services."""
    service: TakeoverType
    cname_patterns: List[str]
    response_fingerprints: List[str]
    nxdomain: bool = True
    severity: Severity = Severity.HIGH
    documentation: str = ""
    poc_steps: List[str] = field(default_factory=list)


@dataclass
class TakeoverFinding:
    """Subdomain takeover finding."""
    id: str
    subdomain: str
    takeover_type: TakeoverType
    severity: Severity
    cname_record: Optional[str]
    evidence: str
    is_vulnerable: bool
    confidence: float  # 0.0 to 1.0
    verification_steps: List[str]
    poc: str
    remediation: str
    references: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)


class SubdomainTakeoverScanner:
    """Advanced subdomain takeover detection scanner."""
    
    # Comprehensive service fingerprints
    FINGERPRINTS: List[ServiceFingerprint] = [
        # AWS Services
        ServiceFingerprint(
            service=TakeoverType.AWS_S3,
            cname_patterns=[r"\.s3\.amazonaws\.com", r"\.s3-.*\.amazonaws\.com", r"\.s3\..*\.amazonaws\.com"],
            response_fingerprints=["NoSuchBucket", "The specified bucket does not exist"],
            severity=Severity.HIGH,
            documentation="https://docs.aws.amazon.com/AmazonS3/latest/userguide/",
            poc_steps=[
                "Create an S3 bucket with the same name as the CNAME target",
                "Upload index.html with PoC content",
                "Verify the subdomain now serves your content"
            ]
        ),
        ServiceFingerprint(
            service=TakeoverType.AWS_CLOUDFRONT,
            cname_patterns=[r"\.cloudfront\.net"],
            response_fingerprints=["Bad Request", "ERROR: The request could not be satisfied"],
            severity=Severity.HIGH,
            poc_steps=[
                "Create a CloudFront distribution",
                "Add the target subdomain as an alternate domain name (CNAME)",
                "Verify the takeover"
            ]
        ),
        ServiceFingerprint(
            service=TakeoverType.AWS_ELASTIC_BEANSTALK,
            cname_patterns=[r"\.elasticbeanstalk\.com"],
            response_fingerprints=["NXDOMAIN"],
            severity=Severity.HIGH
        ),
        
        # Azure Services
        ServiceFingerprint(
            service=TakeoverType.AZURE_CLOUDAPP,
            cname_patterns=[r"\.cloudapp\.net", r"\.cloudapp\.azure\.com"],
            response_fingerprints=["NXDOMAIN"],
            severity=Severity.HIGH,
            poc_steps=[
                "Create an Azure Cloud Service with matching name",
                "Verify DNS resolution and takeover"
            ]
        ),
        ServiceFingerprint(
            service=TakeoverType.AZURE_WEBSITES,
            cname_patterns=[r"\.azurewebsites\.net", r"\.azure-websites\.net"],
            response_fingerprints=["NXDOMAIN", "404 Web Site not found"],
            severity=Severity.HIGH
        ),
        
        # GitHub Pages
        ServiceFingerprint(
            service=TakeoverType.GITHUB_PAGES,
            cname_patterns=[r"\.github\.io", r"\.githubusercontent\.com"],
            response_fingerprints=["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
            severity=Severity.HIGH,
            poc_steps=[
                "Create a GitHub repository named <username>.github.io",
                "Add a CNAME file with the target subdomain",
                "Push content to verify takeover"
            ]
        ),
        
        # Heroku
        ServiceFingerprint(
            service=TakeoverType.HEROKU,
            cname_patterns=[r"\.herokuapp\.com", r"\.herokussl\.com", r"\.herokudns\.com"],
            response_fingerprints=["No such app", "There's nothing here, yet", "no-such-app"],
            severity=Severity.HIGH,
            poc_steps=[
                "Create a Heroku app with matching name",
                "Add custom domain in Heroku dashboard",
                "Deploy PoC application"
            ]
        ),
        
        # Shopify
        ServiceFingerprint(
            service=TakeoverType.SHOPIFY,
            cname_patterns=[r"\.myshopify\.com"],
            response_fingerprints=["Sorry, this shop is currently unavailable", "Only one step left"],
            severity=Severity.HIGH
        ),
        
        # Netlify
        ServiceFingerprint(
            service=TakeoverType.NETLIFY,
            cname_patterns=[r"\.netlify\.app", r"\.netlify\.com"],
            response_fingerprints=["Not Found", "Page Not Found"],
            nxdomain=False,
            severity=Severity.HIGH
        ),
        
        # Vercel
        ServiceFingerprint(
            service=TakeoverType.VERCEL,
            cname_patterns=[r"\.vercel\.app", r"\.now\.sh"],
            response_fingerprints=["The deployment could not be found"],
            severity=Severity.HIGH
        ),
        
        # Tumblr
        ServiceFingerprint(
            service=TakeoverType.TUMBLR,
            cname_patterns=[r"\.tumblr\.com"],
            response_fingerprints=["There's nothing here", "Whatever you were looking for doesn't currently exist"],
            severity=Severity.MEDIUM
        ),
        
        # WordPress
        ServiceFingerprint(
            service=TakeoverType.WORDPRESS,
            cname_patterns=[r"\.wordpress\.com"],
            response_fingerprints=["Do you want to register"],
            severity=Severity.MEDIUM
        ),
        
        # Zendesk
        ServiceFingerprint(
            service=TakeoverType.ZENDESK,
            cname_patterns=[r"\.zendesk\.com", r"\.zd-staging\.com"],
            response_fingerprints=["Help Center Closed", "Oops, this help center"],
            severity=Severity.MEDIUM
        ),
        
        # Ghost
        ServiceFingerprint(
            service=TakeoverType.GHOST,
            cname_patterns=[r"\.ghost\.io"],
            response_fingerprints=["The thing you were looking for is no longer here"],
            severity=Severity.MEDIUM
        ),
        
        # Fastly
        ServiceFingerprint(
            service=TakeoverType.FASTLY,
            cname_patterns=[r"\.fastly\.net", r"\.fastlylb\.net"],
            response_fingerprints=["Fastly error: unknown domain"],
            severity=Severity.HIGH
        ),
        
        # Pantheon
        ServiceFingerprint(
            service=TakeoverType.PANTHEON,
            cname_patterns=[r"\.pantheonsite\.io", r"\.pantheon\.io"],
            response_fingerprints=["The gods are wise", "404 error unknown site"],
            severity=Severity.HIGH
        ),
        
        # Surge.sh
        ServiceFingerprint(
            service=TakeoverType.SURGE,
            cname_patterns=[r"\.surge\.sh"],
            response_fingerprints=["project not found"],
            severity=Severity.MEDIUM
        ),
        
        # Bitbucket
        ServiceFingerprint(
            service=TakeoverType.BITBUCKET,
            cname_patterns=[r"\.bitbucket\.io"],
            response_fingerprints=["Repository not found"],
            severity=Severity.MEDIUM
        ),
        
        # Intercom
        ServiceFingerprint(
            service=TakeoverType.INTERCOM,
            cname_patterns=[r"\.intercom\.help", r"custom\.intercom\.help"],
            response_fingerprints=["This page is reserved for", "Uh oh. That page doesn't exist"],
            severity=Severity.MEDIUM
        ),
        
        # Webflow
        ServiceFingerprint(
            service=TakeoverType.WEBFLOW,
            cname_patterns=[r"\.webflow\.io", r"proxy-ssl\.webflow\.com"],
            response_fingerprints=["The page you are looking for doesn't exist or has been moved"],
            severity=Severity.MEDIUM
        ),
        
        # Strikingly
        ServiceFingerprint(
            service=TakeoverType.STRIKINGLY,
            cname_patterns=[r"\.strikinglydns\.com", r"\.strikingly\.com"],
            response_fingerprints=["page not found", "But if you're looking to build your own website"],
            severity=Severity.MEDIUM
        ),
        
        # Fly.io
        ServiceFingerprint(
            service=TakeoverType.FLY_IO,
            cname_patterns=[r"\.fly\.dev"],
            response_fingerprints=["Could not resolve host"],
            severity=Severity.MEDIUM
        ),
        
        # Render
        ServiceFingerprint(
            service=TakeoverType.RENDER,
            cname_patterns=[r"\.onrender\.com"],
            response_fingerprints=["Not Found"],
            severity=Severity.MEDIUM
        ),
    ]
    
    def __init__(self):
        self.findings: List[TakeoverFinding] = []
        self.resolver: Optional[aiodns.DNSResolver] = None
        self.finding_count = 0
        self.checked_domains: Set[str] = set()
    
    async def initialize(self):
        """Initialize the DNS resolver."""
        self.resolver = aiodns.DNSResolver()
    
    def generate_finding_id(self) -> str:
        """Generate unique finding ID."""
        self.finding_count += 1
        return f"TAKEOVER-{datetime.now().strftime('%Y%m%d')}-{self.finding_count:04d}"
    
    async def resolve_dns(self, domain: str, record_type: str = "CNAME") -> List[str]:
        """Resolve DNS records for a domain."""
        if not self.resolver:
            await self.initialize()
        
        try:
            if record_type == "CNAME":
                result = await self.resolver.query(domain, "CNAME")
                return [r.cname for r in result]
            elif record_type == "A":
                result = await self.resolver.query(domain, "A")
                return [r.host for r in result]
            elif record_type == "AAAA":
                result = await self.resolver.query(domain, "AAAA")
                return [r.host for r in result]
            elif record_type == "NS":
                result = await self.resolver.query(domain, "NS")
                return [r.host for r in result]
            elif record_type == "TXT":
                result = await self.resolver.query(domain, "TXT")
                return [r.text for r in result]
        except aiodns.error.DNSError as e:
            if "NXDOMAIN" in str(e):
                return ["NXDOMAIN"]
            return []
        except Exception:
            return []
        
        return []
    
    async def check_http_response(self, domain: str, 
                                   fingerprints: List[str]) -> Tuple[bool, str]:
        """Check HTTP response for takeover fingerprints."""
        urls = [f"https://{domain}", f"http://{domain}"]
        
        for url in urls:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False,
                        allow_redirects=True
                    ) as response:
                        text = await response.text()
                        
                        for fingerprint in fingerprints:
                            if fingerprint.lower() in text.lower():
                                return True, fingerprint
                        
                        return False, text[:500]
            except Exception:
                continue
        
        return False, ""
    
    async def check_subdomain(self, subdomain: str) -> Optional[TakeoverFinding]:
        """Check a single subdomain for takeover vulnerability."""
        if subdomain in self.checked_domains:
            return None
        
        self.checked_domains.add(subdomain)
        
        # Get CNAME records
        cname_records = await self.resolve_dns(subdomain, "CNAME")
        
        if not cname_records:
            return None
        
        cname = cname_records[0] if cname_records else ""
        
        # Check if CNAME is NXDOMAIN (dangling)
        is_nxdomain = cname == "NXDOMAIN"
        
        # Match against fingerprints
        for fingerprint in self.FINGERPRINTS:
            for pattern in fingerprint.cname_patterns:
                if re.search(pattern, cname, re.IGNORECASE):
                    # Found a potential match
                    is_vulnerable = False
                    evidence = ""
                    confidence = 0.5
                    
                    if is_nxdomain and fingerprint.nxdomain:
                        is_vulnerable = True
                        evidence = "CNAME target returns NXDOMAIN"
                        confidence = 0.9
                    else:
                        # Check HTTP response
                        matched, response = await self.check_http_response(
                            subdomain, 
                            fingerprint.response_fingerprints
                        )
                        
                        if matched:
                            is_vulnerable = True
                            evidence = f"Response contains: '{response}'"
                            confidence = 0.95
                    
                    if is_vulnerable:
                        finding = TakeoverFinding(
                            id=self.generate_finding_id(),
                            subdomain=subdomain,
                            takeover_type=fingerprint.service,
                            severity=fingerprint.severity,
                            cname_record=cname,
                            evidence=evidence,
                            is_vulnerable=True,
                            confidence=confidence,
                            verification_steps=fingerprint.poc_steps,
                            poc=self._generate_poc(subdomain, fingerprint),
                            remediation=self._get_remediation(fingerprint.service),
                            references=[fingerprint.documentation] if fingerprint.documentation else [],
                            dns_records={"CNAME": cname_records}
                        )
                        
                        self.findings.append(finding)
                        return finding
        
        return None
    
    def _generate_poc(self, subdomain: str, fingerprint: ServiceFingerprint) -> str:
        """Generate proof of concept instructions."""
        poc = f"""# Subdomain Takeover PoC for {subdomain}

## Target Information
- Subdomain: {subdomain}
- Service: {fingerprint.service.value}
- Severity: {fingerprint.severity.value}

## Steps to Verify/Exploit

"""
        for i, step in enumerate(fingerprint.poc_steps, 1):
            poc += f"{i}. {step}\n"
        
        poc += f"""
## Verification Command
```bash
# Check DNS
dig {subdomain} CNAME +short

# Check HTTP response
curl -sI https://{subdomain} | head -20
```

## Important Notes
- This is for authorized testing only
- Document your findings before attempting takeover
- Report to the organization's security team
"""
        return poc
    
    def _get_remediation(self, takeover_type: TakeoverType) -> str:
        """Get remediation advice for a takeover type."""
        general_remediation = """1. Remove the dangling CNAME/DNS record pointing to the unclaimed service
2. If the service is still needed, reclaim the resource on the cloud provider
3. Implement DNS monitoring to detect future dangling records
4. Create a process for decommissioning services that includes DNS cleanup
5. Consider implementing DNS CAA records
6. Audit all subdomains regularly for similar issues"""
        
        specific = {
            TakeoverType.AWS_S3: """
For AWS S3:
1. Delete the CNAME record OR
2. Create and claim the S3 bucket with the exact name
3. Enable S3 bucket logging for monitoring
4. Use bucket policies to restrict access""",
            TakeoverType.GITHUB_PAGES: """
For GitHub Pages:
1. Delete the CNAME record OR  
2. Create a GitHub repository with matching name
3. Add a CNAME file claiming the domain
4. Enable HTTPS in repository settings""",
            TakeoverType.HEROKU: """
For Heroku:
1. Delete the CNAME record OR
2. Create a Heroku app and add the custom domain
3. Verify domain ownership through Heroku
4. Enable SSL certificate""",
            TakeoverType.AZURE_CLOUDAPP: """
For Azure:
1. Delete the CNAME record OR
2. Create an Azure resource with the matching name
3. Verify domain in Azure portal
4. Enable custom domain SSL"""
        }
        
        return specific.get(takeover_type, "") + "\n\n" + general_remediation
    
    async def scan_subdomains(self, subdomains: List[str], 
                               concurrent: int = 10) -> List[TakeoverFinding]:
        """Scan multiple subdomains for takeover vulnerabilities."""
        semaphore = asyncio.Semaphore(concurrent)
        
        async def check_with_semaphore(subdomain: str):
            async with semaphore:
                return await self.check_subdomain(subdomain)
        
        tasks = [check_with_semaphore(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [r for r in results if isinstance(r, TakeoverFinding)]
    
    async def enumerate_and_scan(self, domain: str) -> Dict[str, Any]:
        """Enumerate subdomains and scan for takeovers."""
        from .api_discovery import APIDiscovery  # Reuse subdomain enumeration
        
        # This would integrate with subdomain enumeration
        # For now, we'll check common subdomains
        common_prefixes = [
            "www", "mail", "ftp", "admin", "blog", "shop", "api", "dev",
            "staging", "test", "beta", "alpha", "demo", "app", "mobile",
            "cdn", "static", "assets", "media", "images", "img", "video",
            "docs", "help", "support", "status", "portal", "dashboard",
            "login", "auth", "sso", "secure", "vpn", "remote", "git",
            "gitlab", "github", "jenkins", "ci", "build", "deploy",
            "monitor", "metrics", "logs", "analytics", "tracking",
            "stage", "uat", "qa", "prod", "production", "backup"
        ]
        
        subdomains = [f"{prefix}.{domain}" for prefix in common_prefixes]
        
        findings = await self.scan_subdomains(subdomains)
        
        return {
            "domain": domain,
            "subdomains_checked": len(subdomains),
            "findings": [{
                "id": f.id,
                "subdomain": f.subdomain,
                "type": f.takeover_type.value,
                "severity": f.severity.value,
                "cname": f.cname_record,
                "evidence": f.evidence,
                "confidence": f.confidence,
                "remediation": f.remediation
            } for f in findings],
            "vulnerable_count": len(findings),
            "scan_time": datetime.now().isoformat()
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary."""
        severity_counts = {}
        service_counts = {}
        
        for finding in self.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            svc = finding.takeover_type.value
            service_counts[svc] = service_counts.get(svc, 0) + 1
        
        return {
            "total_findings": len(self.findings),
            "domains_checked": len(self.checked_domains),
            "by_severity": severity_counts,
            "by_service": service_counts,
            "critical_count": severity_counts.get("Critical", 0),
            "high_count": severity_counts.get("High", 0)
        }
    
    def export_report(self, format: str = "markdown") -> str:
        """Export findings report."""
        if format == "json":
            return json.dumps([{
                "id": f.id,
                "subdomain": f.subdomain,
                "type": f.takeover_type.value,
                "severity": f.severity.value,
                "cname": f.cname_record,
                "evidence": f.evidence,
                "is_vulnerable": f.is_vulnerable,
                "confidence": f.confidence,
                "poc": f.poc,
                "remediation": f.remediation
            } for f in self.findings], indent=2)
        
        elif format == "markdown":
            md = "# Subdomain Takeover Report\n\n"
            md += f"**Total Vulnerable Subdomains:** {len(self.findings)}\n\n"
            
            for f in self.findings:
                md += f"## {f.subdomain}\n\n"
                md += f"- **Type:** {f.takeover_type.value}\n"
                md += f"- **Severity:** {f.severity.value}\n"
                md += f"- **CNAME:** `{f.cname_record}`\n"
                md += f"- **Confidence:** {f.confidence * 100:.0f}%\n"
                md += f"- **Evidence:** {f.evidence}\n\n"
                md += f"### Remediation\n{f.remediation}\n\n"
                md += "---\n\n"
            
            return md
        
        return ""
