#!/usr/bin/env python3
"""
HydraRecon Advanced OSINT Module
██████████████████████████████████████████████████████████████████████████████
█  CUTTING-EDGE OSINT - Deep Intelligence Gathering with Real API Support     █
██████████████████████████████████████████████████████████████████████████████
"""

import asyncio
import aiohttp
import json
import re
import socket
import hashlib
import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, quote, urljoin
import ssl

from .base import BaseScanner, ScanResult, ScanStatus


@dataclass
class OSINTFinding:
    """OSINT finding data class"""
    finding_type: str
    source: str
    title: str
    data: Dict[str, Any]
    category: str = "general"
    confidence: int = 50
    severity: str = "info"
    tags: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)


class BaseOSINTModule(ABC):
    """Base class for all OSINT modules"""
    
    def __init__(self, config):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    @property
    @abstractmethod
    def module_name(self) -> str:
        pass
    
    @property
    @abstractmethod
    def module_type(self) -> str:
        pass
    
    @abstractmethod
    async def gather(self, target: str) -> List[OSINTFinding]:
        pass
    
    async def get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=False, limit=30)
            timeout = aiohttp.ClientTimeout(total=30)
            headers = {"User-Agent": self.user_agent}
            self._session = aiohttp.ClientSession(
                connector=connector, 
                timeout=timeout,
                headers=headers
            )
        return self._session
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


class EmailOSINT(BaseOSINTModule):
    """
    Advanced Email Intelligence Module
    - Email validation
    - Email breach checking
    - Email-to-domain correlation
    - Social media discovery from email
    - Gravatar lookup
    """
    
    @property
    def module_name(self) -> str:
        return "Email Intelligence"
    
    @property
    def module_type(self) -> str:
        return "email_intel"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        findings = []
        
        # Determine if target is email or domain
        if '@' in target:
            email = target.lower().strip()
            domain = email.split('@')[1]
            emails = [email]
        else:
            domain = target.lower().strip().replace('http://', '').replace('https://', '').split('/')[0]
            email = None
            emails = []
        
        # If domain, first gather emails from it
        if not email:
            discovered_emails = await self._harvest_emails_from_domain(domain)
            emails.extend(discovered_emails)
            
            if discovered_emails:
                findings.append(OSINTFinding(
                    finding_type="emails",
                    source="domain_harvest",
                    title=f"Discovered {len(discovered_emails)} Email Addresses",
                    data={
                        "domain": domain,
                        "emails": list(discovered_emails),
                        "count": len(discovered_emails)
                    },
                    category="emails",
                    confidence=90,
                    severity="info",
                    tags=["email", "harvested"]
                ))
        
        # Process each email
        for email_addr in emails[:20]:  # Limit to prevent rate limiting
            # Email validation
            validation = await self._validate_email(email_addr)
            if validation:
                findings.append(validation)
            
            # Gravatar check
            gravatar = await self._check_gravatar(email_addr)
            if gravatar:
                findings.append(gravatar)
            
            # HaveIBeenPwned style breach check (using free services)
            breaches = await self._check_breaches(email_addr)
            findings.extend(breaches)
            
            # Social profile discovery
            social = await self._discover_social_from_email(email_addr)
            findings.extend(social)
        
        return findings
    
    async def _harvest_emails_from_domain(self, domain: str) -> Set[str]:
        """Harvest emails from multiple sources"""
        emails = set()
        session = await self.get_session()
        
        # Method 1: Website scraping
        urls_to_check = [
            f"https://{domain}",
            f"https://www.{domain}",
            f"https://{domain}/contact",
            f"https://{domain}/about",
            f"https://{domain}/team",
            f"https://{domain}/contact-us",
            f"https://{domain}/about-us",
            f"https://{domain}/imprint",
            f"https://{domain}/impressum",
            f"https://www.{domain}/contact",
            f"https://www.{domain}/about",
        ]
        
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        for url in urls_to_check:
            try:
                async with session.get(url, timeout=10, allow_redirects=True) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        found = re.findall(email_pattern, text)
                        for email in found:
                            email_lower = email.lower()
                            # Filter for relevant domain emails
                            if domain in email_lower or email_lower.endswith(('.com', '.org', '.net', '.io', '.co')):
                                # Skip obvious fake/placeholder emails
                                if not any(x in email_lower for x in ['example', 'test', 'sample', '@x.', '@xx.', 'noreply']):
                                    emails.add(email_lower)
            except:
                continue
        
        # Method 2: Hunter.io (if API key available)
        hunter_key = getattr(self.config.osint, 'hunter_api_key', '')
        if hunter_key:
            try:
                async with session.get(
                    f"https://api.hunter.io/v2/domain-search",
                    params={"domain": domain, "api_key": hunter_key}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for email_info in data.get('data', {}).get('emails', []):
                            emails.add(email_info.get('value', '').lower())
            except:
                pass
        
        # Method 3: GitHub commits search (public info)
        try:
            async with session.get(
                f"https://api.github.com/search/commits",
                params={"q": f"author-email:@{domain}"},
                headers={"Accept": "application/vnd.github.cloak-preview"}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get('items', [])[:20]:
                        author = item.get('commit', {}).get('author', {})
                        email = author.get('email', '')
                        if email and '@' in email:
                            emails.add(email.lower())
        except:
            pass
        
        # Method 4: Google dorking simulation - check common email patterns
        common_prefixes = [
            'info', 'contact', 'admin', 'support', 'help', 'sales', 'marketing',
            'hr', 'careers', 'jobs', 'press', 'media', 'hello', 'team', 'office',
            'enquiries', 'feedback', 'webmaster', 'postmaster', 'abuse', 'security',
            'privacy', 'legal', 'billing', 'accounts', 'finance', 'ceo', 'cto'
        ]
        
        # Add common format emails as potential candidates
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            for prefix in common_prefixes[:10]:
                potential = f"{prefix}@{domain}"
                emails.add(potential)
        
        return emails
    
    async def _validate_email(self, email: str) -> Optional[OSINTFinding]:
        """Validate email address format and check MX records"""
        try:
            import dns.resolver
            domain = email.split('@')[1]
            
            # Check MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                mx_hosts = [str(r.exchange).rstrip('.') for r in mx_records]
                
                return OSINTFinding(
                    finding_type="email_validation",
                    source="dns_mx",
                    title=f"Email Domain Valid: {email}",
                    data={
                        "email": email,
                        "domain": domain,
                        "mx_records": mx_hosts,
                        "valid_domain": True
                    },
                    category="emails",
                    confidence=85,
                    severity="info",
                    tags=["email", "validated"]
                )
            except:
                pass
        except:
            pass
        return None
    
    async def _check_gravatar(self, email: str) -> Optional[OSINTFinding]:
        """Check if email has a Gravatar profile"""
        try:
            email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
            session = await self.get_session()
            
            # Check gravatar
            async with session.get(
                f"https://www.gravatar.com/{email_hash}.json"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    entry = data.get('entry', [{}])[0]
                    
                    profile_data = {
                        "email": email,
                        "hash": email_hash,
                        "display_name": entry.get('displayName'),
                        "profile_url": entry.get('profileUrl'),
                        "thumbnail_url": f"https://www.gravatar.com/avatar/{email_hash}",
                        "photos": entry.get('photos', []),
                        "accounts": entry.get('accounts', []),
                        "urls": entry.get('urls', [])
                    }
                    
                    return OSINTFinding(
                        finding_type="gravatar_profile",
                        source="gravatar",
                        title=f"Gravatar Profile Found: {entry.get('displayName', email)}",
                        data=profile_data,
                        category="social_media",
                        confidence=100,
                        severity="info",
                        tags=["email", "gravatar", "profile"]
                    )
        except:
            pass
        return None
    
    async def _check_breaches(self, email: str) -> List[OSINTFinding]:
        """Check email in known breach databases (using free services)"""
        findings = []
        session = await self.get_session()
        
        # Check haveibeenpwned (if API key available)
        hibp_key = getattr(self.config.osint, 'haveibeenpwned_api_key', '')
        if hibp_key:
            try:
                async with session.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                    headers={"hibp-api-key": hibp_key, "User-Agent": "HydraRecon"}
                ) as resp:
                    if resp.status == 200:
                        breaches = await resp.json()
                        findings.append(OSINTFinding(
                            finding_type="breach",
                            source="haveibeenpwned",
                            title=f"Email Found in {len(breaches)} Data Breaches",
                            data={
                                "email": email,
                                "breach_count": len(breaches),
                                "breaches": [
                                    {
                                        "name": b.get('Name'),
                                        "domain": b.get('Domain'),
                                        "breach_date": b.get('BreachDate'),
                                        "data_classes": b.get('DataClasses', [])
                                    }
                                    for b in breaches
                                ]
                            },
                            category="breach",
                            confidence=100,
                            severity="high" if len(breaches) > 2 else "medium",
                            tags=["breach", "exposure", "credentials"]
                        ))
            except:
                pass
        
        # Check email reputation with emailrep.io (free, no API key needed)
        try:
            async with session.get(
                f"https://emailrep.io/{quote(email)}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    findings.append(OSINTFinding(
                        finding_type="email_reputation",
                        source="emailrep",
                        title=f"Email Reputation: {data.get('reputation', 'unknown').title()}",
                        data={
                            "email": email,
                            "reputation": data.get('reputation'),
                            "suspicious": data.get('suspicious'),
                            "references": data.get('references'),
                            "credentials_leaked": data.get('details', {}).get('credentials_leaked'),
                            "data_breach": data.get('details', {}).get('data_breach'),
                            "profiles": data.get('details', {}).get('profiles', []),
                            "domain_exists": data.get('details', {}).get('domain_exists'),
                            "deliverable": data.get('details', {}).get('deliverable'),
                            "free_provider": data.get('details', {}).get('free_provider'),
                            "spam": data.get('details', {}).get('spam'),
                            "malicious_activity": data.get('details', {}).get('malicious_activity')
                        },
                        category="breach" if data.get('details', {}).get('credentials_leaked') else "emails",
                        confidence=80,
                        severity="high" if data.get('details', {}).get('credentials_leaked') else "info",
                        tags=["email", "reputation"]
                    ))
        except:
            pass
        
        return findings
    
    async def _discover_social_from_email(self, email: str) -> List[OSINTFinding]:
        """Discover social media accounts linked to email"""
        findings = []
        session = await self.get_session()
        
        # Extract username hints from email
        username = email.split('@')[0]
        
        # Try GitHub user search
        try:
            async with session.get(
                f"https://api.github.com/search/users",
                params={"q": f"{email} in:email"}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    if data.get('total_count', 0) > 0:
                        for user in data.get('items', [])[:3]:
                            findings.append(OSINTFinding(
                                finding_type="social_profile",
                                source="github",
                                title=f"GitHub Profile: {user.get('login')}",
                                data={
                                    "email": email,
                                    "platform": "GitHub",
                                    "username": user.get('login'),
                                    "profile_url": user.get('html_url'),
                                    "avatar_url": user.get('avatar_url'),
                                    "type": user.get('type')
                                },
                                category="social_media",
                                confidence=70,
                                severity="info",
                                tags=["github", "developer", "profile"]
                            ))
        except:
            pass
        
        return findings


class SocialMediaOSINT(BaseOSINTModule):
    """Social Media Intelligence Module"""
    
    PLATFORMS = [
        ("Twitter/X", "https://twitter.com/{}", "twitter"),
        ("Instagram", "https://www.instagram.com/{}", "instagram"),
        ("Facebook", "https://www.facebook.com/{}", "facebook"),
        ("LinkedIn", "https://www.linkedin.com/in/{}", "linkedin"),
        ("GitHub", "https://github.com/{}", "github"),
        ("GitLab", "https://gitlab.com/{}", "gitlab"),
        ("Reddit", "https://www.reddit.com/user/{}", "reddit"),
        ("Pinterest", "https://www.pinterest.com/{}", "pinterest"),
        ("TikTok", "https://www.tiktok.com/@{}", "tiktok"),
        ("YouTube", "https://www.youtube.com/@{}", "youtube"),
        ("Medium", "https://medium.com/@{}", "medium"),
        ("Dev.to", "https://dev.to/{}", "devto"),
        ("Keybase", "https://keybase.io/{}", "keybase"),
        ("Twitch", "https://www.twitch.tv/{}", "twitch"),
        ("Patreon", "https://www.patreon.com/{}", "patreon"),
        ("About.me", "https://about.me/{}", "aboutme"),
        ("Behance", "https://www.behance.net/{}", "behance"),
        ("Dribbble", "https://dribbble.com/{}", "dribbble"),
        ("HackerNews", "https://news.ycombinator.com/user?id={}", "hackernews"),
        ("ProductHunt", "https://www.producthunt.com/@{}", "producthunt"),
    ]
    
    @property
    def module_name(self) -> str:
        return "Social Media Intelligence"
    
    @property
    def module_type(self) -> str:
        return "social_media"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        findings = []
        
        # Extract username from various formats
        username = self._extract_username(target)
        
        if not username:
            return findings
        
        found_platforms = []
        session = await self.get_session()
        
        # Check all platforms concurrently
        async def check_platform(name: str, url_template: str, platform_id: str):
            url = url_template.format(username)
            try:
                async with session.get(url, allow_redirects=True, timeout=10) as resp:
                    # Different platforms have different indicators
                    if resp.status == 200:
                        text = await resp.text()
                        # Check for common "not found" indicators
                        not_found_indicators = [
                            'page not found', 'user not found', 'not found',
                            '404', 'doesn\'t exist', 'does not exist',
                            'no user', 'unavailable', 'been suspended'
                        ]
                        
                        text_lower = text.lower()
                        if not any(ind in text_lower for ind in not_found_indicators):
                            return {
                                "platform": name,
                                "platform_id": platform_id,
                                "url": str(resp.url),
                                "exists": True,
                                "status": resp.status
                            }
            except:
                pass
            return None
        
        tasks = [
            check_platform(name, url, pid) 
            for name, url, pid in self.PLATFORMS
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and isinstance(result, dict) and result.get('exists'):
                found_platforms.append(result)
        
        if found_platforms:
            findings.append(OSINTFinding(
                finding_type="social_media",
                source="username_enum",
                title=f"Social Media Profiles for '{username}' ({len(found_platforms)} found)",
                data={
                    "username": username,
                    "platforms": found_platforms,
                    "platform_count": len(found_platforms)
                },
                category="social_media",
                confidence=75,
                severity="info",
                tags=["social", "username", "profile"]
            ))
        
        return findings
    
    def _extract_username(self, target: str) -> Optional[str]:
        """Extract username from various input formats"""
        target = target.strip()
        
        # If it's an email, extract the local part
        if '@' in target:
            return target.split('@')[0]
        
        # If it's a URL, try to extract username
        if '/' in target:
            parts = target.rstrip('/').split('/')
            return parts[-1].lstrip('@')
        
        # Otherwise, treat as username directly
        return target.lstrip('@')


class CodeRepositoryOSINT(BaseOSINTModule):
    """Code Repository Intelligence - GitHub, GitLab secrets"""
    
    @property
    def module_name(self) -> str:
        return "Code Repository Intelligence"
    
    @property
    def module_type(self) -> str:
        return "code_search"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        findings = []
        session = await self.get_session()
        
        # Determine search type
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        # GitHub code search
        search_queries = [
            (f'"{domain}" password', "password"),
            (f'"{domain}" api_key', "api_key"),
            (f'"{domain}" secret', "secret"),
            (f'"{domain}" token', "token"),
        ]
        
        for query, secret_type in search_queries[:3]:  # Limit to avoid rate limiting
            try:
                async with session.get(
                    "https://api.github.com/search/code",
                    params={"q": query},
                    headers={"Accept": "application/vnd.github.v3+json"}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        total = data.get('total_count', 0)
                        
                        if total > 0:
                            findings.append(OSINTFinding(
                                finding_type="code_exposure",
                                source="github",
                                title=f"Potential {secret_type.replace('_', ' ').title()} in Code ({total} results)",
                                data={
                                    "query": query,
                                    "secret_type": secret_type,
                                    "total_results": total,
                                    "results": [
                                        {
                                            "repo": item.get('repository', {}).get('full_name'),
                                            "path": item.get('path'),
                                            "url": item.get('html_url')
                                        }
                                        for item in data.get('items', [])[:5]
                                    ]
                                },
                                category="code_exposure",
                                confidence=60,
                                severity="high" if secret_type in ['password', 'secret'] else "medium",
                                tags=["github", "secrets", "exposure"]
                            ))
                    
                    # Respect rate limits
                    await asyncio.sleep(2)
            except:
                continue
        
        # Search for organization/user repos
        try:
            org_name = domain.split('.')[0]
            async with session.get(f"https://api.github.com/orgs/{org_name}/repos") as resp:
                if resp.status == 200:
                    repos = await resp.json()
                    if repos:
                        findings.append(OSINTFinding(
                            finding_type="github_org",
                            source="github",
                            title=f"GitHub Organization Found: {len(repos)} repositories",
                            data={
                                "organization": org_name,
                                "repo_count": len(repos),
                                "public_repos": [
                                    {
                                        "name": r.get('name'),
                                        "url": r.get('html_url'),
                                        "description": r.get('description'),
                                        "stars": r.get('stargazers_count'),
                                        "language": r.get('language')
                                    }
                                    for r in repos[:10]
                                ]
                            },
                            category="code_exposure",
                            confidence=90,
                            severity="info",
                            tags=["github", "organization", "repositories"]
                        ))
        except:
            pass
        
        return findings


class WaybackOSINT(BaseOSINTModule):
    """Wayback Machine historical analysis"""
    
    @property
    def module_name(self) -> str:
        return "Wayback Machine"
    
    @property
    def module_type(self) -> str:
        return "wayback"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        findings = []
        session = await self.get_session()
        
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        try:
            # Get snapshot count and dates
            async with session.get(
                f"https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "collapse": "urlkey",
                    "limit": 500
                }
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    if len(data) > 1:  # First row is headers
                        urls = set()
                        timestamps = []
                        
                        for row in data[1:]:
                            if len(row) >= 3:
                                urls.add(row[2])  # Original URL
                                timestamps.append(row[1])  # Timestamp
                        
                        findings.append(OSINTFinding(
                            finding_type="wayback_analysis",
                            source="wayback_machine",
                            title=f"Wayback Machine: {len(urls)} Archived URLs",
                            data={
                                "domain": domain,
                                "unique_urls": len(urls),
                                "total_snapshots": len(data) - 1,
                                "oldest_snapshot": min(timestamps) if timestamps else None,
                                "newest_snapshot": max(timestamps) if timestamps else None,
                                "sample_urls": list(urls)[:20]
                            },
                            category="historical",
                            confidence=100,
                            severity="info",
                            tags=["wayback", "historical", "archive"]
                        ))
                        
                        # Look for interesting paths
                        interesting_paths = []
                        sensitive_patterns = [
                            'admin', 'login', 'backup', 'config', 'api',
                            '.git', '.env', 'phpinfo', 'debug', 'test',
                            'wp-admin', 'phpmyadmin', 'server-status'
                        ]
                        
                        for url in urls:
                            if any(p in url.lower() for p in sensitive_patterns):
                                interesting_paths.append(url)
                        
                        if interesting_paths:
                            findings.append(OSINTFinding(
                                finding_type="wayback_sensitive",
                                source="wayback_machine",
                                title=f"Potentially Sensitive Historical URLs ({len(interesting_paths)})",
                                data={
                                    "urls": interesting_paths[:30]
                                },
                                category="historical",
                                confidence=70,
                                severity="medium",
                                tags=["wayback", "sensitive", "historical"]
                            ))
        except:
            pass
        
        return findings


class ThreatIntelOSINT(BaseOSINTModule):
    """Threat Intelligence lookups"""
    
    @property
    def module_name(self) -> str:
        return "Threat Intelligence"
    
    @property
    def module_type(self) -> str:
        return "threat_intel"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        findings = []
        session = await self.get_session()
        
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Resolve to IP
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = target if self._is_ip(target) else None
        
        # AlienVault OTX
        try:
            async with session.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pulses = data.get('pulse_info', {}).get('count', 0)
                    
                    findings.append(OSINTFinding(
                        finding_type="threat_intel",
                        source="alienvault_otx",
                        title=f"AlienVault OTX: {pulses} Threat Pulses",
                        data={
                            "domain": domain,
                            "pulse_count": pulses,
                            "pulses": [
                                {
                                    "name": p.get('name'),
                                    "description": p.get('description', '')[:200],
                                    "created": p.get('created'),
                                    "tags": p.get('tags', [])
                                }
                                for p in data.get('pulse_info', {}).get('pulses', [])[:5]
                            ],
                            "alexa_rank": data.get('alexa'),
                            "validation": data.get('validation', [])
                        },
                        category="threat_intel",
                        confidence=90,
                        severity="high" if pulses > 5 else "medium" if pulses > 0 else "info",
                        tags=["threat", "malware", "otx"]
                    ))
        except:
            pass
        
        # VirusTotal (if API key)
        vt_key = getattr(self.config.osint, 'virustotal_api_key', '')
        if vt_key:
            try:
                async with session.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": vt_key}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attrs = data.get('data', {}).get('attributes', {})
                        stats = attrs.get('last_analysis_stats', {})
                        
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        
                        findings.append(OSINTFinding(
                            finding_type="virustotal",
                            source="virustotal",
                            title=f"VirusTotal: {malicious} malicious, {suspicious} suspicious",
                            data={
                                "domain": domain,
                                "stats": stats,
                                "categories": attrs.get('categories', {}),
                                "reputation": attrs.get('reputation')
                            },
                            category="threat_intel",
                            confidence=95,
                            severity="critical" if malicious > 3 else "high" if malicious > 0 else "medium" if suspicious > 0 else "info",
                            tags=["virustotal", "malware", "reputation"]
                        ))
            except:
                pass
        
        return findings
    
    def _is_ip(self, target: str) -> bool:
        try:
            socket.inet_aton(target)
            return True
        except:
            return False


class AdvancedOSINTScanner(BaseScanner):
    """Advanced OSINT Scanner combining all modules"""
    
    def __init__(self, config, db):
        super().__init__(config, db)
        
        self.modules = {
            'email_intel': EmailOSINT(config),
            'email_harvest': EmailOSINT(config),  # Alias for compatibility
            'social_media': SocialMediaOSINT(config),
            'code_search': CodeRepositoryOSINT(config),
            'wayback': WaybackOSINT(config),
            'threat_intel': ThreatIntelOSINT(config),
        }
    
    @property
    def scanner_name(self) -> str:
        return "Advanced OSINT Scanner"
    
    @property
    def scanner_type(self) -> str:
        return "osint_advanced"
    
    async def validate_target(self, target: str) -> bool:
        return bool(target and len(target) > 2)
    
    async def scan(self, target: str, modules: List[str] = None, **options) -> ScanResult:
        if not await self.validate_target(target):
            return ScanResult(
                scan_id=self.scan_id,
                scan_type=self.scanner_type,
                target=target,
                status=ScanStatus.FAILED,
                started_at=datetime.now(),
                errors=["Invalid target"]
            )
        
        self.status = ScanStatus.RUNNING
        start_time = datetime.now()
        
        if modules is None:
            modules = list(set(self.modules.keys()))
        
        all_findings = []
        errors = []
        total_modules = len(modules)
        
        for i, module_name in enumerate(modules):
            if self.is_cancelled():
                break
            
            self.wait_if_paused()
            
            if module_name not in self.modules:
                continue
            
            module = self.modules[module_name]
            
            self.emit_progress(
                i + 1, total_modules,
                f"Running {module.module_name}",
                stage=module_name
            )
            
            try:
                findings = await module.gather(target)
                all_findings.extend(findings)
            except Exception as e:
                errors.append(f"{module_name}: {str(e)}")
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(all_findings)
        
        result = ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scanner_type,
            target=target,
            status=ScanStatus.COMPLETED if not self.is_cancelled() else ScanStatus.CANCELLED,
            started_at=start_time,
            completed_at=datetime.now(),
            data={
                'target': target,
                'modules_run': modules,
                'total_findings': len(all_findings),
                'overall_risk_score': risk_score
            },
            findings=[
                {
                    'type': f.finding_type,
                    'source': f.source,
                    'title': f.title,
                    'data': f.data,
                    'category': f.category,
                    'confidence': f.confidence,
                    'severity': f.severity,
                    'tags': f.tags,
                    'discovered_at': f.discovered_at.isoformat()
                }
                for f in all_findings
            ],
            errors=errors
        )
        
        self.emit_progress(
            total_modules, total_modules,
            f"Completed: {len(all_findings)} findings",
            "completed"
        )
        
        return result
    
    def _calculate_risk_score(self, findings: List[OSINTFinding]) -> int:
        if not findings:
            return 0
        
        severity_scores = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
            'info': 1
        }
        
        total = sum(severity_scores.get(f.severity, 1) for f in findings)
        # Normalize to 0-100
        return min(100, int(total / max(len(findings), 1) * 10))
    
    async def close(self):
        for module in self.modules.values():
            await module.close()
    
    def get_available_modules(self) -> Dict[str, str]:
        return {name: mod.module_name for name, mod in self.modules.items()}
