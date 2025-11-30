#!/usr/bin/env python3
"""
HydraRecon OSINT Module
Comprehensive Open Source Intelligence gathering capabilities.
"""

import asyncio
import aiohttp
import dns.resolver
import dns.reversename
import json
import re
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin
import whois
from ipwhois import IPWhois

from .base import BaseScanner, ScanResult, ScanStatus


@dataclass
class OSINTFinding:
    """Generic OSINT finding"""
    finding_type: str
    source: str
    title: str
    data: Dict[str, Any]
    confidence: int = 50  # 0-100
    severity: str = "info"
    discovered_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class OSINTModule(ABC):
    """Base class for OSINT modules"""
    
    def __init__(self, config):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
    
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
        """Get or create aiohttp session"""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.osint.whois_timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session
    
    async def close(self):
        """Close session"""
        if self._session and not self._session.closed:
            await self._session.close()


class DNSEnumerator(OSINTModule):
    """DNS enumeration and analysis"""
    
    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'PTR', 'CAA']
    
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'vpn', 'admin', 'administrator', 'blog', 'dev', 'development', 'staging',
        'test', 'portal', 'api', 'app', 'cdn', 'cloud', 'cms', 'cpanel', 'db',
        'database', 'demo', 'docs', 'download', 'email', 'exchange', 'files',
        'forum', 'ftp', 'git', 'gitlab', 'help', 'host', 'imap', 'img', 'images',
        'internal', 'intranet', 'jenkins', 'jira', 'login', 'm', 'mobile', 'mysql',
        'new', 'news', 'office', 'old', 'panel', 'pop3', 'preview', 'proxy',
        'remote', 'server', 'shop', 'sql', 'ssh', 'ssl', 'stage', 'static',
        'store', 'support', 'svn', 'upload', 'web', 'wiki', 'wp', 'www2', 'www3'
    ]
    
    @property
    def module_name(self) -> str:
        return "DNS Enumerator"
    
    @property
    def module_type(self) -> str:
        return "dns"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        """Gather DNS information for a domain"""
        findings = []
        
        # Get all DNS records
        records = await self.get_dns_records(target)
        for record_type, values in records.items():
            if values:
                findings.append(OSINTFinding(
                    finding_type="dns_record",
                    source="dns_query",
                    title=f"DNS {record_type} Records",
                    data={"record_type": record_type, "values": values},
                    confidence=100,
                    severity="info"
                ))
        
        # Enumerate subdomains
        subdomains = await self.enumerate_subdomains(target)
        if subdomains:
            findings.append(OSINTFinding(
                finding_type="subdomains",
                source="dns_bruteforce",
                title=f"Discovered Subdomains ({len(subdomains)})",
                data={"subdomains": subdomains},
                confidence=100,
                severity="info"
            ))
        
        # Zone transfer attempt
        zone_data = await self.try_zone_transfer(target)
        if zone_data:
            findings.append(OSINTFinding(
                finding_type="zone_transfer",
                source="dns_axfr",
                title="Zone Transfer Vulnerability",
                data={"zone_data": zone_data},
                confidence=100,
                severity="high"
            ))
        
        return findings
    
    async def get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get all DNS records for a domain"""
        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.osint.dns_timeout
        resolver.lifetime = self.config.osint.dns_timeout
        
        for record_type in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            except Exception:
                continue
        
        return records
    
    async def enumerate_subdomains(self, domain: str, 
                                   wordlist: List[str] = None) -> List[Dict[str, Any]]:
        """Enumerate subdomains using wordlist"""
        wordlist = wordlist or self.COMMON_SUBDOMAINS
        found_subdomains = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        async def check_subdomain(subdomain: str):
            fqdn = f"{subdomain}.{domain}"
            try:
                answers = resolver.resolve(fqdn, 'A')
                ips = [str(rdata) for rdata in answers]
                return {
                    'subdomain': fqdn,
                    'ips': ips,
                    'alive': True
                }
            except:
                return None
        
        # Check subdomains concurrently
        tasks = [check_subdomain(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and isinstance(result, dict):
                found_subdomains.append(result)
        
        return found_subdomains
    
    async def try_zone_transfer(self, domain: str) -> Optional[List[str]]:
        """Attempt DNS zone transfer"""
        try:
            resolver = dns.resolver.Resolver()
            ns_records = resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                ns_host = str(ns).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_host, domain, timeout=5)
                    )
                    return [str(name) for name in zone.nodes.keys()]
                except:
                    continue
        except:
            pass
        return None
    
    async def reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            rev_name = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(rev_name, 'PTR')
            return str(answers[0]).rstrip('.')
        except:
            return None


class WhoisLookup(OSINTModule):
    """WHOIS information lookup"""
    
    @property
    def module_name(self) -> str:
        return "WHOIS Lookup"
    
    @property
    def module_type(self) -> str:
        return "whois"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        """Gather WHOIS information"""
        findings = []
        
        try:
            # Domain WHOIS
            w = whois.whois(target)
            
            whois_data = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'whois_server': w.whois_server,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'dnssec': w.dnssec,
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'country': w.country,
                'registrant': w.registrant_name if hasattr(w, 'registrant_name') else None
            }
            
            # Filter out None values
            whois_data = {k: v for k, v in whois_data.items() if v}
            
            findings.append(OSINTFinding(
                finding_type="whois",
                source="whois_query",
                title="WHOIS Information",
                data=whois_data,
                confidence=100,
                severity="info"
            ))
            
            # Check for expiring domain
            if w.expiration_date:
                exp_date = w.expiration_date
                if isinstance(exp_date, list):
                    exp_date = exp_date[0]
                days_until_expiry = (exp_date - datetime.now()).days
                
                if days_until_expiry < 30:
                    findings.append(OSINTFinding(
                        finding_type="domain_expiry",
                        source="whois_analysis",
                        title="Domain Expiring Soon",
                        data={"days_until_expiry": days_until_expiry},
                        confidence=100,
                        severity="medium"
                    ))
                    
        except Exception as e:
            findings.append(OSINTFinding(
                finding_type="error",
                source="whois_query",
                title="WHOIS Lookup Failed",
                data={"error": str(e)},
                confidence=100,
                severity="info"
            ))
        
        return findings


class IPIntelligence(OSINTModule):
    """IP address intelligence gathering"""
    
    @property
    def module_name(self) -> str:
        return "IP Intelligence"
    
    @property
    def module_type(self) -> str:
        return "ip_intel"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        """Gather IP intelligence"""
        findings = []
        
        # Resolve domain to IP if needed
        try:
            ip = socket.gethostbyname(target)
        except:
            ip = target
        
        # RDAP/WHOIS for IP
        try:
            obj = IPWhois(ip)
            rdap_result = obj.lookup_rdap()
            
            findings.append(OSINTFinding(
                finding_type="ip_whois",
                source="rdap",
                title="IP WHOIS Information",
                data={
                    'ip': ip,
                    'asn': rdap_result.get('asn'),
                    'asn_description': rdap_result.get('asn_description'),
                    'asn_country_code': rdap_result.get('asn_country_code'),
                    'network_name': rdap_result.get('network', {}).get('name'),
                    'network_cidr': rdap_result.get('network', {}).get('cidr'),
                    'network_country': rdap_result.get('network', {}).get('country')
                },
                confidence=100,
                severity="info"
            ))
        except Exception as e:
            pass
        
        # GeoIP lookup (using free API)
        try:
            session = await self.get_session()
            async with session.get(f"http://ip-api.com/json/{ip}") as resp:
                if resp.status == 200:
                    geo_data = await resp.json()
                    findings.append(OSINTFinding(
                        finding_type="geoip",
                        source="ip-api",
                        title="Geolocation Information",
                        data={
                            'ip': ip,
                            'country': geo_data.get('country'),
                            'country_code': geo_data.get('countryCode'),
                            'region': geo_data.get('regionName'),
                            'city': geo_data.get('city'),
                            'zip': geo_data.get('zip'),
                            'lat': geo_data.get('lat'),
                            'lon': geo_data.get('lon'),
                            'isp': geo_data.get('isp'),
                            'org': geo_data.get('org'),
                            'as': geo_data.get('as')
                        },
                        confidence=80,
                        severity="info"
                    ))
        except:
            pass
        
        return findings


class ShodanIntelligence(OSINTModule):
    """Shodan search engine integration"""
    
    @property
    def module_name(self) -> str:
        return "Shodan Intelligence"
    
    @property
    def module_type(self) -> str:
        return "shodan"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        """Gather Shodan intelligence"""
        findings = []
        
        api_key = self.config.osint.shodan_api_key
        if not api_key:
            return findings
        
        try:
            # Resolve to IP
            try:
                ip = socket.gethostbyname(target)
            except:
                ip = target
            
            session = await self.get_session()
            
            # Host lookup
            async with session.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    findings.append(OSINTFinding(
                        finding_type="shodan_host",
                        source="shodan",
                        title="Shodan Host Information",
                        data={
                            'ip': data.get('ip_str'),
                            'hostnames': data.get('hostnames', []),
                            'os': data.get('os'),
                            'ports': data.get('ports', []),
                            'vulns': data.get('vulns', []),
                            'tags': data.get('tags', []),
                            'last_update': data.get('last_update'),
                            'isp': data.get('isp'),
                            'org': data.get('org'),
                            'asn': data.get('asn')
                        },
                        confidence=95,
                        severity="info"
                    ))
                    
                    # Process vulnerabilities
                    if data.get('vulns'):
                        for vuln in data['vulns']:
                            findings.append(OSINTFinding(
                                finding_type="vulnerability",
                                source="shodan",
                                title=f"Shodan Vulnerability: {vuln}",
                                data={'cve': vuln},
                                confidence=90,
                                severity="high"
                            ))
                    
                    # Process services
                    for service in data.get('data', []):
                        findings.append(OSINTFinding(
                            finding_type="service",
                            source="shodan",
                            title=f"Service: {service.get('product', 'Unknown')}",
                            data={
                                'port': service.get('port'),
                                'transport': service.get('transport'),
                                'product': service.get('product'),
                                'version': service.get('version'),
                                'banner': service.get('data', '')[:500]
                            },
                            confidence=95,
                            severity="info"
                        ))
                        
        except Exception as e:
            pass
        
        return findings


class CertificateTransparency(OSINTModule):
    """Certificate Transparency log search"""
    
    @property
    def module_name(self) -> str:
        return "Certificate Transparency"
    
    @property
    def module_type(self) -> str:
        return "cert_transparency"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        """Search Certificate Transparency logs"""
        findings = []
        
        try:
            session = await self.get_session()
            
            # Use crt.sh API
            async with session.get(
                f"https://crt.sh/?q=%.{target}&output=json"
            ) as resp:
                if resp.status == 200:
                    certs = await resp.json()
                    
                    # Extract unique subdomains
                    subdomains = set()
                    for cert in certs:
                        name = cert.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub and sub.endswith(target):
                                subdomains.add(sub)
                    
                    if subdomains:
                        findings.append(OSINTFinding(
                            finding_type="ct_subdomains",
                            source="crt.sh",
                            title=f"CT Log Subdomains ({len(subdomains)})",
                            data={
                                'subdomains': list(subdomains),
                                'total_certs': len(certs)
                            },
                            confidence=100,
                            severity="info"
                        ))
                    
                    # Recent certificates
                    recent_certs = sorted(
                        certs,
                        key=lambda x: x.get('entry_timestamp', ''),
                        reverse=True
                    )[:10]
                    
                    if recent_certs:
                        findings.append(OSINTFinding(
                            finding_type="certificates",
                            source="crt.sh",
                            title="Recent SSL Certificates",
                            data={
                                'certificates': [
                                    {
                                        'id': c.get('id'),
                                        'name': c.get('name_value'),
                                        'issuer': c.get('issuer_name'),
                                        'not_before': c.get('not_before'),
                                        'not_after': c.get('not_after')
                                    }
                                    for c in recent_certs
                                ]
                            },
                            confidence=100,
                            severity="info"
                        ))
                        
        except Exception as e:
            pass
        
        return findings


class WebTechnologyAnalyzer(OSINTModule):
    """Web technology detection"""
    
    @property
    def module_name(self) -> str:
        return "Web Technology Analyzer"
    
    @property
    def module_type(self) -> str:
        return "web_tech"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        """Analyze web technologies"""
        findings = []
        
        try:
            # Ensure URL format
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"
            
            session = await self.get_session()
            
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                headers = dict(resp.headers)
                html = await resp.text()
                
                technologies = []
                
                # Server header
                if 'Server' in headers:
                    technologies.append({
                        'category': 'Web Server',
                        'name': headers['Server'],
                        'source': 'header'
                    })
                
                # X-Powered-By
                if 'X-Powered-By' in headers:
                    technologies.append({
                        'category': 'Framework',
                        'name': headers['X-Powered-By'],
                        'source': 'header'
                    })
                
                # Detect from HTML
                tech_patterns = [
                    (r'wordpress', 'CMS', 'WordPress'),
                    (r'wp-content', 'CMS', 'WordPress'),
                    (r'drupal', 'CMS', 'Drupal'),
                    (r'joomla', 'CMS', 'Joomla'),
                    (r'shopify', 'E-commerce', 'Shopify'),
                    (r'magento', 'E-commerce', 'Magento'),
                    (r'woocommerce', 'E-commerce', 'WooCommerce'),
                    (r'react', 'JavaScript Framework', 'React'),
                    (r'angular', 'JavaScript Framework', 'Angular'),
                    (r'vue\.js|vuejs', 'JavaScript Framework', 'Vue.js'),
                    (r'jquery', 'JavaScript Library', 'jQuery'),
                    (r'bootstrap', 'CSS Framework', 'Bootstrap'),
                    (r'tailwind', 'CSS Framework', 'Tailwind CSS'),
                    (r'cloudflare', 'CDN', 'Cloudflare'),
                    (r'google-analytics|gtag', 'Analytics', 'Google Analytics'),
                    (r'hotjar', 'Analytics', 'Hotjar'),
                    (r'recaptcha', 'Security', 'reCAPTCHA'),
                    (r'nginx', 'Web Server', 'Nginx'),
                    (r'apache', 'Web Server', 'Apache'),
                    (r'iis', 'Web Server', 'Microsoft IIS'),
                ]
                
                for pattern, category, name in tech_patterns:
                    if re.search(pattern, html, re.IGNORECASE):
                        if not any(t['name'] == name for t in technologies):
                            technologies.append({
                                'category': category,
                                'name': name,
                                'source': 'html'
                            })
                
                # Check security headers
                security_headers = {
                    'Strict-Transport-Security': 'HSTS',
                    'Content-Security-Policy': 'CSP',
                    'X-Content-Type-Options': 'X-Content-Type-Options',
                    'X-Frame-Options': 'X-Frame-Options',
                    'X-XSS-Protection': 'XSS Protection',
                    'Referrer-Policy': 'Referrer Policy'
                }
                
                present_headers = []
                missing_headers = []
                
                for header, name in security_headers.items():
                    if header in headers:
                        present_headers.append(name)
                    else:
                        missing_headers.append(name)
                
                if technologies:
                    findings.append(OSINTFinding(
                        finding_type="technologies",
                        source="web_analysis",
                        title=f"Detected Technologies ({len(technologies)})",
                        data={'technologies': technologies},
                        confidence=80,
                        severity="info"
                    ))
                
                findings.append(OSINTFinding(
                    finding_type="security_headers",
                    source="web_analysis",
                    title="Security Headers Analysis",
                    data={
                        'present': present_headers,
                        'missing': missing_headers
                    },
                    confidence=100,
                    severity="medium" if missing_headers else "info"
                ))
                
        except Exception as e:
            pass
        
        return findings


class EmailHarvester(OSINTModule):
    """Email address harvesting"""
    
    @property
    def module_name(self) -> str:
        return "Email Harvester"
    
    @property
    def module_type(self) -> str:
        return "email_harvest"
    
    async def gather(self, target: str) -> List[OSINTFinding]:
        """Harvest email addresses"""
        findings = []
        emails = set()
        
        # Extract domain
        domain = target.replace('https://', '').replace('http://', '').split('/')[0]
        
        try:
            session = await self.get_session()
            
            # Search through various sources
            sources = [
                f"https://www.google.com/search?q=%40{domain}",
            ]
            
            # Try to get from website
            for url in [f"https://{domain}", f"https://www.{domain}"]:
                try:
                    async with session.get(url, ssl=False, timeout=10) as resp:
                        if resp.status == 200:
                            html = await resp.text()
                            # Extract emails
                            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                            found = re.findall(email_pattern, html)
                            for email in found:
                                if domain in email.lower():
                                    emails.add(email.lower())
                except:
                    continue
            
            if emails:
                findings.append(OSINTFinding(
                    finding_type="emails",
                    source="web_scraping",
                    title=f"Discovered Email Addresses ({len(emails)})",
                    data={'emails': list(emails)},
                    confidence=90,
                    severity="info"
                ))
                
        except Exception as e:
            pass
        
        return findings


class OSINTScanner(BaseScanner):
    """Complete OSINT scanner combining all modules"""
    
    def __init__(self, config, db):
        super().__init__(config, db)
        
        # Initialize all OSINT modules
        self.modules = {
            'dns': DNSEnumerator(config),
            'whois': WhoisLookup(config),
            'ip_intel': IPIntelligence(config),
            'shodan': ShodanIntelligence(config),
            'cert_transparency': CertificateTransparency(config),
            'web_tech': WebTechnologyAnalyzer(config),
            'email_harvest': EmailHarvester(config)
        }
    
    @property
    def scanner_name(self) -> str:
        return "OSINT Scanner"
    
    @property
    def scanner_type(self) -> str:
        return "osint"
    
    async def validate_target(self, target: str) -> bool:
        """Validate target (domain, IP, or URL)"""
        # Very permissive validation for OSINT
        return bool(target and len(target) > 2)
    
    async def scan(self, target: str, modules: List[str] = None, **options) -> ScanResult:
        """Execute OSINT gathering"""
        
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
        
        # Select modules to run
        if modules is None:
            modules = list(self.modules.keys())
        
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
        
        # Convert findings to result
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
                'total_findings': len(all_findings)
            },
            findings=[
                {
                    'type': f.finding_type,
                    'source': f.source,
                    'title': f.title,
                    'data': f.data,
                    'confidence': f.confidence,
                    'severity': f.severity,
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
    
    async def close(self):
        """Close all module sessions"""
        for module in self.modules.values():
            await module.close()
    
    def get_available_modules(self) -> Dict[str, str]:
        """Get available OSINT modules"""
        return {
            name: module.module_name
            for name, module in self.modules.items()
        }
