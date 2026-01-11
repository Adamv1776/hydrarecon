"""
Threat Intelligence Engine
Real-time threat intelligence with Shodan, VirusTotal, AbuseIPDB, and more
"""

import asyncio
import aiohttp
import json
import hashlib
import ipaddress
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set
from enum import Enum
import re
from pathlib import Path

from .free_api_integrations import FreeAPIClient


class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class IOCType(Enum):
    """Indicator of Compromise types"""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "hash"
    EMAIL = "email"
    CVE = "cve"
    MALWARE = "malware"
    CAMPAIGN = "campaign"


@dataclass
class ThreatIndicator:
    """Represents a threat indicator"""
    ioc_type: IOCType
    value: str
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: int = 0
    sources: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: str = ""
    related_iocs: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ShodanResult:
    """Shodan scan result"""
    ip: str
    hostnames: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    os: str = ""
    isp: str = ""
    org: str = ""
    country: str = ""
    city: str = ""
    last_update: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class VirusTotalResult:
    """VirusTotal analysis result"""
    indicator: str
    indicator_type: str
    positives: int = 0
    total: int = 0
    scan_date: Optional[datetime] = None
    permalink: str = ""
    detections: Dict[str, Dict] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    threat_names: List[str] = field(default_factory=list)


@dataclass
class AbuseIPDBResult:
    """AbuseIPDB report result"""
    ip: str
    abuse_confidence: int = 0
    country_code: str = ""
    isp: str = ""
    domain: str = ""
    total_reports: int = 0
    num_distinct_users: int = 0
    last_reported: Optional[datetime] = None
    categories: List[int] = field(default_factory=list)
    is_whitelisted: bool = False


@dataclass
class ThreatReport:
    """Comprehensive threat intelligence report"""
    target: str
    scan_time: datetime = field(default_factory=datetime.now)
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    risk_score: int = 0
    indicators: List[ThreatIndicator] = field(default_factory=list)
    shodan_data: Optional[ShodanResult] = None
    virustotal_data: Optional[VirusTotalResult] = None
    abuseipdb_data: Optional[AbuseIPDBResult] = None
    recommendations: List[str] = field(default_factory=list)
    summary: str = ""


class ThreatIntelligence:
    """
    Threat Intelligence Engine
    Aggregates data from multiple threat intelligence sources
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.api_keys = {
            'shodan': self.config.get('shodan_api_key', ''),
            'virustotal': self.config.get('virustotal_api_key', ''),
            'abuseipdb': self.config.get('abuseipdb_api_key', ''),
            'alienvault': self.config.get('alienvault_api_key', ''),
            'threatcrowd': '',  # Free, no API key needed
            'urlscan': self.config.get('urlscan_api_key', ''),
        }
        self.cache: Dict[str, Any] = {}
        self.cache_ttl = timedelta(hours=1)

        # Free enrichments (no API key). Enabled by default.
        self.enable_free_enrichment = bool(self.config.get('enable_free_enrichment', True))
        
        # Known malicious patterns
        self.malicious_patterns = {
            'suspicious_ports': [4444, 5555, 6666, 31337, 12345],
            'c2_indicators': ['cobalt', 'beacon', 'meterpreter', 'empire'],
            'malware_families': ['emotet', 'trickbot', 'ryuk', 'conti', 'lockbit'],
        }
    
    async def analyze_target(self, target: str, 
                             full_scan: bool = True) -> ThreatReport:
        """
        Perform comprehensive threat intelligence analysis on a target
        """
        report = ThreatReport(target=target)
        
        # Determine target type
        ioc_type = self._identify_ioc_type(target)
        
        tasks = []
        
        if ioc_type == IOCType.IP_ADDRESS:
            if self.api_keys['shodan']:
                tasks.append(self._query_shodan(target))
            if self.api_keys['abuseipdb']:
                tasks.append(self._query_abuseipdb(target))
            if self.api_keys['virustotal']:
                tasks.append(self._query_virustotal_ip(target))
            tasks.append(self._query_threatcrowd_ip(target))

            if self.enable_free_enrichment:
                tasks.append(self._query_free_ip_enrichment(target))
            
        elif ioc_type == IOCType.DOMAIN:
            if self.api_keys['virustotal']:
                tasks.append(self._query_virustotal_domain(target))
            tasks.append(self._query_threatcrowd_domain(target))
            if self.api_keys['urlscan']:
                tasks.append(self._query_urlscan(target))

            if self.enable_free_enrichment:
                # Public search is often usable without a key.
                tasks.append(self._query_free_domain_enrichment(target))
                
        elif ioc_type == IOCType.FILE_HASH:
            if self.api_keys['virustotal']:
                tasks.append(self._query_virustotal_hash(target))
            tasks.append(self._query_malwarebazaar(target))

            if self.enable_free_enrichment:
                tasks.append(self._query_free_hash_enrichment(target))
            
        elif ioc_type == IOCType.URL:
            if self.api_keys['virustotal']:
                tasks.append(self._query_virustotal_url(target))
            if self.api_keys['urlscan']:
                tasks.append(self._query_urlscan(target))

            if self.enable_free_enrichment:
                tasks.append(self._query_free_url_enrichment(target))

        elif ioc_type == IOCType.EMAIL:
            if self.enable_free_enrichment:
                tasks.append(self._query_free_email_enrichment(target))
        
        # Execute all queries in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                continue
            
            if isinstance(result, ShodanResult):
                report.shodan_data = result
                report.indicators.extend(
                    self._extract_indicators_from_shodan(result)
                )
            elif isinstance(result, VirusTotalResult):
                report.virustotal_data = result
                report.indicators.extend(
                    self._extract_indicators_from_vt(result)
                )
            elif isinstance(result, AbuseIPDBResult):
                report.abuseipdb_data = result
                report.indicators.extend(
                    self._extract_indicators_from_abuseipdb(result)
                )
            elif isinstance(result, list):
                report.indicators.extend(result)
        
        # Calculate overall risk score
        report.risk_score = self._calculate_risk_score(report)
        report.threat_level = self._determine_threat_level(report.risk_score)
        
        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)
        report.summary = self._generate_summary(report)
        
        return report

    async def _query_free_ip_enrichment(self, ip: str) -> List[ThreatIndicator]:
        """Free IP enrichment (geo + RDAP)."""
        indicators: List[ThreatIndicator] = []
        try:
            async with FreeAPIClient() as client:
                geo = await client.ip_geolocation(ip)
                if geo.ok and geo.data:
                    indicators.append(
                        ThreatIndicator(
                            ioc_type=IOCType.IP_ADDRESS,
                            value=ip,
                            sources=['ip-api'],
                            tags=['geolocation'],
                            description=f"Geo: {geo.data.get('country', '')} {geo.data.get('city', '')}".strip(),
                            raw_data={'ip_api': geo.data},
                            confidence=60,
                        )
                    )

                rdap = await client.ipwhois_rdap(ip)
                if rdap.ok and rdap.data:
                    name = rdap.data.get('name') or rdap.data.get('handle') or ''
                    indicators.append(
                        ThreatIndicator(
                            ioc_type=IOCType.IP_ADDRESS,
                            value=ip,
                            sources=['rdap'],
                            tags=['rdap'],
                            description=f"RDAP: {name}".strip(),
                            raw_data={'rdap': rdap.data},
                            confidence=60,
                        )
                    )
        except Exception:
            pass
        return indicators

    async def _query_free_domain_enrichment(self, domain: str) -> List[ThreatIndicator]:
        """Free domain enrichment via urlscan public search."""
        indicators: List[ThreatIndicator] = []
        try:
            async with FreeAPIClient() as client:
                res = await client.urlscan_search(domain)
                if res.ok and res.data:
                    indicators.append(
                        ThreatIndicator(
                            ioc_type=IOCType.DOMAIN,
                            value=domain,
                            sources=['urlscan'],
                            tags=['urlscan'],
                            description="URLScan public search results",
                            raw_data={'urlscan': res.data},
                            confidence=55,
                        )
                    )
        except Exception:
            pass
        return indicators

    async def _query_free_hash_enrichment(self, sha256: str) -> List[ThreatIndicator]:
        """Free hash enrichment via MalwareBazaar + ThreatFox."""
        indicators: List[ThreatIndicator] = []
        try:
            async with FreeAPIClient() as client:
                mb = await client.malwarebazaar_hash(sha256)
                if mb.ok and mb.data:
                    indicators.append(
                        ThreatIndicator(
                            ioc_type=IOCType.FILE_HASH,
                            value=sha256,
                            sources=['malwarebazaar'],
                            tags=['malware'],
                            description="MalwareBazaar lookup",
                            raw_data={'malwarebazaar': mb.data},
                            confidence=70,
                        )
                    )

                tf = await client.threatfox_search(sha256)
                if tf.ok and tf.data:
                    indicators.append(
                        ThreatIndicator(
                            ioc_type=IOCType.FILE_HASH,
                            value=sha256,
                            sources=['threatfox'],
                            tags=['threatfox'],
                            description="ThreatFox IOC search",
                            raw_data={'threatfox': tf.data},
                            confidence=65,
                        )
                    )
        except Exception:
            pass
        return indicators

    async def _query_free_url_enrichment(self, url: str) -> List[ThreatIndicator]:
        """Free URL enrichment via urlscan public search."""
        indicators: List[ThreatIndicator] = []
        try:
            async with FreeAPIClient() as client:
                res = await client.urlscan_search(url)
                if res.ok and res.data:
                    indicators.append(
                        ThreatIndicator(
                            ioc_type=IOCType.URL,
                            value=url,
                            sources=['urlscan'],
                            tags=['urlscan'],
                            description="URLScan public search results",
                            raw_data={'urlscan': res.data},
                            confidence=55,
                        )
                    )
        except Exception:
            pass
        return indicators

    async def _query_free_email_enrichment(self, email: str) -> List[ThreatIndicator]:
        """Free email enrichment via emailrep.io."""
        indicators: List[ThreatIndicator] = []
        try:
            async with FreeAPIClient() as client:
                rep = await client.email_reputation(email)
                if rep.ok and rep.data:
                    reputation = rep.data.get('reputation', '')
                    suspicious = rep.data.get('suspicious')
                    indicators.append(
                        ThreatIndicator(
                            ioc_type=IOCType.EMAIL,
                            value=email,
                            sources=['emailrep'],
                            tags=['emailrep'],
                            description=f"EmailRep: {reputation} suspicious={suspicious}",
                            raw_data={'emailrep': rep.data},
                            confidence=70,
                        )
                    )
        except Exception:
            pass
        return indicators
    
    def _identify_ioc_type(self, target: str) -> IOCType:
        """Identify the type of indicator"""
        # Check if IP address
        try:
            ipaddress.ip_address(target)
            return IOCType.IP_ADDRESS
        except ValueError:
            pass
        
        # Check if URL
        if target.startswith(('http://', 'https://')):
            return IOCType.URL
        
        # Check if hash
        if re.match(r'^[a-fA-F0-9]{32}$', target):  # MD5
            return IOCType.FILE_HASH
        if re.match(r'^[a-fA-F0-9]{40}$', target):  # SHA1
            return IOCType.FILE_HASH
        if re.match(r'^[a-fA-F0-9]{64}$', target):  # SHA256
            return IOCType.FILE_HASH
        
        # Check if email
        if '@' in target and '.' in target:
            return IOCType.EMAIL
        
        # Check if CVE
        if re.match(r'^CVE-\d{4}-\d+$', target, re.IGNORECASE):
            return IOCType.CVE
        
        # Default to domain
        return IOCType.DOMAIN
    
    async def _query_shodan(self, ip: str) -> ShodanResult:
        """Query Shodan for host information"""
        cache_key = f"shodan:{ip}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if datetime.now() - cached['time'] < self.cache_ttl:
                return cached['data']
        
        result = ShodanResult(ip=ip)
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.shodan.io/shodan/host/{ip}"
                params = {'key': self.api_keys['shodan']}
                
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        result.hostnames = data.get('hostnames', [])
                        result.ports = data.get('ports', [])
                        result.os = data.get('os', '')
                        result.isp = data.get('isp', '')
                        result.org = data.get('org', '')
                        result.country = data.get('country_name', '')
                        result.city = data.get('city', '')
                        result.vulns = list(data.get('vulns', {}).keys())
                        result.tags = data.get('tags', [])
                        
                        # Extract services
                        for item in data.get('data', []):
                            result.services.append({
                                'port': item.get('port'),
                                'transport': item.get('transport'),
                                'product': item.get('product', ''),
                                'version': item.get('version', ''),
                                'banner': item.get('data', '')[:500],
                            })
                        
                        if data.get('last_update'):
                            result.last_update = datetime.fromisoformat(
                                data['last_update'].replace('Z', '+00:00')
                            )
        except Exception as e:
            result.tags.append(f"error:{str(e)}")
        
        self.cache[cache_key] = {'time': datetime.now(), 'data': result}
        return result
    
    async def _query_abuseipdb(self, ip: str) -> AbuseIPDBResult:
        """Query AbuseIPDB for IP reputation"""
        result = AbuseIPDBResult(ip=ip)
        
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    'Accept': 'application/json',
                    'Key': self.api_keys['abuseipdb']
                }
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90,
                    'verbose': True
                }
                
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        info = data.get('data', {})
                        
                        result.abuse_confidence = info.get('abuseConfidenceScore', 0)
                        result.country_code = info.get('countryCode', '')
                        result.isp = info.get('isp', '')
                        result.domain = info.get('domain', '')
                        result.total_reports = info.get('totalReports', 0)
                        result.num_distinct_users = info.get('numDistinctUsers', 0)
                        result.is_whitelisted = info.get('isWhitelisted', False)
                        
                        if info.get('lastReportedAt'):
                            result.last_reported = datetime.fromisoformat(
                                info['lastReportedAt'].replace('Z', '+00:00')
                            )
        except Exception:
            pass
        
        return result
    
    async def _query_virustotal_ip(self, ip: str) -> VirusTotalResult:
        """Query VirusTotal for IP reputation"""
        return await self._query_virustotal(ip, "ip-address")
    
    async def _query_virustotal_domain(self, domain: str) -> VirusTotalResult:
        """Query VirusTotal for domain reputation"""
        return await self._query_virustotal(domain, "domain")
    
    async def _query_virustotal_hash(self, hash_val: str) -> VirusTotalResult:
        """Query VirusTotal for file hash"""
        return await self._query_virustotal(hash_val, "file")
    
    async def _query_virustotal_url(self, url: str) -> VirusTotalResult:
        """Query VirusTotal for URL"""
        return await self._query_virustotal(url, "url")
    
    async def _query_virustotal(self, indicator: str, 
                                indicator_type: str) -> VirusTotalResult:
        """Generic VirusTotal query"""
        result = VirusTotalResult(indicator=indicator, indicator_type=indicator_type)
        
        try:
            async with aiohttp.ClientSession() as session:
                if indicator_type == "file":
                    url = f"https://www.virustotal.com/vtapi/v2/file/report"
                    params = {
                        'apikey': self.api_keys['virustotal'],
                        'resource': indicator
                    }
                elif indicator_type == "url":
                    url = f"https://www.virustotal.com/vtapi/v2/url/report"
                    params = {
                        'apikey': self.api_keys['virustotal'],
                        'resource': indicator
                    }
                elif indicator_type == "domain":
                    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                    params = {
                        'apikey': self.api_keys['virustotal'],
                        'domain': indicator
                    }
                else:  # IP
                    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
                    params = {
                        'apikey': self.api_keys['virustotal'],
                        'ip': indicator
                    }
                
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        result.positives = data.get('positives', 0)
                        result.total = data.get('total', 0)
                        result.permalink = data.get('permalink', '')
                        
                        if data.get('scan_date'):
                            result.scan_date = datetime.strptime(
                                data['scan_date'], '%Y-%m-%d %H:%M:%S'
                            )
                        
                        # Extract detections
                        scans = data.get('scans', {})
                        for engine, info in scans.items():
                            if info.get('detected'):
                                result.detections[engine] = info
                                if info.get('result'):
                                    result.threat_names.append(info['result'])
        except Exception:
            pass
        
        return result
    
    async def _query_threatcrowd_ip(self, ip: str) -> List[ThreatIndicator]:
        """Query ThreatCrowd for IP intel (free)"""
        indicators = []
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://www.threatcrowd.org/searchApi/v2/ip/report/"
                params = {'ip': ip}
                
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Extract related domains
                        for domain in data.get('resolutions', [])[:10]:
                            indicators.append(ThreatIndicator(
                                ioc_type=IOCType.DOMAIN,
                                value=domain.get('domain', ''),
                                sources=['threatcrowd'],
                                description="Related domain"
                            ))
                        
                        # Extract related hashes
                        for hash_val in data.get('hashes', [])[:10]:
                            indicators.append(ThreatIndicator(
                                ioc_type=IOCType.FILE_HASH,
                                value=hash_val,
                                sources=['threatcrowd'],
                                description="Related malware hash"
                            ))
        except Exception:
            pass
        
        return indicators
    
    async def _query_threatcrowd_domain(self, domain: str) -> List[ThreatIndicator]:
        """Query ThreatCrowd for domain intel"""
        indicators = []
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/"
                params = {'domain': domain}
                
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Extract related IPs
                        for res in data.get('resolutions', [])[:10]:
                            indicators.append(ThreatIndicator(
                                ioc_type=IOCType.IP_ADDRESS,
                                value=res.get('ip_address', ''),
                                sources=['threatcrowd'],
                                description="Related IP"
                            ))
                        
                        # Extract subdomains
                        for subdomain in data.get('subdomains', [])[:10]:
                            indicators.append(ThreatIndicator(
                                ioc_type=IOCType.DOMAIN,
                                value=subdomain,
                                sources=['threatcrowd'],
                                tags=['subdomain']
                            ))
        except Exception:
            pass
        
        return indicators
    
    async def _query_urlscan(self, target: str) -> List[ThreatIndicator]:
        """Query URLScan.io for URL analysis"""
        indicators = []
        
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://urlscan.io/api/v1/search/"
                params = {'q': target}
                headers = {'API-Key': self.api_keys['urlscan']} if self.api_keys['urlscan'] else {}
                
                async with session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for result in data.get('results', [])[:5]:
                            task = result.get('task', {})
                            page = result.get('page', {})
                            
                            indicators.append(ThreatIndicator(
                                ioc_type=IOCType.URL,
                                value=task.get('url', ''),
                                sources=['urlscan'],
                                tags=[page.get('status', ''), page.get('mimeType', '')],
                                description=f"Scanned: {task.get('time', '')}"
                            ))
        except Exception:
            pass
        
        return indicators
    
    async def _query_malwarebazaar(self, hash_val: str) -> List[ThreatIndicator]:
        """Query MalwareBazaar for hash info"""
        indicators = []
        
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://mb-api.abuse.ch/api/v1/"
                data = {
                    'query': 'get_info',
                    'hash': hash_val
                }
                
                async with session.post(url, data=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        if result.get('query_status') == 'ok':
                            info = result.get('data', [{}])[0]
                            
                            indicators.append(ThreatIndicator(
                                ioc_type=IOCType.MALWARE,
                                value=info.get('signature', 'Unknown'),
                                threat_level=ThreatLevel.CRITICAL,
                                confidence=90,
                                sources=['malwarebazaar'],
                                tags=info.get('tags', []),
                                first_seen=datetime.fromisoformat(
                                    info.get('first_seen', '')[:19]
                                ) if info.get('first_seen') else None,
                                description=f"File: {info.get('file_name', '')}"
                            ))
        except Exception:
            pass
        
        return indicators
    
    def _extract_indicators_from_shodan(self, 
                                        result: ShodanResult) -> List[ThreatIndicator]:
        """Extract threat indicators from Shodan results"""
        indicators = []
        
        # Check for vulnerabilities
        for vuln in result.vulns:
            indicators.append(ThreatIndicator(
                ioc_type=IOCType.CVE,
                value=vuln,
                threat_level=ThreatLevel.HIGH,
                confidence=80,
                sources=['shodan'],
                description=f"Vulnerability found on {result.ip}"
            ))
        
        # Check for suspicious ports
        for port in result.ports:
            if port in self.malicious_patterns['suspicious_ports']:
                indicators.append(ThreatIndicator(
                    ioc_type=IOCType.IP_ADDRESS,
                    value=f"{result.ip}:{port}",
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=60,
                    sources=['shodan'],
                    tags=['suspicious_port'],
                    description=f"Suspicious port {port} open"
                ))
        
        # Check for C2 indicators in banners
        for service in result.services:
            banner = service.get('banner', '').lower()
            for c2_indicator in self.malicious_patterns['c2_indicators']:
                if c2_indicator in banner:
                    indicators.append(ThreatIndicator(
                        ioc_type=IOCType.IP_ADDRESS,
                        value=result.ip,
                        threat_level=ThreatLevel.CRITICAL,
                        confidence=70,
                        sources=['shodan'],
                        tags=['c2', c2_indicator],
                        description=f"Potential C2 indicator in service banner"
                    ))
        
        return indicators
    
    def _extract_indicators_from_vt(self, 
                                    result: VirusTotalResult) -> List[ThreatIndicator]:
        """Extract threat indicators from VirusTotal results"""
        indicators = []
        
        if result.positives > 0:
            # Determine threat level based on detection ratio
            ratio = result.positives / max(result.total, 1)
            
            if ratio > 0.5:
                threat_level = ThreatLevel.CRITICAL
            elif ratio > 0.3:
                threat_level = ThreatLevel.HIGH
            elif ratio > 0.1:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
            
            indicators.append(ThreatIndicator(
                ioc_type=IOCType.MALWARE if result.indicator_type == "file" else IOCType.URL,
                value=result.indicator,
                threat_level=threat_level,
                confidence=int(ratio * 100),
                sources=['virustotal'],
                tags=result.threat_names[:5],
                description=f"Detected by {result.positives}/{result.total} engines"
            ))
        
        return indicators
    
    def _extract_indicators_from_abuseipdb(self, 
                                           result: AbuseIPDBResult) -> List[ThreatIndicator]:
        """Extract threat indicators from AbuseIPDB results"""
        indicators = []
        
        if result.abuse_confidence > 0:
            if result.abuse_confidence >= 80:
                threat_level = ThreatLevel.CRITICAL
            elif result.abuse_confidence >= 50:
                threat_level = ThreatLevel.HIGH
            elif result.abuse_confidence >= 25:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
            
            indicators.append(ThreatIndicator(
                ioc_type=IOCType.IP_ADDRESS,
                value=result.ip,
                threat_level=threat_level,
                confidence=result.abuse_confidence,
                sources=['abuseipdb'],
                tags=[f"reports:{result.total_reports}"],
                last_seen=result.last_reported,
                description=f"Reported {result.total_reports} times by {result.num_distinct_users} users"
            ))
        
        return indicators
    
    def _calculate_risk_score(self, report: ThreatReport) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        weights = {
            ThreatLevel.CRITICAL: 25,
            ThreatLevel.HIGH: 15,
            ThreatLevel.MEDIUM: 10,
            ThreatLevel.LOW: 5,
            ThreatLevel.INFO: 1,
            ThreatLevel.UNKNOWN: 0,
        }
        
        for indicator in report.indicators:
            score += weights.get(indicator.threat_level, 0)
        
        # Add Shodan vulnerability score
        if report.shodan_data:
            score += len(report.shodan_data.vulns) * 10
        
        # Add VirusTotal detection score
        if report.virustotal_data:
            ratio = report.virustotal_data.positives / max(report.virustotal_data.total, 1)
            score += int(ratio * 30)
        
        # Add AbuseIPDB score
        if report.abuseipdb_data:
            score += int(report.abuseipdb_data.abuse_confidence * 0.3)
        
        return min(100, score)
    
    def _determine_threat_level(self, risk_score: int) -> ThreatLevel:
        """Determine threat level from risk score"""
        if risk_score >= 80:
            return ThreatLevel.CRITICAL
        elif risk_score >= 60:
            return ThreatLevel.HIGH
        elif risk_score >= 40:
            return ThreatLevel.MEDIUM
        elif risk_score >= 20:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO
    
    def _generate_recommendations(self, report: ThreatReport) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if report.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            recommendations.append("⚠️ IMMEDIATE ACTION REQUIRED - Block this indicator at the firewall")
            recommendations.append("Investigate any systems that have communicated with this target")
        
        if report.shodan_data:
            if report.shodan_data.vulns:
                recommendations.append(
                    f"Patch {len(report.shodan_data.vulns)} known vulnerabilities: " +
                    ", ".join(report.shodan_data.vulns[:3])
                )
            
            for service in report.shodan_data.services:
                if 'telnet' in str(service.get('product', '')).lower():
                    recommendations.append("Disable Telnet service - use SSH instead")
                if 'ftp' in str(service.get('product', '')).lower():
                    recommendations.append("Consider replacing FTP with SFTP")
        
        if report.virustotal_data and report.virustotal_data.positives > 0:
            recommendations.append(
                f"Add to blocklist - {report.virustotal_data.positives} security vendors flagged this"
            )
            if report.virustotal_data.threat_names:
                recommendations.append(
                    f"Scan for related malware: {', '.join(report.virustotal_data.threat_names[:3])}"
                )
        
        if report.abuseipdb_data and report.abuseipdb_data.abuse_confidence > 50:
            recommendations.append(
                f"IP has been reported for abuse by {report.abuseipdb_data.num_distinct_users} users"
            )
            recommendations.append("Consider adding to threat intelligence blocklist")
        
        if not recommendations:
            recommendations.append("No immediate threats detected - continue monitoring")
        
        return recommendations
    
    def _generate_summary(self, report: ThreatReport) -> str:
        """Generate human-readable summary"""
        parts = [f"Threat Analysis for {report.target}"]
        parts.append(f"Risk Score: {report.risk_score}/100 ({report.threat_level.value.upper()})")
        parts.append(f"Indicators Found: {len(report.indicators)}")
        
        if report.shodan_data:
            parts.append(
                f"Shodan: {len(report.shodan_data.ports)} ports, "
                f"{len(report.shodan_data.vulns)} vulnerabilities"
            )
        
        if report.virustotal_data:
            parts.append(
                f"VirusTotal: {report.virustotal_data.positives}/{report.virustotal_data.total} detections"
            )
        
        if report.abuseipdb_data:
            parts.append(
                f"AbuseIPDB: {report.abuseipdb_data.abuse_confidence}% confidence, "
                f"{report.abuseipdb_data.total_reports} reports"
            )
        
        return " | ".join(parts)
    
    async def bulk_analyze(self, targets: List[str]) -> Dict[str, ThreatReport]:
        """Analyze multiple targets in parallel"""
        tasks = [self.analyze_target(target) for target in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            target: result for target, result in zip(targets, results)
            if not isinstance(result, Exception)
        }
    
    async def get_ioc_feed(self, feed_type: str = "all") -> List[ThreatIndicator]:
        """Get threat indicators from public feeds"""
        indicators = []
        
        feeds = {
            'feodo': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
            'urlhaus': 'https://urlhaus.abuse.ch/downloads/json_recent/',
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                if feed_type in ['all', 'feodo']:
                    async with session.get(feeds['feodo']) as response:
                        if response.status == 200:
                            data = await response.json()
                            for entry in data[:100]:
                                indicators.append(ThreatIndicator(
                                    ioc_type=IOCType.IP_ADDRESS,
                                    value=entry.get('ip_address', ''),
                                    threat_level=ThreatLevel.CRITICAL,
                                    sources=['feodotracker'],
                                    tags=['botnet', 'c2'],
                                    first_seen=datetime.fromisoformat(
                                        entry.get('first_seen', '')[:19]
                                    ) if entry.get('first_seen') else None,
                                    description=entry.get('malware', '')
                                ))
                
                if feed_type in ['all', 'urlhaus']:
                    async with session.get(feeds['urlhaus']) as response:
                        if response.status == 200:
                            data = await response.json()
                            for url_id, entry in list(data.get('urls', {}).items())[:100]:
                                indicators.append(ThreatIndicator(
                                    ioc_type=IOCType.URL,
                                    value=entry.get('url', ''),
                                    threat_level=ThreatLevel.HIGH,
                                    sources=['urlhaus'],
                                    tags=entry.get('tags', []),
                                    description=entry.get('threat', '')
                                ))
        except Exception:
            pass
        
        return indicators
    
    def export_iocs(self, indicators: List[ThreatIndicator], 
                    format: str = "stix") -> str:
        """Export IOCs in various formats"""
        if format == "csv":
            lines = ["type,value,threat_level,confidence,sources"]
            for ind in indicators:
                lines.append(
                    f"{ind.ioc_type.value},{ind.value},{ind.threat_level.value},"
                    f"{ind.confidence},{';'.join(ind.sources)}"
                )
            return "\n".join(lines)
        
        elif format == "json":
            return json.dumps([{
                'type': ind.ioc_type.value,
                'value': ind.value,
                'threat_level': ind.threat_level.value,
                'confidence': ind.confidence,
                'sources': ind.sources,
                'tags': ind.tags,
                'description': ind.description
            } for ind in indicators], indent=2)
        
        elif format == "stix":
            # STIX 2.1 format
            bundle = {
                "type": "bundle",
                "id": f"bundle--{hashlib.md5(str(datetime.now()).encode()).hexdigest()}",
                "objects": []
            }
            
            for ind in indicators:
                stix_obj = {
                    "type": "indicator",
                    "id": f"indicator--{hashlib.md5(ind.value.encode()).hexdigest()}",
                    "created": datetime.now().isoformat() + "Z",
                    "modified": datetime.now().isoformat() + "Z",
                    "pattern": f"[{ind.ioc_type.value}:value = '{ind.value}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.now().isoformat() + "Z",
                    "labels": ind.tags,
                    "confidence": ind.confidence
                }
                bundle["objects"].append(stix_obj)
            
            return json.dumps(bundle, indent=2)
        
        return ""
