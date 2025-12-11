"""
HydraRecon Threat Intelligence Platform
Advanced threat feed integration and correlation engine
"""

import asyncio
import hashlib
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import re


class ThreatType(Enum):
    """Types of threats"""
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    APT = "apt"
    BOTNET = "botnet"
    EXPLOIT = "exploit"
    C2_SERVER = "c2_server"
    DROPPER = "dropper"
    LOADER = "loader"
    STEALER = "stealer"
    RAT = "rat"
    CRYPTOMINER = "cryptominer"
    SPAM = "spam"
    SCAM = "scam"


class IndicatorType(Enum):
    """Types of threat indicators (IOCs)"""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    EMAIL = "email"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry"
    FILE_PATH = "filepath"
    USER_AGENT = "user_agent"
    YARA_RULE = "yara"
    SNORT_RULE = "snort"
    SIGMA_RULE = "sigma"
    CVE = "cve"
    TTP = "ttp"
    CERTIFICATE = "certificate"
    BITCOIN_ADDRESS = "bitcoin"
    MONERO_ADDRESS = "monero"
    ASN = "asn"
    CIDR = "cidr"


class ConfidenceLevel(Enum):
    """Confidence levels for threat intelligence"""
    UNKNOWN = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CONFIRMED = 100


class FeedType(Enum):
    """Types of threat intelligence feeds"""
    STIX_TAXII = "stix_taxii"
    MISP = "misp"
    OTX = "otx"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    SHODAN = "shodan"
    CENSYS = "censys"
    GREYNOISE = "greynoise"
    URLHAUS = "urlhaus"
    MALWARE_BAZAAR = "malware_bazaar"
    THREATFOX = "threatfox"
    FEODO_TRACKER = "feodo_tracker"
    PHISHTANK = "phishtank"
    OPENPHISH = "openphish"
    CUSTOM = "custom"
    CSV = "csv"
    JSON_FEED = "json"
    RSS = "rss"


@dataclass
class ThreatIndicator:
    """Threat indicator with metadata"""
    indicator_id: str
    indicator_type: IndicatorType
    value: str
    threat_types: List[ThreatType]
    confidence: ConfidenceLevel
    source_feeds: List[str]
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    description: str = ""
    raw_data: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'indicator_id': self.indicator_id,
            'indicator_type': self.indicator_type.value,
            'value': self.value,
            'threat_types': [t.value for t in self.threat_types],
            'confidence': self.confidence.value,
            'source_feeds': self.source_feeds,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'tags': self.tags,
            'malware_families': self.malware_families,
            'threat_actors': self.threat_actors,
            'campaigns': self.campaigns,
            'ttps': self.ttps,
            'references': self.references,
            'description': self.description
        }


@dataclass
class ThreatActor:
    """Threat actor profile"""
    actor_id: str
    name: str
    aliases: List[str]
    description: str
    country: Optional[str]
    motivation: List[str]  # financial, espionage, hacktivism, etc.
    sophistication: str  # low, medium, high, advanced
    target_sectors: List[str]
    target_countries: List[str]
    known_ttps: List[str]
    known_tools: List[str]
    known_campaigns: List[str]
    associated_indicators: List[str]
    first_observed: datetime
    last_active: datetime
    confidence: ConfidenceLevel
    references: List[str] = field(default_factory=list)


@dataclass
class ThreatCampaign:
    """Threat campaign information"""
    campaign_id: str
    name: str
    description: str
    threat_actors: List[str]
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    is_active: bool
    target_sectors: List[str]
    target_countries: List[str]
    ttps: List[str]
    malware_used: List[str]
    infrastructure: List[str]
    indicators: List[str]
    confidence: ConfidenceLevel
    references: List[str] = field(default_factory=list)


@dataclass
class FeedConfig:
    """Configuration for a threat intelligence feed"""
    feed_id: str
    name: str
    feed_type: FeedType
    url: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    enabled: bool = True
    refresh_interval: int = 3600  # seconds
    last_update: Optional[datetime] = None
    filters: Dict = field(default_factory=dict)
    priority: int = 5  # 1-10, higher = more trusted
    custom_headers: Dict = field(default_factory=dict)
    proxy: Optional[str] = None


class STIXTAXIIClient:
    """STIX/TAXII 2.x client for threat intelligence feeds"""
    
    def __init__(self, server_url: str, api_key: Optional[str] = None):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.collections: Dict[str, Dict] = {}
        
    async def discover(self) -> Dict:
        """Discover TAXII server capabilities"""
        # Simulated discovery response
        return {
            'title': 'TAXII Server',
            'description': 'Threat Intelligence TAXII Server',
            'contact': 'security@example.com',
            'default': f'{self.server_url}/api/v21/',
            'api_roots': [
                f'{self.server_url}/api/v21/'
            ]
        }
    
    async def get_collections(self, api_root: str) -> List[Dict]:
        """Get available collections from API root"""
        # Return simulated collections
        return [
            {
                'id': 'malware-indicators',
                'title': 'Malware Indicators',
                'description': 'IOCs for known malware families',
                'can_read': True,
                'can_write': False,
                'media_types': ['application/stix+json;version=2.1']
            },
            {
                'id': 'apt-indicators',
                'title': 'APT Indicators',
                'description': 'Advanced Persistent Threat IOCs',
                'can_read': True,
                'can_write': False,
                'media_types': ['application/stix+json;version=2.1']
            },
            {
                'id': 'phishing-urls',
                'title': 'Phishing URLs',
                'description': 'Known phishing URLs and domains',
                'can_read': True,
                'can_write': False,
                'media_types': ['application/stix+json;version=2.1']
            }
        ]
    
    async def get_objects(self, collection_id: str, 
                         added_after: Optional[datetime] = None,
                         limit: int = 1000) -> List[Dict]:
        """Retrieve STIX objects from collection"""
        # Return simulated STIX objects
        objects = []
        
        # Generate sample STIX indicators
        for i in range(min(limit, 100)):
            stix_object = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f'indicator--{hashlib.sha256(f"{collection_id}-{i}".encode()).hexdigest()[:36]}',
                'created': datetime.now().isoformat(),
                'modified': datetime.now().isoformat(),
                'name': f'Malware Indicator {i}',
                'description': f'Known malicious indicator from {collection_id}',
                'pattern': f"[ipv4-addr:value = '192.168.{i}.{i % 256}']",
                'pattern_type': 'stix',
                'valid_from': datetime.now().isoformat(),
                'labels': ['malicious-activity'],
                'confidence': 75,
                'external_references': [
                    {
                        'source_name': 'HydraRecon',
                        'url': f'https://example.com/indicator/{i}'
                    }
                ]
            }
            objects.append(stix_object)
        
        return objects
    
    def parse_stix_pattern(self, pattern: str) -> List[Tuple[str, str]]:
        """Parse STIX pattern to extract indicators"""
        indicators = []
        
        # Pattern matching for common STIX patterns
        patterns = [
            (r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", IndicatorType.IP_ADDRESS),
            (r"\[domain-name:value\s*=\s*'([^']+)'\]", IndicatorType.DOMAIN),
            (r"\[url:value\s*=\s*'([^']+)'\]", IndicatorType.URL),
            (r"\[file:hashes\.MD5\s*=\s*'([^']+)'\]", IndicatorType.FILE_HASH_MD5),
            (r"\[file:hashes\.SHA-1\s*=\s*'([^']+)'\]", IndicatorType.FILE_HASH_SHA1),
            (r"\[file:hashes\.SHA-256\s*=\s*'([^']+)'\]", IndicatorType.FILE_HASH_SHA256),
            (r"\[email-addr:value\s*=\s*'([^']+)'\]", IndicatorType.EMAIL),
        ]
        
        for regex, ioc_type in patterns:
            matches = re.findall(regex, pattern, re.IGNORECASE)
            for match in matches:
                indicators.append((ioc_type, match))
        
        return indicators


class MISPClient:
    """MISP (Malware Information Sharing Platform) client"""
    
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip('/')
        self.api_key = api_key
        
    async def get_events(self, limit: int = 100, 
                        timestamp: Optional[int] = None) -> List[Dict]:
        """Retrieve MISP events"""
        # Simulated MISP events
        events = []
        
        for i in range(min(limit, 50)):
            event = {
                'id': str(1000 + i),
                'uuid': hashlib.sha256(f"event-{i}".encode()).hexdigest()[:36],
                'date': datetime.now().strftime('%Y-%m-%d'),
                'info': f'Security Incident Report #{i}',
                'threat_level_id': str((i % 4) + 1),
                'analysis': '2',  # Completed
                'distribution': '3',  # All communities
                'org': 'HydraRecon',
                'Attribute': [
                    {
                        'id': str(10000 + i * 10 + j),
                        'type': 'ip-dst',
                        'category': 'Network activity',
                        'value': f'10.{i}.{j}.{(i+j) % 256}',
                        'to_ids': True,
                        'comment': f'C2 server for campaign {i}'
                    }
                    for j in range(5)
                ],
                'Tag': [
                    {'name': 'tlp:amber'},
                    {'name': 'malware:ransomware'}
                ]
            }
            events.append(event)
        
        return events
    
    async def search_attributes(self, value: str = None,
                               type_attribute: str = None,
                               category: str = None) -> List[Dict]:
        """Search MISP attributes"""
        # Simulated search results
        return [
            {
                'id': '12345',
                'type': type_attribute or 'ip-dst',
                'value': value or '192.168.1.1',
                'category': category or 'Network activity',
                'to_ids': True,
                'event_id': '1000',
                'event_info': 'Known C2 Infrastructure'
            }
        ]
    
    async def add_event(self, event_info: str, 
                       threat_level: int = 3,
                       analysis: int = 0,
                       attributes: List[Dict] = None) -> Dict:
        """Create a new MISP event"""
        return {
            'id': str(hash(event_info) % 10000),
            'uuid': hashlib.sha256(event_info.encode()).hexdigest()[:36],
            'info': event_info,
            'threat_level_id': str(threat_level),
            'analysis': str(analysis),
            'Attribute': attributes or []
        }


class OTXClient:
    """AlienVault OTX (Open Threat Exchange) client"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://otx.alienvault.com/api/v1'
        
    async def get_pulse_subscribed(self, limit: int = 50,
                                   modified_since: Optional[str] = None) -> List[Dict]:
        """Get subscribed pulses"""
        # Simulated OTX pulses
        pulses = []
        
        for i in range(min(limit, 25)):
            pulse = {
                'id': f'pulse-{i:04d}',
                'name': f'Threat Intelligence Pulse #{i}',
                'description': f'Automated threat feed pulse {i}',
                'author_name': 'HydraRecon',
                'created': datetime.now().isoformat(),
                'modified': datetime.now().isoformat(),
                'tlp': 'amber',
                'adversary': f'APT{i % 100}',
                'targeted_countries': ['US', 'UK', 'DE'],
                'industries': ['finance', 'technology'],
                'malware_families': ['emotet', 'trickbot'],
                'attack_ids': ['T1566', 'T1059', 'T1071'],
                'indicators': [
                    {
                        'id': j,
                        'indicator': f'malware{i}{j}.evil.com',
                        'type': 'domain',
                        'created': datetime.now().isoformat()
                    }
                    for j in range(10)
                ],
                'tags': ['malware', 'c2', 'apt'],
                'references': [f'https://blog.example.com/threat/{i}']
            }
            pulses.append(pulse)
        
        return pulses
    
    async def get_indicator_details(self, indicator_type: str, 
                                   indicator: str) -> Dict:
        """Get details for a specific indicator"""
        return {
            'indicator': indicator,
            'type': indicator_type,
            'pulse_info': {
                'count': 5,
                'pulses': [
                    {
                        'id': 'pulse-001',
                        'name': 'Known Malware Infrastructure',
                        'created': datetime.now().isoformat()
                    }
                ]
            },
            'general': {
                'reputation': -5,
                'whois': 'Example WHOIS data'
            },
            'geo': {
                'country_code': 'RU',
                'country_name': 'Russia',
                'city': 'Moscow'
            },
            'malware': {
                'count': 10,
                'samples': []
            }
        }


class VirusTotalClient:
    """VirusTotal API client for file/URL/domain analysis"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3'
        
    async def get_file_report(self, file_hash: str) -> Dict:
        """Get analysis report for a file hash"""
        return {
            'id': file_hash,
            'type': 'file',
            'attributes': {
                'sha256': file_hash if len(file_hash) == 64 else hashlib.sha256(file_hash.encode()).hexdigest(),
                'sha1': hashlib.sha1(file_hash.encode()).hexdigest(),
                'md5': hashlib.md5(file_hash.encode()).hexdigest(),
                'names': ['malware.exe', 'bad_file.exe'],
                'type_description': 'Win32 EXE',
                'size': 102400,
                'first_submission_date': int(datetime.now().timestamp()) - 86400 * 30,
                'last_analysis_date': int(datetime.now().timestamp()),
                'last_analysis_stats': {
                    'harmless': 0,
                    'type-unsupported': 5,
                    'suspicious': 2,
                    'confirmed-timeout': 0,
                    'timeout': 0,
                    'failure': 0,
                    'malicious': 55,
                    'undetected': 8
                },
                'last_analysis_results': {
                    'Kaspersky': {'category': 'malicious', 'result': 'Trojan.Generic'},
                    'McAfee': {'category': 'malicious', 'result': 'RDN/Generic.dx'},
                    'Symantec': {'category': 'malicious', 'result': 'Packed.Generic'}
                },
                'popular_threat_classification': {
                    'suggested_threat_label': 'trojan.emotet/banker',
                    'threat_family': 'emotet'
                },
                'tags': ['peexe', 'overlay', 'signed']
            }
        }
    
    async def get_domain_report(self, domain: str) -> Dict:
        """Get analysis report for a domain"""
        return {
            'id': domain,
            'type': 'domain',
            'attributes': {
                'creation_date': int(datetime.now().timestamp()) - 86400 * 365,
                'registrar': 'Example Registrar',
                'last_analysis_date': int(datetime.now().timestamp()),
                'last_analysis_stats': {
                    'harmless': 40,
                    'malicious': 15,
                    'suspicious': 5,
                    'undetected': 10,
                    'timeout': 0
                },
                'reputation': -100,
                'categories': {
                    'Forcepoint ThreatSeeker': 'malware',
                    'Webroot': 'malware site'
                },
                'tags': ['malware', 'c2']
            }
        }
    
    async def get_ip_report(self, ip_address: str) -> Dict:
        """Get analysis report for an IP address"""
        return {
            'id': ip_address,
            'type': 'ip_address',
            'attributes': {
                'network': ip_address.rsplit('.', 1)[0] + '.0/24',
                'asn': 12345,
                'as_owner': 'Example ISP',
                'country': 'RU',
                'continent': 'EU',
                'last_analysis_date': int(datetime.now().timestamp()),
                'last_analysis_stats': {
                    'harmless': 30,
                    'malicious': 20,
                    'suspicious': 10,
                    'undetected': 10,
                    'timeout': 0
                },
                'reputation': -50,
                'tags': ['c2', 'botnet']
            }
        }


class ThreatCorrelationEngine:
    """Engine for correlating threat intelligence across multiple sources"""
    
    def __init__(self):
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.actors: Dict[str, ThreatActor] = {}
        self.campaigns: Dict[str, ThreatCampaign] = {}
        self.correlations: Dict[str, List[str]] = defaultdict(list)
        self.indicator_graph: Dict[str, Set[str]] = defaultdict(set)
        
    def add_indicator(self, indicator: ThreatIndicator):
        """Add or merge an indicator"""
        key = f"{indicator.indicator_type.value}:{indicator.value}"
        
        if key in self.indicators:
            # Merge with existing
            existing = self.indicators[key]
            existing.source_feeds = list(set(existing.source_feeds + indicator.source_feeds))
            existing.tags = list(set(existing.tags + indicator.tags))
            existing.malware_families = list(set(existing.malware_families + indicator.malware_families))
            existing.threat_actors = list(set(existing.threat_actors + indicator.threat_actors))
            existing.last_seen = max(existing.last_seen, indicator.last_seen)
            
            # Upgrade confidence if multiple sources agree
            if len(existing.source_feeds) >= 3:
                existing.confidence = ConfidenceLevel.HIGH
            if len(existing.source_feeds) >= 5:
                existing.confidence = ConfidenceLevel.CONFIRMED
        else:
            self.indicators[key] = indicator
    
    def correlate_indicators(self, indicator_id: str) -> Dict:
        """Find correlations for an indicator"""
        if indicator_id not in self.indicators:
            return {'correlated_indicators': [], 'actors': [], 'campaigns': []}
        
        indicator = self.indicators[indicator_id]
        correlated = []
        
        # Find indicators sharing attributes
        for other_id, other in self.indicators.items():
            if other_id == indicator_id:
                continue
            
            # Check for shared attributes
            shared_malware = set(indicator.malware_families) & set(other.malware_families)
            shared_actors = set(indicator.threat_actors) & set(other.threat_actors)
            shared_campaigns = set(indicator.campaigns) & set(other.campaigns)
            shared_ttps = set(indicator.ttps) & set(other.ttps)
            
            if shared_malware or shared_actors or shared_campaigns or shared_ttps:
                correlation_score = (
                    len(shared_malware) * 10 +
                    len(shared_actors) * 20 +
                    len(shared_campaigns) * 15 +
                    len(shared_ttps) * 5
                )
                
                correlated.append({
                    'indicator': other.to_dict(),
                    'correlation_score': correlation_score,
                    'shared_malware': list(shared_malware),
                    'shared_actors': list(shared_actors),
                    'shared_campaigns': list(shared_campaigns),
                    'shared_ttps': list(shared_ttps)
                })
        
        # Sort by correlation score
        correlated.sort(key=lambda x: x['correlation_score'], reverse=True)
        
        # Find related actors
        related_actors = []
        for actor_id in indicator.threat_actors:
            if actor_id in self.actors:
                related_actors.append(self.actors[actor_id])
        
        # Find related campaigns
        related_campaigns = []
        for campaign_id in indicator.campaigns:
            if campaign_id in self.campaigns:
                related_campaigns.append(self.campaigns[campaign_id])
        
        return {
            'correlated_indicators': correlated[:20],  # Top 20
            'actors': related_actors,
            'campaigns': related_campaigns
        }
    
    def build_threat_graph(self) -> Dict:
        """Build a graph of threat relationships"""
        nodes = []
        edges = []
        
        # Add indicator nodes
        for key, indicator in self.indicators.items():
            nodes.append({
                'id': key,
                'type': 'indicator',
                'indicator_type': indicator.indicator_type.value,
                'value': indicator.value,
                'confidence': indicator.confidence.value
            })
            
            # Add edges to related entities
            for actor in indicator.threat_actors:
                edges.append({
                    'source': key,
                    'target': f'actor:{actor}',
                    'relationship': 'attributed-to'
                })
            
            for campaign in indicator.campaigns:
                edges.append({
                    'source': key,
                    'target': f'campaign:{campaign}',
                    'relationship': 'indicates'
                })
            
            for malware in indicator.malware_families:
                edges.append({
                    'source': key,
                    'target': f'malware:{malware}',
                    'relationship': 'associated-with'
                })
        
        # Add actor nodes
        for actor_id, actor in self.actors.items():
            nodes.append({
                'id': f'actor:{actor_id}',
                'type': 'threat_actor',
                'name': actor.name,
                'country': actor.country
            })
        
        # Add campaign nodes
        for campaign_id, campaign in self.campaigns.items():
            nodes.append({
                'id': f'campaign:{campaign_id}',
                'type': 'campaign',
                'name': campaign.name,
                'is_active': campaign.is_active
            })
        
        return {'nodes': nodes, 'edges': edges}


class ThreatIntelligencePlatform:
    """
    Main threat intelligence platform
    Integrates multiple feeds and provides unified threat intelligence
    """
    
    def __init__(self):
        self.feeds: Dict[str, FeedConfig] = {}
        self.clients: Dict[str, Any] = {}
        self.correlation_engine = ThreatCorrelationEngine()
        self.update_thread: Optional[threading.Thread] = None
        self.running = False
        self.last_update_status: Dict[str, Dict] = {}
        
        # Initialize default feeds
        self._init_default_feeds()
    
    def _init_default_feeds(self):
        """Initialize default threat intelligence feeds"""
        default_feeds = [
            FeedConfig(
                feed_id='urlhaus',
                name='URLhaus',
                feed_type=FeedType.URLHAUS,
                url='https://urlhaus-api.abuse.ch/v1/',
                priority=7
            ),
            FeedConfig(
                feed_id='malware_bazaar',
                name='MalwareBazaar',
                feed_type=FeedType.MALWARE_BAZAAR,
                url='https://bazaar.abuse.ch/api/v1/',
                priority=7
            ),
            FeedConfig(
                feed_id='threatfox',
                name='ThreatFox',
                feed_type=FeedType.THREATFOX,
                url='https://threatfox-api.abuse.ch/api/v1/',
                priority=7
            ),
            FeedConfig(
                feed_id='feodo',
                name='Feodo Tracker',
                feed_type=FeedType.FEODO_TRACKER,
                url='https://feodotracker.abuse.ch/',
                priority=8
            ),
            FeedConfig(
                feed_id='phishtank',
                name='PhishTank',
                feed_type=FeedType.PHISHTANK,
                url='https://data.phishtank.com/data/',
                priority=6
            )
        ]
        
        for feed in default_feeds:
            self.feeds[feed.feed_id] = feed
    
    def add_feed(self, config: FeedConfig):
        """Add a threat intelligence feed"""
        self.feeds[config.feed_id] = config
        
        # Initialize appropriate client
        if config.feed_type == FeedType.STIX_TAXII:
            self.clients[config.feed_id] = STIXTAXIIClient(config.url, config.api_key)
        elif config.feed_type == FeedType.MISP:
            self.clients[config.feed_id] = MISPClient(config.url, config.api_key)
        elif config.feed_type == FeedType.OTX:
            self.clients[config.feed_id] = OTXClient(config.api_key)
        elif config.feed_type == FeedType.VIRUSTOTAL:
            self.clients[config.feed_id] = VirusTotalClient(config.api_key)
    
    def remove_feed(self, feed_id: str):
        """Remove a threat intelligence feed"""
        if feed_id in self.feeds:
            del self.feeds[feed_id]
        if feed_id in self.clients:
            del self.clients[feed_id]
    
    async def update_feed(self, feed_id: str) -> Dict:
        """Update a single feed"""
        if feed_id not in self.feeds:
            return {'success': False, 'error': 'Feed not found'}
        
        config = self.feeds[feed_id]
        start_time = time.time()
        indicators_added = 0
        
        try:
            if config.feed_type == FeedType.STIX_TAXII:
                client = self.clients.get(feed_id, STIXTAXIIClient(config.url, config.api_key))
                collections = await client.get_collections(config.url)
                
                for collection in collections:
                    objects = await client.get_objects(collection['id'], 
                                                       added_after=config.last_update)
                    for obj in objects:
                        if obj['type'] == 'indicator':
                            iocs = client.parse_stix_pattern(obj.get('pattern', ''))
                            for ioc_type, value in iocs:
                                indicator = ThreatIndicator(
                                    indicator_id=obj['id'],
                                    indicator_type=ioc_type,
                                    value=value,
                                    threat_types=[ThreatType.MALWARE],
                                    confidence=ConfidenceLevel(obj.get('confidence', 50)),
                                    source_feeds=[feed_id],
                                    first_seen=datetime.fromisoformat(obj['created'].replace('Z', '+00:00')),
                                    last_seen=datetime.now(),
                                    tags=obj.get('labels', []),
                                    description=obj.get('description', '')
                                )
                                self.correlation_engine.add_indicator(indicator)
                                indicators_added += 1
            
            elif config.feed_type == FeedType.MISP:
                client = self.clients.get(feed_id, MISPClient(config.url, config.api_key))
                events = await client.get_events()
                
                for event in events:
                    for attr in event.get('Attribute', []):
                        ioc_type = self._misp_type_to_indicator_type(attr['type'])
                        if ioc_type:
                            indicator = ThreatIndicator(
                                indicator_id=f"misp-{attr['id']}",
                                indicator_type=ioc_type,
                                value=attr['value'],
                                threat_types=[ThreatType.MALWARE],
                                confidence=ConfidenceLevel.MEDIUM,
                                source_feeds=[feed_id],
                                first_seen=datetime.strptime(event['date'], '%Y-%m-%d'),
                                last_seen=datetime.now(),
                                tags=[t['name'] for t in event.get('Tag', [])],
                                description=attr.get('comment', '')
                            )
                            self.correlation_engine.add_indicator(indicator)
                            indicators_added += 1
            
            elif config.feed_type == FeedType.OTX:
                client = self.clients.get(feed_id, OTXClient(config.api_key))
                pulses = await client.get_pulse_subscribed()
                
                for pulse in pulses:
                    for ioc in pulse.get('indicators', []):
                        ioc_type = self._otx_type_to_indicator_type(ioc['type'])
                        if ioc_type:
                            indicator = ThreatIndicator(
                                indicator_id=f"otx-{pulse['id']}-{ioc['id']}",
                                indicator_type=ioc_type,
                                value=ioc['indicator'],
                                threat_types=[ThreatType.MALWARE],
                                confidence=ConfidenceLevel.MEDIUM,
                                source_feeds=[feed_id],
                                first_seen=datetime.fromisoformat(ioc['created'].replace('Z', '+00:00')),
                                last_seen=datetime.now(),
                                tags=pulse.get('tags', []),
                                malware_families=pulse.get('malware_families', []),
                                threat_actors=[pulse.get('adversary', '')] if pulse.get('adversary') else [],
                                ttps=pulse.get('attack_ids', []),
                                references=pulse.get('references', [])
                            )
                            self.correlation_engine.add_indicator(indicator)
                            indicators_added += 1
            
            # Update last update time
            config.last_update = datetime.now()
            
            result = {
                'success': True,
                'feed_id': feed_id,
                'indicators_added': indicators_added,
                'duration': time.time() - start_time
            }
            
            self.last_update_status[feed_id] = result
            return result
            
        except Exception as e:
            result = {
                'success': False,
                'feed_id': feed_id,
                'error': str(e),
                'duration': time.time() - start_time
            }
            self.last_update_status[feed_id] = result
            return result
    
    async def update_all_feeds(self) -> Dict:
        """Update all enabled feeds"""
        results = {}
        
        for feed_id, config in self.feeds.items():
            if config.enabled:
                results[feed_id] = await self.update_feed(feed_id)
        
        return {
            'total_feeds': len(results),
            'successful': sum(1 for r in results.values() if r['success']),
            'failed': sum(1 for r in results.values() if not r['success']),
            'total_indicators': sum(r.get('indicators_added', 0) for r in results.values()),
            'details': results
        }
    
    def _misp_type_to_indicator_type(self, misp_type: str) -> Optional[IndicatorType]:
        """Convert MISP attribute type to IndicatorType"""
        mapping = {
            'ip-src': IndicatorType.IP_ADDRESS,
            'ip-dst': IndicatorType.IP_ADDRESS,
            'domain': IndicatorType.DOMAIN,
            'hostname': IndicatorType.DOMAIN,
            'url': IndicatorType.URL,
            'md5': IndicatorType.FILE_HASH_MD5,
            'sha1': IndicatorType.FILE_HASH_SHA1,
            'sha256': IndicatorType.FILE_HASH_SHA256,
            'email': IndicatorType.EMAIL,
            'email-src': IndicatorType.EMAIL,
            'email-dst': IndicatorType.EMAIL,
            'mutex': IndicatorType.MUTEX,
            'regkey': IndicatorType.REGISTRY_KEY,
            'filename': IndicatorType.FILE_PATH,
            'user-agent': IndicatorType.USER_AGENT,
            'yara': IndicatorType.YARA_RULE,
            'snort': IndicatorType.SNORT_RULE,
            'sigma': IndicatorType.SIGMA_RULE,
            'vulnerability': IndicatorType.CVE,
            'btc': IndicatorType.BITCOIN_ADDRESS,
            'xmr': IndicatorType.MONERO_ADDRESS,
            'AS': IndicatorType.ASN,
        }
        return mapping.get(misp_type)
    
    def _otx_type_to_indicator_type(self, otx_type: str) -> Optional[IndicatorType]:
        """Convert OTX indicator type to IndicatorType"""
        mapping = {
            'IPv4': IndicatorType.IP_ADDRESS,
            'IPv6': IndicatorType.IP_ADDRESS,
            'domain': IndicatorType.DOMAIN,
            'hostname': IndicatorType.DOMAIN,
            'URL': IndicatorType.URL,
            'URI': IndicatorType.URL,
            'FileHash-MD5': IndicatorType.FILE_HASH_MD5,
            'FileHash-SHA1': IndicatorType.FILE_HASH_SHA1,
            'FileHash-SHA256': IndicatorType.FILE_HASH_SHA256,
            'email': IndicatorType.EMAIL,
            'Mutex': IndicatorType.MUTEX,
            'FilePath': IndicatorType.FILE_PATH,
            'CVE': IndicatorType.CVE,
            'CIDR': IndicatorType.CIDR,
            'YARA': IndicatorType.YARA_RULE,
        }
        return mapping.get(otx_type)
    
    def lookup_indicator(self, indicator_type: IndicatorType, 
                        value: str) -> Optional[ThreatIndicator]:
        """Look up an indicator in the database"""
        key = f"{indicator_type.value}:{value}"
        return self.correlation_engine.indicators.get(key)
    
    def search_indicators(self, query: str = None,
                         indicator_type: IndicatorType = None,
                         threat_type: ThreatType = None,
                         min_confidence: ConfidenceLevel = None,
                         limit: int = 100) -> List[ThreatIndicator]:
        """Search for indicators matching criteria"""
        results = []
        
        for indicator in self.correlation_engine.indicators.values():
            # Apply filters
            if indicator_type and indicator.indicator_type != indicator_type:
                continue
            
            if threat_type and threat_type not in indicator.threat_types:
                continue
            
            if min_confidence and indicator.confidence.value < min_confidence.value:
                continue
            
            if query:
                query_lower = query.lower()
                if not (query_lower in indicator.value.lower() or
                       any(query_lower in tag.lower() for tag in indicator.tags) or
                       any(query_lower in mf.lower() for mf in indicator.malware_families)):
                    continue
            
            results.append(indicator)
            
            if len(results) >= limit:
                break
        
        return results
    
    def get_threat_statistics(self) -> Dict:
        """Get statistics about threat intelligence data"""
        indicators = self.correlation_engine.indicators.values()
        
        stats = {
            'total_indicators': len(self.correlation_engine.indicators),
            'total_actors': len(self.correlation_engine.actors),
            'total_campaigns': len(self.correlation_engine.campaigns),
            'by_type': defaultdict(int),
            'by_threat_type': defaultdict(int),
            'by_confidence': defaultdict(int),
            'by_source': defaultdict(int),
            'recent_24h': 0,
            'recent_7d': 0,
            'malware_families': defaultdict(int),
            'threat_actors': defaultdict(int)
        }
        
        now = datetime.now()
        day_ago = now - timedelta(days=1)
        week_ago = now - timedelta(days=7)
        
        for indicator in indicators:
            stats['by_type'][indicator.indicator_type.value] += 1
            
            for tt in indicator.threat_types:
                stats['by_threat_type'][tt.value] += 1
            
            stats['by_confidence'][indicator.confidence.name] += 1
            
            for source in indicator.source_feeds:
                stats['by_source'][source] += 1
            
            if indicator.last_seen > day_ago:
                stats['recent_24h'] += 1
            if indicator.last_seen > week_ago:
                stats['recent_7d'] += 1
            
            for mf in indicator.malware_families:
                stats['malware_families'][mf] += 1
            
            for actor in indicator.threat_actors:
                stats['threat_actors'][actor] += 1
        
        # Convert defaultdicts to regular dicts
        stats['by_type'] = dict(stats['by_type'])
        stats['by_threat_type'] = dict(stats['by_threat_type'])
        stats['by_confidence'] = dict(stats['by_confidence'])
        stats['by_source'] = dict(stats['by_source'])
        stats['malware_families'] = dict(stats['malware_families'])
        stats['threat_actors'] = dict(stats['threat_actors'])
        
        return stats
    
    def export_iocs(self, format_type: str = 'json',
                   filters: Dict = None) -> str:
        """Export IOCs in various formats"""
        indicators = self.search_indicators(**(filters or {}))
        
        if format_type == 'json':
            return json.dumps([i.to_dict() for i in indicators], indent=2)
        
        elif format_type == 'csv':
            lines = ['type,value,confidence,sources,tags,first_seen,last_seen']
            for i in indicators:
                lines.append(f'{i.indicator_type.value},{i.value},{i.confidence.value},'
                           f'"{";".join(i.source_feeds)}","{";".join(i.tags)}",'
                           f'{i.first_seen.isoformat()},{i.last_seen.isoformat()}')
            return '\n'.join(lines)
        
        elif format_type == 'stix':
            # Generate STIX bundle
            stix_bundle = {
                'type': 'bundle',
                'id': f'bundle--{hashlib.sha256(str(time.time()).encode()).hexdigest()[:36]}',
                'objects': []
            }
            
            for indicator in indicators:
                stix_indicator = {
                    'type': 'indicator',
                    'spec_version': '2.1',
                    'id': f'indicator--{indicator.indicator_id}',
                    'created': indicator.first_seen.isoformat(),
                    'modified': indicator.last_seen.isoformat(),
                    'name': f'{indicator.indicator_type.value}: {indicator.value}',
                    'description': indicator.description,
                    'pattern': self._to_stix_pattern(indicator),
                    'pattern_type': 'stix',
                    'valid_from': indicator.first_seen.isoformat(),
                    'labels': indicator.tags,
                    'confidence': indicator.confidence.value
                }
                stix_bundle['objects'].append(stix_indicator)
            
            return json.dumps(stix_bundle, indent=2)
        
        elif format_type == 'misp':
            # Generate MISP event format
            misp_event = {
                'Event': {
                    'info': 'HydraRecon Threat Intelligence Export',
                    'date': datetime.now().strftime('%Y-%m-%d'),
                    'Attribute': []
                }
            }
            
            for indicator in indicators:
                misp_attr = {
                    'type': self._to_misp_type(indicator.indicator_type),
                    'value': indicator.value,
                    'comment': indicator.description,
                    'to_ids': True,
                    'Tag': [{'name': tag} for tag in indicator.tags]
                }
                misp_event['Event']['Attribute'].append(misp_attr)
            
            return json.dumps(misp_event, indent=2)
        
        else:
            return json.dumps([i.to_dict() for i in indicators], indent=2)
    
    def _to_stix_pattern(self, indicator: ThreatIndicator) -> str:
        """Convert indicator to STIX pattern"""
        type_map = {
            IndicatorType.IP_ADDRESS: f"[ipv4-addr:value = '{indicator.value}']",
            IndicatorType.DOMAIN: f"[domain-name:value = '{indicator.value}']",
            IndicatorType.URL: f"[url:value = '{indicator.value}']",
            IndicatorType.FILE_HASH_MD5: f"[file:hashes.MD5 = '{indicator.value}']",
            IndicatorType.FILE_HASH_SHA1: f"[file:hashes.'SHA-1' = '{indicator.value}']",
            IndicatorType.FILE_HASH_SHA256: f"[file:hashes.'SHA-256' = '{indicator.value}']",
            IndicatorType.EMAIL: f"[email-addr:value = '{indicator.value}']",
        }
        return type_map.get(indicator.indicator_type, f"[x-custom:value = '{indicator.value}']")
    
    def _to_misp_type(self, indicator_type: IndicatorType) -> str:
        """Convert IndicatorType to MISP type"""
        type_map = {
            IndicatorType.IP_ADDRESS: 'ip-dst',
            IndicatorType.DOMAIN: 'domain',
            IndicatorType.URL: 'url',
            IndicatorType.FILE_HASH_MD5: 'md5',
            IndicatorType.FILE_HASH_SHA1: 'sha1',
            IndicatorType.FILE_HASH_SHA256: 'sha256',
            IndicatorType.EMAIL: 'email-dst',
            IndicatorType.MUTEX: 'mutex',
            IndicatorType.REGISTRY_KEY: 'regkey',
            IndicatorType.FILE_PATH: 'filename',
        }
        return type_map.get(indicator_type, 'text')
    
    def start_auto_update(self, interval: int = 3600):
        """Start automatic feed updates"""
        self.running = True
        
        def update_loop():
            while self.running:
                asyncio.run(self.update_all_feeds())
                time.sleep(interval)
        
        self.update_thread = threading.Thread(target=update_loop, daemon=True)
        self.update_thread.start()
    
    def stop_auto_update(self):
        """Stop automatic feed updates"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
