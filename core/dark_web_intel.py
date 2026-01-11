#!/usr/bin/env python3
"""
Dark Web Intelligence Crawler - Hidden Service Monitoring & Threat Intelligence
Revolutionary dark web intelligence gathering and analysis platform.
"""

import asyncio
import hashlib
import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


class HiddenServiceType(Enum):
    """Types of hidden services."""
    MARKETPLACE = auto()
    FORUM = auto()
    PASTE_SITE = auto()
    LEAK_SITE = auto()
    RANSOMWARE_PORTAL = auto()
    HACKING_SERVICE = auto()
    CARDING_SITE = auto()
    MALWARE_SHOP = auto()
    DATA_BROKER = auto()
    EXPLOIT_MARKET = auto()
    BOTNET_PANEL = auto()
    CRYPTOCURRENCY_MIXER = auto()
    PHISHING_KIT = auto()
    CREDENTIAL_SHOP = auto()
    UNKNOWN = auto()


class ThreatCategory(Enum):
    """Categories of dark web threats."""
    DATA_BREACH = auto()
    CREDENTIAL_LEAK = auto()
    MALWARE_SALE = auto()
    EXPLOIT_SALE = auto()
    RANSOMWARE = auto()
    INSIDER_THREAT = auto()
    BRAND_ABUSE = auto()
    EXECUTIVE_THREAT = auto()
    INFRASTRUCTURE_THREAT = auto()
    SUPPLY_CHAIN = auto()
    ZERO_DAY = auto()
    APT_ACTIVITY = auto()
    HACKTIVISM = auto()


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFORMATIONAL = auto()


class NetworkType(Enum):
    """Dark web network types."""
    TOR = auto()
    I2P = auto()
    FREENET = auto()
    ZeroNET = auto()
    LOKINET = auto()
    CLEARNET_PASTE = auto()
    TELEGRAM = auto()
    DISCORD = auto()


@dataclass
class HiddenService:
    """Represents a dark web hidden service."""
    service_id: str
    onion_address: str
    network_type: NetworkType
    service_type: HiddenServiceType
    title: str
    description: str
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    threat_level: AlertSeverity
    categories: List[ThreatCategory] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    related_services: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DarkWebMention:
    """Represents a mention of interest on the dark web."""
    mention_id: str
    source_service: str
    source_url: str
    mention_type: ThreatCategory
    matched_keywords: List[str]
    content_snippet: str
    full_content_hash: str
    timestamp: datetime
    severity: AlertSeverity
    confidence: float
    context: Dict[str, Any] = field(default_factory=dict)
    actors: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)


@dataclass
class ThreatActor:
    """Represents a dark web threat actor."""
    actor_id: str
    aliases: List[str]
    first_seen: datetime
    last_active: datetime
    reputation_score: float
    verified: bool
    services_active: List[str]
    specializations: List[ThreatCategory]
    languages: List[str]
    communication_channels: List[str]
    known_campaigns: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    infrastructure: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LeakedCredential:
    """Represents leaked credentials found on dark web."""
    credential_id: str
    source: str
    breach_name: str
    email: str
    domain: str
    password_hash: Optional[str]
    password_type: str
    discovered_date: datetime
    breach_date: Optional[datetime]
    additional_data: Dict[str, Any] = field(default_factory=dict)
    is_corporate: bool = False
    risk_score: float = 0.0


@dataclass
class DataLeak:
    """Represents a data leak or breach on dark web."""
    leak_id: str
    source_service: str
    victim_organization: str
    leak_type: ThreatCategory
    announced_date: datetime
    data_volume: str
    record_count: Optional[int]
    data_categories: List[str]
    sample_available: bool
    price: Optional[str]
    seller_actor: Optional[str]
    verification_status: str
    relevance_score: float
    iocs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DarkWebAlert:
    """Alert generated from dark web monitoring."""
    alert_id: str
    alert_type: ThreatCategory
    severity: AlertSeverity
    title: str
    description: str
    source: str
    source_url: str
    created_at: datetime
    matched_rules: List[str]
    affected_assets: List[str]
    recommended_actions: List[str]
    related_iocs: List[str] = field(default_factory=list)
    related_actors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MonitoringRule:
    """Rule for dark web monitoring."""
    rule_id: str
    name: str
    description: str
    keywords: List[str]
    regex_patterns: List[str]
    domains_of_interest: List[str]
    email_patterns: List[str]
    threat_categories: List[ThreatCategory]
    severity_override: Optional[AlertSeverity]
    is_active: bool
    created_at: datetime
    last_triggered: Optional[datetime]
    trigger_count: int = 0


class DarkWebIntelligence:
    """
    Revolutionary dark web intelligence gathering and analysis platform.
    
    Features:
    - Hidden service discovery and monitoring
    - Credential leak detection
    - Threat actor tracking
    - Data breach monitoring
    - Brand abuse detection
    - Executive threat monitoring
    - Automated alerting
    """
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "dark_web_intel.db"
        self.logger = logging.getLogger("DarkWebIntelligence")
        self.services: Dict[str, HiddenService] = {}
        self.mentions: Dict[str, DarkWebMention] = {}
        self.actors: Dict[str, ThreatActor] = {}
        self.credentials: Dict[str, LeakedCredential] = {}
        self.leaks: Dict[str, DataLeak] = {}
        self.alerts: List[DarkWebAlert] = []
        self.rules: Dict[str, MonitoringRule] = {}
        self.callbacks: Dict[str, List[Callable]] = {}
        
        # Known malicious patterns
        self.ransomware_groups = self._load_ransomware_groups()
        self.malware_families = self._load_malware_families()
        self.apt_groups = self._load_apt_groups()
        
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize SQLite database for dark web intelligence."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS hidden_services (
                service_id TEXT PRIMARY KEY,
                onion_address TEXT UNIQUE,
                network_type TEXT,
                service_type TEXT,
                title TEXT,
                description TEXT,
                first_seen TEXT,
                last_seen TEXT,
                is_active INTEGER,
                threat_level TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS mentions (
                mention_id TEXT PRIMARY KEY,
                source_service TEXT,
                source_url TEXT,
                mention_type TEXT,
                matched_keywords TEXT,
                content_snippet TEXT,
                content_hash TEXT,
                timestamp TEXT,
                severity TEXT,
                confidence REAL,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS threat_actors (
                actor_id TEXT PRIMARY KEY,
                aliases TEXT,
                first_seen TEXT,
                last_active TEXT,
                reputation_score REAL,
                verified INTEGER,
                services_active TEXT,
                specializations TEXT,
                languages TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS credentials (
                credential_id TEXT PRIMARY KEY,
                source TEXT,
                breach_name TEXT,
                email TEXT,
                domain TEXT,
                password_hash TEXT,
                password_type TEXT,
                discovered_date TEXT,
                breach_date TEXT,
                is_corporate INTEGER,
                risk_score REAL
            );
            
            CREATE TABLE IF NOT EXISTS data_leaks (
                leak_id TEXT PRIMARY KEY,
                source_service TEXT,
                victim_organization TEXT,
                leak_type TEXT,
                announced_date TEXT,
                data_volume TEXT,
                record_count INTEGER,
                data_categories TEXT,
                sample_available INTEGER,
                price TEXT,
                seller_actor TEXT,
                verification_status TEXT,
                relevance_score REAL
            );
            
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                alert_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                source TEXT,
                source_url TEXT,
                created_at TEXT,
                matched_rules TEXT,
                affected_assets TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS monitoring_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                keywords TEXT,
                regex_patterns TEXT,
                domains_of_interest TEXT,
                email_patterns TEXT,
                threat_categories TEXT,
                severity_override TEXT,
                is_active INTEGER,
                created_at TEXT,
                last_triggered TEXT,
                trigger_count INTEGER
            );
            
            CREATE INDEX IF NOT EXISTS idx_mentions_source ON mentions(source_service);
            CREATE INDEX IF NOT EXISTS idx_mentions_type ON mentions(mention_type);
            CREATE INDEX IF NOT EXISTS idx_credentials_domain ON credentials(domain);
            CREATE INDEX IF NOT EXISTS idx_leaks_victim ON data_leaks(victim_organization);
        """)
        
        conn.commit()
        conn.close()
    
    def _load_ransomware_groups(self) -> Dict[str, Dict[str, Any]]:
        """Load known ransomware group signatures."""
        return {
            "lockbit": {
                "aliases": ["LockBit 3.0", "LockBit Black"],
                "onion_patterns": [r"lockbit.*\.onion"],
                "indicators": ["lockbit", "decryption", "stolen data"],
                "ttps": ["T1486", "T1490", "T1562"]
            },
            "alphv": {
                "aliases": ["BlackCat", "ALPHV"],
                "onion_patterns": [r"alphv.*\.onion", r"blackcat.*\.onion"],
                "indicators": ["alphv", "blackcat", "rust ransomware"],
                "ttps": ["T1486", "T1027", "T1070"]
            },
            "clop": {
                "aliases": ["Cl0p", "TA505"],
                "onion_patterns": [r"clop.*\.onion"],
                "indicators": ["clop", "cl0p", "moveit"],
                "ttps": ["T1486", "T1567", "T1190"]
            },
            "royal": {
                "aliases": ["Royal Ransomware", "Zeon"],
                "onion_patterns": [r"royal.*\.onion"],
                "indicators": ["royal", "readme.txt"],
                "ttps": ["T1486", "T1059", "T1562"]
            },
            "play": {
                "aliases": ["Play Ransomware", "PlayCrypt"],
                "onion_patterns": [r"play.*\.onion"],
                "indicators": ["play", ".play extension"],
                "ttps": ["T1486", "T1562", "T1048"]
            }
        }
    
    def _load_malware_families(self) -> Dict[str, Dict[str, Any]]:
        """Load known malware family signatures."""
        return {
            "emotet": {
                "type": "loader",
                "indicators": ["emotet", "epoch", "heodo"],
                "c2_patterns": [r"emotet.*\.onion"]
            },
            "qakbot": {
                "type": "banking_trojan",
                "indicators": ["qakbot", "qbot", "pinkslipbot"],
                "c2_patterns": [r"qak.*\.onion"]
            },
            "icedid": {
                "type": "banking_trojan",
                "indicators": ["icedid", "bokbot"],
                "c2_patterns": []
            },
            "cobalt_strike": {
                "type": "c2_framework",
                "indicators": ["cobalt strike", "beacon", "cs4"],
                "c2_patterns": []
            },
            "raccoon": {
                "type": "stealer",
                "indicators": ["raccoon", "raccoon stealer", "recordbreaker"],
                "c2_patterns": [r"raccoon.*\.onion"]
            },
            "redline": {
                "type": "stealer",
                "indicators": ["redline", "redline stealer"],
                "c2_patterns": []
            },
            "vidar": {
                "type": "stealer",
                "indicators": ["vidar", "vidar stealer"],
                "c2_patterns": []
            }
        }
    
    def _load_apt_groups(self) -> Dict[str, Dict[str, Any]]:
        """Load known APT group signatures."""
        return {
            "apt28": {
                "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "STRONTIUM"],
                "nation_state": "Russia",
                "sectors": ["government", "military", "media"],
                "indicators": ["sednit", "sofacy", "x-agent"]
            },
            "apt29": {
                "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM"],
                "nation_state": "Russia",
                "sectors": ["government", "technology", "think_tanks"],
                "indicators": ["cozy bear", "nobelium", "solarwinds"]
            },
            "apt41": {
                "aliases": ["Winnti", "BARIUM", "Wicked Panda"],
                "nation_state": "China",
                "sectors": ["technology", "healthcare", "gaming"],
                "indicators": ["winnti", "shadowpad", "plugx"]
            },
            "lazarus": {
                "aliases": ["Hidden Cobra", "APT38", "ZINC"],
                "nation_state": "North Korea",
                "sectors": ["financial", "cryptocurrency", "defense"],
                "indicators": ["lazarus", "hidden cobra", "applejeus"]
            },
            "apt33": {
                "aliases": ["Elfin", "Magnallium", "Refined Kitten"],
                "nation_state": "Iran",
                "sectors": ["aerospace", "energy", "petrochemical"],
                "indicators": ["elfin", "shamoon", "stonedrill"]
            }
        }
    
    async def discover_hidden_services(
        self,
        seed_urls: List[str],
        max_depth: int = 2,
        timeout: int = 30
    ) -> List[HiddenService]:
        """
        Discover hidden services starting from seed URLs.
        
        Args:
            seed_urls: Initial onion URLs to start crawling
            max_depth: Maximum crawl depth
            timeout: Request timeout in seconds
            
        Returns:
            List of discovered hidden services
        """
        discovered = []
        visited: Set[str] = set()
        queue = [(url, 0) for url in seed_urls]
        
        while queue:
            url, depth = queue.pop(0)
            
            if url in visited or depth > max_depth:
                continue
            
            visited.add(url)
            
            try:
                service = await self._analyze_hidden_service(url, timeout)
                if service:
                    discovered.append(service)
                    self.services[service.service_id] = service
                    
                    # Extract links for further crawling
                    if depth < max_depth:
                        links = await self._extract_onion_links(url, timeout)
                        for link in links:
                            if link not in visited:
                                queue.append((link, depth + 1))
            
            except Exception as e:
                self.logger.warning(f"Error analyzing {url}: {e}")
        
        self._save_services(discovered)
        return discovered
    
    async def _analyze_hidden_service(
        self,
        url: str,
        timeout: int
    ) -> Optional[HiddenService]:
        """Analyze a hidden service and extract metadata."""
        try:
            service_id = hashlib.sha256(url.encode()).hexdigest()[:16]
            
            # Parse onion address
            parsed = urlparse(url)
            onion_address = parsed.netloc
            
            # Determine network type
            network_type = NetworkType.TOR
            if ".i2p" in url:
                network_type = NetworkType.I2P
            
            # Try to fetch the hidden service using Tor proxy
            title = f"Service at {onion_address[:16]}..."
            description = "Hidden service discovered during crawl"
            content = ""
            is_active = False
            
            try:
                import aiohttp
                import aiohttp_socks
                
                # Check for Tor SOCKS proxy
                tor_proxy = "socks5://127.0.0.1:9050"
                
                connector = aiohttp_socks.ProxyConnector.from_url(tor_proxy)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False
                    ) as response:
                        if response.status == 200:
                            content = await response.text()
                            is_active = True
                            
                            # Extract title
                            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.I)
                            if title_match:
                                title = title_match.group(1).strip()[:200]
                            
                            # Extract description
                            desc_match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']+)["\']', content, re.I)
                            if desc_match:
                                description = desc_match.group(1).strip()[:500]
                                
            except ImportError:
                # aiohttp_socks not available, try stem/torpy
                try:
                    from stem import Signal
                    from stem.control import Controller
                    import requests
                    
                    # Request new Tor circuit
                    with Controller.from_port(port=9051) as controller:
                        controller.authenticate()
                        controller.signal(Signal.NEWNYM)
                    
                    # Make request through Tor
                    session = requests.Session()
                    session.proxies = {
                        'http': 'socks5h://127.0.0.1:9050',
                        'https': 'socks5h://127.0.0.1:9050'
                    }
                    
                    response = session.get(url, timeout=timeout, verify=False)
                    if response.status_code == 200:
                        content = response.text
                        is_active = True
                        
                        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.I)
                        if title_match:
                            title = title_match.group(1).strip()[:200]
                            
                except ImportError:
                    self.logger.warning("Neither aiohttp_socks nor stem available for Tor requests")
                except Exception as e:
                    self.logger.debug(f"Tor request failed: {e}")
            except Exception as e:
                self.logger.debug(f"Hidden service request failed: {e}")
            
            # Classify service type (based on URL or content if available)
            service_type = await self._classify_service(url, content)
            
            # Determine threat level
            threat_level = self._assess_threat_level(service_type)
            
            # Extract categories
            categories = self._extract_threat_categories(service_type)
            
            # Extract keywords from content if available
            keywords = []
            if content:
                # Extract common threat keywords
                threat_keywords = [
                    'ransomware', 'leak', 'breach', 'dump', 'credit card', 'cvv',
                    'exploit', 'zero-day', '0day', 'malware', 'botnet', 'ddos',
                    'credential', 'password', 'database', 'hacked', 'stolen'
                ]
                keywords = [kw for kw in threat_keywords if kw.lower() in content.lower()]
            
            service = HiddenService(
                service_id=service_id,
                onion_address=onion_address,
                network_type=network_type,
                service_type=service_type,
                title=title,
                description=description,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                is_active=is_active,
                threat_level=threat_level,
                categories=categories,
                languages=["en"],
                keywords=keywords,
                metadata={"discovery_url": url, "content_length": len(content)}
            )
            
            return service
            
        except Exception as e:
            self.logger.error(f"Error analyzing hidden service: {e}")
            return None
    
    async def _classify_service(self, url: str, content: str = "") -> HiddenServiceType:
        """Classify the type of hidden service based on URL and content analysis."""
        url_lower = url.lower()
        content_lower = content.lower() if content else ""
        text_to_analyze = url_lower + " " + content_lower
        
        # Check for ransomware indicators
        for group, data in self.ransomware_groups.items():
            for pattern in data.get("onion_patterns", []):
                if re.search(pattern, url_lower):
                    return HiddenServiceType.RANSOMWARE_PORTAL
        
        # Content-based ransomware detection
        ransomware_indicators = ['decrypt', 'ransom', 'bitcoin payment', 'your files', 'encrypted', 'timer']
        if sum(1 for ind in ransomware_indicators if ind in content_lower) >= 3:
            return HiddenServiceType.RANSOMWARE_PORTAL
        
        # Keyword-based classification with scoring
        classifications = {
            HiddenServiceType.MARKETPLACE: ["market", "shop", "store", "vendor", "listing", "buy", "sell"],
            HiddenServiceType.FORUM: ["forum", "board", "community", "discuss", "thread", "post", "member"],
            HiddenServiceType.PASTE_SITE: ["paste", "bin", "text", "raw", "expire"],
            HiddenServiceType.LEAK_SITE: ["leak", "dump", "breach", "data", "exposed", "stolen data"],
            HiddenServiceType.CARDING_SITE: ["card", "cvv", "fullz", "cc", "bins", "track1", "track2"],
            HiddenServiceType.CREDENTIAL_SHOP: ["account", "login", "access", "combo", "netflix", "spotify"],
            HiddenServiceType.EXPLOIT_MARKET: ["exploit", "0day", "vuln", "poc", "payload", "shellcode"],
            HiddenServiceType.MALWARE_SHOP: ["malware", "rat", "stealer", "crypter", "fud", "loader", "botnet"]
        }
        
        best_match = HiddenServiceType.UNKNOWN
        best_score = 0
        
        for service_type, keywords in classifications.items():
            score = sum(1 for kw in keywords if kw in text_to_analyze)
            if score > best_score:
                best_score = score
                best_match = service_type
        
        return best_match if best_score >= 2 else HiddenServiceType.UNKNOWN
    
    def _assess_threat_level(self, service_type: HiddenServiceType) -> AlertSeverity:
        """Assess threat level based on service type."""
        critical_types = {
            HiddenServiceType.RANSOMWARE_PORTAL,
            HiddenServiceType.EXPLOIT_MARKET,
            HiddenServiceType.BOTNET_PANEL
        }
        
        high_types = {
            HiddenServiceType.LEAK_SITE,
            HiddenServiceType.MALWARE_SHOP,
            HiddenServiceType.CREDENTIAL_SHOP,
            HiddenServiceType.DATA_BROKER
        }
        
        medium_types = {
            HiddenServiceType.MARKETPLACE,
            HiddenServiceType.CARDING_SITE,
            HiddenServiceType.HACKING_SERVICE
        }
        
        if service_type in critical_types:
            return AlertSeverity.CRITICAL
        elif service_type in high_types:
            return AlertSeverity.HIGH
        elif service_type in medium_types:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    def _extract_threat_categories(
        self,
        service_type: HiddenServiceType
    ) -> List[ThreatCategory]:
        """Extract threat categories from service type."""
        category_map = {
            HiddenServiceType.RANSOMWARE_PORTAL: [ThreatCategory.RANSOMWARE],
            HiddenServiceType.LEAK_SITE: [
                ThreatCategory.DATA_BREACH,
                ThreatCategory.CREDENTIAL_LEAK
            ],
            HiddenServiceType.MALWARE_SHOP: [ThreatCategory.MALWARE_SALE],
            HiddenServiceType.EXPLOIT_MARKET: [
                ThreatCategory.EXPLOIT_SALE,
                ThreatCategory.ZERO_DAY
            ],
            HiddenServiceType.CREDENTIAL_SHOP: [ThreatCategory.CREDENTIAL_LEAK],
            HiddenServiceType.MARKETPLACE: [
                ThreatCategory.MALWARE_SALE,
                ThreatCategory.EXPLOIT_SALE
            ]
        }
        
        return category_map.get(service_type, [])
    
    async def _extract_onion_links(self, url: str, timeout: int) -> List[str]:
        """Extract onion links from a page."""
        # Pattern for onion addresses
        onion_pattern = r'[a-z2-7]{16,56}\.onion'
        
        # In production, would fetch page content via Tor
        # Returning empty for simulation
        return []
    
    async def monitor_for_organization(
        self,
        organization: str,
        domains: List[str],
        email_patterns: List[str],
        executives: List[str],
        keywords: List[str]
    ) -> List[DarkWebAlert]:
        """
        Monitor dark web for mentions of an organization.
        
        Args:
            organization: Organization name
            domains: Domains associated with the organization
            email_patterns: Email patterns to monitor
            executives: Executive names to monitor
            keywords: Additional keywords to monitor
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        # Create comprehensive monitoring rules
        rule = MonitoringRule(
            rule_id=hashlib.sha256(organization.encode()).hexdigest()[:16],
            name=f"Monitor {organization}",
            description=f"Comprehensive monitoring for {organization}",
            keywords=[organization] + keywords,
            regex_patterns=[rf"\b{re.escape(org)}\b" for org in [organization]],
            domains_of_interest=domains,
            email_patterns=email_patterns,
            threat_categories=[
                ThreatCategory.DATA_BREACH,
                ThreatCategory.CREDENTIAL_LEAK,
                ThreatCategory.BRAND_ABUSE,
                ThreatCategory.EXECUTIVE_THREAT,
                ThreatCategory.RANSOMWARE
            ],
            severity_override=None,
            is_active=True,
            created_at=datetime.now(),
            last_triggered=None
        )
        
        self.rules[rule.rule_id] = rule
        
        # Scan known services for matches
        for service_id, service in self.services.items():
            mentions = await self._scan_service_for_matches(service, rule)
            
            for mention in mentions:
                alert = self._create_alert_from_mention(mention, rule)
                alerts.append(alert)
                self.alerts.append(alert)
        
        # Check credential databases
        credential_alerts = await self._check_credential_leaks(domains, email_patterns)
        alerts.extend(credential_alerts)
        
        # Check for executive threats
        executive_alerts = await self._check_executive_threats(executives, organization)
        alerts.extend(executive_alerts)
        
        self._save_alerts(alerts)
        return alerts
    
    async def _scan_service_for_matches(
        self,
        service: HiddenService,
        rule: MonitoringRule
    ) -> List[DarkWebMention]:
        """Scan a hidden service for rule matches."""
        mentions = []
        
        # Simulated content scanning
        # In production, would fetch and analyze actual content
        
        for keyword in rule.keywords:
            if keyword.lower() in service.title.lower():
                mention = DarkWebMention(
                    mention_id=hashlib.sha256(
                        f"{service.service_id}{keyword}".encode()
                    ).hexdigest()[:16],
                    source_service=service.service_id,
                    source_url=f"http://{service.onion_address}",
                    mention_type=ThreatCategory.BRAND_ABUSE,
                    matched_keywords=[keyword],
                    content_snippet=service.title,
                    full_content_hash=hashlib.sha256(
                        service.title.encode()
                    ).hexdigest(),
                    timestamp=datetime.now(),
                    severity=AlertSeverity.MEDIUM,
                    confidence=0.7
                )
                mentions.append(mention)
                self.mentions[mention.mention_id] = mention
        
        return mentions
    
    async def _check_credential_leaks(
        self,
        domains: List[str],
        email_patterns: List[str]
    ) -> List[DarkWebAlert]:
        """Check for credential leaks affecting specified domains."""
        alerts = []
        
        # Search credential database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for domain in domains:
            cursor.execute(
                "SELECT * FROM credentials WHERE domain = ?",
                (domain,)
            )
            
            rows = cursor.fetchall()
            
            if rows:
                alert = DarkWebAlert(
                    alert_id=hashlib.sha256(
                        f"credential_{domain}_{datetime.now().isoformat()}".encode()
                    ).hexdigest()[:16],
                    alert_type=ThreatCategory.CREDENTIAL_LEAK,
                    severity=AlertSeverity.HIGH,
                    title=f"Credential Leak Detected for {domain}",
                    description=f"Found {len(rows)} leaked credentials for domain {domain}",
                    source="Credential Database",
                    source_url="internal://credential_db",
                    created_at=datetime.now(),
                    matched_rules=[f"domain:{domain}"],
                    affected_assets=[domain],
                    recommended_actions=[
                        "Force password reset for affected accounts",
                        "Enable MFA for all accounts",
                        "Monitor for unauthorized access",
                        "Review authentication logs"
                    ]
                )
                alerts.append(alert)
        
        conn.close()
        return alerts
    
    async def _check_executive_threats(
        self,
        executives: List[str],
        organization: str
    ) -> List[DarkWebAlert]:
        """Check for threats targeting executives."""
        alerts = []
        
        # Threat patterns to look for
        threat_patterns = [
            "dox", "personal info", "home address",
            "phone number", "social security", "impersonation"
        ]
        
        for executive in executives:
            # Check for executive mentions in threat contexts
            for pattern in threat_patterns:
                # Simulated search - in production would search actual data
                if len(executive) > 5:  # Simulate finding threats
                    alert = DarkWebAlert(
                        alert_id=hashlib.sha256(
                            f"exec_{executive}_{pattern}".encode()
                        ).hexdigest()[:16],
                        alert_type=ThreatCategory.EXECUTIVE_THREAT,
                        severity=AlertSeverity.HIGH,
                        title=f"Potential Executive Threat: {executive}",
                        description=f"Monitoring for threats targeting {executive}",
                        source="Executive Monitoring",
                        source_url="internal://exec_monitor",
                        created_at=datetime.now(),
                        matched_rules=[f"executive:{executive}"],
                        affected_assets=[executive, organization],
                        recommended_actions=[
                            "Alert executive security team",
                            "Review executive's public exposure",
                            "Enable enhanced security measures",
                            "Monitor for impersonation attempts"
                        ]
                    )
                    # Only add one alert per executive
                    alerts.append(alert)
                    break
        
        return alerts
    
    def _create_alert_from_mention(
        self,
        mention: DarkWebMention,
        rule: MonitoringRule
    ) -> DarkWebAlert:
        """Create an alert from a dark web mention."""
        return DarkWebAlert(
            alert_id=hashlib.sha256(
                f"alert_{mention.mention_id}".encode()
            ).hexdigest()[:16],
            alert_type=mention.mention_type,
            severity=rule.severity_override or mention.severity,
            title=f"Dark Web Mention: {', '.join(mention.matched_keywords)}",
            description=f"Found mention matching keywords in {mention.source_service}",
            source=mention.source_service,
            source_url=mention.source_url,
            created_at=datetime.now(),
            matched_rules=[rule.rule_id],
            affected_assets=mention.matched_keywords,
            recommended_actions=self._get_recommended_actions(mention.mention_type),
            related_iocs=mention.iocs,
            related_actors=mention.actors
        )
    
    def _get_recommended_actions(
        self,
        threat_type: ThreatCategory
    ) -> List[str]:
        """Get recommended actions for a threat type."""
        actions = {
            ThreatCategory.DATA_BREACH: [
                "Identify affected data and individuals",
                "Prepare breach notification",
                "Engage incident response team",
                "Preserve evidence for forensics"
            ],
            ThreatCategory.CREDENTIAL_LEAK: [
                "Force password resets for affected accounts",
                "Enable multi-factor authentication",
                "Monitor for unauthorized access",
                "Review authentication logs"
            ],
            ThreatCategory.RANSOMWARE: [
                "Isolate potentially affected systems",
                "Review backup integrity",
                "Engage incident response",
                "Notify law enforcement if appropriate"
            ],
            ThreatCategory.BRAND_ABUSE: [
                "Document the abuse",
                "Prepare takedown request",
                "Monitor for customer impact",
                "Update fraud detection rules"
            ],
            ThreatCategory.EXECUTIVE_THREAT: [
                "Alert executive security team",
                "Increase physical security measures",
                "Monitor for impersonation",
                "Review digital footprint"
            ]
        }
        
        return actions.get(threat_type, [
            "Investigate the alert",
            "Document findings",
            "Escalate if necessary"
        ])
    
    async def track_threat_actor(
        self,
        actor_identifier: str,
        include_aliases: bool = True
    ) -> Optional[ThreatActor]:
        """
        Track a threat actor across dark web sources.
        
        Args:
            actor_identifier: Actor name or alias
            include_aliases: Whether to track aliases
            
        Returns:
            Threat actor profile if found
        """
        # Check existing actors
        for actor_id, actor in self.actors.items():
            if actor_identifier.lower() in [a.lower() for a in actor.aliases]:
                return actor
        
        # Search for actor mentions
        actor_data = await self._gather_actor_intelligence(actor_identifier)
        
        if actor_data:
            actor = ThreatActor(
                actor_id=hashlib.sha256(actor_identifier.encode()).hexdigest()[:16],
                aliases=actor_data.get("aliases", [actor_identifier]),
                first_seen=actor_data.get("first_seen", datetime.now()),
                last_active=datetime.now(),
                reputation_score=actor_data.get("reputation", 0.0),
                verified=actor_data.get("verified", False),
                services_active=actor_data.get("services", []),
                specializations=actor_data.get("specializations", []),
                languages=actor_data.get("languages", ["en"]),
                communication_channels=actor_data.get("channels", []),
                known_campaigns=actor_data.get("campaigns", []),
                ttps=actor_data.get("ttps", [])
            )
            
            self.actors[actor.actor_id] = actor
            self._save_actor(actor)
            
            return actor
        
        return None
    
    async def _gather_actor_intelligence(
        self,
        actor_identifier: str
    ) -> Optional[Dict[str, Any]]:
        """Gather intelligence on a threat actor."""
        # Check against known APT groups
        for apt_name, apt_data in self.apt_groups.items():
            if (actor_identifier.lower() == apt_name.lower() or
                actor_identifier.lower() in [a.lower() for a in apt_data["aliases"]]):
                return {
                    "aliases": [apt_name] + apt_data["aliases"],
                    "first_seen": datetime.now() - timedelta(days=365*3),
                    "reputation": 9.5,
                    "verified": True,
                    "services": [],
                    "specializations": [ThreatCategory.APT_ACTIVITY],
                    "languages": ["en", "ru", "zh", "ko", "fa"],
                    "channels": ["tor", "telegram"],
                    "campaigns": apt_data.get("campaigns", []),
                    "ttps": apt_data.get("indicators", [])
                }
        
        # Check against ransomware groups
        for group_name, group_data in self.ransomware_groups.items():
            if (actor_identifier.lower() == group_name.lower() or
                actor_identifier.lower() in [a.lower() for a in group_data["aliases"]]):
                return {
                    "aliases": [group_name] + group_data["aliases"],
                    "first_seen": datetime.now() - timedelta(days=365),
                    "reputation": 8.5,
                    "verified": True,
                    "services": [],
                    "specializations": [ThreatCategory.RANSOMWARE],
                    "languages": ["en", "ru"],
                    "channels": ["tor"],
                    "campaigns": [],
                    "ttps": group_data.get("ttps", [])
                }
        
        return None
    
    async def analyze_ransomware_leak(
        self,
        victim_organization: str,
        leak_url: str
    ) -> Optional[DataLeak]:
        """
        Analyze a ransomware leak announcement.
        
        Args:
            victim_organization: Name of the victim
            leak_url: URL of the leak announcement
            
        Returns:
            Data leak record if analyzed successfully
        """
        leak_id = hashlib.sha256(
            f"{victim_organization}{leak_url}".encode()
        ).hexdigest()[:16]
        
        # Analyze the leak
        leak = DataLeak(
            leak_id=leak_id,
            source_service=urlparse(leak_url).netloc,
            victim_organization=victim_organization,
            leak_type=ThreatCategory.RANSOMWARE,
            announced_date=datetime.now(),
            data_volume="Unknown",
            record_count=None,
            data_categories=[
                "corporate_data",
                "employee_data",
                "financial_data"
            ],
            sample_available=False,
            price=None,
            seller_actor=None,
            verification_status="unverified",
            relevance_score=0.8
        )
        
        # Identify ransomware group
        for group_name, group_data in self.ransomware_groups.items():
            for pattern in group_data.get("onion_patterns", []):
                if re.search(pattern, leak_url.lower()):
                    leak.seller_actor = group_name
                    leak.metadata["ransomware_group"] = group_name
                    leak.metadata["group_aliases"] = group_data["aliases"]
                    break
        
        self.leaks[leak_id] = leak
        self._save_leak(leak)
        
        # Generate alert
        alert = DarkWebAlert(
            alert_id=hashlib.sha256(f"leak_alert_{leak_id}".encode()).hexdigest()[:16],
            alert_type=ThreatCategory.RANSOMWARE,
            severity=AlertSeverity.CRITICAL,
            title=f"Ransomware Leak: {victim_organization}",
            description=f"Ransomware group announced data leak for {victim_organization}",
            source=leak.source_service,
            source_url=leak_url,
            created_at=datetime.now(),
            matched_rules=["ransomware_monitoring"],
            affected_assets=[victim_organization],
            recommended_actions=[
                "Verify if organization is in your supply chain",
                "Check for shared data exposure",
                "Monitor for related attacks",
                "Review third-party risk assessments"
            ],
            related_actors=[leak.seller_actor] if leak.seller_actor else []
        )
        
        self.alerts.append(alert)
        
        return leak
    
    async def search_credential_leaks(
        self,
        email: Optional[str] = None,
        domain: Optional[str] = None,
        limit: int = 100
    ) -> List[LeakedCredential]:
        """
        Search for leaked credentials.
        
        Args:
            email: Specific email to search
            domain: Domain to search
            limit: Maximum results to return
            
        Returns:
            List of matching leaked credentials
        """
        results = []
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if email:
            cursor.execute(
                "SELECT * FROM credentials WHERE email = ? LIMIT ?",
                (email, limit)
            )
        elif domain:
            cursor.execute(
                "SELECT * FROM credentials WHERE domain = ? LIMIT ?",
                (domain, limit)
            )
        else:
            cursor.execute(
                "SELECT * FROM credentials LIMIT ?",
                (limit,)
            )
        
        rows = cursor.fetchall()
        conn.close()
        
        for row in rows:
            cred = LeakedCredential(
                credential_id=row[0],
                source=row[1],
                breach_name=row[2],
                email=row[3],
                domain=row[4],
                password_hash=row[5],
                password_type=row[6],
                discovered_date=datetime.fromisoformat(row[7]) if row[7] else datetime.now(),
                breach_date=datetime.fromisoformat(row[8]) if row[8] else None,
                is_corporate=bool(row[9]),
                risk_score=row[10]
            )
            results.append(cred)
            self.credentials[cred.credential_id] = cred
        
        return results
    
    async def import_credentials(
        self,
        source: str,
        breach_name: str,
        credentials: List[Dict[str, str]]
    ) -> int:
        """
        Import leaked credentials into the database.
        
        Args:
            source: Source of the leak
            breach_name: Name of the breach
            credentials: List of credential dictionaries
            
        Returns:
            Number of credentials imported
        """
        imported = 0
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for cred in credentials:
            email = cred.get("email", "")
            domain = email.split("@")[1] if "@" in email else ""
            
            cred_id = hashlib.sha256(
                f"{source}{breach_name}{email}".encode()
            ).hexdigest()[:16]
            
            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO credentials
                    (credential_id, source, breach_name, email, domain,
                     password_hash, password_type, discovered_date, 
                     is_corporate, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cred_id,
                    source,
                    breach_name,
                    email,
                    domain,
                    cred.get("password_hash"),
                    cred.get("password_type", "unknown"),
                    datetime.now().isoformat(),
                    self._is_corporate_domain(domain),
                    self._calculate_credential_risk(cred)
                ))
                imported += 1
            except Exception as e:
                self.logger.error(f"Error importing credential: {e}")
        
        conn.commit()
        conn.close()
        
        return imported
    
    def _is_corporate_domain(self, domain: str) -> bool:
        """Check if domain is likely corporate (not freemail)."""
        freemail_providers = {
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "aol.com", "icloud.com", "protonmail.com", "mail.com"
        }
        return domain.lower() not in freemail_providers
    
    def _calculate_credential_risk(self, cred: Dict[str, str]) -> float:
        """Calculate risk score for a credential."""
        risk = 0.5
        
        # Higher risk for corporate domains
        email = cred.get("email", "")
        if "@" in email:
            domain = email.split("@")[1]
            if self._is_corporate_domain(domain):
                risk += 0.2
        
        # Higher risk if password is plaintext
        if cred.get("password_type") == "plaintext":
            risk += 0.2
        
        # Higher risk for recent breaches
        if cred.get("breach_date"):
            try:
                breach_date = datetime.fromisoformat(cred["breach_date"])
                if (datetime.now() - breach_date).days < 30:
                    risk += 0.1
            except Exception:
                pass
        
        return min(risk, 1.0)
    
    def _save_services(self, services: List[HiddenService]) -> None:
        """Save hidden services to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for service in services:
            cursor.execute("""
                INSERT OR REPLACE INTO hidden_services
                (service_id, onion_address, network_type, service_type,
                 title, description, first_seen, last_seen, is_active,
                 threat_level, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                service.service_id,
                service.onion_address,
                service.network_type.name,
                service.service_type.name,
                service.title,
                service.description,
                service.first_seen.isoformat(),
                service.last_seen.isoformat(),
                1 if service.is_active else 0,
                service.threat_level.name,
                json.dumps(service.metadata)
            ))
        
        conn.commit()
        conn.close()
    
    def _save_alerts(self, alerts: List[DarkWebAlert]) -> None:
        """Save alerts to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for alert in alerts:
            cursor.execute("""
                INSERT OR REPLACE INTO alerts
                (alert_id, alert_type, severity, title, description,
                 source, source_url, created_at, matched_rules,
                 affected_assets, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id,
                alert.alert_type.name,
                alert.severity.name,
                alert.title,
                alert.description,
                alert.source,
                alert.source_url,
                alert.created_at.isoformat(),
                json.dumps(alert.matched_rules),
                json.dumps(alert.affected_assets),
                json.dumps(alert.metadata)
            ))
        
        conn.commit()
        conn.close()
    
    def _save_actor(self, actor: ThreatActor) -> None:
        """Save threat actor to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO threat_actors
            (actor_id, aliases, first_seen, last_active, reputation_score,
             verified, services_active, specializations, languages, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            actor.actor_id,
            json.dumps(actor.aliases),
            actor.first_seen.isoformat(),
            actor.last_active.isoformat(),
            actor.reputation_score,
            1 if actor.verified else 0,
            json.dumps(actor.services_active),
            json.dumps([s.name for s in actor.specializations]),
            json.dumps(actor.languages),
            json.dumps(actor.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def _save_leak(self, leak: DataLeak) -> None:
        """Save data leak to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO data_leaks
            (leak_id, source_service, victim_organization, leak_type,
             announced_date, data_volume, record_count, data_categories,
             sample_available, price, seller_actor, verification_status,
             relevance_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            leak.leak_id,
            leak.source_service,
            leak.victim_organization,
            leak.leak_type.name,
            leak.announced_date.isoformat(),
            leak.data_volume,
            leak.record_count,
            json.dumps(leak.data_categories),
            1 if leak.sample_available else 0,
            leak.price,
            leak.seller_actor,
            leak.verification_status,
            leak.relevance_score
        ))
        
        conn.commit()
        conn.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get dark web intelligence statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM hidden_services")
        service_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM credentials")
        credential_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM data_leaks")
        leak_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM threat_actors")
        actor_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alert_count = cursor.fetchone()[0]
        
        cursor.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'"
        )
        critical_alerts = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "hidden_services": service_count,
            "leaked_credentials": credential_count,
            "data_leaks": leak_count,
            "threat_actors": actor_count,
            "total_alerts": alert_count,
            "critical_alerts": critical_alerts,
            "active_rules": len([r for r in self.rules.values() if r.is_active]),
            "monitored_networks": [n.name for n in NetworkType],
            "ransomware_groups_tracked": len(self.ransomware_groups),
            "apt_groups_tracked": len(self.apt_groups)
        }
    
    def register_callback(
        self,
        event_type: str,
        callback: Callable
    ) -> None:
        """Register callback for dark web events."""
        if event_type not in self.callbacks:
            self.callbacks[event_type] = []
        self.callbacks[event_type].append(callback)
    
    async def emit_event(self, event_type: str, data: Any) -> None:
        """Emit event to registered callbacks."""
        if event_type in self.callbacks:
            for callback in self.callbacks[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    self.logger.error(f"Error in callback: {e}")
