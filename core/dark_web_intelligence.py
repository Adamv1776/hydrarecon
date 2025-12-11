"""
HydraRecon Dark Web Intelligence Module
Deep web and dark web monitoring and analysis
"""

import asyncio
import hashlib
import json
import time
import threading
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import base64


class DarkWebSource(Enum):
    """Dark web source types"""
    TOR_FORUM = "tor_forum"
    TOR_MARKETPLACE = "tor_marketplace"
    TOR_PASTE = "tor_paste"
    I2P_SITE = "i2p_site"
    TELEGRAM = "telegram"
    DISCORD = "discord"
    IRC = "irc"
    JABBER = "jabber"
    DUMP_SITE = "dump_site"
    LEAK_SITE = "leak_site"
    RANSOMWARE_SITE = "ransomware_site"


class ThreatCategory(Enum):
    """Threat categories"""
    CREDENTIAL_LEAK = "credential_leak"
    DATA_BREACH = "data_breach"
    RANSOMWARE = "ransomware"
    MALWARE_SALE = "malware_sale"
    EXPLOIT_SALE = "exploit_sale"
    ACCESS_SALE = "access_sale"
    DDoS_SERVICE = "ddos_service"
    FRAUD = "fraud"
    CARDING = "carding"
    IDENTITY_THEFT = "identity_theft"
    CORPORATE_INTEL = "corporate_intel"
    THREAT_ACTOR = "threat_actor"
    VULNERABILITY_DISCLOSURE = "vuln_disclosure"


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = ("critical", "#dc3545", 10)
    HIGH = ("high", "#fd7e14", 7)
    MEDIUM = ("medium", "#ffc107", 4)
    LOW = ("low", "#17a2b8", 1)
    INFO = ("info", "#6c757d", 0)
    
    @property
    def name_str(self) -> str:
        return self.value[0]
    
    @property
    def color(self) -> str:
        return self.value[1]
    
    @property
    def score(self) -> int:
        return self.value[2]


@dataclass
class DarkWebMention:
    """Mention found on dark web"""
    mention_id: str
    source: DarkWebSource
    source_name: str
    source_url: str
    category: ThreatCategory
    severity: AlertSeverity
    title: str
    content: str
    matched_keywords: List[str]
    discovered_at: datetime
    author: Optional[str] = None
    thread_id: Optional[str] = None
    post_date: Optional[datetime] = None
    attachments: List[Dict] = field(default_factory=list)
    related_mentions: List[str] = field(default_factory=list)
    is_verified: bool = False
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'mention_id': self.mention_id,
            'source': self.source.value,
            'source_name': self.source_name,
            'source_url': self.source_url,
            'category': self.category.value,
            'severity': self.severity.name_str,
            'title': self.title,
            'content': self.content[:500] + '...' if len(self.content) > 500 else self.content,
            'matched_keywords': self.matched_keywords,
            'discovered_at': self.discovered_at.isoformat(),
            'author': self.author,
            'post_date': self.post_date.isoformat() if self.post_date else None,
            'is_verified': self.is_verified,
            'metadata': self.metadata
        }


@dataclass
class CredentialLeak:
    """Leaked credential information"""
    leak_id: str
    email: str
    password_hash: Optional[str] = None
    password_plain: Optional[str] = None
    source: str = ""
    breach_name: str = ""
    breach_date: Optional[datetime] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    domain: str = ""
    additional_data: Dict = field(default_factory=dict)
    is_verified: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'leak_id': self.leak_id,
            'email': self.email,
            'has_password': self.password_plain is not None or self.password_hash is not None,
            'source': self.source,
            'breach_name': self.breach_name,
            'breach_date': self.breach_date.isoformat() if self.breach_date else None,
            'discovered_at': self.discovered_at.isoformat(),
            'domain': self.domain,
            'is_verified': self.is_verified
        }


@dataclass
class ThreatActor:
    """Threat actor profile"""
    actor_id: str
    handle: str
    aliases: List[str]
    platforms: List[DarkWebSource]
    first_seen: datetime
    last_seen: datetime
    reputation_score: int
    activity_count: int
    categories: List[ThreatCategory]
    known_targets: List[str]
    language: str
    timezone_estimate: Optional[str] = None
    contact_methods: List[str] = field(default_factory=list)
    pgp_fingerprint: Optional[str] = None
    bitcoin_addresses: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'actor_id': self.actor_id,
            'handle': self.handle,
            'aliases': self.aliases,
            'platforms': [p.value for p in self.platforms],
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'reputation_score': self.reputation_score,
            'activity_count': self.activity_count,
            'categories': [c.value for c in self.categories],
            'known_targets': self.known_targets,
            'language': self.language,
            'timezone_estimate': self.timezone_estimate,
            'contact_methods': self.contact_methods,
            'bitcoin_addresses': self.bitcoin_addresses
        }


@dataclass
class RansomwareVictim:
    """Ransomware victim listing"""
    victim_id: str
    ransomware_group: str
    victim_name: str
    victim_domain: Optional[str]
    industry: str
    country: str
    announced_date: datetime
    deadline: Optional[datetime]
    data_size: Optional[str]
    sample_files: List[str]
    ransom_amount: Optional[str]
    payment_status: str  # unpaid, paid, negotiating, data_leaked
    leak_url: Optional[str]
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            'victim_id': self.victim_id,
            'ransomware_group': self.ransomware_group,
            'victim_name': self.victim_name,
            'victim_domain': self.victim_domain,
            'industry': self.industry,
            'country': self.country,
            'announced_date': self.announced_date.isoformat(),
            'deadline': self.deadline.isoformat() if self.deadline else None,
            'data_size': self.data_size,
            'payment_status': self.payment_status,
            'discovered_at': self.discovered_at.isoformat()
        }


class DarkWebCrawler:
    """Dark web crawler for onion sites"""
    
    def __init__(self, tor_proxy: str = "socks5h://127.0.0.1:9050"):
        self.tor_proxy = tor_proxy
        self.crawled_pages: Set[str] = set()
        self.discovered_onions: Set[str] = set()
        
    async def crawl_onion(self, onion_url: str, depth: int = 2) -> Dict:
        """Crawl an onion site"""
        results = {
            'url': onion_url,
            'pages_crawled': 0,
            'content': [],
            'links_found': [],
            'onions_discovered': []
        }
        
        # Simulate crawling (in production, would use Tor)
        await self._simulate_crawl(onion_url, depth, results)
        
        return results
    
    async def _simulate_crawl(self, url: str, depth: int, results: Dict):
        """Simulate crawling for demonstration"""
        if depth <= 0 or url in self.crawled_pages:
            return
        
        self.crawled_pages.add(url)
        results['pages_crawled'] += 1
        
        # Simulate finding content
        results['content'].append({
            'url': url,
            'title': f"Page at {url[:50]}",
            'text_sample': "Sample content from dark web page...",
            'crawled_at': datetime.now().isoformat()
        })
        
        # Simulate finding new onion links
        for i in range(2):
            fake_onion = hashlib.sha256(f"{url}{i}".encode()).hexdigest()[:16] + ".onion"
            if fake_onion not in self.discovered_onions:
                self.discovered_onions.add(fake_onion)
                results['onions_discovered'].append(f"http://{fake_onion}")
    
    def extract_onion_links(self, content: str) -> List[str]:
        """Extract .onion links from content"""
        onion_pattern = r'(?:https?://)?([a-z2-7]{16,56}\.onion)(?:/[^\s]*)?'
        matches = re.findall(onion_pattern, content, re.IGNORECASE)
        return list(set(matches))
    
    def extract_bitcoin_addresses(self, content: str) -> List[str]:
        """Extract Bitcoin addresses from content"""
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-zA-HJ-NP-Z0-9]{39,59}\b'
        matches = re.findall(btc_pattern, content)
        return list(set(matches))
    
    def extract_emails(self, content: str) -> List[str]:
        """Extract email addresses from content"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        matches = re.findall(email_pattern, content)
        return list(set(matches))


class PasteMonitor:
    """Monitor paste sites for leaks"""
    
    def __init__(self):
        self.paste_sites = [
            'pastebin.com', 'ghostbin.com', 'paste.ee',
            'dpaste.org', 'hastebin.com', 'privatebin.net'
        ]
        self.monitored_keywords: Set[str] = set()
        
    async def monitor_pastes(self, keywords: List[str]) -> List[Dict]:
        """Monitor paste sites for keywords"""
        findings = []
        
        for keyword in keywords:
            self.monitored_keywords.add(keyword.lower())
        
        # Simulate finding pastes
        for i in range(3):
            finding = {
                'paste_id': hashlib.sha256(f"paste-{i}-{time.time()}".encode()).hexdigest()[:16],
                'site': self.paste_sites[i % len(self.paste_sites)],
                'title': f"Possible data leak containing keywords",
                'matched_keywords': list(keywords)[:2],
                'snippet': f"...found keyword {keywords[0] if keywords else 'data'}...",
                'discovered_at': datetime.now().isoformat(),
                'raw_size': f"{1000 * (i + 1)} bytes"
            }
            findings.append(finding)
        
        return findings
    
    async def search_paste_archives(self, query: str, 
                                   date_range: Tuple[datetime, datetime] = None) -> List[Dict]:
        """Search paste archives"""
        results = []
        
        # Simulate archive search
        for i in range(5):
            results.append({
                'paste_id': hashlib.sha256(f"archive-{query}-{i}".encode()).hexdigest()[:16],
                'site': self.paste_sites[i % len(self.paste_sites)],
                'date': (datetime.now() - timedelta(days=i * 30)).isoformat(),
                'title': f"Archive result {i + 1}",
                'relevance_score': 0.9 - (i * 0.1)
            })
        
        return results


class BreachDatabase:
    """Database for tracking data breaches"""
    
    def __init__(self):
        self.breaches: Dict[str, Dict] = {}
        self.credentials: Dict[str, List[CredentialLeak]] = defaultdict(list)
        
        # Load known breaches
        self._load_known_breaches()
    
    def _load_known_breaches(self):
        """Load known data breaches"""
        known_breaches = [
            {
                'name': 'Collection #1',
                'date': '2019-01',
                'records': 773000000,
                'data_types': ['email', 'password']
            },
            {
                'name': 'LinkedIn 2021',
                'date': '2021-06',
                'records': 700000000,
                'data_types': ['email', 'name', 'phone', 'workplace']
            },
            {
                'name': 'Facebook 2021',
                'date': '2021-04',
                'records': 533000000,
                'data_types': ['name', 'phone', 'email', 'location']
            },
            {
                'name': 'Cit0Day',
                'date': '2020-11',
                'records': 23000000,
                'data_types': ['email', 'password']
            }
        ]
        
        for breach in known_breaches:
            breach_id = hashlib.sha256(breach['name'].encode()).hexdigest()[:16]
            self.breaches[breach_id] = breach
    
    def add_credential(self, leak: CredentialLeak):
        """Add a leaked credential"""
        domain = leak.email.split('@')[1] if '@' in leak.email else 'unknown'
        leak.domain = domain
        self.credentials[domain].append(leak)
    
    def search_by_email(self, email: str) -> List[CredentialLeak]:
        """Search for leaks by email"""
        domain = email.split('@')[1] if '@' in email else ''
        
        results = []
        for leak in self.credentials.get(domain, []):
            if leak.email.lower() == email.lower():
                results.append(leak)
        
        return results
    
    def search_by_domain(self, domain: str) -> List[CredentialLeak]:
        """Search for leaks by domain"""
        return self.credentials.get(domain, [])
    
    def get_breach_stats(self) -> Dict:
        """Get breach statistics"""
        total_credentials = sum(len(creds) for creds in self.credentials.values())
        unique_domains = len(self.credentials)
        
        return {
            'total_breaches': len(self.breaches),
            'total_credentials': total_credentials,
            'unique_domains': unique_domains,
            'breaches': list(self.breaches.values())
        }


class RansomwareTracker:
    """Track ransomware groups and victims"""
    
    def __init__(self):
        self.groups: Dict[str, Dict] = {}
        self.victims: List[RansomwareVictim] = []
        
        # Load known ransomware groups
        self._load_ransomware_groups()
    
    def _load_ransomware_groups(self):
        """Load known ransomware groups"""
        groups = [
            {
                'name': 'LockBit',
                'aliases': ['LockBit 2.0', 'LockBit 3.0'],
                'first_seen': '2019-09',
                'status': 'active',
                'leak_site': 'lockbit*.onion',
                'typical_ransom': '$50,000 - $10,000,000',
                'targets': ['enterprise', 'healthcare', 'government']
            },
            {
                'name': 'BlackCat',
                'aliases': ['ALPHV'],
                'first_seen': '2021-11',
                'status': 'active',
                'leak_site': 'alphv*.onion',
                'typical_ransom': '$100,000 - $5,000,000',
                'targets': ['enterprise', 'critical infrastructure']
            },
            {
                'name': 'Cl0p',
                'aliases': ['Clop', 'TA505'],
                'first_seen': '2019-02',
                'status': 'active',
                'leak_site': 'cl0p*.onion',
                'typical_ransom': '$500,000 - $20,000,000',
                'targets': ['enterprise', 'finance', 'healthcare']
            },
            {
                'name': 'Royal',
                'aliases': [],
                'first_seen': '2022-09',
                'status': 'active',
                'leak_site': 'royal*.onion',
                'typical_ransom': '$250,000 - $2,000,000',
                'targets': ['healthcare', 'education', 'manufacturing']
            },
            {
                'name': 'Play',
                'aliases': ['PlayCrypt'],
                'first_seen': '2022-06',
                'status': 'active',
                'leak_site': 'play*.onion',
                'typical_ransom': '$100,000 - $1,000,000',
                'targets': ['enterprise', 'government']
            }
        ]
        
        for group in groups:
            group_id = hashlib.sha256(group['name'].encode()).hexdigest()[:16]
            self.groups[group_id] = group
    
    def add_victim(self, victim: RansomwareVictim):
        """Add a ransomware victim"""
        self.victims.append(victim)
    
    def get_victims_by_group(self, group_name: str) -> List[RansomwareVictim]:
        """Get victims by ransomware group"""
        return [v for v in self.victims if v.ransomware_group.lower() == group_name.lower()]
    
    def get_recent_victims(self, days: int = 30) -> List[RansomwareVictim]:
        """Get recent ransomware victims"""
        cutoff = datetime.now() - timedelta(days=days)
        return [v for v in self.victims if v.announced_date >= cutoff]
    
    def search_victims(self, query: str) -> List[RansomwareVictim]:
        """Search victims by name or domain"""
        query_lower = query.lower()
        return [
            v for v in self.victims
            if query_lower in v.victim_name.lower() or
               (v.victim_domain and query_lower in v.victim_domain.lower())
        ]
    
    def get_statistics(self) -> Dict:
        """Get ransomware statistics"""
        by_group = defaultdict(int)
        by_industry = defaultdict(int)
        by_country = defaultdict(int)
        by_status = defaultdict(int)
        
        for victim in self.victims:
            by_group[victim.ransomware_group] += 1
            by_industry[victim.industry] += 1
            by_country[victim.country] += 1
            by_status[victim.payment_status] += 1
        
        return {
            'total_victims': len(self.victims),
            'active_groups': len(self.groups),
            'by_group': dict(by_group),
            'by_industry': dict(by_industry),
            'by_country': dict(by_country),
            'by_status': dict(by_status)
        }


class ThreatActorTracker:
    """Track threat actors across dark web"""
    
    def __init__(self):
        self.actors: Dict[str, ThreatActor] = {}
        self.actor_mentions: Dict[str, List[DarkWebMention]] = defaultdict(list)
    
    def add_actor(self, actor: ThreatActor):
        """Add or update a threat actor"""
        self.actors[actor.actor_id] = actor
    
    def add_mention(self, actor_id: str, mention: DarkWebMention):
        """Add a mention related to an actor"""
        self.actor_mentions[actor_id].append(mention)
        
        # Update last seen
        if actor_id in self.actors:
            self.actors[actor_id].last_seen = mention.discovered_at
            self.actors[actor_id].activity_count += 1
    
    def search_actors(self, query: str) -> List[ThreatActor]:
        """Search threat actors"""
        query_lower = query.lower()
        results = []
        
        for actor in self.actors.values():
            if (query_lower in actor.handle.lower() or
                any(query_lower in alias.lower() for alias in actor.aliases)):
                results.append(actor)
        
        return results
    
    def get_actor_activity(self, actor_id: str, days: int = 30) -> List[DarkWebMention]:
        """Get recent activity for an actor"""
        cutoff = datetime.now() - timedelta(days=days)
        mentions = self.actor_mentions.get(actor_id, [])
        return [m for m in mentions if m.discovered_at >= cutoff]
    
    def get_most_active_actors(self, limit: int = 10) -> List[ThreatActor]:
        """Get most active threat actors"""
        return sorted(
            self.actors.values(),
            key=lambda a: a.activity_count,
            reverse=True
        )[:limit]


class DarkWebIntelligence:
    """
    Main dark web intelligence platform
    Monitors dark web for threats and intelligence
    """
    
    def __init__(self):
        self.crawler = DarkWebCrawler()
        self.paste_monitor = PasteMonitor()
        self.breach_db = BreachDatabase()
        self.ransomware_tracker = RansomwareTracker()
        self.actor_tracker = ThreatActorTracker()
        
        self.mentions: List[DarkWebMention] = []
        self.alerts: List[Dict] = []
        self.monitored_keywords: Set[str] = set()
        self.monitored_domains: Set[str] = set()
        
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # Callbacks
        self.on_alert: Optional[callable] = None
        self.on_mention: Optional[callable] = None
    
    def add_monitored_keyword(self, keyword: str):
        """Add keyword to monitor"""
        self.monitored_keywords.add(keyword.lower())
    
    def add_monitored_domain(self, domain: str):
        """Add domain to monitor"""
        self.monitored_domains.add(domain.lower())
    
    async def scan_for_mentions(self) -> List[DarkWebMention]:
        """Scan dark web for mentions of monitored keywords"""
        new_mentions = []
        
        # Simulate finding mentions
        for keyword in list(self.monitored_keywords)[:5]:
            if hash(keyword) % 3 == 0:  # Simulate finding some mentions
                mention = DarkWebMention(
                    mention_id=hashlib.sha256(f"{keyword}-{time.time()}".encode()).hexdigest()[:16],
                    source=DarkWebSource.TOR_FORUM,
                    source_name="Underground Forum",
                    source_url=f"http://example{hashlib.sha256(keyword.encode()).hexdigest()[:8]}.onion",
                    category=ThreatCategory.CORPORATE_INTEL,
                    severity=AlertSeverity.MEDIUM,
                    title=f"Mention of {keyword}",
                    content=f"Post discussing {keyword} found on dark web forum...",
                    matched_keywords=[keyword],
                    discovered_at=datetime.now(),
                    author=f"user_{hash(keyword) % 1000}"
                )
                
                new_mentions.append(mention)
                self.mentions.append(mention)
                
                # Generate alert
                self._create_alert(mention)
        
        return new_mentions
    
    async def search_credentials(self, email: str = None, 
                                domain: str = None) -> List[CredentialLeak]:
        """Search for leaked credentials"""
        results = []
        
        if email:
            results.extend(self.breach_db.search_by_email(email))
        
        if domain:
            results.extend(self.breach_db.search_by_domain(domain))
        
        return results
    
    async def check_domain_exposure(self, domain: str) -> Dict:
        """Check domain exposure on dark web"""
        exposure = {
            'domain': domain,
            'credential_leaks': [],
            'mentions': [],
            'ransomware_listings': [],
            'paste_mentions': [],
            'risk_score': 0
        }
        
        # Check credentials
        cred_leaks = self.breach_db.search_by_domain(domain)
        exposure['credential_leaks'] = [l.to_dict() for l in cred_leaks]
        
        # Check mentions
        domain_mentions = [
            m for m in self.mentions
            if domain.lower() in m.content.lower()
        ]
        exposure['mentions'] = [m.to_dict() for m in domain_mentions]
        
        # Check ransomware
        ransomware_victims = self.ransomware_tracker.search_victims(domain)
        exposure['ransomware_listings'] = [v.to_dict() for v in ransomware_victims]
        
        # Check pastes
        paste_results = await self.paste_monitor.monitor_pastes([domain])
        exposure['paste_mentions'] = paste_results
        
        # Calculate risk score
        risk_score = 0
        risk_score += min(50, len(cred_leaks) * 5)
        risk_score += len(domain_mentions) * 10
        risk_score += len(ransomware_victims) * 30
        risk_score += len(paste_results) * 5
        
        exposure['risk_score'] = min(100, risk_score)
        
        return exposure
    
    async def monitor_ransomware_sites(self) -> List[RansomwareVictim]:
        """Monitor ransomware leak sites"""
        new_victims = []
        
        # Simulate finding new victims
        for group_id, group in self.ransomware_tracker.groups.items():
            if hash(group['name']) % 4 == 0:  # Simulate finding some victims
                victim = RansomwareVictim(
                    victim_id=hashlib.sha256(f"{group['name']}-{time.time()}".encode()).hexdigest()[:16],
                    ransomware_group=group['name'],
                    victim_name=f"Company{hash(group['name']) % 1000} Inc.",
                    victim_domain=f"company{hash(group['name']) % 1000}.com",
                    industry="Technology",
                    country="US",
                    announced_date=datetime.now(),
                    deadline=datetime.now() + timedelta(days=7),
                    data_size="50 GB",
                    sample_files=['customers.csv', 'financials.xlsx'],
                    ransom_amount="$500,000",
                    payment_status="unpaid"
                )
                
                new_victims.append(victim)
                self.ransomware_tracker.add_victim(victim)
                
                # Create alert
                alert = {
                    'alert_id': hashlib.sha256(victim.victim_id.encode()).hexdigest()[:16],
                    'type': 'ransomware_victim',
                    'severity': AlertSeverity.CRITICAL.name_str,
                    'title': f"New ransomware victim: {victim.victim_name}",
                    'description': f"{group['name']} claims attack on {victim.victim_name}",
                    'created_at': datetime.now().isoformat()
                }
                self.alerts.append(alert)
        
        return new_victims
    
    def _create_alert(self, mention: DarkWebMention):
        """Create an alert from a mention"""
        alert = {
            'alert_id': hashlib.sha256(mention.mention_id.encode()).hexdigest()[:16],
            'type': 'dark_web_mention',
            'severity': mention.severity.name_str,
            'title': mention.title,
            'description': f"Mention found on {mention.source_name}",
            'mention_id': mention.mention_id,
            'created_at': datetime.now().isoformat()
        }
        
        self.alerts.append(alert)
        
        if self.on_alert:
            self.on_alert(alert)
    
    def start_monitoring(self, interval: int = 3600):
        """Start continuous monitoring"""
        self.running = True
        
        def monitor_loop():
            while self.running:
                asyncio.run(self.scan_for_mentions())
                asyncio.run(self.monitor_ransomware_sites())
                time.sleep(interval)
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def get_alerts(self, severity: AlertSeverity = None, 
                  limit: int = 100) -> List[Dict]:
        """Get alerts"""
        alerts = self.alerts
        
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity.name_str]
        
        return sorted(alerts, key=lambda a: a['created_at'], reverse=True)[:limit]
    
    def get_statistics(self) -> Dict:
        """Get dark web intelligence statistics"""
        return {
            'total_mentions': len(self.mentions),
            'total_alerts': len(self.alerts),
            'monitored_keywords': len(self.monitored_keywords),
            'monitored_domains': len(self.monitored_domains),
            'credential_leaks': self.breach_db.get_breach_stats(),
            'ransomware': self.ransomware_tracker.get_statistics(),
            'threat_actors': len(self.actor_tracker.actors),
            'mentions_by_category': self._count_by_category(),
            'mentions_by_severity': self._count_by_severity()
        }
    
    def _count_by_category(self) -> Dict[str, int]:
        """Count mentions by category"""
        counts = defaultdict(int)
        for mention in self.mentions:
            counts[mention.category.value] += 1
        return dict(counts)
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count mentions by severity"""
        counts = defaultdict(int)
        for mention in self.mentions:
            counts[mention.severity.name_str] += 1
        return dict(counts)
    
    def export_intelligence(self, format_type: str = 'json') -> str:
        """Export intelligence data"""
        data = {
            'export_date': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'mentions': [m.to_dict() for m in self.mentions],
            'alerts': self.alerts,
            'ransomware_victims': [v.to_dict() for v in self.ransomware_tracker.victims],
            'threat_actors': [a.to_dict() for a in self.actor_tracker.actors.values()]
        }
        
        if format_type == 'json':
            return json.dumps(data, indent=2)
        
        return json.dumps(data, indent=2)
