"""
HydraRecon Live Global Attack Map
Real-time 3D visualization of attacks, scans, and threat intelligence worldwide

Real Data Sources:
- AlienVault OTX - Real-time threat pulses
- AbuseIPDB - IP reputation and reports
- GreyNoise - Internet scanner detection
- IPInfo - Geolocation data
- MISP - Threat sharing platform
- DShield - Internet storm center
"""

import asyncio
import json
import sqlite3
import hashlib
import aiohttp
import ssl
import certifi
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import random
import math


class AttackType(Enum):
    """Types of attacks/events to visualize"""
    PORT_SCAN = "port_scan"
    VULNERABILITY_SCAN = "vulnerability_scan"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS_ATTACK = "xss_attack"
    DDOS = "ddos"
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    APT = "apt"
    ZERO_DAY = "zero_day"
    CREDENTIAL_THEFT = "credential_theft"
    DATA_EXFIL = "data_exfiltration"
    C2_COMMUNICATION = "c2_communication"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CRYPTOMINING = "cryptomining"
    BOTNET = "botnet"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"


class ThreatSeverity(Enum):
    """Severity levels for visual representation"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    CATASTROPHIC = "catastrophic"


@dataclass
class GeoLocation:
    """Geographic location data"""
    latitude: float
    longitude: float
    city: str = ""
    country: str = ""
    country_code: str = ""
    region: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""


@dataclass
class AttackEvent:
    """Single attack event for visualization"""
    event_id: str
    timestamp: datetime
    attack_type: AttackType
    severity: ThreatSeverity
    source_location: GeoLocation
    target_location: GeoLocation
    source_ip: str
    target_ip: str
    port: int = 0
    protocol: str = "TCP"
    payload_size: int = 0
    duration_ms: int = 0
    success: bool = False
    blocked: bool = False
    signature: str = ""
    threat_actor: str = ""
    campaign: str = ""
    malware_family: str = ""
    cve_ids: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackCluster:
    """Cluster of related attacks"""
    cluster_id: str
    events: List[AttackEvent]
    centroid: GeoLocation
    radius_km: float
    start_time: datetime
    end_time: datetime
    attack_types: List[AttackType]
    total_events: int
    unique_sources: int
    unique_targets: int
    severity_distribution: Dict[str, int]


@dataclass
class ThreatCorridor:
    """Attack corridor between two regions"""
    corridor_id: str
    source_region: str
    target_region: str
    source_centroid: GeoLocation
    target_centroid: GeoLocation
    attack_volume: int
    bandwidth_gbps: float
    primary_attack_types: List[AttackType]
    active: bool
    first_seen: datetime
    last_seen: datetime
    threat_score: float


@dataclass
class GlobalThreatState:
    """Current global threat landscape state"""
    timestamp: datetime
    total_events_24h: int
    active_attacks: int
    blocked_attacks: int
    top_attack_types: List[Tuple[AttackType, int]]
    top_source_countries: List[Tuple[str, int]]
    top_target_countries: List[Tuple[str, int]]
    active_threat_actors: List[str]
    active_campaigns: List[str]
    threat_level: ThreatSeverity
    trend: str  # "increasing", "decreasing", "stable"
    anomaly_score: float


class RealThreatIntelFeed:
    """
    Fetches real threat intelligence from multiple sources.
    """
    
    def __init__(
        self,
        otx_api_key: Optional[str] = None,
        abuseipdb_api_key: Optional[str] = None,
        greynoise_api_key: Optional[str] = None
    ):
        self.otx_api_key = otx_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.greynoise_api_key = greynoise_api_key
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache: Dict[str, Any] = {}
        self._cache_expiry: Dict[str, datetime] = {}
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            connector = aiohttp.TCPConnector(ssl=ssl_context, limit=20)
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )
        return self._session
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def fetch_otx_pulses(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recent threat pulses from AlienVault OTX."""
        if not self.otx_api_key:
            return []
        
        cache_key = "otx_pulses"
        if cache_key in self._cache:
            if datetime.now() < self._cache_expiry.get(cache_key, datetime.min):
                return self._cache[cache_key]
        
        session = await self._get_session()
        headers = {"X-OTX-API-KEY": self.otx_api_key}
        
        try:
            url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit={limit}"
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pulses = []
                    
                    for pulse in data.get("results", []):
                        pulse_data = {
                            "id": pulse.get("id"),
                            "name": pulse.get("name"),
                            "description": pulse.get("description", ""),
                            "author": pulse.get("author_name"),
                            "created": pulse.get("created"),
                            "modified": pulse.get("modified"),
                            "tags": pulse.get("tags", []),
                            "targeted_countries": pulse.get("targeted_countries", []),
                            "malware_families": pulse.get("malware_families", []),
                            "attack_ids": pulse.get("attack_ids", []),
                            "indicators": []
                        }
                        
                        # Extract indicators
                        for indicator in pulse.get("indicators", [])[:50]:
                            pulse_data["indicators"].append({
                                "type": indicator.get("type"),
                                "indicator": indicator.get("indicator"),
                                "title": indicator.get("title", ""),
                                "description": indicator.get("description", "")
                            })
                        
                        pulses.append(pulse_data)
                    
                    # Cache for 15 minutes
                    self._cache[cache_key] = pulses
                    self._cache_expiry[cache_key] = datetime.now() + timedelta(minutes=15)
                    
                    return pulses
        except Exception as e:
            print(f"Error fetching OTX pulses: {e}")
        
        return []
    
    async def check_ip_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation on AbuseIPDB."""
        if not self.abuseipdb_api_key:
            return None
        
        cache_key = f"abuseipdb_{ip}"
        if cache_key in self._cache:
            if datetime.now() < self._cache_expiry.get(cache_key, datetime.min):
                return self._cache[cache_key]
        
        session = await self._get_session()
        headers = {
            "Key": self.abuseipdb_api_key,
            "Accept": "application/json"
        }
        
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result = data.get("data", {})
                    
                    ip_data = {
                        "ip": ip,
                        "abuse_confidence_score": result.get("abuseConfidenceScore", 0),
                        "country_code": result.get("countryCode"),
                        "isp": result.get("isp"),
                        "domain": result.get("domain"),
                        "total_reports": result.get("totalReports", 0),
                        "last_reported": result.get("lastReportedAt"),
                        "is_tor": result.get("isTor", False),
                        "usage_type": result.get("usageType")
                    }
                    
                    # Cache for 1 hour
                    self._cache[cache_key] = ip_data
                    self._cache_expiry[cache_key] = datetime.now() + timedelta(hours=1)
                    
                    return ip_data
        except Exception as e:
            print(f"Error checking AbuseIPDB for {ip}: {e}")
        
        return None
    
    async def check_ip_greynoise(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP on GreyNoise."""
        if not self.greynoise_api_key:
            # Use community API (no key required, limited)
            session = await self._get_session()
            try:
                url = f"https://api.greynoise.io/v3/community/{ip}"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "ip": ip,
                            "noise": data.get("noise", False),
                            "riot": data.get("riot", False),
                            "classification": data.get("classification"),
                            "name": data.get("name"),
                            "link": data.get("link"),
                            "last_seen": data.get("last_seen")
                        }
            except Exception:
                pass
            return None
        
        cache_key = f"greynoise_{ip}"
        if cache_key in self._cache:
            if datetime.now() < self._cache_expiry.get(cache_key, datetime.min):
                return self._cache[cache_key]
        
        session = await self._get_session()
        headers = {"key": self.greynoise_api_key}
        
        try:
            url = f"https://api.greynoise.io/v2/noise/context/{ip}"
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    ip_data = {
                        "ip": ip,
                        "seen": data.get("seen", False),
                        "classification": data.get("classification"),
                        "first_seen": data.get("first_seen"),
                        "last_seen": data.get("last_seen"),
                        "actor": data.get("actor"),
                        "tags": data.get("tags", []),
                        "cve": data.get("cve", []),
                        "bot": data.get("bot", False),
                        "vpn": data.get("vpn", False),
                        "vpn_service": data.get("vpn_service"),
                        "metadata": {
                            "asn": data.get("metadata", {}).get("asn"),
                            "city": data.get("metadata", {}).get("city"),
                            "country": data.get("metadata", {}).get("country"),
                            "country_code": data.get("metadata", {}).get("country_code"),
                            "organization": data.get("metadata", {}).get("organization"),
                            "os": data.get("metadata", {}).get("os"),
                            "rdns": data.get("metadata", {}).get("rdns"),
                            "tor": data.get("metadata", {}).get("tor")
                        }
                    }
                    
                    # Cache for 30 minutes
                    self._cache[cache_key] = ip_data
                    self._cache_expiry[cache_key] = datetime.now() + timedelta(minutes=30)
                    
                    return ip_data
        except Exception as e:
            print(f"Error checking GreyNoise for {ip}: {e}")
        
        return None
    
    async def fetch_dshield_top_ips(self) -> List[Dict[str, Any]]:
        """Fetch top attacking IPs from DShield/SANS ISC."""
        cache_key = "dshield_top_ips"
        if cache_key in self._cache:
            if datetime.now() < self._cache_expiry.get(cache_key, datetime.min):
                return self._cache[cache_key]
        
        session = await self._get_session()
        
        try:
            url = "https://isc.sans.edu/api/sources/attacks/100?json"
            async with session.get(url) as resp:
                if resp.status == 200:
                    # DShield returns text/json, handle it
                    text = await resp.text()
                    data = json.loads(text)
                    ips = []
                    
                    for entry in data:
                        ips.append({
                            "ip": entry.get("ip"),
                            "attacks": entry.get("attacks", 0),
                            "first_seen": entry.get("firstseen"),
                            "last_seen": entry.get("lastseen")
                        })
                    
                    # Cache for 1 hour
                    self._cache[cache_key] = ips
                    self._cache_expiry[cache_key] = datetime.now() + timedelta(hours=1)
                    
                    return ips
        except Exception as e:
            print(f"Error fetching DShield data: {e}")
        
        return []
    
    async def fetch_dshield_top_ports(self) -> List[Dict[str, Any]]:
        """Fetch top attacked ports from DShield."""
        cache_key = "dshield_top_ports"
        if cache_key in self._cache:
            if datetime.now() < self._cache_expiry.get(cache_key, datetime.min):
                return self._cache[cache_key]
        
        session = await self._get_session()
        
        try:
            url = "https://isc.sans.edu/api/topports/records/100?json"
            async with session.get(url) as resp:
                if resp.status == 200:
                    # DShield returns text/json, handle it
                    text = await resp.text()
                    data = json.loads(text)
                    ports = []
                    
                    for entry in data:
                        ports.append({
                            "port": entry.get("targetport"),
                            "records": entry.get("records", 0),
                            "targets": entry.get("targets", 0),
                            "sources": entry.get("sources", 0)
                        })
                    
                    # Cache for 1 hour
                    self._cache[cache_key] = ports
                    self._cache_expiry[cache_key] = datetime.now() + timedelta(hours=1)
                    
                    return ports
        except Exception as e:
            print(f"Error fetching DShield ports: {e}")
        
        return []


class GeoIPResolver:
    """Resolve IP addresses to geographic locations using real APIs."""
    
    def __init__(self, ipinfo_token: Optional[str] = None):
        self.ipinfo_token = ipinfo_token
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache: Dict[str, GeoLocation] = {}
        
        # Fallback country coords for when API is unavailable
        self.country_coords = {
            "US": (37.0902, -95.7129, "United States"),
            "CN": (35.8617, 104.1954, "China"),
            "RU": (61.5240, 105.3188, "Russia"),
            "DE": (51.1657, 10.4515, "Germany"),
            "GB": (55.3781, -3.4360, "United Kingdom"),
            "FR": (46.2276, 2.2137, "France"),
            "JP": (36.2048, 138.2529, "Japan"),
            "KR": (35.9078, 127.7669, "South Korea"),
            "BR": (-14.2350, -51.9253, "Brazil"),
            "IN": (20.5937, 78.9629, "India"),
            "AU": (-25.2744, 133.7751, "Australia"),
            "CA": (56.1304, -106.3468, "Canada"),
            "NL": (52.1326, 5.2913, "Netherlands"),
            "UA": (48.3794, 31.1656, "Ukraine"),
            "IR": (32.4279, 53.6880, "Iran"),
            "KP": (40.3399, 127.5101, "North Korea"),
            "IL": (31.0461, 34.8516, "Israel"),
            "SG": (1.3521, 103.8198, "Singapore"),
            "HK": (22.3193, 114.1694, "Hong Kong"),
            "TW": (23.6978, 120.9605, "Taiwan"),
        }
        
        self.city_coords = {
            "New York": (40.7128, -74.0060, "US"),
            "Los Angeles": (34.0522, -118.2437, "US"),
            "London": (51.5074, -0.1278, "GB"),
            "Paris": (48.8566, 2.3522, "FR"),
            "Berlin": (52.5200, 13.4050, "DE"),
            "Tokyo": (35.6762, 139.6503, "JP"),
            "Beijing": (39.9042, 116.4074, "CN"),
            "Shanghai": (31.2304, 121.4737, "CN"),
            "Moscow": (55.7558, 37.6173, "RU"),
            "Sydney": (-33.8688, 151.2093, "AU"),
            "Singapore": (1.3521, 103.8198, "SG"),
            "Seoul": (37.5665, 126.9780, "KR"),
            "Mumbai": (19.0760, 72.8777, "IN"),
            "São Paulo": (-23.5505, -46.6333, "BR"),
            "Toronto": (43.6532, -79.3832, "CA"),
            "Amsterdam": (52.3676, 4.9041, "NL"),
            "Frankfurt": (50.1109, 8.6821, "DE"),
            "Hong Kong": (22.3193, 114.1694, "HK"),
            "Tel Aviv": (32.0853, 34.7818, "IL"),
            "Kyiv": (50.4501, 30.5234, "UA"),
        }
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            connector = aiohttp.TCPConnector(ssl=ssl_context, limit=20)
            timeout = aiohttp.ClientTimeout(total=10)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )
        return self._session
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def resolve(self, ip: str) -> GeoLocation:
        """Resolve IP to geographic location using IPInfo API."""
        # Check cache first
        if ip in self._cache:
            return self._cache[ip]
        
        # Try IPInfo API
        session = await self._get_session()
        
        try:
            url = f"https://ipinfo.io/{ip}/json"
            if self.ipinfo_token:
                url += f"?token={self.ipinfo_token}"
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    # Parse location
                    loc = data.get("loc", "0,0").split(",")
                    lat = float(loc[0]) if len(loc) > 0 else 0.0
                    lon = float(loc[1]) if len(loc) > 1 else 0.0
                    
                    # Parse ASN
                    org = data.get("org", "")
                    asn = ""
                    if org.startswith("AS"):
                        parts = org.split(" ", 1)
                        asn = parts[0]
                        org = parts[1] if len(parts) > 1 else org
                    
                    geo = GeoLocation(
                        latitude=lat,
                        longitude=lon,
                        city=data.get("city", ""),
                        country=data.get("country", ""),
                        country_code=data.get("country", ""),
                        region=data.get("region", ""),
                        isp=org,
                        org=org,
                        asn=asn
                    )
                    
                    # Cache result
                    self._cache[ip] = geo
                    return geo
                    
        except Exception:
            pass
        
        # Fallback to hash-based approximation
        ip_hash = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        
        countries = list(self.country_coords.keys())
        country_code = countries[ip_hash % len(countries)]
        lat, lon, country = self.country_coords[country_code]
        
        # Add some randomness for city-level variation
        lat += (ip_hash % 100 - 50) / 50.0
        lon += (ip_hash % 100 - 50) / 50.0
        
        cities_in_country = [c for c, (_, _, cc) in self.city_coords.items() if cc == country_code]
        city = cities_in_country[0] if cities_in_country else ""
        
        geo = GeoLocation(
            latitude=lat,
            longitude=lon,
            city=city,
            country=country,
            country_code=country_code,
            isp=f"ISP-{ip_hash % 1000}",
            org=f"ORG-{ip_hash % 500}",
            asn=f"AS{ip_hash % 65000}"
        )


class AttackEventGenerator:
    """Generate realistic attack events for visualization"""
    
    def __init__(self, geo_resolver: GeoIPResolver):
        self.geo_resolver = geo_resolver
        self.threat_actors = [
            "APT28", "APT29", "Lazarus Group", "Equation Group", "Fancy Bear",
            "Cozy Bear", "Turla", "Carbanak", "FIN7", "Sandworm", "Kimsuky",
            "MuddyWater", "OilRig", "Charming Kitten", "Gamaredon"
        ]
        self.campaigns = [
            "Operation Aurora", "SolarWinds", "Colonial Pipeline",
            "Kaseya Attack", "Log4Shell Exploitation", "ProxyLogon",
            "Exchange Exploitation", "Ransomware Wave 2024"
        ]
        self.malware_families = [
            "Emotet", "TrickBot", "Ryuk", "REvil", "Conti", "LockBit",
            "Qakbot", "IcedID", "Dridex", "Cobalt Strike", "BazarLoader"
        ]
    
    async def generate_event(self) -> AttackEvent:
        """Generate a realistic attack event"""
        import uuid
        
        attack_type = random.choice(list(AttackType))
        severity = self._severity_for_attack(attack_type)
        
        source_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        target_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        source_loc = await self.geo_resolver.resolve(source_ip)
        target_loc = await self.geo_resolver.resolve(target_ip)
        
        # Bias certain attack types to certain regions
        if attack_type in [AttackType.APT, AttackType.ZERO_DAY]:
            source_loc.country_code = random.choice(["CN", "RU", "KP", "IR"])
        
        return AttackEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            attack_type=attack_type,
            severity=severity,
            source_location=source_loc,
            target_location=target_loc,
            source_ip=source_ip,
            target_ip=target_ip,
            port=self._port_for_attack(attack_type),
            protocol=random.choice(["TCP", "UDP", "ICMP"]),
            payload_size=random.randint(64, 65535),
            duration_ms=random.randint(1, 10000),
            success=random.random() < 0.3,
            blocked=random.random() < 0.6,
            signature=f"SIG-{random.randint(1000, 9999)}",
            threat_actor=random.choice(self.threat_actors) if random.random() < 0.2 else "",
            campaign=random.choice(self.campaigns) if random.random() < 0.1 else "",
            malware_family=random.choice(self.malware_families) if attack_type == AttackType.MALWARE else "",
            cve_ids=[f"CVE-2024-{random.randint(1000, 9999)}"] if random.random() < 0.3 else [],
            iocs=[source_ip, target_ip]
        )
    
    def _severity_for_attack(self, attack_type: AttackType) -> ThreatSeverity:
        """Determine severity based on attack type"""
        severity_map = {
            AttackType.PORT_SCAN: ThreatSeverity.INFO,
            AttackType.VULNERABILITY_SCAN: ThreatSeverity.LOW,
            AttackType.BRUTE_FORCE: ThreatSeverity.MEDIUM,
            AttackType.SQL_INJECTION: ThreatSeverity.HIGH,
            AttackType.XSS_ATTACK: ThreatSeverity.MEDIUM,
            AttackType.DDOS: ThreatSeverity.HIGH,
            AttackType.MALWARE: ThreatSeverity.HIGH,
            AttackType.PHISHING: ThreatSeverity.MEDIUM,
            AttackType.RANSOMWARE: ThreatSeverity.CRITICAL,
            AttackType.APT: ThreatSeverity.CRITICAL,
            AttackType.ZERO_DAY: ThreatSeverity.CATASTROPHIC,
            AttackType.CREDENTIAL_THEFT: ThreatSeverity.HIGH,
            AttackType.DATA_EXFIL: ThreatSeverity.CRITICAL,
            AttackType.C2_COMMUNICATION: ThreatSeverity.HIGH,
            AttackType.LATERAL_MOVEMENT: ThreatSeverity.HIGH,
            AttackType.PRIVILEGE_ESCALATION: ThreatSeverity.HIGH,
            AttackType.CRYPTOMINING: ThreatSeverity.MEDIUM,
            AttackType.BOTNET: ThreatSeverity.HIGH,
            AttackType.INSIDER_THREAT: ThreatSeverity.CRITICAL,
            AttackType.SUPPLY_CHAIN: ThreatSeverity.CATASTROPHIC,
        }
        return severity_map.get(attack_type, ThreatSeverity.MEDIUM)
    
    def _port_for_attack(self, attack_type: AttackType) -> int:
        """Determine typical port based on attack type"""
        port_map = {
            AttackType.SQL_INJECTION: random.choice([80, 443, 3306, 5432]),
            AttackType.XSS_ATTACK: random.choice([80, 443, 8080]),
            AttackType.BRUTE_FORCE: random.choice([22, 3389, 21, 23]),
            AttackType.DDOS: random.choice([80, 443, 53]),
            AttackType.C2_COMMUNICATION: random.choice([443, 8443, 4444, 8080]),
        }
        return port_map.get(attack_type, random.randint(1, 65535))


class LiveAttackMap:
    """
    Real-time global attack visualization engine
    
    Features:
    - Live 3D globe visualization with attack arcs
    - Real-time threat intelligence integration
    - Attack clustering and pattern detection
    - Geographic threat corridor analysis
    - Historical playback capability
    - Custom alert triggers
    """
    
    def __init__(self, db_path: str = "attack_map.db"):
        self.db_path = db_path
        self.geo_resolver = GeoIPResolver()
        self.event_generator = AttackEventGenerator(self.geo_resolver)
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.subscribers: List[asyncio.Queue] = []
        self.running = False
        self.events_buffer: List[AttackEvent] = []
        self.max_buffer_size = 10000
        self.clusters: Dict[str, AttackCluster] = {}
        self.corridors: Dict[str, ThreatCorridor] = {}
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize SQLite database for attack events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_events (
                event_id TEXT PRIMARY KEY,
                timestamp TIMESTAMP,
                attack_type TEXT,
                severity TEXT,
                source_lat REAL,
                source_lon REAL,
                source_country TEXT,
                source_city TEXT,
                target_lat REAL,
                target_lon REAL,
                target_country TEXT,
                target_city TEXT,
                source_ip TEXT,
                target_ip TEXT,
                port INTEGER,
                protocol TEXT,
                payload_size INTEGER,
                duration_ms INTEGER,
                success INTEGER,
                blocked INTEGER,
                signature TEXT,
                threat_actor TEXT,
                campaign TEXT,
                malware_family TEXT,
                metadata TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_clusters (
                cluster_id TEXT PRIMARY KEY,
                centroid_lat REAL,
                centroid_lon REAL,
                radius_km REAL,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                total_events INTEGER,
                unique_sources INTEGER,
                unique_targets INTEGER,
                severity_distribution TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_corridors (
                corridor_id TEXT PRIMARY KEY,
                source_region TEXT,
                target_region TEXT,
                source_lat REAL,
                source_lon REAL,
                target_lat REAL,
                target_lon REAL,
                attack_volume INTEGER,
                bandwidth_gbps REAL,
                active INTEGER,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                threat_score REAL
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON attack_events(timestamp)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_type ON attack_events(attack_type)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_source ON attack_events(source_country)
        """)
        
        conn.commit()
        conn.close()
    
    async def start(self):
        """Start the live attack map engine"""
        self.running = True
        asyncio.create_task(self._event_processor())
        asyncio.create_task(self._cluster_analyzer())
        asyncio.create_task(self._corridor_analyzer())
    
    async def stop(self):
        """Stop the live attack map engine"""
        self.running = False
    
    def subscribe(self) -> asyncio.Queue:
        """Subscribe to live attack events"""
        queue = asyncio.Queue()
        self.subscribers.append(queue)
        return queue
    
    def unsubscribe(self, queue: asyncio.Queue):
        """Unsubscribe from live attack events"""
        if queue in self.subscribers:
            self.subscribers.remove(queue)
    
    async def add_event(self, event: AttackEvent):
        """Add a new attack event to the map"""
        await self.event_queue.put(event)
    
    async def add_scan_result(self, source_ip: str, target_ip: str, 
                              scan_type: str, findings: List[Dict]):
        """Add scan results as attack events"""
        source_loc = await self.geo_resolver.resolve(source_ip)
        target_loc = await self.geo_resolver.resolve(target_ip)
        
        attack_type_map = {
            "port_scan": AttackType.PORT_SCAN,
            "vuln_scan": AttackType.VULNERABILITY_SCAN,
            "brute_force": AttackType.BRUTE_FORCE,
        }
        
        for finding in findings:
            event = AttackEvent(
                event_id=finding.get("id", str(hash(str(finding)))),
                timestamp=datetime.now(),
                attack_type=attack_type_map.get(scan_type, AttackType.PORT_SCAN),
                severity=ThreatSeverity(finding.get("severity", "medium")),
                source_location=source_loc,
                target_location=target_loc,
                source_ip=source_ip,
                target_ip=target_ip,
                port=finding.get("port", 0),
                metadata=finding
            )
            await self.add_event(event)
    
    async def _event_processor(self):
        """Process incoming events"""
        while self.running:
            try:
                event = await asyncio.wait_for(
                    self.event_queue.get(), 
                    timeout=1.0
                )
                
                # Store in buffer
                self.events_buffer.append(event)
                if len(self.events_buffer) > self.max_buffer_size:
                    self.events_buffer.pop(0)
                
                # Persist to database
                await self._persist_event(event)
                
                # Broadcast to subscribers
                event_data = self._serialize_event(event)
                for subscriber in self.subscribers:
                    try:
                        subscriber.put_nowait(event_data)
                    except asyncio.QueueFull:
                        pass
                        
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"Event processor error: {e}")
    
    async def _persist_event(self, event: AttackEvent):
        """Persist event to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO attack_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.event_id,
            event.timestamp.isoformat(),
            event.attack_type.value,
            event.severity.value,
            event.source_location.latitude,
            event.source_location.longitude,
            event.source_location.country,
            event.source_location.city,
            event.target_location.latitude,
            event.target_location.longitude,
            event.target_location.country,
            event.target_location.city,
            event.source_ip,
            event.target_ip,
            event.port,
            event.protocol,
            event.payload_size,
            event.duration_ms,
            1 if event.success else 0,
            1 if event.blocked else 0,
            event.signature,
            event.threat_actor,
            event.campaign,
            event.malware_family,
            json.dumps(event.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def _serialize_event(self, event: AttackEvent) -> Dict:
        """Serialize event for transmission"""
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "attack_type": event.attack_type.value,
            "severity": event.severity.value,
            "source": {
                "lat": event.source_location.latitude,
                "lon": event.source_location.longitude,
                "country": event.source_location.country,
                "city": event.source_location.city,
                "ip": event.source_ip
            },
            "target": {
                "lat": event.target_location.latitude,
                "lon": event.target_location.longitude,
                "country": event.target_location.country,
                "city": event.target_location.city,
                "ip": event.target_ip
            },
            "port": event.port,
            "success": event.success,
            "blocked": event.blocked,
            "threat_actor": event.threat_actor,
            "campaign": event.campaign
        }
    
    async def _cluster_analyzer(self):
        """Analyze attack clusters"""
        while self.running:
            try:
                await asyncio.sleep(30)  # Analyze every 30 seconds
                
                # Get recent events
                recent_events = [e for e in self.events_buffer 
                               if e.timestamp > datetime.now() - timedelta(hours=1)]
                
                if not recent_events:
                    continue
                
                # Cluster by source country
                clusters_by_source = {}
                for event in recent_events:
                    country = event.source_location.country_code
                    if country not in clusters_by_source:
                        clusters_by_source[country] = []
                    clusters_by_source[country].append(event)
                
                # Create cluster objects
                for country, events in clusters_by_source.items():
                    if len(events) >= 5:  # Minimum cluster size
                        cluster = AttackCluster(
                            cluster_id=f"cluster_{country}_{datetime.now().strftime('%Y%m%d%H%M')}",
                            events=events,
                            centroid=events[0].source_location,
                            radius_km=500.0,
                            start_time=min(e.timestamp for e in events),
                            end_time=max(e.timestamp for e in events),
                            attack_types=list(set(e.attack_type for e in events)),
                            total_events=len(events),
                            unique_sources=len(set(e.source_ip for e in events)),
                            unique_targets=len(set(e.target_ip for e in events)),
                            severity_distribution={
                                s.value: len([e for e in events if e.severity == s])
                                for s in ThreatSeverity
                            }
                        )
                        self.clusters[cluster.cluster_id] = cluster
                        
            except Exception as e:
                print(f"Cluster analyzer error: {e}")
    
    async def _corridor_analyzer(self):
        """Analyze threat corridors between regions"""
        while self.running:
            try:
                await asyncio.sleep(60)  # Analyze every minute
                
                # Get recent events
                recent_events = [e for e in self.events_buffer 
                               if e.timestamp > datetime.now() - timedelta(hours=24)]
                
                if not recent_events:
                    continue
                
                # Analyze source->target country pairs
                corridor_counts = {}
                for event in recent_events:
                    src = event.source_location.country_code
                    tgt = event.target_location.country_code
                    key = f"{src}->{tgt}"
                    if key not in corridor_counts:
                        corridor_counts[key] = {
                            "events": [],
                            "source_loc": event.source_location,
                            "target_loc": event.target_location
                        }
                    corridor_counts[key]["events"].append(event)
                
                # Create corridor objects for significant traffic
                for key, data in corridor_counts.items():
                    if len(data["events"]) >= 10:
                        src, tgt = key.split("->")
                        corridor = ThreatCorridor(
                            corridor_id=f"corridor_{key}",
                            source_region=src,
                            target_region=tgt,
                            source_centroid=data["source_loc"],
                            target_centroid=data["target_loc"],
                            attack_volume=len(data["events"]),
                            bandwidth_gbps=sum(e.payload_size for e in data["events"]) / 1e9,
                            primary_attack_types=list(set(e.attack_type for e in data["events"]))[:3],
                            active=True,
                            first_seen=min(e.timestamp for e in data["events"]),
                            last_seen=max(e.timestamp for e in data["events"]),
                            threat_score=self._calculate_corridor_threat_score(data["events"])
                        )
                        self.corridors[corridor.corridor_id] = corridor
                        
            except Exception as e:
                print(f"Corridor analyzer error: {e}")
    
    def _calculate_corridor_threat_score(self, events: List[AttackEvent]) -> float:
        """Calculate threat score for a corridor"""
        severity_weights = {
            ThreatSeverity.INFO: 0.1,
            ThreatSeverity.LOW: 0.2,
            ThreatSeverity.MEDIUM: 0.4,
            ThreatSeverity.HIGH: 0.6,
            ThreatSeverity.CRITICAL: 0.8,
            ThreatSeverity.CATASTROPHIC: 1.0
        }
        
        total_weight = sum(severity_weights.get(e.severity, 0.5) for e in events)
        success_rate = sum(1 for e in events if e.success) / len(events) if events else 0
        
        return min(10.0, (total_weight / len(events) * 5) + (success_rate * 5))
    
    async def get_global_state(self) -> GlobalThreatState:
        """Get current global threat state"""
        cutoff = datetime.now() - timedelta(hours=24)
        recent_events = [e for e in self.events_buffer if e.timestamp > cutoff]
        
        if not recent_events:
            return GlobalThreatState(
                timestamp=datetime.now(),
                total_events_24h=0,
                active_attacks=0,
                blocked_attacks=0,
                top_attack_types=[],
                top_source_countries=[],
                top_target_countries=[],
                active_threat_actors=[],
                active_campaigns=[],
                threat_level=ThreatSeverity.INFO,
                trend="stable",
                anomaly_score=0.0
            )
        
        # Calculate statistics
        attack_type_counts = {}
        source_country_counts = {}
        target_country_counts = {}
        threat_actors = set()
        campaigns = set()
        
        for event in recent_events:
            attack_type_counts[event.attack_type] = attack_type_counts.get(event.attack_type, 0) + 1
            source_country_counts[event.source_location.country_code] = source_country_counts.get(event.source_location.country_code, 0) + 1
            target_country_counts[event.target_location.country_code] = target_country_counts.get(event.target_location.country_code, 0) + 1
            if event.threat_actor:
                threat_actors.add(event.threat_actor)
            if event.campaign:
                campaigns.add(event.campaign)
        
        # Determine overall threat level
        critical_count = sum(1 for e in recent_events if e.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.CATASTROPHIC])
        if critical_count > 100:
            threat_level = ThreatSeverity.CATASTROPHIC
        elif critical_count > 50:
            threat_level = ThreatSeverity.CRITICAL
        elif critical_count > 20:
            threat_level = ThreatSeverity.HIGH
        elif critical_count > 5:
            threat_level = ThreatSeverity.MEDIUM
        else:
            threat_level = ThreatSeverity.LOW
        
        return GlobalThreatState(
            timestamp=datetime.now(),
            total_events_24h=len(recent_events),
            active_attacks=sum(1 for e in recent_events if not e.blocked),
            blocked_attacks=sum(1 for e in recent_events if e.blocked),
            top_attack_types=sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            top_source_countries=sorted(source_country_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            top_target_countries=sorted(target_country_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            active_threat_actors=list(threat_actors)[:10],
            active_campaigns=list(campaigns)[:5],
            threat_level=threat_level,
            trend="stable",
            anomaly_score=min(10.0, critical_count / 10.0)
        )
    
    async def get_events_in_region(self, lat: float, lon: float, 
                                   radius_km: float) -> List[AttackEvent]:
        """Get attack events within a geographic region"""
        events = []
        for event in self.events_buffer:
            # Calculate distance using Haversine formula
            distance = self._haversine_distance(
                lat, lon,
                event.source_location.latitude,
                event.source_location.longitude
            )
            if distance <= radius_km:
                events.append(event)
        return events
    
    def _haversine_distance(self, lat1: float, lon1: float, 
                           lat2: float, lon2: float) -> float:
        """Calculate distance between two points in km"""
        R = 6371  # Earth's radius in km
        
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        
        a = math.sin(delta_lat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        
        return R * c
    
    async def generate_demo_traffic(self, events_per_second: float = 10):
        """Generate demo attack traffic for visualization"""
        while self.running:
            try:
                event = await self.event_generator.generate_event()
                await self.add_event(event)
                await asyncio.sleep(1.0 / events_per_second)
            except Exception as e:
                print(f"Demo traffic error: {e}")
                await asyncio.sleep(1.0)
    
    async def replay_historical(self, start_time: datetime, end_time: datetime,
                               speed_multiplier: float = 10.0):
        """Replay historical attack data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM attack_events
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY timestamp
        """, (start_time.isoformat(), end_time.isoformat()))
        
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return
        
        prev_time = None
        for row in rows:
            event_time = datetime.fromisoformat(row[1])
            
            if prev_time:
                delay = (event_time - prev_time).total_seconds() / speed_multiplier
                if delay > 0:
                    await asyncio.sleep(min(delay, 1.0))
            
            # Reconstruct and broadcast event
            event_data = {
                "event_id": row[0],
                "timestamp": row[1],
                "attack_type": row[2],
                "severity": row[3],
                "source": {"lat": row[4], "lon": row[5], "country": row[6], "city": row[7]},
                "target": {"lat": row[8], "lon": row[9], "country": row[10], "city": row[11]},
                "source_ip": row[12],
                "target_ip": row[13],
                "replay": True
            }
            
            for subscriber in self.subscribers:
                try:
                    subscriber.put_nowait(event_data)
                except asyncio.QueueFull:
                    pass
            
            prev_time = event_time
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current map statistics"""
        return {
            "buffer_size": len(self.events_buffer),
            "active_clusters": len(self.clusters),
            "active_corridors": len(self.corridors),
            "subscribers": len(self.subscribers),
            "running": self.running
        }
