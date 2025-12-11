#!/usr/bin/env python3
"""
Unified Data Sources Module - Real-Time Intelligence Feeds
Centralizes API integrations for all modules to access real data.
"""

import asyncio
import aiohttp
import hashlib
import json
import logging
import os
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import base64


class DataSourceType(Enum):
    """Types of data sources."""
    THREAT_INTEL = auto()
    VULNERABILITY = auto()
    OSINT = auto()
    BLOCKCHAIN = auto()
    NETWORK = auto()
    MALWARE = auto()
    GEOLOCATION = auto()
    DNS = auto()
    CERTIFICATE = auto()
    REPUTATION = auto()


@dataclass
class APICredential:
    """API credential storage."""
    name: str
    api_key: str
    api_secret: Optional[str] = None
    base_url: str = ""
    rate_limit: int = 60  # requests per minute
    last_used: Optional[datetime] = None
    requests_today: int = 0
    daily_limit: int = 1000


@dataclass
class DataSourceResult:
    """Result from a data source query."""
    source: str
    success: bool
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    cached: bool = False
    error: Optional[str] = None


class BaseDataSource(ABC):
    """Base class for all data sources."""
    
    def __init__(self, credentials: Optional[APICredential] = None):
        self.credentials = credentials
        self.logger = logging.getLogger(self.__class__.__name__)
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache: Dict[str, Tuple[Any, datetime]] = {}
        self._cache_ttl = 3600  # 1 hour default
    
    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session
    
    async def close(self):
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    def _get_cache_key(self, query: str) -> str:
        """Generate cache key."""
        return hashlib.md5(f"{self.__class__.__name__}:{query}".encode()).hexdigest()
    
    def _check_cache(self, query: str) -> Optional[Any]:
        """Check if result is cached."""
        key = self._get_cache_key(query)
        if key in self._cache:
            data, timestamp = self._cache[key]
            if datetime.now() - timestamp < timedelta(seconds=self._cache_ttl):
                return data
            del self._cache[key]
        return None
    
    def _set_cache(self, query: str, data: Any):
        """Cache a result."""
        key = self._get_cache_key(query)
        self._cache[key] = (data, datetime.now())
    
    @abstractmethod
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query the data source."""
        pass
    
    @property
    @abstractmethod
    def source_type(self) -> DataSourceType:
        """Return the type of data source."""
        pass


# ============================================================================
# THREAT INTELLIGENCE SOURCES
# ============================================================================

class AbuseIPDBSource(BaseDataSource):
    """AbuseIPDB - IP reputation and abuse reports."""
    
    source_type = DataSourceType.THREAT_INTEL
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query IP abuse database."""
        cached = self._check_cache(target)
        if cached:
            return DataSourceResult(source="abuseipdb", success=True, data=cached, cached=True)
        
        if not self.credentials or not self.credentials.api_key:
            return DataSourceResult(source="abuseipdb", success=False, data={}, 
                                   error="API key required. Get free key at abuseipdb.com")
        
        try:
            session = await self.get_session()
            headers = {
                "Key": self.credentials.api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": target,
                "maxAgeInDays": 90,
                "verbose": True
            }
            
            async with session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(target, data)
                    return DataSourceResult(source="abuseipdb", success=True, data=data)
                else:
                    return DataSourceResult(source="abuseipdb", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="abuseipdb", success=False, data={}, error=str(e))


class AlienVaultOTXSource(BaseDataSource):
    """AlienVault OTX - Open Threat Exchange."""
    
    source_type = DataSourceType.THREAT_INTEL
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query OTX for threat intelligence."""
        indicator_type = kwargs.get("type", "IPv4")  # IPv4, domain, hostname, url, FileHash-MD5, etc.
        
        cached = self._check_cache(f"{indicator_type}:{target}")
        if cached:
            return DataSourceResult(source="otx", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            headers = {}
            if self.credentials and self.credentials.api_key:
                headers["X-OTX-API-KEY"] = self.credentials.api_key
            
            # OTX has free tier without API key
            url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{target}/general"
            
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(f"{indicator_type}:{target}", data)
                    return DataSourceResult(source="otx", success=True, data=data)
                else:
                    return DataSourceResult(source="otx", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="otx", success=False, data={}, error=str(e))


class VirusTotalSource(BaseDataSource):
    """VirusTotal - File/URL/IP scanning."""
    
    source_type = DataSourceType.MALWARE
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query VirusTotal."""
        query_type = kwargs.get("type", "ip")  # ip, domain, file, url
        
        if not self.credentials or not self.credentials.api_key:
            return DataSourceResult(source="virustotal", success=False, data={},
                                   error="API key required. Get free key at virustotal.com")
        
        cached = self._check_cache(f"{query_type}:{target}")
        if cached:
            return DataSourceResult(source="virustotal", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            headers = {"x-apikey": self.credentials.api_key}
            
            if query_type == "ip":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            elif query_type == "domain":
                url = f"https://www.virustotal.com/api/v3/domains/{target}"
            elif query_type == "file":
                url = f"https://www.virustotal.com/api/v3/files/{target}"
            else:
                url = f"https://www.virustotal.com/api/v3/urls/{base64.urlsafe_b64encode(target.encode()).decode().rstrip('=')}"
            
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(f"{query_type}:{target}", data)
                    return DataSourceResult(source="virustotal", success=True, data=data)
                else:
                    return DataSourceResult(source="virustotal", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="virustotal", success=False, data={}, error=str(e))


class ShodanSource(BaseDataSource):
    """Shodan - Internet-connected device search."""
    
    source_type = DataSourceType.NETWORK
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query Shodan for host info."""
        if not self.credentials or not self.credentials.api_key:
            return DataSourceResult(source="shodan", success=False, data={},
                                   error="API key required. Get key at shodan.io")
        
        cached = self._check_cache(target)
        if cached:
            return DataSourceResult(source="shodan", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            url = f"https://api.shodan.io/shodan/host/{target}?key={self.credentials.api_key}"
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(target, data)
                    return DataSourceResult(source="shodan", success=True, data=data)
                else:
                    return DataSourceResult(source="shodan", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="shodan", success=False, data={}, error=str(e))


class CensysSource(BaseDataSource):
    """Censys - Internet-wide scanning data."""
    
    source_type = DataSourceType.NETWORK
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query Censys for host info."""
        if not self.credentials or not self.credentials.api_key:
            return DataSourceResult(source="censys", success=False, data={},
                                   error="API credentials required. Get at censys.io")
        
        cached = self._check_cache(target)
        if cached:
            return DataSourceResult(source="censys", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            auth = aiohttp.BasicAuth(self.credentials.api_key, self.credentials.api_secret or "")
            url = f"https://search.censys.io/api/v2/hosts/{target}"
            
            async with session.get(url, auth=auth) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(target, data)
                    return DataSourceResult(source="censys", success=True, data=data)
                else:
                    return DataSourceResult(source="censys", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="censys", success=False, data={}, error=str(e))


# ============================================================================
# VULNERABILITY SOURCES
# ============================================================================

class NVDSource(BaseDataSource):
    """NIST National Vulnerability Database."""
    
    source_type = DataSourceType.VULNERABILITY
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query NVD for CVE information."""
        cached = self._check_cache(target)
        if cached:
            return DataSourceResult(source="nvd", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            headers = {}
            if self.credentials and self.credentials.api_key:
                headers["apiKey"] = self.credentials.api_key
            
            # Search by CVE ID or keyword
            if target.upper().startswith("CVE-"):
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={target}"
            else:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={target}"
            
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(target, data)
                    return DataSourceResult(source="nvd", success=True, data=data)
                else:
                    return DataSourceResult(source="nvd", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="nvd", success=False, data={}, error=str(e))


class ExploitDBSource(BaseDataSource):
    """Exploit Database search."""
    
    source_type = DataSourceType.VULNERABILITY
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Search ExploitDB."""
        cached = self._check_cache(target)
        if cached:
            return DataSourceResult(source="exploitdb", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            # Using the ExploitDB API endpoint
            url = f"https://www.exploit-db.com/search?q={target}"
            headers = {"Accept": "application/json"}
            
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(target, data)
                    return DataSourceResult(source="exploitdb", success=True, data=data)
                else:
                    # Fallback to scraping search results
                    return DataSourceResult(source="exploitdb", success=False, data={},
                                           error="Use local searchsploit for better results")
        except Exception as e:
            return DataSourceResult(source="exploitdb", success=False, data={}, error=str(e))


class VulnersSource(BaseDataSource):
    """Vulners vulnerability database."""
    
    source_type = DataSourceType.VULNERABILITY
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query Vulners API."""
        if not self.credentials or not self.credentials.api_key:
            # Vulners has limited free access
            pass
        
        cached = self._check_cache(target)
        if cached:
            return DataSourceResult(source="vulners", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            url = "https://vulners.com/api/v3/search/lucene/"
            payload = {
                "query": target,
                "size": 20,
                "fields": ["id", "title", "description", "cvss", "published", "type"]
            }
            if self.credentials and self.credentials.api_key:
                payload["apiKey"] = self.credentials.api_key
            
            async with session.post(url, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(target, data)
                    return DataSourceResult(source="vulners", success=True, data=data)
                else:
                    return DataSourceResult(source="vulners", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="vulners", success=False, data={}, error=str(e))


# ============================================================================
# DNS & CERTIFICATE SOURCES
# ============================================================================

class CrtShSource(BaseDataSource):
    """crt.sh - Certificate Transparency logs."""
    
    source_type = DataSourceType.CERTIFICATE
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query certificate transparency logs."""
        cached = self._check_cache(target)
        if cached:
            return DataSourceResult(source="crtsh", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            url = f"https://crt.sh/?q=%.{target}&output=json"
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(target, data)
                    return DataSourceResult(source="crtsh", success=True, data={"certificates": data})
                else:
                    return DataSourceResult(source="crtsh", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="crtsh", success=False, data={}, error=str(e))


class SecurityTrailsSource(BaseDataSource):
    """SecurityTrails - DNS history and intelligence."""
    
    source_type = DataSourceType.DNS
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query SecurityTrails API."""
        if not self.credentials or not self.credentials.api_key:
            return DataSourceResult(source="securitytrails", success=False, data={},
                                   error="API key required. Get at securitytrails.com")
        
        query_type = kwargs.get("type", "domain")  # domain, subdomains, history
        
        cached = self._check_cache(f"{query_type}:{target}")
        if cached:
            return DataSourceResult(source="securitytrails", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            headers = {"APIKEY": self.credentials.api_key}
            
            if query_type == "subdomains":
                url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
            elif query_type == "history":
                url = f"https://api.securitytrails.com/v1/history/{target}/dns/a"
            else:
                url = f"https://api.securitytrails.com/v1/domain/{target}"
            
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(f"{query_type}:{target}", data)
                    return DataSourceResult(source="securitytrails", success=True, data=data)
                else:
                    return DataSourceResult(source="securitytrails", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="securitytrails", success=False, data={}, error=str(e))


# ============================================================================
# GEOLOCATION & REPUTATION SOURCES
# ============================================================================

class IPInfoSource(BaseDataSource):
    """IPInfo - IP geolocation and ASN info."""
    
    source_type = DataSourceType.GEOLOCATION
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query IPInfo API."""
        cached = self._check_cache(target)
        if cached:
            return DataSourceResult(source="ipinfo", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            url = f"https://ipinfo.io/{target}/json"
            if self.credentials and self.credentials.api_key:
                url += f"?token={self.credentials.api_key}"
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(target, data)
                    return DataSourceResult(source="ipinfo", success=True, data=data)
                else:
                    return DataSourceResult(source="ipinfo", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="ipinfo", success=False, data={}, error=str(e))


class GreyNoiseSource(BaseDataSource):
    """GreyNoise - Internet scanner and bot detection."""
    
    source_type = DataSourceType.REPUTATION
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query GreyNoise Community API."""
        cached = self._check_cache(target)
        if cached:
            return DataSourceResult(source="greynoise", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            # Community API is free
            url = f"https://api.greynoise.io/v3/community/{target}"
            headers = {}
            if self.credentials and self.credentials.api_key:
                headers["key"] = self.credentials.api_key
            
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(target, data)
                    return DataSourceResult(source="greynoise", success=True, data=data)
                else:
                    return DataSourceResult(source="greynoise", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="greynoise", success=False, data={}, error=str(e))


# ============================================================================
# BLOCKCHAIN SOURCES
# ============================================================================

class EtherscanSource(BaseDataSource):
    """Etherscan - Ethereum blockchain explorer."""
    
    source_type = DataSourceType.BLOCKCHAIN
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query Etherscan API."""
        action = kwargs.get("action", "balance")  # balance, txlist, tokentx
        
        cached = self._check_cache(f"{action}:{target}")
        if cached:
            return DataSourceResult(source="etherscan", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            api_key = self.credentials.api_key if self.credentials else ""
            
            if action == "balance":
                url = f"https://api.etherscan.io/api?module=account&action=balance&address={target}&tag=latest&apikey={api_key}"
            elif action == "txlist":
                url = f"https://api.etherscan.io/api?module=account&action=txlist&address={target}&startblock=0&endblock=99999999&sort=desc&apikey={api_key}"
            else:
                url = f"https://api.etherscan.io/api?module=account&action=tokentx&address={target}&startblock=0&endblock=99999999&sort=desc&apikey={api_key}"
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(f"{action}:{target}", data)
                    return DataSourceResult(source="etherscan", success=True, data=data)
                else:
                    return DataSourceResult(source="etherscan", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="etherscan", success=False, data={}, error=str(e))


class BlockchainInfoSource(BaseDataSource):
    """Blockchain.info - Bitcoin blockchain explorer."""
    
    source_type = DataSourceType.BLOCKCHAIN
    
    async def query(self, target: str, **kwargs) -> DataSourceResult:
        """Query Blockchain.info API."""
        cached = self._check_cache(target)
        if cached:
            return DataSourceResult(source="blockchain", success=True, data=cached, cached=True)
        
        try:
            session = await self.get_session()
            url = f"https://blockchain.info/rawaddr/{target}"
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._set_cache(target, data)
                    return DataSourceResult(source="blockchain", success=True, data=data)
                else:
                    return DataSourceResult(source="blockchain", success=False, data={},
                                           error=f"API error: {resp.status}")
        except Exception as e:
            return DataSourceResult(source="blockchain", success=False, data={}, error=str(e))


# ============================================================================
# UNIFIED DATA SOURCE MANAGER
# ============================================================================

class DataSourceManager:
    """
    Manages all data sources and provides unified query interface.
    
    Usage:
        manager = DataSourceManager()
        manager.configure_from_config(config)
        
        # Query single source
        result = await manager.query_source("shodan", "8.8.8.8")
        
        # Query all sources of a type
        results = await manager.query_by_type(DataSourceType.THREAT_INTEL, "8.8.8.8")
        
        # Query all available sources
        results = await manager.query_all("8.8.8.8")
    """
    
    def __init__(self):
        self.sources: Dict[str, BaseDataSource] = {}
        self.credentials: Dict[str, APICredential] = {}
        self.logger = logging.getLogger("DataSourceManager")
        self._db_path = "data_sources.db"
        self._init_database()
    
    def _init_database(self):
        """Initialize cache database."""
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS api_usage (
                source TEXT PRIMARY KEY,
                requests_today INTEGER DEFAULT 0,
                last_reset TEXT,
                last_used TEXT
            );
            
            CREATE TABLE IF NOT EXISTS query_cache (
                cache_key TEXT PRIMARY KEY,
                source TEXT,
                data TEXT,
                timestamp TEXT
            );
        """)
        conn.commit()
        conn.close()
    
    def configure_from_config(self, config):
        """Configure data sources from application config."""
        osint_config = config.osint
        
        # Configure available sources based on API keys
        if osint_config.shodan_api_key:
            self.add_credential("shodan", APICredential(
                name="shodan",
                api_key=osint_config.shodan_api_key,
                base_url="https://api.shodan.io",
                rate_limit=1,  # 1 request per second for free tier
                daily_limit=100
            ))
        
        if osint_config.virustotal_api_key:
            self.add_credential("virustotal", APICredential(
                name="virustotal",
                api_key=osint_config.virustotal_api_key,
                base_url="https://www.virustotal.com",
                rate_limit=4,  # 4 requests per minute for free tier
                daily_limit=500
            ))
        
        if osint_config.censys_api_id:
            self.add_credential("censys", APICredential(
                name="censys",
                api_key=osint_config.censys_api_id,
                api_secret=osint_config.censys_api_secret,
                base_url="https://search.censys.io",
                rate_limit=0.4,  # 0.4 requests per second
                daily_limit=250
            ))
        
        if osint_config.securitytrails_api_key:
            self.add_credential("securitytrails", APICredential(
                name="securitytrails",
                api_key=osint_config.securitytrails_api_key,
                base_url="https://api.securitytrails.com",
                rate_limit=2,
                daily_limit=50
            ))
        
        # Initialize all sources
        self._init_sources()
    
    def add_credential(self, name: str, credential: APICredential):
        """Add or update API credential."""
        self.credentials[name] = credential
    
    def _init_sources(self):
        """Initialize all data source instances."""
        # Free sources (no API key required)
        self.sources["otx"] = AlienVaultOTXSource(self.credentials.get("otx"))
        self.sources["nvd"] = NVDSource(self.credentials.get("nvd"))
        self.sources["crtsh"] = CrtShSource()
        self.sources["ipinfo"] = IPInfoSource(self.credentials.get("ipinfo"))
        self.sources["greynoise"] = GreyNoiseSource(self.credentials.get("greynoise"))
        self.sources["blockchain"] = BlockchainInfoSource()
        
        # Sources requiring API keys
        if "shodan" in self.credentials:
            self.sources["shodan"] = ShodanSource(self.credentials["shodan"])
        
        if "virustotal" in self.credentials:
            self.sources["virustotal"] = VirusTotalSource(self.credentials["virustotal"])
        
        if "censys" in self.credentials:
            self.sources["censys"] = CensysSource(self.credentials["censys"])
        
        if "securitytrails" in self.credentials:
            self.sources["securitytrails"] = SecurityTrailsSource(self.credentials["securitytrails"])
        
        if "abuseipdb" in self.credentials:
            self.sources["abuseipdb"] = AbuseIPDBSource(self.credentials["abuseipdb"])
        
        if "etherscan" in self.credentials:
            self.sources["etherscan"] = EtherscanSource(self.credentials["etherscan"])
    
    async def query_source(self, source_name: str, target: str, **kwargs) -> DataSourceResult:
        """Query a specific data source."""
        if source_name not in self.sources:
            return DataSourceResult(
                source=source_name,
                success=False,
                data={},
                error=f"Source '{source_name}' not available"
            )
        
        source = self.sources[source_name]
        return await source.query(target, **kwargs)
    
    async def query_by_type(
        self, 
        source_type: DataSourceType, 
        target: str,
        **kwargs
    ) -> List[DataSourceResult]:
        """Query all sources of a specific type."""
        results = []
        tasks = []
        
        for name, source in self.sources.items():
            if source.source_type == source_type:
                tasks.append(source.query(target, **kwargs))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            # Convert exceptions to error results
            processed = []
            for r in results:
                if isinstance(r, Exception):
                    processed.append(DataSourceResult(
                        source="unknown",
                        success=False,
                        data={},
                        error=str(r)
                    ))
                else:
                    processed.append(r)
            return processed
        
        return results
    
    async def query_all(self, target: str, **kwargs) -> Dict[str, DataSourceResult]:
        """Query all available data sources."""
        results = {}
        tasks = {}
        
        for name, source in self.sources.items():
            tasks[name] = source.query(target, **kwargs)
        
        if tasks:
            responses = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for name, response in zip(tasks.keys(), responses):
                if isinstance(response, Exception):
                    results[name] = DataSourceResult(
                        source=name,
                        success=False,
                        data={},
                        error=str(response)
                    )
                else:
                    results[name] = response
        
        return results
    
    def get_available_sources(self) -> List[str]:
        """Get list of available data sources."""
        return list(self.sources.keys())
    
    def get_sources_by_type(self, source_type: DataSourceType) -> List[str]:
        """Get sources of a specific type."""
        return [
            name for name, source in self.sources.items()
            if source.source_type == source_type
        ]
    
    async def close_all(self):
        """Close all data source connections."""
        for source in self.sources.values():
            await source.close()


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

async def enrich_ip(manager: DataSourceManager, ip: str) -> Dict[str, Any]:
    """Enrich an IP address with data from multiple sources."""
    enrichment = {
        "ip": ip,
        "geolocation": {},
        "reputation": {},
        "network_info": {},
        "threat_intel": {},
        "open_ports": [],
        "vulnerabilities": []
    }
    
    # Query relevant sources
    results = await manager.query_all(ip)
    
    for source, result in results.items():
        if not result.success:
            continue
        
        if source == "ipinfo":
            enrichment["geolocation"] = result.data
        elif source == "shodan":
            enrichment["network_info"]["shodan"] = result.data
            if "ports" in result.data:
                enrichment["open_ports"] = result.data["ports"]
        elif source == "greynoise":
            enrichment["reputation"]["greynoise"] = result.data
        elif source == "abuseipdb":
            enrichment["reputation"]["abuseipdb"] = result.data
        elif source == "otx":
            enrichment["threat_intel"]["otx"] = result.data
        elif source == "virustotal":
            enrichment["threat_intel"]["virustotal"] = result.data
    
    return enrichment


async def enrich_domain(manager: DataSourceManager, domain: str) -> Dict[str, Any]:
    """Enrich a domain with data from multiple sources."""
    enrichment = {
        "domain": domain,
        "dns": {},
        "certificates": [],
        "subdomains": [],
        "threat_intel": {},
        "technologies": []
    }
    
    # Certificate transparency
    crtsh = await manager.query_source("crtsh", domain)
    if crtsh.success:
        enrichment["certificates"] = crtsh.data.get("certificates", [])[:100]
        # Extract subdomains from certificates
        seen = set()
        for cert in enrichment["certificates"]:
            name = cert.get("name_value", "")
            for subdomain in name.split("\n"):
                if subdomain and subdomain not in seen:
                    seen.add(subdomain)
        enrichment["subdomains"] = list(seen)
    
    # SecurityTrails if available
    st = await manager.query_source("securitytrails", domain, type="subdomains")
    if st.success:
        enrichment["subdomains"].extend(st.data.get("subdomains", []))
        enrichment["subdomains"] = list(set(enrichment["subdomains"]))
    
    # Threat intel
    vt = await manager.query_source("virustotal", domain, type="domain")
    if vt.success:
        enrichment["threat_intel"]["virustotal"] = vt.data
    
    otx = await manager.query_source("otx", domain, type="domain")
    if otx.success:
        enrichment["threat_intel"]["otx"] = otx.data
    
    return enrichment
