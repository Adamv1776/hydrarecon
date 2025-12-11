"""
Asset Inventory Module for HydraRecon
Comprehensive asset discovery, tracking, and management
"""

import asyncio
import json
import socket
import struct
import subprocess
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import uuid
import logging

logger = logging.getLogger(__name__)


class AssetType(Enum):
    """Types of assets"""
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    FIREWALL = "firewall"
    ROUTER = "router"
    SWITCH = "switch"
    LOAD_BALANCER = "load_balancer"
    DATABASE = "database"
    WEB_SERVER = "web_server"
    APPLICATION_SERVER = "application_server"
    STORAGE = "storage"
    PRINTER = "printer"
    IOT_DEVICE = "iot_device"
    MOBILE_DEVICE = "mobile_device"
    VIRTUAL_MACHINE = "virtual_machine"
    CONTAINER = "container"
    CLOUD_INSTANCE = "cloud_instance"
    API_ENDPOINT = "api_endpoint"
    DOMAIN = "domain"
    CERTIFICATE = "certificate"
    UNKNOWN = "unknown"


class AssetStatus(Enum):
    """Asset operational status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"
    DECOMMISSIONED = "decommissioned"
    UNKNOWN = "unknown"


class Criticality(Enum):
    """Asset criticality levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class DiscoveryMethod(Enum):
    """How the asset was discovered"""
    NETWORK_SCAN = "network_scan"
    ARP_DISCOVERY = "arp_discovery"
    DNS_ENUMERATION = "dns_enumeration"
    MANUAL_ENTRY = "manual_entry"
    IMPORT = "import"
    API_INTEGRATION = "api_integration"
    AGENT_REPORT = "agent_report"
    CLOUD_SYNC = "cloud_sync"
    OSINT = "osint"


@dataclass
class NetworkInterface:
    """Network interface details"""
    mac_address: str
    ip_addresses: List[str]
    interface_name: str = ""
    speed: str = ""
    is_primary: bool = False
    vlan_id: Optional[int] = None


@dataclass
class Software:
    """Software installed on asset"""
    name: str
    version: str
    vendor: str = ""
    install_date: Optional[datetime] = None
    is_security_related: bool = False
    cpe: str = ""  # Common Platform Enumeration


@dataclass
class Service:
    """Service running on asset"""
    name: str
    port: int
    protocol: str = "tcp"
    version: str = ""
    state: str = "running"
    banner: str = ""
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class Credential:
    """Credentials associated with asset"""
    username: str
    credential_type: str  # password, ssh_key, api_key, certificate
    last_rotated: Optional[datetime] = None
    is_default: bool = False
    is_weak: bool = False
    privileged: bool = False


@dataclass
class Asset:
    """Comprehensive asset representation"""
    id: str
    name: str
    asset_type: AssetType
    status: AssetStatus
    criticality: Criticality
    
    # Network info
    primary_ip: str
    hostname: str = ""
    fqdn: str = ""
    network_interfaces: List[NetworkInterface] = field(default_factory=list)
    
    # System info
    os_family: str = ""
    os_version: str = ""
    os_build: str = ""
    architecture: str = ""
    manufacturer: str = ""
    model: str = ""
    serial_number: str = ""
    
    # Software and services
    software: List[Software] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    
    # Security info
    credentials: List[Credential] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    last_vulnerability_scan: Optional[datetime] = None
    last_pentest: Optional[datetime] = None
    
    # Location and ownership
    location: str = ""
    data_center: str = ""
    rack: str = ""
    owner: str = ""
    department: str = ""
    business_unit: str = ""
    cost_center: str = ""
    
    # Relationships
    parent_id: Optional[str] = None
    child_ids: List[str] = field(default_factory=list)
    connected_to: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    
    # Discovery and tracking
    discovery_method: DiscoveryMethod = DiscoveryMethod.MANUAL_ENTRY
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    
    # Tags and metadata
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    
    # Compliance
    compliance_tags: List[str] = field(default_factory=list)  # PCI, HIPAA, etc.
    in_scope: bool = True


@dataclass
class AssetGroup:
    """Group of assets"""
    id: str
    name: str
    description: str = ""
    asset_ids: List[str] = field(default_factory=list)
    parent_group_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class DiscoveryScan:
    """Asset discovery scan results"""
    id: str
    scan_type: str
    target_range: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"
    discovered_assets: int = 0
    new_assets: int = 0
    updated_assets: int = 0
    errors: List[str] = field(default_factory=list)


class AssetDiscoverer:
    """Discovers assets on the network"""
    
    def __init__(self):
        self.discovered_hosts: List[Dict[str, Any]] = []
    
    async def arp_scan(self, network: str) -> List[Dict[str, str]]:
        """Perform ARP scan to discover hosts"""
        results = []
        try:
            # Use arp-scan if available
            cmd = ["arp-scan", "--localnet", network, "-q"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            
            for line in stdout.decode().strip().split('\n'):
                if line and not line.startswith('#'):
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        results.append({
                            "ip": parts[0],
                            "mac": parts[1],
                            "vendor": parts[2] if len(parts) > 2 else ""
                        })
        except Exception as e:
            logger.warning(f"ARP scan failed: {e}")
        
        return results
    
    async def ping_sweep(self, network: str) -> List[str]:
        """Perform ping sweep to discover live hosts"""
        live_hosts = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            tasks = []
            
            for ip in net.hosts():
                tasks.append(self._ping_host(str(ip)))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for ip, result in zip(net.hosts(), results):
                if result is True:
                    live_hosts.append(str(ip))
        except Exception as e:
            logger.error(f"Ping sweep failed: {e}")
        
        return live_hosts
    
    async def _ping_host(self, ip: str) -> bool:
        """Ping a single host"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "1", ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
            return proc.returncode == 0
        except:
            return False
    
    async def dns_discovery(self, domain: str) -> List[Dict[str, Any]]:
        """Discover assets via DNS enumeration"""
        discovered = []
        
        # Common subdomain prefixes
        prefixes = [
            "www", "mail", "smtp", "pop", "imap", "ftp", "ssh",
            "vpn", "remote", "rdp", "citrix", "webmail", "portal",
            "api", "app", "dev", "test", "staging", "prod", "uat",
            "db", "database", "sql", "mysql", "postgres", "mongo",
            "web", "www1", "www2", "proxy", "ns", "ns1", "ns2",
            "dns", "ldap", "dc", "ad", "exchange", "owa",
            "sso", "auth", "login", "git", "gitlab", "github",
            "jenkins", "ci", "cd", "docker", "k8s", "kubernetes",
            "elastic", "kibana", "grafana", "prometheus", "splunk",
            "nagios", "zabbix", "monitoring", "backup", "storage"
        ]
        
        for prefix in prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                ips = socket.gethostbyname_ex(subdomain)[2]
                for ip in ips:
                    discovered.append({
                        "hostname": subdomain,
                        "ip": ip,
                        "type": self._guess_type_from_name(prefix)
                    })
            except socket.gaierror:
                continue
        
        return discovered
    
    def _guess_type_from_name(self, name: str) -> AssetType:
        """Guess asset type from hostname/prefix"""
        type_map = {
            "db": AssetType.DATABASE,
            "database": AssetType.DATABASE,
            "sql": AssetType.DATABASE,
            "mysql": AssetType.DATABASE,
            "postgres": AssetType.DATABASE,
            "mongo": AssetType.DATABASE,
            "web": AssetType.WEB_SERVER,
            "www": AssetType.WEB_SERVER,
            "app": AssetType.APPLICATION_SERVER,
            "api": AssetType.API_ENDPOINT,
            "mail": AssetType.SERVER,
            "smtp": AssetType.SERVER,
            "ftp": AssetType.SERVER,
            "ns": AssetType.NETWORK_DEVICE,
            "dns": AssetType.NETWORK_DEVICE,
            "vpn": AssetType.NETWORK_DEVICE,
            "fw": AssetType.FIREWALL,
            "firewall": AssetType.FIREWALL,
            "router": AssetType.ROUTER,
            "switch": AssetType.SWITCH,
            "lb": AssetType.LOAD_BALANCER,
            "docker": AssetType.CONTAINER,
            "k8s": AssetType.CONTAINER,
        }
        
        return type_map.get(name.lower(), AssetType.SERVER)
    
    async def port_scan(self, ip: str, ports: List[int] = None) -> List[Service]:
        """Scan ports on a host"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                    445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 
                    8080, 8443, 27017]
        
        services = []
        tasks = []
        
        for port in ports:
            tasks.append(self._check_port(ip, port))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for port, result in zip(ports, results):
            if isinstance(result, Service):
                services.append(result)
        
        return services
    
    async def _check_port(self, ip: str, port: int) -> Optional[Service]:
        """Check if a port is open and grab banner"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2.0
            )
            
            # Try to grab banner
            banner = ""
            try:
                writer.write(b"\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode('utf-8', errors='ignore').strip()
            except:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            return Service(
                name=self._guess_service(port),
                port=port,
                protocol="tcp",
                state="open",
                banner=banner[:256] if banner else ""
            )
        except:
            return None
    
    def _guess_service(self, port: int) -> str:
        """Guess service name from port"""
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
            139: "netbios", 143: "imap", 443: "https", 445: "smb",
            993: "imaps", 995: "pop3s", 1433: "mssql", 1723: "pptp",
            3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
            6379: "redis", 8080: "http-proxy", 8443: "https-alt",
            27017: "mongodb"
        }
        return services.get(port, f"unknown-{port}")
    
    async def os_fingerprint(self, ip: str) -> Dict[str, str]:
        """Attempt OS fingerprinting"""
        result = {"os_family": "", "os_version": "", "confidence": "low"}
        
        try:
            # Try nmap OS detection
            cmd = ["nmap", "-O", "--osscan-guess", "-T4", ip]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode()
            
            # Parse OS detection results
            for line in output.split('\n'):
                if "OS details:" in line or "Running:" in line:
                    os_info = line.split(':', 1)[1].strip()
                    if "Windows" in os_info:
                        result["os_family"] = "Windows"
                    elif "Linux" in os_info:
                        result["os_family"] = "Linux"
                    elif "Mac" in os_info or "Darwin" in os_info:
                        result["os_family"] = "macOS"
                    result["os_version"] = os_info
                    result["confidence"] = "high"
                    break
        except Exception as e:
            logger.warning(f"OS fingerprinting failed for {ip}: {e}")
        
        return result


class AssetInventoryEngine:
    """Main asset inventory management engine"""
    
    def __init__(self, db_path: str = "assets.db"):
        self.db_path = db_path
        self.assets: Dict[str, Asset] = {}
        self.groups: Dict[str, AssetGroup] = {}
        self.scans: Dict[str, DiscoveryScan] = {}
        self.discoverer = AssetDiscoverer()
        self._lock = asyncio.Lock()
    
    async def discover_network(
        self,
        target: str,
        methods: List[DiscoveryMethod] = None,
        callback=None
    ) -> DiscoveryScan:
        """Run network discovery"""
        if methods is None:
            methods = [DiscoveryMethod.NETWORK_SCAN, DiscoveryMethod.ARP_DISCOVERY]
        
        scan_id = str(uuid.uuid4())
        scan = DiscoveryScan(
            id=scan_id,
            scan_type="network_discovery",
            target_range=target,
            start_time=datetime.now()
        )
        self.scans[scan_id] = scan
        
        try:
            discovered_ips = set()
            
            # ARP discovery
            if DiscoveryMethod.ARP_DISCOVERY in methods:
                if callback:
                    callback("status", "Running ARP discovery...")
                arp_results = await self.discoverer.arp_scan(target)
                for result in arp_results:
                    discovered_ips.add(result["ip"])
                    await self._create_or_update_asset(
                        result["ip"],
                        mac=result.get("mac"),
                        vendor=result.get("vendor"),
                        method=DiscoveryMethod.ARP_DISCOVERY
                    )
            
            # Ping sweep
            if DiscoveryMethod.NETWORK_SCAN in methods:
                if callback:
                    callback("status", "Running ping sweep...")
                live_hosts = await self.discoverer.ping_sweep(target)
                for ip in live_hosts:
                    discovered_ips.add(ip)
            
            # Port scan discovered hosts
            total = len(discovered_ips)
            for i, ip in enumerate(discovered_ips):
                if callback:
                    callback("progress", f"Scanning {ip} ({i+1}/{total})")
                
                services = await self.discoverer.port_scan(ip)
                os_info = await self.discoverer.os_fingerprint(ip)
                
                asset = await self._create_or_update_asset(
                    ip,
                    services=services,
                    os_info=os_info,
                    method=DiscoveryMethod.NETWORK_SCAN
                )
                
                if asset:
                    if asset.first_seen == asset.last_seen:
                        scan.new_assets += 1
                    else:
                        scan.updated_assets += 1
            
            scan.discovered_assets = len(discovered_ips)
            scan.status = "completed"
            
        except Exception as e:
            scan.status = "failed"
            scan.errors.append(str(e))
            logger.error(f"Discovery scan failed: {e}")
        
        scan.end_time = datetime.now()
        return scan
    
    async def _create_or_update_asset(
        self,
        ip: str,
        mac: str = None,
        vendor: str = None,
        services: List[Service] = None,
        os_info: Dict[str, str] = None,
        method: DiscoveryMethod = DiscoveryMethod.NETWORK_SCAN
    ) -> Optional[Asset]:
        """Create or update an asset"""
        async with self._lock:
            # Check if asset exists by IP
            existing = None
            for asset in self.assets.values():
                if asset.primary_ip == ip:
                    existing = asset
                    break
            
            if existing:
                # Update existing asset
                existing.last_seen = datetime.now()
                existing.last_updated = datetime.now()
                
                if services:
                    existing.services = services
                    existing.open_ports = [s.port for s in services]
                
                if os_info:
                    if os_info.get("os_family"):
                        existing.os_family = os_info["os_family"]
                    if os_info.get("os_version"):
                        existing.os_version = os_info["os_version"]
                
                if mac and not existing.network_interfaces:
                    existing.network_interfaces = [
                        NetworkInterface(mac_address=mac, ip_addresses=[ip], is_primary=True)
                    ]
                
                if vendor:
                    existing.manufacturer = vendor
                
                return existing
            else:
                # Create new asset
                asset_id = str(uuid.uuid4())
                
                # Try to get hostname
                hostname = ""
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    pass
                
                # Determine asset type
                asset_type = AssetType.UNKNOWN
                if services:
                    if any(s.port in [80, 443, 8080, 8443] for s in services):
                        asset_type = AssetType.WEB_SERVER
                    elif any(s.port in [3306, 5432, 1433, 27017] for s in services):
                        asset_type = AssetType.DATABASE
                    elif any(s.port == 22 for s in services):
                        asset_type = AssetType.SERVER
                    elif any(s.port == 3389 for s in services):
                        asset_type = AssetType.WORKSTATION
                
                asset = Asset(
                    id=asset_id,
                    name=hostname or ip,
                    asset_type=asset_type,
                    status=AssetStatus.ACTIVE,
                    criticality=Criticality.MEDIUM,
                    primary_ip=ip,
                    hostname=hostname,
                    discovery_method=method,
                    services=services or [],
                    open_ports=[s.port for s in services] if services else []
                )
                
                if mac:
                    asset.network_interfaces = [
                        NetworkInterface(mac_address=mac, ip_addresses=[ip], is_primary=True)
                    ]
                
                if vendor:
                    asset.manufacturer = vendor
                
                if os_info:
                    asset.os_family = os_info.get("os_family", "")
                    asset.os_version = os_info.get("os_version", "")
                
                self.assets[asset_id] = asset
                return asset
    
    def add_asset(self, asset: Asset) -> str:
        """Manually add an asset"""
        if not asset.id:
            asset.id = str(uuid.uuid4())
        self.assets[asset.id] = asset
        return asset.id
    
    def update_asset(self, asset_id: str, updates: Dict[str, Any]) -> bool:
        """Update asset properties"""
        if asset_id not in self.assets:
            return False
        
        asset = self.assets[asset_id]
        for key, value in updates.items():
            if hasattr(asset, key):
                setattr(asset, key, value)
        
        asset.last_updated = datetime.now()
        return True
    
    def delete_asset(self, asset_id: str) -> bool:
        """Delete an asset"""
        if asset_id in self.assets:
            del self.assets[asset_id]
            return True
        return False
    
    def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Get asset by ID"""
        return self.assets.get(asset_id)
    
    def search_assets(
        self,
        query: str = None,
        asset_type: AssetType = None,
        status: AssetStatus = None,
        criticality: Criticality = None,
        tags: List[str] = None,
        ip_range: str = None,
        os_family: str = None
    ) -> List[Asset]:
        """Search assets with filters"""
        results = []
        
        for asset in self.assets.values():
            # Text query
            if query:
                query_lower = query.lower()
                searchable = f"{asset.name} {asset.hostname} {asset.primary_ip} {asset.os_version}".lower()
                if query_lower not in searchable:
                    continue
            
            # Type filter
            if asset_type and asset.asset_type != asset_type:
                continue
            
            # Status filter
            if status and asset.status != status:
                continue
            
            # Criticality filter
            if criticality and asset.criticality != criticality:
                continue
            
            # Tags filter
            if tags and not any(t in asset.tags for t in tags):
                continue
            
            # IP range filter
            if ip_range:
                try:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    if ipaddress.ip_address(asset.primary_ip) not in network:
                        continue
                except:
                    pass
            
            # OS filter
            if os_family and os_family.lower() not in asset.os_family.lower():
                continue
            
            results.append(asset)
        
        return results
    
    def create_group(self, name: str, description: str = "", asset_ids: List[str] = None) -> AssetGroup:
        """Create an asset group"""
        group = AssetGroup(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            asset_ids=asset_ids or []
        )
        self.groups[group.id] = group
        return group
    
    def add_to_group(self, group_id: str, asset_ids: List[str]) -> bool:
        """Add assets to a group"""
        if group_id not in self.groups:
            return False
        
        group = self.groups[group_id]
        for asset_id in asset_ids:
            if asset_id in self.assets and asset_id not in group.asset_ids:
                group.asset_ids.append(asset_id)
        
        return True
    
    def remove_from_group(self, group_id: str, asset_ids: List[str]) -> bool:
        """Remove assets from a group"""
        if group_id not in self.groups:
            return False
        
        group = self.groups[group_id]
        group.asset_ids = [aid for aid in group.asset_ids if aid not in asset_ids]
        return True
    
    def get_asset_statistics(self) -> Dict[str, Any]:
        """Get asset inventory statistics"""
        stats = {
            "total_assets": len(self.assets),
            "by_type": {},
            "by_status": {},
            "by_criticality": {},
            "by_os": {},
            "recently_discovered": 0,
            "stale_assets": 0,
            "with_vulnerabilities": 0,
            "high_risk": 0
        }
        
        now = datetime.now()
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        for asset in self.assets.values():
            # By type
            type_name = asset.asset_type.value
            stats["by_type"][type_name] = stats["by_type"].get(type_name, 0) + 1
            
            # By status
            status_name = asset.status.value
            stats["by_status"][status_name] = stats["by_status"].get(status_name, 0) + 1
            
            # By criticality
            crit_name = asset.criticality.value
            stats["by_criticality"][crit_name] = stats["by_criticality"].get(crit_name, 0) + 1
            
            # By OS
            os_name = asset.os_family or "Unknown"
            stats["by_os"][os_name] = stats["by_os"].get(os_name, 0) + 1
            
            # Recent discoveries
            if asset.first_seen >= week_ago:
                stats["recently_discovered"] += 1
            
            # Stale assets
            if asset.last_seen < month_ago:
                stats["stale_assets"] += 1
            
            # Vulnerabilities
            if asset.vulnerabilities:
                stats["with_vulnerabilities"] += 1
            
            # High risk
            if asset.risk_score >= 7.0 or asset.criticality == Criticality.CRITICAL:
                stats["high_risk"] += 1
        
        return stats
    
    def calculate_risk_score(self, asset_id: str) -> float:
        """Calculate risk score for an asset"""
        asset = self.assets.get(asset_id)
        if not asset:
            return 0.0
        
        score = 0.0
        
        # Base score from criticality
        criticality_scores = {
            Criticality.CRITICAL: 4.0,
            Criticality.HIGH: 3.0,
            Criticality.MEDIUM: 2.0,
            Criticality.LOW: 1.0,
            Criticality.INFORMATIONAL: 0.5
        }
        score += criticality_scores.get(asset.criticality, 2.0)
        
        # Vulnerabilities
        vuln_count = len(asset.vulnerabilities)
        if vuln_count > 10:
            score += 3.0
        elif vuln_count > 5:
            score += 2.0
        elif vuln_count > 0:
            score += 1.0
        
        # Exposed services
        risky_ports = {22, 23, 3389, 5900, 445, 21}
        exposed_risky = len(set(asset.open_ports) & risky_ports)
        score += exposed_risky * 0.5
        
        # Default/weak credentials
        weak_creds = sum(1 for c in asset.credentials if c.is_weak or c.is_default)
        score += weak_creds * 0.5
        
        # Outdated OS
        if asset.os_version:
            old_patterns = ["Windows 7", "Windows XP", "Windows Server 2008", 
                          "Ubuntu 14", "CentOS 6", "Debian 8"]
            if any(p in asset.os_version for p in old_patterns):
                score += 1.5
        
        # No recent security scan
        if asset.last_vulnerability_scan:
            days_since_scan = (datetime.now() - asset.last_vulnerability_scan).days
            if days_since_scan > 90:
                score += 1.0
            elif days_since_scan > 30:
                score += 0.5
        else:
            score += 1.0
        
        # Cap at 10
        return min(10.0, score)
    
    def export_inventory(self, format: str = "json") -> str:
        """Export asset inventory"""
        if format == "json":
            data = {
                "export_date": datetime.now().isoformat(),
                "total_assets": len(self.assets),
                "assets": []
            }
            
            for asset in self.assets.values():
                asset_dict = {
                    "id": asset.id,
                    "name": asset.name,
                    "type": asset.asset_type.value,
                    "status": asset.status.value,
                    "criticality": asset.criticality.value,
                    "primary_ip": asset.primary_ip,
                    "hostname": asset.hostname,
                    "os_family": asset.os_family,
                    "os_version": asset.os_version,
                    "open_ports": asset.open_ports,
                    "risk_score": asset.risk_score,
                    "first_seen": asset.first_seen.isoformat(),
                    "last_seen": asset.last_seen.isoformat(),
                    "tags": asset.tags
                }
                data["assets"].append(asset_dict)
            
            return json.dumps(data, indent=2)
        
        elif format == "csv":
            lines = ["id,name,type,status,criticality,ip,hostname,os,ports,risk_score"]
            for asset in self.assets.values():
                ports = ";".join(str(p) for p in asset.open_ports)
                lines.append(f"{asset.id},{asset.name},{asset.asset_type.value},"
                           f"{asset.status.value},{asset.criticality.value},"
                           f"{asset.primary_ip},{asset.hostname},"
                           f"{asset.os_family},{ports},{asset.risk_score}")
            return "\n".join(lines)
        
        return ""
    
    def import_inventory(self, data: str, format: str = "json") -> int:
        """Import assets from file"""
        imported = 0
        
        if format == "json":
            try:
                parsed = json.loads(data)
                for asset_data in parsed.get("assets", []):
                    asset = Asset(
                        id=asset_data.get("id", str(uuid.uuid4())),
                        name=asset_data.get("name", ""),
                        asset_type=AssetType(asset_data.get("type", "unknown")),
                        status=AssetStatus(asset_data.get("status", "unknown")),
                        criticality=Criticality(asset_data.get("criticality", "medium")),
                        primary_ip=asset_data.get("primary_ip", ""),
                        hostname=asset_data.get("hostname", ""),
                        os_family=asset_data.get("os_family", ""),
                        os_version=asset_data.get("os_version", ""),
                        open_ports=asset_data.get("open_ports", []),
                        risk_score=asset_data.get("risk_score", 0.0),
                        tags=asset_data.get("tags", [])
                    )
                    asset.discovery_method = DiscoveryMethod.IMPORT
                    self.assets[asset.id] = asset
                    imported += 1
            except Exception as e:
                logger.error(f"Import failed: {e}")
        
        return imported
    
    def get_network_topology(self) -> Dict[str, Any]:
        """Generate network topology data for visualization"""
        nodes = []
        edges = []
        
        for asset in self.assets.values():
            node = {
                "id": asset.id,
                "label": asset.name,
                "type": asset.asset_type.value,
                "ip": asset.primary_ip,
                "criticality": asset.criticality.value,
                "risk_score": asset.risk_score
            }
            nodes.append(node)
            
            # Add edges for connections
            for connected_id in asset.connected_to:
                if connected_id in self.assets:
                    edges.append({
                        "from": asset.id,
                        "to": connected_id,
                        "type": "connection"
                    })
            
            # Add edges for dependencies
            for dep_id in asset.dependencies:
                if dep_id in self.assets:
                    edges.append({
                        "from": asset.id,
                        "to": dep_id,
                        "type": "dependency"
                    })
        
        return {"nodes": nodes, "edges": edges}
