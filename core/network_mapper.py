"""
Advanced Network Mapper & Topology Visualizer
Real-time network discovery and infrastructure mapping
"""

import asyncio
import socket
import struct
import ipaddress
import json
import time
import subprocess
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import re
from collections import defaultdict


class NodeType(Enum):
    """Types of network nodes"""
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    SERVER = "server"
    WORKSTATION = "workstation"
    PRINTER = "printer"
    IOT = "iot"
    MOBILE = "mobile"
    VM = "vm"
    CONTAINER = "container"
    CLOUD = "cloud"
    LOAD_BALANCER = "load_balancer"
    DATABASE = "database"
    WEB_SERVER = "web_server"
    MAIL_SERVER = "mail_server"
    DNS_SERVER = "dns_server"
    UNKNOWN = "unknown"


class ConnectionType(Enum):
    """Types of network connections"""
    ETHERNET = "ethernet"
    WIFI = "wifi"
    VPN = "vpn"
    TUNNEL = "tunnel"
    VLAN = "vlan"
    BRIDGE = "bridge"
    NAT = "nat"
    DIRECT = "direct"
    UNKNOWN = "unknown"


@dataclass
class NetworkNode:
    """Represents a node in the network"""
    ip: str
    hostname: str = ""
    mac: str = ""
    node_type: NodeType = NodeType.UNKNOWN
    os_info: str = ""
    vendor: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    is_gateway: bool = False
    network_segment: str = ""
    risk_score: float = 0.0


@dataclass
class NetworkLink:
    """Represents a connection between nodes"""
    source: str
    target: str
    connection_type: ConnectionType = ConnectionType.UNKNOWN
    bandwidth: str = ""
    latency: float = 0.0
    hop_count: int = 1
    is_encrypted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkSegment:
    """Represents a network segment/subnet"""
    network: str
    name: str = ""
    vlan_id: int = 0
    gateway: str = ""
    nodes: List[str] = field(default_factory=list)
    is_dmz: bool = False
    is_internal: bool = True
    security_zone: str = ""


class NetworkMapper:
    """
    Advanced Network Mapping Engine
    Discovers and maps network infrastructure
    """
    
    # OUI database for vendor identification (sample)
    OUI_DATABASE = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "00:15:5D": "Microsoft Hyper-V",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:16:3E": "Xen",
        "00:1A:11": "Google Cloud",
        "02:42": "Docker",
        "AC:DE:48": "Amazon AWS",
        "00:00:5E": "IANA",
        "00:09:0F": "Fortinet",
        "00:1B:17": "Palo Alto",
        "00:1E:BD": "Cisco",
        "00:1F:A4": "Shenzhen",
        "B4:FB:E4": "Ubiquiti",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
    }
    
    # Port to service mapping
    SERVICE_SIGNATURES = {
        21: ("FTP", "file_transfer"),
        22: ("SSH", "remote_access"),
        23: ("Telnet", "remote_access"),
        25: ("SMTP", "mail"),
        53: ("DNS", "dns"),
        67: ("DHCP", "network"),
        68: ("DHCP", "network"),
        80: ("HTTP", "web"),
        110: ("POP3", "mail"),
        123: ("NTP", "time"),
        135: ("MSRPC", "windows"),
        137: ("NetBIOS", "windows"),
        138: ("NetBIOS", "windows"),
        139: ("NetBIOS", "windows"),
        143: ("IMAP", "mail"),
        161: ("SNMP", "monitoring"),
        389: ("LDAP", "directory"),
        443: ("HTTPS", "web"),
        445: ("SMB", "windows"),
        465: ("SMTPS", "mail"),
        514: ("Syslog", "logging"),
        587: ("SMTP", "mail"),
        636: ("LDAPS", "directory"),
        993: ("IMAPS", "mail"),
        995: ("POP3S", "mail"),
        1433: ("MSSQL", "database"),
        1521: ("Oracle", "database"),
        3306: ("MySQL", "database"),
        3389: ("RDP", "remote_access"),
        5432: ("PostgreSQL", "database"),
        5900: ("VNC", "remote_access"),
        6379: ("Redis", "database"),
        8080: ("HTTP-Proxy", "web"),
        8443: ("HTTPS-Alt", "web"),
        9200: ("Elasticsearch", "database"),
        27017: ("MongoDB", "database"),
    }
    
    def __init__(self):
        self.nodes: Dict[str, NetworkNode] = {}
        self.links: List[NetworkLink] = []
        self.segments: Dict[str, NetworkSegment] = {}
        self.topology: Dict[str, Any] = {}
        
    async def discover_network(self, 
                               targets: List[str],
                               scan_type: str = "fast",
                               include_traceroute: bool = True) -> Dict[str, Any]:
        """
        Main network discovery function
        
        Args:
            targets: List of IP addresses, ranges, or CIDR notations
            scan_type: 'fast', 'normal', or 'comprehensive'
            include_traceroute: Whether to trace routes between nodes
        """
        results = {
            "scan_start": datetime.now().isoformat(),
            "targets": targets,
            "nodes": [],
            "links": [],
            "segments": [],
            "topology": {},
            "statistics": {},
        }
        
        # Expand targets to individual IPs
        all_ips = self._expand_targets(targets)
        print(f"[*] Scanning {len(all_ips)} IP addresses...")
        
        # Phase 1: Host discovery
        print("[*] Phase 1: Host Discovery")
        live_hosts = await self._discover_hosts(all_ips, scan_type)
        print(f"[+] Found {len(live_hosts)} live hosts")
        
        # Phase 2: Service enumeration
        print("[*] Phase 2: Service Enumeration")
        for ip in live_hosts:
            node = await self._enumerate_host(ip, scan_type)
            self.nodes[ip] = node
            
        # Phase 3: Identify node types
        print("[*] Phase 3: Node Classification")
        for ip, node in self.nodes.items():
            node.node_type = self._classify_node(node)
            node.vendor = self._identify_vendor(node.mac)
            
        # Phase 4: Discover network segments
        print("[*] Phase 4: Network Segmentation")
        self._discover_segments()
        
        # Phase 5: Map connections
        print("[*] Phase 5: Connection Mapping")
        if include_traceroute:
            await self._map_connections(list(self.nodes.keys()))
            
        # Phase 6: Build topology
        print("[*] Phase 6: Building Topology")
        self._build_topology()
        
        # Phase 7: Risk assessment
        print("[*] Phase 7: Risk Assessment")
        self._assess_risks()
        
        # Compile results
        results["nodes"] = [n.__dict__ for n in self.nodes.values()]
        results["links"] = [l.__dict__ for l in self.links]
        results["segments"] = [s.__dict__ for s in self.segments.values()]
        results["topology"] = self.topology
        results["scan_end"] = datetime.now().isoformat()
        results["statistics"] = self._compile_statistics()
        
        return results
        
    def _expand_targets(self, targets: List[str]) -> List[str]:
        """Expand target specifications to individual IPs"""
        ips = []
        
        for target in targets:
            try:
                # Check if it's a CIDR notation
                if "/" in target:
                    network = ipaddress.ip_network(target, strict=False)
                    # Limit to /16 to avoid massive scans
                    if network.num_addresses > 65536:
                        print(f"[!] Network {target} too large, limiting to first 65536 hosts")
                        ips.extend([str(ip) for ip in list(network.hosts())[:65536]])
                    else:
                        ips.extend([str(ip) for ip in network.hosts()])
                # Check if it's a range (e.g., 192.168.1.1-100)
                elif "-" in target:
                    base, end = target.rsplit("-", 1)
                    base_parts = base.split(".")
                    start = int(base_parts[-1])
                    end_num = int(end)
                    
                    for i in range(start, end_num + 1):
                        ips.append(f"{'.'.join(base_parts[:-1])}.{i}")
                else:
                    # Single IP
                    ipaddress.ip_address(target)  # Validate
                    ips.append(target)
                    
            except ValueError as e:
                print(f"[!] Invalid target: {target} - {e}")
                
        return list(set(ips))
        
    async def _discover_hosts(self, ips: List[str], scan_type: str) -> List[str]:
        """Discover live hosts"""
        live_hosts = []
        
        # Use asyncio for parallel ping
        chunk_size = 100
        for i in range(0, len(ips), chunk_size):
            chunk = ips[i:i + chunk_size]
            tasks = [self._ping_host(ip) for ip in chunk]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for ip, is_alive in zip(chunk, results):
                if is_alive is True:
                    live_hosts.append(ip)
                    
        return live_hosts
        
    async def _ping_host(self, ip: str, timeout: float = 1.0) -> bool:
        """Check if host is alive using ping"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", str(int(timeout)), ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(proc.wait(), timeout=timeout + 1)
            return proc.returncode == 0
        except Exception:
            return False
            
    async def _enumerate_host(self, ip: str, scan_type: str) -> NetworkNode:
        """Enumerate a single host"""
        node = NetworkNode(ip=ip)
        
        # Resolve hostname
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            node.hostname = hostname
        except Exception:
            pass
            
        # Get MAC address (only works for local network)
        node.mac = await self._get_mac(ip)
        
        # Port scan
        if scan_type == "fast":
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                     3306, 3389, 5432, 5900, 8080, 8443]
        elif scan_type == "normal":
            ports = list(range(1, 1024)) + [1433, 1521, 3306, 3389, 5432, 
                                             5900, 8080, 8443, 9200, 27017]
        else:
            ports = list(range(1, 10000))
            
        open_ports = await self._scan_ports(ip, ports)
        node.open_ports = open_ports
        
        # Identify services
        for port in open_ports:
            service_info = self.SERVICE_SIGNATURES.get(port, ("Unknown", "unknown"))
            node.services[port] = service_info[0]
            
        return node
        
    async def _get_mac(self, ip: str) -> str:
        """Get MAC address for an IP"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "arp", "-n", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode()
            
            # Parse MAC from arp output
            mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
            match = re.search(mac_pattern, output)
            if match:
                return match.group(0).upper()
        except Exception:
            pass
            
        return ""
        
    async def _scan_ports(self, ip: str, ports: List[int], 
                          timeout: float = 0.5) -> List[int]:
        """Scan ports on a host"""
        open_ports = []
        
        async def check_port(port: int) -> Optional[int]:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                return port
            except Exception:
                return None
                
        # Scan in chunks to avoid overwhelming the target
        chunk_size = 50
        for i in range(0, len(ports), chunk_size):
            chunk = ports[i:i + chunk_size]
            tasks = [check_port(port) for port in chunk]
            results = await asyncio.gather(*tasks)
            
            for port in results:
                if port is not None:
                    open_ports.append(port)
                    
        return sorted(open_ports)
        
    def _classify_node(self, node: NetworkNode) -> NodeType:
        """Classify the type of node based on its characteristics"""
        ports = set(node.open_ports)
        services = set(node.services.values())
        
        # Check for routers/firewalls
        if 179 in ports or "BGP" in services:
            return NodeType.ROUTER
        if any(p in ports for p in [514, 515]) and len(ports) < 10:
            return NodeType.FIREWALL
            
        # Check for servers by service type
        if any(db in services for db in ["MySQL", "PostgreSQL", "MSSQL", "Oracle", "MongoDB", "Redis"]):
            return NodeType.DATABASE
        if "HTTP" in services or "HTTPS" in services:
            if any(db in services for db in ["MySQL", "PostgreSQL"]):
                return NodeType.WEB_SERVER
            return NodeType.WEB_SERVER
        if "SMTP" in services or "IMAP" in services or "POP3" in services:
            return NodeType.MAIL_SERVER
        if 53 in ports:
            return NodeType.DNS_SERVER
            
        # Check for network devices
        if 161 in ports and len(ports) < 5:
            return NodeType.SWITCH
            
        # Check for virtualization
        vendor = self._identify_vendor(node.mac)
        if vendor in ["VMware", "VirtualBox", "QEMU/KVM", "Microsoft Hyper-V", "Xen"]:
            return NodeType.VM
        if vendor == "Docker":
            return NodeType.CONTAINER
        if vendor in ["Amazon AWS", "Google Cloud"]:
            return NodeType.CLOUD
            
        # Check for Windows workstation
        if 135 in ports and 139 in ports and 445 in ports:
            if 3389 in ports:
                return NodeType.SERVER
            return NodeType.WORKSTATION
            
        # IoT/Embedded devices
        if len(ports) < 3 and any(p in [80, 443, 23] for p in ports):
            return NodeType.IOT
            
        # Printers
        if any(p in ports for p in [9100, 515, 631]):
            return NodeType.PRINTER
            
        return NodeType.UNKNOWN
        
    def _identify_vendor(self, mac: str) -> str:
        """Identify vendor from MAC address OUI"""
        if not mac:
            return "Unknown"
            
        # Normalize MAC
        mac_clean = mac.upper().replace("-", ":").replace(".", ":")
        
        # Check against OUI database
        for oui, vendor in self.OUI_DATABASE.items():
            if mac_clean.startswith(oui.upper()):
                return vendor
                
        return "Unknown"
        
    def _discover_segments(self):
        """Discover network segments from discovered nodes"""
        # Group nodes by /24 subnet
        subnet_nodes = defaultdict(list)
        
        for ip, node in self.nodes.items():
            try:
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
                subnet_nodes[str(network)].append(ip)
            except Exception:
                pass
                
        # Create segments
        for network_str, ips in subnet_nodes.items():
            segment = NetworkSegment(
                network=network_str,
                nodes=ips,
            )
            
            # Try to identify gateway
            for ip in ips:
                node = self.nodes.get(ip)
                if node and node.node_type in [NodeType.ROUTER, NodeType.FIREWALL]:
                    segment.gateway = ip
                    node.is_gateway = True
                    break
                    
            # Check if it's a DMZ (has web servers exposed)
            has_web = any(
                self.nodes[ip].node_type in [NodeType.WEB_SERVER, NodeType.MAIL_SERVER]
                for ip in ips if ip in self.nodes
            )
            segment.is_dmz = has_web
            
            self.segments[network_str] = segment
            
            # Update node segment references
            for ip in ips:
                if ip in self.nodes:
                    self.nodes[ip].network_segment = network_str
                    
    async def _map_connections(self, ips: List[str]):
        """Map connections between nodes using traceroute"""
        # Sample a subset for traceroute (expensive operation)
        sample_size = min(len(ips), 20)
        sample_ips = ips[:sample_size]
        
        for ip in sample_ips:
            hops = await self._traceroute(ip)
            
            # Create links from hop data
            for i in range(len(hops) - 1):
                if hops[i] and hops[i + 1]:
                    link = NetworkLink(
                        source=hops[i],
                        target=hops[i + 1],
                        connection_type=ConnectionType.DIRECT,
                        hop_count=1,
                    )
                    
                    # Avoid duplicate links
                    if not any(l.source == link.source and l.target == link.target 
                              for l in self.links):
                        self.links.append(link)
                        
    async def _traceroute(self, target: str, max_hops: int = 15) -> List[str]:
        """Perform traceroute to target"""
        hops = []
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "traceroute", "-n", "-m", str(max_hops), "-w", "1", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode()
            
            # Parse traceroute output
            ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            for line in output.split('\n'):
                match = re.search(ip_pattern, line)
                if match:
                    hops.append(match.group(1))
                    
        except Exception:
            pass
            
        return hops
        
    def _build_topology(self):
        """Build network topology structure"""
        self.topology = {
            "nodes": [],
            "edges": [],
            "clusters": [],
        }
        
        # Build nodes for visualization
        for ip, node in self.nodes.items():
            topo_node = {
                "id": ip,
                "label": node.hostname or ip,
                "type": node.node_type.value,
                "segment": node.network_segment,
                "risk_score": node.risk_score,
                "metadata": {
                    "ports": node.open_ports,
                    "services": node.services,
                    "vendor": node.vendor,
                    "os": node.os_info,
                },
            }
            self.topology["nodes"].append(topo_node)
            
        # Build edges
        for link in self.links:
            edge = {
                "source": link.source,
                "target": link.target,
                "type": link.connection_type.value,
                "metadata": link.metadata,
            }
            self.topology["edges"].append(edge)
            
        # Build clusters (segments)
        for net, segment in self.segments.items():
            cluster = {
                "id": net,
                "name": segment.name or net,
                "nodes": segment.nodes,
                "gateway": segment.gateway,
                "is_dmz": segment.is_dmz,
            }
            self.topology["clusters"].append(cluster)
            
    def _assess_risks(self):
        """Assess risk scores for each node"""
        for ip, node in self.nodes.items():
            risk_score = 0.0
            
            # High-risk services
            high_risk_ports = {
                23: 30,   # Telnet
                21: 20,   # FTP
                3389: 25, # RDP
                445: 20,  # SMB
                135: 15,  # MSRPC
                139: 15,  # NetBIOS
                161: 15,  # SNMP
                1433: 20, # MSSQL
                3306: 20, # MySQL
                5432: 20, # PostgreSQL
                27017: 25, # MongoDB
                6379: 25,  # Redis
            }
            
            for port in node.open_ports:
                risk_score += high_risk_ports.get(port, 5)
                
            # Node type risk modifiers
            type_risk = {
                NodeType.SERVER: 1.5,
                NodeType.DATABASE: 2.0,
                NodeType.DOMAIN_CONTROLLER: 2.5 if hasattr(NodeType, 'DOMAIN_CONTROLLER') else 1.0,
                NodeType.WEB_SERVER: 1.3,
                NodeType.IOT: 1.8,
                NodeType.WORKSTATION: 1.0,
            }
            
            risk_score *= type_risk.get(node.node_type, 1.0)
            
            # Normalize to 0-100
            node.risk_score = min(100, risk_score)
            
            # Generate vulnerability suggestions
            if 23 in node.open_ports:
                node.vulnerabilities.append("Telnet enabled - unencrypted remote access")
            if 21 in node.open_ports:
                node.vulnerabilities.append("FTP enabled - potential cleartext credentials")
            if 445 in node.open_ports:
                node.vulnerabilities.append("SMB exposed - potential for EternalBlue-type exploits")
            if 27017 in node.open_ports:
                node.vulnerabilities.append("MongoDB exposed - check for authentication")
            if 6379 in node.open_ports:
                node.vulnerabilities.append("Redis exposed - often unauthenticated")
                
    def _compile_statistics(self) -> Dict[str, Any]:
        """Compile scan statistics"""
        return {
            "total_nodes": len(self.nodes),
            "total_links": len(self.links),
            "total_segments": len(self.segments),
            "nodes_by_type": self._count_by_type(),
            "services_found": self._count_services(),
            "high_risk_nodes": len([n for n in self.nodes.values() if n.risk_score > 50]),
            "total_open_ports": sum(len(n.open_ports) for n in self.nodes.values()),
        }
        
    def _count_by_type(self) -> Dict[str, int]:
        """Count nodes by type"""
        counts = {}
        for node in self.nodes.values():
            node_type = node.node_type.value
            counts[node_type] = counts.get(node_type, 0) + 1
        return counts
        
    def _count_services(self) -> Dict[str, int]:
        """Count services found"""
        counts = {}
        for node in self.nodes.values():
            for service in node.services.values():
                counts[service] = counts.get(service, 0) + 1
        return counts
        
    def export_topology(self, format: str = "json") -> str:
        """Export topology in various formats"""
        if format == "json":
            return json.dumps(self.topology, indent=2)
        elif format == "graphml":
            return self._export_graphml()
        elif format == "dot":
            return self._export_dot()
        else:
            return json.dumps(self.topology, indent=2)
            
    def _export_graphml(self) -> str:
        """Export as GraphML"""
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <graph id="G" edgedefault="undirected">',
        ]
        
        for node in self.topology["nodes"]:
            lines.append(f'    <node id="{node["id"]}" label="{node["label"]}" />')
            
        for i, edge in enumerate(self.topology["edges"]):
            lines.append(f'    <edge id="e{i}" source="{edge["source"]}" target="{edge["target"]}" />')
            
        lines.extend(['  </graph>', '</graphml>'])
        return '\n'.join(lines)
        
    def _export_dot(self) -> str:
        """Export as DOT format for Graphviz"""
        lines = ["digraph network {"]
        
        # Node styles by type
        type_styles = {
            "router": 'shape=diamond,color=red',
            "server": 'shape=box,color=blue',
            "workstation": 'shape=ellipse,color=green',
            "database": 'shape=cylinder,color=purple',
            "unknown": 'shape=circle,color=gray',
        }
        
        for node in self.topology["nodes"]:
            style = type_styles.get(node["type"], type_styles["unknown"])
            lines.append(f'  "{node["id"]}" [{style},label="{node["label"]}"];')
            
        for edge in self.topology["edges"]:
            lines.append(f'  "{edge["source"]}" -> "{edge["target"]}";')
            
        lines.append("}")
        return '\n'.join(lines)


class NetworkAnalyzer:
    """
    Network Analysis Engine
    Performs advanced analysis on discovered network topology
    """
    
    def __init__(self, mapper: NetworkMapper):
        self.mapper = mapper
        
    def find_attack_paths(self, 
                          source: str, 
                          target: str) -> List[List[str]]:
        """Find potential attack paths from source to target"""
        paths = []
        
        # Build adjacency list
        adj = defaultdict(list)
        for link in self.mapper.links:
            adj[link.source].append(link.target)
            adj[link.target].append(link.source)
            
        # BFS to find paths
        queue = [(source, [source])]
        visited = set()
        
        while queue:
            current, path = queue.pop(0)
            
            if current == target:
                paths.append(path)
                continue
                
            if current in visited:
                continue
                
            visited.add(current)
            
            for neighbor in adj[current]:
                if neighbor not in visited:
                    queue.append((neighbor, path + [neighbor]))
                    
        return paths
        
    def identify_critical_nodes(self) -> List[Dict[str, Any]]:
        """Identify critical nodes that could cause major impact if compromised"""
        critical = []
        
        for ip, node in self.mapper.nodes.items():
            # Gateways are critical
            if node.is_gateway:
                critical.append({
                    "ip": ip,
                    "reason": "Network gateway",
                    "impact": "high",
                })
                continue
                
            # Databases are critical
            if node.node_type == NodeType.DATABASE:
                critical.append({
                    "ip": ip,
                    "reason": "Database server - data store",
                    "impact": "critical",
                })
                continue
                
            # DNS servers are critical
            if node.node_type == NodeType.DNS_SERVER:
                critical.append({
                    "ip": ip,
                    "reason": "DNS server - name resolution",
                    "impact": "high",
                })
                continue
                
            # High connectivity nodes
            connections = sum(1 for l in self.mapper.links 
                            if l.source == ip or l.target == ip)
            if connections > 5:
                critical.append({
                    "ip": ip,
                    "reason": f"High connectivity ({connections} connections)",
                    "impact": "medium",
                })
                
        return critical
        
    def detect_segmentation_issues(self) -> List[Dict[str, Any]]:
        """Detect network segmentation issues"""
        issues = []
        
        # Check for DMZ to internal connections
        for link in self.mapper.links:
            source_seg = self.mapper.nodes.get(link.source, NetworkNode("")).network_segment
            target_seg = self.mapper.nodes.get(link.target, NetworkNode("")).network_segment
            
            if source_seg and target_seg and source_seg != target_seg:
                source_is_dmz = self.mapper.segments.get(source_seg, NetworkSegment("")).is_dmz
                target_is_dmz = self.mapper.segments.get(target_seg, NetworkSegment("")).is_dmz
                
                if source_is_dmz != target_is_dmz:
                    issues.append({
                        "type": "dmz_internal_link",
                        "source": link.source,
                        "target": link.target,
                        "description": "Direct connection between DMZ and internal network",
                        "severity": "high",
                    })
                    
        # Check for flat network (everything in one segment)
        if len(self.mapper.segments) == 1 and len(self.mapper.nodes) > 10:
            issues.append({
                "type": "flat_network",
                "description": "Flat network topology detected - no segmentation",
                "severity": "medium",
            })
            
        return issues


# Async helper function
async def map_network(targets: List[str], **kwargs) -> Dict[str, Any]:
    """Convenience function to map a network"""
    mapper = NetworkMapper()
    results = await mapper.discover_network(targets, **kwargs)
    
    # Run analysis
    analyzer = NetworkAnalyzer(mapper)
    results["critical_nodes"] = analyzer.identify_critical_nodes()
    results["segmentation_issues"] = analyzer.detect_segmentation_issues()
    
    return results


if __name__ == "__main__":
    import sys
    
    async def main():
        if len(sys.argv) < 2:
            print("Usage: python network_mapper.py <target_range>")
            print("Example: python network_mapper.py 192.168.1.0/24")
            sys.exit(1)
            
        target = sys.argv[1]
        
        print(f"\n{'='*60}")
        print(f"Network Mapper - Target: {target}")
        print(f"{'='*60}\n")
        
        results = await map_network([target], scan_type="fast")
        
        print(f"\n[+] Scan Results:")
        print(f"    Nodes discovered: {results['statistics']['total_nodes']}")
        print(f"    Segments found: {results['statistics']['total_segments']}")
        print(f"    High-risk nodes: {results['statistics']['high_risk_nodes']}")
        
        print(f"\n[*] Nodes by type:")
        for node_type, count in results['statistics']['nodes_by_type'].items():
            print(f"    {node_type}: {count}")
            
        if results['critical_nodes']:
            print(f"\n[!] Critical nodes:")
            for node in results['critical_nodes'][:5]:
                print(f"    {node['ip']}: {node['reason']}")
                
    asyncio.run(main())
