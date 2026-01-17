"""
HydraRecon - Network Topology Mapper
Advanced network visualization and automatic topology discovery

This module provides intelligent network mapping with:
- Automatic network discovery and device fingerprinting
- Visual topology representation with node relationships
- Real-time network change detection
- Security zone identification and segmentation analysis
- Traffic flow visualization
"""

import asyncio
import json
import uuid
import random
import math
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any, Set, Tuple
from pathlib import Path


class DeviceType(Enum):
    """Types of network devices"""
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    SERVER = "server"
    WORKSTATION = "workstation"
    PRINTER = "printer"
    IOT = "iot"
    MOBILE = "mobile"
    WIRELESS_AP = "wireless_ap"
    LOAD_BALANCER = "load_balancer"
    DATABASE = "database"
    STORAGE = "storage"
    VIRTUAL = "virtual"
    CLOUD = "cloud"
    UNKNOWN = "unknown"


class SecurityZone(Enum):
    """Network security zones"""
    EXTERNAL = "external"
    DMZ = "dmz"
    INTERNAL = "internal"
    MANAGEMENT = "management"
    RESTRICTED = "restricted"
    GUEST = "guest"
    QUARANTINE = "quarantine"


class ConnectionType(Enum):
    """Types of network connections"""
    ETHERNET = "ethernet"
    FIBER = "fiber"
    WIRELESS = "wireless"
    VPN = "vpn"
    TUNNEL = "tunnel"
    VLAN = "vlan"
    INTERNET = "internet"


@dataclass
class NetworkNode:
    """Represents a node in the network topology"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    ip_address: str = ""
    mac_address: str = ""
    hostname: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    os_type: str = ""
    os_version: str = ""
    vendor: str = ""
    model: str = ""
    security_zone: SecurityZone = SecurityZone.INTERNAL
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    is_gateway: bool = False
    is_critical: bool = False
    is_compromised: bool = False
    last_seen: datetime = field(default_factory=datetime.now)
    first_seen: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Visual properties
    x: float = 0.0
    y: float = 0.0
    layer: int = 0


@dataclass
class NetworkEdge:
    """Represents a connection between nodes"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    source_id: str = ""
    target_id: str = ""
    connection_type: ConnectionType = ConnectionType.ETHERNET
    bandwidth: str = ""
    latency_ms: float = 0.0
    packet_loss: float = 0.0
    is_encrypted: bool = False
    is_active: bool = True
    traffic_bytes: int = 0
    protocol: str = ""
    vlan_id: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Subnet:
    """Represents a network subnet"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    cidr: str = ""
    gateway: str = ""
    vlan_id: Optional[int] = None
    security_zone: SecurityZone = SecurityZone.INTERNAL
    nodes: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class TopologyScan:
    """Represents a topology scan result"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    target_network: str = ""
    nodes_discovered: int = 0
    edges_discovered: int = 0
    subnets_discovered: int = 0
    status: str = "pending"
    findings: List[Dict] = field(default_factory=list)


class NetworkTopologyMapper:
    """
    Advanced network topology discovery and visualization engine
    
    Features:
    - Automatic device discovery and fingerprinting
    - Layer-based topology organization
    - Security zone mapping
    - Traffic flow analysis
    - Change detection and alerting
    """
    
    def __init__(self):
        self.nodes: Dict[str, NetworkNode] = {}
        self.edges: Dict[str, NetworkEdge] = {}
        self.subnets: Dict[str, Subnet] = {}
        self.scans: List[TopologyScan] = []
        
        # Statistics
        self.stats = {
            "total_nodes": 0,
            "total_edges": 0,
            "total_subnets": 0,
            "devices_by_type": {},
            "zones_count": {},
            "critical_assets": 0,
            "compromised_hosts": 0,
            "last_scan": None,
        }
        
        # Initialize with sample network
        self._generate_sample_network()
        
    def _generate_sample_network(self):
        """Generate a realistic sample enterprise network"""
        
        # Create subnets
        subnets_data = [
            {"name": "External", "cidr": "203.0.113.0/24", "zone": SecurityZone.EXTERNAL, "vlan": 1},
            {"name": "DMZ", "cidr": "10.0.1.0/24", "zone": SecurityZone.DMZ, "vlan": 10},
            {"name": "Servers", "cidr": "10.0.10.0/24", "zone": SecurityZone.INTERNAL, "vlan": 20},
            {"name": "Workstations", "cidr": "10.0.20.0/24", "zone": SecurityZone.INTERNAL, "vlan": 30},
            {"name": "Management", "cidr": "10.0.100.0/24", "zone": SecurityZone.MANAGEMENT, "vlan": 100},
            {"name": "Guest WiFi", "cidr": "192.168.200.0/24", "zone": SecurityZone.GUEST, "vlan": 200},
        ]
        
        for sd in subnets_data:
            subnet = Subnet(
                name=sd["name"],
                cidr=sd["cidr"],
                security_zone=sd["zone"],
                vlan_id=sd["vlan"],
                gateway=sd["cidr"].replace(".0/24", ".1")
            )
            self.subnets[subnet.id] = subnet
            
        # Create network devices
        devices = [
            # Core infrastructure
            {
                "name": "edge-fw-01", "ip": "203.0.113.1", "type": DeviceType.FIREWALL,
                "zone": SecurityZone.EXTERNAL, "vendor": "Palo Alto", "model": "PA-3260",
                "is_gateway": True, "is_critical": True, "layer": 0
            },
            {
                "name": "core-rtr-01", "ip": "10.0.0.1", "type": DeviceType.ROUTER,
                "zone": SecurityZone.INTERNAL, "vendor": "Cisco", "model": "ASR 1001-X",
                "is_gateway": True, "is_critical": True, "layer": 1
            },
            {
                "name": "core-sw-01", "ip": "10.0.0.2", "type": DeviceType.SWITCH,
                "zone": SecurityZone.INTERNAL, "vendor": "Cisco", "model": "Catalyst 9500",
                "is_critical": True, "layer": 2
            },
            {
                "name": "core-sw-02", "ip": "10.0.0.3", "type": DeviceType.SWITCH,
                "zone": SecurityZone.INTERNAL, "vendor": "Cisco", "model": "Catalyst 9500",
                "is_critical": True, "layer": 2
            },
            
            # DMZ
            {
                "name": "dmz-fw-01", "ip": "10.0.1.1", "type": DeviceType.FIREWALL,
                "zone": SecurityZone.DMZ, "vendor": "Fortinet", "model": "FortiGate 200F",
                "is_critical": True, "layer": 2
            },
            {
                "name": "web-01", "ip": "10.0.1.10", "type": DeviceType.SERVER,
                "zone": SecurityZone.DMZ, "vendor": "Dell", "model": "PowerEdge R750",
                "os_type": "Linux", "os_version": "Ubuntu 22.04",
                "ports": [80, 443], "layer": 3
            },
            {
                "name": "web-02", "ip": "10.0.1.11", "type": DeviceType.SERVER,
                "zone": SecurityZone.DMZ, "vendor": "Dell", "model": "PowerEdge R750",
                "os_type": "Linux", "os_version": "Ubuntu 22.04",
                "ports": [80, 443], "layer": 3
            },
            {
                "name": "lb-01", "ip": "10.0.1.5", "type": DeviceType.LOAD_BALANCER,
                "zone": SecurityZone.DMZ, "vendor": "F5", "model": "BIG-IP i5800",
                "is_critical": True, "layer": 3
            },
            {
                "name": "mail-01", "ip": "10.0.1.20", "type": DeviceType.SERVER,
                "zone": SecurityZone.DMZ, "vendor": "HPE", "model": "ProLiant DL380",
                "os_type": "Windows", "os_version": "Server 2022",
                "ports": [25, 587, 993], "layer": 3
            },
            
            # Internal Servers
            {
                "name": "dc-01", "ip": "10.0.10.10", "type": DeviceType.SERVER,
                "zone": SecurityZone.INTERNAL, "vendor": "Dell", "model": "PowerEdge R750",
                "os_type": "Windows", "os_version": "Server 2022",
                "ports": [53, 88, 389, 636, 3268], "is_critical": True, "layer": 3
            },
            {
                "name": "dc-02", "ip": "10.0.10.11", "type": DeviceType.SERVER,
                "zone": SecurityZone.INTERNAL, "vendor": "Dell", "model": "PowerEdge R750",
                "os_type": "Windows", "os_version": "Server 2022",
                "ports": [53, 88, 389, 636, 3268], "is_critical": True, "layer": 3
            },
            {
                "name": "db-01", "ip": "10.0.10.20", "type": DeviceType.DATABASE,
                "zone": SecurityZone.INTERNAL, "vendor": "Dell", "model": "PowerEdge R750",
                "os_type": "Linux", "os_version": "RHEL 8",
                "ports": [1433, 3306, 5432], "is_critical": True, "layer": 3
            },
            {
                "name": "db-02", "ip": "10.0.10.21", "type": DeviceType.DATABASE,
                "zone": SecurityZone.INTERNAL, "vendor": "Dell", "model": "PowerEdge R750",
                "os_type": "Linux", "os_version": "RHEL 8",
                "ports": [1433, 3306, 5432], "is_critical": True, "layer": 3
            },
            {
                "name": "file-01", "ip": "10.0.10.30", "type": DeviceType.STORAGE,
                "zone": SecurityZone.INTERNAL, "vendor": "NetApp", "model": "FAS8700",
                "ports": [445, 2049], "is_critical": True, "layer": 3
            },
            {
                "name": "app-01", "ip": "10.0.10.40", "type": DeviceType.SERVER,
                "zone": SecurityZone.INTERNAL, "vendor": "Dell", "model": "PowerEdge R640",
                "os_type": "Linux", "os_version": "CentOS 8",
                "ports": [8080, 8443], "layer": 3
            },
            {
                "name": "app-02", "ip": "10.0.10.41", "type": DeviceType.SERVER,
                "zone": SecurityZone.INTERNAL, "vendor": "Dell", "model": "PowerEdge R640",
                "os_type": "Linux", "os_version": "CentOS 8",
                "ports": [8080, 8443], "layer": 3
            },
            
            # Workstations
            {
                "name": "ws-it-01", "ip": "10.0.20.10", "type": DeviceType.WORKSTATION,
                "zone": SecurityZone.INTERNAL, "vendor": "Dell", "model": "OptiPlex 7090",
                "os_type": "Windows", "os_version": "11 Pro", "layer": 4
            },
            {
                "name": "ws-it-02", "ip": "10.0.20.11", "type": DeviceType.WORKSTATION,
                "zone": SecurityZone.INTERNAL, "vendor": "Dell", "model": "OptiPlex 7090",
                "os_type": "Windows", "os_version": "11 Pro", "layer": 4
            },
            {
                "name": "ws-dev-01", "ip": "10.0.20.20", "type": DeviceType.WORKSTATION,
                "zone": SecurityZone.INTERNAL, "vendor": "Apple", "model": "MacBook Pro M2",
                "os_type": "macOS", "os_version": "Sonoma 14.2", "layer": 4
            },
            {
                "name": "ws-dev-02", "ip": "10.0.20.21", "type": DeviceType.WORKSTATION,
                "zone": SecurityZone.INTERNAL, "vendor": "Apple", "model": "MacBook Pro M2",
                "os_type": "macOS", "os_version": "Sonoma 14.2", "layer": 4
            },
            {
                "name": "ws-hr-01", "ip": "10.0.20.30", "type": DeviceType.WORKSTATION,
                "zone": SecurityZone.INTERNAL, "vendor": "HP", "model": "EliteDesk 800",
                "os_type": "Windows", "os_version": "10 Pro", "layer": 4
            },
            
            # Management
            {
                "name": "mgmt-sw-01", "ip": "10.0.100.1", "type": DeviceType.SWITCH,
                "zone": SecurityZone.MANAGEMENT, "vendor": "Cisco", "model": "Catalyst 9200",
                "layer": 2
            },
            {
                "name": "siem-01", "ip": "10.0.100.10", "type": DeviceType.SERVER,
                "zone": SecurityZone.MANAGEMENT, "vendor": "Dell", "model": "PowerEdge R750",
                "os_type": "Linux", "os_version": "RHEL 8",
                "ports": [514, 9200], "is_critical": True, "layer": 3
            },
            {
                "name": "nms-01", "ip": "10.0.100.20", "type": DeviceType.SERVER,
                "zone": SecurityZone.MANAGEMENT, "vendor": "Dell", "model": "PowerEdge R640",
                "os_type": "Linux", "os_version": "Ubuntu 22.04",
                "ports": [161, 443], "layer": 3
            },
            {
                "name": "jump-01", "ip": "10.0.100.100", "type": DeviceType.SERVER,
                "zone": SecurityZone.MANAGEMENT, "vendor": "Dell", "model": "PowerEdge R640",
                "os_type": "Windows", "os_version": "Server 2022",
                "ports": [22, 3389], "is_critical": True, "layer": 3
            },
            
            # Wireless / IoT
            {
                "name": "wap-01", "ip": "10.0.20.250", "type": DeviceType.WIRELESS_AP,
                "zone": SecurityZone.INTERNAL, "vendor": "Aruba", "model": "AP-515",
                "layer": 3
            },
            {
                "name": "wap-02", "ip": "10.0.20.251", "type": DeviceType.WIRELESS_AP,
                "zone": SecurityZone.INTERNAL, "vendor": "Aruba", "model": "AP-515",
                "layer": 3
            },
            {
                "name": "printer-01", "ip": "10.0.20.200", "type": DeviceType.PRINTER,
                "zone": SecurityZone.INTERNAL, "vendor": "HP", "model": "LaserJet M609",
                "ports": [9100], "layer": 4
            },
            {
                "name": "camera-01", "ip": "10.0.20.210", "type": DeviceType.IOT,
                "zone": SecurityZone.INTERNAL, "vendor": "Axis", "model": "P3245-V",
                "ports": [80, 554], "layer": 4
            },
            
            # Cloud/Virtual
            {
                "name": "cloud-gw", "ip": "10.0.50.1", "type": DeviceType.CLOUD,
                "zone": SecurityZone.INTERNAL, "vendor": "AWS", "model": "Transit Gateway",
                "layer": 2
            },
            {
                "name": "k8s-master", "ip": "10.0.50.10", "type": DeviceType.VIRTUAL,
                "zone": SecurityZone.INTERNAL, "vendor": "VMware", "model": "vSphere 8",
                "os_type": "Linux", "os_version": "Ubuntu 22.04",
                "ports": [6443, 2379], "layer": 3
            },
            {
                "name": "k8s-worker-01", "ip": "10.0.50.11", "type": DeviceType.VIRTUAL,
                "zone": SecurityZone.INTERNAL, "vendor": "VMware", "model": "vSphere 8",
                "os_type": "Linux", "os_version": "Ubuntu 22.04", "layer": 4
            },
            {
                "name": "k8s-worker-02", "ip": "10.0.50.12", "type": DeviceType.VIRTUAL,
                "zone": SecurityZone.INTERNAL, "vendor": "VMware", "model": "vSphere 8",
                "os_type": "Linux", "os_version": "Ubuntu 22.04", "layer": 4
            },
            
            # Guest network
            {
                "name": "guest-wap-01", "ip": "192.168.200.1", "type": DeviceType.WIRELESS_AP,
                "zone": SecurityZone.GUEST, "vendor": "Aruba", "model": "AP-303",
                "layer": 3
            },
        ]
        
        # Create nodes
        for dev in devices:
            mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
            node = NetworkNode(
                name=dev["name"],
                ip_address=dev["ip"],
                hostname=f"{dev['name']}.corp.local",
                mac_address=mac,
                device_type=dev["type"],
                vendor=dev.get("vendor", "Unknown"),
                model=dev.get("model", "Unknown"),
                os_type=dev.get("os_type", ""),
                os_version=dev.get("os_version", ""),
                security_zone=dev.get("zone", SecurityZone.INTERNAL),
                open_ports=dev.get("ports", []),
                is_gateway=dev.get("is_gateway", False),
                is_critical=dev.get("is_critical", False),
                layer=dev.get("layer", 3),
            )
            self.nodes[node.id] = node
            
        # Create connections (edges)
        self._generate_connections()
        
        # Update statistics
        self._update_stats()
        
    def _generate_connections(self):
        """Generate network connections between nodes"""
        nodes_by_layer = {}
        for node in self.nodes.values():
            if node.layer not in nodes_by_layer:
                nodes_by_layer[node.layer] = []
            nodes_by_layer[node.layer].append(node)
            
        # Connect layers hierarchically
        layers = sorted(nodes_by_layer.keys())
        
        for i, layer in enumerate(layers[:-1]):
            next_layer = layers[i + 1]
            
            for node in nodes_by_layer[layer]:
                # Connect to nodes in next layer
                targets = nodes_by_layer[next_layer]
                num_connections = min(len(targets), random.randint(2, 4))
                connected = random.sample(targets, num_connections)
                
                for target in connected:
                    edge = NetworkEdge(
                        source_id=node.id,
                        target_id=target.id,
                        connection_type=ConnectionType.ETHERNET,
                        bandwidth="10 Gbps",
                        latency_ms=random.uniform(0.1, 2.0),
                        is_active=True,
                        traffic_bytes=random.randint(1000000, 100000000000),
                    )
                    self.edges[edge.id] = edge
                    
        # Add some lateral connections within layers
        for layer, nodes in nodes_by_layer.items():
            if len(nodes) > 1:
                for i in range(min(3, len(nodes) - 1)):
                    n1, n2 = random.sample(nodes, 2)
                    if not self._connection_exists(n1.id, n2.id):
                        edge = NetworkEdge(
                            source_id=n1.id,
                            target_id=n2.id,
                            connection_type=ConnectionType.ETHERNET,
                            bandwidth="1 Gbps",
                            latency_ms=random.uniform(0.1, 1.0),
                            is_active=True,
                            traffic_bytes=random.randint(100000, 10000000000),
                        )
                        self.edges[edge.id] = edge
                        
    def _connection_exists(self, source_id: str, target_id: str) -> bool:
        """Check if a connection already exists between two nodes"""
        for edge in self.edges.values():
            if (edge.source_id == source_id and edge.target_id == target_id) or \
               (edge.source_id == target_id and edge.target_id == source_id):
                return True
        return False
        
    def _update_stats(self):
        """Update topology statistics"""
        self.stats["total_nodes"] = len(self.nodes)
        self.stats["total_edges"] = len(self.edges)
        self.stats["total_subnets"] = len(self.subnets)
        
        # Count by type
        self.stats["devices_by_type"] = {}
        for node in self.nodes.values():
            dtype = node.device_type.value
            self.stats["devices_by_type"][dtype] = \
                self.stats["devices_by_type"].get(dtype, 0) + 1
                
        # Count by zone
        self.stats["zones_count"] = {}
        for node in self.nodes.values():
            zone = node.security_zone.value
            self.stats["zones_count"][zone] = \
                self.stats["zones_count"].get(zone, 0) + 1
                
        # Critical and compromised
        self.stats["critical_assets"] = sum(
            1 for n in self.nodes.values() if n.is_critical
        )
        self.stats["compromised_hosts"] = sum(
            1 for n in self.nodes.values() if n.is_compromised
        )
        
    async def discover_network(self, target: str) -> TopologyScan:
        """Perform network discovery scan"""
        scan = TopologyScan(
            target_network=target,
            status="running"
        )
        self.scans.append(scan)
        
        # Simulate discovery
        await asyncio.sleep(0.5)
        
        scan.nodes_discovered = len(self.nodes)
        scan.edges_discovered = len(self.edges)
        scan.subnets_discovered = len(self.subnets)
        scan.completed_at = datetime.now()
        scan.status = "completed"
        
        self.stats["last_scan"] = datetime.now()
        
        return scan
        
    def get_node_by_id(self, node_id: str) -> Optional[NetworkNode]:
        """Get node by ID"""
        return self.nodes.get(node_id)
        
    def get_node_by_ip(self, ip: str) -> Optional[NetworkNode]:
        """Get node by IP address"""
        for node in self.nodes.values():
            if node.ip_address == ip:
                return node
        return None
        
    def get_connected_nodes(self, node_id: str) -> List[NetworkNode]:
        """Get all nodes connected to a given node"""
        connected_ids = set()
        
        for edge in self.edges.values():
            if edge.source_id == node_id:
                connected_ids.add(edge.target_id)
            elif edge.target_id == node_id:
                connected_ids.add(edge.source_id)
                
        return [self.nodes[nid] for nid in connected_ids if nid in self.nodes]
        
    def get_nodes_by_type(self, device_type: DeviceType) -> List[NetworkNode]:
        """Get all nodes of a specific type"""
        return [n for n in self.nodes.values() if n.device_type == device_type]
        
    def get_nodes_by_zone(self, zone: SecurityZone) -> List[NetworkNode]:
        """Get all nodes in a security zone"""
        return [n for n in self.nodes.values() if n.security_zone == zone]
        
    def get_critical_path(self, source_id: str, target_id: str) -> List[NetworkNode]:
        """Find path between two nodes (simplified BFS)"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return []
            
        visited = set()
        queue = [(source_id, [source_id])]
        
        while queue:
            current_id, path = queue.pop(0)
            
            if current_id == target_id:
                return [self.nodes[nid] for nid in path]
                
            if current_id in visited:
                continue
            visited.add(current_id)
            
            for edge in self.edges.values():
                next_id = None
                if edge.source_id == current_id:
                    next_id = edge.target_id
                elif edge.target_id == current_id:
                    next_id = edge.source_id
                    
                if next_id and next_id not in visited:
                    queue.append((next_id, path + [next_id]))
                    
        return []
        
    def calculate_layout(self) -> Dict[str, Tuple[float, float]]:
        """Calculate node positions for visualization"""
        positions = {}
        
        # Organize by layer
        nodes_by_layer = {}
        for node in self.nodes.values():
            if node.layer not in nodes_by_layer:
                nodes_by_layer[node.layer] = []
            nodes_by_layer[node.layer].append(node)
            
        # Calculate positions
        canvas_width = 1200
        canvas_height = 800
        
        layers = sorted(nodes_by_layer.keys())
        layer_height = canvas_height / (len(layers) + 1)
        
        for layer_idx, layer in enumerate(layers):
            nodes = nodes_by_layer[layer]
            y = layer_height * (layer_idx + 1)
            
            node_spacing = canvas_width / (len(nodes) + 1)
            
            for node_idx, node in enumerate(nodes):
                x = node_spacing * (node_idx + 1)
                positions[node.id] = (x, y)
                node.x = x
                node.y = y
                
        return positions
        
    def export_topology(self) -> Dict:
        """Export topology for visualization"""
        self.calculate_layout()
        
        return {
            "nodes": [
                {
                    "id": n.id,
                    "name": n.name,
                    "ip": n.ip_address,
                    "type": n.device_type.value,
                    "zone": n.security_zone.value,
                    "is_critical": n.is_critical,
                    "is_compromised": n.is_compromised,
                    "vendor": n.vendor,
                    "os": f"{n.os_type} {n.os_version}".strip(),
                    "x": n.x,
                    "y": n.y,
                    "layer": n.layer,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "id": e.id,
                    "source": e.source_id,
                    "target": e.target_id,
                    "type": e.connection_type.value,
                    "bandwidth": e.bandwidth,
                    "active": e.is_active,
                }
                for e in self.edges.values()
            ],
            "subnets": [
                {
                    "id": s.id,
                    "name": s.name,
                    "cidr": s.cidr,
                    "zone": s.security_zone.value,
                    "vlan": s.vlan_id,
                }
                for s in self.subnets.values()
            ],
            "stats": self.stats,
        }
        
    def get_security_findings(self) -> List[Dict]:
        """Analyze topology for security issues"""
        findings = []
        
        # Check for exposed critical assets
        for node in self.nodes.values():
            if node.is_critical and node.security_zone == SecurityZone.DMZ:
                findings.append({
                    "severity": "high",
                    "type": "exposure",
                    "title": f"Critical asset in DMZ: {node.name}",
                    "description": f"Critical asset {node.name} ({node.ip_address}) is exposed in DMZ",
                    "node_id": node.id,
                })
                
        # Check for missing segmentation
        zone_connections = {}
        for edge in self.edges.values():
            source = self.nodes.get(edge.source_id)
            target = self.nodes.get(edge.target_id)
            if source and target:
                key = tuple(sorted([source.security_zone.value, target.security_zone.value]))
                zone_connections[key] = zone_connections.get(key, 0) + 1
                
        for zones, count in zone_connections.items():
            if "guest" in zones and "internal" in zones:
                findings.append({
                    "severity": "critical",
                    "type": "segmentation",
                    "title": "Guest network connected to internal",
                    "description": f"Found {count} connections between guest and internal networks",
                })
                
        # Check for IoT devices in internal network
        iot_internal = [n for n in self.nodes.values() 
                       if n.device_type == DeviceType.IOT 
                       and n.security_zone == SecurityZone.INTERNAL]
        if iot_internal:
            findings.append({
                "severity": "medium",
                "type": "segmentation",
                "title": f"{len(iot_internal)} IoT devices in internal network",
                "description": "IoT devices should be segmented in dedicated network",
            })
            
        return findings


# Global instance
_mapper: Optional[NetworkTopologyMapper] = None


def get_topology_mapper() -> NetworkTopologyMapper:
    """Get or create the global topology mapper"""
    global _mapper
    if _mapper is None:
        _mapper = NetworkTopologyMapper()
    return _mapper
