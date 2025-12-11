"""
HydraRecon Advanced Network Traffic Analysis Module
Deep packet inspection, protocol analysis, and threat detection
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


class ProtocolType(Enum):
    """Network protocols"""
    ETHERNET = "ethernet"
    IP = "ip"
    IPv6 = "ipv6"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ARP = "arp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    DHCP = "dhcp"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    SMB = "smb"
    RDP = "rdp"
    TELNET = "telnet"
    MODBUS = "modbus"
    DNP3 = "dnp3"
    UNKNOWN = "unknown"


class ThreatCategory(Enum):
    """Threat categories"""
    MALWARE_C2 = "malware_c2"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    RECONNAISSANCE = "reconnaissance"
    EXPLOIT = "exploit"
    DOS = "denial_of_service"
    CREDENTIAL_THEFT = "credential_theft"
    POLICY_VIOLATION = "policy_violation"
    SUSPICIOUS = "suspicious"


class SeverityLevel(Enum):
    """Alert severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class EthernetFrame:
    """Ethernet frame"""
    src_mac: str
    dst_mac: str
    ether_type: int
    payload: bytes = b''


@dataclass
class IPPacket:
    """IP packet"""
    version: int
    src_ip: str
    dst_ip: str
    protocol: int
    ttl: int = 64
    flags: int = 0
    payload: bytes = b''
    identification: int = 0


@dataclass
class TCPSegment:
    """TCP segment"""
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    flags: int
    window: int = 65535
    payload: bytes = b''
    
    @property
    def syn(self) -> bool:
        return bool(self.flags & 0x02)
        
    @property
    def ack(self) -> bool:
        return bool(self.flags & 0x10)
        
    @property
    def fin(self) -> bool:
        return bool(self.flags & 0x01)
        
    @property
    def rst(self) -> bool:
        return bool(self.flags & 0x04)
        
    @property
    def psh(self) -> bool:
        return bool(self.flags & 0x08)


@dataclass
class UDPDatagram:
    """UDP datagram"""
    src_port: int
    dst_port: int
    length: int
    payload: bytes = b''


@dataclass
class DNSQuery:
    """DNS query/response"""
    transaction_id: int
    query_name: str
    query_type: int
    is_response: bool = False
    answers: List[str] = field(default_factory=list)
    ttl: int = 0


@dataclass
class HTTPRequest:
    """HTTP request"""
    method: str
    uri: str
    version: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b''


@dataclass
class HTTPResponse:
    """HTTP response"""
    version: str
    status_code: int
    status_text: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b''


@dataclass
class Connection:
    """Network connection/flow"""
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: ProtocolType
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    packets: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    state: str = "new"


@dataclass
class NetworkAlert:
    """Network security alert"""
    alert_id: str
    title: str
    description: str
    severity: SeverityLevel
    category: ThreatCategory
    source_ip: str = ""
    source_port: int = 0
    dest_ip: str = ""
    dest_port: int = 0
    protocol: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    evidence: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""


class PacketParser:
    """Parse network packets"""
    
    @staticmethod
    def parse_ethernet(data: bytes) -> Optional[EthernetFrame]:
        """Parse Ethernet frame"""
        if len(data) < 14:
            return None
            
        dst_mac = ':'.join(f'{b:02x}' for b in data[0:6])
        src_mac = ':'.join(f'{b:02x}' for b in data[6:12])
        ether_type = struct.unpack('>H', data[12:14])[0]
        
        return EthernetFrame(
            src_mac=src_mac,
            dst_mac=dst_mac,
            ether_type=ether_type,
            payload=data[14:]
        )
        
    @staticmethod
    def parse_ip(data: bytes) -> Optional[IPPacket]:
        """Parse IP packet"""
        if len(data) < 20:
            return None
            
        version = (data[0] >> 4) & 0xF
        ihl = data[0] & 0xF
        header_length = ihl * 4
        
        if version != 4 or len(data) < header_length:
            return None
            
        ttl = data[8]
        protocol = data[9]
        src_ip = '.'.join(str(b) for b in data[12:16])
        dst_ip = '.'.join(str(b) for b in data[16:20])
        identification = struct.unpack('>H', data[4:6])[0]
        flags = (struct.unpack('>H', data[6:8])[0] >> 13) & 0x7
        
        return IPPacket(
            version=version,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            ttl=ttl,
            flags=flags,
            identification=identification,
            payload=data[header_length:]
        )
        
    @staticmethod
    def parse_tcp(data: bytes) -> Optional[TCPSegment]:
        """Parse TCP segment"""
        if len(data) < 20:
            return None
            
        src_port = struct.unpack('>H', data[0:2])[0]
        dst_port = struct.unpack('>H', data[2:4])[0]
        seq_num = struct.unpack('>I', data[4:8])[0]
        ack_num = struct.unpack('>I', data[8:12])[0]
        data_offset = (data[12] >> 4) * 4
        flags = data[13]
        window = struct.unpack('>H', data[14:16])[0]
        
        return TCPSegment(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=flags,
            window=window,
            payload=data[data_offset:]
        )
        
    @staticmethod
    def parse_udp(data: bytes) -> Optional[UDPDatagram]:
        """Parse UDP datagram"""
        if len(data) < 8:
            return None
            
        src_port = struct.unpack('>H', data[0:2])[0]
        dst_port = struct.unpack('>H', data[2:4])[0]
        length = struct.unpack('>H', data[4:6])[0]
        
        return UDPDatagram(
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            payload=data[8:]
        )
        
    @staticmethod
    def parse_dns(data: bytes) -> Optional[DNSQuery]:
        """Parse DNS query/response"""
        if len(data) < 12:
            return None
            
        transaction_id = struct.unpack('>H', data[0:2])[0]
        flags = struct.unpack('>H', data[2:4])[0]
        is_response = bool(flags & 0x8000)
        qd_count = struct.unpack('>H', data[4:6])[0]
        an_count = struct.unpack('>H', data[6:8])[0]
        
        # Parse query name
        offset = 12
        labels = []
        while offset < len(data) and data[offset] != 0:
            label_len = data[offset]
            if label_len > 63:
                break
            offset += 1
            labels.append(data[offset:offset+label_len].decode('utf-8', errors='ignore'))
            offset += label_len
            
        query_name = '.'.join(labels) if labels else ''
        
        query_type = 0
        if offset + 2 < len(data):
            query_type = struct.unpack('>H', data[offset+1:offset+3])[0]
            
        return DNSQuery(
            transaction_id=transaction_id,
            query_name=query_name,
            query_type=query_type,
            is_response=is_response
        )
        
    @staticmethod
    def parse_http_request(data: bytes) -> Optional[HTTPRequest]:
        """Parse HTTP request"""
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            
            if not lines:
                return None
                
            # Parse request line
            parts = lines[0].split(' ')
            if len(parts) < 3:
                return None
                
            method, uri, version = parts[0], parts[1], parts[2]
            
            if method not in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT']:
                return None
                
            # Parse headers
            headers = {}
            i = 1
            while i < len(lines) and lines[i]:
                if ': ' in lines[i]:
                    key, value = lines[i].split(': ', 1)
                    headers[key.lower()] = value
                i += 1
                
            # Body
            body_start = text.find('\r\n\r\n')
            body = data[body_start+4:] if body_start >= 0 else b''
            
            return HTTPRequest(
                method=method,
                uri=uri,
                version=version,
                headers=headers,
                body=body
            )
            
        except Exception:
            return None


class PcapReader:
    """Read PCAP files"""
    
    PCAP_MAGIC = 0xa1b2c3d4
    PCAP_MAGIC_SWAPPED = 0xd4c3b2a1
    PCAPNG_MAGIC = 0x0a0d0d0a
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.link_type = 1  # Ethernet by default
        self.packets: List[Tuple[float, bytes]] = []
        
    def read(self) -> List[Tuple[float, bytes]]:
        """Read PCAP file"""
        with open(self.file_path, 'rb') as f:
            data = f.read()
            
        if len(data) < 24:
            return []
            
        # Check magic number
        magic = struct.unpack('<I', data[0:4])[0]
        
        if magic == self.PCAP_MAGIC:
            return self._parse_pcap(data, '<')
        elif magic == self.PCAP_MAGIC_SWAPPED:
            return self._parse_pcap(data, '>')
        else:
            logger.warning("Unknown PCAP format")
            return []
            
    def _parse_pcap(self, data: bytes, endian: str) -> List[Tuple[float, bytes]]:
        """Parse traditional PCAP format"""
        packets = []
        
        # Parse global header
        self.link_type = struct.unpack(f'{endian}I', data[20:24])[0]
        
        offset = 24
        while offset + 16 <= len(data):
            # Packet header
            ts_sec = struct.unpack(f'{endian}I', data[offset:offset+4])[0]
            ts_usec = struct.unpack(f'{endian}I', data[offset+4:offset+8])[0]
            incl_len = struct.unpack(f'{endian}I', data[offset+8:offset+12])[0]
            
            timestamp = ts_sec + ts_usec / 1000000.0
            
            offset += 16
            
            if offset + incl_len > len(data):
                break
                
            packet_data = data[offset:offset+incl_len]
            packets.append((timestamp, packet_data))
            
            offset += incl_len
            
        self.packets = packets
        return packets


class ConnectionTracker:
    """Track network connections"""
    
    def __init__(self):
        self.connections: Dict[str, Connection] = {}
        
    def get_flow_id(self, src_ip: str, src_port: int, 
                   dst_ip: str, dst_port: int) -> str:
        """Generate flow ID"""
        # Normalize to ensure same ID regardless of direction
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            
    def track_packet(self, ip: IPPacket, tcp: Optional[TCPSegment] = None,
                    udp: Optional[UDPDatagram] = None) -> Connection:
        """Track packet in connection"""
        if tcp:
            src_port = tcp.src_port
            dst_port = tcp.dst_port
            protocol = ProtocolType.TCP
            payload_size = len(tcp.payload)
        elif udp:
            src_port = udp.src_port
            dst_port = udp.dst_port
            protocol = ProtocolType.UDP
            payload_size = len(udp.payload)
        else:
            return None
            
        flow_id = self.get_flow_id(ip.src_ip, src_port, ip.dst_ip, dst_port)
        
        if flow_id not in self.connections:
            self.connections[flow_id] = Connection(
                flow_id=flow_id,
                src_ip=ip.src_ip,
                src_port=src_port,
                dst_ip=ip.dst_ip,
                dst_port=dst_port,
                protocol=protocol
            )
            
        conn = self.connections[flow_id]
        conn.packets += 1
        
        # Track bytes by direction
        if ip.src_ip == conn.src_ip:
            conn.bytes_sent += payload_size
        else:
            conn.bytes_received += payload_size
            
        # Update connection state for TCP
        if tcp:
            if tcp.syn and not tcp.ack:
                conn.state = "syn_sent"
            elif tcp.syn and tcp.ack:
                conn.state = "syn_ack"
            elif tcp.fin:
                conn.state = "closing"
            elif tcp.rst:
                conn.state = "reset"
            elif conn.state == "syn_ack" or conn.state == "new":
                conn.state = "established"
                
        return conn


class ThreatDetector:
    """Detect threats in network traffic"""
    
    def __init__(self):
        self.signatures = self._load_signatures()
        self.known_malicious_ips: Set[str] = set()
        self.known_malicious_domains: Set[str] = set()
        self.alerts: List[NetworkAlert] = []
        
    def _load_signatures(self) -> Dict[str, Dict]:
        """Load detection signatures"""
        return {
            'port_scan': {
                'description': 'Port scanning detected',
                'category': ThreatCategory.RECONNAISSANCE,
                'severity': SeverityLevel.MEDIUM
            },
            'c2_beacon': {
                'description': 'Potential C2 beaconing behavior',
                'category': ThreatCategory.MALWARE_C2,
                'severity': SeverityLevel.HIGH
            },
            'data_exfil': {
                'description': 'Large outbound data transfer',
                'category': ThreatCategory.DATA_EXFILTRATION,
                'severity': SeverityLevel.HIGH
            },
            'dns_tunnel': {
                'description': 'DNS tunneling detected',
                'category': ThreatCategory.DATA_EXFILTRATION,
                'severity': SeverityLevel.HIGH
            },
            'smb_lateral': {
                'description': 'SMB lateral movement detected',
                'category': ThreatCategory.LATERAL_MOVEMENT,
                'severity': SeverityLevel.HIGH
            },
            'ssh_brute': {
                'description': 'SSH brute force attempt',
                'category': ThreatCategory.CREDENTIAL_THEFT,
                'severity': SeverityLevel.MEDIUM
            },
            'http_exploit': {
                'description': 'Potential HTTP exploit attempt',
                'category': ThreatCategory.EXPLOIT,
                'severity': SeverityLevel.HIGH
            },
            'clear_password': {
                'description': 'Cleartext password transmitted',
                'category': ThreatCategory.CREDENTIAL_THEFT,
                'severity': SeverityLevel.CRITICAL
            }
        }
        
    def analyze_connection(self, conn: Connection) -> List[NetworkAlert]:
        """Analyze connection for threats"""
        alerts = []
        
        # Check for data exfiltration
        if conn.bytes_sent > 10 * 1024 * 1024:  # 10MB
            alerts.append(NetworkAlert(
                alert_id=hashlib.md5(f"exfil_{conn.flow_id}".encode()).hexdigest()[:12],
                title="Large Outbound Data Transfer",
                description=f"Connection sent {conn.bytes_sent / 1024 / 1024:.2f}MB to {conn.dst_ip}",
                severity=SeverityLevel.MEDIUM,
                category=ThreatCategory.DATA_EXFILTRATION,
                source_ip=conn.src_ip,
                source_port=conn.src_port,
                dest_ip=conn.dst_ip,
                dest_port=conn.dst_port,
                protocol=conn.protocol.value
            ))
            
        # Check for C2 patterns (many small packets)
        if conn.packets > 100 and (conn.bytes_sent + conn.bytes_received) / conn.packets < 100:
            alerts.append(NetworkAlert(
                alert_id=hashlib.md5(f"c2_{conn.flow_id}".encode()).hexdigest()[:12],
                title="Potential C2 Beaconing",
                description=f"Suspicious traffic pattern to {conn.dst_ip}:{conn.dst_port}",
                severity=SeverityLevel.HIGH,
                category=ThreatCategory.MALWARE_C2,
                source_ip=conn.src_ip,
                dest_ip=conn.dst_ip,
                dest_port=conn.dst_port,
                protocol=conn.protocol.value
            ))
            
        # Check for suspicious ports
        suspicious_ports = {4444, 5555, 6666, 7777, 8888, 1234, 31337}
        if conn.dst_port in suspicious_ports:
            alerts.append(NetworkAlert(
                alert_id=hashlib.md5(f"port_{conn.flow_id}".encode()).hexdigest()[:12],
                title="Connection to Suspicious Port",
                description=f"Connection to known suspicious port {conn.dst_port}",
                severity=SeverityLevel.MEDIUM,
                category=ThreatCategory.SUSPICIOUS,
                source_ip=conn.src_ip,
                dest_ip=conn.dst_ip,
                dest_port=conn.dst_port
            ))
            
        return alerts
        
    def analyze_dns(self, query: DNSQuery, src_ip: str) -> List[NetworkAlert]:
        """Analyze DNS for threats"""
        alerts = []
        
        # Check for DNS tunneling (long subdomain)
        if query.query_name:
            subdomain = query.query_name.split('.')[0]
            
            if len(subdomain) > 30:
                alerts.append(NetworkAlert(
                    alert_id=hashlib.md5(f"dnstun_{query.query_name}".encode()).hexdigest()[:12],
                    title="Potential DNS Tunneling",
                    description=f"Unusually long subdomain in DNS query: {query.query_name[:50]}...",
                    severity=SeverityLevel.HIGH,
                    category=ThreatCategory.DATA_EXFILTRATION,
                    source_ip=src_ip,
                    evidence={'query': query.query_name}
                ))
                
            # Check entropy of subdomain
            entropy = self._calculate_entropy(subdomain)
            if entropy > 4.0:
                alerts.append(NetworkAlert(
                    alert_id=hashlib.md5(f"dnsent_{query.query_name}".encode()).hexdigest()[:12],
                    title="High Entropy DNS Query",
                    description=f"DNS query with high entropy subdomain (possible exfiltration)",
                    severity=SeverityLevel.MEDIUM,
                    category=ThreatCategory.SUSPICIOUS,
                    source_ip=src_ip,
                    evidence={'query': query.query_name, 'entropy': entropy}
                ))
                
        # Check for suspicious TLDs
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'}
        for tld in suspicious_tlds:
            if query.query_name.endswith(tld):
                alerts.append(NetworkAlert(
                    alert_id=hashlib.md5(f"dnstld_{query.query_name}".encode()).hexdigest()[:12],
                    title="DNS Query to Suspicious TLD",
                    description=f"DNS query to suspicious TLD: {query.query_name}",
                    severity=SeverityLevel.LOW,
                    category=ThreatCategory.SUSPICIOUS,
                    source_ip=src_ip
                ))
                break
                
        return alerts
        
    def analyze_http(self, request: HTTPRequest, src_ip: str, 
                    dst_ip: str) -> List[NetworkAlert]:
        """Analyze HTTP for threats"""
        alerts = []
        
        # Check for SQL injection patterns
        sqli_patterns = [
            r"(?:union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
            r"(?:'\s*or\s+'1'\s*=\s*'1|'\s*or\s+1\s*=\s*1)",
            r"(?:;\s*(?:exec|execute|xp_cmdshell))",
        ]
        
        for pattern in sqli_patterns:
            if re.search(pattern, request.uri, re.IGNORECASE):
                alerts.append(NetworkAlert(
                    alert_id=hashlib.md5(f"sqli_{request.uri[:20]}".encode()).hexdigest()[:12],
                    title="SQL Injection Attempt",
                    description="Potential SQL injection in HTTP request",
                    severity=SeverityLevel.HIGH,
                    category=ThreatCategory.EXPLOIT,
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    evidence={'uri': request.uri[:200]}
                ))
                break
                
        # Check for XSS patterns
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on(?:load|error|click|mouse)\s*=",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, request.uri, re.IGNORECASE):
                alerts.append(NetworkAlert(
                    alert_id=hashlib.md5(f"xss_{request.uri[:20]}".encode()).hexdigest()[:12],
                    title="XSS Attempt",
                    description="Potential XSS attack in HTTP request",
                    severity=SeverityLevel.MEDIUM,
                    category=ThreatCategory.EXPLOIT,
                    source_ip=src_ip,
                    dest_ip=dst_ip
                ))
                break
                
        # Check for directory traversal
        if '../' in request.uri or '..\\' in request.uri:
            alerts.append(NetworkAlert(
                alert_id=hashlib.md5(f"lfi_{request.uri[:20]}".encode()).hexdigest()[:12],
                title="Directory Traversal Attempt",
                description="Path traversal attempt in HTTP request",
                severity=SeverityLevel.HIGH,
                category=ThreatCategory.EXPLOIT,
                source_ip=src_ip,
                dest_ip=dst_ip,
                evidence={'uri': request.uri[:200]}
            ))
            
        # Check for suspicious user agents
        suspicious_agents = ['curl', 'wget', 'python-requests', 'nikto', 'sqlmap', 'nmap']
        user_agent = request.headers.get('user-agent', '').lower()
        
        for agent in suspicious_agents:
            if agent in user_agent:
                alerts.append(NetworkAlert(
                    alert_id=hashlib.md5(f"ua_{user_agent[:20]}".encode()).hexdigest()[:12],
                    title="Suspicious User Agent",
                    description=f"HTTP request with suspicious user agent: {agent}",
                    severity=SeverityLevel.LOW,
                    category=ThreatCategory.RECONNAISSANCE,
                    source_ip=src_ip,
                    dest_ip=dst_ip
                ))
                break
                
        return alerts
        
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy"""
        import math
        
        if not s:
            return 0.0
            
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
            
        entropy = 0.0
        length = len(s)
        
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
            
        return entropy


class TrafficAnalyzer:
    """Main traffic analysis engine"""
    
    def __init__(self):
        self.parser = PacketParser()
        self.connection_tracker = ConnectionTracker()
        self.threat_detector = ThreatDetector()
        
    async def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """Analyze PCAP file"""
        results = {
            'analysis_id': hashlib.md5(f"{pcap_path}{datetime.now()}".encode()).hexdigest()[:12],
            'timestamp': datetime.now().isoformat(),
            'pcap_file': pcap_path,
            'statistics': {},
            'connections': [],
            'dns_queries': [],
            'http_requests': [],
            'alerts': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Read PCAP
        reader = PcapReader(pcap_path)
        packets = reader.read()
        
        results['statistics']['total_packets'] = len(packets)
        
        # Process packets
        protocol_counts = defaultdict(int)
        dns_queries = []
        http_requests = []
        
        for timestamp, packet_data in packets:
            # Parse Ethernet
            eth = self.parser.parse_ethernet(packet_data)
            if not eth:
                continue
                
            # Parse IP
            if eth.ether_type == 0x0800:  # IPv4
                ip = self.parser.parse_ip(eth.payload)
                if not ip:
                    continue
                    
                protocol_counts['ip'] += 1
                
                # Parse TCP
                if ip.protocol == 6:
                    tcp = self.parser.parse_tcp(ip.payload)
                    if tcp:
                        protocol_counts['tcp'] += 1
                        
                        # Track connection
                        conn = self.connection_tracker.track_packet(ip, tcp=tcp)
                        
                        # Check for HTTP
                        if tcp.dst_port == 80 or tcp.src_port == 80:
                            http_req = self.parser.parse_http_request(tcp.payload)
                            if http_req:
                                http_requests.append({
                                    'src_ip': ip.src_ip,
                                    'dst_ip': ip.dst_ip,
                                    'method': http_req.method,
                                    'uri': http_req.uri,
                                    'host': http_req.headers.get('host', '')
                                })
                                
                                # Analyze HTTP
                                alerts = self.threat_detector.analyze_http(
                                    http_req, ip.src_ip, ip.dst_ip
                                )
                                for alert in alerts:
                                    results['alerts'].append(self._alert_to_dict(alert))
                                    
                # Parse UDP
                elif ip.protocol == 17:
                    udp = self.parser.parse_udp(ip.payload)
                    if udp:
                        protocol_counts['udp'] += 1
                        
                        # Track connection
                        self.connection_tracker.track_packet(ip, udp=udp)
                        
                        # Check for DNS
                        if udp.dst_port == 53 or udp.src_port == 53:
                            dns = self.parser.parse_dns(udp.payload)
                            if dns and dns.query_name:
                                dns_queries.append({
                                    'query': dns.query_name,
                                    'type': dns.query_type,
                                    'is_response': dns.is_response,
                                    'src_ip': ip.src_ip
                                })
                                
                                # Analyze DNS
                                alerts = self.threat_detector.analyze_dns(dns, ip.src_ip)
                                for alert in alerts:
                                    results['alerts'].append(self._alert_to_dict(alert))
                                    
        # Add statistics
        results['statistics']['protocols'] = dict(protocol_counts)
        results['statistics']['connections'] = len(self.connection_tracker.connections)
        results['statistics']['dns_queries'] = len(dns_queries)
        results['statistics']['http_requests'] = len(http_requests)
        
        # Analyze connections
        for conn in self.connection_tracker.connections.values():
            results['connections'].append({
                'flow_id': conn.flow_id,
                'src': f"{conn.src_ip}:{conn.src_port}",
                'dst': f"{conn.dst_ip}:{conn.dst_port}",
                'protocol': conn.protocol.value,
                'packets': conn.packets,
                'bytes_sent': conn.bytes_sent,
                'bytes_received': conn.bytes_received,
                'state': conn.state
            })
            
            # Detect threats in connections
            alerts = self.threat_detector.analyze_connection(conn)
            for alert in alerts:
                results['alerts'].append(self._alert_to_dict(alert))
                
        results['dns_queries'] = dns_queries[:100]  # Limit
        results['http_requests'] = http_requests[:100]
        
        # Calculate summary
        for alert in results['alerts']:
            severity = alert.get('severity', 'info').lower()
            if severity in results['summary']:
                results['summary'][severity] += 1
                
        return results
        
    def _alert_to_dict(self, alert: NetworkAlert) -> Dict:
        """Convert alert to dictionary"""
        return {
            'id': alert.alert_id,
            'title': alert.title,
            'description': alert.description,
            'severity': alert.severity.value,
            'category': alert.category.value,
            'source_ip': alert.source_ip,
            'source_port': alert.source_port,
            'dest_ip': alert.dest_ip,
            'dest_port': alert.dest_port,
            'protocol': alert.protocol,
            'timestamp': alert.timestamp.isoformat()
        }
        
    def generate_report(self, results: Dict) -> str:
        """Generate analysis report"""
        report = []
        
        report.append("=" * 70)
        report.append("NETWORK TRAFFIC ANALYSIS REPORT")
        report.append("=" * 70)
        
        report.append(f"\nAnalysis ID: {results['analysis_id']}")
        report.append(f"Timestamp: {results['timestamp']}")
        report.append(f"PCAP File: {results['pcap_file']}")
        
        report.append(f"\n{'=' * 50}")
        report.append("STATISTICS")
        report.append("=" * 50)
        
        stats = results.get('statistics', {})
        report.append(f"Total Packets: {stats.get('total_packets', 0)}")
        report.append(f"Connections: {stats.get('connections', 0)}")
        report.append(f"DNS Queries: {stats.get('dns_queries', 0)}")
        report.append(f"HTTP Requests: {stats.get('http_requests', 0)}")
        
        protocols = stats.get('protocols', {})
        if protocols:
            report.append("\nProtocol Distribution:")
            for proto, count in protocols.items():
                report.append(f"  {proto.upper()}: {count}")
                
        report.append(f"\n{'=' * 50}")
        report.append("ALERTS SUMMARY")
        report.append("=" * 50)
        
        summary = results.get('summary', {})
        report.append(f"Critical: {summary.get('critical', 0)}")
        report.append(f"High: {summary.get('high', 0)}")
        report.append(f"Medium: {summary.get('medium', 0)}")
        report.append(f"Low: {summary.get('low', 0)}")
        
        report.append(f"\n{'=' * 50}")
        report.append("SECURITY ALERTS")
        report.append("=" * 50)
        
        for alert in results.get('alerts', [])[:20]:
            report.append(f"\n[{alert['severity'].upper()}] {alert['title']}")
            report.append(f"  Category: {alert['category']}")
            report.append(f"  Description: {alert['description']}")
            if alert.get('source_ip'):
                report.append(f"  Source: {alert['source_ip']}:{alert.get('source_port', '')}")
            if alert.get('dest_ip'):
                report.append(f"  Destination: {alert['dest_ip']}:{alert.get('dest_port', '')}")
                
        report.append(f"\n{'=' * 50}")
        report.append("TOP CONNECTIONS")
        report.append("=" * 50)
        
        connections = sorted(
            results.get('connections', []),
            key=lambda x: x.get('bytes_sent', 0) + x.get('bytes_received', 0),
            reverse=True
        )[:10]
        
        for conn in connections:
            total_bytes = conn.get('bytes_sent', 0) + conn.get('bytes_received', 0)
            report.append(f"\n{conn['src']} -> {conn['dst']}")
            report.append(f"  Protocol: {conn['protocol']}")
            report.append(f"  Packets: {conn['packets']}")
            report.append(f"  Total Bytes: {total_bytes}")
            
        return "\n".join(report)


class AdvancedNetworkTrafficAnalysis:
    """Main integration class for network traffic analysis"""
    
    def __init__(self):
        self.analyzer = TrafficAnalyzer()
        
    async def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """Analyze PCAP file"""
        return await self.analyzer.analyze_pcap(pcap_path)
