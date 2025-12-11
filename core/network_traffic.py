#!/usr/bin/env python3
"""
HydraRecon Network Traffic Analysis Module
Deep packet inspection, protocol analysis, and traffic intelligence.
"""

import asyncio
import json
import logging
import os
import re
import struct
import socket
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Callable, Tuple
from datetime import datetime
from enum import Enum
import subprocess
import tempfile


class ProtocolType(Enum):
    """Network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    FTP = "ftp"
    SSH = "ssh"
    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"
    TELNET = "telnet"
    RDP = "rdp"
    SMB = "smb"
    LDAP = "ldap"
    SNMP = "snmp"
    SIP = "sip"
    RTP = "rtp"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """Traffic threat levels"""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


class TrafficType(Enum):
    """Traffic classification types"""
    NORMAL = "normal"
    RECONNAISSANCE = "reconnaissance"
    EXPLOIT = "exploit"
    C2_BEACON = "c2_beacon"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    DOS_ATTACK = "dos_attack"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"


@dataclass
class PacketInfo:
    """Individual packet information"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: ProtocolType
    size: int
    payload: bytes = b""
    flags: List[str] = field(default_factory=list)
    ttl: int = 0
    sequence: int = 0


@dataclass
class FlowInfo:
    """Network flow information"""
    flow_id: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: ProtocolType
    start_time: datetime
    end_time: Optional[datetime] = None
    packet_count: int = 0
    byte_count: int = 0
    flags: Set[str] = field(default_factory=set)
    state: str = "new"


@dataclass
class ThreatIndicator:
    """Traffic threat indicator"""
    indicator_id: str
    flow_id: str
    threat_level: ThreatLevel
    traffic_type: TrafficType
    description: str
    source_ip: str
    dest_ip: str
    confidence: float = 0.0
    ioc_matches: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ProtocolStats:
    """Protocol statistics"""
    protocol: ProtocolType
    packet_count: int = 0
    byte_count: int = 0
    flow_count: int = 0
    unique_sources: Set[str] = field(default_factory=set)
    unique_destinations: Set[str] = field(default_factory=set)


@dataclass
class TrafficAnalysisResult:
    """Traffic analysis result"""
    capture_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_packets: int = 0
    total_bytes: int = 0
    total_flows: int = 0
    protocols: Dict[ProtocolType, ProtocolStats] = field(default_factory=dict)
    threats: List[ThreatIndicator] = field(default_factory=list)
    top_talkers: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_flows: List[FlowInfo] = field(default_factory=list)
    extracted_files: List[str] = field(default_factory=list)
    extracted_credentials: List[Dict[str, str]] = field(default_factory=list)


class PacketParser:
    """Parse network packets"""
    
    def __init__(self):
        self.logger = logging.getLogger("PacketParser")
        
        # Port to protocol mapping
        self.port_protocols = {
            20: ProtocolType.FTP,
            21: ProtocolType.FTP,
            22: ProtocolType.SSH,
            23: ProtocolType.TELNET,
            25: ProtocolType.SMTP,
            53: ProtocolType.DNS,
            80: ProtocolType.HTTP,
            110: ProtocolType.POP3,
            143: ProtocolType.IMAP,
            389: ProtocolType.LDAP,
            443: ProtocolType.HTTPS,
            445: ProtocolType.SMB,
            3389: ProtocolType.RDP,
            161: ProtocolType.SNMP,
            162: ProtocolType.SNMP,
            5060: ProtocolType.SIP,
            5061: ProtocolType.SIP,
        }
    
    def parse_pcap_file(self, filepath: str) -> List[PacketInfo]:
        """Parse packets from PCAP file using tshark"""
        packets = []
        
        try:
            # Use tshark to parse PCAP
            cmd = [
                "tshark", "-r", filepath,
                "-T", "json",
                "-e", "frame.time_epoch",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "tcp.srcport",
                "-e", "tcp.dstport",
                "-e", "udp.srcport",
                "-e", "udp.dstport",
                "-e", "ip.proto",
                "-e", "frame.len",
                "-e", "ip.ttl",
                "-e", "tcp.seq",
                "-e", "tcp.flags"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                
                for pkt in data:
                    layers = pkt.get("_source", {}).get("layers", {})
                    
                    # Parse timestamp
                    ts = layers.get("frame.time_epoch", ["0"])[0]
                    timestamp = datetime.fromtimestamp(float(ts))
                    
                    # Parse IPs
                    src_ip = layers.get("ip.src", ["0.0.0.0"])[0]
                    dst_ip = layers.get("ip.dst", ["0.0.0.0"])[0]
                    
                    # Parse ports
                    src_port = int(layers.get("tcp.srcport", layers.get("udp.srcport", ["0"]))[0])
                    dst_port = int(layers.get("tcp.dstport", layers.get("udp.dstport", ["0"]))[0])
                    
                    # Determine protocol
                    proto_num = int(layers.get("ip.proto", ["0"])[0])
                    protocol = self._get_protocol(proto_num, src_port, dst_port)
                    
                    # Parse other fields
                    size = int(layers.get("frame.len", ["0"])[0])
                    ttl = int(layers.get("ip.ttl", ["0"])[0])
                    seq = int(layers.get("tcp.seq", ["0"])[0])
                    
                    # Parse flags
                    flags = self._parse_tcp_flags(layers.get("tcp.flags", [""])[0])
                    
                    packet = PacketInfo(
                        timestamp=timestamp,
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        source_port=src_port,
                        dest_port=dst_port,
                        protocol=protocol,
                        size=size,
                        ttl=ttl,
                        sequence=seq,
                        flags=flags
                    )
                    
                    packets.append(packet)
                    
        except Exception as e:
            self.logger.error(f"Error parsing PCAP: {e}")
        
        return packets
    
    def _get_protocol(self, proto_num: int, src_port: int, dst_port: int) -> ProtocolType:
        """Determine protocol from port/protocol number"""
        if proto_num == 6:  # TCP
            # Check for known ports
            for port in [src_port, dst_port]:
                if port in self.port_protocols:
                    return self.port_protocols[port]
            return ProtocolType.TCP
        elif proto_num == 17:  # UDP
            for port in [src_port, dst_port]:
                if port in self.port_protocols:
                    return self.port_protocols[port]
            return ProtocolType.UDP
        elif proto_num == 1:  # ICMP
            return ProtocolType.ICMP
        
        return ProtocolType.UNKNOWN
    
    def _parse_tcp_flags(self, flags_hex: str) -> List[str]:
        """Parse TCP flags from hex string"""
        flags = []
        
        try:
            if flags_hex.startswith("0x"):
                flag_val = int(flags_hex, 16)
            else:
                flag_val = int(flags_hex or "0")
            
            if flag_val & 0x01:
                flags.append("FIN")
            if flag_val & 0x02:
                flags.append("SYN")
            if flag_val & 0x04:
                flags.append("RST")
            if flag_val & 0x08:
                flags.append("PSH")
            if flag_val & 0x10:
                flags.append("ACK")
            if flag_val & 0x20:
                flags.append("URG")
                
        except ValueError:
            pass
        
        return flags


class FlowTracker:
    """Track and analyze network flows"""
    
    def __init__(self):
        self.logger = logging.getLogger("FlowTracker")
        self.flows: Dict[str, FlowInfo] = {}
        self.flow_counter = 0
    
    def _generate_flow_key(self, packet: PacketInfo) -> str:
        """Generate flow key from packet"""
        # Use 5-tuple for flow identification
        return f"{packet.source_ip}:{packet.source_port}-{packet.dest_ip}:{packet.dest_port}-{packet.protocol.value}"
    
    def _generate_reverse_flow_key(self, packet: PacketInfo) -> str:
        """Generate reverse flow key"""
        return f"{packet.dest_ip}:{packet.dest_port}-{packet.source_ip}:{packet.source_port}-{packet.protocol.value}"
    
    def process_packet(self, packet: PacketInfo) -> FlowInfo:
        """Process packet and update flow"""
        flow_key = self._generate_flow_key(packet)
        reverse_key = self._generate_reverse_flow_key(packet)
        
        # Check for existing flow (either direction)
        if flow_key in self.flows:
            flow = self.flows[flow_key]
        elif reverse_key in self.flows:
            flow = self.flows[reverse_key]
        else:
            # Create new flow
            self.flow_counter += 1
            flow = FlowInfo(
                flow_id=f"flow_{self.flow_counter:08d}",
                source_ip=packet.source_ip,
                dest_ip=packet.dest_ip,
                source_port=packet.source_port,
                dest_port=packet.dest_port,
                protocol=packet.protocol,
                start_time=packet.timestamp
            )
            self.flows[flow_key] = flow
        
        # Update flow
        flow.packet_count += 1
        flow.byte_count += packet.size
        flow.end_time = packet.timestamp
        flow.flags.update(packet.flags)
        
        # Update state based on TCP flags
        if "SYN" in packet.flags and "ACK" not in packet.flags:
            flow.state = "syn_sent"
        elif "SYN" in packet.flags and "ACK" in packet.flags:
            flow.state = "established"
        elif "FIN" in packet.flags:
            flow.state = "closing"
        elif "RST" in packet.flags:
            flow.state = "reset"
        
        return flow
    
    def get_all_flows(self) -> List[FlowInfo]:
        """Get all tracked flows"""
        return list(self.flows.values())
    
    def get_flow_stats(self) -> Dict[str, Any]:
        """Get flow statistics"""
        return {
            "total_flows": len(self.flows),
            "established": sum(1 for f in self.flows.values() if f.state == "established"),
            "total_packets": sum(f.packet_count for f in self.flows.values()),
            "total_bytes": sum(f.byte_count for f in self.flows.values())
        }


class ThreatDetector:
    """Detect threats in network traffic"""
    
    def __init__(self):
        self.logger = logging.getLogger("ThreatDetector")
        self.threat_counter = 0
        
        # Known malicious IPs (would be loaded from threat intel)
        self.malicious_ips: Set[str] = set()
        
        # Known malicious domains
        self.malicious_domains: Set[str] = set()
        
        # C2 indicators
        self.c2_ports = {4444, 5555, 8080, 9999, 1337, 31337}
        
        # Suspicious patterns
        self.suspicious_patterns = [
            rb"(?i)password\s*[:=]",
            rb"(?i)passwd\s*[:=]",
            rb"(?i)secret\s*[:=]",
            rb"(?i)api[_-]?key\s*[:=]",
            rb"(?i)authorization\s*:\s*bearer",
            rb"(?i)x-auth-token",
        ]
    
    def load_iocs(self, ioc_file: str):
        """Load IOCs from file"""
        try:
            with open(ioc_file, 'r') as f:
                data = json.load(f)
                
            self.malicious_ips = set(data.get("ips", []))
            self.malicious_domains = set(data.get("domains", []))
            
        except Exception as e:
            self.logger.error(f"Error loading IOCs: {e}")
    
    def analyze_flow(self, flow: FlowInfo) -> Optional[ThreatIndicator]:
        """Analyze flow for threats"""
        
        # Check for known malicious IPs
        if flow.source_ip in self.malicious_ips or flow.dest_ip in self.malicious_ips:
            self.threat_counter += 1
            return ThreatIndicator(
                indicator_id=f"threat_{self.threat_counter:08d}",
                flow_id=flow.flow_id,
                threat_level=ThreatLevel.CRITICAL,
                traffic_type=TrafficType.MALWARE,
                description=f"Connection to known malicious IP",
                source_ip=flow.source_ip,
                dest_ip=flow.dest_ip,
                confidence=0.95,
                ioc_matches=[f"IP: {flow.source_ip if flow.source_ip in self.malicious_ips else flow.dest_ip}"]
            )
        
        # Check for potential C2 activity
        if flow.dest_port in self.c2_ports:
            self.threat_counter += 1
            return ThreatIndicator(
                indicator_id=f"threat_{self.threat_counter:08d}",
                flow_id=flow.flow_id,
                threat_level=ThreatLevel.SUSPICIOUS,
                traffic_type=TrafficType.C2_BEACON,
                description=f"Potential C2 communication on port {flow.dest_port}",
                source_ip=flow.source_ip,
                dest_ip=flow.dest_ip,
                confidence=0.6
            )
        
        # Check for port scan indicators
        if flow.packet_count == 1 and "RST" in flow.flags:
            self.threat_counter += 1
            return ThreatIndicator(
                indicator_id=f"threat_{self.threat_counter:08d}",
                flow_id=flow.flow_id,
                threat_level=ThreatLevel.SUSPICIOUS,
                traffic_type=TrafficType.RECONNAISSANCE,
                description="Possible port scan (single packet with RST)",
                source_ip=flow.source_ip,
                dest_ip=flow.dest_ip,
                confidence=0.5
            )
        
        # Check for SYN flood indicators
        if "SYN" in flow.flags and "ACK" not in flow.flags and flow.packet_count > 100:
            self.threat_counter += 1
            return ThreatIndicator(
                indicator_id=f"threat_{self.threat_counter:08d}",
                flow_id=flow.flow_id,
                threat_level=ThreatLevel.MALICIOUS,
                traffic_type=TrafficType.DOS_ATTACK,
                description="Possible SYN flood attack",
                source_ip=flow.source_ip,
                dest_ip=flow.dest_ip,
                confidence=0.75
            )
        
        return None
    
    def analyze_payload(self, packet: PacketInfo) -> List[ThreatIndicator]:
        """Analyze packet payload for threats"""
        threats = []
        
        if not packet.payload:
            return threats
        
        # Check for credential leakage
        for pattern in self.suspicious_patterns:
            if re.search(pattern, packet.payload):
                self.threat_counter += 1
                threats.append(ThreatIndicator(
                    indicator_id=f"threat_{self.threat_counter:08d}",
                    flow_id="",
                    threat_level=ThreatLevel.SUSPICIOUS,
                    traffic_type=TrafficType.DATA_EXFILTRATION,
                    description="Potential credential/secret in cleartext",
                    source_ip=packet.source_ip,
                    dest_ip=packet.dest_ip,
                    confidence=0.7
                ))
                break
        
        return threats


class ProtocolAnalyzer:
    """Deep protocol analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger("ProtocolAnalyzer")
    
    def analyze_http(self, payload: bytes) -> Dict[str, Any]:
        """Analyze HTTP traffic"""
        result = {
            "method": "",
            "uri": "",
            "headers": {},
            "body": b"",
            "suspicious": False,
            "findings": []
        }
        
        try:
            # Parse HTTP request
            lines = payload.split(b"\r\n")
            if lines:
                # Request line
                request_line = lines[0].decode('utf-8', errors='ignore')
                parts = request_line.split()
                if len(parts) >= 2:
                    result["method"] = parts[0]
                    result["uri"] = parts[1]
                
                # Headers
                for line in lines[1:]:
                    if b":" in line:
                        key, value = line.split(b":", 1)
                        result["headers"][key.decode('utf-8', errors='ignore').lower()] = \
                            value.decode('utf-8', errors='ignore').strip()
                    elif line == b"":
                        break
                
                # Check for suspicious patterns
                if any(sus in result["uri"].lower() for sus in 
                       ["../", "..%2f", "cmd=", "exec=", "system("]):
                    result["suspicious"] = True
                    result["findings"].append("Potential path traversal or command injection")
                
                if "user-agent" in result["headers"]:
                    ua = result["headers"]["user-agent"].lower()
                    if any(tool in ua for tool in ["sqlmap", "nikto", "nmap", "curl"]):
                        result["suspicious"] = True
                        result["findings"].append(f"Suspicious user-agent detected")
                        
        except Exception as e:
            self.logger.debug(f"Error parsing HTTP: {e}")
        
        return result
    
    def analyze_dns(self, payload: bytes) -> Dict[str, Any]:
        """Analyze DNS traffic"""
        result = {
            "query": "",
            "query_type": "",
            "response": [],
            "suspicious": False,
            "findings": []
        }
        
        try:
            # Simple DNS parsing
            if len(payload) > 12:
                # Skip DNS header
                offset = 12
                
                # Parse query name
                query_parts = []
                while offset < len(payload):
                    length = payload[offset]
                    if length == 0:
                        break
                    offset += 1
                    query_parts.append(payload[offset:offset+length].decode('utf-8', errors='ignore'))
                    offset += length
                
                result["query"] = ".".join(query_parts)
                
                # Check for suspicious domains
                query_lower = result["query"].lower()
                
                # Check for DGA patterns (long random strings)
                if len(result["query"]) > 30 and re.match(r'^[a-z0-9]+\.[a-z]+$', query_lower):
                    result["suspicious"] = True
                    result["findings"].append("Potential DGA domain")
                
                # Check for suspicious TLDs
                suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".xyz"]
                if any(query_lower.endswith(tld) for tld in suspicious_tlds):
                    result["suspicious"] = True
                    result["findings"].append("Suspicious TLD detected")
                    
        except Exception as e:
            self.logger.debug(f"Error parsing DNS: {e}")
        
        return result


class FileExtractor:
    """Extract files from network traffic"""
    
    def __init__(self):
        self.logger = logging.getLogger("FileExtractor")
        self.extracted_files: List[str] = []
        
        # Magic bytes for file detection
        self.magic_bytes = {
            b"\x50\x4b\x03\x04": "zip",
            b"\x50\x4b\x05\x06": "zip",
            b"\x52\x61\x72\x21": "rar",
            b"\x1f\x8b": "gzip",
            b"\x25\x50\x44\x46": "pdf",
            b"\x7f\x45\x4c\x46": "elf",
            b"\x4d\x5a": "exe",
            b"\x89\x50\x4e\x47": "png",
            b"\xff\xd8\xff": "jpg",
            b"\x47\x49\x46\x38": "gif",
        }
    
    def extract_from_pcap(self, filepath: str, output_dir: str) -> List[str]:
        """Extract files from PCAP using binwalk or custom extraction"""
        extracted = []
        
        try:
            # Try using tcpflow first
            cmd = ["tcpflow", "-r", filepath, "-o", output_dir]
            result = subprocess.run(cmd, capture_output=True, timeout=120)
            
            if result.returncode == 0:
                # List extracted files
                for f in os.listdir(output_dir):
                    extracted.append(os.path.join(output_dir, f))
                    
        except FileNotFoundError:
            self.logger.warning("tcpflow not found, trying alternative extraction")
        except Exception as e:
            self.logger.error(f"Error extracting files: {e}")
        
        return extracted
    
    def detect_file_type(self, data: bytes) -> Optional[str]:
        """Detect file type from magic bytes"""
        for magic, file_type in self.magic_bytes.items():
            if data.startswith(magic):
                return file_type
        return None


class NetworkTrafficAnalyzer:
    """Main network traffic analyzer"""
    
    def __init__(self):
        self.logger = logging.getLogger("NetworkTrafficAnalyzer")
        self.parser = PacketParser()
        self.flow_tracker = FlowTracker()
        self.threat_detector = ThreatDetector()
        self.protocol_analyzer = ProtocolAnalyzer()
        self.file_extractor = FileExtractor()
        
        self.analyses: List[TrafficAnalysisResult] = []
    
    async def analyze_pcap(self, filepath: str,
                          extract_files: bool = False,
                          callback: Optional[Callable] = None) -> TrafficAnalysisResult:
        """Analyze PCAP file"""
        
        import hashlib
        capture_id = hashlib.md5(f"{filepath}{datetime.now()}".encode()).hexdigest()[:12]
        
        result = TrafficAnalysisResult(
            capture_id=capture_id,
            start_time=datetime.now()
        )
        
        if callback:
            callback("Parsing PCAP file...", 10)
        
        # Parse packets
        packets = self.parser.parse_pcap_file(filepath)
        result.total_packets = len(packets)
        
        if callback:
            callback(f"Processing {len(packets)} packets...", 30)
        
        # Process packets into flows
        for i, packet in enumerate(packets):
            result.total_bytes += packet.size
            
            # Track flow
            flow = self.flow_tracker.process_packet(packet)
            
            # Update protocol stats
            if packet.protocol not in result.protocols:
                result.protocols[packet.protocol] = ProtocolStats(protocol=packet.protocol)
            
            stats = result.protocols[packet.protocol]
            stats.packet_count += 1
            stats.byte_count += packet.size
            stats.unique_sources.add(packet.source_ip)
            stats.unique_destinations.add(packet.dest_ip)
            
            if callback and i % 1000 == 0:
                progress = 30 + (i / len(packets)) * 40
                callback(f"Processed {i}/{len(packets)} packets", progress)
        
        if callback:
            callback("Analyzing flows...", 70)
        
        # Analyze flows for threats
        all_flows = self.flow_tracker.get_all_flows()
        result.total_flows = len(all_flows)
        
        for flow in all_flows:
            # Update protocol flow count
            if flow.protocol in result.protocols:
                result.protocols[flow.protocol].flow_count += 1
            
            # Check for threats
            threat = self.threat_detector.analyze_flow(flow)
            if threat:
                result.threats.append(threat)
                result.suspicious_flows.append(flow)
        
        if callback:
            callback("Calculating statistics...", 85)
        
        # Calculate top talkers
        ip_bytes: Dict[str, int] = {}
        for flow in all_flows:
            ip_bytes[flow.source_ip] = ip_bytes.get(flow.source_ip, 0) + flow.byte_count
            ip_bytes[flow.dest_ip] = ip_bytes.get(flow.dest_ip, 0) + flow.byte_count
        
        result.top_talkers = [
            {"ip": ip, "bytes": bytes_count}
            for ip, bytes_count in sorted(ip_bytes.items(), 
                                         key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Extract files if requested
        if extract_files:
            if callback:
                callback("Extracting files...", 90)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                extracted = self.file_extractor.extract_from_pcap(filepath, tmpdir)
                result.extracted_files = extracted
        
        result.end_time = datetime.now()
        self.analyses.append(result)
        
        if callback:
            callback("Analysis complete", 100)
        
        return result
    
    async def live_capture(self, interface: str,
                          duration: int = 60,
                          filter_expr: str = "",
                          callback: Optional[Callable] = None) -> TrafficAnalysisResult:
        """Perform live traffic capture and analysis"""
        
        import hashlib
        capture_id = hashlib.md5(f"{interface}{datetime.now()}".encode()).hexdigest()[:12]
        
        result = TrafficAnalysisResult(
            capture_id=capture_id,
            start_time=datetime.now()
        )
        
        # Create temporary PCAP file
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            pcap_file = tmp.name
        
        try:
            if callback:
                callback(f"Capturing on {interface} for {duration}s...", 10)
            
            # Run tcpdump for capture
            cmd = ["tcpdump", "-i", interface, "-w", pcap_file, "-c", "10000"]
            
            if filter_expr:
                cmd.extend(filter_expr.split())
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for specified duration
            try:
                process.wait(timeout=duration)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait()
            
            if callback:
                callback("Analyzing captured traffic...", 50)
            
            # Analyze the captured file
            result = await self.analyze_pcap(pcap_file, callback=callback)
            result.capture_id = capture_id
            
        finally:
            # Clean up
            try:
                os.unlink(pcap_file)
            except:
                pass
        
        return result
    
    def get_threat_summary(self, result: TrafficAnalysisResult) -> Dict[str, Any]:
        """Get threat summary from analysis"""
        threat_counts = {}
        for threat in result.threats:
            level = threat.threat_level.value
            threat_counts[level] = threat_counts.get(level, 0) + 1
        
        traffic_types = {}
        for threat in result.threats:
            ttype = threat.traffic_type.value
            traffic_types[ttype] = traffic_types.get(ttype, 0) + 1
        
        return {
            "total_threats": len(result.threats),
            "by_level": threat_counts,
            "by_type": traffic_types,
            "critical_count": threat_counts.get("critical", 0),
            "malicious_count": threat_counts.get("malicious", 0),
            "suspicious_count": threat_counts.get("suspicious", 0)
        }
    
    def export_report(self, capture_id: str, format: str = "json") -> str:
        """Export analysis report"""
        for analysis in self.analyses:
            if analysis.capture_id == capture_id:
                if format == "json":
                    return json.dumps({
                        "capture_id": analysis.capture_id,
                        "start_time": analysis.start_time.isoformat(),
                        "end_time": analysis.end_time.isoformat() if analysis.end_time else None,
                        "total_packets": analysis.total_packets,
                        "total_bytes": analysis.total_bytes,
                        "total_flows": analysis.total_flows,
                        "protocols": {
                            p.value: {
                                "packets": s.packet_count,
                                "bytes": s.byte_count,
                                "flows": s.flow_count
                            }
                            for p, s in analysis.protocols.items()
                        },
                        "threats": [
                            {
                                "id": t.indicator_id,
                                "level": t.threat_level.value,
                                "type": t.traffic_type.value,
                                "description": t.description,
                                "source": t.source_ip,
                                "dest": t.dest_ip,
                                "confidence": t.confidence
                            }
                            for t in analysis.threats
                        ],
                        "top_talkers": analysis.top_talkers
                    }, indent=2)
        
        return ""
