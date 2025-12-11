"""
HydraRecon Industrial Control System (ICS/SCADA) Security Module
Critical infrastructure security assessment and monitoring
"""

import asyncio
import hashlib
import json
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


class ICSProtocol(Enum):
    """ICS/SCADA protocols"""
    MODBUS = "modbus"
    DNP3 = "dnp3"
    BACNET = "bacnet"
    S7COMM = "s7comm"
    ETHERNETIP = "ethernet_ip"
    OPC_UA = "opc_ua"
    OPC_DA = "opc_da"
    IEC104 = "iec104"
    IEC61850 = "iec61850"
    PROFINET = "profinet"
    HART = "hart"
    FINS = "fins"


class DeviceType(Enum):
    """ICS device types"""
    PLC = "programmable_logic_controller"
    RTU = "remote_terminal_unit"
    HMI = "human_machine_interface"
    SCADA_SERVER = "scada_server"
    HISTORIAN = "historian"
    DCS = "distributed_control_system"
    SENSOR = "sensor"
    ACTUATOR = "actuator"
    GATEWAY = "protocol_gateway"
    RELAY = "protective_relay"
    IED = "intelligent_electronic_device"


class SeverityLevel(Enum):
    """Vulnerability severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatCategory(Enum):
    """ICS threat categories"""
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DOS = "denial_of_service"
    FIRMWARE_MANIPULATION = "firmware_manipulation"
    LOGIC_MANIPULATION = "logic_manipulation"
    DATA_INJECTION = "data_injection"
    RECONNAISSANCE = "reconnaissance"
    LATERAL_MOVEMENT = "lateral_movement"
    HISTORIAN_ATTACK = "historian_attack"


@dataclass
class ICSDevice:
    """Industrial control system device"""
    device_id: str
    ip_address: str
    mac_address: Optional[str] = None
    device_type: Optional[DeviceType] = None
    vendor: str = ""
    model: str = ""
    firmware_version: str = ""
    protocols: List[ICSProtocol] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    is_critical: bool = False
    discovered_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)


@dataclass
class ICSVulnerability:
    """ICS-specific vulnerability"""
    vuln_id: str
    title: str
    description: str
    severity: SeverityLevel
    category: ThreatCategory
    affected_device: Optional[ICSDevice] = None
    cve_id: Optional[str] = None
    icsa_id: Optional[str] = None
    cvss_score: float = 0.0
    exploit_available: bool = False
    remediation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class ProcessValue:
    """Process control value"""
    tag_name: str
    value: Any
    unit: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    quality: str = "good"
    source_device: str = ""


class ModbusScanner:
    """Modbus protocol scanner"""
    
    MODBUS_PORT = 502
    
    # Function codes
    FC_READ_COILS = 0x01
    FC_READ_DISCRETE_INPUTS = 0x02
    FC_READ_HOLDING_REGISTERS = 0x03
    FC_READ_INPUT_REGISTERS = 0x04
    FC_WRITE_SINGLE_COIL = 0x05
    FC_WRITE_SINGLE_REGISTER = 0x06
    FC_READ_DEVICE_ID = 0x2B
    
    def __init__(self):
        self.discovered_devices: List[ICSDevice] = []
        
    async def scan_host(self, ip: str, port: int = 502) -> Optional[ICSDevice]:
        """Scan host for Modbus service"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=5.0
            )
            
            # Read device identification
            device_info = await self._read_device_id(reader, writer)
            
            device = ICSDevice(
                device_id=hashlib.md5(f"{ip}:{port}".encode()).hexdigest()[:12],
                ip_address=ip,
                device_type=DeviceType.PLC,
                protocols=[ICSProtocol.MODBUS],
                open_ports=[port]
            )
            
            if device_info:
                device.vendor = device_info.get('vendor', '')
                device.model = device_info.get('product', '')
                
            # Test coil reading
            coils = await self._read_coils(reader, writer, 0, 10)
            if coils is not None:
                device.vulnerabilities.append({
                    'type': 'read_access',
                    'description': 'Modbus coils readable without authentication',
                    'severity': 'medium'
                })
                
            writer.close()
            await writer.wait_closed()
            
            self.discovered_devices.append(device)
            return device
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
            
    async def _read_device_id(self, reader, writer) -> Optional[Dict]:
        """Read Modbus device identification"""
        # Modbus TCP header + Read Device ID request
        transaction_id = 1
        protocol_id = 0
        length = 5
        unit_id = 1
        
        # Function code 0x2B, MEI type 0x0E, Read Device ID code 0x01
        request = struct.pack('>HHHBBBBB',
            transaction_id,
            protocol_id,
            length,
            unit_id,
            0x2B,  # Function code
            0x0E,  # MEI type
            0x01,  # Read device ID
            0x00   # Object ID
        )
        
        try:
            writer.write(request)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(256), timeout=2.0)
            
            if len(response) >= 9:
                # Parse response
                return {
                    'vendor': 'Unknown',
                    'product': 'Modbus Device'
                }
                
        except:
            pass
            
        return None
        
    async def _read_coils(self, reader, writer, start_addr: int, count: int) -> Optional[List[bool]]:
        """Read Modbus coils"""
        transaction_id = 2
        request = struct.pack('>HHHBBHH',
            transaction_id,
            0,  # protocol
            6,  # length
            1,  # unit id
            self.FC_READ_COILS,
            start_addr,
            count
        )
        
        try:
            writer.write(request)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(256), timeout=2.0)
            
            if len(response) >= 9:
                func_code = response[7]
                if func_code == self.FC_READ_COILS:
                    byte_count = response[8]
                    data = response[9:9+byte_count]
                    
                    coils = []
                    for byte in data:
                        for i in range(8):
                            if len(coils) < count:
                                coils.append(bool(byte & (1 << i)))
                    return coils
                    
        except:
            pass
            
        return None
        
    async def _read_holding_registers(self, reader, writer, start_addr: int, count: int) -> Optional[List[int]]:
        """Read Modbus holding registers"""
        transaction_id = 3
        request = struct.pack('>HHHBBHH',
            transaction_id,
            0,
            6,
            1,
            self.FC_READ_HOLDING_REGISTERS,
            start_addr,
            count
        )
        
        try:
            writer.write(request)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(256), timeout=2.0)
            
            if len(response) >= 9:
                func_code = response[7]
                if func_code == self.FC_READ_HOLDING_REGISTERS:
                    byte_count = response[8]
                    registers = []
                    for i in range(0, byte_count, 2):
                        value = struct.unpack('>H', response[9+i:11+i])[0]
                        registers.append(value)
                    return registers
                    
        except:
            pass
            
        return None


class S7CommScanner:
    """Siemens S7 protocol scanner"""
    
    S7_PORT = 102
    
    # COTP connection request
    COTP_CR = bytes([
        0x03, 0x00, 0x00, 0x16,  # TPKT header
        0x11, 0xE0, 0x00, 0x00,  # COTP CR
        0x00, 0x01, 0x00, 0xC0,  # Source TSAP
        0x01, 0x0A, 0xC1, 0x02,
        0x01, 0x00, 0xC2, 0x02,
        0x01, 0x02
    ])
    
    # S7 setup communication
    S7_SETUP = bytes([
        0x03, 0x00, 0x00, 0x19,
        0x02, 0xF0, 0x80, 0x32,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x08, 0x00,
        0x00, 0xF0, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00,
        0xF0
    ])
    
    def __init__(self):
        self.discovered_devices: List[ICSDevice] = []
        
    async def scan_host(self, ip: str) -> Optional[ICSDevice]:
        """Scan host for S7 service"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, self.S7_PORT),
                timeout=5.0
            )
            
            # COTP connection
            writer.write(self.COTP_CR)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(256), timeout=2.0)
            
            if len(response) >= 4:
                # COTP connection confirmed
                device = ICSDevice(
                    device_id=hashlib.md5(f"{ip}:s7".encode()).hexdigest()[:12],
                    ip_address=ip,
                    device_type=DeviceType.PLC,
                    vendor="Siemens",
                    protocols=[ICSProtocol.S7COMM],
                    open_ports=[self.S7_PORT]
                )
                
                # Try to get more info
                cpu_info = await self._read_cpu_info(reader, writer)
                if cpu_info:
                    device.model = cpu_info.get('module_type', '')
                    device.firmware_version = cpu_info.get('firmware', '')
                    
                writer.close()
                await writer.wait_closed()
                
                self.discovered_devices.append(device)
                return device
                
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass
            
        return None
        
    async def _read_cpu_info(self, reader, writer) -> Optional[Dict]:
        """Read S7 CPU information"""
        # S7 read SZL request for module identification
        szl_request = bytes([
            0x03, 0x00, 0x00, 0x21,
            0x02, 0xF0, 0x80, 0x32,
            0x07, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x08, 0x00,
            0x08, 0x00, 0x01, 0x12,
            0x04, 0x11, 0x44, 0x01,
            0x00, 0xFF, 0x09, 0x00,
            0x04, 0x00, 0x11, 0x00,
            0x00
        ])
        
        try:
            writer.write(self.S7_SETUP)
            await writer.drain()
            
            await asyncio.wait_for(reader.read(256), timeout=2.0)
            
            writer.write(szl_request)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(512), timeout=2.0)
            
            if len(response) > 40:
                return {
                    'module_type': 'S7-300/400',
                    'firmware': 'Unknown'
                }
                
        except:
            pass
            
        return None


class BACnetScanner:
    """BACnet protocol scanner"""
    
    BACNET_PORT = 47808
    
    def __init__(self):
        self.discovered_devices: List[ICSDevice] = []
        
    async def scan_network(self, network_range: str) -> List[ICSDevice]:
        """Scan network for BACnet devices using Who-Is"""
        # BACnet Who-Is broadcast
        who_is = bytes([
            0x81, 0x0B, 0x00, 0x0C,  # BVLC header
            0x01, 0x20,              # NPDU
            0x10, 0x08,              # APDU Who-Is
            0x00, 0x00,              # Device instance range
            0xFF, 0xFF
        ])
        
        # This would be UDP broadcast in real implementation
        logger.info(f"BACnet discovery would scan {network_range}")
        
        return self.discovered_devices


class DNP3Scanner:
    """DNP3 protocol scanner"""
    
    DNP3_PORT = 20000
    
    def __init__(self):
        self.discovered_devices: List[ICSDevice] = []
        
    async def scan_host(self, ip: str, port: int = 20000) -> Optional[ICSDevice]:
        """Scan host for DNP3 service"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=5.0
            )
            
            # DNP3 link layer frame
            link_request = self._build_link_frame(1, 0, 0x40, True)
            
            writer.write(link_request)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(256), timeout=2.0)
            
            if response and response[0:2] == b'\x05\x64':
                device = ICSDevice(
                    device_id=hashlib.md5(f"{ip}:dnp3".encode()).hexdigest()[:12],
                    ip_address=ip,
                    device_type=DeviceType.RTU,
                    protocols=[ICSProtocol.DNP3],
                    open_ports=[port]
                )
                
                writer.close()
                await writer.wait_closed()
                
                self.discovered_devices.append(device)
                return device
                
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass
            
        return None
        
    def _build_link_frame(self, dest: int, src: int, control: int, dir_prm: bool) -> bytes:
        """Build DNP3 link layer frame"""
        start = bytes([0x05, 0x64])  # Start bytes
        length = 5  # Minimum length
        
        control_byte = control
        if dir_prm:
            control_byte |= 0x80
            
        frame = bytearray()
        frame.extend(start)
        frame.append(length)
        frame.append(control_byte)
        frame.extend(struct.pack('<H', dest))
        frame.extend(struct.pack('<H', src))
        
        # Calculate CRC (simplified)
        crc = self._calculate_crc(frame[2:])
        frame.extend(struct.pack('<H', crc))
        
        return bytes(frame)
        
    def _calculate_crc(self, data: bytes) -> int:
        """Calculate DNP3 CRC"""
        crc = 0xFFFF
        poly = 0xA6BC
        
        for byte in data:
            for i in range(8):
                if (crc ^ byte) & 0x0001:
                    crc = (crc >> 1) ^ poly
                else:
                    crc >>= 1
                byte >>= 1
                
        return ~crc & 0xFFFF


class ICSVulnerabilityScanner:
    """ICS-specific vulnerability scanner"""
    
    def __init__(self):
        self.known_vulnerabilities = self._load_vulnerability_db()
        
    def _load_vulnerability_db(self) -> Dict[str, List[Dict]]:
        """Load ICS vulnerability database"""
        return {
            'siemens': [
                {
                    'cve': 'CVE-2019-13945',
                    'icsa': 'ICSA-19-344-06',
                    'title': 'Siemens S7-1500 DoS',
                    'severity': 'high',
                    'description': 'Denial of Service vulnerability in S7-1500 CPU'
                },
                {
                    'cve': 'CVE-2019-10936',
                    'icsa': 'ICSA-19-190-03',
                    'title': 'Siemens SINAMICS S120 Improper Auth',
                    'severity': 'critical',
                    'description': 'Authentication bypass vulnerability'
                }
            ],
            'schneider': [
                {
                    'cve': 'CVE-2020-7561',
                    'icsa': 'ICSA-20-205-01',
                    'title': 'Schneider Modicon M340 RCE',
                    'severity': 'critical',
                    'description': 'Remote code execution in Modicon M340'
                }
            ],
            'rockwell': [
                {
                    'cve': 'CVE-2020-12034',
                    'icsa': 'ICSA-20-163-01',
                    'title': 'Allen-Bradley MicroLogix DoS',
                    'severity': 'high',
                    'description': 'Denial of Service in MicroLogix 1100'
                }
            ],
            'generic_modbus': [
                {
                    'vuln_id': 'MODBUS-001',
                    'title': 'Modbus No Authentication',
                    'severity': 'high',
                    'description': 'Modbus protocol lacks authentication'
                },
                {
                    'vuln_id': 'MODBUS-002',
                    'title': 'Modbus No Encryption',
                    'severity': 'medium',
                    'description': 'Modbus traffic is unencrypted'
                }
            ],
            'generic_s7': [
                {
                    'vuln_id': 'S7-001',
                    'title': 'S7 Default Configuration',
                    'severity': 'high',
                    'description': 'S7 PLC using default security settings'
                }
            ]
        }
        
    def scan_device(self, device: ICSDevice) -> List[ICSVulnerability]:
        """Scan device for known vulnerabilities"""
        vulnerabilities = []
        
        vendor_lower = device.vendor.lower()
        
        # Check vendor-specific vulnerabilities
        for vendor_key in self.known_vulnerabilities:
            if vendor_key in vendor_lower:
                for vuln in self.known_vulnerabilities[vendor_key]:
                    vulnerabilities.append(ICSVulnerability(
                        vuln_id=vuln.get('cve', vuln.get('vuln_id', '')),
                        title=vuln['title'],
                        description=vuln['description'],
                        severity=SeverityLevel[vuln['severity'].upper()],
                        category=ThreatCategory.UNAUTHORIZED_ACCESS,
                        affected_device=device,
                        cve_id=vuln.get('cve'),
                        icsa_id=vuln.get('icsa')
                    ))
                    
        # Check protocol-specific vulnerabilities
        for protocol in device.protocols:
            if protocol == ICSProtocol.MODBUS:
                for vuln in self.known_vulnerabilities['generic_modbus']:
                    vulnerabilities.append(ICSVulnerability(
                        vuln_id=vuln['vuln_id'],
                        title=vuln['title'],
                        description=vuln['description'],
                        severity=SeverityLevel[vuln['severity'].upper()],
                        category=ThreatCategory.UNAUTHORIZED_ACCESS,
                        affected_device=device
                    ))
                    
            elif protocol == ICSProtocol.S7COMM:
                for vuln in self.known_vulnerabilities['generic_s7']:
                    vulnerabilities.append(ICSVulnerability(
                        vuln_id=vuln['vuln_id'],
                        title=vuln['title'],
                        description=vuln['description'],
                        severity=SeverityLevel[vuln['severity'].upper()],
                        category=ThreatCategory.UNAUTHORIZED_ACCESS,
                        affected_device=device
                    ))
                    
        return vulnerabilities


class ICSNetworkSegmentation:
    """Analyze ICS network segmentation"""
    
    def __init__(self):
        self.zones: Dict[str, List[ICSDevice]] = {}
        self.conduits: List[Dict[str, Any]] = []
        
    def analyze_topology(self, devices: List[ICSDevice]) -> Dict[str, Any]:
        """Analyze ICS network topology"""
        analysis = {
            'zones': {},
            'findings': [],
            'recommendations': []
        }
        
        # Group devices by network segment
        segments = {}
        for device in devices:
            network = '.'.join(device.ip_address.split('.')[:3])
            if network not in segments:
                segments[network] = []
            segments[network].append(device)
            
        analysis['zones'] = segments
        
        # Analyze segmentation
        if len(segments) == 1:
            analysis['findings'].append({
                'type': 'flat_network',
                'severity': 'high',
                'description': 'ICS devices appear to be on flat network without segmentation'
            })
            analysis['recommendations'].append(
                'Implement network segmentation according to IEC 62443 zones and conduits model'
            )
            
        # Check for proper zone separation
        critical_devices = [d for d in devices if d.is_critical or d.device_type == DeviceType.PLC]
        non_critical = [d for d in devices if not d.is_critical]
        
        if critical_devices and non_critical:
            critical_networks = set('.'.join(d.ip_address.split('.')[:3]) for d in critical_devices)
            non_critical_networks = set('.'.join(d.ip_address.split('.')[:3]) for d in non_critical)
            
            if critical_networks & non_critical_networks:
                analysis['findings'].append({
                    'type': 'mixed_criticality',
                    'severity': 'high',
                    'description': 'Critical and non-critical devices on same network segment'
                })
                
        return analysis


class ICSAnomalyDetection:
    """ICS-specific anomaly detection"""
    
    def __init__(self):
        self.baseline_values: Dict[str, List[float]] = {}
        self.alerts: List[Dict[str, Any]] = []
        
    def set_baseline(self, tag: str, values: List[float]):
        """Set baseline values for process tag"""
        self.baseline_values[tag] = values
        
    def check_value(self, value: ProcessValue) -> Optional[Dict[str, Any]]:
        """Check if value is anomalous"""
        tag = value.tag_name
        
        if tag not in self.baseline_values:
            return None
            
        baseline = self.baseline_values[tag]
        
        if not baseline:
            return None
            
        # Calculate statistics
        import statistics
        mean = statistics.mean(baseline)
        stdev = statistics.stdev(baseline) if len(baseline) > 1 else 0
        
        # Check for anomaly (more than 3 standard deviations)
        if stdev > 0:
            z_score = abs(value.value - mean) / stdev
            
            if z_score > 3:
                alert = {
                    'type': 'anomaly',
                    'tag': tag,
                    'value': value.value,
                    'expected_range': (mean - 3*stdev, mean + 3*stdev),
                    'z_score': z_score,
                    'timestamp': value.timestamp.isoformat()
                }
                self.alerts.append(alert)
                return alert
                
        # Check for rate of change
        if baseline:
            rate = abs(value.value - baseline[-1])
            max_rate = max(abs(baseline[i] - baseline[i-1]) for i in range(1, len(baseline))) if len(baseline) > 1 else 0
            
            if max_rate > 0 and rate > max_rate * 2:
                alert = {
                    'type': 'rate_anomaly',
                    'tag': tag,
                    'rate': rate,
                    'max_expected_rate': max_rate,
                    'timestamp': value.timestamp.isoformat()
                }
                self.alerts.append(alert)
                return alert
                
        return None


class ICSSecurityAssessment:
    """Comprehensive ICS security assessment"""
    
    def __init__(self):
        self.modbus_scanner = ModbusScanner()
        self.s7_scanner = S7CommScanner()
        self.dnp3_scanner = DNP3Scanner()
        self.bacnet_scanner = BACnetScanner()
        self.vuln_scanner = ICSVulnerabilityScanner()
        self.segmentation = ICSNetworkSegmentation()
        
    async def discover_devices(self, targets: List[str]) -> List[ICSDevice]:
        """Discover ICS devices on network"""
        all_devices = []
        
        for target in targets:
            # Scan for different protocols
            modbus = await self.modbus_scanner.scan_host(target)
            if modbus:
                all_devices.append(modbus)
                
            s7 = await self.s7_scanner.scan_host(target)
            if s7:
                all_devices.append(s7)
                
            dnp3 = await self.dnp3_scanner.scan_host(target)
            if dnp3:
                all_devices.append(dnp3)
                
        return all_devices
        
    async def full_assessment(self, targets: List[str]) -> Dict[str, Any]:
        """Perform full ICS security assessment"""
        results = {
            'assessment_id': hashlib.md5(f"{targets}{datetime.now()}".encode()).hexdigest()[:12],
            'timestamp': datetime.now().isoformat(),
            'targets': targets,
            'devices': [],
            'vulnerabilities': [],
            'segmentation_analysis': None,
            'findings': [],
            'summary': {
                'devices_found': 0,
                'critical_vulns': 0,
                'high_vulns': 0,
                'medium_vulns': 0,
                'low_vulns': 0
            },
            'recommendations': []
        }
        
        # Device discovery
        devices = await self.discover_devices(targets)
        results['devices'] = [
            {
                'id': d.device_id,
                'ip': d.ip_address,
                'type': d.device_type.value if d.device_type else 'unknown',
                'vendor': d.vendor,
                'model': d.model,
                'protocols': [p.value for p in d.protocols],
                'ports': d.open_ports
            }
            for d in devices
        ]
        results['summary']['devices_found'] = len(devices)
        
        # Vulnerability scanning
        for device in devices:
            vulns = self.vuln_scanner.scan_device(device)
            
            for vuln in vulns:
                results['vulnerabilities'].append({
                    'id': vuln.vuln_id,
                    'title': vuln.title,
                    'description': vuln.description,
                    'severity': vuln.severity.value,
                    'device': device.ip_address,
                    'cve': vuln.cve_id,
                    'icsa': vuln.icsa_id
                })
                
                if vuln.severity == SeverityLevel.CRITICAL:
                    results['summary']['critical_vulns'] += 1
                elif vuln.severity == SeverityLevel.HIGH:
                    results['summary']['high_vulns'] += 1
                elif vuln.severity == SeverityLevel.MEDIUM:
                    results['summary']['medium_vulns'] += 1
                else:
                    results['summary']['low_vulns'] += 1
                    
        # Segmentation analysis
        results['segmentation_analysis'] = self.segmentation.analyze_topology(devices)
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
        
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if results['summary']['critical_vulns'] > 0:
            recommendations.append("CRITICAL: Address all critical vulnerabilities immediately")
            
        if results['summary']['devices_found'] > 0:
            recommendations.append("Implement network segmentation following IEC 62443 zones and conduits")
            recommendations.append("Deploy industrial firewalls with protocol-aware inspection")
            recommendations.append("Implement continuous monitoring with ICS-specific IDS")
            recommendations.append("Establish secure remote access through jump servers")
            recommendations.append("Develop and test incident response procedures for ICS environments")
            
        # Protocol-specific recommendations
        protocols_found = set()
        for device in results.get('devices', []):
            protocols_found.update(device.get('protocols', []))
            
        if 'modbus' in protocols_found:
            recommendations.append("Consider Modbus/TCP security: implement authentication wrapper or upgrade to Modbus/TCP Security")
            
        if 's7comm' in protocols_found:
            recommendations.append("Enable S7 security features including access control and encryption")
            
        return recommendations
        
    def generate_report(self, results: Dict) -> str:
        """Generate ICS security assessment report"""
        report = []
        
        report.append("=" * 70)
        report.append("ICS/SCADA SECURITY ASSESSMENT REPORT")
        report.append("=" * 70)
        
        report.append(f"\nAssessment ID: {results['assessment_id']}")
        report.append(f"Timestamp: {results['timestamp']}")
        report.append(f"Targets: {', '.join(results['targets'])}")
        
        report.append(f"\n{'=' * 50}")
        report.append("EXECUTIVE SUMMARY")
        report.append("=" * 50)
        
        summary = results['summary']
        report.append(f"\nDevices Discovered: {summary['devices_found']}")
        report.append(f"Critical Vulnerabilities: {summary['critical_vulns']}")
        report.append(f"High Vulnerabilities: {summary['high_vulns']}")
        report.append(f"Medium Vulnerabilities: {summary['medium_vulns']}")
        report.append(f"Low Vulnerabilities: {summary['low_vulns']}")
        
        report.append(f"\n{'=' * 50}")
        report.append("DISCOVERED DEVICES")
        report.append("=" * 50)
        
        for device in results.get('devices', []):
            report.append(f"\n[{device['type'].upper()}] {device['ip']}")
            report.append(f"  Vendor: {device['vendor'] or 'Unknown'}")
            report.append(f"  Model: {device['model'] or 'Unknown'}")
            report.append(f"  Protocols: {', '.join(device['protocols'])}")
            report.append(f"  Open Ports: {device['ports']}")
            
        report.append(f"\n{'=' * 50}")
        report.append("VULNERABILITIES")
        report.append("=" * 50)
        
        for vuln in results.get('vulnerabilities', []):
            report.append(f"\n[{vuln['severity'].upper()}] {vuln['title']}")
            report.append(f"  Device: {vuln['device']}")
            if vuln.get('cve'):
                report.append(f"  CVE: {vuln['cve']}")
            if vuln.get('icsa'):
                report.append(f"  ICS-CERT: {vuln['icsa']}")
            report.append(f"  Description: {vuln['description']}")
            
        report.append(f"\n{'=' * 50}")
        report.append("NETWORK SEGMENTATION")
        report.append("=" * 50)
        
        seg = results.get('segmentation_analysis', {})
        for finding in seg.get('findings', []):
            report.append(f"\n[{finding['severity'].upper()}] {finding['type']}")
            report.append(f"  {finding['description']}")
            
        report.append(f"\n{'=' * 50}")
        report.append("RECOMMENDATIONS")
        report.append("=" * 50)
        
        for i, rec in enumerate(results.get('recommendations', []), 1):
            report.append(f"\n{i}. {rec}")
            
        report.append(f"\n{'=' * 50}")
        report.append("COMPLIANCE REFERENCES")
        report.append("=" * 50)
        
        report.append("\n- IEC 62443 Industrial Automation Security")
        report.append("- NIST SP 800-82 Guide to ICS Security")
        report.append("- NERC CIP (for Electric Utilities)")
        report.append("- ISA/IEC 62443 Cybersecurity Framework")
        
        return "\n".join(report)


class ICSSecurityModule:
    """Main integration class for ICS/SCADA security"""
    
    def __init__(self):
        self.assessment = ICSSecurityAssessment()
        self.anomaly_detection = ICSAnomalyDetection()
        
    async def run_assessment(self, targets: List[str]) -> Dict[str, Any]:
        """Run comprehensive ICS security assessment"""
        return await self.assessment.full_assessment(targets)
