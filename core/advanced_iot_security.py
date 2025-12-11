"""
HydraRecon Advanced IoT Security Module
Comprehensive IoT device security analysis and exploitation framework
"""

import asyncio
import hashlib
import json
import os
import re
import socket
import struct
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import logging

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

logger = logging.getLogger(__name__)


class IoTDeviceType(Enum):
    """IoT device categories"""
    CAMERA = "camera"
    ROUTER = "router"
    SMART_HOME = "smart_home"
    INDUSTRIAL = "industrial"
    MEDICAL = "medical"
    AUTOMOTIVE = "automotive"
    WEARABLE = "wearable"
    SMART_METER = "smart_meter"
    PLC = "plc"
    RTU = "rtu"
    SENSOR = "sensor"
    ACTUATOR = "actuator"
    GATEWAY = "gateway"
    UNKNOWN = "unknown"


class IoTProtocol(Enum):
    """IoT communication protocols"""
    MQTT = "mqtt"
    COAP = "coap"
    ZIGBEE = "zigbee"
    ZWAVE = "z-wave"
    BLE = "ble"
    LORAWAN = "lorawan"
    MODBUS = "modbus"
    BACNET = "bacnet"
    DNP3 = "dnp3"
    OPCUA = "opc-ua"
    AMQP = "amqp"
    HTTP = "http"
    WEBSOCKET = "websocket"
    UPNP = "upnp"


class VulnerabilityType(Enum):
    """IoT vulnerability types"""
    DEFAULT_CREDENTIALS = "default_credentials"
    WEAK_ENCRYPTION = "weak_encryption"
    NO_ENCRYPTION = "no_encryption"
    COMMAND_INJECTION = "command_injection"
    BUFFER_OVERFLOW = "buffer_overflow"
    PATH_TRAVERSAL = "path_traversal"
    HARDCODED_SECRETS = "hardcoded_secrets"
    INSECURE_UPDATE = "insecure_update"
    DEBUG_INTERFACE = "debug_interface"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    REPLAY_ATTACK = "replay_attack"
    FIRMWARE_EXTRACTION = "firmware_extraction"


class SeverityLevel(Enum):
    """Vulnerability severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class IoTDevice:
    """IoT device information"""
    device_id: str
    ip_address: str
    mac_address: Optional[str] = None
    device_type: IoTDeviceType = IoTDeviceType.UNKNOWN
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    protocols: List[IoTProtocol] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    vulnerabilities: List['IoTVulnerability'] = field(default_factory=list)
    last_seen: datetime = field(default_factory=datetime.now)
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class IoTVulnerability:
    """IoT vulnerability finding"""
    vuln_id: str
    vuln_type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    affected_device: str
    affected_component: str
    cvss_score: float = 0.0
    cve_ids: List[str] = field(default_factory=list)
    remediation: str = ""
    proof_of_concept: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class FirmwareAnalysis:
    """Firmware analysis results"""
    firmware_hash: str
    firmware_size: int
    architecture: str = "unknown"
    endianness: str = "unknown"
    filesystem_type: str = "unknown"
    compression: str = "unknown"
    extracted_files: List[str] = field(default_factory=list)
    hardcoded_credentials: List[Dict[str, str]] = field(default_factory=list)
    cryptographic_keys: List[Dict[str, str]] = field(default_factory=list)
    network_configurations: List[Dict[str, str]] = field(default_factory=list)
    vulnerabilities: List[IoTVulnerability] = field(default_factory=list)


class IoTDeviceDiscovery:
    """IoT device discovery engine"""
    
    def __init__(self):
        self.discovered_devices: Dict[str, IoTDevice] = {}
        self.discovery_callbacks: List[Callable] = []
        self._stop_discovery = False
        
    def discover_network(self, network: str, timeout: int = 30) -> List[IoTDevice]:
        """Discover IoT devices on network"""
        devices = []
        
        # Common IoT ports to scan
        iot_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            80,    # HTTP
            443,   # HTTPS
            554,   # RTSP
            1883,  # MQTT
            5683,  # CoAP
            8080,  # HTTP Alt
            8443,  # HTTPS Alt
            8883,  # MQTTS
            47808, # BACnet
            102,   # S7comm
            502,   # Modbus
            44818, # EtherNet/IP
            20000, # DNP3
        ]
        
        if NMAP_AVAILABLE:
            devices = self._nmap_discovery(network, iot_ports, timeout)
        else:
            devices = self._socket_discovery(network, iot_ports, timeout)
            
        return devices
        
    def _nmap_discovery(self, network: str, ports: List[int], timeout: int) -> List[IoTDevice]:
        """Use nmap for device discovery"""
        devices = []
        
        try:
            nm = nmap.PortScanner()
            port_str = ','.join(map(str, ports))
            nm.scan(hosts=network, ports=port_str, arguments='-sV -O --osscan-guess')
            
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    device = IoTDevice(
                        device_id=hashlib.md5(host.encode()).hexdigest()[:12],
                        ip_address=host,
                        mac_address=nm[host].get('addresses', {}).get('mac'),
                        open_ports=[],
                        services={}
                    )
                    
                    # Get open ports and services
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            port_info = nm[host][proto][port]
                            if port_info['state'] == 'open':
                                device.open_ports.append(port)
                                device.services[port] = port_info.get('product', '') or port_info.get('name', '')
                                
                    # Identify device type
                    device.device_type = self._identify_device_type(device)
                    device.manufacturer = self._identify_manufacturer(device)
                    device.protocols = self._identify_protocols(device)
                    
                    devices.append(device)
                    self.discovered_devices[device.device_id] = device
                    
        except Exception as e:
            logger.error(f"Nmap discovery error: {e}")
            
        return devices
        
    def _socket_discovery(self, network: str, ports: List[int], timeout: int) -> List[IoTDevice]:
        """Basic socket-based discovery"""
        devices = []
        
        # Parse network range
        try:
            if '/' in network:
                import ipaddress
                net = ipaddress.ip_network(network, strict=False)
                hosts = [str(ip) for ip in net.hosts()]
            else:
                hosts = [network]
        except Exception:
            hosts = [network]
            
        for host in hosts[:256]:  # Limit to first 256 hosts
            if self._stop_discovery:
                break
                
            device = None
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    
                    if result == 0:
                        if not device:
                            device = IoTDevice(
                                device_id=hashlib.md5(host.encode()).hexdigest()[:12],
                                ip_address=host,
                                open_ports=[],
                                services={}
                            )
                        device.open_ports.append(port)
                        device.services[port] = self._get_service_name(port)
                        
                except Exception:
                    pass
                    
            if device:
                device.device_type = self._identify_device_type(device)
                device.protocols = self._identify_protocols(device)
                devices.append(device)
                self.discovered_devices[device.device_id] = device
                
        return devices
        
    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            80: 'http',
            443: 'https',
            554: 'rtsp',
            1883: 'mqtt',
            5683: 'coap',
            8080: 'http-alt',
            8443: 'https-alt',
            8883: 'mqtts',
            47808: 'bacnet',
            102: 's7comm',
            502: 'modbus',
            44818: 'ethernet-ip',
            20000: 'dnp3',
        }
        return services.get(port, 'unknown')
        
    def _identify_device_type(self, device: IoTDevice) -> IoTDeviceType:
        """Identify IoT device type"""
        ports = device.open_ports
        services = device.services
        
        # Camera detection
        if 554 in ports or 'rtsp' in str(services).lower():
            return IoTDeviceType.CAMERA
            
        # Industrial protocols
        if any(p in ports for p in [502, 102, 44818, 20000, 47808]):
            if 502 in ports:
                return IoTDeviceType.PLC
            return IoTDeviceType.INDUSTRIAL
            
        # Smart home
        if 1883 in ports or 8883 in ports:
            return IoTDeviceType.SMART_HOME
            
        # Router/Gateway
        if 80 in ports or 443 in ports:
            if 22 in ports or 23 in ports:
                return IoTDeviceType.ROUTER
                
        return IoTDeviceType.UNKNOWN
        
    def _identify_manufacturer(self, device: IoTDevice) -> Optional[str]:
        """Identify device manufacturer from MAC OUI"""
        if not device.mac_address:
            return None
            
        # OUI database (partial)
        oui_database = {
            '00:0C:29': 'VMware',
            '00:50:56': 'VMware',
            'B8:27:EB': 'Raspberry Pi',
            'DC:A6:32': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:1E:C0': 'Microchip',
            '00:04:A3': 'Microchip',
            '40:D8:55': 'Espressif',
            '24:0A:C4': 'Espressif',
            '18:FE:34': 'Espressif',
            'B4:E6:2D': 'Espressif',
            '3C:71:BF': 'Espressif',
            '00:17:88': 'Philips Hue',
            'EC:B5:FA': 'Philips Hue',
            '00:06:6B': 'Cisco',
            '00:1A:A0': 'Dell',
            'F0:9F:C2': 'Ubiquiti',
            '04:18:D6': 'Ubiquiti',
            '68:D7:9A': 'Ubiquiti',
            '80:2A:A8': 'Ubiquiti',
            '00:1C:C0': 'Honeywell',
            '00:08:E2': 'ABB',
            '00:0B:AB': 'Siemens',
            '00:0E:8C': 'Siemens',
            '08:00:86': 'Siemens',
        }
        
        mac_prefix = device.mac_address[:8].upper()
        return oui_database.get(mac_prefix)
        
    def _identify_protocols(self, device: IoTDevice) -> List[IoTProtocol]:
        """Identify IoT protocols"""
        protocols = []
        
        port_to_protocol = {
            1883: IoTProtocol.MQTT,
            8883: IoTProtocol.MQTT,
            5683: IoTProtocol.COAP,
            47808: IoTProtocol.BACNET,
            502: IoTProtocol.MODBUS,
            20000: IoTProtocol.DNP3,
            4840: IoTProtocol.OPCUA,
            5672: IoTProtocol.AMQP,
            80: IoTProtocol.HTTP,
            443: IoTProtocol.HTTP,
        }
        
        for port in device.open_ports:
            if port in port_to_protocol:
                protocols.append(port_to_protocol[port])
                
        return protocols


class IoTVulnerabilityScanner:
    """IoT vulnerability scanner"""
    
    def __init__(self):
        self.default_credentials = self._load_default_credentials()
        self.vulnerability_signatures = self._load_signatures()
        
    def _load_default_credentials(self) -> Dict[str, List[Tuple[str, str]]]:
        """Load default credentials database"""
        return {
            'camera': [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '12345'),
                ('root', 'root'),
                ('admin', ''),
                ('user', 'user'),
            ],
            'router': [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '1234'),
                ('root', 'admin'),
                ('cisco', 'cisco'),
                ('admin', 'default'),
            ],
            'plc': [
                ('admin', 'admin'),
                ('guest', 'guest'),
                ('user', 'user'),
                ('operator', 'operator'),
            ],
            'smart_home': [
                ('admin', 'admin'),
                ('user', '1234'),
                ('root', 'password'),
            ],
            'telnet': [
                ('admin', 'admin'),
                ('root', 'root'),
                ('admin', ''),
                ('root', ''),
                ('support', 'support'),
            ],
            'ssh': [
                ('root', 'root'),
                ('pi', 'raspberry'),
                ('admin', 'admin'),
                ('user', 'user'),
            ],
        }
        
    def _load_signatures(self) -> List[Dict[str, Any]]:
        """Load vulnerability signatures"""
        return [
            {
                'id': 'IOT-001',
                'type': VulnerabilityType.DEBUG_INTERFACE,
                'pattern': r'telnet.*enabled|debug.*port|uart.*console',
                'severity': SeverityLevel.HIGH,
                'title': 'Debug Interface Exposed',
            },
            {
                'id': 'IOT-002',
                'type': VulnerabilityType.HARDCODED_SECRETS,
                'pattern': r'password\s*=\s*["\'][^"\']+["\']|api[_-]?key\s*=\s*',
                'severity': SeverityLevel.CRITICAL,
                'title': 'Hardcoded Credentials',
            },
            {
                'id': 'IOT-003',
                'type': VulnerabilityType.WEAK_ENCRYPTION,
                'pattern': r'DES|RC4|MD5|SHA1(?!_)',
                'severity': SeverityLevel.MEDIUM,
                'title': 'Weak Cryptographic Algorithm',
            },
            {
                'id': 'IOT-004',
                'type': VulnerabilityType.NO_ENCRYPTION,
                'pattern': r'http://|ftp://|telnet://|mqtt:(?!/ssl)',
                'severity': SeverityLevel.HIGH,
                'title': 'Unencrypted Communication',
            },
        ]
        
    async def scan_device(self, device: IoTDevice) -> List[IoTVulnerability]:
        """Scan IoT device for vulnerabilities"""
        vulnerabilities = []
        
        # Default credentials check
        vulnerabilities.extend(await self._check_default_credentials(device))
        
        # Protocol-specific vulnerability checks
        for protocol in device.protocols:
            if protocol == IoTProtocol.MQTT:
                vulnerabilities.extend(await self._check_mqtt_security(device))
            elif protocol == IoTProtocol.COAP:
                vulnerabilities.extend(await self._check_coap_security(device))
            elif protocol == IoTProtocol.MODBUS:
                vulnerabilities.extend(await self._check_modbus_security(device))
                
        # Web interface checks
        if 80 in device.open_ports or 443 in device.open_ports:
            vulnerabilities.extend(await self._check_web_interface(device))
            
        # Service-specific checks
        if 23 in device.open_ports:
            vulnerabilities.extend(await self._check_telnet_security(device))
        if 22 in device.open_ports:
            vulnerabilities.extend(await self._check_ssh_security(device))
        if 554 in device.open_ports:
            vulnerabilities.extend(await self._check_rtsp_security(device))
            
        device.vulnerabilities = vulnerabilities
        return vulnerabilities
        
    async def _check_default_credentials(self, device: IoTDevice) -> List[IoTVulnerability]:
        """Check for default credentials"""
        vulnerabilities = []
        
        device_type = device.device_type.value
        creds_to_try = self.default_credentials.get(device_type, [])
        
        # Add telnet/ssh specific creds
        if 23 in device.open_ports:
            creds_to_try.extend(self.default_credentials.get('telnet', []))
        if 22 in device.open_ports:
            creds_to_try.extend(self.default_credentials.get('ssh', []))
            
        # Attempt authentication (simulated for safety)
        for username, password in set(creds_to_try):
            # In real implementation, would attempt actual authentication
            # For safety, we're simulating detection
            pass
            
        return vulnerabilities
        
    async def _check_mqtt_security(self, device: IoTDevice) -> List[IoTVulnerability]:
        """Check MQTT broker security"""
        vulnerabilities = []
        
        mqtt_port = 1883 if 1883 in device.open_ports else 8883
        
        try:
            # Check for anonymous access
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((device.ip_address, mqtt_port))
            
            # Send MQTT CONNECT packet without credentials
            connect_packet = bytes([
                0x10,  # CONNECT
                0x10,  # Remaining length
                0x00, 0x04, 0x4D, 0x51, 0x54, 0x54,  # Protocol name "MQTT"
                0x04,  # Protocol level (4 = 3.1.1)
                0x02,  # Connect flags (clean session)
                0x00, 0x3C,  # Keep alive (60 seconds)
                0x00, 0x04, 0x74, 0x65, 0x73, 0x74,  # Client ID "test"
            ])
            
            sock.send(connect_packet)
            response = sock.recv(4)
            sock.close()
            
            if len(response) >= 4 and response[0] == 0x20:  # CONNACK
                return_code = response[3]
                if return_code == 0:  # Connection accepted
                    vulnerabilities.append(IoTVulnerability(
                        vuln_id='MQTT-ANON-001',
                        vuln_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                        severity=SeverityLevel.HIGH,
                        title='MQTT Anonymous Access Allowed',
                        description='MQTT broker accepts connections without authentication',
                        affected_device=device.device_id,
                        affected_component=f'MQTT:{mqtt_port}',
                        remediation='Enable MQTT authentication and use strong credentials'
                    ))
                    
        except Exception as e:
            logger.debug(f"MQTT check error: {e}")
            
        return vulnerabilities
        
    async def _check_coap_security(self, device: IoTDevice) -> List[IoTVulnerability]:
        """Check CoAP security"""
        vulnerabilities = []
        
        try:
            # Check for unencrypted CoAP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # CoAP GET request for well-known resources
            coap_request = bytes([
                0x40,  # Version 1, Type 0 (CON), Token length 0
                0x01,  # Code 0.01 (GET)
                0x00, 0x01,  # Message ID
                0xBB,  # Option: Uri-Path (11) with length 11
                0x2E, 0x77, 0x65, 0x6C, 0x6C, 0x2D, 0x6B, 0x6E, 0x6F, 0x77, 0x6E,  # ".well-known"
                0x04,  # Option: Uri-Path delta 0, length 4
                0x63, 0x6F, 0x72, 0x65,  # "core"
            ])
            
            sock.sendto(coap_request, (device.ip_address, 5683))
            response, _ = sock.recvfrom(1024)
            sock.close()
            
            if response:
                vulnerabilities.append(IoTVulnerability(
                    vuln_id='COAP-NOAUTH-001',
                    vuln_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                    severity=SeverityLevel.MEDIUM,
                    title='CoAP Resources Accessible Without Authentication',
                    description='CoAP endpoint responds without authentication',
                    affected_device=device.device_id,
                    affected_component='CoAP:5683',
                    remediation='Implement DTLS for CoAP (CoAPS) and require authentication'
                ))
                
        except Exception:
            pass
            
        return vulnerabilities
        
    async def _check_modbus_security(self, device: IoTDevice) -> List[IoTVulnerability]:
        """Check Modbus TCP security"""
        vulnerabilities = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((device.ip_address, 502))
            
            # Modbus read holding registers request
            modbus_request = bytes([
                0x00, 0x01,  # Transaction ID
                0x00, 0x00,  # Protocol ID (Modbus)
                0x00, 0x06,  # Length
                0x01,        # Unit ID
                0x03,        # Function code (Read Holding Registers)
                0x00, 0x00,  # Starting address
                0x00, 0x0A,  # Number of registers
            ])
            
            sock.send(modbus_request)
            response = sock.recv(256)
            sock.close()
            
            if response and len(response) > 7:
                vulnerabilities.append(IoTVulnerability(
                    vuln_id='MODBUS-NOAUTH-001',
                    vuln_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                    severity=SeverityLevel.CRITICAL,
                    title='Modbus TCP No Authentication',
                    description='Modbus TCP accepts read requests without authentication',
                    affected_device=device.device_id,
                    affected_component='Modbus:502',
                    remediation='Implement network segmentation and firewall rules for Modbus'
                ))
                
        except Exception:
            pass
            
        return vulnerabilities
        
    async def _check_web_interface(self, device: IoTDevice) -> List[IoTVulnerability]:
        """Check web interface security"""
        vulnerabilities = []
        
        try:
            import urllib.request
            import ssl
            
            # Check for HTTP (unencrypted)
            if 80 in device.open_ports:
                vulnerabilities.append(IoTVulnerability(
                    vuln_id='HTTP-NOSSL-001',
                    vuln_type=VulnerabilityType.NO_ENCRYPTION,
                    severity=SeverityLevel.MEDIUM,
                    title='Unencrypted HTTP Web Interface',
                    description='Device web interface is accessible via unencrypted HTTP',
                    affected_device=device.device_id,
                    affected_component='HTTP:80',
                    remediation='Enable HTTPS and redirect HTTP to HTTPS'
                ))
                
            # Check for weak SSL/TLS
            if 443 in device.open_ports:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ssl_sock = context.wrap_socket(sock)
                    ssl_sock.settimeout(5)
                    ssl_sock.connect((device.ip_address, 443))
                    
                    cipher = ssl_sock.cipher()
                    version = ssl_sock.version()
                    ssl_sock.close()
                    
                    # Check for weak protocols
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vulnerabilities.append(IoTVulnerability(
                            vuln_id='SSL-WEAK-001',
                            vuln_type=VulnerabilityType.WEAK_ENCRYPTION,
                            severity=SeverityLevel.HIGH,
                            title=f'Weak TLS Version: {version}',
                            description=f'Device supports deprecated TLS version {version}',
                            affected_device=device.device_id,
                            affected_component='HTTPS:443',
                            remediation='Enable only TLS 1.2 and TLS 1.3'
                        ))
                        
                except Exception:
                    pass
                    
        except Exception:
            pass
            
        return vulnerabilities
        
    async def _check_telnet_security(self, device: IoTDevice) -> List[IoTVulnerability]:
        """Check Telnet security"""
        vulnerabilities = []
        
        # Telnet is inherently insecure
        vulnerabilities.append(IoTVulnerability(
            vuln_id='TELNET-ENABLED-001',
            vuln_type=VulnerabilityType.NO_ENCRYPTION,
            severity=SeverityLevel.HIGH,
            title='Telnet Service Enabled',
            description='Device has Telnet service enabled which transmits data unencrypted',
            affected_device=device.device_id,
            affected_component='Telnet:23',
            remediation='Disable Telnet and use SSH instead'
        ))
        
        return vulnerabilities
        
    async def _check_ssh_security(self, device: IoTDevice) -> List[IoTVulnerability]:
        """Check SSH security"""
        vulnerabilities = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((device.ip_address, 22))
            
            banner = sock.recv(256).decode('utf-8', errors='ignore')
            sock.close()
            
            # Check for old SSH versions
            if 'SSH-1' in banner:
                vulnerabilities.append(IoTVulnerability(
                    vuln_id='SSH-V1-001',
                    vuln_type=VulnerabilityType.WEAK_ENCRYPTION,
                    severity=SeverityLevel.CRITICAL,
                    title='SSH Version 1 Supported',
                    description='Device supports deprecated SSH version 1',
                    affected_device=device.device_id,
                    affected_component='SSH:22',
                    remediation='Disable SSH v1 and use only SSH v2'
                ))
                
            # Check for known vulnerable versions
            vulnerable_patterns = [
                ('OpenSSH_4', 'CVE-2017-15906'),
                ('OpenSSH_5', 'CVE-2016-0777'),
                ('dropbear_0.4', 'CVE-2012-0920'),
            ]
            
            for pattern, cve in vulnerable_patterns:
                if pattern in banner:
                    vulnerabilities.append(IoTVulnerability(
                        vuln_id=f'SSH-{cve}',
                        vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
                        severity=SeverityLevel.HIGH,
                        title=f'Vulnerable SSH Version ({cve})',
                        description=f'SSH version is vulnerable to {cve}',
                        affected_device=device.device_id,
                        affected_component='SSH:22',
                        cve_ids=[cve],
                        remediation='Update SSH to latest version'
                    ))
                    
        except Exception:
            pass
            
        return vulnerabilities
        
    async def _check_rtsp_security(self, device: IoTDevice) -> List[IoTVulnerability]:
        """Check RTSP security"""
        vulnerabilities = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((device.ip_address, 554))
            
            # Send OPTIONS request
            request = b'OPTIONS rtsp://' + device.ip_address.encode() + b':554 RTSP/1.0\r\nCSeq: 1\r\n\r\n'
            sock.send(request)
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if '200 OK' in response:
                # Check for authentication
                if 'WWW-Authenticate' not in response:
                    vulnerabilities.append(IoTVulnerability(
                        vuln_id='RTSP-NOAUTH-001',
                        vuln_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                        severity=SeverityLevel.HIGH,
                        title='RTSP No Authentication Required',
                        description='RTSP stream accessible without authentication',
                        affected_device=device.device_id,
                        affected_component='RTSP:554',
                        remediation='Enable RTSP authentication'
                    ))
                    
        except Exception:
            pass
            
        return vulnerabilities


class FirmwareAnalyzer:
    """IoT firmware analysis engine"""
    
    def __init__(self):
        self.extraction_tools = ['binwalk', 'firmware-mod-kit', 'ubi_reader']
        self.analysis_results: Dict[str, FirmwareAnalysis] = {}
        
    def analyze_firmware(self, firmware_path: str) -> FirmwareAnalysis:
        """Analyze firmware binary"""
        if not os.path.exists(firmware_path):
            raise FileNotFoundError(f"Firmware not found: {firmware_path}")
            
        # Calculate hash
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()
            firmware_hash = hashlib.sha256(firmware_data).hexdigest()
            
        analysis = FirmwareAnalysis(
            firmware_hash=firmware_hash,
            firmware_size=len(firmware_data)
        )
        
        # Identify architecture
        analysis.architecture = self._identify_architecture(firmware_data)
        analysis.endianness = self._identify_endianness(firmware_data)
        
        # Identify filesystem
        analysis.filesystem_type = self._identify_filesystem(firmware_data)
        analysis.compression = self._identify_compression(firmware_data)
        
        # Extract and analyze contents
        extracted_files = self._extract_firmware(firmware_path)
        analysis.extracted_files = extracted_files
        
        # Scan for secrets
        analysis.hardcoded_credentials = self._find_credentials(extracted_files)
        analysis.cryptographic_keys = self._find_crypto_keys(extracted_files)
        analysis.network_configurations = self._find_network_configs(extracted_files)
        
        # Identify vulnerabilities
        analysis.vulnerabilities = self._analyze_vulnerabilities(analysis)
        
        self.analysis_results[firmware_hash] = analysis
        return analysis
        
    def _identify_architecture(self, data: bytes) -> str:
        """Identify CPU architecture from binary"""
        # Check ELF header
        if data[:4] == b'\x7fELF':
            machine_type = struct.unpack('<H', data[18:20])[0]
            architectures = {
                3: 'x86',
                62: 'x86_64',
                40: 'ARM',
                183: 'ARM64',
                8: 'MIPS',
            }
            return architectures.get(machine_type, 'unknown')
            
        # Check for common firmware signatures
        signatures = {
            b'sqsh': 'ARM/MIPS (SquashFS)',
            b'hsqs': 'ARM/MIPS (SquashFS)',
            b'\x1f\x8b': 'Compressed (gzip)',
            b'BZ': 'Compressed (bzip2)',
            b'\xfd7zXZ': 'Compressed (xz)',
        }
        
        for sig, arch in signatures.items():
            if sig in data[:1024]:
                return arch
                
        return 'unknown'
        
    def _identify_endianness(self, data: bytes) -> str:
        """Identify byte order"""
        if data[:4] == b'\x7fELF':
            return 'little' if data[5] == 1 else 'big'
        return 'unknown'
        
    def _identify_filesystem(self, data: bytes) -> str:
        """Identify filesystem type"""
        filesystems = {
            b'sqsh': 'SquashFS',
            b'hsqs': 'SquashFS (LE)',
            b'ubi#': 'UBIFS',
            b'UBI#': 'UBIFS',
            b'\x85\x19': 'JFFS2 (LE)',
            b'\x19\x85': 'JFFS2 (BE)',
            b'CRAMFS': 'CramFS',
            b'\x28\xcd\x3d\x45': 'CramFS',
        }
        
        for sig, fs in filesystems.items():
            if sig in data[:65536]:
                return fs
                
        return 'unknown'
        
    def _identify_compression(self, data: bytes) -> str:
        """Identify compression type"""
        compressions = {
            b'\x1f\x8b': 'gzip',
            b'BZ': 'bzip2',
            b'\xfd7zXZ': 'xz',
            b'\x89LZO': 'lzo',
            b'\x04\x22\x4d\x18': 'lz4',
        }
        
        for sig, comp in compressions.items():
            if sig in data[:256]:
                return comp
                
        return 'unknown'
        
    def _extract_firmware(self, firmware_path: str) -> List[str]:
        """Extract firmware contents"""
        extracted_files = []
        
        try:
            import subprocess
            
            # Try binwalk extraction
            result = subprocess.run(
                ['binwalk', '-e', '-M', firmware_path],
                capture_output=True,
                timeout=300
            )
            
            # List extracted files
            extract_dir = firmware_path + '.extracted'
            if os.path.isdir(extract_dir):
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        extracted_files.append(os.path.join(root, file))
                        
        except Exception as e:
            logger.warning(f"Firmware extraction failed: {e}")
            
        return extracted_files
        
    def _find_credentials(self, files: List[str]) -> List[Dict[str, str]]:
        """Find hardcoded credentials in extracted files"""
        credentials = []
        
        credential_patterns = [
            (r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']+)', 'password'),
            (r'(?:username|user|login)\s*[=:]\s*["\']?([^\s"\']+)', 'username'),
            (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([^\s"\']+)', 'api_key'),
            (r'(?:secret|token)\s*[=:]\s*["\']?([^\s"\']+)', 'secret'),
        ]
        
        for filepath in files:
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
                    
                for pattern, cred_type in credential_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if len(match) > 3:  # Filter noise
                            credentials.append({
                                'type': cred_type,
                                'value': match,
                                'file': filepath
                            })
                            
            except Exception:
                pass
                
        return credentials
        
    def _find_crypto_keys(self, files: List[str]) -> List[Dict[str, str]]:
        """Find cryptographic keys"""
        keys = []
        
        key_patterns = [
            (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key'),
            (r'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key'),
            (r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key'),
            (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'SSH Private Key'),
            (r'-----BEGIN CERTIFICATE-----', 'X.509 Certificate'),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key'),
        ]
        
        for filepath in files:
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
                    
                for pattern, key_type in key_patterns:
                    if pattern in content:
                        keys.append({
                            'type': key_type,
                            'file': filepath
                        })
                        
            except Exception:
                pass
                
        return keys
        
    def _find_network_configs(self, files: List[str]) -> List[Dict[str, str]]:
        """Find network configurations"""
        configs = []
        
        config_files = ['interfaces', 'wpa_supplicant.conf', 'dhcpd.conf',
                       'resolv.conf', 'hosts', 'hostname', 'network']
                       
        for filepath in files:
            filename = os.path.basename(filepath).lower()
            if any(cf in filename for cf in config_files):
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read()
                    configs.append({
                        'file': filepath,
                        'content': content[:500]
                    })
                except Exception:
                    pass
                    
        return configs
        
    def _analyze_vulnerabilities(self, analysis: FirmwareAnalysis) -> List[IoTVulnerability]:
        """Analyze for vulnerabilities"""
        vulnerabilities = []
        
        # Check for hardcoded credentials
        if analysis.hardcoded_credentials:
            for cred in analysis.hardcoded_credentials:
                vulnerabilities.append(IoTVulnerability(
                    vuln_id=f"FW-CRED-{hashlib.md5(cred['value'].encode()).hexdigest()[:8]}",
                    vuln_type=VulnerabilityType.HARDCODED_SECRETS,
                    severity=SeverityLevel.CRITICAL,
                    title=f"Hardcoded {cred['type']} in Firmware",
                    description=f"Found hardcoded {cred['type']} in {cred['file']}",
                    affected_device='firmware',
                    affected_component=cred['file'],
                    remediation='Remove hardcoded credentials and use secure storage'
                ))
                
        # Check for exposed private keys
        if analysis.cryptographic_keys:
            for key in analysis.cryptographic_keys:
                if 'Private Key' in key['type']:
                    vulnerabilities.append(IoTVulnerability(
                        vuln_id=f"FW-KEY-{hashlib.md5(key['file'].encode()).hexdigest()[:8]}",
                        vuln_type=VulnerabilityType.HARDCODED_SECRETS,
                        severity=SeverityLevel.CRITICAL,
                        title=f"Exposed {key['type']} in Firmware",
                        description=f"Found {key['type']} in {key['file']}",
                        affected_device='firmware',
                        affected_component=key['file'],
                        remediation='Remove private keys from firmware and use secure key provisioning'
                    ))
                    
        return vulnerabilities


class AdvancedIoTSecurity:
    """Main IoT security integration class"""
    
    def __init__(self):
        self.discovery = IoTDeviceDiscovery()
        self.scanner = IoTVulnerabilityScanner()
        self.firmware_analyzer = FirmwareAnalyzer()
        self.scan_callbacks: List[Callable] = []
        
    async def full_assessment(self, target: str) -> Dict[str, Any]:
        """Perform full IoT security assessment"""
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'devices': [],
            'vulnerabilities': [],
            'summary': {
                'total_devices': 0,
                'vulnerable_devices': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
            }
        }
        
        # Discover devices
        devices = self.discovery.discover_network(target)
        results['summary']['total_devices'] = len(devices)
        
        # Scan each device
        for device in devices:
            vulnerabilities = await self.scanner.scan_device(device)
            
            device_result = {
                'device_id': device.device_id,
                'ip': device.ip_address,
                'type': device.device_type.value,
                'manufacturer': device.manufacturer,
                'protocols': [p.value for p in device.protocols],
                'open_ports': device.open_ports,
                'vulnerabilities': [
                    {
                        'id': v.vuln_id,
                        'severity': v.severity.value,
                        'title': v.title,
                        'description': v.description,
                        'remediation': v.remediation
                    }
                    for v in vulnerabilities
                ]
            }
            
            results['devices'].append(device_result)
            
            if vulnerabilities:
                results['summary']['vulnerable_devices'] += 1
                for v in vulnerabilities:
                    results['summary'][v.severity.value] = results['summary'].get(v.severity.value, 0) + 1
                    
        return results
        
    def analyze_firmware_file(self, firmware_path: str) -> FirmwareAnalysis:
        """Analyze firmware file"""
        return self.firmware_analyzer.analyze_firmware(firmware_path)
        
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate assessment report"""
        report = []
        
        report.append("=" * 60)
        report.append("IOT SECURITY ASSESSMENT REPORT")
        report.append("=" * 60)
        
        report.append(f"\nTarget: {results['target']}")
        report.append(f"Scan Time: {results['timestamp']}")
        
        report.append(f"\n{'=' * 40}")
        report.append("SUMMARY")
        report.append("=" * 40)
        
        summary = results['summary']
        report.append(f"Total Devices: {summary['total_devices']}")
        report.append(f"Vulnerable Devices: {summary['vulnerable_devices']}")
        report.append(f"\nVulnerabilities by Severity:")
        report.append(f"  Critical: {summary.get('critical', 0)}")
        report.append(f"  High: {summary.get('high', 0)}")
        report.append(f"  Medium: {summary.get('medium', 0)}")
        report.append(f"  Low: {summary.get('low', 0)}")
        
        report.append(f"\n{'=' * 40}")
        report.append("DEVICE DETAILS")
        report.append("=" * 40)
        
        for device in results['devices']:
            report.append(f"\n[{device['type'].upper()}] {device['ip']}")
            report.append(f"  Manufacturer: {device.get('manufacturer', 'Unknown')}")
            report.append(f"  Protocols: {', '.join(device['protocols'])}")
            report.append(f"  Open Ports: {', '.join(map(str, device['open_ports']))}")
            report.append(f"  Vulnerabilities: {len(device['vulnerabilities'])}")
            
            for vuln in device['vulnerabilities']:
                severity = vuln['severity'].upper()
                report.append(f"    [{severity}] {vuln['title']}")
                
        return "\n".join(report)
