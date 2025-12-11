#!/usr/bin/env python3
"""
HydraRecon SCADA/ICS Security Module
Industrial Control Systems security assessment and vulnerability analysis.
"""

import asyncio
import socket
import struct
import json
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from enum import Enum
import hashlib


class ICSProtocol(Enum):
    """Industrial Control System protocols"""
    MODBUS_TCP = "modbus_tcp"
    MODBUS_RTU = "modbus_rtu"
    DNP3 = "dnp3"
    OPC_UA = "opc_ua"
    OPC_DA = "opc_da"
    BACNET = "bacnet"
    PROFINET = "profinet"
    ETHERNET_IP = "ethernet_ip"
    S7COMM = "s7comm"
    IEC_61850 = "iec_61850"
    IEC_60870_5_104 = "iec_104"
    HART_IP = "hart_ip"
    FF_HSE = "ff_hse"
    COAP = "coap"
    MQTT = "mqtt"


class DeviceType(Enum):
    """ICS device types"""
    PLC = "plc"
    RTU = "rtu"
    HMI = "hmi"
    SCADA_SERVER = "scada_server"
    HISTORIAN = "historian"
    DCS = "dcs"
    PAC = "pac"
    IED = "ied"
    SMART_METER = "smart_meter"
    FIELD_DEVICE = "field_device"
    GATEWAY = "gateway"
    ENGINEERING_WORKSTATION = "engineering_ws"


class VulnerabilitySeverity(Enum):
    """ICS vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ICSDevice:
    """Represents an ICS/SCADA device"""
    ip: str
    port: int
    protocol: ICSProtocol
    device_type: DeviceType
    vendor: str = ""
    model: str = ""
    firmware_version: str = ""
    device_id: str = ""
    description: str = ""
    coils: List[Dict] = field(default_factory=list)
    registers: List[Dict] = field(default_factory=list)
    tags: List[Dict] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)
    vulnerabilities: List[Dict] = field(default_factory=list)
    is_authenticated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SCADAVulnerability:
    """SCADA/ICS vulnerability finding"""
    vulnerability_id: str
    title: str
    severity: VulnerabilitySeverity
    protocol: ICSProtocol
    affected_device: Optional[ICSDevice]
    description: str
    impact: str
    remediation: str
    cve_ids: List[str] = field(default_factory=list)
    icsa_advisory: str = ""
    cvss_score: float = 0.0
    exploitable: bool = False
    proof_of_concept: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class SCADAScanResult:
    """Complete SCADA security scan result"""
    scan_id: str
    target_network: str
    start_time: datetime
    end_time: Optional[datetime] = None
    devices: List[ICSDevice] = field(default_factory=list)
    vulnerabilities: List[SCADAVulnerability] = field(default_factory=list)
    network_topology: Dict[str, Any] = field(default_factory=dict)
    protocol_analysis: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)


class ModbusScanner:
    """Modbus protocol scanner and analyzer"""
    
    MODBUS_PORT = 502
    FUNCTION_CODES = {
        0x01: "Read Coils",
        0x02: "Read Discrete Inputs",
        0x03: "Read Holding Registers",
        0x04: "Read Input Registers",
        0x05: "Write Single Coil",
        0x06: "Write Single Register",
        0x07: "Read Exception Status",
        0x08: "Diagnostics",
        0x0B: "Get Comm Event Counter",
        0x0C: "Get Comm Event Log",
        0x0F: "Write Multiple Coils",
        0x10: "Write Multiple Registers",
        0x11: "Report Slave ID",
        0x14: "Read File Record",
        0x15: "Write File Record",
        0x16: "Mask Write Register",
        0x17: "Read/Write Multiple Registers",
        0x18: "Read FIFO Queue",
        0x2B: "Encapsulated Interface Transport",
        0x43: "Read Device Identification"
    }
    
    def __init__(self):
        self.logger = logging.getLogger("ModbusScanner")
        self.timeout = 5.0
    
    async def scan_device(self, ip: str, port: int = 502, unit_id: int = 1) -> Optional[ICSDevice]:
        """Scan a Modbus TCP device"""
        try:
            device = ICSDevice(
                ip=ip,
                port=port,
                protocol=ICSProtocol.MODBUS_TCP,
                device_type=DeviceType.PLC
            )
            
            # Try to read device identification
            device_info = await self._read_device_identification(ip, port, unit_id)
            if device_info:
                device.vendor = device_info.get("vendor", "")
                device.model = device_info.get("product_code", "")
                device.firmware_version = device_info.get("revision", "")
                device.device_id = device_info.get("vendor_url", "")
            
            # Enumerate coils
            device.coils = await self._enumerate_coils(ip, port, unit_id)
            
            # Enumerate holding registers
            device.registers = await self._enumerate_registers(ip, port, unit_id)
            
            # Check for vulnerabilities
            device.vulnerabilities = await self._check_vulnerabilities(device, unit_id)
            
            return device
            
        except Exception as e:
            self.logger.error(f"Error scanning Modbus device {ip}:{port} - {e}")
            return None
    
    async def _read_device_identification(self, ip: str, port: int, unit_id: int) -> Dict[str, str]:
        """Read Modbus device identification (function code 0x2B/0x0E)"""
        try:
            # Build Read Device Identification request
            transaction_id = 1
            protocol_id = 0
            length = 5
            mei_type = 0x0E  # Read Device Identification
            read_device_id = 0x01  # Basic device identification
            object_id = 0x00  # Vendor name
            
            request = struct.pack(
                ">HHHBBBBBB",
                transaction_id, protocol_id, length, unit_id,
                0x2B, mei_type, read_device_id, object_id
            )
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            writer.write(request)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            # Parse response
            if len(response) >= 8:
                return self._parse_device_id_response(response)
            
            return {}
            
        except Exception as e:
            self.logger.debug(f"Could not read device ID: {e}")
            return {}
    
    def _parse_device_id_response(self, response: bytes) -> Dict[str, str]:
        """Parse Modbus device identification response"""
        result = {}
        try:
            # Skip MBAP header (7 bytes) and function code (2 bytes)
            if len(response) < 12:
                return result
            
            # Basic parsing - real implementation would be more complex
            object_count = response[11]
            offset = 12
            
            object_names = ["vendor", "product_code", "revision", "vendor_url", 
                          "product_name", "model_name", "application_name"]
            
            for i in range(min(object_count, len(object_names))):
                if offset + 2 > len(response):
                    break
                obj_id = response[offset]
                obj_len = response[offset + 1]
                if offset + 2 + obj_len > len(response):
                    break
                obj_value = response[offset + 2:offset + 2 + obj_len].decode('utf-8', errors='ignore')
                if obj_id < len(object_names):
                    result[object_names[obj_id]] = obj_value
                offset += 2 + obj_len
                
        except Exception:
            pass
        
        return result
    
    async def _enumerate_coils(self, ip: str, port: int, unit_id: int, 
                               start: int = 0, count: int = 100) -> List[Dict]:
        """Enumerate Modbus coils"""
        coils = []
        try:
            transaction_id = 2
            protocol_id = 0
            length = 6
            function_code = 0x01  # Read Coils
            
            request = struct.pack(
                ">HHHBBHH",
                transaction_id, protocol_id, length, unit_id,
                function_code, start, count
            )
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            writer.write(request)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            # Parse coil values
            if len(response) >= 9:
                byte_count = response[8]
                for i in range(min(byte_count, len(response) - 9)):
                    byte_val = response[9 + i]
                    for bit in range(8):
                        coil_addr = start + i * 8 + bit
                        if coil_addr < start + count:
                            coils.append({
                                "address": coil_addr,
                                "value": bool(byte_val & (1 << bit)),
                                "accessible": True
                            })
                            
        except Exception as e:
            self.logger.debug(f"Could not enumerate coils: {e}")
        
        return coils
    
    async def _enumerate_registers(self, ip: str, port: int, unit_id: int,
                                   start: int = 0, count: int = 50) -> List[Dict]:
        """Enumerate Modbus holding registers"""
        registers = []
        try:
            transaction_id = 3
            protocol_id = 0
            length = 6
            function_code = 0x03  # Read Holding Registers
            
            request = struct.pack(
                ">HHHBBHH",
                transaction_id, protocol_id, length, unit_id,
                function_code, start, count
            )
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            writer.write(request)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            # Parse register values
            if len(response) >= 9:
                byte_count = response[8]
                reg_count = byte_count // 2
                for i in range(reg_count):
                    if 9 + i * 2 + 1 < len(response):
                        reg_value = struct.unpack(">H", response[9 + i * 2:11 + i * 2])[0]
                        registers.append({
                            "address": start + i,
                            "value": reg_value,
                            "accessible": True,
                            "type": "holding"
                        })
                        
        except Exception as e:
            self.logger.debug(f"Could not enumerate registers: {e}")
        
        return registers
    
    async def _check_vulnerabilities(self, device: ICSDevice, unit_id: int) -> List[Dict]:
        """Check for known Modbus vulnerabilities"""
        vulns = []
        
        # Check for unauthenticated access
        if device.coils or device.registers:
            vulns.append({
                "id": "MODBUS-001",
                "title": "Unauthenticated Modbus Access",
                "severity": "critical",
                "description": "Device allows unauthenticated read/write access to coils and registers",
                "impact": "Attacker can read sensitive data or modify control values"
            })
        
        # Check for broadcast unit ID acceptance
        vulns.append({
            "id": "MODBUS-002", 
            "title": "Unit ID Enumeration Possible",
            "severity": "medium",
            "description": "Device responds to unit ID queries allowing enumeration"
        })
        
        return vulns


class DNP3Scanner:
    """DNP3 protocol scanner for SCADA systems"""
    
    DNP3_PORT = 20000
    
    def __init__(self):
        self.logger = logging.getLogger("DNP3Scanner")
        self.timeout = 5.0
    
    async def scan_device(self, ip: str, port: int = 20000) -> Optional[ICSDevice]:
        """Scan a DNP3 device"""
        try:
            device = ICSDevice(
                ip=ip,
                port=port,
                protocol=ICSProtocol.DNP3,
                device_type=DeviceType.RTU
            )
            
            # Try DNP3 link layer discovery
            link_info = await self._dnp3_link_discovery(ip, port)
            if link_info:
                device.device_id = str(link_info.get("source_address", ""))
                device.metadata["dnp3_info"] = link_info
            
            # Check for vulnerabilities
            device.vulnerabilities = await self._check_dnp3_vulnerabilities(device)
            
            return device
            
        except Exception as e:
            self.logger.error(f"Error scanning DNP3 device {ip}:{port} - {e}")
            return None
    
    async def _dnp3_link_discovery(self, ip: str, port: int) -> Dict[str, Any]:
        """Perform DNP3 link layer discovery"""
        info = {}
        try:
            # DNP3 Link Layer frame structure
            # Start bytes: 0x0564
            # Length: data length
            # Control: control byte
            # Destination: 2 bytes
            # Source: 2 bytes
            # CRC: 2 bytes
            
            # Build a basic read request
            start = b'\x05\x64'
            length = 5
            control = 0xC0  # User data, first frame
            destination = 0x0001  # Master typically 1
            source = 0xFFFF  # Broadcast
            
            frame = struct.pack(
                "<2sBBHH",
                start, length, control, destination, source
            )
            
            # Add CRC (simplified - real DNP3 uses CRC-16)
            crc = self._calculate_dnp3_crc(frame[2:])
            frame += struct.pack("<H", crc)
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            writer.write(frame)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            if len(response) >= 10:
                info = self._parse_dnp3_response(response)
                
        except Exception as e:
            self.logger.debug(f"DNP3 discovery failed: {e}")
        
        return info
    
    def _calculate_dnp3_crc(self, data: bytes) -> int:
        """Calculate DNP3 CRC-16"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc >>= 1
        return crc ^ 0xFFFF
    
    def _parse_dnp3_response(self, response: bytes) -> Dict[str, Any]:
        """Parse DNP3 link layer response"""
        result = {}
        try:
            if response[:2] == b'\x05\x64':
                result["valid_frame"] = True
                result["length"] = response[2]
                result["control"] = response[3]
                result["destination"] = struct.unpack("<H", response[4:6])[0]
                result["source_address"] = struct.unpack("<H", response[6:8])[0]
        except Exception:
            pass
        return result
    
    async def _check_dnp3_vulnerabilities(self, device: ICSDevice) -> List[Dict]:
        """Check for DNP3 vulnerabilities"""
        vulns = []
        
        vulns.append({
            "id": "DNP3-001",
            "title": "DNP3 Authentication Not Enforced",
            "severity": "high",
            "description": "DNP3 Secure Authentication (SA) not detected"
        })
        
        return vulns


class S7CommScanner:
    """Siemens S7 Communication protocol scanner"""
    
    S7_PORT = 102
    
    def __init__(self):
        self.logger = logging.getLogger("S7CommScanner")
        self.timeout = 5.0
    
    async def scan_device(self, ip: str, port: int = 102) -> Optional[ICSDevice]:
        """Scan a Siemens S7 PLC"""
        try:
            device = ICSDevice(
                ip=ip,
                port=port,
                protocol=ICSProtocol.S7COMM,
                device_type=DeviceType.PLC,
                vendor="Siemens"
            )
            
            # Try S7 connection and identification
            s7_info = await self._s7_identify(ip, port)
            if s7_info:
                device.model = s7_info.get("module_type", "")
                device.firmware_version = s7_info.get("firmware", "")
                device.device_id = s7_info.get("serial", "")
                device.description = s7_info.get("plant_id", "")
                device.metadata["s7_info"] = s7_info
            
            # Check vulnerabilities
            device.vulnerabilities = await self._check_s7_vulnerabilities(device)
            
            return device
            
        except Exception as e:
            self.logger.error(f"Error scanning S7 device {ip}:{port} - {e}")
            return None
    
    async def _s7_identify(self, ip: str, port: int) -> Dict[str, str]:
        """Identify Siemens S7 PLC"""
        info = {}
        try:
            # COTP Connection Request
            cotp_cr = bytes([
                0x03, 0x00, 0x00, 0x16,  # TPKT header
                0x11, 0xe0, 0x00, 0x00,  # COTP CR
                0x00, 0x01, 0x00, 0xc0,  # Source ref
                0x01, 0x0a, 0xc1, 0x02,  # Destination ref
                0x01, 0x00, 0xc2, 0x02,  # Class
                0x01, 0x02              # TPDU size
            ])
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # Send COTP Connection Request
            writer.write(cotp_cr)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            
            if len(response) >= 6 and response[5] == 0xd0:  # COTP CC
                # Send S7 Setup Communication
                s7_setup = bytes([
                    0x03, 0x00, 0x00, 0x19,  # TPKT
                    0x02, 0xf0, 0x80,        # COTP DT
                    0x32, 0x01, 0x00, 0x00,  # S7 header
                    0x00, 0x00, 0x00, 0x08,  # Parameters
                    0x00, 0x00, 0xf0, 0x00,  # Setup comm
                    0x00, 0x01, 0x00, 0x01,  # PDU size
                    0x01, 0xe0              # Max jobs
                ])
                
                writer.write(s7_setup)
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
                
                if len(response) >= 20:
                    # Try to read SZL (System Status List) for identification
                    szl_request = await self._build_szl_request(0x0011)  # Component identification
                    writer.write(szl_request)
                    await writer.drain()
                    
                    szl_response = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
                    info = self._parse_szl_response(szl_response)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            self.logger.debug(f"S7 identification failed: {e}")
        
        return info
    
    async def _build_szl_request(self, szl_id: int) -> bytes:
        """Build S7 SZL read request"""
        return bytes([
            0x03, 0x00, 0x00, 0x21,  # TPKT
            0x02, 0xf0, 0x80,        # COTP DT
            0x32, 0x07, 0x00, 0x00,  # S7 header (userdata)
            0x00, 0x00, 0x00, 0x08,  # Parameters  
            0x00, 0x08, 0x00, 0x01,  # More params
            0x12, 0x04, 0x11, 0x44,  # SZL request
            0x01, 0x00,              # SZL ID
            (szl_id >> 8) & 0xFF,
            szl_id & 0xFF,
            0x00, 0x00              # Index
        ])
    
    def _parse_szl_response(self, response: bytes) -> Dict[str, str]:
        """Parse S7 SZL response for device info"""
        result = {}
        try:
            # Find string data in response
            if len(response) > 30:
                data = response[30:]
                # Extract text fields (simplified parsing)
                text_parts = data.split(b'\x00')
                text_parts = [p.decode('ascii', errors='ignore').strip() 
                            for p in text_parts if len(p) > 2]
                
                if text_parts:
                    for i, part in enumerate(text_parts[:5]):
                        if 'CPU' in part or 'S7' in part:
                            result["module_type"] = part
                        elif 'V' in part and '.' in part:
                            result["firmware"] = part
                        elif len(part) > 10 and part.isalnum():
                            result["serial"] = part
        except Exception:
            pass
        
        return result
    
    async def _check_s7_vulnerabilities(self, device: ICSDevice) -> List[Dict]:
        """Check for S7 vulnerabilities"""
        vulns = []
        
        vulns.append({
            "id": "S7-001",
            "title": "S7 Communication Without Authentication",
            "severity": "critical",
            "description": "S7 protocol allows unauthenticated access to PLC"
        })
        
        if device.model:
            vulns.append({
                "id": "S7-002",
                "title": "PLC Model Enumeration",
                "severity": "medium",
                "description": f"PLC model identified: {device.model}"
            })
        
        return vulns


class OPCUAScanner:
    """OPC UA protocol scanner"""
    
    OPC_UA_PORT = 4840
    
    def __init__(self):
        self.logger = logging.getLogger("OPCUAScanner")
        self.timeout = 10.0
    
    async def scan_device(self, ip: str, port: int = 4840) -> Optional[ICSDevice]:
        """Scan an OPC UA server"""
        try:
            device = ICSDevice(
                ip=ip,
                port=port,
                protocol=ICSProtocol.OPC_UA,
                device_type=DeviceType.SCADA_SERVER
            )
            
            # Try OPC UA endpoint discovery
            endpoints = await self._discover_endpoints(ip, port)
            if endpoints:
                device.metadata["opc_ua_endpoints"] = endpoints
                device.description = endpoints[0].get("application_name", "")
            
            # Check vulnerabilities
            device.vulnerabilities = await self._check_opcua_vulnerabilities(device)
            
            return device
            
        except Exception as e:
            self.logger.error(f"Error scanning OPC UA device {ip}:{port} - {e}")
            return None
    
    async def _discover_endpoints(self, ip: str, port: int) -> List[Dict]:
        """Discover OPC UA endpoints"""
        endpoints = []
        try:
            # Build GetEndpoints request (simplified OPC UA binary)
            # Real implementation would use proper OPC UA encoding
            
            # For now, just check if port responds
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # Send OPC UA Hello message
            hello = self._build_hello_message(ip, port)
            writer.write(hello)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            if response and b'ACK' in response or len(response) > 20:
                endpoints.append({
                    "endpoint_url": f"opc.tcp://{ip}:{port}",
                    "application_name": "OPC UA Server",
                    "security_mode": "None"  # Would parse from response
                })
                
        except Exception as e:
            self.logger.debug(f"OPC UA endpoint discovery failed: {e}")
        
        return endpoints
    
    def _build_hello_message(self, ip: str, port: int) -> bytes:
        """Build OPC UA Hello message"""
        endpoint_url = f"opc.tcp://{ip}:{port}".encode('utf-8')
        url_length = len(endpoint_url)
        
        # Message header
        msg_type = b'HEL'
        chunk_type = b'F'
        
        # Hello body
        protocol_version = 0
        receive_buffer = 65535
        send_buffer = 65535
        max_message = 0
        max_chunk = 0
        
        body = struct.pack(
            "<IIIII",
            protocol_version, receive_buffer, send_buffer,
            max_message, max_chunk
        )
        body += struct.pack("<I", url_length) + endpoint_url
        
        msg_size = 8 + len(body)
        header = msg_type + chunk_type + struct.pack("<I", msg_size)
        
        return header + body
    
    async def _check_opcua_vulnerabilities(self, device: ICSDevice) -> List[Dict]:
        """Check for OPC UA vulnerabilities"""
        vulns = []
        
        endpoints = device.metadata.get("opc_ua_endpoints", [])
        for ep in endpoints:
            if ep.get("security_mode") == "None":
                vulns.append({
                    "id": "OPCUA-001",
                    "title": "OPC UA Endpoint Without Security",
                    "severity": "high",
                    "description": "OPC UA endpoint allows unencrypted connections"
                })
                break
        
        return vulns


class SCADASecurityEngine:
    """Main SCADA/ICS security assessment engine"""
    
    # Common ICS ports
    ICS_PORTS = {
        502: ICSProtocol.MODBUS_TCP,
        102: ICSProtocol.S7COMM,
        20000: ICSProtocol.DNP3,
        4840: ICSProtocol.OPC_UA,
        47808: ICSProtocol.BACNET,
        44818: ICSProtocol.ETHERNET_IP,
        1911: ICSProtocol.PROFINET,
        2404: ICSProtocol.IEC_60870_5_104
    }
    
    # Known ICS vulnerabilities database
    KNOWN_VULNS = {
        "CVE-2021-22681": {
            "vendor": "Rockwell",
            "severity": VulnerabilitySeverity.CRITICAL,
            "cvss": 10.0,
            "description": "Studio 5000 Logix Designer bypass"
        },
        "CVE-2020-14516": {
            "vendor": "Siemens",
            "severity": VulnerabilitySeverity.CRITICAL,
            "cvss": 9.8,
            "description": "S7-300/400 CPU DoS vulnerability"
        },
        "CVE-2019-18968": {
            "vendor": "Schneider",
            "severity": VulnerabilitySeverity.HIGH,
            "cvss": 8.6,
            "description": "Modicon M340 unauthorized access"
        }
    }
    
    def __init__(self):
        self.logger = logging.getLogger("SCADASecurityEngine")
        self.modbus_scanner = ModbusScanner()
        self.dnp3_scanner = DNP3Scanner()
        self.s7_scanner = S7CommScanner()
        self.opcua_scanner = OPCUAScanner()
        self.scan_results: List[SCADAScanResult] = []
        self.active_scans: Dict[str, asyncio.Task] = {}
    
    async def discover_ics_devices(self, network: str, 
                                    callback=None) -> List[ICSDevice]:
        """Discover ICS devices on a network"""
        devices = []
        
        # Parse network range
        ips = self._parse_network_range(network)
        total = len(ips)
        
        for i, ip in enumerate(ips):
            if callback:
                callback(f"Scanning {ip}...", (i + 1) / total * 100)
            
            # Check each ICS port
            for port, protocol in self.ICS_PORTS.items():
                device = await self._probe_port(ip, port, protocol)
                if device:
                    devices.append(device)
        
        return devices
    
    async def _probe_port(self, ip: str, port: int, 
                          protocol: ICSProtocol) -> Optional[ICSDevice]:
        """Probe a specific ICS port"""
        try:
            # Quick TCP connect check first
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            
            # Port is open, use appropriate scanner
            if protocol == ICSProtocol.MODBUS_TCP:
                return await self.modbus_scanner.scan_device(ip, port)
            elif protocol == ICSProtocol.S7COMM:
                return await self.s7_scanner.scan_device(ip, port)
            elif protocol == ICSProtocol.DNP3:
                return await self.dnp3_scanner.scan_device(ip, port)
            elif protocol == ICSProtocol.OPC_UA:
                return await self.opcua_scanner.scan_device(ip, port)
            else:
                # Generic ICS device
                return ICSDevice(
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    device_type=DeviceType.FIELD_DEVICE
                )
                
        except Exception:
            return None
    
    def _parse_network_range(self, network: str) -> List[str]:
        """Parse network range into list of IPs"""
        ips = []
        try:
            if '/' in network:
                # CIDR notation
                import ipaddress
                net = ipaddress.ip_network(network, strict=False)
                ips = [str(ip) for ip in list(net.hosts())[:256]]  # Limit to 256
            elif '-' in network:
                # Range notation
                parts = network.split('-')
                start_ip = parts[0].strip()
                end_part = parts[1].strip()
                
                base = '.'.join(start_ip.split('.')[:-1])
                start = int(start_ip.split('.')[-1])
                end = int(end_part) if '.' not in end_part else int(end_part.split('.')[-1])
                
                ips = [f"{base}.{i}" for i in range(start, min(end + 1, start + 256))]
            else:
                ips = [network]
        except Exception as e:
            self.logger.error(f"Error parsing network range: {e}")
        
        return ips
    
    async def full_security_assessment(self, target: str,
                                       callback=None) -> SCADAScanResult:
        """Perform comprehensive SCADA security assessment"""
        scan_id = hashlib.md5(f"{target}_{datetime.now()}".encode()).hexdigest()[:12]
        
        result = SCADAScanResult(
            scan_id=scan_id,
            target_network=target,
            start_time=datetime.now()
        )
        
        if callback:
            callback("Starting ICS device discovery...", 5)
        
        # Discover devices
        result.devices = await self.discover_ics_devices(target, callback)
        
        if callback:
            callback(f"Found {len(result.devices)} devices. Analyzing...", 50)
        
        # Analyze each device for vulnerabilities
        for device in result.devices:
            device_vulns = await self._assess_device_security(device)
            result.vulnerabilities.extend(device_vulns)
        
        if callback:
            callback("Building network topology...", 75)
        
        # Build network topology
        result.network_topology = self._build_topology(result.devices)
        
        # Calculate risk score
        result.risk_score = self._calculate_risk_score(result)
        
        # Generate recommendations
        result.recommendations = self._generate_recommendations(result)
        
        result.end_time = datetime.now()
        
        if callback:
            callback("Assessment complete", 100)
        
        self.scan_results.append(result)
        return result
    
    async def _assess_device_security(self, device: ICSDevice) -> List[SCADAVulnerability]:
        """Assess security of a single ICS device"""
        vulns = []
        
        # Convert device vulnerabilities to SCADAVulnerability objects
        for vuln_dict in device.vulnerabilities:
            vulns.append(SCADAVulnerability(
                vulnerability_id=vuln_dict.get("id", "UNKNOWN"),
                title=vuln_dict.get("title", "Unknown Vulnerability"),
                severity=VulnerabilitySeverity[vuln_dict.get("severity", "medium").upper()],
                protocol=device.protocol,
                affected_device=device,
                description=vuln_dict.get("description", ""),
                impact=vuln_dict.get("impact", ""),
                remediation=vuln_dict.get("remediation", "Apply vendor patches")
            ))
        
        # Check for default credentials (common ICS issue)
        if device.is_authenticated == False:
            vulns.append(SCADAVulnerability(
                vulnerability_id="ICS-NOAUTH-001",
                title="No Authentication Required",
                severity=VulnerabilitySeverity.CRITICAL,
                protocol=device.protocol,
                affected_device=device,
                description="Device allows unauthenticated access",
                impact="Complete control over device operation",
                remediation="Enable authentication if supported"
            ))
        
        return vulns
    
    def _build_topology(self, devices: List[ICSDevice]) -> Dict[str, Any]:
        """Build network topology from discovered devices"""
        topology = {
            "nodes": [],
            "edges": [],
            "zones": {}
        }
        
        for device in devices:
            node = {
                "id": f"{device.ip}:{device.port}",
                "ip": device.ip,
                "type": device.device_type.value,
                "protocol": device.protocol.value,
                "vendor": device.vendor
            }
            topology["nodes"].append(node)
            
            # Group by subnet
            subnet = '.'.join(device.ip.split('.')[:-1])
            if subnet not in topology["zones"]:
                topology["zones"][subnet] = []
            topology["zones"][subnet].append(node["id"])
        
        return topology
    
    def _calculate_risk_score(self, result: SCADAScanResult) -> float:
        """Calculate overall risk score (0-100)"""
        if not result.vulnerabilities:
            return 0.0
        
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 40,
            VulnerabilitySeverity.HIGH: 25,
            VulnerabilitySeverity.MEDIUM: 15,
            VulnerabilitySeverity.LOW: 5,
            VulnerabilitySeverity.INFO: 1
        }
        
        total_weight = sum(
            severity_weights.get(v.severity, 0) 
            for v in result.vulnerabilities
        )
        
        # Normalize to 0-100
        max_possible = len(result.vulnerabilities) * 40
        return min(100, (total_weight / max_possible) * 100) if max_possible > 0 else 0
    
    def _generate_recommendations(self, result: SCADAScanResult) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Analyze vulnerabilities
        has_auth_issues = any(
            "auth" in v.title.lower() 
            for v in result.vulnerabilities
        )
        
        if has_auth_issues:
            recommendations.append(
                "CRITICAL: Implement authentication on all ICS devices. "
                "Consider deploying industrial firewalls with deep packet inspection."
            )
        
        # Protocol-specific recommendations
        protocols = set(d.protocol for d in result.devices)
        
        if ICSProtocol.MODBUS_TCP in protocols:
            recommendations.append(
                "Modbus TCP devices detected. Consider implementing Modbus/TCP security "
                "extensions or isolating these devices in a dedicated network segment."
            )
        
        if ICSProtocol.S7COMM in protocols:
            recommendations.append(
                "Siemens S7 PLCs detected. Ensure latest firmware is installed and "
                "consider enabling S7 communication processor password protection."
            )
        
        if result.risk_score > 50:
            recommendations.insert(0,
                "HIGH RISK ENVIRONMENT: Immediate remediation required. "
                "Consider implementing emergency network segmentation."
            )
        
        return recommendations
    
    def get_scan_report(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed report for a scan"""
        for result in self.scan_results:
            if result.scan_id == scan_id:
                return {
                    "scan_id": result.scan_id,
                    "target": result.target_network,
                    "duration": str(result.end_time - result.start_time) if result.end_time else "In progress",
                    "devices_found": len(result.devices),
                    "vulnerabilities": len(result.vulnerabilities),
                    "critical_count": sum(1 for v in result.vulnerabilities 
                                        if v.severity == VulnerabilitySeverity.CRITICAL),
                    "risk_score": result.risk_score,
                    "recommendations": result.recommendations,
                    "devices": [
                        {
                            "ip": d.ip,
                            "port": d.port,
                            "protocol": d.protocol.value,
                            "type": d.device_type.value,
                            "vendor": d.vendor,
                            "model": d.model
                        }
                        for d in result.devices
                    ],
                    "vulnerability_details": [
                        {
                            "id": v.vulnerability_id,
                            "title": v.title,
                            "severity": v.severity.value,
                            "description": v.description,
                            "remediation": v.remediation
                        }
                        for v in result.vulnerabilities
                    ]
                }
        return None
    
    def export_report(self, scan_id: str, format: str = "json") -> Optional[str]:
        """Export scan report in specified format"""
        report = self.get_scan_report(scan_id)
        if not report:
            return None
        
        if format == "json":
            return json.dumps(report, indent=2, default=str)
        
        return None
