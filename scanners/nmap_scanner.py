#!/usr/bin/env python3
"""
HydraRecon Nmap Scanner Module
Advanced Nmap integration with async support and comprehensive parsing.
"""

import asyncio
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import subprocess
import tempfile
import os
from pathlib import Path

from .base import BaseScanner, ScanResult, ScanStatus


@dataclass
class NmapHost:
    """Nmap host result"""
    ip_address: str
    hostname: str = ""
    mac_address: str = ""
    vendor: str = ""
    state: str = "unknown"
    state_reason: str = ""
    os_matches: List[Dict[str, Any]] = field(default_factory=list)
    ports: List['NmapPort'] = field(default_factory=list)
    scripts: Dict[str, str] = field(default_factory=dict)
    uptime: Optional[int] = None
    distance: Optional[int] = None


@dataclass
class NmapPort:
    """Nmap port result"""
    port: int
    protocol: str = "tcp"
    state: str = "unknown"
    state_reason: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""
    conf: int = 0
    scripts: Dict[str, str] = field(default_factory=dict)


@dataclass
class NmapScanResult:
    """Complete Nmap scan result"""
    command: str
    start_time: datetime
    end_time: Optional[datetime] = None
    hosts_up: int = 0
    hosts_down: int = 0
    hosts_total: int = 0
    hosts: List[NmapHost] = field(default_factory=list)
    scan_info: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    raw_xml: str = ""


class NmapScanner(BaseScanner):
    """Advanced Nmap scanner with comprehensive functionality"""
    
    SCAN_PROFILES = {
        'quick': {
            'name': 'Quick Scan',
            'description': 'Fast scan of most common ports',
            'args': '-T4 -F'
        },
        'standard': {
            'name': 'Standard Scan',
            'description': 'Service version detection on common ports',
            'args': '-sV -sC -T4'
        },
        'comprehensive': {
            'name': 'Comprehensive Scan',
            'description': 'Full port scan with version and script detection',
            'args': '-sV -sC -p- -T4'
        },
        'stealth': {
            'name': 'Stealth Scan',
            'description': 'SYN scan with slower timing',
            'args': '-sS -T2 -f'
        },
        'aggressive': {
            'name': 'Aggressive Scan',
            'description': 'OS detection, version, scripts, traceroute',
            'args': '-A -T4'
        },
        'vuln': {
            'name': 'Vulnerability Scan',
            'description': 'Vulnerability scripts scan',
            'args': '-sV --script=vuln -T4'
        },
        'discovery': {
            'name': 'Host Discovery',
            'description': 'Discover live hosts',
            'args': '-sn -PE -PP -PM -PS80,443'
        },
        'udp': {
            'name': 'UDP Scan',
            'description': 'Scan common UDP ports',
            'args': '-sU --top-ports 100 -T4'
        },
        'web': {
            'name': 'Web Server Scan',
            'description': 'HTTP-focused scan with web scripts',
            'args': '-sV -p80,443,8080,8443 --script=http-*'
        },
        'full': {
            'name': 'Full Audit',
            'description': 'Complete security audit scan',
            'args': '-sS -sV -sC -O -A -p- -T4 --script=default,vuln'
        }
    }
    
    NSE_CATEGORIES = {
        'auth': 'Authentication scripts',
        'broadcast': 'Network broadcast discovery',
        'brute': 'Brute force attacks',
        'default': 'Default safe scripts',
        'discovery': 'Service discovery',
        'dos': 'Denial of service (use with caution)',
        'exploit': 'Exploitation scripts',
        'external': 'External service queries',
        'fuzzer': 'Fuzzing scripts',
        'intrusive': 'Intrusive scripts (may crash services)',
        'malware': 'Malware detection',
        'safe': 'Safe scripts',
        'version': 'Version detection',
        'vuln': 'Vulnerability detection'
    }
    
    def __init__(self, config, db):
        super().__init__(config, db)
        self.nmap_path = config.nmap.path
        self.nmap_available = False
        self.nmap_version = "unknown"
        self._verify_nmap()
    
    @property
    def scanner_name(self) -> str:
        return "Nmap Scanner"
    
    @property
    def scanner_type(self) -> str:
        return "nmap"
    
    def _verify_nmap(self):
        """Verify nmap is installed and accessible"""
        try:
            result = subprocess.run(
                [self.nmap_path, '--version'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self.nmap_available = True
                # Parse version
                version_match = re.search(r'Nmap version (\d+\.\d+)', result.stdout)
                if version_match:
                    self.nmap_version = version_match.group(1)
                else:
                    self.nmap_version = "unknown"
            else:
                self.nmap_available = False
                
        except FileNotFoundError:
            self.nmap_available = False
        except subprocess.TimeoutExpired:
            self.nmap_available = False
        except Exception:
            self.nmap_available = False
    
    async def validate_target(self, target: str) -> bool:
        """Validate target (IP, hostname, or CIDR range)"""
        # IP address pattern
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # CIDR pattern
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        # IP range pattern
        range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$'
        # Hostname pattern
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$'
        
        import re
        patterns = [ip_pattern, cidr_pattern, range_pattern, hostname_pattern]
        return any(re.match(p, target) for p in patterns)
    
    def build_command(self, target: str, profile: str = 'standard',
                     ports: str = None, scripts: List[str] = None,
                     additional_args: str = None, output_xml: str = None) -> List[str]:
        """Build nmap command with all options"""
        cmd = [self.nmap_path]
        
        # Add profile arguments
        if profile in self.SCAN_PROFILES:
            cmd.extend(self.SCAN_PROFILES[profile]['args'].split())
        
        # Add custom ports
        if ports:
            cmd.extend(['-p', ports])
        
        # Add custom scripts
        if scripts:
            cmd.extend(['--script', ','.join(scripts)])
        
        # Add timing options from config
        cmd.extend([f'-T{self.config.nmap.timing_template}'])
        
        # Add parallelism
        cmd.extend([f'--max-parallelism={self.config.nmap.max_parallelism}'])
        cmd.extend([f'--min-parallelism={self.config.nmap.min_parallelism}'])
        
        # Add retries
        cmd.extend([f'--max-retries={self.config.nmap.max_retries}'])
        
        # Add host timeout
        cmd.extend([f'--host-timeout={self.config.nmap.host_timeout}s'])
        
        # Add version intensity
        if '-sV' in ' '.join(cmd):
            cmd.extend([f'--version-intensity={self.config.nmap.version_intensity}'])
        
        # OS detection if enabled
        if self.config.nmap.os_detection and '-O' not in ' '.join(cmd):
            cmd.append('-O')
        
        # XML output
        if output_xml:
            cmd.extend(['-oX', output_xml])
        
        # Additional custom arguments
        if additional_args:
            cmd.extend(additional_args.split())
        
        # Add target
        cmd.append(target)
        
        return cmd
    
    async def scan(self, target: str, profile: str = 'standard',
                   ports: str = None, scripts: List[str] = None,
                   additional_args: str = None, **options) -> ScanResult:
        """Execute Nmap scan"""
        
        if not await self.validate_target(target):
            return ScanResult(
                scan_id=self.scan_id,
                scan_type=self.scanner_type,
                target=target,
                status=ScanStatus.FAILED,
                started_at=datetime.now(),
                errors=["Invalid target format"]
            )
        
        self.status = ScanStatus.RUNNING
        start_time = datetime.now()
        
        # Create temporary XML output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            xml_output = f.name
        
        try:
            # Build command
            cmd = self.build_command(
                target, profile, ports, scripts, additional_args, xml_output
            )
            
            self.emit_progress(0, 100, f"Starting scan: {target}", "initializing")
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if self.is_cancelled():
                return ScanResult(
                    scan_id=self.scan_id,
                    scan_type=self.scanner_type,
                    target=target,
                    status=ScanStatus.CANCELLED,
                    started_at=start_time
                )
            
            # Parse XML output
            nmap_result = self._parse_xml_output(xml_output)
            nmap_result.command = ' '.join(cmd)
            nmap_result.start_time = start_time
            nmap_result.end_time = datetime.now()
            
            # Convert to generic ScanResult
            result = ScanResult(
                scan_id=self.scan_id,
                scan_type=self.scanner_type,
                target=target,
                status=ScanStatus.COMPLETED,
                started_at=start_time,
                completed_at=datetime.now(),
                data=self._nmap_result_to_dict(nmap_result),
                raw_output=stdout.decode() if stdout else ""
            )
            
            # Store in database
            await self._store_results(result, nmap_result)
            
            self.emit_progress(100, 100, f"Scan completed: {target}", "completed")
            
            return result
            
        except Exception as e:
            return ScanResult(
                scan_id=self.scan_id,
                scan_type=self.scanner_type,
                target=target,
                status=ScanStatus.FAILED,
                started_at=start_time,
                errors=[str(e)]
            )
        finally:
            # Cleanup temporary file
            if os.path.exists(xml_output):
                os.unlink(xml_output)
    
    def _parse_xml_output(self, xml_file: str) -> NmapScanResult:
        """Parse Nmap XML output"""
        result = NmapScanResult(command="", start_time=datetime.now())
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Store raw XML
            with open(xml_file, 'r') as f:
                result.raw_xml = f.read()
            
            # Parse scan info
            if root.attrib:
                result.scan_info = dict(root.attrib)
            
            # Parse runstats
            runstats = root.find('runstats')
            if runstats is not None:
                hosts = runstats.find('hosts')
                if hosts is not None:
                    result.hosts_up = int(hosts.get('up', 0))
                    result.hosts_down = int(hosts.get('down', 0))
                    result.hosts_total = int(hosts.get('total', 0))
            
            # Parse hosts
            for host_elem in root.findall('host'):
                host = self._parse_host(host_elem)
                if host:
                    result.hosts.append(host)
            
        except ET.ParseError as e:
            result.warnings.append(f"XML parsing error: {str(e)}")
        except Exception as e:
            result.warnings.append(f"Error parsing results: {str(e)}")
        
        return result
    
    def _parse_host(self, host_elem: ET.Element) -> Optional[NmapHost]:
        """Parse host element from XML"""
        host = NmapHost(ip_address="")
        
        # Get status
        status = host_elem.find('status')
        if status is not None:
            host.state = status.get('state', 'unknown')
            host.state_reason = status.get('reason', '')
        
        # Get addresses
        for addr in host_elem.findall('address'):
            addr_type = addr.get('addrtype', '')
            if addr_type == 'ipv4' or addr_type == 'ipv6':
                host.ip_address = addr.get('addr', '')
            elif addr_type == 'mac':
                host.mac_address = addr.get('addr', '')
                host.vendor = addr.get('vendor', '')
        
        if not host.ip_address:
            return None
        
        # Get hostnames
        hostnames = host_elem.find('hostnames')
        if hostnames is not None:
            for hn in hostnames.findall('hostname'):
                if hn.get('type') == 'PTR' or hn.get('type') == 'user':
                    host.hostname = hn.get('name', '')
                    break
        
        # Get OS matches
        os_elem = host_elem.find('os')
        if os_elem is not None:
            for match in os_elem.findall('osmatch'):
                host.os_matches.append({
                    'name': match.get('name', ''),
                    'accuracy': int(match.get('accuracy', 0)),
                    'line': match.get('line', '')
                })
        
        # Get uptime
        uptime = host_elem.find('uptime')
        if uptime is not None:
            host.uptime = int(uptime.get('seconds', 0))
        
        # Get distance
        distance = host_elem.find('distance')
        if distance is not None:
            host.distance = int(distance.get('value', 0))
        
        # Parse ports
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port_elem in ports_elem.findall('port'):
                port = self._parse_port(port_elem)
                if port:
                    host.ports.append(port)
        
        # Parse host scripts
        hostscript = host_elem.find('hostscript')
        if hostscript is not None:
            for script in hostscript.findall('script'):
                script_id = script.get('id', '')
                script_output = script.get('output', '')
                if script_id:
                    host.scripts[script_id] = script_output
        
        return host
    
    def _parse_port(self, port_elem: ET.Element) -> Optional[NmapPort]:
        """Parse port element from XML"""
        port = NmapPort(
            port=int(port_elem.get('portid', 0)),
            protocol=port_elem.get('protocol', 'tcp')
        )
        
        # Get state
        state = port_elem.find('state')
        if state is not None:
            port.state = state.get('state', 'unknown')
            port.state_reason = state.get('reason', '')
        
        # Get service info
        service = port_elem.find('service')
        if service is not None:
            port.service = service.get('name', '')
            port.product = service.get('product', '')
            port.version = service.get('version', '')
            port.extrainfo = service.get('extrainfo', '')
            port.cpe = service.get('cpe', '')
            port.conf = int(service.get('conf', 0))
        
        # Parse port scripts
        for script in port_elem.findall('script'):
            script_id = script.get('id', '')
            script_output = script.get('output', '')
            if script_id:
                port.scripts[script_id] = script_output
        
        return port
    
    def _nmap_result_to_dict(self, result: NmapScanResult) -> Dict[str, Any]:
        """Convert NmapScanResult to dictionary"""
        return {
            'command': result.command,
            'start_time': result.start_time.isoformat(),
            'end_time': result.end_time.isoformat() if result.end_time else None,
            'hosts_up': result.hosts_up,
            'hosts_down': result.hosts_down,
            'hosts_total': result.hosts_total,
            'scan_info': result.scan_info,
            'warnings': result.warnings,
            'hosts': [
                {
                    'ip_address': h.ip_address,
                    'hostname': h.hostname,
                    'mac_address': h.mac_address,
                    'vendor': h.vendor,
                    'state': h.state,
                    'state_reason': h.state_reason,
                    'os_matches': h.os_matches,
                    'uptime': h.uptime,
                    'distance': h.distance,
                    'scripts': h.scripts,
                    'ports': [
                        {
                            'port': p.port,
                            'protocol': p.protocol,
                            'state': p.state,
                            'state_reason': p.state_reason,
                            'service': p.service,
                            'product': p.product,
                            'version': p.version,
                            'extrainfo': p.extrainfo,
                            'cpe': p.cpe,
                            'conf': p.conf,
                            'scripts': p.scripts
                        }
                        for p in h.ports
                    ]
                }
                for h in result.hosts
            ]
        }
    
    async def _store_results(self, scan_result: ScanResult, nmap_result: NmapScanResult):
        """Store scan results in database"""
        # This would be implemented to store results in the database
        # For now, we'll skip actual storage
        pass
    
    async def discover_hosts(self, network: str) -> List[str]:
        """Discover live hosts in a network"""
        result = await self.scan(network, profile='discovery')
        
        if result.status == ScanStatus.COMPLETED and result.data:
            return [
                h['ip_address'] for h in result.data.get('hosts', [])
                if h.get('state') == 'up'
            ]
        return []
    
    async def quick_scan(self, target: str) -> ScanResult:
        """Quick scan common ports"""
        return await self.scan(target, profile='quick')
    
    async def vuln_scan(self, target: str) -> ScanResult:
        """Vulnerability scan"""
        return await self.scan(target, profile='vuln')
    
    async def full_audit(self, target: str) -> ScanResult:
        """Full security audit"""
        return await self.scan(target, profile='full')
    
    def get_scan_profiles(self) -> Dict[str, Dict[str, str]]:
        """Get available scan profiles"""
        return self.SCAN_PROFILES.copy()
    
    def get_nse_categories(self) -> Dict[str, str]:
        """Get NSE script categories"""
        return self.NSE_CATEGORIES.copy()
