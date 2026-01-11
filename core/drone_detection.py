"""
ESP32-Based Drone Detection System for HydraRecon
==================================================

Advanced drone detection using ESP32 hardware for:
- WiFi probe request monitoring
- MAC address manufacturer identification
- RF signal fingerprinting (2.4GHz/5.8GHz)
- Signal strength triangulation
- Known drone protocol detection
- Real-time threat alerting

Supports detection of:
- DJI (Mavic, Phantom, Mini, Air, Inspire)
- Parrot (Anafi, Bebop)
- Autel (Evo, Dragonfish)
- Skydio
- Holy Stone
- Hubsan
- Syma
- Custom/FPV drones
"""

import asyncio
import json
import logging
import re
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Callable, Any
from collections import defaultdict
import hashlib
import math

try:
    import serial
    import serial.tools.list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

logger = logging.getLogger(__name__)


class DroneType(Enum):
    """Known drone types"""
    DJI_MAVIC = "DJI Mavic"
    DJI_PHANTOM = "DJI Phantom"
    DJI_MINI = "DJI Mini"
    DJI_AIR = "DJI Air"
    DJI_INSPIRE = "DJI Inspire"
    DJI_FPV = "DJI FPV"
    DJI_AVATA = "DJI Avata"
    DJI_MATRICE = "DJI Matrice"
    PARROT_ANAFI = "Parrot Anafi"
    PARROT_BEBOP = "Parrot Bebop"
    AUTEL_EVO = "Autel Evo"
    AUTEL_DRAGONFISH = "Autel Dragonfish"
    SKYDIO = "Skydio"
    HOLY_STONE = "Holy Stone"
    HUBSAN = "Hubsan"
    SYMA = "Syma"
    CUSTOM_FPV = "Custom FPV"
    UNKNOWN = "Unknown Drone"


class ThreatLevel(Enum):
    """Threat assessment levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionMethod(Enum):
    """How the drone was detected"""
    WIFI_PROBE = "WiFi Probe Request"
    WIFI_BEACON = "WiFi Beacon"
    MAC_OUI = "MAC Manufacturer"
    RF_SIGNATURE = "RF Signature"
    REMOTE_ID = "Remote ID Broadcast"
    PROTOCOL_ANALYSIS = "Protocol Analysis"
    TRIANGULATION = "Signal Triangulation"


@dataclass
class DroneSignature:
    """Known drone WiFi/RF signatures"""
    manufacturer: str
    model_patterns: List[str]
    oui_prefixes: List[str]  # MAC address prefixes
    ssid_patterns: List[str]
    frequencies: List[float]  # Common frequencies in MHz
    protocol: str
    typical_power: Tuple[int, int]  # dBm range


@dataclass
class DetectedDrone:
    """A detected drone instance"""
    id: str
    drone_type: DroneType
    mac_address: str
    ssid: Optional[str]
    signal_strength: int  # dBm
    frequency: float  # MHz
    channel: int
    first_seen: datetime
    last_seen: datetime
    detection_method: DetectionMethod
    threat_level: ThreatLevel
    estimated_distance: float  # meters
    estimated_position: Optional[Tuple[float, float, float]] = None  # lat, lon, alt
    manufacturer: str = "Unknown"
    model: str = "Unknown"
    controller_mac: Optional[str] = None
    remote_id: Optional[str] = None
    packet_count: int = 0
    data_rate: float = 0.0
    encryption: str = "Unknown"
    metadata: Dict = field(default_factory=dict)


# Known drone manufacturer OUI prefixes
DRONE_OUI_DATABASE = {
    # DJI
    "60:60:1F": DroneSignature("DJI", ["Mavic", "Mini", "Air"], ["60:60:1F"], ["DJI-*", "Mavic-*"], [2400, 5800], "DJI OcuSync", (-70, -30)),
    "34:D2:62": DroneSignature("DJI", ["Phantom", "Inspire"], ["34:D2:62"], ["Phantom*", "Inspire*"], [2400, 5800], "Lightbridge", (-70, -30)),
    "48:1C:B9": DroneSignature("DJI", ["FPV", "Avata"], ["48:1C:B9"], ["DJI FPV*"], [2400, 5800], "DJI O3", (-70, -30)),
    "98:3A:92": DroneSignature("DJI", ["Matrice"], ["98:3A:92"], ["Matrice*"], [2400, 5800], "DJI OcuSync", (-70, -30)),
    "A0:14:3D": DroneSignature("DJI", ["Various"], ["A0:14:3D"], ["DJI*"], [2400, 5800], "DJI Protocol", (-70, -30)),
    "C4:62:6B": DroneSignature("DJI", ["Controller"], ["C4:62:6B"], ["RC*"], [2400, 5800], "Controller", (-50, -20)),
    
    # Parrot
    "90:03:B7": DroneSignature("Parrot", ["Anafi", "Bebop"], ["90:03:B7"], ["Parrot*", "Anafi*", "Bebop*"], [2400, 5800], "Parrot Protocol", (-75, -35)),
    "A0:14:3D": DroneSignature("Parrot", ["Disco"], ["A0:14:3D"], ["Disco*"], [2400], "WiFi Direct", (-80, -40)),
    
    # Autel
    "50:0F:10": DroneSignature("Autel", ["Evo", "Dragonfish"], ["50:0F:10"], ["Autel*", "Evo*"], [2400, 5800], "Autel Link", (-70, -30)),
    
    # Skydio
    "B8:F0:09": DroneSignature("Skydio", ["Skydio 2", "X2"], ["B8:F0:09"], ["Skydio*"], [2400, 5800], "Skydio Protocol", (-70, -30)),
    
    # Holy Stone
    "E8:68:E7": DroneSignature("Holy Stone", ["HS Series"], ["E8:68:E7"], ["HS*", "HolyStone*"], [2400], "WiFi FPV", (-80, -40)),
    
    # Hubsan
    "B4:E6:2D": DroneSignature("Hubsan", ["Zino", "X4"], ["B4:E6:2D"], ["Hubsan*", "Zino*"], [2400, 5800], "Hubsan Protocol", (-80, -40)),
    
    # Syma
    "00:1A:79": DroneSignature("Syma", ["X Series"], ["00:1A:79"], ["Syma*", "SYMA*"], [2400], "WiFi FPV", (-85, -45)),
    
    # Generic FPV
    "00:12:6D": DroneSignature("Generic FPV", ["Custom"], ["00:12:6D"], ["FPV*", "DRONE*"], [2400, 5800], "Custom", (-90, -40)),
}

# SSID patterns for drone detection
DRONE_SSID_PATTERNS = [
    (r"^DJI[-_]", DroneType.DJI_MAVIC),
    (r"^Mavic[-_]", DroneType.DJI_MAVIC),
    (r"^Mini[-_]", DroneType.DJI_MINI),
    (r"^Air[-_]2", DroneType.DJI_AIR),
    (r"^Phantom[-_]", DroneType.DJI_PHANTOM),
    (r"^Inspire[-_]", DroneType.DJI_INSPIRE),
    (r"^FPV[-_]", DroneType.DJI_FPV),
    (r"^Avata[-_]", DroneType.DJI_AVATA),
    (r"^Matrice[-_]", DroneType.DJI_MATRICE),
    (r"^Parrot[-_]", DroneType.PARROT_ANAFI),
    (r"^Anafi[-_]", DroneType.PARROT_ANAFI),
    (r"^Bebop[-_]", DroneType.PARROT_BEBOP),
    (r"^Autel[-_]", DroneType.AUTEL_EVO),
    (r"^Evo[-_]", DroneType.AUTEL_EVO),
    (r"^Skydio[-_]", DroneType.SKYDIO),
    (r"^HS\d{3}", DroneType.HOLY_STONE),
    (r"^HolyStone", DroneType.HOLY_STONE),
    (r"^Hubsan[-_]", DroneType.HUBSAN),
    (r"^Zino[-_]", DroneType.HUBSAN),
    (r"^Syma[-_]", DroneType.SYMA),
    (r"^SYMA[-_]", DroneType.SYMA),
    (r"^FPV[-_]Drone", DroneType.CUSTOM_FPV),
    (r"^DRONE[-_]", DroneType.UNKNOWN),
]


class ESP32DroneDetector:
    """
    ESP32-based drone detection system
    
    Communicates with ESP32 hardware running custom firmware
    to detect drone WiFi signals, analyze RF patterns, and
    triangulate positions.
    """
    
    def __init__(
        self,
        port: str = None,
        baudrate: int = 115200,
        detection_callback: Callable[[DetectedDrone], None] = None,
        alert_callback: Callable[[str, ThreatLevel], None] = None,
    ):
        self.port = port
        self.baudrate = baudrate
        self.serial_conn = None
        self.running = False
        self.detection_callback = detection_callback
        self.alert_callback = alert_callback
        
        # Detection state
        self.detected_drones: Dict[str, DetectedDrone] = {}
        self.signal_history: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)
        self.packet_buffer: List[Dict] = []
        
        # Multi-sensor triangulation
        self.sensors: Dict[str, Tuple[float, float]] = {}  # sensor_id -> (lat, lon)
        self.sensor_readings: Dict[str, Dict[str, int]] = defaultdict(dict)  # drone_id -> sensor_id -> rssi
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'drone_packets': 0,
            'unique_drones': 0,
            'alerts_raised': 0,
            'uptime_start': None,
        }
        
        # Alert thresholds
        self.alert_distance_threshold = 100  # meters
        self.alert_signal_threshold = -50  # dBm (strong = close)
        
        # Threading
        self.lock = threading.Lock()
        self.read_thread = None
        
    def find_esp32_ports(self) -> List[str]:
        """Find available ESP32 serial ports"""
        if not SERIAL_AVAILABLE:
            return []
            
        esp32_ports = []
        ports = serial.tools.list_ports.comports()
        
        for port in ports:
            # Common ESP32 USB-Serial chips
            if any(x in port.description.lower() for x in ['cp210', 'ch340', 'ftdi', 'esp32', 'silicon labs']):
                esp32_ports.append(port.device)
            elif any(x in str(port.vid) for x in ['10C4', '1A86', '0403']) if port.vid else False:
                esp32_ports.append(port.device)
                
        return esp32_ports
    
    def connect(self, port: str = None) -> bool:
        """Connect to ESP32 device"""
        if not SERIAL_AVAILABLE:
            logger.error("PySerial not installed")
            return False
            
        if port:
            self.port = port
        
        if not self.port:
            ports = self.find_esp32_ports()
            if ports:
                self.port = ports[0]
            else:
                logger.error("No ESP32 device found")
                return False
        
        try:
            self.serial_conn = serial.Serial(
                self.port,
                self.baudrate,
                timeout=1,
                write_timeout=1
            )
            logger.info(f"Connected to ESP32 on {self.port}")
            
            # Send initialization command
            time.sleep(2)  # Wait for ESP32 to reset
            self.send_command("INIT")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to ESP32: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from ESP32"""
        self.running = False
        if self.read_thread:
            self.read_thread.join(timeout=2)
        if self.serial_conn:
            self.serial_conn.close()
            self.serial_conn = None
    
    def send_command(self, command: str, params: Dict = None) -> bool:
        """Send command to ESP32"""
        if not self.serial_conn:
            return False
            
        try:
            cmd = {"cmd": command}
            if params:
                cmd.update(params)
            
            data = json.dumps(cmd) + "\n"
            self.serial_conn.write(data.encode())
            return True
            
        except Exception as e:
            logger.error(f"Failed to send command: {e}")
            return False
    
    def start_detection(self):
        """Start drone detection"""
        if not self.serial_conn:
            if not self.connect():
                return False
        
        self.running = True
        self.stats['uptime_start'] = datetime.now()
        
        # Start read thread
        self.read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self.read_thread.start()
        
        # Enable detection modes on ESP32
        self.send_command("START_SCAN", {"mode": "all"})
        self.send_command("SET_CHANNELS", {"channels": [1, 6, 11, 36, 40, 44, 48]})
        
        logger.info("Drone detection started")
        return True
    
    def stop_detection(self):
        """Stop drone detection"""
        self.running = False
        self.send_command("STOP_SCAN")
        
    def _read_loop(self):
        """Main loop for reading ESP32 data"""
        while self.running and self.serial_conn:
            try:
                if self.serial_conn.in_waiting:
                    line = self.serial_conn.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        self._process_packet(line)
            except Exception as e:
                logger.error(f"Read error: {e}")
                time.sleep(0.1)
    
    def _process_packet(self, data: str):
        """Process incoming packet from ESP32"""
        try:
            packet = json.loads(data)
            self.stats['total_packets'] += 1
            
            packet_type = packet.get('type', '')
            
            if packet_type == 'PROBE':
                self._handle_probe_request(packet)
            elif packet_type == 'BEACON':
                self._handle_beacon(packet)
            elif packet_type == 'DATA':
                self._handle_data_frame(packet)
            elif packet_type == 'REMOTE_ID':
                self._handle_remote_id(packet)
            elif packet_type == 'RF_SIGNAL':
                self._handle_rf_signal(packet)
            elif packet_type == 'STATUS':
                self._handle_status(packet)
                
        except json.JSONDecodeError:
            # Handle raw data
            if data.startswith("DRONE:"):
                self._handle_legacy_format(data)
        except Exception as e:
            logger.debug(f"Packet processing error: {e}")
    
    def _handle_probe_request(self, packet: Dict):
        """Handle WiFi probe request"""
        mac = packet.get('mac', '')
        ssid = packet.get('ssid', '')
        rssi = packet.get('rssi', -100)
        channel = packet.get('channel', 0)
        
        # Check if this is a drone
        drone_type = self._identify_drone(mac, ssid)
        
        if drone_type:
            self.stats['drone_packets'] += 1
            self._register_drone(
                mac=mac,
                ssid=ssid,
                rssi=rssi,
                channel=channel,
                drone_type=drone_type,
                method=DetectionMethod.WIFI_PROBE
            )
    
    def _handle_beacon(self, packet: Dict):
        """Handle WiFi beacon frame"""
        mac = packet.get('mac', '')
        ssid = packet.get('ssid', '')
        rssi = packet.get('rssi', -100)
        channel = packet.get('channel', 0)
        
        drone_type = self._identify_drone(mac, ssid)
        
        if drone_type:
            self.stats['drone_packets'] += 1
            self._register_drone(
                mac=mac,
                ssid=ssid,
                rssi=rssi,
                channel=channel,
                drone_type=drone_type,
                method=DetectionMethod.WIFI_BEACON
            )
    
    def _handle_data_frame(self, packet: Dict):
        """Handle WiFi data frame - analyze for drone protocols"""
        mac_src = packet.get('src', '')
        mac_dst = packet.get('dst', '')
        rssi = packet.get('rssi', -100)
        
        # Check both source and destination
        for mac in [mac_src, mac_dst]:
            if mac and self._is_drone_mac(mac):
                self.stats['drone_packets'] += 1
                
                drone_id = mac.upper()
                if drone_id in self.detected_drones:
                    drone = self.detected_drones[drone_id]
                    drone.last_seen = datetime.now()
                    drone.packet_count += 1
                    drone.signal_strength = rssi
    
    def _handle_remote_id(self, packet: Dict):
        """Handle FAA Remote ID broadcast"""
        remote_id = packet.get('id', '')
        mac = packet.get('mac', '')
        lat = packet.get('lat', 0)
        lon = packet.get('lon', 0)
        alt = packet.get('alt', 0)
        
        if remote_id:
            self._register_drone(
                mac=mac,
                ssid=None,
                rssi=packet.get('rssi', -70),
                channel=0,
                drone_type=DroneType.UNKNOWN,
                method=DetectionMethod.REMOTE_ID,
                extra={
                    'remote_id': remote_id,
                    'position': (lat, lon, alt)
                }
            )
    
    def _handle_rf_signal(self, packet: Dict):
        """Handle raw RF signal detection"""
        freq = packet.get('freq', 0)
        power = packet.get('power', -100)
        bandwidth = packet.get('bw', 0)
        
        # Analyze signal characteristics
        if self._is_drone_rf_signature(freq, power, bandwidth):
            self.stats['drone_packets'] += 1
            
            # Generate pseudo-MAC from signal characteristics
            sig_hash = hashlib.md5(f"{freq}:{bandwidth}".encode()).hexdigest()[:12]
            pseudo_mac = ':'.join([sig_hash[i:i+2] for i in range(0, 12, 2)])
            
            self._register_drone(
                mac=pseudo_mac,
                ssid=None,
                rssi=power,
                channel=self._freq_to_channel(freq),
                drone_type=DroneType.CUSTOM_FPV,
                method=DetectionMethod.RF_SIGNATURE,
                extra={'frequency': freq, 'bandwidth': bandwidth}
            )
    
    def _handle_status(self, packet: Dict):
        """Handle ESP32 status message"""
        status = packet.get('status', '')
        logger.debug(f"ESP32 Status: {status}")
    
    def _handle_legacy_format(self, data: str):
        """Handle legacy text format from ESP32"""
        # Format: DRONE:MAC:SSID:RSSI:CHANNEL
        parts = data.split(':')
        if len(parts) >= 5:
            mac = parts[1]
            ssid = parts[2]
            rssi = int(parts[3])
            channel = int(parts[4])
            
            drone_type = self._identify_drone(mac, ssid)
            if drone_type:
                self._register_drone(mac, ssid, rssi, channel, drone_type, DetectionMethod.WIFI_PROBE)
    
    def _identify_drone(self, mac: str, ssid: str = None) -> Optional[DroneType]:
        """Identify if MAC/SSID belongs to a drone"""
        mac = mac.upper()
        
        # Check MAC OUI
        oui = mac[:8]
        if oui in DRONE_OUI_DATABASE:
            return self._oui_to_drone_type(oui)
        
        # Check SSID patterns
        if ssid:
            for pattern, dtype in DRONE_SSID_PATTERNS:
                if re.match(pattern, ssid, re.IGNORECASE):
                    return dtype
        
        return None
    
    def _is_drone_mac(self, mac: str) -> bool:
        """Quick check if MAC is from known drone manufacturer"""
        oui = mac.upper()[:8]
        return oui in DRONE_OUI_DATABASE
    
    def _oui_to_drone_type(self, oui: str) -> DroneType:
        """Convert OUI to drone type"""
        sig = DRONE_OUI_DATABASE.get(oui)
        if sig:
            manufacturer = sig.manufacturer.upper()
            if 'DJI' in manufacturer:
                return DroneType.DJI_MAVIC
            elif 'PARROT' in manufacturer:
                return DroneType.PARROT_ANAFI
            elif 'AUTEL' in manufacturer:
                return DroneType.AUTEL_EVO
            elif 'SKYDIO' in manufacturer:
                return DroneType.SKYDIO
            elif 'HOLY' in manufacturer:
                return DroneType.HOLY_STONE
            elif 'HUBSAN' in manufacturer:
                return DroneType.HUBSAN
            elif 'SYMA' in manufacturer:
                return DroneType.SYMA
        return DroneType.UNKNOWN
    
    def _is_drone_rf_signature(self, freq: float, power: int, bandwidth: float) -> bool:
        """Check if RF signature matches drone characteristics"""
        # Common drone frequencies
        drone_freqs = [
            (2400, 2500),   # 2.4GHz WiFi/RC
            (5725, 5850),   # 5.8GHz FPV
            (900, 930),     # 900MHz RC (some drones)
            (1200, 1300),   # 1.2GHz video
        ]
        
        for low, high in drone_freqs:
            if low <= freq <= high:
                # Check power level (drones typically -30 to -80 dBm when in range)
                if -85 <= power <= -20:
                    return True
        
        return False
    
    def _freq_to_channel(self, freq: float) -> int:
        """Convert frequency to WiFi channel"""
        if 2412 <= freq <= 2484:
            return int((freq - 2407) / 5)
        elif 5170 <= freq <= 5825:
            return int((freq - 5000) / 5)
        return 0
    
    def _register_drone(
        self,
        mac: str,
        ssid: Optional[str],
        rssi: int,
        channel: int,
        drone_type: DroneType,
        method: DetectionMethod,
        extra: Dict = None
    ):
        """Register or update a detected drone"""
        drone_id = mac.upper()
        now = datetime.now()
        
        with self.lock:
            if drone_id in self.detected_drones:
                # Update existing drone
                drone = self.detected_drones[drone_id]
                drone.last_seen = now
                drone.signal_strength = rssi
                drone.packet_count += 1
                
                # Update SSID if we get a better one
                if ssid and not drone.ssid:
                    drone.ssid = ssid
                    
            else:
                # New drone detected
                oui = mac.upper()[:8]
                sig = DRONE_OUI_DATABASE.get(oui)
                
                freq = extra.get('frequency', 2437) if extra else 2437
                
                drone = DetectedDrone(
                    id=drone_id,
                    drone_type=drone_type,
                    mac_address=mac,
                    ssid=ssid,
                    signal_strength=rssi,
                    frequency=freq,
                    channel=channel,
                    first_seen=now,
                    last_seen=now,
                    detection_method=method,
                    threat_level=self._assess_threat(rssi),
                    estimated_distance=self._estimate_distance(rssi),
                    manufacturer=sig.manufacturer if sig else "Unknown",
                    model=drone_type.value,
                    packet_count=1,
                )
                
                # Add extra data
                if extra:
                    if 'remote_id' in extra:
                        drone.remote_id = extra['remote_id']
                    if 'position' in extra:
                        drone.estimated_position = extra['position']
                    drone.metadata.update(extra)
                
                self.detected_drones[drone_id] = drone
                self.stats['unique_drones'] += 1
                
                logger.info(f"🚁 NEW DRONE DETECTED: {drone_type.value} ({mac}) RSSI: {rssi}dBm")
                
                # Trigger callback
                if self.detection_callback:
                    self.detection_callback(drone)
            
            # Update signal history
            self.signal_history[drone_id].append((now, rssi))
            
            # Keep only last 100 readings
            if len(self.signal_history[drone_id]) > 100:
                self.signal_history[drone_id] = self.signal_history[drone_id][-100:]
            
            # Check for alerts
            self._check_alerts(self.detected_drones[drone_id])
    
    def _assess_threat(self, rssi: int) -> ThreatLevel:
        """Assess threat level based on signal strength"""
        if rssi >= -40:
            return ThreatLevel.CRITICAL  # Very close
        elif rssi >= -55:
            return ThreatLevel.HIGH  # Close
        elif rssi >= -70:
            return ThreatLevel.MEDIUM  # Medium distance
        else:
            return ThreatLevel.LOW  # Far away
    
    def _estimate_distance(self, rssi: int, tx_power: int = -40) -> float:
        """
        Estimate distance from RSSI using log-distance path loss model
        
        Distance = 10 ^ ((TxPower - RSSI) / (10 * n))
        n = path loss exponent (2-4, using 2.5 for outdoor)
        """
        n = 2.5  # Path loss exponent
        distance = 10 ** ((tx_power - rssi) / (10 * n))
        return round(distance, 1)
    
    def _check_alerts(self, drone: DetectedDrone):
        """Check if drone triggers any alerts"""
        alerts = []
        
        # Distance alert
        if drone.estimated_distance < self.alert_distance_threshold:
            alerts.append(f"Drone {drone.manufacturer} detected within {drone.estimated_distance}m")
        
        # Signal strength alert
        if drone.signal_strength > self.alert_signal_threshold:
            alerts.append(f"Strong drone signal detected: {drone.signal_strength}dBm")
        
        # Threat level alert
        if drone.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            alerts.append(f"HIGH THREAT: {drone.drone_type.value} proximity warning!")
        
        for alert in alerts:
            self.stats['alerts_raised'] += 1
            logger.warning(f"🚨 ALERT: {alert}")
            
            if self.alert_callback:
                self.alert_callback(alert, drone.threat_level)
    
    def get_active_drones(self, timeout_seconds: int = 60) -> List[DetectedDrone]:
        """Get list of currently active drones"""
        now = datetime.now()
        active = []
        
        with self.lock:
            for drone in self.detected_drones.values():
                if (now - drone.last_seen).total_seconds() < timeout_seconds:
                    active.append(drone)
        
        return sorted(active, key=lambda d: d.signal_strength, reverse=True)
    
    def get_drone_by_id(self, drone_id: str) -> Optional[DetectedDrone]:
        """Get specific drone by ID"""
        return self.detected_drones.get(drone_id.upper())
    
    def get_signal_trend(self, drone_id: str) -> List[Tuple[datetime, int]]:
        """Get signal strength history for a drone"""
        return self.signal_history.get(drone_id.upper(), [])
    
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        uptime = 0
        if self.stats['uptime_start']:
            uptime = (datetime.now() - self.stats['uptime_start']).total_seconds()
        
        return {
            **self.stats,
            'uptime_seconds': uptime,
            'active_drones': len(self.get_active_drones()),
            'drones_per_minute': self.stats['unique_drones'] / max(1, uptime / 60),
        }
    
    def export_detections(self, filepath: str):
        """Export all detections to JSON file"""
        data = {
            'export_time': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'drones': []
        }
        
        for drone in self.detected_drones.values():
            data['drones'].append({
                'id': drone.id,
                'type': drone.drone_type.value,
                'mac': drone.mac_address,
                'ssid': drone.ssid,
                'manufacturer': drone.manufacturer,
                'model': drone.model,
                'signal_strength': drone.signal_strength,
                'estimated_distance': drone.estimated_distance,
                'threat_level': drone.threat_level.value,
                'first_seen': drone.first_seen.isoformat(),
                'last_seen': drone.last_seen.isoformat(),
                'packet_count': drone.packet_count,
                'detection_method': drone.detection_method.value,
                'remote_id': drone.remote_id,
                'position': drone.estimated_position,
            })
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported {len(data['drones'])} drone detections to {filepath}")
    
    def add_sensor(self, sensor_id: str, lat: float, lon: float):
        """Add a sensor location for triangulation"""
        self.sensors[sensor_id] = (lat, lon)
        
    def triangulate_position(self, drone_id: str) -> Optional[Tuple[float, float]]:
        """
        Triangulate drone position from multiple sensors
        Requires at least 3 sensors with readings
        """
        if not NUMPY_AVAILABLE:
            return None
            
        readings = self.sensor_readings.get(drone_id)
        if not readings or len(readings) < 3:
            return None
        
        # Get sensor positions and distances
        positions = []
        distances = []
        
        for sensor_id, rssi in readings.items():
            if sensor_id in self.sensors:
                positions.append(self.sensors[sensor_id])
                distances.append(self._estimate_distance(rssi))
        
        if len(positions) < 3:
            return None
        
        # Trilateration algorithm
        try:
            # Convert to numpy arrays
            P = np.array(positions)
            D = np.array(distances)
            
            # Use least squares to estimate position
            # This is a simplified 2D trilateration
            A = 2 * (P[1:] - P[0])
            b = D[0]**2 - D[1:]**2 - np.sum(P[0]**2) + np.sum(P[1:]**2, axis=1)
            
            position = np.linalg.lstsq(A, b, rcond=None)[0]
            
            return (float(position[0]), float(position[1]))
            
        except Exception as e:
            logger.error(f"Triangulation failed: {e}")
            return None


class DroneDetectionSimulator:
    """
    Simulator for testing drone detection without hardware
    """
    
    def __init__(self, detector: ESP32DroneDetector):
        self.detector = detector
        self.running = False
        self.sim_thread = None
        
    def start(self):
        """Start simulation"""
        self.running = True
        self.sim_thread = threading.Thread(target=self._simulate, daemon=True)
        self.sim_thread.start()
        
    def stop(self):
        """Stop simulation"""
        self.running = False
        
    def _simulate(self):
        """Generate simulated drone detections"""
        import random
        
        # Simulated drones
        sim_drones = [
            ("60:60:1F:AB:CD:EF", "DJI-Mavic3-ABCD", DroneType.DJI_MAVIC),
            ("90:03:B7:12:34:56", "Parrot-Anafi-1234", DroneType.PARROT_ANAFI),
            ("50:0F:10:AA:BB:CC", "Autel-Evo2-AABB", DroneType.AUTEL_EVO),
            ("E8:68:E7:11:22:33", "HS720-112233", DroneType.HOLY_STONE),
        ]
        
        active_drones = []
        
        while self.running:
            # Random chance for new drone to appear
            if random.random() < 0.1 and len(active_drones) < 4:
                available = [d for d in sim_drones if d not in active_drones]
                if available:
                    active_drones.append(random.choice(available))
            
            # Random chance for drone to disappear
            if random.random() < 0.05 and active_drones:
                active_drones.pop(random.randint(0, len(active_drones) - 1))
            
            # Emit packets for active drones
            for mac, ssid, dtype in active_drones:
                rssi = random.randint(-80, -40)
                channel = random.choice([1, 6, 11, 36, 44])
                
                packet = {
                    'type': 'PROBE',
                    'mac': mac,
                    'ssid': ssid,
                    'rssi': rssi,
                    'channel': channel
                }
                
                self.detector._process_packet(json.dumps(packet))
            
            time.sleep(random.uniform(0.5, 2.0))


# ESP32 Firmware commands reference
ESP32_FIRMWARE_INFO = """
ESP32 Drone Detection Firmware Commands
========================================

Serial Protocol: 115200 baud, 8N1

Commands (JSON format):
-----------------------
{"cmd": "INIT"}                          - Initialize detector
{"cmd": "START_SCAN", "mode": "all"}     - Start scanning (all/wifi/rf)
{"cmd": "STOP_SCAN"}                     - Stop scanning
{"cmd": "SET_CHANNELS", "channels": [1,6,11]}  - Set WiFi channels to scan
{"cmd": "SET_POWER", "power": 20}        - Set TX power (dBm)
{"cmd": "GET_STATUS"}                    - Get device status
{"cmd": "RESET"}                         - Reset device

Output Packet Types:
--------------------
{"type": "PROBE", "mac": "XX:XX:XX:XX:XX:XX", "ssid": "...", "rssi": -60, "channel": 6}
{"type": "BEACON", "mac": "XX:XX:XX:XX:XX:XX", "ssid": "...", "rssi": -60, "channel": 6}
{"type": "DATA", "src": "XX:XX:XX:XX:XX:XX", "dst": "XX:XX:XX:XX:XX:XX", "rssi": -60}
{"type": "REMOTE_ID", "id": "...", "mac": "...", "lat": 0.0, "lon": 0.0, "alt": 0.0}
{"type": "RF_SIGNAL", "freq": 2437, "power": -50, "bw": 20}
{"type": "STATUS", "status": "scanning", "packets": 1000}

Legacy Text Format:
-------------------
DRONE:MAC:SSID:RSSI:CHANNEL
"""


if __name__ == "__main__":
    # Test the drone detector
    logging.basicConfig(level=logging.INFO)
    
    def on_detection(drone):
        print(f"🚁 Detected: {drone.drone_type.value} - {drone.mac_address}")
        print(f"   Signal: {drone.signal_strength}dBm, Distance: ~{drone.estimated_distance}m")
        print(f"   Threat: {drone.threat_level.value}")
    
    def on_alert(message, level):
        print(f"🚨 ALERT [{level.value}]: {message}")
    
    detector = ESP32DroneDetector(
        detection_callback=on_detection,
        alert_callback=on_alert
    )
    
    # Use simulator for testing
    print("Starting drone detection simulator...")
    sim = DroneDetectionSimulator(detector)
    sim.start()
    
    try:
        while True:
            time.sleep(5)
            drones = detector.get_active_drones()
            print(f"\n📡 Active drones: {len(drones)}")
            for d in drones:
                print(f"  - {d.drone_type.value}: {d.signal_strength}dBm")
    except KeyboardInterrupt:
        sim.stop()
        print("\nDetection stopped")
