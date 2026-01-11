#!/usr/bin/env python3
"""
HydraSense Environment Visualizer
==================================
Real-time WiFi sensing visualization connecting to ESP32 via HTTP API.
Uses triangulation from dual ESP32 nodes to reconstruct environment.
"""

import sys
import json
import time
import math
import threading
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# Try PyQt6 first, fall back to terminal mode
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QFrame, QSplitter, QStatusBar, QProgressBar
    )
    from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
    from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QFont, QLinearGradient
    HAS_QT = True
except ImportError:
    HAS_QT = False
    print("PyQt6 not available - running in terminal mode")


# ============== Data Classes ==============

@dataclass
class DetectedDevice:
    """A detected WiFi device."""
    mac: str
    rssi_primary: int = -100
    rssi_remote: int = -100
    last_seen: float = 0
    channel: int = 0
    frame_type: int = 0
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    velocity: Tuple[float, float, float] = (0, 0, 0)
    is_moving: bool = False
    device_type: str = "unknown"


@dataclass  
class EnvironmentState:
    """Current environment state."""
    devices: Dict[str, DetectedDevice] = field(default_factory=dict)
    primary_pps: int = 0
    remote_pps: int = 0
    total_packets: int = 0
    channel: int = 1
    remote_connected: bool = False
    remote_rssi: int = 0
    timestamp: float = 0


# ============== Triangulation Engine ==============

class TriangulationEngine:
    """Calculate positions using RSSI triangulation."""
    
    # Node positions (meters) - primary at origin, remote 4.5m away (15 feet)
    PRIMARY_POS = (0.0, 0.0)
    REMOTE_POS = (4.5, 0.0)
    
    # RSSI to distance model parameters
    RSSI_REF = -40  # RSSI at 1 meter
    PATH_LOSS_EXP = 2.7  # Path loss exponent (2-4 typical for indoor)
    
    def __init__(self):
        self.position_history: Dict[str, List[Tuple[float, float, float]]] = defaultdict(list)
        
    def rssi_to_distance(self, rssi: int) -> float:
        """Convert RSSI to estimated distance in meters."""
        if rssi >= 0 or rssi < -100:
            return 10.0  # Invalid RSSI
        
        # Log-distance path loss model
        distance = 10 ** ((self.RSSI_REF - rssi) / (10 * self.PATH_LOSS_EXP))
        return min(max(distance, 0.1), 20.0)  # Clamp to reasonable range
    
    def triangulate(self, rssi_primary: int, rssi_remote: int) -> Tuple[float, float]:
        """Triangulate position from two RSSI measurements."""
        d1 = self.rssi_to_distance(rssi_primary)
        d2 = self.rssi_to_distance(rssi_remote)
        
        # Distance between nodes
        d = math.sqrt((self.REMOTE_POS[0] - self.PRIMARY_POS[0])**2 + 
                      (self.REMOTE_POS[1] - self.PRIMARY_POS[1])**2)
        
        if d == 0:
            return (0, 0)
            
        # Trilateration formula
        a = (d1**2 - d2**2 + d**2) / (2 * d)
        h_sq = d1**2 - a**2
        
        if h_sq < 0:
            # Circles don't intersect - use weighted average
            weight1 = 1 / (d1 + 0.1)
            weight2 = 1 / (d2 + 0.1)
            total = weight1 + weight2
            x = (self.PRIMARY_POS[0] * weight1 + self.REMOTE_POS[0] * weight2) / total
            y = (self.PRIMARY_POS[1] * weight1 + self.REMOTE_POS[1] * weight2) / total
            return (x, y)
        
        h = math.sqrt(h_sq)
        
        # Calculate intersection point (take one solution)
        x = self.PRIMARY_POS[0] + a * (self.REMOTE_POS[0] - self.PRIMARY_POS[0]) / d
        y = self.PRIMARY_POS[1] + h
        
        return (x, y)
    
    def update_device(self, device: DetectedDevice) -> DetectedDevice:
        """Update device position using triangulation."""
        if device.rssi_primary < -95 and device.rssi_remote < -95:
            return device
            
        # Triangulate position
        x, y = self.triangulate(device.rssi_primary, device.rssi_remote)
        
        # Smooth position using history
        history = self.position_history[device.mac]
        history.append((x, y, time.time()))
        
        # Keep last 10 samples
        if len(history) > 10:
            history.pop(0)
        
        # Average recent positions (exponential weighting)
        if len(history) > 1:
            total_weight = 0
            avg_x, avg_y = 0, 0
            for i, (hx, hy, ht) in enumerate(history):
                weight = math.exp(i - len(history) + 1)
                avg_x += hx * weight
                avg_y += hy * weight
                total_weight += weight
            x = avg_x / total_weight
            y = avg_y / total_weight
        
        # Detect movement
        if len(history) >= 3:
            old_x, old_y, old_t = history[-3]
            dt = time.time() - old_t
            if dt > 0:
                vx = (x - old_x) / dt
                vy = (y - old_y) / dt
                speed = math.sqrt(vx**2 + vy**2)
                device.is_moving = speed > 0.1  # Moving if > 0.1 m/s
                device.velocity = (vx, vy, 0)
        
        device.x = x
        device.y = y
        device.z = 0
        
        return device


# ============== ESP32 Data Fetcher ==============

class ESP32DataFetcher(QThread if HAS_QT else threading.Thread):
    """Fetches data from ESP32 via HTTP API."""
    
    if HAS_QT:
        data_received = pyqtSignal(dict)
        connection_status = pyqtSignal(bool, str)
    
    def __init__(self, host: str = "192.168.0.139", port: int = 80):
        super().__init__()
        self.host = host
        self.port = port
        self.running = True
        self.connected = False
        self.last_data = {}
        self._callbacks = []
        
    def add_callback(self, callback):
        self._callbacks.append(callback)
        
    def run(self):
        """Main fetch loop."""
        while self.running:
            try:
                # Fetch status
                status = self._fetch_json(f"http://{self.host}:{self.port}/status")
                if status:
                    self.connected = True
                    
                    # Fetch scan data
                    scan = self._fetch_json(f"http://{self.host}:{self.port}/scan")
                    
                    # Fetch remote info
                    remotes = self._fetch_json(f"http://{self.host}:{self.port}/remotes")
                    
                    data = {
                        'status': status,
                        'scan': scan or {},
                        'remotes': remotes or {},
                        'timestamp': time.time()
                    }
                    
                    self.last_data = data
                    
                    if HAS_QT:
                        self.data_received.emit(data)
                        self.connection_status.emit(True, f"{self.host}:{self.port}")
                    
                    for cb in self._callbacks:
                        cb(data)
                else:
                    self.connected = False
                    if HAS_QT:
                        self.connection_status.emit(False, "")
                    
            except Exception as e:
                self.connected = False
                if HAS_QT:
                    self.connection_status.emit(False, str(e))
                    
            time.sleep(0.1)  # 10 Hz update rate
    
    def _fetch_json(self, url: str) -> Optional[dict]:
        """Fetch JSON from URL."""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'HydraSense/1.0')
            with urllib.request.urlopen(req, timeout=2) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception:
            return None
    
    def stop(self):
        self.running = False


# ============== Qt Visualization Widgets ==============

if HAS_QT:
    
    class EnvironmentMapWidget(QWidget):
        """2D top-down environment visualization."""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setMinimumSize(600, 500)
            self.devices: Dict[str, DetectedDevice] = {}
            self.triangulator = TriangulationEngine()
            self.primary_pos = (0, 0)
            self.remote_pos = (4.5, 0)
            self.scale = 60  # pixels per meter
            self.offset_x = 300
            self.offset_y = 250
            
        def update_devices(self, devices: Dict[str, DetectedDevice]):
            self.devices = devices
            self.update()
            
        def world_to_screen(self, x: float, y: float) -> Tuple[int, int]:
            """Convert world coordinates to screen coordinates."""
            sx = int(self.offset_x + x * self.scale)
            sy = int(self.offset_y - y * self.scale)  # Flip Y
            return (sx, sy)
            
        def paintEvent(self, event):
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            w, h = self.width(), self.height()
            
            # Background gradient
            grad = QLinearGradient(0, 0, 0, h)
            grad.setColorAt(0, QColor("#0a1628"))
            grad.setColorAt(1, QColor("#0d1f35"))
            painter.fillRect(0, 0, w, h, grad)
            
            # Grid
            painter.setPen(QPen(QColor("#1a3050"), 1))
            grid_step = self.scale  # 1 meter grid
            for x in range(0, w, grid_step):
                painter.drawLine(x, 0, x, h)
            for y in range(0, h, grid_step):
                painter.drawLine(0, y, w, y)
            
            # Room boundary (approximate 6m x 5m room)
            painter.setPen(QPen(QColor("#2a5080"), 2))
            room_corners = [(-1, -2), (5, -2), (5, 3), (-1, 3)]
            for i in range(len(room_corners)):
                p1 = self.world_to_screen(*room_corners[i])
                p2 = self.world_to_screen(*room_corners[(i+1) % len(room_corners)])
                painter.drawLine(p1[0], p1[1], p2[0], p2[1])
            
            # Draw sensor nodes
            # Primary node (green)
            px, py = self.world_to_screen(*self.primary_pos)
            painter.setBrush(QBrush(QColor("#00ff88")))
            painter.setPen(QPen(QColor("#00ff88"), 2))
            painter.drawEllipse(px - 12, py - 12, 24, 24)
            painter.setPen(QColor("#00ff88"))
            painter.setFont(QFont("Arial", 9, QFont.Weight.Bold))
            painter.drawText(px - 30, py + 25, "PRIMARY")
            
            # Remote node (cyan)
            rx, ry = self.world_to_screen(*self.remote_pos)
            painter.setBrush(QBrush(QColor("#00d4ff")))
            painter.setPen(QPen(QColor("#00d4ff"), 2))
            painter.drawEllipse(rx - 12, ry - 12, 24, 24)
            painter.setPen(QColor("#00d4ff"))
            painter.drawText(rx - 25, ry + 25, "REMOTE")
            
            # Connection line between nodes
            painter.setPen(QPen(QColor("#1a5080"), 1, Qt.PenStyle.DashLine))
            painter.drawLine(px, py, rx, ry)
            
            # Draw detected devices
            now = time.time()
            for mac, device in self.devices.items():
                # Skip stale devices
                if now - device.last_seen > 10:
                    continue
                    
                dx, dy = self.world_to_screen(device.x, device.y)
                
                # Determine color based on signal strength and movement
                if device.is_moving:
                    color = QColor("#ff6b6b")  # Red for moving
                    size = 16
                elif device.rssi_primary > -60:
                    color = QColor("#ffd93d")  # Yellow for strong signal
                    size = 14
                else:
                    color = QColor("#6bcb77")  # Green for normal
                    size = 12
                
                # Fade based on age
                age = now - device.last_seen
                alpha = max(50, 255 - int(age * 25))
                color.setAlpha(alpha)
                
                # Draw device
                painter.setBrush(QBrush(color))
                painter.setPen(QPen(color.darker(120), 2))
                painter.drawEllipse(dx - size//2, dy - size//2, size, size)
                
                # Draw velocity vector if moving
                if device.is_moving:
                    vx, vy, _ = device.velocity
                    vlen = math.sqrt(vx**2 + vy**2)
                    if vlen > 0:
                        vx_norm = vx / vlen * 30
                        vy_norm = vy / vlen * 30
                        painter.setPen(QPen(QColor("#ff6b6b"), 2))
                        painter.drawLine(dx, dy, int(dx + vx_norm), int(dy - vy_norm))
                
                # MAC label (shortened)
                painter.setPen(QColor("#8fb3ff"))
                painter.setFont(QFont("Consolas", 8))
                short_mac = mac[-8:]
                painter.drawText(dx - 25, dy - size//2 - 5, short_mac)
            
            # Legend
            painter.setPen(QColor("#8fb3ff"))
            painter.setFont(QFont("Arial", 10))
            painter.drawText(10, 20, f"Devices: {len([d for d in self.devices.values() if now - d.last_seen < 10])}")
            painter.drawText(10, 40, "🟢 Stationary  🔴 Moving  🟡 Strong Signal")
    
    
    class StatsWidget(QFrame):
        """Statistics display panel."""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setStyleSheet("""
                QFrame {
                    background: #0d1520;
                    border: 1px solid #1f3a5f;
                    border-radius: 8px;
                }
                QLabel {
                    color: #d7e7ff;
                    font-family: 'Consolas', monospace;
                }
            """)
            
            layout = QVBoxLayout(self)
            layout.setContentsMargins(15, 15, 15, 15)
            layout.setSpacing(10)
            
            title = QLabel("📊 System Status")
            title.setStyleSheet("font-size: 16px; font-weight: bold; color: #00d4ff;")
            layout.addWidget(title)
            
            self.pps_label = QLabel("Packets/sec: 0")
            self.total_label = QLabel("Total Packets: 0")
            self.channel_label = QLabel("Channel: --")
            self.remote_label = QLabel("Remote: Disconnected")
            self.devices_label = QLabel("Active Devices: 0")
            self.moving_label = QLabel("Moving Objects: 0")
            
            for label in [self.pps_label, self.total_label, self.channel_label,
                         self.remote_label, self.devices_label, self.moving_label]:
                label.setStyleSheet("font-size: 12px; padding: 5px;")
                layout.addWidget(label)
            
            layout.addStretch()
            
        def update_stats(self, status: dict, remotes: dict, devices: Dict[str, DetectedDevice]):
            pps = status.get('pps', 0)
            total = status.get('total', 0)
            channel = status.get('channel', 0)
            
            self.pps_label.setText(f"📡 Packets/sec: {pps}")
            self.total_label.setText(f"📦 Total Packets: {total:,}")
            self.channel_label.setText(f"📻 Channel: {channel}")
            
            remote_list = remotes.get('remotes', [])
            if remote_list:
                r = remote_list[0]
                self.remote_label.setText(f"🔗 Remote: {r.get('node_id', 'Unknown')} ({r.get('rssi', 0)} dBm)")
                self.remote_label.setStyleSheet("font-size: 12px; padding: 5px; color: #00ff88;")
            else:
                self.remote_label.setText("🔗 Remote: Disconnected")
                self.remote_label.setStyleSheet("font-size: 12px; padding: 5px; color: #ff6b6b;")
            
            now = time.time()
            active = [d for d in devices.values() if now - d.last_seen < 10]
            moving = [d for d in active if d.is_moving]
            
            self.devices_label.setText(f"👥 Active Devices: {len(active)}")
            self.moving_label.setText(f"🏃 Moving Objects: {len(moving)}")
    
    
    class DeviceListWidget(QFrame):
        """List of detected devices."""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setStyleSheet("""
                QFrame {
                    background: #0d1520;
                    border: 1px solid #1f3a5f;
                    border-radius: 8px;
                }
                QLabel {
                    color: #d7e7ff;
                    font-family: 'Consolas', monospace;
                }
            """)
            
            self.layout = QVBoxLayout(self)
            self.layout.setContentsMargins(15, 15, 15, 15)
            self.layout.setSpacing(5)
            
            title = QLabel("📱 Detected Devices")
            title.setStyleSheet("font-size: 16px; font-weight: bold; color: #00d4ff;")
            self.layout.addWidget(title)
            
            self.device_labels = []
            for _ in range(15):
                label = QLabel("")
                label.setStyleSheet("font-size: 11px; padding: 2px;")
                self.layout.addWidget(label)
                self.device_labels.append(label)
            
            self.layout.addStretch()
            
        def update_devices(self, devices: Dict[str, DetectedDevice]):
            now = time.time()
            
            # Sort by signal strength
            sorted_devices = sorted(
                [(mac, d) for mac, d in devices.items() if now - d.last_seen < 10],
                key=lambda x: x[1].rssi_primary,
                reverse=True
            )
            
            for i, label in enumerate(self.device_labels):
                if i < len(sorted_devices):
                    mac, device = sorted_devices[i]
                    status = "🏃" if device.is_moving else "🧍"
                    rssi1 = device.rssi_primary
                    rssi2 = device.rssi_remote
                    pos = f"({device.x:.1f}, {device.y:.1f})"
                    label.setText(f"{status} {mac[-8:]} P:{rssi1:3d} R:{rssi2:3d} {pos}")
                    
                    if device.is_moving:
                        label.setStyleSheet("font-size: 11px; padding: 2px; color: #ff6b6b;")
                    elif rssi1 > -60:
                        label.setStyleSheet("font-size: 11px; padding: 2px; color: #ffd93d;")
                    else:
                        label.setStyleSheet("font-size: 11px; padding: 2px; color: #8fb3ff;")
                else:
                    label.setText("")
    
    
    class HydraSenseMainWindow(QMainWindow):
        """Main application window."""
        
        def __init__(self):
            super().__init__()
            self.setWindowTitle("🛰️ HydraSense Environment Visualizer")
            self.setMinimumSize(1200, 800)
            self.resize(1400, 900)
            
            self.setStyleSheet("""
                QMainWindow {
                    background: #0a0f1a;
                }
                QStatusBar {
                    background: #0d1520;
                    color: #8fb3ff;
                    border-top: 1px solid #1f3a5f;
                }
            """)
            
            # State
            self.devices: Dict[str, DetectedDevice] = {}
            self.triangulator = TriangulationEngine()
            
            # Data fetcher
            self.fetcher = ESP32DataFetcher("192.168.0.139", 80)
            self.fetcher.data_received.connect(self._on_data_received)
            self.fetcher.connection_status.connect(self._on_connection_status)
            
            # Setup UI
            self._setup_ui()
            
            # Start fetching
            self.fetcher.start()
            
        def _setup_ui(self):
            central = QWidget()
            self.setCentralWidget(central)
            
            main_layout = QHBoxLayout(central)
            main_layout.setContentsMargins(10, 10, 10, 10)
            main_layout.setSpacing(10)
            
            # Left panel - stats and device list
            left_panel = QVBoxLayout()
            left_panel.setSpacing(10)
            
            self.stats_widget = StatsWidget()
            self.stats_widget.setFixedWidth(280)
            left_panel.addWidget(self.stats_widget)
            
            self.device_list = DeviceListWidget()
            left_panel.addWidget(self.device_list)
            
            main_layout.addLayout(left_panel)
            
            # Center - environment map
            self.env_map = EnvironmentMapWidget()
            main_layout.addWidget(self.env_map, stretch=1)
            
            # Status bar
            self.status_bar = QStatusBar()
            self.setStatusBar(self.status_bar)
            self.connection_label = QLabel("⏳ Connecting...")
            self.status_bar.addWidget(self.connection_label)
            
        def _on_data_received(self, data: dict):
            """Handle incoming data from ESP32."""
            status = data.get('status', {})
            scan = data.get('scan', {})
            remotes = data.get('remotes', {})
            
            # Process detections
            detections = scan.get('detections', [])
            now = time.time()
            
            # Get remote RSSI data
            remote_list = remotes.get('remotes', [])
            
            for det in detections:
                mac = det.get('mac', '')
                if not mac or mac == '00:00:00:00:00:00':
                    continue
                
                rssi = det.get('rssi', -100)
                channel = det.get('channel', 0)
                frame_type = det.get('frame_type', 0)
                antenna = det.get('antenna', 0)
                
                # Create or update device
                if mac not in self.devices:
                    self.devices[mac] = DetectedDevice(mac=mac)
                
                device = self.devices[mac]
                device.channel = channel
                device.frame_type = frame_type
                device.last_seen = now
                
                # Determine if this is from primary or remote
                if antenna >= 100:  # Remote node data
                    device.rssi_remote = rssi
                else:
                    device.rssi_primary = rssi
                
                # Triangulate position
                if device.rssi_primary > -100 and device.rssi_remote > -100:
                    self.triangulator.update_device(device)
            
            # Update UI
            self.stats_widget.update_stats(status, remotes, self.devices)
            self.device_list.update_devices(self.devices)
            self.env_map.update_devices(self.devices)
            
        def _on_connection_status(self, connected: bool, info: str):
            if connected:
                self.connection_label.setText(f"🟢 Connected: {info}")
                self.connection_label.setStyleSheet("color: #00ff88;")
            else:
                self.connection_label.setText(f"🔴 Disconnected")
                self.connection_label.setStyleSheet("color: #ff6b6b;")
                
        def closeEvent(self, event):
            self.fetcher.stop()
            self.fetcher.wait()
            super().closeEvent(event)


# ============== Terminal Mode ==============

def run_terminal_mode():
    """Run in terminal mode without Qt."""
    print("\n" + "="*60)
    print("🛰️  HydraSense Environment Visualizer - Terminal Mode")
    print("="*60)
    
    fetcher = ESP32DataFetcher("192.168.0.139", 80)
    triangulator = TriangulationEngine()
    devices: Dict[str, DetectedDevice] = {}
    
    def on_data(data):
        status = data.get('status', {})
        scan = data.get('scan', {})
        remotes = data.get('remotes', {})
        
        # Clear screen
        print("\033[2J\033[H", end="")
        
        print("╔══════════════════════════════════════════════════════════╗")
        print("║     🛰️  HydraSense Environment Visualizer                ║")
        print("╠══════════════════════════════════════════════════════════╣")
        print(f"║  PPS: {status.get('pps', 0):5d}  │  Total: {status.get('total', 0):10,}  │  CH: {status.get('channel', 0):2d}    ║")
        
        remote_list = remotes.get('remotes', [])
        if remote_list:
            r = remote_list[0]
            print(f"║  Remote: {r.get('node_id', 'N/A'):10s}  │  RSSI: {r.get('rssi', 0):4d} dBm         ║")
        else:
            print("║  Remote: Disconnected                                    ║")
        
        print("╠══════════════════════════════════════════════════════════╣")
        print("║  MAC Address    │ P.RSSI │ R.RSSI │  Position   │ Status ║")
        print("╠══════════════════════════════════════════════════════════╣")
        
        # Process detections
        now = time.time()
        for det in scan.get('detections', [])[:20]:
            mac = det.get('mac', '')
            if not mac or mac == '00:00:00:00:00:00':
                continue
            
            if mac not in devices:
                devices[mac] = DetectedDevice(mac=mac)
            
            device = devices[mac]
            rssi = det.get('rssi', -100)
            antenna = det.get('antenna', 0)
            device.last_seen = now
            
            if antenna >= 100:
                device.rssi_remote = rssi
            else:
                device.rssi_primary = rssi
            
            triangulator.update_device(device)
        
        # Display active devices
        active = sorted(
            [(m, d) for m, d in devices.items() if now - d.last_seen < 10],
            key=lambda x: x[1].rssi_primary, reverse=True
        )[:12]
        
        for mac, d in active:
            status_icon = "🏃" if d.is_moving else "🧍"
            print(f"║  {mac[-14:]:14s} │ {d.rssi_primary:6d} │ {d.rssi_remote:6d} │ ({d.x:4.1f},{d.y:4.1f}) │ {status_icon}     ║")
        
        print("╚══════════════════════════════════════════════════════════╝")
        print(f"\n  Active Devices: {len(active)}  │  Time: {datetime.now().strftime('%H:%M:%S')}")
        print("  Press Ctrl+C to exit")
    
    fetcher.add_callback(on_data)
    fetcher.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        fetcher.stop()


# ============== Main ==============

def main():
    if HAS_QT:
        app = QApplication(sys.argv)
        app.setApplicationName("HydraSense Visualizer")
        
        window = HydraSenseMainWindow()
        window.show()
        
        sys.exit(app.exec())
    else:
        run_terminal_mode()


if __name__ == "__main__":
    main()
