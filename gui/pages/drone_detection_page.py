"""
Drone Detection Page - ESP32-based Drone Detection GUI
========================================================

Real-time drone detection, tracking, and alerting interface
with map visualization and threat assessment.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox,
    QLabel, QLineEdit, QTextEdit, QPushButton, QComboBox,
    QCheckBox, QSpinBox, QProgressBar, QTabWidget, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame, QSlider,
    QListWidget, QListWidgetItem, QMessageBox, QFileDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush, QRadialGradient, QPainterPath
import sys
import os
import math
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class RadarWidget(QWidget):
    """Radar-style visualization of detected drones"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(400, 400)
        self.drones = []
        self.sweep_angle = 0
        self.center_x = 0
        self.center_y = 0
        self.max_range = 500  # meters
        
        # Animation timer
        self.sweep_timer = QTimer(self)
        self.sweep_timer.timeout.connect(self._update_sweep)
        self.sweep_timer.start(30)
        
    def set_drones(self, drones):
        """Update drone list"""
        self.drones = drones
        self.update()
    
    def _update_sweep(self):
        """Update radar sweep animation"""
        self.sweep_angle = (self.sweep_angle + 2) % 360
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Get dimensions
        w = self.width()
        h = self.height()
        self.center_x = w // 2
        self.center_y = h // 2
        radius = min(w, h) // 2 - 20
        
        # Draw background
        painter.fillRect(0, 0, w, h, QColor("#0d1117"))
        
        # Draw radar circles
        painter.setPen(QPen(QColor("#1a472a"), 1))
        for i in range(1, 5):
            r = int(radius * i / 4)
            painter.drawEllipse(self.center_x - r, self.center_y - r, r * 2, r * 2)
            
            # Distance labels
            dist = int(self.max_range * i / 4)
            painter.setPen(QPen(QColor("#3fb950"), 1))
            painter.drawText(self.center_x + 5, self.center_y - r + 15, f"{dist}m")
        
        # Draw cross lines
        painter.setPen(QPen(QColor("#1a472a"), 1))
        painter.drawLine(self.center_x, self.center_y - radius, self.center_x, self.center_y + radius)
        painter.drawLine(self.center_x - radius, self.center_y, self.center_x + radius, self.center_y)
        
        # Draw sweep line with glow
        sweep_rad = math.radians(self.sweep_angle)
        sweep_x = self.center_x + int(radius * math.cos(sweep_rad))
        sweep_y = self.center_y - int(radius * math.sin(sweep_rad))
        
        # Glow effect
        for i in range(10, 0, -1):
            alpha = int(25 * (10 - i) / 10)
            painter.setPen(QPen(QColor(59, 185, 80, alpha), i))
            angle = sweep_rad - math.radians(i * 2)
            glow_x = self.center_x + int(radius * math.cos(angle))
            glow_y = self.center_y - int(radius * math.sin(angle))
            painter.drawLine(self.center_x, self.center_y, glow_x, glow_y)
        
        # Main sweep line
        painter.setPen(QPen(QColor("#3fb950"), 2))
        painter.drawLine(self.center_x, self.center_y, sweep_x, sweep_y)
        
        # Draw drones
        for drone in self.drones:
            self._draw_drone(painter, drone, radius)
        
        # Draw center point
        painter.setBrush(QBrush(QColor("#58a6ff")))
        painter.setPen(QPen(QColor("#58a6ff"), 1))
        painter.drawEllipse(self.center_x - 5, self.center_y - 5, 10, 10)
        
        # Draw legend
        self._draw_legend(painter, w, h)
        
    def _draw_drone(self, painter, drone, radius):
        """Draw a drone blip on the radar"""
        # Calculate position based on distance and random angle
        distance = getattr(drone, 'estimated_distance', 100)
        
        # Use MAC hash for consistent positioning
        mac_hash = hash(drone.mac_address)
        angle = (mac_hash % 360) * math.pi / 180
        
        # Scale distance to radar
        r = min(int((distance / self.max_range) * radius), radius)
        
        x = self.center_x + int(r * math.cos(angle))
        y = self.center_y - int(r * math.sin(angle))
        
        # Choose color based on threat level
        threat = getattr(drone, 'threat_level', None)
        if threat:
            colors = {
                'critical': QColor("#f85149"),
                'high': QColor("#f0883e"),
                'medium': QColor("#d29922"),
                'low': QColor("#3fb950"),
            }
            color = colors.get(threat.value, QColor("#8b949e"))
        else:
            color = QColor("#8b949e")
        
        # Pulsing effect for high threat
        pulse = 1.0
        if threat and threat.value in ['critical', 'high']:
            pulse = 1.0 + 0.3 * math.sin(time.time() * 5)
        
        # Draw drone blip with glow
        size = int(8 * pulse)
        
        # Glow
        gradient = QRadialGradient(x, y, size * 2)
        gradient.setColorAt(0, QColor(color.red(), color.green(), color.blue(), 150))
        gradient.setColorAt(1, QColor(color.red(), color.green(), color.blue(), 0))
        painter.setBrush(QBrush(gradient))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(x - size * 2, y - size * 2, size * 4, size * 4)
        
        # Main blip
        painter.setBrush(QBrush(color))
        painter.drawEllipse(x - size//2, y - size//2, size, size)
        
        # Label
        painter.setPen(QPen(color, 1))
        painter.setFont(QFont("Arial", 8))
        label = getattr(drone, 'manufacturer', 'Unknown')[:10]
        painter.drawText(x + 10, y + 5, label)
    
    def _draw_legend(self, painter, w, h):
        """Draw threat level legend"""
        painter.setFont(QFont("Arial", 9))
        
        legend = [
            ("🔴 Critical", "#f85149"),
            ("🟠 High", "#f0883e"),
            ("🟡 Medium", "#d29922"),
            ("🟢 Low", "#3fb950"),
        ]
        
        y = 20
        for text, color in legend:
            painter.setPen(QPen(QColor(color), 1))
            painter.drawText(10, y, text)
            y += 18


class DroneDetectionWorker(QThread):
    """Background worker for drone detection"""
    drone_detected = pyqtSignal(dict)
    alert_raised = pyqtSignal(str, str)
    status_update = pyqtSignal(dict)
    log_message = pyqtSignal(str, str)
    
    def __init__(self, port=None, use_simulator=True):
        super().__init__()
        self.port = port
        self.use_simulator = use_simulator
        self.running = False
        self.detector = None
        
    def run(self):
        try:
            from core.drone_detection import ESP32DroneDetector, DroneDetectionSimulator
            
            self.log_message.emit("🚁 Initializing drone detection system...", "info")
            
            self.detector = ESP32DroneDetector(
                port=self.port,
                detection_callback=self._on_detection,
                alert_callback=self._on_alert
            )
            
            if self.use_simulator:
                self.log_message.emit("🎮 Starting in SIMULATOR mode", "warning")
                sim = DroneDetectionSimulator(self.detector)
                sim.start()
            else:
                if not self.detector.connect():
                    self.log_message.emit("❌ Failed to connect to ESP32", "error")
                    return
                self.log_message.emit(f"✅ Connected to ESP32 on {self.detector.port}", "success")
                self.detector.start_detection()
            
            self.running = True
            
            while self.running:
                # Emit status updates
                stats = self.detector.get_statistics()
                self.status_update.emit(stats)
                
                # Emit active drones
                for drone in self.detector.get_active_drones():
                    self.drone_detected.emit(self._drone_to_dict(drone))
                
                time.sleep(1)
                
        except Exception as e:
            self.log_message.emit(f"❌ Error: {str(e)}", "error")
    
    def stop(self):
        self.running = False
        if self.detector:
            self.detector.stop_detection()
    
    def _on_detection(self, drone):
        self.drone_detected.emit(self._drone_to_dict(drone))
        self.log_message.emit(
            f"🚁 DETECTED: {drone.drone_type.value} | {drone.mac_address} | {drone.signal_strength}dBm",
            "success"
        )
    
    def _on_alert(self, message, threat_level):
        self.alert_raised.emit(message, threat_level.value)
        self.log_message.emit(f"🚨 ALERT: {message}", "error")
    
    def _drone_to_dict(self, drone):
        return {
            'id': drone.id,
            'type': drone.drone_type.value,
            'mac': drone.mac_address,
            'ssid': drone.ssid,
            'manufacturer': drone.manufacturer,
            'model': drone.model,
            'signal': drone.signal_strength,
            'distance': drone.estimated_distance,
            'threat': drone.threat_level.value,
            'first_seen': drone.first_seen.isoformat(),
            'last_seen': drone.last_seen.isoformat(),
            'packets': drone.packet_count,
            'method': drone.detection_method.value,
        }


class DroneDetectionPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.detected_drones = {}
        self.init_ui()
        self._apply_styles()
        
    def init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Radar and controls
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setSpacing(10)
        
        # Title
        title = QLabel("🚁 ESP32 Drone Detection System")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")
        left_layout.addWidget(title)
        
        # Radar display
        radar_group = QGroupBox("📡 Radar View")
        radar_layout = QVBoxLayout(radar_group)
        self.radar = RadarWidget()
        radar_layout.addWidget(self.radar)
        left_layout.addWidget(radar_group)
        
        # Connection settings
        conn_group = QGroupBox("🔌 ESP32 Connection")
        conn_layout = QGridLayout(conn_group)
        
        conn_layout.addWidget(QLabel("Serial Port:"), 0, 0)
        self.port_combo = QComboBox()
        self.port_combo.addItems(["/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyACM0", "COM3", "COM4"])
        self.port_combo.setEditable(True)
        conn_layout.addWidget(self.port_combo, 0, 1)
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_ports)
        conn_layout.addWidget(self.refresh_btn, 0, 2)
        
        self.sim_mode = QCheckBox("Simulator Mode (no hardware)")
        self.sim_mode.setChecked(True)
        conn_layout.addWidget(self.sim_mode, 1, 0, 1, 3)
        
        left_layout.addWidget(conn_group)
        
        # Detection settings
        settings_group = QGroupBox("⚙️ Detection Settings")
        settings_layout = QGridLayout(settings_group)
        
        settings_layout.addWidget(QLabel("Alert Distance (m):"), 0, 0)
        self.alert_distance = QSpinBox()
        self.alert_distance.setRange(10, 1000)
        self.alert_distance.setValue(100)
        settings_layout.addWidget(self.alert_distance, 0, 1)
        
        settings_layout.addWidget(QLabel("Max Range (m):"), 1, 0)
        self.max_range = QSpinBox()
        self.max_range.setRange(100, 5000)
        self.max_range.setValue(500)
        self.max_range.valueChanged.connect(lambda v: setattr(self.radar, 'max_range', v))
        settings_layout.addWidget(self.max_range, 1, 1)
        
        self.sound_alerts = QCheckBox("Sound Alerts")
        self.sound_alerts.setChecked(True)
        settings_layout.addWidget(self.sound_alerts, 2, 0, 1, 2)
        
        left_layout.addWidget(settings_group)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("▶️ Start Detection")
        self.start_btn.clicked.connect(self.start_detection)
        self.start_btn.setStyleSheet("background-color: #238636; font-weight: bold; padding: 12px;")
        btn_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.clicked.connect(self.stop_detection)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("background-color: #da3633; padding: 12px;")
        btn_layout.addWidget(self.stop_btn)
        
        left_layout.addLayout(btn_layout)
        
        # Statistics
        stats_group = QGroupBox("📊 Statistics")
        stats_layout = QGridLayout(stats_group)
        
        self.stat_labels = {}
        stats = [
            ("Active Drones:", "active"),
            ("Total Detected:", "total"),
            ("Packets Analyzed:", "packets"),
            ("Alerts Raised:", "alerts"),
            ("Uptime:", "uptime"),
        ]
        
        for i, (label, key) in enumerate(stats):
            stats_layout.addWidget(QLabel(label), i, 0)
            self.stat_labels[key] = QLabel("0")
            self.stat_labels[key].setStyleSheet("color: #58a6ff; font-weight: bold;")
            stats_layout.addWidget(self.stat_labels[key], i, 1)
        
        left_layout.addWidget(stats_group)
        
        # Right panel - Drone list and logs
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        # Tabs
        self.tabs = QTabWidget()
        
        # Detected Drones Tab
        drones_widget = QWidget()
        drones_layout = QVBoxLayout(drones_widget)
        
        self.drone_table = QTableWidget()
        self.drone_table.setColumnCount(7)
        self.drone_table.setHorizontalHeaderLabels([
            'Type', 'Manufacturer', 'MAC', 'Signal', 'Distance', 'Threat', 'Last Seen'
        ])
        self.drone_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.drone_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        drones_layout.addWidget(self.drone_table)
        
        drone_btns = QHBoxLayout()
        self.export_btn = QPushButton("💾 Export Detections")
        self.export_btn.clicked.connect(self.export_detections)
        drone_btns.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear History")
        self.clear_btn.clicked.connect(self.clear_history)
        drone_btns.addWidget(self.clear_btn)
        
        drones_layout.addLayout(drone_btns)
        
        self.tabs.addTab(drones_widget, "🚁 Detected Drones")
        
        # Activity Log Tab
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setFont(QFont("Monospace", 10))
        log_layout.addWidget(self.activity_log)
        
        log_clear = QPushButton("🗑️ Clear Log")
        log_clear.clicked.connect(lambda: self.activity_log.clear())
        log_layout.addWidget(log_clear)
        
        self.tabs.addTab(log_widget, "📋 Activity Log")
        
        # Alerts Tab
        alerts_widget = QWidget()
        alerts_layout = QVBoxLayout(alerts_widget)
        
        self.alerts_list = QListWidget()
        alerts_layout.addWidget(self.alerts_list)
        
        alerts_clear = QPushButton("🗑️ Clear Alerts")
        alerts_clear.clicked.connect(lambda: self.alerts_list.clear())
        alerts_layout.addWidget(alerts_clear)
        
        self.tabs.addTab(alerts_widget, "🚨 Alerts")
        
        # Drone Database Tab
        db_widget = QWidget()
        db_layout = QVBoxLayout(db_widget)
        
        db_info = QTextEdit()
        db_info.setReadOnly(True)
        db_info.setPlainText("""
Known Drone Manufacturers & OUI Prefixes:

🔹 DJI
   - 60:60:1F:* - Mavic, Mini, Air series
   - 34:D2:62:* - Phantom, Inspire series
   - 48:1C:B9:* - FPV, Avata series
   - 98:3A:92:* - Matrice series
   - A0:14:3D:* - Various models
   - C4:62:6B:* - Controllers

🔹 Parrot
   - 90:03:B7:* - Anafi, Bebop series

🔹 Autel
   - 50:0F:10:* - Evo, Dragonfish series

🔹 Skydio
   - B8:F0:09:* - Skydio 2, X2

🔹 Holy Stone
   - E8:68:E7:* - HS series

🔹 Hubsan
   - B4:E6:2D:* - Zino, X4 series

🔹 Syma
   - 00:1A:79:* - X series

Detection Methods:
==================
• WiFi Probe Requests - Passive monitoring
• WiFi Beacons - AP mode detection
• MAC OUI Analysis - Manufacturer identification
• RF Signature - 2.4/5.8GHz signal patterns
• Remote ID - FAA broadcast protocol
• Protocol Analysis - DJI/Parrot protocol fingerprinting
        """)
        db_layout.addWidget(db_info)
        
        self.tabs.addTab(db_widget, "📚 Drone Database")
        
        right_layout.addWidget(self.tabs)
        
        # Add panels to splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([450, 550])
        
        layout.addWidget(splitter)
        
        # Initial log
        self.log_activity("🚁 Drone Detection System initialized", "info")
        self.log_activity("Connect ESP32 or enable Simulator Mode to start", "info")
        
    def _apply_styles(self):
        self.setStyleSheet("""
            QWidget { background-color: #0d1117; color: #c9d1d9; }
            QGroupBox { font-weight: bold; border: 1px solid #30363d; border-radius: 8px; margin-top: 12px; padding-top: 10px; background-color: #161b22; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; color: #58a6ff; }
            QLineEdit, QComboBox, QSpinBox { background-color: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 8px; color: #c9d1d9; }
            QCheckBox { color: #c9d1d9; }
            QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid #30363d; background-color: #0d1117; }
            QCheckBox::indicator:checked { background-color: #238636; }
            QTabWidget::pane { border: 1px solid #30363d; border-radius: 6px; background-color: #0d1117; top: -1px; }
            QTabBar::tab { background-color: #161b22; color: #8b949e; padding: 10px 16px; margin-right: 4px; border: 1px solid #30363d; border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; }
            QTabBar::tab:selected { background-color: #0d1117; color: #58a6ff; }
            QPushButton { background-color: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 8px 16px; font-weight: bold; }
            QPushButton:hover { background-color: #30363d; }
            QPushButton:disabled { background-color: #161b22; color: #484f58; }
            QTableWidget { background-color: #0d1117; border: 1px solid #30363d; gridline-color: #30363d; }
            QTableWidget::item { padding: 8px; }
            QTableWidget::item:selected { background-color: #388bfd33; }
            QHeaderView::section { background-color: #161b22; color: #c9d1d9; padding: 8px; border: none; border-bottom: 1px solid #30363d; }
            QListWidget { background-color: #0d1117; border: 1px solid #30363d; border-radius: 6px; }
            QListWidget::item { padding: 8px; border-bottom: 1px solid #21262d; }
            QTextEdit { background-color: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; }
        """)
    
    def log_activity(self, message, level="info"):
        colors = {
            "info": "#8b949e",
            "success": "#3fb950",
            "warning": "#d29922",
            "error": "#f85149"
        }
        color = colors.get(level, "#8b949e")
        timestamp = datetime.now().strftime("%H:%M:%S")
        html = f'<span style="color: #6e7681;">[{timestamp}]</span> <span style="color: {color};">{message}</span><br>'
        self.activity_log.insertHtml(html)
        scrollbar = self.activity_log.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def refresh_ports(self):
        """Refresh available serial ports"""
        try:
            from core.drone_detection import ESP32DroneDetector
            detector = ESP32DroneDetector()
            ports = detector.find_esp32_ports()
            
            self.port_combo.clear()
            if ports:
                self.port_combo.addItems(ports)
                self.log_activity(f"✅ Found {len(ports)} ESP32 device(s)", "success")
            else:
                self.port_combo.addItems(["/dev/ttyUSB0", "/dev/ttyUSB1", "COM3"])
                self.log_activity("⚠️ No ESP32 devices found", "warning")
        except Exception as e:
            self.log_activity(f"❌ Port scan failed: {e}", "error")
    
    def start_detection(self):
        """Start drone detection"""
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        port = self.port_combo.currentText() if not self.sim_mode.isChecked() else None
        
        self.worker = DroneDetectionWorker(
            port=port,
            use_simulator=self.sim_mode.isChecked()
        )
        self.worker.drone_detected.connect(self.on_drone_detected)
        self.worker.alert_raised.connect(self.on_alert)
        self.worker.status_update.connect(self.on_status_update)
        self.worker.log_message.connect(self.log_activity)
        self.worker.start()
        
        self.log_activity("▶️ Detection started", "success")
    
    def stop_detection(self):
        """Stop drone detection"""
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.log_activity("⏹️ Detection stopped", "warning")
    
    def on_drone_detected(self, drone_data):
        """Handle new drone detection"""
        drone_id = drone_data['id']
        self.detected_drones[drone_id] = drone_data
        self._update_drone_table()
        self._update_radar()
    
    def on_alert(self, message, threat_level):
        """Handle alert"""
        colors = {
            'critical': '#f85149',
            'high': '#f0883e',
            'medium': '#d29922',
            'low': '#3fb950'
        }
        color = colors.get(threat_level, '#8b949e')
        
        item = QListWidgetItem(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        item.setForeground(QColor(color))
        self.alerts_list.insertItem(0, item)
        
        # Switch to alerts tab for critical
        if threat_level in ['critical', 'high']:
            self.tabs.setCurrentIndex(2)
    
    def on_status_update(self, stats):
        """Update statistics display"""
        self.stat_labels['active'].setText(str(stats.get('active_drones', 0)))
        self.stat_labels['total'].setText(str(stats.get('unique_drones', 0)))
        self.stat_labels['packets'].setText(str(stats.get('total_packets', 0)))
        self.stat_labels['alerts'].setText(str(stats.get('alerts_raised', 0)))
        
        uptime = stats.get('uptime_seconds', 0)
        mins, secs = divmod(int(uptime), 60)
        hours, mins = divmod(mins, 60)
        self.stat_labels['uptime'].setText(f"{hours:02d}:{mins:02d}:{secs:02d}")
    
    def _update_drone_table(self):
        """Update drone table with current detections"""
        self.drone_table.setRowCount(len(self.detected_drones))
        
        for i, (drone_id, drone) in enumerate(self.detected_drones.items()):
            self.drone_table.setItem(i, 0, QTableWidgetItem(drone['type']))
            self.drone_table.setItem(i, 1, QTableWidgetItem(drone['manufacturer']))
            self.drone_table.setItem(i, 2, QTableWidgetItem(drone['mac']))
            self.drone_table.setItem(i, 3, QTableWidgetItem(f"{drone['signal']} dBm"))
            self.drone_table.setItem(i, 4, QTableWidgetItem(f"{drone['distance']:.1f} m"))
            
            threat_item = QTableWidgetItem(drone['threat'].upper())
            threat_colors = {
                'critical': '#f85149',
                'high': '#f0883e',
                'medium': '#d29922',
                'low': '#3fb950'
            }
            threat_item.setForeground(QColor(threat_colors.get(drone['threat'], '#8b949e')))
            self.drone_table.setItem(i, 5, threat_item)
            
            last_seen = datetime.fromisoformat(drone['last_seen']).strftime('%H:%M:%S')
            self.drone_table.setItem(i, 6, QTableWidgetItem(last_seen))
    
    def _update_radar(self):
        """Update radar display with current drones"""
        # Create drone-like objects for radar
        class DronePlot:
            pass
        
        drone_plots = []
        for drone_data in self.detected_drones.values():
            plot = DronePlot()
            plot.mac_address = drone_data['mac']
            plot.estimated_distance = drone_data['distance']
            plot.manufacturer = drone_data['manufacturer']
            
            class ThreatLevel:
                def __init__(self, val):
                    self.value = val
            plot.threat_level = ThreatLevel(drone_data['threat'])
            
            drone_plots.append(plot)
        
        self.radar.set_drones(drone_plots)
    
    def export_detections(self):
        """Export detections to file"""
        if not self.detected_drones:
            self.log_activity("❌ No detections to export", "error")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Detections", "drone_detections.json", "JSON Files (*.json)"
        )
        
        if filename:
            import json
            data = {
                'export_time': datetime.now().isoformat(),
                'drones': list(self.detected_drones.values())
            }
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            self.log_activity(f"✅ Exported to {filename}", "success")
    
    def clear_history(self):
        """Clear detection history"""
        self.detected_drones.clear()
        self.drone_table.setRowCount(0)
        self.radar.set_drones([])
        self.log_activity("🗑️ History cleared", "info")
