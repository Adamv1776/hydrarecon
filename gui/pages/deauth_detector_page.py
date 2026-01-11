"""
Deauth Detector GUI Page
========================
Wireless Intrusion Detection System (WIDS) interface for monitoring
deauthentication and disassociation flood attacks.
"""

import asyncio
import json
from datetime import datetime
from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QLineEdit, QSpinBox, QDoubleSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QGroupBox, QTextEdit, QComboBox, QCheckBox, QProgressBar,
    QSplitter, QTabWidget, QScrollArea, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor

import logging

logger = logging.getLogger(__name__)


class DetectorWorker(QThread):
    """Background worker thread for the deauth detector"""
    status_update = pyqtSignal(dict)
    event_received = pyqtSignal(dict)
    alert_received = pyqtSignal(dict)
    error = pyqtSignal(str)
    connected = pyqtSignal(bool)
    
    def __init__(self, host: str, port: int, interval: float):
        super().__init__()
        self.host = host
        self.port = port
        self.interval = interval
        self.running = False
        self.detector = None
    
    def run(self):
        """Run the detector in background thread with its own event loop"""
        import asyncio
        
        # Create new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(self._run_detector())
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()
    
    async def _run_detector(self):
        """Async detector runner"""
        try:
            from core.esp32_deauth_detector import DeauthDetector, Alert
            
            def alert_callback(alert: Alert):
                self.alert_received.emit(alert.to_dict())
            
            self.detector = DeauthDetector(
                esp32_host=self.host,
                esp32_port=self.port,
                poll_interval=self.interval,
                auto_discover=True,
                alert_callback=alert_callback,
            )
            
            self.running = await self.detector.start()
            if not self.running:
                self.error.emit("Failed to connect to ESP32")
                self.connected.emit(False)
                return
            
            self.connected.emit(True)
            
            # Polling loop
            while self.running:
                await asyncio.sleep(1.0)
                
                if self.detector:
                    # Emit status
                    status = self.detector.get_status()
                    self.status_update.emit(status)
                    
                    # Emit recent events
                    events = self.detector.get_recent_events(10)
                    for evt in events:
                        self.event_received.emit(evt)
            
        except Exception as e:
            self.error.emit(f"Detector error: {e}")
        finally:
            if self.detector:
                await self.detector.stop()
    
    def stop(self):
        """Stop the detector"""
        self.running = False
        self.wait(3000)


class DeauthDetectorPage(QWidget):
    """Main GUI page for ESP32 Deauth Detector WIDS"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: Optional[DetectorWorker] = None
        self.event_hashes = set()  # Deduplicate displayed events
        self.setup_ui()
        self.setup_timers()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("🛡️ Wireless IDS - Deauth/Disassoc Flood Detection")
        header.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ff88; padding: 10px;")
        layout.addWidget(header)
        
        # Connection settings
        conn_group = QGroupBox("ESP32 Connection")
        conn_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #444;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        conn_layout = QHBoxLayout(conn_group)
        
        conn_layout.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit("192.168.4.1")
        self.host_input.setPlaceholderText("ESP32 IP or hostname")
        self.host_input.setMaximumWidth(200)
        conn_layout.addWidget(self.host_input)
        
        conn_layout.addWidget(QLabel("Port:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(80)
        self.port_input.setMaximumWidth(80)
        conn_layout.addWidget(self.port_input)
        
        conn_layout.addWidget(QLabel("Poll Interval:"))
        self.interval_input = QDoubleSpinBox()
        self.interval_input.setRange(0.1, 10.0)
        self.interval_input.setValue(1.0)
        self.interval_input.setSuffix(" sec")
        self.interval_input.setMaximumWidth(100)
        conn_layout.addWidget(self.interval_input)
        
        conn_layout.addStretch()
        
        self.start_btn = QPushButton("▶ Start Monitoring")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background: #00aa55;
                color: white;
                padding: 8px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #00cc66;
            }
            QPushButton:disabled {
                background: #555;
            }
        """)
        self.start_btn.clicked.connect(self.toggle_monitoring)
        conn_layout.addWidget(self.start_btn)
        
        self.status_indicator = QLabel("● Disconnected")
        self.status_indicator.setStyleSheet("color: #ff4444; font-weight: bold;")
        conn_layout.addWidget(self.status_indicator)
        
        layout.addWidget(conn_group)
        
        # Stats panel
        stats_group = QGroupBox("Real-time Statistics")
        stats_layout = QGridLayout(stats_group)
        
        self.stat_labels = {}
        stats = [
            ("deauth_frames", "Deauth Frames", 0, 0),
            ("disassoc_frames", "Disassoc Frames", 0, 1),
            ("attacks_detected", "Attacks Detected", 0, 2),
            ("active_attacks", "Active Attacks", 0, 3),
            ("alerts", "Alerts", 1, 0),
            ("uptime", "Uptime", 1, 1),
            ("last_event", "Last Event", 1, 2),
            ("frame_rate", "Frame Rate", 1, 3),
        ]
        
        for key, label, row, col in stats:
            frame = QFrame()
            frame.setStyleSheet("""
                QFrame {
                    background: #1a1a2e;
                    border: 1px solid #333;
                    border-radius: 5px;
                    padding: 5px;
                }
            """)
            frame_layout = QVBoxLayout(frame)
            frame_layout.setSpacing(2)
            
            name_lbl = QLabel(label)
            name_lbl.setStyleSheet("color: #888; font-size: 11px;")
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            frame_layout.addWidget(name_lbl)
            
            value_lbl = QLabel("0")
            value_lbl.setStyleSheet("color: #00ff88; font-size: 18px; font-weight: bold;")
            value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            frame_layout.addWidget(value_lbl)
            
            self.stat_labels[key] = value_lbl
            stats_layout.addWidget(frame, row, col)
        
        layout.addWidget(stats_group)
        
        # Main content - tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #444;
                border-radius: 5px;
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #aaa;
                padding: 8px 20px;
                border: 1px solid #333;
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background: #2a2a4e;
                color: #00ff88;
            }
        """)
        
        # Events tab
        events_widget = QWidget()
        events_layout = QVBoxLayout(events_widget)
        
        self.events_table = QTableWidget()
        self.events_table.setColumnCount(7)
        self.events_table.setHorizontalHeaderLabels([
            "Time", "Type", "Source MAC", "BSSID", "Channel", "RSSI", "Details"
        ])
        self.events_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.events_table.setAlternatingRowColors(True)
        self.events_table.setStyleSheet("""
            QTableWidget {
                background: #0a0a1a;
                gridline-color: #333;
                color: #ddd;
            }
            QTableWidget::item:alternate {
                background: #1a1a2e;
            }
            QHeaderView::section {
                background: #2a2a4e;
                color: #00ff88;
                padding: 5px;
                border: 1px solid #333;
            }
        """)
        events_layout.addWidget(self.events_table)
        
        events_controls = QHBoxLayout()
        self.clear_events_btn = QPushButton("Clear Events")
        self.clear_events_btn.clicked.connect(self.clear_events)
        events_controls.addWidget(self.clear_events_btn)
        
        self.export_events_btn = QPushButton("Export to JSON")
        self.export_events_btn.clicked.connect(self.export_events)
        events_controls.addWidget(self.export_events_btn)
        
        events_controls.addStretch()
        events_layout.addLayout(events_controls)
        
        tabs.addTab(events_widget, "📊 Live Events")
        
        # Alerts tab
        alerts_widget = QWidget()
        alerts_layout = QVBoxLayout(alerts_widget)
        
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(5)
        self.alerts_table.setHorizontalHeaderLabels([
            "Time", "Severity", "Title", "Attacker MAC", "Target BSSID"
        ])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.alerts_table.setStyleSheet("""
            QTableWidget {
                background: #0a0a1a;
                gridline-color: #333;
                color: #ddd;
            }
            QHeaderView::section {
                background: #4a2a2e;
                color: #ff6666;
                padding: 5px;
                border: 1px solid #333;
            }
        """)
        alerts_layout.addWidget(self.alerts_table)
        
        tabs.addTab(alerts_widget, "🚨 Alerts")
        
        # Attack sessions tab
        sessions_widget = QWidget()
        sessions_layout = QVBoxLayout(sessions_widget)
        
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(7)
        self.sessions_table.setHorizontalHeaderLabels([
            "ID", "Start Time", "Status", "Target BSSID", "Attacker", "Frames", "Severity"
        ])
        self.sessions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.sessions_table.setStyleSheet("""
            QTableWidget {
                background: #0a0a1a;
                gridline-color: #333;
                color: #ddd;
            }
            QHeaderView::section {
                background: #2a4a2e;
                color: #88ff88;
                padding: 5px;
                border: 1px solid #333;
            }
        """)
        sessions_layout.addWidget(self.sessions_table)
        
        tabs.addTab(sessions_widget, "🎯 Attack Sessions")
        
        # Console/log tab
        console_widget = QWidget()
        console_layout = QVBoxLayout(console_widget)
        
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setStyleSheet("""
            QTextEdit {
                background: #0a0a0a;
                color: #00ff00;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                border: 1px solid #333;
            }
        """)
        console_layout.addWidget(self.console_output)
        
        tabs.addTab(console_widget, "📝 Console Log")
        
        layout.addWidget(tabs)
    
    def setup_timers(self):
        """Setup UI update timers"""
        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_ui)
        self.ui_timer.start(1000)  # Update every second
    
    def toggle_monitoring(self):
        """Start or stop monitoring"""
        if self.worker and self.worker.running:
            self.stop_monitoring()
        else:
            self.start_monitoring()
    
    def start_monitoring(self):
        """Start the deauth detector"""
        host = self.host_input.text().strip()
        port = self.port_input.value()
        interval = self.interval_input.value()
        
        if not host:
            QMessageBox.warning(self, "Error", "Please enter ESP32 host address")
            return
        
        self.log_console(f"Starting WIDS monitoring on {host}:{port}...")
        
        # Create and start worker
        self.worker = DetectorWorker(host, port, interval)
        self.worker.status_update.connect(self.on_status_update)
        self.worker.event_received.connect(self.on_event_received)
        self.worker.alert_received.connect(self.on_alert_received)
        self.worker.error.connect(self.on_error)
        self.worker.connected.connect(self.on_connected)
        self.worker.start()
        
        self.start_btn.setText("⏹ Stop Monitoring")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background: #aa3333;
                color: white;
                padding: 8px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #cc4444;
            }
        """)
        self.host_input.setEnabled(False)
        self.port_input.setEnabled(False)
        self.interval_input.setEnabled(False)
    
    def stop_monitoring(self):
        """Stop the deauth detector"""
        if self.worker:
            self.log_console("Stopping WIDS monitoring...")
            self.worker.stop()
            self.worker = None
        
        self.start_btn.setText("▶ Start Monitoring")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background: #00aa55;
                color: white;
                padding: 8px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #00cc66;
            }
        """)
        self.host_input.setEnabled(True)
        self.port_input.setEnabled(True)
        self.interval_input.setEnabled(True)
        
        self.status_indicator.setText("● Disconnected")
        self.status_indicator.setStyleSheet("color: #ff4444; font-weight: bold;")
    
    def on_connected(self, connected: bool):
        """Handle connection status change"""
        if connected:
            self.status_indicator.setText("● Connected")
            self.status_indicator.setStyleSheet("color: #00ff88; font-weight: bold;")
            self.log_console("✓ Connected to ESP32 successfully")
        else:
            self.status_indicator.setText("● Disconnected")
            self.status_indicator.setStyleSheet("color: #ff4444; font-weight: bold;")
    
    def on_status_update(self, status: dict):
        """Handle status updates from detector"""
        stats = status.get("stats", {})
        
        self.stat_labels["deauth_frames"].setText(str(stats.get("total_deauth_frames", 0)))
        self.stat_labels["disassoc_frames"].setText(str(stats.get("total_disassoc_frames", 0)))
        self.stat_labels["attacks_detected"].setText(str(stats.get("total_attacks_detected", 0)))
        self.stat_labels["active_attacks"].setText(str(stats.get("active_sessions", 0)))
        self.stat_labels["alerts"].setText(str(stats.get("total_alerts", 0)))
        
        uptime = status.get("uptime_seconds")
        if uptime:
            mins, secs = divmod(int(uptime), 60)
            hours, mins = divmod(mins, 60)
            self.stat_labels["uptime"].setText(f"{hours:02d}:{mins:02d}:{secs:02d}")
        
        # Calculate frame rate
        total = stats.get("total_deauth_frames", 0) + stats.get("total_disassoc_frames", 0)
        if uptime and uptime > 0:
            rate = total / uptime
            self.stat_labels["frame_rate"].setText(f"{rate:.1f}/s")
    
    def on_event_received(self, event: dict):
        """Handle new deauth/disassoc event"""
        # Deduplicate by timestamp
        event_hash = f"{event.get('device_timestamp_us', 0)}_{event.get('source_mac', '')}"
        if event_hash in self.event_hashes:
            return
        self.event_hashes.add(event_hash)
        
        # Keep hash set bounded
        if len(self.event_hashes) > 5000:
            self.event_hashes = set(list(self.event_hashes)[-2500:])
        
        # Add to table
        row = self.events_table.rowCount()
        self.events_table.insertRow(row)
        
        timestamp = event.get("timestamp", "")
        if isinstance(timestamp, str) and "T" in timestamp:
            timestamp = timestamp.split("T")[1][:8]
        
        frame_type = event.get("frame_type", "Unknown")
        color = QColor("#ff6666") if frame_type == "Deauth" else QColor("#ffaa66")
        
        items = [
            timestamp,
            frame_type,
            event.get("source_mac", ""),
            event.get("bssid", ""),
            str(event.get("channel", "")),
            str(event.get("rssi", "")),
            f"subtype=0x{event.get('subtype', 0):02X}"
        ]
        
        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            if col == 1:  # Frame type column
                item.setForeground(color)
            self.events_table.setItem(row, col, item)
        
        # Auto-scroll to bottom
        self.events_table.scrollToBottom()
        
        # Update last event time
        self.stat_labels["last_event"].setText(timestamp)
        
        # Limit table rows
        while self.events_table.rowCount() > 500:
            self.events_table.removeRow(0)
    
    def on_alert_received(self, alert: dict):
        """Handle new alert"""
        # Add to alerts table
        row = self.alerts_table.rowCount()
        self.alerts_table.insertRow(row)
        
        timestamp = alert.get("timestamp", "")
        if isinstance(timestamp, str) and "T" in timestamp:
            timestamp = timestamp.split("T")[1][:8]
        
        severity = alert.get("severity", "low").upper()
        severity_colors = {
            "INFO": "#36a3eb",
            "LOW": "#44ff44",
            "MEDIUM": "#ffaa44",
            "HIGH": "#ff4444",
            "CRITICAL": "#ff00ff",
        }
        color = QColor(severity_colors.get(severity, "#ffffff"))
        
        indicators = alert.get("indicators", {})
        
        items = [
            timestamp,
            severity,
            alert.get("title", ""),
            indicators.get("attacker_mac", ""),
            indicators.get("target_bssid", ""),
        ]
        
        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            if col == 1:  # Severity column
                item.setForeground(color)
                item.setFont(QFont("Arial", 10, QFont.Weight.Bold))
            self.alerts_table.setItem(row, col, item)
        
        self.alerts_table.scrollToBottom()
        
        # Log to console
        self.log_console(f"🚨 ALERT [{severity}]: {alert.get('title', '')}")
        
        # Flash the stats
        self.stat_labels["alerts"].setStyleSheet("color: #ff4444; font-size: 18px; font-weight: bold;")
        QTimer.singleShot(500, lambda: self.stat_labels["alerts"].setStyleSheet(
            "color: #00ff88; font-size: 18px; font-weight: bold;"
        ))
    
    def on_error(self, error: str):
        """Handle errors from detector"""
        self.log_console(f"❌ ERROR: {error}")
        self.stop_monitoring()
    
    def log_console(self, message: str):
        """Log message to console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console_output.append(f"[{timestamp}] {message}")
    
    def update_ui(self):
        """Periodic UI updates"""
        pass  # Stats updated via signals
    
    def clear_events(self):
        """Clear events table"""
        self.events_table.setRowCount(0)
        self.event_hashes.clear()
        self.log_console("Events cleared")
    
    def export_events(self):
        """Export events to JSON file"""
        from PyQt6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Events", "deauth_events.json", "JSON Files (*.json)"
        )
        
        if filename:
            events = []
            for row in range(self.events_table.rowCount()):
                event = {
                    "time": self.events_table.item(row, 0).text() if self.events_table.item(row, 0) else "",
                    "type": self.events_table.item(row, 1).text() if self.events_table.item(row, 1) else "",
                    "source_mac": self.events_table.item(row, 2).text() if self.events_table.item(row, 2) else "",
                    "bssid": self.events_table.item(row, 3).text() if self.events_table.item(row, 3) else "",
                    "channel": self.events_table.item(row, 4).text() if self.events_table.item(row, 4) else "",
                    "rssi": self.events_table.item(row, 5).text() if self.events_table.item(row, 5) else "",
                }
                events.append(event)
            
            with open(filename, "w") as f:
                json.dump(events, f, indent=2)
            
            self.log_console(f"Exported {len(events)} events to {filename}")
    
    def closeEvent(self, event):
        """Handle page close"""
        self.stop_monitoring()
        super().closeEvent(event)


# For standalone testing
if __name__ == "__main__":
    import sys
    from PyQt6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Dark theme
    from PyQt6.QtGui import QPalette, QColor
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(26, 26, 46))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(221, 221, 221))
    palette.setColor(QPalette.ColorRole.Base, QColor(10, 10, 26))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(26, 26, 46))
    palette.setColor(QPalette.ColorRole.Text, QColor(221, 221, 221))
    palette.setColor(QPalette.ColorRole.Button, QColor(42, 42, 78))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(221, 221, 221))
    app.setPalette(palette)
    
    window = DeauthDetectorPage()
    window.setWindowTitle("ESP32 Deauth Detector - Wireless IDS")
    window.resize(1200, 800)
    window.show()
    
    sys.exit(app.exec())
