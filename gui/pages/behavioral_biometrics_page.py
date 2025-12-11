"""
Behavioral Biometrics GUI Page
User behavior profiling, keystroke dynamics, and continuous authentication.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTextEdit, QLineEdit, QComboBox, QProgressBar, QTabWidget,
    QGroupBox, QSpinBox, QCheckBox, QSplitter, QGridLayout,
    QListWidget, QSlider
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from datetime import datetime
import random


class BiometricMonitorWorker(QThread):
    """Worker for biometric monitoring"""
    keystroke_data = pyqtSignal(dict)
    mouse_data = pyqtSignal(dict)
    anomaly = pyqtSignal(dict)
    finished = pyqtSignal()
    
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.running = True
    
    def run(self):
        try:
            while self.running:
                self.keystroke_data.emit({
                    "wpm": random.randint(40, 80),
                    "dwell": random.uniform(80, 150),
                    "flight": random.uniform(100, 200)
                })
                self.mouse_data.emit({
                    "speed": random.uniform(200, 500),
                    "clicks": random.randint(0, 5)
                })
                self.msleep(1000)
        except Exception:
            pass
        finally:
            self.finished.emit()
    
    def stop(self):
        self.running = False


class BehavioralBiometricsPage(QWidget):
    """Behavioral Biometrics GUI"""
    
    def __init__(self, config, db):
        super().__init__()
        self.config = config
        self.db = db
        self.engine = None
        self.worker = None
        
        self._init_engine()
        self._setup_ui()
        self._apply_styles()
        self._start_demo_updates()
    
    def _init_engine(self):
        """Initialize biometrics engine"""
        try:
            from core.behavioral_biometrics import BehavioralBiometricsEngine
            self.engine = BehavioralBiometricsEngine()
        except ImportError:
            self.engine = None
    
    def _setup_ui(self):
        """Setup user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main tabs
        tabs = QTabWidget()
        tabs.setObjectName("biometricTabs")
        
        tabs.addTab(self._create_dashboard_tab(), "📊 Dashboard")
        tabs.addTab(self._create_keystroke_tab(), "⌨️ Keystroke Dynamics")
        tabs.addTab(self._create_mouse_tab(), "🖱️ Mouse Behavior")
        tabs.addTab(self._create_profiles_tab(), "👤 User Profiles")
        tabs.addTab(self._create_anomalies_tab(), "⚠️ Anomaly Detection")
        
        layout.addWidget(tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setObjectName("headerFrame")
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🧬 Behavioral Biometrics")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #9b59b6;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Continuous authentication through keystroke dynamics and behavioral patterns")
        subtitle.setStyleSheet("color: #888; font-size: 12px;")
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Real-time indicators
        indicators = QHBoxLayout()
        
        self.auth_score = QLabel("Auth Score: 94%")
        self.auth_score.setStyleSheet("color: #00ff88; font-weight: bold;")
        indicators.addWidget(self.auth_score)
        
        self.threat_level = QLabel("● Normal")
        self.threat_level.setStyleSheet("color: #00ff88;")
        indicators.addWidget(self.threat_level)
        
        layout.addLayout(indicators)
        
        # Action button
        self.monitor_btn = QPushButton("🔴 Start Monitoring")
        self.monitor_btn.setObjectName("primaryButton")
        self.monitor_btn.setCheckable(True)
        self.monitor_btn.clicked.connect(self._toggle_monitoring)
        layout.addWidget(self.monitor_btn)
        
        return frame
    
    def _create_dashboard_tab(self) -> QWidget:
        """Create dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Stats grid
        stats_layout = QGridLayout()
        
        stats = [
            ("👥", "Active Profiles", "12", "#3498db"),
            ("⌨️", "Typing Speed", "65 WPM", "#2ecc71"),
            ("🖱️", "Mouse Patterns", "Normal", "#9b59b6"),
            ("⚠️", "Anomalies Today", "3", "#e74c3c"),
        ]
        
        for i, (icon, label, value, color) in enumerate(stats):
            card = self._create_stat_card(icon, label, value, color)
            stats_layout.addWidget(card, 0, i)
        
        layout.addLayout(stats_layout)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Real-time metrics
        metrics_panel = QFrame()
        metrics_panel.setObjectName("metricsPanel")
        metrics_layout = QVBoxLayout(metrics_panel)
        
        metrics_layout.addWidget(QLabel("Real-time Metrics"))
        
        # Keystroke metrics
        ks_group = QGroupBox("Keystroke Dynamics")
        ks_layout = QGridLayout(ks_group)
        
        ks_layout.addWidget(QLabel("Typing Speed:"), 0, 0)
        self.wpm_label = QLabel("65 WPM")
        self.wpm_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        ks_layout.addWidget(self.wpm_label, 0, 1)
        
        ks_layout.addWidget(QLabel("Key Dwell Time:"), 1, 0)
        self.dwell_label = QLabel("112 ms")
        ks_layout.addWidget(self.dwell_label, 1, 1)
        
        ks_layout.addWidget(QLabel("Flight Time:"), 2, 0)
        self.flight_label = QLabel("145 ms")
        ks_layout.addWidget(self.flight_label, 2, 1)
        
        ks_layout.addWidget(QLabel("Consistency:"), 3, 0)
        self.consistency_bar = QProgressBar()
        self.consistency_bar.setValue(87)
        ks_layout.addWidget(self.consistency_bar, 3, 1)
        
        metrics_layout.addWidget(ks_group)
        
        # Mouse metrics
        mouse_group = QGroupBox("Mouse Dynamics")
        mouse_layout = QGridLayout(mouse_group)
        
        mouse_layout.addWidget(QLabel("Movement Speed:"), 0, 0)
        self.speed_label = QLabel("324 px/s")
        mouse_layout.addWidget(self.speed_label, 0, 1)
        
        mouse_layout.addWidget(QLabel("Click Interval:"), 1, 0)
        self.click_label = QLabel("890 ms")
        mouse_layout.addWidget(self.click_label, 1, 1)
        
        mouse_layout.addWidget(QLabel("Path Deviation:"), 2, 0)
        self.deviation_label = QLabel("12.3%")
        mouse_layout.addWidget(self.deviation_label, 2, 1)
        
        metrics_layout.addWidget(mouse_group)
        
        splitter.addWidget(metrics_panel)
        
        # Right - Activity log
        log_panel = QFrame()
        log_panel.setObjectName("logPanel")
        log_layout = QVBoxLayout(log_panel)
        
        log_layout.addWidget(QLabel("Authentication Events"))
        
        self.auth_log = QListWidget()
        events = [
            "✅ [14:32:18] User authenticated - Score: 96%",
            "✅ [14:28:45] Session verified - Score: 94%",
            "⚠️ [14:15:22] Slight deviation detected - Score: 78%",
            "✅ [14:10:08] Keystroke pattern matched",
            "⚠️ [13:55:33] Mouse behavior anomaly - Score: 65%",
            "🚨 [13:42:11] Authentication failed - Score: 34%",
        ]
        for event in events:
            self.auth_log.addItem(event)
        log_layout.addWidget(self.auth_log)
        
        splitter.addWidget(log_panel)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_keystroke_tab(self) -> QWidget:
        """Create keystroke dynamics tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Configuration
        config_panel = QFrame()
        config_panel.setObjectName("configPanel")
        config_layout = QVBoxLayout(config_panel)
        
        # Training
        train_group = QGroupBox("Profile Training")
        train_layout = QVBoxLayout(train_group)
        
        train_layout.addWidget(QLabel("Enter text to train typing pattern:"))
        self.train_input = QTextEdit()
        self.train_input.setPlaceholderText("Type here to capture your keystroke dynamics...")
        self.train_input.setMaximumHeight(100)
        train_layout.addWidget(self.train_input)
        
        train_btn = QPushButton("📝 Capture Pattern")
        train_btn.clicked.connect(self._capture_pattern)
        train_layout.addWidget(train_btn)
        
        config_layout.addWidget(train_group)
        
        # Settings
        settings_group = QGroupBox("Detection Settings")
        settings_layout = QGridLayout(settings_group)
        
        settings_layout.addWidget(QLabel("Sensitivity:"), 0, 0)
        self.sensitivity = QSlider(Qt.Orientation.Horizontal)
        self.sensitivity.setRange(1, 100)
        self.sensitivity.setValue(70)
        settings_layout.addWidget(self.sensitivity, 0, 1)
        
        settings_layout.addWidget(QLabel("Min Samples:"), 1, 0)
        self.min_samples = QSpinBox()
        self.min_samples.setRange(10, 1000)
        self.min_samples.setValue(100)
        settings_layout.addWidget(self.min_samples, 1, 1)
        
        self.continuous = QCheckBox("Continuous Authentication")
        self.continuous.setChecked(True)
        settings_layout.addWidget(self.continuous, 2, 0, 1, 2)
        
        config_layout.addWidget(settings_group)
        
        config_layout.addStretch()
        splitter.addWidget(config_panel)
        
        # Right - Analysis
        analysis_panel = QFrame()
        analysis_panel.setObjectName("analysisPanel")
        analysis_layout = QVBoxLayout(analysis_panel)
        
        analysis_layout.addWidget(QLabel("Keystroke Analysis"))
        
        self.keystroke_table = QTableWidget()
        self.keystroke_table.setColumnCount(5)
        self.keystroke_table.setHorizontalHeaderLabels([
            "Key", "Dwell Time", "Flight Time", "Expected", "Deviation"
        ])
        self.keystroke_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        keystrokes = [
            ("A", "95 ms", "142 ms", "112 ms / 145 ms", "±15%"),
            ("S", "102 ms", "138 ms", "115 ms / 140 ms", "±10%"),
            ("D", "88 ms", "155 ms", "108 ms / 148 ms", "±18%"),
            ("F", "115 ms", "132 ms", "110 ms / 135 ms", "±8%"),
        ]
        
        self.keystroke_table.setRowCount(len(keystrokes))
        for row, ks in enumerate(keystrokes):
            for col, value in enumerate(ks):
                self.keystroke_table.setItem(row, col, QTableWidgetItem(value))
        
        analysis_layout.addWidget(self.keystroke_table)
        
        splitter.addWidget(analysis_panel)
        splitter.setSizes([350, 650])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_mouse_tab(self) -> QWidget:
        """Create mouse behavior tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Metrics
        metrics_panel = QFrame()
        metrics_panel.setObjectName("metricsPanel")
        metrics_layout = QVBoxLayout(metrics_panel)
        
        metrics_layout.addWidget(QLabel("Mouse Behavior Metrics"))
        
        metrics = [
            ("Movement Speed", "324 px/s", "Normal"),
            ("Click Frequency", "12 clicks/min", "Normal"),
            ("Double-Click Speed", "245 ms", "Normal"),
            ("Scroll Pattern", "Consistent", "Normal"),
            ("Path Curvature", "0.85", "Normal"),
            ("Idle Time Pattern", "Variable", "⚠️ Slightly unusual"),
        ]
        
        for name, value, status in metrics:
            row = QHBoxLayout()
            row.addWidget(QLabel(name + ":"))
            row.addStretch()
            value_label = QLabel(value)
            if "⚠️" in status:
                value_label.setStyleSheet("color: #ff8800;")
            else:
                value_label.setStyleSheet("color: #00ff88;")
            row.addWidget(value_label)
            status_label = QLabel(status)
            if "⚠️" in status:
                status_label.setStyleSheet("color: #ff8800;")
            row.addWidget(status_label)
            metrics_layout.addLayout(row)
        
        metrics_layout.addStretch()
        splitter.addWidget(metrics_panel)
        
        # Right - Heat map placeholder
        heatmap_panel = QFrame()
        heatmap_panel.setObjectName("heatmapPanel")
        heatmap_layout = QVBoxLayout(heatmap_panel)
        
        heatmap_layout.addWidget(QLabel("Mouse Movement Heatmap"))
        
        heatmap_text = QTextEdit()
        heatmap_text.setReadOnly(True)
        heatmap_text.setHtml("""
<div style="text-align: center; padding: 50px;">
<h2>🖱️ Mouse Movement Analysis</h2>
<p style="color: #888;">Visualizes mouse movement patterns and click hotspots</p>
<br/>
<p>Movement Zones:</p>
<table style="margin: auto;">
<tr><td style="background: #ff4444; padding: 20px;">High Activity</td>
<td style="background: #ff8800; padding: 20px;">Medium</td>
<td style="background: #00ff88; padding: 20px;">Low</td></tr>
</table>
<br/>
<p>Pattern Analysis: <span style="color: #00ff88;">✅ Consistent with profile</span></p>
</div>
""")
        heatmap_layout.addWidget(heatmap_text)
        
        splitter.addWidget(heatmap_panel)
        splitter.setSizes([350, 650])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_profiles_tab(self) -> QWidget:
        """Create user profiles tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.profile_search = QLineEdit()
        self.profile_search.setPlaceholderText("🔍 Search profiles...")
        toolbar.addWidget(self.profile_search)
        
        add_btn = QPushButton("➕ New Profile")
        toolbar.addWidget(add_btn)
        
        import_btn = QPushButton("📥 Import")
        toolbar.addWidget(import_btn)
        
        export_btn = QPushButton("📤 Export")
        toolbar.addWidget(export_btn)
        
        layout.addLayout(toolbar)
        
        # Profiles table
        self.profiles_table = QTableWidget()
        self.profiles_table.setColumnCount(7)
        self.profiles_table.setHorizontalHeaderLabels([
            "User", "Samples", "Accuracy", "Last Updated", "Status", "Sessions", "Actions"
        ])
        self.profiles_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        profiles = [
            ("admin", "1,247", "98.5%", "2024-02-15", "Active", "156", ""),
            ("user1", "856", "94.2%", "2024-02-14", "Active", "89", ""),
            ("user2", "432", "87.1%", "2024-02-13", "Training", "45", ""),
            ("guest", "124", "72.3%", "2024-02-10", "Inactive", "12", ""),
        ]
        
        self.profiles_table.setRowCount(len(profiles))
        for row, profile in enumerate(profiles):
            for col, value in enumerate(profile[:-1]):
                item = QTableWidgetItem(value)
                if col == 4:  # Status
                    if value == "Active":
                        item.setForeground(QColor("#00ff88"))
                    elif value == "Training":
                        item.setForeground(QColor("#ff8800"))
                    else:
                        item.setForeground(QColor("#888"))
                self.profiles_table.setItem(row, col, item)
        
        layout.addWidget(self.profiles_table)
        
        return widget
    
    def _create_anomalies_tab(self) -> QWidget:
        """Create anomaly detection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Anomaly stats
        stats = QHBoxLayout()
        
        for label, value, color in [
            ("Total Anomalies", "23", "#e74c3c"),
            ("High Severity", "5", "#ff4444"),
            ("Medium Severity", "12", "#ff8800"),
            ("Low Severity", "6", "#ffaa00"),
        ]:
            card = self._create_stat_card("⚠️", label, value, color)
            stats.addWidget(card)
        
        layout.addLayout(stats)
        
        # Anomalies table
        self.anomalies_table = QTableWidget()
        self.anomalies_table.setColumnCount(7)
        self.anomalies_table.setHorizontalHeaderLabels([
            "Time", "User", "Type", "Description", "Severity", "Score", "Action"
        ])
        self.anomalies_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        anomalies = [
            ("14:32:18", "user1", "Keystroke", "Typing speed 40% faster than normal", "High", "34%", "Review"),
            ("14:15:22", "admin", "Mouse", "Unusual movement pattern", "Medium", "65%", "Dismissed"),
            ("13:55:33", "user2", "Combined", "Multiple behavioral deviations", "High", "45%", "Review"),
            ("13:42:11", "guest", "Keystroke", "Dwell time significantly different", "Critical", "28%", "Blocked"),
        ]
        
        self.anomalies_table.setRowCount(len(anomalies))
        for row, anomaly in enumerate(anomalies):
            for col, value in enumerate(anomaly):
                item = QTableWidgetItem(value)
                if col == 4:  # Severity
                    if value == "Critical":
                        item.setForeground(QColor("#ff4444"))
                    elif value == "High":
                        item.setForeground(QColor("#ff8800"))
                    elif value == "Medium":
                        item.setForeground(QColor("#ffaa00"))
                self.anomalies_table.setItem(row, col, item)
        
        layout.addWidget(self.anomalies_table)
        
        return widget
    
    def _create_stat_card(self, icon, label, value, color) -> QFrame:
        """Create a stat card widget"""
        card = QFrame()
        card.setObjectName("statCard")
        card.setStyleSheet(f"""
            QFrame#statCard {{
                background-color: #16213e;
                border-left: 4px solid {color};
                border-radius: 8px;
                padding: 15px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        header = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI", 20))
        header.addWidget(icon_label)
        header.addStretch()
        layout.addLayout(header)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        layout.addWidget(value_label)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #888;")
        layout.addWidget(name_label)
        
        return card
    
    def _apply_styles(self):
        """Apply custom styles"""
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a2e;
                color: #ffffff;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            QFrame#headerFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2d1f3d, stop:1 #1a1a2e);
                border-radius: 10px;
                padding: 15px;
            }
            
            QFrame#configPanel, QFrame#analysisPanel,
            QFrame#metricsPanel, QFrame#logPanel, QFrame#heatmapPanel {
                background-color: #16213e;
                border-radius: 8px;
                padding: 10px;
            }
            
            QGroupBox {
                font-weight: bold;
                border: 1px solid #0f3460;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            
            QPushButton {
                background-color: #0f3460;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                color: white;
                font-weight: bold;
            }
            
            QPushButton:hover {
                background-color: #1a4a7a;
            }
            
            QPushButton#primaryButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #9b59b6, stop:1 #8e44ad);
                color: #fff;
            }
            
            QTableWidget {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QHeaderView::section {
                background-color: #16213e;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #9b59b6;
                font-weight: bold;
            }
            
            QLineEdit, QComboBox, QSpinBox, QTextEdit {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
            
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #9b59b6, stop:1 #00ff88);
                border-radius: 4px;
            }
            
            QTabBar::tab:selected {
                background-color: #0f3460;
                border-bottom: 2px solid #9b59b6;
            }
            
            QListWidget {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
        """)
    
    def _start_demo_updates(self):
        """Start demo UI updates"""
        self.demo_timer = QTimer()
        self.demo_timer.timeout.connect(self._update_demo)
        self.demo_timer.start(2000)
    
    def _update_demo(self):
        """Update demo values"""
        self.wpm_label.setText(f"{random.randint(55, 75)} WPM")
        self.dwell_label.setText(f"{random.randint(90, 130)} ms")
        self.flight_label.setText(f"{random.randint(120, 170)} ms")
        self.consistency_bar.setValue(random.randint(80, 95))
        self.speed_label.setText(f"{random.randint(280, 380)} px/s")
        
        score = random.randint(88, 98)
        self.auth_score.setText(f"Auth Score: {score}%")
        if score >= 90:
            self.auth_score.setStyleSheet("color: #00ff88; font-weight: bold;")
        else:
            self.auth_score.setStyleSheet("color: #ff8800; font-weight: bold;")
    
    def _toggle_monitoring(self, checked):
        """Toggle monitoring"""
        if checked:
            self.monitor_btn.setText("🔴 Stop Monitoring")
            self.monitor_btn.setStyleSheet("""
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #e74c3c, stop:1 #c0392b);
            """)
        else:
            self.monitor_btn.setText("🟢 Start Monitoring")
            self.monitor_btn.setStyleSheet("")
    
    def _capture_pattern(self):
        """Capture keystroke pattern"""
        text = self.train_input.toPlainText()
        if len(text) < 20:
            return
        self.train_input.clear()
