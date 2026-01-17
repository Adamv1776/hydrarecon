"""
Security Chaos Engineering Page
GUI for Netflix-style chaos engineering for security testing
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QGroupBox,
    QProgressBar, QSplitter, QFrame, QHeaderView, QTreeWidget,
    QTreeWidgetItem, QGridLayout, QComboBox, QTextEdit, QCheckBox,
    QCalendarWidget, QTimeEdit, QListWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer, QTime
from PyQt6.QtGui import QFont, QColor
import asyncio


class ExperimentWorker(QThread):
    """Worker thread for running chaos experiments"""
    progress = pyqtSignal(str, int)
    result = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, experiment_id):
        super().__init__()
        self.experiment_id = experiment_id
        
    def run(self):
        try:
            from core.security_chaos import SecurityChaos
            
            async def run_experiment():
                chaos = SecurityChaos()
                return await chaos.run_experiment(self.experiment_id, safe_mode=True)
                
            result = asyncio.run(run_experiment())
            self.result.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class SecurityChaosPage(QWidget):
    """Security Chaos Engineering Dashboard"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.experiment_worker = None
        
        self._setup_ui()
        self._connect_signals()
        self._load_demo_data()
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                border-radius: 8px;
                background: #0d1117;
            }
            QTabBar::tab {
                background: #21262d;
                color: #8b949e;
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #0d1117;
                color: #f97316;
            }
        """)
        
        # Create tabs
        self.tabs.addTab(self._create_experiments_tab(), "🧪 Experiments")
        self.tabs.addTab(self._create_gameday_tab(), "🎮 Game Days")
        self.tabs.addTab(self._create_results_tab(), "📊 Results")
        self.tabs.addTab(self._create_metrics_tab(), "📈 Metrics")
        self.tabs.addTab(self._create_controls_tab(), "🛡️ Controls")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QWidget:
        """Create the page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2f1a0d, stop:1 #0d1117);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🔥 Security Chaos Engineering")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            color: #e6e6e6;
        """)
        title_layout.addWidget(title)
        
        subtitle = QLabel("Netflix-Style Chaos Testing for Security Resilience")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.experiments_count = self._create_stat_card("Experiments", "18", "#f97316")
        self.detection_rate = self._create_stat_card("Detection Rate", "75%", "#00ff88")
        self.resilience_score = self._create_stat_card("Resilience", "68/100", "#58a6ff")
        
        stats_layout.addWidget(self.experiments_count)
        stats_layout.addWidget(self.detection_rate)
        stats_layout.addWidget(self.resilience_score)
        
        layout.addLayout(stats_layout)
        
        # Run controls
        control_layout = QVBoxLayout()
        
        self.exp_type = QComboBox()
        self.exp_type.addItems([
            "🔧 Control Failure",
            "🔑 Credential Leak",
            "👤 Insider Threat",
            "🌐 Network Attack",
            "📤 Data Exfiltration",
            "🦠 Malware Injection",
            "⚙️ Config Drift",
            "⬆️ Privilege Escalation",
            "🔀 Lateral Movement",
            "📡 C2 Communication"
        ])
        self.exp_type.setStyleSheet("""
            QComboBox {
                background: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                padding: 8px;
                border-radius: 6px;
                min-width: 180px;
            }
        """)
        control_layout.addWidget(self.exp_type)
        
        self.run_btn = QPushButton("🔥 Run Experiment")
        self.run_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #f97316, stop:1 #fb923c);
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #fb923c, stop:1 #f97316);
            }
        """)
        control_layout.addWidget(self.run_btn)
        
        layout.addLayout(control_layout)
        
        return header
    
    def _create_stat_card(self, label: str, value: str, color: str) -> QFrame:
        """Create a statistics card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #161b22;
                border: 1px solid {color}40;
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setSpacing(4)
        
        value_label = QLabel(value)
        value_label.setStyleSheet(f"color: {color}; font-size: 20px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value_label)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #8b949e; font-size: 11px;")
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_label)
        
        return card
        
    def _create_experiments_tab(self) -> QWidget:
        """Create experiments library tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Experiments table
        self.experiments_table = QTableWidget()
        self.experiments_table.setColumnCount(7)
        self.experiments_table.setHorizontalHeaderLabels([
            "ID", "Name", "Type", "Targets", "Duration", "Blast Radius", "Actions"
        ])
        self.experiments_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.experiments_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
                gridline-color: #30363d;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.experiments_table)
        
        return widget
        
    def _create_gameday_tab(self) -> QWidget:
        """Create game day scheduling tab"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Left side - scheduling
        schedule_group = QGroupBox("Schedule Game Day")
        schedule_group.setStyleSheet("""
            QGroupBox {
                color: #e6e6e6;
                font-weight: bold;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        schedule_layout = QVBoxLayout(schedule_group)
        
        # Calendar
        self.calendar = QCalendarWidget()
        self.calendar.setStyleSheet("""
            QCalendarWidget {
                background: #161b22;
                color: #e6e6e6;
            }
            QCalendarWidget QToolButton {
                color: #e6e6e6;
                background: #21262d;
                border-radius: 4px;
            }
        """)
        schedule_layout.addWidget(self.calendar)
        
        # Experiments to include
        exp_label = QLabel("Select Experiments:")
        exp_label.setStyleSheet("color: #8b949e;")
        schedule_layout.addWidget(exp_label)
        
        self.exp_list = QListWidget()
        self.exp_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #e6e6e6;
            }
        """)
        self.exp_list.addItems([
            "✓ EDR Blackout",
            "✓ AWS Keys on GitHub",
            "✓ Mass Data Download",
            "  Port Scan Storm",
            "  Fileless Malware"
        ])
        schedule_layout.addWidget(self.exp_list)
        
        self.schedule_btn = QPushButton("📅 Schedule Game Day")
        self.schedule_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background: #2ea043; }
        """)
        schedule_layout.addWidget(self.schedule_btn)
        
        layout.addWidget(schedule_group)
        
        # Right side - scheduled game days
        scheduled_group = QGroupBox("Scheduled Game Days")
        scheduled_group.setStyleSheet("""
            QGroupBox {
                color: #e6e6e6;
                font-weight: bold;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
            }
        """)
        scheduled_layout = QVBoxLayout(scheduled_group)
        
        self.gamedays_table = QTableWidget()
        self.gamedays_table.setColumnCount(5)
        self.gamedays_table.setHorizontalHeaderLabels([
            "Game Day", "Date", "Experiments", "Participants", "Status"
        ])
        self.gamedays_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.gamedays_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
                gridline-color: #30363d;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        scheduled_layout.addWidget(self.gamedays_table)
        
        layout.addWidget(scheduled_group)
        
        return widget
        
    def _create_results_tab(self) -> QWidget:
        """Create experiment results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(8)
        self.results_table.setHorizontalHeaderLabels([
            "Experiment", "Detection", "Response", "TTD", "TTR", "Resilience", "Alerts", "Status"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
                gridline-color: #30363d;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.results_table)
        
        return widget
        
    def _create_metrics_tab(self) -> QWidget:
        """Create resilience metrics tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Metrics grid
        metrics_group = QGroupBox("Security Resilience Metrics")
        metrics_group.setStyleSheet("""
            QGroupBox {
                color: #e6e6e6;
                font-weight: bold;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
            }
        """)
        metrics_layout = QGridLayout(metrics_group)
        
        metrics = [
            ("⏱️ Mean Time to Detect", "10.5 min", "Target: 5 min", "#ffa500"),
            ("🚀 Mean Time to Respond", "15.2 min", "Target: 10 min", "#ffa500"),
            ("🛡️ Mean Time to Contain", "45.0 min", "Target: 30 min", "#ff6b6b"),
            ("🎯 Detection Rate", "75%", "Target: 95%", "#ffa500"),
            ("❌ False Positive Rate", "15%", "Target: 5%", "#ff6b6b"),
            ("🤖 Automation Rate", "40%", "Target: 80%", "#ffa500"),
            ("📊 Control Coverage", "85%", "Target: 100%", "#00ff88"),
            ("💪 Resilience Index", "68/100", "Target: 90/100", "#ffa500"),
        ]
        
        for i, (name, value, target, color) in enumerate(metrics):
            row, col = divmod(i, 2)
            metric_card = self._create_metric_card(name, value, target, color)
            metrics_layout.addWidget(metric_card, row, col)
            
        layout.addWidget(metrics_group)
        
        return widget
        
    def _create_metric_card(self, name: str, value: str, target: str, color: str) -> QFrame:
        """Create metric display card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #161b22;
                border: 1px solid {color}40;
                border-radius: 8px;
                padding: 16px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        name_label = QLabel(name)
        name_label.setStyleSheet("color: #8b949e; font-size: 13px;")
        layout.addWidget(name_label)
        
        value_label = QLabel(value)
        value_label.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")
        layout.addWidget(value_label)
        
        target_label = QLabel(target)
        target_label.setStyleSheet("color: #6e7681; font-size: 11px;")
        layout.addWidget(target_label)
        
        return card
        
    def _create_controls_tab(self) -> QWidget:
        """Create security controls tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Controls table
        self.controls_table = QTableWidget()
        self.controls_table.setColumnCount(6)
        self.controls_table.setHorizontalHeaderLabels([
            "Control", "Type", "Systems", "Effectiveness", "Last Tested", "Failure Modes"
        ])
        self.controls_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.controls_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
                gridline-color: #30363d;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.controls_table)
        
        return widget
        
    def _connect_signals(self):
        """Connect signals and slots"""
        self.run_btn.clicked.connect(self._run_experiment)
        self.schedule_btn.clicked.connect(self._schedule_gameday)
        
    def _run_experiment(self):
        """Run chaos experiment"""
        self.run_btn.setEnabled(False)
        self.run_btn.setText("🔄 Running...")
        
        QTimer.singleShot(2500, self._experiment_complete)
        
    def _experiment_complete(self):
        """Handle experiment completion"""
        self.run_btn.setEnabled(True)
        self.run_btn.setText("🔥 Run Experiment")
        self._add_result()
        
    def _add_result(self):
        """Add experiment result"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        exp_type = self.exp_type.currentText()
        
        # Random result
        import random
        detection = random.choice(["✅ Detected", "⚠️ Partial", "❌ Undetected"])
        response = random.choice(["✅ Contained", "⚠️ Partial", "❌ Failed"])
        ttd = f"{random.uniform(1, 15):.1f} min"
        ttr = f"{random.uniform(5, 30):.1f} min"
        resilience = f"{random.randint(40, 95)}/100"
        alerts = str(random.randint(1, 5))
        
        data = [exp_type, detection, response, ttd, ttr, resilience, alerts, "✅ Complete"]
        
        for col, value in enumerate(data):
            item = QTableWidgetItem(value)
            self.results_table.setItem(row, col, item)
            
    def _schedule_gameday(self):
        """Schedule a game day"""
        row = self.gamedays_table.rowCount()
        self.gamedays_table.insertRow(row)
        
        date = self.calendar.selectedDate().toString("MMM d, yyyy")
        data = [f"Game Day #{row+1}", date, "3 experiments", "Security Team", "📅 Scheduled"]
        
        for col, value in enumerate(data):
            item = QTableWidgetItem(value)
            self.gamedays_table.setItem(row, col, item)
        
    def _load_demo_data(self):
        """Load demonstration data"""
        # Experiments
        experiments = [
            ("CHAOS-001", "EDR Blackout", "Control Failure", "Servers", "5 min", "Medium", "▶️"),
            ("CHAOS-002", "SIEM Lag Spike", "Control Failure", "SIEM", "30 min", "Large", "▶️"),
            ("CHAOS-003", "AWS Keys on GitHub", "Credential Leak", "GitHub", "10 min", "Medium", "▶️"),
            ("CHAOS-004", "Database Creds in Logs", "Credential Leak", "App Logs", "5 min", "Small", "▶️"),
            ("CHAOS-005", "Mass Data Download", "Insider Threat", "File Server", "15 min", "Medium", "▶️"),
            ("CHAOS-006", "Port Scan Storm", "Network Attack", "Firewall", "5 min", "Small", "▶️"),
            ("CHAOS-007", "DNS Tunneling", "Data Exfil", "DNS Server", "10 min", "Medium", "▶️"),
            ("CHAOS-008", "Fileless Malware", "Malware", "Endpoints", "5 min", "Small", "▶️"),
        ]
        
        self.experiments_table.setRowCount(len(experiments))
        for row, exp in enumerate(experiments):
            for col, value in enumerate(exp):
                item = QTableWidgetItem(value)
                self.experiments_table.setItem(row, col, item)
                
        # Game days
        gamedays = [
            ("Q1 Resilience Test", "Jan 20, 2025", "5 experiments", "SOC Team", "✅ Completed"),
            ("IR Drill", "Feb 15, 2025", "3 experiments", "IR Team", "📅 Scheduled"),
        ]
        
        self.gamedays_table.setRowCount(len(gamedays))
        for row, gd in enumerate(gamedays):
            for col, value in enumerate(gd):
                item = QTableWidgetItem(value)
                self.gamedays_table.setItem(row, col, item)
                
        # Results
        results = [
            ("EDR Blackout", "✅ Detected", "✅ Contained", "2.3 min", "5.1 min", "85/100", "2", "✅ Complete"),
            ("Credential Leak", "✅ Detected", "🤖 Auto-fixed", "1.5 min", "2.0 min", "92/100", "3", "✅ Complete"),
            ("Insider Threat", "⚠️ Partial", "⚠️ Partial", "25.0 min", "45.0 min", "55/100", "1", "✅ Complete"),
            ("Network Attack", "✅ Blocked", "🤖 Auto-fixed", "0.5 min", "1.0 min", "98/100", "4", "✅ Complete"),
        ]
        
        self.results_table.setRowCount(len(results))
        for row, res in enumerate(results):
            for col, value in enumerate(res):
                item = QTableWidgetItem(value)
                if col == 1:  # Detection
                    if "Detected" in value or "Blocked" in value:
                        item.setForeground(QColor("#00ff88"))
                    elif "Partial" in value:
                        item.setForeground(QColor("#ffa500"))
                    else:
                        item.setForeground(QColor("#ff6b6b"))
                self.results_table.setItem(row, col, item)
                
        # Controls
        controls = [
            ("EDR Platform", "Detective", "Endpoints", "85%", "Today", "Signature bypass, Memory-only"),
            ("SIEM Platform", "Detective", "All", "75%", "Today", "Log flooding, Alert fatigue"),
            ("Next-Gen Firewall", "Preventive", "Network", "90%", "Yesterday", "Encryption bypass"),
            ("DLP Solution", "Preventive", "Endpoints", "70%", "2 days ago", "Encryption, Chunking"),
            ("MFA System", "Preventive", "Identity", "95%", "Today", "MFA fatigue, Phishing"),
            ("SOAR Platform", "Responsive", "All", "80%", "3 days ago", "Playbook gaps"),
        ]
        
        self.controls_table.setRowCount(len(controls))
        for row, ctrl in enumerate(controls):
            for col, value in enumerate(ctrl):
                item = QTableWidgetItem(value)
                self.controls_table.setItem(row, col, item)
