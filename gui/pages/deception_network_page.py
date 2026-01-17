"""
Deception Network Fabric GUI Page
AI-powered honeypot orchestration and attacker tracking dashboard.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTextEdit, QLineEdit, QComboBox, QProgressBar, QTabWidget,
    QGroupBox, QSpinBox, QCheckBox, QSplitter, QGridLayout,
    QListWidget, QScrollArea, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from datetime import datetime
import asyncio


class DeployDecoyWorker(QThread):
    """Worker for decoy deployment"""
    progress = pyqtSignal(int)
    decoy_deployed = pyqtSignal(dict)
    finished = pyqtSignal()
    
    def __init__(self, fabric, decoy_type, name, interaction_level):
        super().__init__()
        self.fabric = fabric
        self.decoy_type = decoy_type
        self.name = name
        self.interaction_level = interaction_level
    
    def run(self):
        try:
            for i in range(100):
                self.progress.emit(i + 1)
                self.msleep(30)
            
            self.decoy_deployed.emit({
                "id": f"decoy-{datetime.now().strftime('%H%M%S')}",
                "type": self.decoy_type,
                "name": self.name,
                "ip": f"10.200.0.{10 + hash(self.name) % 240}",
                "status": "active"
            })
        except Exception as e:
            pass
        finally:
            self.finished.emit()


class DeceptionNetworkPage(QWidget):
    """Deception Network Fabric dashboard page."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.fabric = None
        self.decoys = []
        self.sessions = []
        self.alerts = []
        self.setup_ui()
        self.start_monitoring()
    
    def setup_ui(self):
        """Setup the page UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        tabs = QTabWidget()
        tabs.addTab(self.create_network_tab(), "🕸️ Network Map")
        tabs.addTab(self.create_decoys_tab(), "🍯 Decoys")
        tabs.addTab(self.create_sessions_tab(), "👤 Attacker Sessions")
        tabs.addTab(self.create_alerts_tab(), "🚨 Alerts")
        tabs.addTab(self.create_campaigns_tab(), "📋 Campaigns")
        tabs.addTab(self.create_analytics_tab(), "📊 Analytics")
        
        layout.addWidget(tabs)
    
    def create_header(self) -> QFrame:
        """Create header section."""
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.StyledPanel)
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:0.5 #16213e, stop:1 #0f3460);
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🕸️ Deception Network Fabric")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88;")
        
        subtitle = QLabel("AI-Powered Honeypot Orchestration & Attacker Analysis")
        subtitle.setStyleSheet("color: #888;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Stats
        stats_layout = QHBoxLayout()
        
        self.decoys_count = self.create_stat_card("Active Decoys", "0", "#00ff88")
        self.sessions_count = self.create_stat_card("Sessions", "0", "#ff6b6b")
        self.alerts_count = self.create_stat_card("Alerts (24h)", "0", "#ffd93d")
        self.techniques_count = self.create_stat_card("Techniques", "0", "#6c5ce7")
        
        stats_layout.addWidget(self.decoys_count)
        stats_layout.addWidget(self.sessions_count)
        stats_layout.addWidget(self.alerts_count)
        stats_layout.addWidget(self.techniques_count)
        
        layout.addLayout(stats_layout)
        
        return frame
    
    def create_stat_card(self, label: str, value: str, color: str) -> QFrame:
        """Create a statistics card."""
        card = QFrame()
        card.setFixedSize(120, 70)
        card.setStyleSheet(f"""
            QFrame {{
                background: rgba(0,0,0,0.3);
                border: 1px solid {color};
                border-radius: 8px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setObjectName("value")
        
        text_label = QLabel(label)
        text_label.setStyleSheet("color: #888; font-size: 10px;")
        text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(value_label)
        layout.addWidget(text_label)
        
        return card
    
    def create_network_tab(self) -> QWidget:
        """Create network map tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Controls
        controls = QHBoxLayout()
        
        deploy_btn = QPushButton("🚀 Deploy Decoy")
        deploy_btn.clicked.connect(self.deploy_decoy)
        deploy_btn.setStyleSheet("background: #00ff88; color: black; padding: 10px;")
        
        campaign_btn = QPushButton("📋 New Campaign")
        campaign_btn.clicked.connect(self.new_campaign)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_network)
        
        controls.addWidget(deploy_btn)
        controls.addWidget(campaign_btn)
        controls.addWidget(refresh_btn)
        controls.addStretch()
        
        layout.addLayout(controls)
        
        # Network visualization (simplified)
        network_frame = QFrame()
        network_frame.setMinimumHeight(400)
        network_frame.setStyleSheet("""
            QFrame {
                background: #0a0a1a;
                border: 1px solid #333;
                border-radius: 8px;
            }
        """)
        
        network_layout = QGridLayout(network_frame)
        
        # Placeholder network nodes
        self.network_nodes = {}
        positions = [(0, 0), (0, 2), (1, 1), (2, 0), (2, 2)]
        labels = ["Gateway", "Web Server", "Database", "File Server", "Domain Controller"]
        
        for pos, label in zip(positions, labels):
            node = self.create_network_node(label, "#00ff88" if "Gateway" in label else "#4a4a6a")
            network_layout.addWidget(node, pos[0], pos[1])
            self.network_nodes[label] = node
        
        layout.addWidget(network_frame)
        
        return widget
    
    def create_network_node(self, label: str, color: str) -> QFrame:
        """Create a network node widget."""
        frame = QFrame()
        frame.setFixedSize(150, 80)
        frame.setStyleSheet(f"""
            QFrame {{
                background: {color};
                border-radius: 10px;
                border: 2px solid #fff;
            }}
        """)
        
        layout = QVBoxLayout(frame)
        
        name = QLabel(label)
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name.setStyleSheet("color: white; font-weight: bold;")
        
        status = QLabel("● Active")
        status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status.setStyleSheet("color: #aaffaa; font-size: 10px;")
        
        layout.addWidget(name)
        layout.addWidget(status)
        
        return frame
    
    def create_decoys_tab(self) -> QWidget:
        """Create decoys management tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Deployment form
        form_group = QGroupBox("Deploy New Decoy")
        form_layout = QGridLayout(form_group)
        
        form_layout.addWidget(QLabel("Type:"), 0, 0)
        self.decoy_type_combo = QComboBox()
        self.decoy_type_combo.addItems([
            "Web Server", "Database", "File Server", "SSH Server",
            "RDP Server", "Email Server", "Domain Controller",
            "IoT Device", "Cloud Instance", "API Endpoint"
        ])
        form_layout.addWidget(self.decoy_type_combo, 0, 1)
        
        form_layout.addWidget(QLabel("Name:"), 0, 2)
        self.decoy_name_input = QLineEdit()
        self.decoy_name_input.setPlaceholderText("e.g., www-prod-01")
        form_layout.addWidget(self.decoy_name_input, 0, 3)
        
        form_layout.addWidget(QLabel("Interaction:"), 1, 0)
        self.interaction_combo = QComboBox()
        self.interaction_combo.addItems(["Low", "Medium", "High", "Research"])
        self.interaction_combo.setCurrentIndex(1)
        form_layout.addWidget(self.interaction_combo, 1, 1)
        
        self.seed_creds_check = QCheckBox("Seed Credentials")
        self.seed_creds_check.setChecked(True)
        form_layout.addWidget(self.seed_creds_check, 1, 2)
        
        self.seed_data_check = QCheckBox("Seed Data")
        self.seed_data_check.setChecked(True)
        form_layout.addWidget(self.seed_data_check, 1, 3)
        
        deploy_btn = QPushButton("🚀 Deploy Decoy")
        deploy_btn.clicked.connect(self.deploy_decoy)
        deploy_btn.setStyleSheet("background: #00ff88; color: black;")
        form_layout.addWidget(deploy_btn, 2, 0, 1, 4)
        
        self.deploy_progress = QProgressBar()
        self.deploy_progress.setVisible(False)
        form_layout.addWidget(self.deploy_progress, 3, 0, 1, 4)
        
        layout.addWidget(form_group)
        
        # Decoys table
        self.decoys_table = QTableWidget()
        self.decoys_table.setColumnCount(8)
        self.decoys_table.setHorizontalHeaderLabels([
            "ID", "Type", "Name", "IP", "Services", "Interactions", "Last Activity", "Status"
        ])
        self.decoys_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.decoys_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.decoys_table)
        
        return widget
    
    def create_sessions_tab(self) -> QWidget:
        """Create attacker sessions tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Splitter for sessions list and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Sessions list
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        left_layout.addWidget(QLabel("Active Sessions"))
        
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(6)
        self.sessions_table.setHorizontalHeaderLabels([
            "Session", "Source IP", "Target", "Duration", "Threat Score", "Profile"
        ])
        self.sessions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.sessions_table.cellClicked.connect(self.show_session_details)
        
        left_layout.addWidget(self.sessions_table)
        splitter.addWidget(left_widget)
        
        # Session details
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        right_layout.addWidget(QLabel("Session Details"))
        
        self.session_details = QTextEdit()
        self.session_details.setReadOnly(True)
        self.session_details.setStyleSheet("background: #1a1a2e; font-family: monospace;")
        
        right_layout.addWidget(self.session_details)
        
        # MITRE techniques
        techniques_group = QGroupBox("MITRE ATT&CK Techniques")
        techniques_layout = QVBoxLayout(techniques_group)
        
        self.techniques_tree = QTreeWidget()
        self.techniques_tree.setHeaderLabels(["Technique", "Tactic", "Confidence"])
        techniques_layout.addWidget(self.techniques_tree)
        
        right_layout.addWidget(techniques_group)
        
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        return widget
    
    def create_alerts_tab(self) -> QWidget:
        """Create alerts tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self.filter_alerts)
        filter_layout.addWidget(self.severity_filter)
        
        filter_layout.addWidget(QLabel("Indicator:"))
        self.indicator_filter = QComboBox()
        self.indicator_filter.addItems([
            "All", "Reconnaissance", "Credential Theft", "Lateral Movement",
            "Data Exfiltration", "Malware Execution"
        ])
        filter_layout.addWidget(self.indicator_filter)
        
        filter_layout.addStretch()
        
        clear_btn = QPushButton("Clear Alerts")
        filter_layout.addWidget(clear_btn)
        
        layout.addLayout(filter_layout)
        
        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(7)
        self.alerts_table.setHorizontalHeaderLabels([
            "Time", "Severity", "Decoy", "Source IP", "Indicator", "MITRE", "Description"
        ])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.alerts_table)
        
        return widget
    
    def create_campaigns_tab(self) -> QWidget:
        """Create campaigns tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # New campaign form
        form_group = QGroupBox("Create Campaign")
        form_layout = QGridLayout(form_group)
        
        form_layout.addWidget(QLabel("Name:"), 0, 0)
        self.campaign_name_input = QLineEdit()
        self.campaign_name_input.setPlaceholderText("e.g., APT Detection Campaign")
        form_layout.addWidget(self.campaign_name_input, 0, 1)
        
        form_layout.addWidget(QLabel("Objective:"), 0, 2)
        self.campaign_objective_input = QLineEdit()
        self.campaign_objective_input.setPlaceholderText("Detect and analyze...")
        form_layout.addWidget(self.campaign_objective_input, 0, 3)
        
        form_layout.addWidget(QLabel("Duration (hours):"), 1, 0)
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(1, 720)
        self.duration_spin.setValue(72)
        form_layout.addWidget(self.duration_spin, 1, 1)
        
        form_layout.addWidget(QLabel("Decoy Types:"), 1, 2)
        self.decoy_types_list = QListWidget()
        self.decoy_types_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.decoy_types_list.addItems([
            "Web Server", "Database", "File Server", "Domain Controller", "API Endpoint"
        ])
        self.decoy_types_list.setMaximumHeight(80)
        form_layout.addWidget(self.decoy_types_list, 1, 3)
        
        create_btn = QPushButton("📋 Create Campaign")
        create_btn.clicked.connect(self.create_campaign)
        create_btn.setStyleSheet("background: #6c5ce7; color: white;")
        form_layout.addWidget(create_btn, 2, 0, 1, 4)
        
        layout.addWidget(form_group)
        
        # Active campaigns
        self.campaigns_table = QTableWidget()
        self.campaigns_table.setColumnCount(6)
        self.campaigns_table.setHorizontalHeaderLabels([
            "Name", "Objective", "Decoys", "Alerts", "Sessions", "Status"
        ])
        self.campaigns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.campaigns_table)
        
        return widget
    
    def create_analytics_tab(self) -> QWidget:
        """Create analytics tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Stats cards
        stats_grid = QGridLayout()
        
        metrics = [
            ("Total Interactions", "1,247", "#00ff88"),
            ("Unique Attackers", "43", "#ff6b6b"),
            ("Credentials Captured", "156", "#ffd93d"),
            ("Techniques Detected", "28", "#6c5ce7"),
            ("Active Campaigns", "3", "#00d4ff"),
            ("Average Session Duration", "12m 34s", "#ff9f43")
        ]
        
        for i, (label, value, color) in enumerate(metrics):
            card = self.create_analytics_card(label, value, color)
            stats_grid.addWidget(card, i // 3, i % 3)
        
        layout.addLayout(stats_grid)
        
        # Charts placeholder
        charts_group = QGroupBox("Attack Trends")
        charts_layout = QVBoxLayout(charts_group)
        
        chart_placeholder = QLabel("📊 Attack trend visualization would be rendered here")
        chart_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        chart_placeholder.setMinimumHeight(200)
        chart_placeholder.setStyleSheet("background: #1a1a2e; color: #888; border-radius: 8px;")
        
        charts_layout.addWidget(chart_placeholder)
        
        layout.addWidget(charts_group)
        
        # Top attacker profiles
        profiles_group = QGroupBox("Top Attacker Profiles")
        profiles_layout = QVBoxLayout(profiles_group)
        
        profiles = [
            ("APT-style", "Advanced", "5 sessions", "#ff6b6b"),
            ("Opportunistic", "Medium", "23 sessions", "#ffd93d"),
            ("Script Kiddie", "Low", "15 sessions", "#00ff88")
        ]
        
        for profile, sophistication, sessions, color in profiles:
            profile_widget = QFrame()
            profile_widget.setStyleSheet(f"border-left: 4px solid {color}; padding: 5px;")
            profile_layout = QHBoxLayout(profile_widget)
            profile_layout.addWidget(QLabel(f"👤 {profile}"))
            profile_layout.addWidget(QLabel(f"[{sophistication}]"))
            profile_layout.addStretch()
            profile_layout.addWidget(QLabel(sessions))
            profiles_layout.addWidget(profile_widget)
        
        layout.addWidget(profiles_group)
        
        return widget
    
    def create_analytics_card(self, label: str, value: str, color: str) -> QFrame:
        """Create an analytics card."""
        card = QFrame()
        card.setFixedHeight(100)
        card.setStyleSheet(f"""
            QFrame {{
                background: rgba(0,0,0,0.3);
                border: 1px solid {color};
                border-radius: 10px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        text_label = QLabel(label)
        text_label.setStyleSheet("color: #888;")
        text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(value_label)
        layout.addWidget(text_label)
        
        return card
    
    def deploy_decoy(self):
        """Deploy a new decoy."""
        decoy_type = self.decoy_type_combo.currentText()
        name = self.decoy_name_input.text() or f"{decoy_type.lower().replace(' ', '-')}-01"
        interaction = self.interaction_combo.currentText()
        
        self.deploy_progress.setVisible(True)
        self.deploy_progress.setValue(0)
        
        self.deploy_worker = DeployDecoyWorker(self.fabric, decoy_type, name, interaction)
        self.deploy_worker.progress.connect(self.deploy_progress.setValue)
        self.deploy_worker.decoy_deployed.connect(self.add_decoy_to_table)
        self.deploy_worker.finished.connect(lambda: self.deploy_progress.setVisible(False))
        self.deploy_worker.start()
    
    def add_decoy_to_table(self, decoy: dict):
        """Add deployed decoy to table."""
        row = self.decoys_table.rowCount()
        self.decoys_table.insertRow(row)
        
        items = [
            decoy["id"],
            decoy["type"],
            decoy["name"],
            decoy["ip"],
            "HTTP/80, HTTPS/443",
            "0",
            "Never",
            "Active"
        ]
        
        for col, item in enumerate(items):
            cell = QTableWidgetItem(str(item))
            if col == 7:  # Status
                cell.setForeground(QColor("#00ff88"))
            self.decoys_table.setItem(row, col, cell)
        
        # Update stats
        count = self.decoys_table.rowCount()
        self.decoys_count.findChild(QLabel, "value").setText(str(count))
    
    def new_campaign(self):
        """Open new campaign dialog."""
        pass
    
    def create_campaign(self):
        """Create a new campaign."""
        name = self.campaign_name_input.text()
        if not name:
            return
        
        row = self.campaigns_table.rowCount()
        self.campaigns_table.insertRow(row)
        
        items = [
            name,
            self.campaign_objective_input.text(),
            str(len(self.decoy_types_list.selectedItems())),
            "0",
            "0",
            "Active"
        ]
        
        for col, item in enumerate(items):
            self.campaigns_table.setItem(row, col, QTableWidgetItem(item))
    
    def refresh_network(self):
        """Refresh network display."""
        pass
    
    def show_session_details(self, row: int, col: int):
        """Show session details."""
        session_id = self.sessions_table.item(row, 0).text()
        self.session_details.setText(f"""
Session: {session_id}
══════════════════════════════════════

Source IP: {self.sessions_table.item(row, 1).text()}
Target: {self.sessions_table.item(row, 2).text()}
Duration: {self.sessions_table.item(row, 3).text()}
Threat Score: {self.sessions_table.item(row, 4).text()}
Profile: {self.sessions_table.item(row, 5).text()}

Commands Executed:
  > whoami
  > uname -a
  > cat /etc/passwd
  > find / -name "*.conf"

Files Accessed:
  - /etc/shadow (attempted)
  - /var/log/auth.log
  - /home/admin/.ssh/id_rsa

Credentials Tried:
  - admin:admin123
  - root:toor
  - admin:Admin@2024 ⚠️ HONEYCRED
""")
    
    def filter_alerts(self, severity: str):
        """Filter alerts by severity."""
        for row in range(self.alerts_table.rowCount()):
            if severity == "All":
                self.alerts_table.setRowHidden(row, False)
            else:
                cell = self.alerts_table.item(row, 1)
                if cell:
                    self.alerts_table.setRowHidden(row, cell.text() != severity)
    
    def start_monitoring(self):
        """Start live monitoring."""
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.update_live_data)
        self.monitor_timer.start(5000)
    
    def update_live_data(self):
        """Update live monitoring data."""
        import random
        
        # Simulate occasional new alerts
        if random.random() < 0.3:
            self.add_simulated_alert()
    
    def add_simulated_alert(self):
        """Add a simulated alert."""
        import random
        
        severities = ["Low", "Medium", "High", "Critical"]
        indicators = ["Reconnaissance", "Credential Theft", "Lateral Movement"]
        
        row = 0
        self.alerts_table.insertRow(row)
        
        items = [
            datetime.now().strftime("%H:%M:%S"),
            random.choice(severities),
            f"decoy-{random.randint(1,5):02d}",
            f"185.220.101.{random.randint(1,255)}",
            random.choice(indicators),
            f"T{random.randint(1000,1999)}",
            "Suspicious activity detected"
        ]
        
        for col, item in enumerate(items):
            cell = QTableWidgetItem(item)
            if col == 1:  # Severity
                colors = {"Critical": "#ff4444", "High": "#ff8844", "Medium": "#ffcc44", "Low": "#88ff88"}
                cell.setForeground(QColor(colors.get(item, "#fff")))
            self.alerts_table.setItem(row, col, cell)
        
        # Update count
        count = int(self.alerts_count.findChild(QLabel, "value").text()) + 1
        self.alerts_count.findChild(QLabel, "value").setText(str(count))
