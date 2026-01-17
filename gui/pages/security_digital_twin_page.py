"""
Security Digital Twin Page
GUI for virtual network simulation and attack testing
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QGroupBox,
    QProgressBar, QSplitter, QFrame, QHeaderView, QTreeWidget,
    QTreeWidgetItem, QGridLayout, QComboBox, QTextEdit, QSpinBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor
import asyncio


class SimulationWorker(QThread):
    """Worker thread for running simulations"""
    progress = pyqtSignal(str, int)
    result = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, simulation_type):
        super().__init__()
        self.simulation_type = simulation_type
        
    def run(self):
        try:
            from core.security_digital_twin import SecurityDigitalTwin
            
            async def simulate():
                twin = SecurityDigitalTwin()
                return await twin.run_simulation(self.simulation_type)
                
            result = asyncio.run(simulate())
            self.result.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class SecurityDigitalTwinPage(QWidget):
    """Security Digital Twin Dashboard"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.simulation_worker = None
        
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
                color: #00d4ff;
            }
        """)
        
        # Create tabs
        self.tabs.addTab(self._create_topology_tab(), "🌐 Network Topology")
        self.tabs.addTab(self._create_simulations_tab(), "⚡ Simulations")
        self.tabs.addTab(self._create_results_tab(), "📊 Results")
        self.tabs.addTab(self._create_assets_tab(), "💻 Virtual Assets")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QWidget:
        """Create the page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a2a3a, stop:1 #0d1117);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🔄 Security Digital Twin")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            color: #e6e6e6;
        """)
        title_layout.addWidget(title)
        
        subtitle = QLabel("Virtual Network Simulation for Unlimited Attack Testing")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.assets_count = self._create_stat_card("Virtual Assets", "15", "#00d4ff")
        self.networks_count = self._create_stat_card("Networks", "3", "#00ff88")
        self.simulations_count = self._create_stat_card("Simulations", "24", "#ffa500")
        
        stats_layout.addWidget(self.assets_count)
        stats_layout.addWidget(self.networks_count)
        stats_layout.addWidget(self.simulations_count)
        
        layout.addLayout(stats_layout)
        
        # Simulation controls
        control_layout = QVBoxLayout()
        
        self.sim_type = QComboBox()
        self.sim_type.addItems([
            "🦠 Ransomware Attack",
            "🕵️ APT Simulation",
            "🔀 Lateral Movement",
            "⬆️ Privilege Escalation",
            "📤 Data Exfiltration",
            "💥 DDoS Attack",
            "👤 Insider Threat",
            "🎯 Zero-Day Exploit"
        ])
        self.sim_type.setStyleSheet("""
            QComboBox {
                background: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                padding: 8px;
                border-radius: 6px;
                min-width: 180px;
            }
        """)
        control_layout.addWidget(self.sim_type)
        
        self.run_btn = QPushButton("🚀 Run Simulation")
        self.run_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00d4ff, stop:1 #00ff88);
                color: #0d1117;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, stop:1 #00d4ff);
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
        
    def _create_topology_tab(self) -> QWidget:
        """Create network topology tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Network visualization placeholder
        viz_frame = QFrame()
        viz_frame.setStyleSheet("""
            QFrame {
                background: #0d1117;
                border: 2px dashed #30363d;
                border-radius: 12px;
                min-height: 300px;
            }
        """)
        viz_layout = QVBoxLayout(viz_frame)
        
        viz_label = QLabel("🌐 Interactive Network Topology")
        viz_label.setStyleSheet("color: #00d4ff; font-size: 24px; font-weight: bold;")
        viz_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        viz_layout.addWidget(viz_label)
        
        viz_desc = QLabel("Virtual representation of your network infrastructure\nClick nodes to see attack paths and vulnerabilities")
        viz_desc.setStyleSheet("color: #8b949e; font-size: 14px;")
        viz_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        viz_layout.addWidget(viz_desc)
        
        layout.addWidget(viz_frame)
        
        # Networks table
        self.networks_table = QTableWidget()
        self.networks_table.setColumnCount(5)
        self.networks_table.setHorizontalHeaderLabels([
            "Network", "CIDR", "Assets", "Security Level", "Status"
        ])
        self.networks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.networks_table.setStyleSheet("""
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
        layout.addWidget(self.networks_table)
        
        return widget
        
    def _create_simulations_tab(self) -> QWidget:
        """Create simulations configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Simulation types grid
        sim_group = QGroupBox("Available Simulations")
        sim_group.setStyleSheet("""
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
        sim_layout = QGridLayout(sim_group)
        
        simulations = [
            ("🦠 Ransomware", "Simulate ransomware encryption and lateral spread"),
            ("🕵️ APT Campaign", "Multi-stage advanced persistent threat"),
            ("🔀 Lateral Movement", "Test network segmentation effectiveness"),
            ("⬆️ Privilege Escalation", "Local and domain privilege escalation"),
            ("📤 Data Exfiltration", "Test DLP and egress controls"),
            ("💥 DDoS Attack", "Volumetric and application layer attacks"),
            ("👤 Insider Threat", "Malicious insider simulation"),
            ("🎯 Zero-Day Exploit", "Unknown vulnerability exploitation"),
        ]
        
        for i, (name, desc) in enumerate(simulations):
            row, col = divmod(i, 2)
            sim_card = self._create_sim_card(name, desc)
            sim_layout.addWidget(sim_card, row, col)
            
        layout.addWidget(sim_group)
        
        return widget
        
    def _create_sim_card(self, name: str, desc: str) -> QFrame:
        """Create simulation type card"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
            }
            QFrame:hover {
                border: 1px solid #00d4ff;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        name_label = QLabel(name)
        name_label.setStyleSheet("color: #00d4ff; font-weight: bold; font-size: 14px;")
        layout.addWidget(name_label)
        
        desc_label = QLabel(desc)
        desc_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        return card
        
    def _create_results_tab(self) -> QWidget:
        """Create simulation results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels([
            "Simulation", "Type", "Duration", "Compromised", "Detected", "Score", "Status"
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
        
    def _create_assets_tab(self) -> QWidget:
        """Create virtual assets tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Assets table
        self.assets_table = QTableWidget()
        self.assets_table.setColumnCount(6)
        self.assets_table.setHorizontalHeaderLabels([
            "Asset", "Type", "IP Address", "Network", "Criticality", "Vulnerabilities"
        ])
        self.assets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.assets_table.setStyleSheet("""
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
        layout.addWidget(self.assets_table)
        
        return widget
        
    def _connect_signals(self):
        """Connect signals and slots"""
        self.run_btn.clicked.connect(self._run_simulation)
        
    def _run_simulation(self):
        """Run attack simulation"""
        self.run_btn.setEnabled(False)
        self.run_btn.setText("🔄 Simulating...")
        
        QTimer.singleShot(3000, self._simulation_complete)
        
    def _simulation_complete(self):
        """Handle simulation completion"""
        self.run_btn.setEnabled(True)
        self.run_btn.setText("🚀 Run Simulation")
        self._add_simulation_result()
        
    def _add_simulation_result(self):
        """Add a new simulation result"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        sim_type = self.sim_type.currentText()
        data = [
            f"SIM-{row+1:03d}",
            sim_type,
            "2m 34s",
            "3/15 assets",
            "Yes",
            "72/100",
            "✅ Complete"
        ]
        
        for col, value in enumerate(data):
            item = QTableWidgetItem(value)
            self.results_table.setItem(row, col, item)
        
    def _load_demo_data(self):
        """Load demonstration data"""
        # Networks
        networks = [
            ("Corporate", "10.0.0.0/8", "8", "High", "🟢 Active"),
            ("DMZ", "172.16.0.0/16", "4", "Critical", "🟢 Active"),
            ("Development", "192.168.0.0/16", "3", "Medium", "🟢 Active"),
        ]
        
        self.networks_table.setRowCount(len(networks))
        for row, net in enumerate(networks):
            for col, value in enumerate(net):
                item = QTableWidgetItem(value)
                self.networks_table.setItem(row, col, item)
                
        # Assets
        assets = [
            ("web-server-01", "Web Server", "10.0.1.10", "Corporate", "High", "3"),
            ("db-server-01", "Database", "10.0.2.20", "Corporate", "Critical", "1"),
            ("app-server-01", "Application", "10.0.1.15", "Corporate", "High", "2"),
            ("fw-dmz-01", "Firewall", "172.16.0.1", "DMZ", "Critical", "0"),
            ("dev-vm-01", "Development", "192.168.1.100", "Development", "Low", "5"),
        ]
        
        self.assets_table.setRowCount(len(assets))
        for row, asset in enumerate(assets):
            for col, value in enumerate(asset):
                item = QTableWidgetItem(value)
                self.assets_table.setItem(row, col, item)
                
        # Sample results
        results = [
            ("SIM-001", "🦠 Ransomware", "5m 12s", "7/15", "Yes", "65/100", "✅ Complete"),
            ("SIM-002", "🕵️ APT", "12m 45s", "4/15", "Partial", "78/100", "✅ Complete"),
            ("SIM-003", "📤 Data Exfil", "3m 22s", "2/15", "Yes", "85/100", "✅ Complete"),
        ]
        
        self.results_table.setRowCount(len(results))
        for row, res in enumerate(results):
            for col, value in enumerate(res):
                item = QTableWidgetItem(value)
                self.results_table.setItem(row, col, item)
