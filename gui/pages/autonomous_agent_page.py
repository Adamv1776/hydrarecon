"""
HydraRecon - Autonomous Red Team Agent GUI
Real-time visualization of AI-driven penetration testing operations
"""

import asyncio
from datetime import datetime
from typing import Optional, Dict, List
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QTextEdit, QComboBox,
    QProgressBar, QSplitter, QGroupBox, QLineEdit, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QListWidget, QListWidgetItem, QCheckBox, QDialog, QFormLayout,
    QDialogButtonBox, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon


class AgentWorker(QThread):
    """Background worker for agent execution"""
    state_changed = pyqtSignal(str, str)  # old_state, new_state
    task_started = pyqtSignal(object)
    task_completed = pyqtSignal(object, bool)
    log_entry = pyqtSignal(object)
    asset_discovered = pyqtSignal(object)
    asset_compromised = pyqtSignal(object)
    finding_added = pyqtSignal(object)
    execution_finished = pyqtSignal()
    
    def __init__(self, agent):
        super().__init__()
        self.agent = agent
        
    def run(self):
        """Run agent in background thread"""
        # Register callbacks
        self.agent.register_callback("state_changed", 
            lambda old, new: self.state_changed.emit(old.value, new.value))
        self.agent.register_callback("task_started",
            lambda task: self.task_started.emit(task))
        self.agent.register_callback("task_completed",
            lambda task, success: self.task_completed.emit(task, success))
        self.agent.register_callback("log_entry",
            lambda entry: self.log_entry.emit(entry))
        self.agent.register_callback("asset_discovered",
            lambda asset: self.asset_discovered.emit(asset))
        self.agent.register_callback("asset_compromised",
            lambda asset: self.asset_compromised.emit(asset))
        self.agent.register_callback("finding_added",
            lambda finding: self.finding_added.emit(finding))
            
        # Run agent
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.agent.run())
        finally:
            loop.close()
            
        self.execution_finished.emit()


class TargetConfigDialog(QDialog):
    """Dialog for configuring engagement targets"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configure Engagement")
        self.setMinimumWidth(500)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Targets
        targets_group = QGroupBox("Target Scope")
        targets_layout = QVBoxLayout(targets_group)
        
        targets_layout.addWidget(QLabel("IP Ranges / Hostnames (one per line):"))
        self.targets_input = QTextEdit()
        self.targets_input.setPlaceholderText(
            "10.0.0.0/24\nweb-server.example.com\n192.168.1.100"
        )
        self.targets_input.setMaximumHeight(100)
        targets_layout.addWidget(self.targets_input)
        
        layout.addWidget(targets_group)
        
        # Options
        options_group = QGroupBox("Engagement Options")
        options_layout = QFormLayout(options_group)
        
        self.risk_combo = QComboBox()
        self.risk_combo.addItems(["Stealth", "Balanced", "Aggressive", "Maximum"])
        self.risk_combo.setCurrentIndex(1)
        options_layout.addRow("Risk Level:", self.risk_combo)
        
        self.auto_pivot = QCheckBox()
        self.auto_pivot.setChecked(True)
        options_layout.addRow("Auto Pivot:", self.auto_pivot)
        
        self.credential_spray = QCheckBox()
        self.credential_spray.setChecked(True)
        options_layout.addRow("Credential Spray:", self.credential_spray)
        
        self.cleanup = QCheckBox()
        self.cleanup.setChecked(True)
        options_layout.addRow("Cleanup on Exit:", self.cleanup)
        
        layout.addWidget(options_group)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def get_config(self) -> Dict:
        """Get engagement configuration"""
        targets = []
        for line in self.targets_input.toPlainText().strip().split('\n'):
            if line.strip():
                targets.append({"ip": line.strip(), "priority": "high"})
                
        return {
            "targets": targets or [
                {"ip": "10.0.1.10", "hostname": "web-01", "priority": "critical"},
                {"ip": "10.0.1.20", "hostname": "dc-01", "priority": "critical"},
                {"ip": "10.0.1.30", "hostname": "db-01", "priority": "high"},
                {"ip": "10.0.1.40", "hostname": "file-01", "priority": "medium"},
            ],
            "objectives": ["full_compromise"],
            "risk_level": self.risk_combo.currentText().lower(),
            "auto_pivot": self.auto_pivot.isChecked(),
            "credential_spray": self.credential_spray.isChecked(),
            "cleanup_on_exit": self.cleanup.isChecked(),
        }


class StatCard(QFrame):
    """Animated statistic card"""
    
    def __init__(self, title: str, value: str = "0", color: str = "#3498db"):
        super().__init__()
        self.setObjectName("statCard")
        self.color = color
        self.setup_ui(title, value)
        
    def setup_ui(self, title: str, value: str):
        self.setStyleSheet(f"""
            QFrame#statCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {self.color}40, stop:1 {self.color}20);
                border: 1px solid {self.color}60;
                border-radius: 12px;
                padding: 15px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        self.value_label = QLabel(value)
        self.value_label.setFont(QFont("Arial", 32, QFont.Weight.Bold))
        self.value_label.setStyleSheet(f"color: {self.color}; background: transparent;")
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.value_label)
        
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 11))
        title_label.setStyleSheet("color: #888; background: transparent;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
    def set_value(self, value: str):
        self.value_label.setText(value)


class TaskWidget(QFrame):
    """Widget representing a task in the queue"""
    
    def __init__(self, task):
        super().__init__()
        self.task = task
        self.setup_ui()
        
    def setup_ui(self):
        status_colors = {
            "pending": "#95a5a6",
            "running": "#f39c12",
            "completed": "#27ae60",
            "failed": "#e74c3c",
            "cancelled": "#9b59b6",
        }
        color = status_colors.get(self.task.status, "#95a5a6")
        
        self.setStyleSheet(f"""
            QFrame {{
                background: {color}20;
                border-left: 4px solid {color};
                border-radius: 8px;
                padding: 10px;
                margin: 2px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)
        
        # Header
        header = QHBoxLayout()
        
        name_label = QLabel(self.task.name)
        name_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        name_label.setStyleSheet(f"color: #fff; background: transparent;")
        header.addWidget(name_label)
        
        header.addStretch()
        
        status_label = QLabel(self.task.status.upper())
        status_label.setStyleSheet(f"""
            color: {color};
            background: {color}30;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: bold;
        """)
        header.addWidget(status_label)
        
        layout.addLayout(header)
        
        # Details
        details = QHBoxLayout()
        
        technique_label = QLabel(f"🎯 {self.task.technique_id}")
        technique_label.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
        details.addWidget(technique_label)
        
        risk_label = QLabel(f"⚠️ Risk: {self.task.risk_level}/10")
        risk_label.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
        details.addWidget(risk_label)
        
        prob_label = QLabel(f"📊 {self.task.success_probability*100:.0f}%")
        prob_label.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
        details.addWidget(prob_label)
        
        details.addStretch()
        
        layout.addLayout(details)


class AssetWidget(QFrame):
    """Widget representing a discovered asset"""
    
    def __init__(self, asset):
        super().__init__()
        self.asset = asset
        self.setup_ui()
        
    def setup_ui(self):
        color = "#27ae60" if self.asset.compromised else "#3498db"
        
        self.setStyleSheet(f"""
            QFrame {{
                background: {color}15;
                border: 1px solid {color}40;
                border-radius: 10px;
                padding: 10px;
                margin: 2px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)
        
        # Header
        header = QHBoxLayout()
        
        status_icon = "💀" if self.asset.compromised else "🖥️"
        name = self.asset.hostname or self.asset.ip_address
        name_label = QLabel(f"{status_icon} {name}")
        name_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        name_label.setStyleSheet(f"color: {color}; background: transparent;")
        header.addWidget(name_label)
        
        header.addStretch()
        
        if self.asset.compromised:
            pwned = QLabel("PWNED")
            pwned.setStyleSheet("""
                color: #27ae60;
                background: #27ae6030;
                padding: 2px 8px;
                border-radius: 10px;
                font-size: 10px;
                font-weight: bold;
            """)
            header.addWidget(pwned)
            
        layout.addLayout(header)
        
        # IP
        if self.asset.ip_address:
            ip_label = QLabel(f"📍 {self.asset.ip_address}")
            ip_label.setStyleSheet("color: #888; font-size: 11px; background: transparent;")
            layout.addWidget(ip_label)
            
        # Ports
        if self.asset.open_ports:
            ports_str = ", ".join(str(p) for p in self.asset.open_ports[:6])
            if len(self.asset.open_ports) > 6:
                ports_str += f" (+{len(self.asset.open_ports) - 6})"
            ports_label = QLabel(f"🔓 Ports: {ports_str}")
            ports_label.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
            layout.addWidget(ports_label)


class FindingWidget(QFrame):
    """Widget representing a security finding"""
    
    def __init__(self, finding: Dict):
        super().__init__()
        self.finding = finding
        self.setup_ui()
        
    def setup_ui(self):
        severity_colors = {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f1c40f",
            "low": "#27ae60",
        }
        color = severity_colors.get(self.finding.get("severity", "medium"), "#f1c40f")
        
        self.setStyleSheet(f"""
            QFrame {{
                background: {color}15;
                border-left: 4px solid {color};
                border-radius: 8px;
                padding: 10px;
                margin: 2px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)
        
        # Category icon
        icons = {
            "vulnerability": "🔓",
            "access": "🚪",
            "credentials": "🔑",
            "privilege_escalation": "⬆️",
            "data": "📁",
        }
        icon = icons.get(self.finding.get("category", ""), "📌")
        
        title = QLabel(f"{icon} {self.finding.get('title', 'Finding')}")
        title.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {color}; background: transparent;")
        layout.addWidget(title)
        
        # Target
        target = QLabel(f"Target: {self.finding.get('target', 'N/A')}")
        target.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
        layout.addWidget(target)
        
        # Details
        details = self.finding.get("details", "")
        if isinstance(details, list):
            details = ", ".join(str(d) for d in details[:3])
        details_label = QLabel(str(details)[:100])
        details_label.setStyleSheet("color: #aaa; font-size: 10px; background: transparent;")
        details_label.setWordWrap(True)
        layout.addWidget(details_label)


class AutonomousAgentPage(QWidget):
    """Main page for Autonomous Red Team Agent"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.agent = None
        self.worker = None
        self.setup_ui()
        self.setup_timers()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Stats bar
        stats_bar = self.create_stats_bar()
        layout.addWidget(stats_bar)
        
        # Main content
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Tasks & Control
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)
        
        # Center panel - Live Activity
        center_panel = self.create_center_panel()
        splitter.addWidget(center_panel)
        
        # Right panel - Intelligence
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([350, 500, 350])
        layout.addWidget(splitter, 1)
        
    def create_header(self) -> QFrame:
        """Create header with controls"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:0.5 #16213e, stop:1 #0f3460);
                border-radius: 15px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title section
        title_section = QVBoxLayout()
        
        title = QLabel("🤖 Autonomous Red Team Agent")
        title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #e74c3c; background: transparent;")
        title_section.addWidget(title)
        
        subtitle = QLabel("AI-Driven Autonomous Penetration Testing")
        subtitle.setStyleSheet("color: #888; font-size: 12px; background: transparent;")
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Agent status
        status_section = QVBoxLayout()
        status_section.setAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.agent_status = QLabel("⚫ OFFLINE")
        self.agent_status.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.agent_status.setStyleSheet("color: #95a5a6; background: transparent;")
        status_section.addWidget(self.agent_status, alignment=Qt.AlignmentFlag.AlignRight)
        
        self.state_label = QLabel("Waiting to initialize...")
        self.state_label.setStyleSheet("color: #666; background: transparent;")
        status_section.addWidget(self.state_label, alignment=Qt.AlignmentFlag.AlignRight)
        
        layout.addLayout(status_section)
        
        # Control buttons
        btn_style = """
            QPushButton {
                background: %s;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 25px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background: %s;
            }
            QPushButton:disabled {
                background: #444;
                color: #666;
            }
        """
        
        self.init_btn = QPushButton("⚙️ Configure")
        self.init_btn.setStyleSheet(btn_style % ("#3498db", "#2980b9"))
        self.init_btn.clicked.connect(self.configure_engagement)
        layout.addWidget(self.init_btn)
        
        self.start_btn = QPushButton("▶️ Launch Agent")
        self.start_btn.setStyleSheet(btn_style % ("#27ae60", "#1e8449"))
        self.start_btn.clicked.connect(self.start_agent)
        self.start_btn.setEnabled(False)
        layout.addWidget(self.start_btn)
        
        self.pause_btn = QPushButton("⏸️ Pause")
        self.pause_btn.setStyleSheet(btn_style % ("#f39c12", "#d68910"))
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.pause_btn.setEnabled(False)
        layout.addWidget(self.pause_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setStyleSheet(btn_style % ("#e74c3c", "#c0392b"))
        self.stop_btn.clicked.connect(self.stop_agent)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn)
        
        return frame
        
    def create_stats_bar(self) -> QFrame:
        """Create statistics bar"""
        frame = QFrame()
        layout = QHBoxLayout(frame)
        layout.setSpacing(15)
        
        self.stat_cards = {}
        
        stats = [
            ("Tasks Completed", "0", "#27ae60"),
            ("Assets Discovered", "0", "#3498db"),
            ("Systems Compromised", "0", "#e74c3c"),
            ("Credentials Found", "0", "#9b59b6"),
            ("Findings", "0", "#f39c12"),
            ("Runtime", "00:00", "#1abc9c"),
        ]
        
        for title, value, color in stats:
            card = StatCard(title, value, color)
            self.stat_cards[title] = card
            layout.addWidget(card)
            
        return frame
        
    def create_left_panel(self) -> QFrame:
        """Create left panel with task queue"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 12px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        # Header
        header = QHBoxLayout()
        title = QLabel("📋 Task Queue")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #fff; background: transparent;")
        header.addWidget(title)
        
        header.addStretch()
        
        self.task_count = QLabel("0 tasks")
        self.task_count.setStyleSheet("color: #888; background: transparent;")
        header.addWidget(self.task_count)
        
        layout.addLayout(header)
        
        # Current task
        current_frame = QFrame()
        current_frame.setStyleSheet("""
            QFrame {
                background: #16213e;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        current_layout = QVBoxLayout(current_frame)
        
        current_title = QLabel("🎯 Current Task")
        current_title.setStyleSheet("color: #f39c12; font-weight: bold; background: transparent;")
        current_layout.addWidget(current_title)
        
        self.current_task_label = QLabel("No task running")
        self.current_task_label.setStyleSheet("color: #fff; background: transparent;")
        self.current_task_label.setWordWrap(True)
        current_layout.addWidget(self.current_task_label)
        
        self.task_progress = QProgressBar()
        self.task_progress.setStyleSheet("""
            QProgressBar {
                background: #0a0a15;
                border-radius: 5px;
                height: 8px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #f39c12, stop:1 #e74c3c);
                border-radius: 5px;
            }
        """)
        self.task_progress.setTextVisible(False)
        current_layout.addWidget(self.task_progress)
        
        layout.addWidget(current_frame)
        
        # Pending tasks scroll
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        
        self.tasks_container = QWidget()
        self.tasks_layout = QVBoxLayout(self.tasks_container)
        self.tasks_layout.setContentsMargins(0, 0, 0, 0)
        self.tasks_layout.setSpacing(8)
        self.tasks_layout.addStretch()
        
        scroll.setWidget(self.tasks_container)
        layout.addWidget(scroll, 1)
        
        return frame
        
    def create_center_panel(self) -> QFrame:
        """Create center panel with live activity log"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 12px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        # Header
        header = QHBoxLayout()
        title = QLabel("📊 Live Activity")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #fff; background: transparent;")
        header.addWidget(title)
        
        header.addStretch()
        
        self.clear_log_btn = QPushButton("Clear")
        self.clear_log_btn.setStyleSheet("""
            QPushButton {
                background: #333;
                color: #888;
                border: none;
                border-radius: 5px;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background: #444;
            }
        """)
        self.clear_log_btn.clicked.connect(self.clear_log)
        header.addWidget(self.clear_log_btn)
        
        layout.addLayout(header)
        
        # Activity log
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setStyleSheet("""
            QTextEdit {
                background: #0a0a15;
                color: #0f0;
                border: 1px solid #333;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
            }
        """)
        layout.addWidget(self.activity_log, 1)
        
        # Attack path visualization
        path_frame = QFrame()
        path_frame.setStyleSheet("""
            QFrame {
                background: #16213e;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        path_layout = QVBoxLayout(path_frame)
        
        path_title = QLabel("🗺️ Attack Path Progress")
        path_title.setStyleSheet("color: #3498db; font-weight: bold; background: transparent;")
        path_layout.addWidget(path_title)
        
        self.path_progress = QProgressBar()
        self.path_progress.setStyleSheet("""
            QProgressBar {
                background: #0a0a15;
                border-radius: 8px;
                height: 20px;
                text-align: center;
                color: #fff;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #27ae60, stop:0.5 #3498db, stop:1 #9b59b6);
                border-radius: 8px;
            }
        """)
        self.path_progress.setFormat("%p% Complete")
        path_layout.addWidget(self.path_progress)
        
        # Phase indicators
        phases_layout = QHBoxLayout()
        phases = ["Recon", "Enum", "Exploit", "PrivEsc", "Lateral", "Exfil"]
        self.phase_labels = []
        
        for phase in phases:
            label = QLabel(phase)
            label.setStyleSheet("""
                color: #555;
                background: #1a1a2e;
                padding: 5px 10px;
                border-radius: 5px;
                font-size: 10px;
            """)
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.phase_labels.append(label)
            phases_layout.addWidget(label)
            
        path_layout.addLayout(phases_layout)
        
        layout.addWidget(path_frame)
        
        return frame
        
    def create_right_panel(self) -> QFrame:
        """Create right panel with intelligence"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 12px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        # Tabs for different intel
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background: transparent;
            }
            QTabBar::tab {
                background: #16213e;
                color: #888;
                padding: 8px 15px;
                margin-right: 5px;
                border-radius: 5px 5px 0 0;
            }
            QTabBar::tab:selected {
                background: #0f3460;
                color: #fff;
            }
        """)
        
        # Assets tab
        assets_widget = QWidget()
        assets_layout = QVBoxLayout(assets_widget)
        
        assets_scroll = QScrollArea()
        assets_scroll.setWidgetResizable(True)
        assets_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        self.assets_container = QWidget()
        self.assets_layout = QVBoxLayout(self.assets_container)
        self.assets_layout.setContentsMargins(0, 0, 0, 0)
        self.assets_layout.setSpacing(8)
        self.assets_layout.addStretch()
        
        assets_scroll.setWidget(self.assets_container)
        assets_layout.addWidget(assets_scroll)
        
        tabs.addTab(assets_widget, "🖥️ Assets")
        
        # Findings tab
        findings_widget = QWidget()
        findings_layout = QVBoxLayout(findings_widget)
        
        findings_scroll = QScrollArea()
        findings_scroll.setWidgetResizable(True)
        findings_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        self.findings_container = QWidget()
        self.findings_layout = QVBoxLayout(self.findings_container)
        self.findings_layout.setContentsMargins(0, 0, 0, 0)
        self.findings_layout.setSpacing(8)
        self.findings_layout.addStretch()
        
        findings_scroll.setWidget(self.findings_container)
        findings_layout.addWidget(findings_scroll)
        
        tabs.addTab(findings_widget, "🔍 Findings")
        
        # Credentials tab
        creds_widget = QWidget()
        creds_layout = QVBoxLayout(creds_widget)
        
        self.creds_table = QTableWidget()
        self.creds_table.setColumnCount(3)
        self.creds_table.setHorizontalHeaderLabels(["Type", "Username", "Status"])
        self.creds_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.creds_table.setStyleSheet("""
            QTableWidget {
                background: #0a0a15;
                color: #fff;
                border: none;
                gridline-color: #333;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background: #16213e;
                color: #888;
                padding: 8px;
                border: none;
            }
        """)
        creds_layout.addWidget(self.creds_table)
        
        tabs.addTab(creds_widget, "🔑 Credentials")
        
        layout.addWidget(tabs)
        
        # Report button
        self.report_btn = QPushButton("📄 Generate Report")
        self.report_btn.setStyleSheet("""
            QPushButton {
                background: #16213e;
                color: #3498db;
                border: 1px solid #3498db40;
                border-radius: 8px;
                padding: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #1a2a4e;
            }
        """)
        self.report_btn.clicked.connect(self.generate_report)
        self.report_btn.setEnabled(False)
        layout.addWidget(self.report_btn)
        
        return frame
        
    def setup_timers(self):
        """Setup update timers"""
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_progress)
        
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        
        self.runtime_start = None
        
    def configure_engagement(self):
        """Show configuration dialog"""
        dialog = TargetConfigDialog(self)
        if dialog.exec():
            config = dialog.get_config()
            self.initialize_agent(config)
            
    def initialize_agent(self, config: Dict):
        """Initialize agent with configuration"""
        from core.autonomous_agent import create_new_agent, RiskLevel
        
        self.agent = create_new_agent()
        
        # Set risk level
        risk_map = {
            "stealth": RiskLevel.STEALTH,
            "balanced": RiskLevel.BALANCED,
            "aggressive": RiskLevel.AGGRESSIVE,
            "maximum": RiskLevel.MAXIMUM,
        }
        self.agent.set_risk_level(risk_map.get(config.get("risk_level", "balanced"), RiskLevel.BALANCED))
        
        # Initialize engagement
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.agent.initialize_engagement({
                "targets": config.get("targets", []),
                "objectives": config.get("objectives", ["full_compromise"]),
            }))
        finally:
            loop.close()
            
        # Update UI
        self.agent_status.setText("🟡 INITIALIZED")
        self.agent_status.setStyleSheet("color: #f39c12; background: transparent;")
        self.state_label.setText(f"Ready - {len(config.get('targets', []))} targets in scope")
        
        self.start_btn.setEnabled(True)
        self.init_btn.setEnabled(False)
        
        # Show initial assets
        for asset in self.agent.discovered_assets.values():
            self.add_asset_widget(asset)
            
        self.update_stats()
        
        self.log_message("INFO", f"Agent initialized with {len(config.get('targets', []))} targets")
        
    def start_agent(self):
        """Start agent execution"""
        if not self.agent:
            return
            
        self.runtime_start = datetime.now()
        
        # Create worker thread
        self.worker = AgentWorker(self.agent)
        self.worker.state_changed.connect(self.on_state_changed)
        self.worker.task_started.connect(self.on_task_started)
        self.worker.task_completed.connect(self.on_task_completed)
        self.worker.log_entry.connect(self.on_log_entry)
        self.worker.asset_discovered.connect(self.on_asset_discovered)
        self.worker.asset_compromised.connect(self.on_asset_compromised)
        self.worker.finding_added.connect(self.on_finding_added)
        self.worker.execution_finished.connect(self.on_execution_finished)
        
        self.worker.start()
        
        # Update UI
        self.agent_status.setText("🟢 RUNNING")
        self.agent_status.setStyleSheet("color: #27ae60; background: transparent;")
        
        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        
        # Start timers
        self.progress_timer.start(100)
        self.stats_timer.start(1000)
        
        self.log_message("INFO", "🚀 Agent launched - autonomous operation started")
        
    def toggle_pause(self):
        """Toggle pause state"""
        if not self.agent:
            return
            
        if self.agent.paused:
            self.agent.resume()
            self.pause_btn.setText("⏸️ Pause")
            self.agent_status.setText("🟢 RUNNING")
            self.agent_status.setStyleSheet("color: #27ae60; background: transparent;")
            self.log_message("INFO", "▶️ Agent resumed")
        else:
            self.agent.pause()
            self.pause_btn.setText("▶️ Resume")
            self.agent_status.setText("🟡 PAUSED")
            self.agent_status.setStyleSheet("color: #f39c12; background: transparent;")
            self.log_message("INFO", "⏸️ Agent paused")
            
    def stop_agent(self):
        """Stop agent execution"""
        if not self.agent:
            return
            
        self.agent.stop()
        self.log_message("WARNING", "⏹️ Agent stop requested")
        
    def on_state_changed(self, old_state: str, new_state: str):
        """Handle state change"""
        self.state_label.setText(f"Phase: {new_state.replace('_', ' ').title()}")
        
        # Update phase indicators
        phase_map = {
            "reconnaissance": 0,
            "enumeration": 1,
            "exploitation": 2,
            "privilege_escalation": 3,
            "post_exploitation": 3,
            "lateral_movement": 4,
            "data_exfiltration": 5,
        }
        
        current_phase = phase_map.get(new_state, -1)
        for i, label in enumerate(self.phase_labels):
            if i < current_phase:
                label.setStyleSheet("""
                    color: #fff;
                    background: #27ae60;
                    padding: 5px 10px;
                    border-radius: 5px;
                    font-size: 10px;
                """)
            elif i == current_phase:
                label.setStyleSheet("""
                    color: #fff;
                    background: #f39c12;
                    padding: 5px 10px;
                    border-radius: 5px;
                    font-size: 10px;
                """)
            else:
                label.setStyleSheet("""
                    color: #555;
                    background: #1a1a2e;
                    padding: 5px 10px;
                    border-radius: 5px;
                    font-size: 10px;
                """)
                
    def on_task_started(self, task):
        """Handle task started"""
        self.current_task_label.setText(f"{task.name}\n{task.technique_id} - {task.tactic}")
        self.task_progress.setValue(0)
        
        self.log_message("INFO", f"🎯 Task started: {task.name}")
        self.update_task_list()
        
    def on_task_completed(self, task, success: bool):
        """Handle task completed"""
        if success:
            self.log_message("SUCCESS", f"✅ Task completed: {task.name}")
            if task.result.get("summary"):
                self.log_message("INFO", f"   └─ {task.result['summary']}")
        else:
            self.log_message("ERROR", f"❌ Task failed: {task.name}")
            
        self.current_task_label.setText("No task running")
        self.task_progress.setValue(100)
        self.update_task_list()
        self.update_path_progress()
        
    def on_log_entry(self, entry):
        """Handle log entry"""
        pass  # Handled by specific events
        
    def on_asset_discovered(self, asset):
        """Handle asset discovered"""
        self.add_asset_widget(asset)
        self.log_message("INFO", f"🖥️ Asset discovered: {asset.ip_address or asset.hostname}")
        
    def on_asset_compromised(self, asset):
        """Handle asset compromised"""
        self.log_message("SUCCESS", f"💀 Asset compromised: {asset.ip_address or asset.hostname}")
        # Refresh asset widgets
        self.refresh_assets()
        
    def on_finding_added(self, finding: Dict):
        """Handle finding added"""
        self.add_finding_widget(finding)
        self.log_message("WARNING", f"🔍 Finding: {finding.get('title', 'Unknown')}")
        
        # Add credentials to table
        if finding.get("category") == "credentials":
            details = finding.get("details", [])
            if isinstance(details, list):
                for username in details:
                    row = self.creds_table.rowCount()
                    self.creds_table.insertRow(row)
                    self.creds_table.setItem(row, 0, QTableWidgetItem("harvested"))
                    self.creds_table.setItem(row, 1, QTableWidgetItem(str(username)))
                    self.creds_table.setItem(row, 2, QTableWidgetItem("valid"))
                    
    def on_execution_finished(self):
        """Handle execution finished"""
        self.progress_timer.stop()
        self.stats_timer.stop()
        
        self.agent_status.setText("🔵 COMPLETED")
        self.agent_status.setStyleSheet("color: #3498db; background: transparent;")
        self.state_label.setText("Engagement completed")
        
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.report_btn.setEnabled(True)
        
        self.path_progress.setValue(100)
        
        self.log_message("SUCCESS", "=" * 50)
        self.log_message("SUCCESS", "🏆 ENGAGEMENT COMPLETED")
        self.log_message("SUCCESS", f"   Tasks: {self.agent.stats['tasks_completed']} completed, {self.agent.stats['tasks_failed']} failed")
        self.log_message("SUCCESS", f"   Assets: {len(self.agent.discovered_assets)} discovered, {self.agent.stats['assets_compromised']} compromised")
        self.log_message("SUCCESS", f"   Credentials: {len(self.agent.credentials_found)} harvested")
        self.log_message("SUCCESS", f"   Findings: {len(self.agent.findings)}")
        self.log_message("SUCCESS", "=" * 50)
        
    def add_asset_widget(self, asset):
        """Add asset widget to panel"""
        widget = AssetWidget(asset)
        self.assets_layout.insertWidget(self.assets_layout.count() - 1, widget)
        
    def add_finding_widget(self, finding: Dict):
        """Add finding widget to panel"""
        widget = FindingWidget(finding)
        self.findings_layout.insertWidget(self.findings_layout.count() - 1, widget)
        
    def refresh_assets(self):
        """Refresh all asset widgets"""
        # Clear existing
        while self.assets_layout.count() > 1:
            item = self.assets_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        # Re-add all
        if self.agent:
            for asset in self.agent.discovered_assets.values():
                self.add_asset_widget(asset)
                
    def update_task_list(self):
        """Update task list display"""
        if not self.agent:
            return
            
        # Clear existing
        while self.tasks_layout.count() > 1:
            item = self.tasks_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        # Add pending tasks
        for task in self.agent.task_queue[:10]:
            widget = TaskWidget(task)
            self.tasks_layout.insertWidget(self.tasks_layout.count() - 1, widget)
            
        self.task_count.setText(f"{len(self.agent.task_queue)} pending")
        
    def update_progress(self):
        """Update progress bar animation"""
        current = self.task_progress.value()
        if current < 95:
            self.task_progress.setValue(current + 1)
            
    def update_path_progress(self):
        """Update attack path progress"""
        if not self.agent or not self.agent.current_path:
            return
            
        total = len(self.agent.current_path.tasks)
        completed = len(self.agent.completed_tasks) + len(self.agent.failed_tasks)
        
        if total > 0:
            progress = int((completed / total) * 100)
            self.path_progress.setValue(progress)
            
    def update_stats(self):
        """Update statistics display"""
        if not self.agent:
            return
            
        self.stat_cards["Tasks Completed"].set_value(str(self.agent.stats["tasks_completed"]))
        self.stat_cards["Assets Discovered"].set_value(str(len(self.agent.discovered_assets)))
        self.stat_cards["Systems Compromised"].set_value(str(self.agent.stats["assets_compromised"]))
        self.stat_cards["Credentials Found"].set_value(str(len(self.agent.credentials_found)))
        self.stat_cards["Findings"].set_value(str(len(self.agent.findings)))
        
        # Runtime
        if self.runtime_start:
            elapsed = datetime.now() - self.runtime_start
            minutes = int(elapsed.total_seconds() // 60)
            seconds = int(elapsed.total_seconds() % 60)
            self.stat_cards["Runtime"].set_value(f"{minutes:02d}:{seconds:02d}")
            
    def log_message(self, level: str, message: str):
        """Add message to activity log"""
        colors = {
            "INFO": "#0f0",
            "SUCCESS": "#27ae60",
            "WARNING": "#f39c12",
            "ERROR": "#e74c3c",
        }
        color = colors.get(level, "#0f0")
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_log.append(
            f'<span style="color: #666">[{timestamp}]</span> '
            f'<span style="color: {color}">{message}</span>'
        )
        
        # Auto scroll
        scrollbar = self.activity_log.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def clear_log(self):
        """Clear activity log"""
        self.activity_log.clear()
        
    def generate_report(self):
        """Generate engagement report"""
        if not self.agent:
            return
            
        report = self.agent.generate_report()
        
        # Show report dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Engagement Report")
        dialog.setMinimumSize(800, 600)
        
        layout = QVBoxLayout(dialog)
        
        report_text = QTextEdit()
        report_text.setReadOnly(True)
        report_text.setStyleSheet("""
            QTextEdit {
                background: #0a0a15;
                color: #fff;
                border: none;
                font-family: 'Consolas', monospace;
                padding: 15px;
            }
        """)
        
        # Format report
        import json
        formatted = json.dumps(report, indent=2, default=str)
        report_text.setPlainText(formatted)
        
        layout.addWidget(report_text)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)
        
        dialog.exec()
