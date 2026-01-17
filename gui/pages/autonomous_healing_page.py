"""
Autonomous Healing Page
GUI for self-healing security with automatic remediation
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QGroupBox,
    QProgressBar, QSplitter, QFrame, QHeaderView, QTreeWidget,
    QTreeWidgetItem, QGridLayout, QComboBox, QTextEdit, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor
import asyncio


class HealingWorker(QThread):
    """Worker thread for healing operations"""
    progress = pyqtSignal(str, int)
    result = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, issue_id):
        super().__init__()
        self.issue_id = issue_id
        
    def run(self):
        try:
            from core.autonomous_healing import AutonomousHealing
            
            async def heal():
                healer = AutonomousHealing()
                return await healer.remediate_issue(self.issue_id)
                
            result = asyncio.run(heal())
            self.result.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class AutonomousHealingPage(QWidget):
    """Autonomous Healing Dashboard"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.healing_worker = None
        
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
                color: #00ff88;
            }
        """)
        
        # Create tabs
        self.tabs.addTab(self._create_issues_tab(), "🔧 Active Issues")
        self.tabs.addTab(self._create_remediation_tab(), "⚡ Remediation Queue")
        self.tabs.addTab(self._create_history_tab(), "📜 History")
        self.tabs.addTab(self._create_policies_tab(), "📋 Policies")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QWidget:
        """Create the page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a2f1a, stop:1 #0d1117);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🔧 Autonomous Security Healing")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            color: #e6e6e6;
        """)
        title_layout.addWidget(title)
        
        subtitle = QLabel("Self-Healing Security with Automatic Remediation")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.issues_count = self._create_stat_card("Active Issues", "8", "#ff6b6b")
        self.healing_count = self._create_stat_card("Auto-Healed", "142", "#00ff88")
        self.pending_count = self._create_stat_card("Pending Approval", "3", "#ffa500")
        
        stats_layout.addWidget(self.issues_count)
        stats_layout.addWidget(self.healing_count)
        stats_layout.addWidget(self.pending_count)
        
        layout.addLayout(stats_layout)
        
        # Scan button
        self.scan_btn = QPushButton("🔍 Scan Issues")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, stop:1 #00d4ff);
                color: #0d1117;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00d4ff, stop:1 #00ff88);
            }
        """)
        layout.addWidget(self.scan_btn)
        
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
        
    def _create_issues_tab(self) -> QWidget:
        """Create active issues tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Issues table
        self.issues_table = QTableWidget()
        self.issues_table.setColumnCount(7)
        self.issues_table.setHorizontalHeaderLabels([
            "Issue ID", "Type", "Severity", "Asset", "Detected", "Auto-Heal", "Actions"
        ])
        self.issues_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.issues_table.setStyleSheet("""
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
        layout.addWidget(self.issues_table)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        self.heal_selected_btn = QPushButton("🔧 Heal Selected")
        self.heal_selected_btn.setStyleSheet("""
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
        btn_layout.addWidget(self.heal_selected_btn)
        
        self.heal_all_btn = QPushButton("⚡ Heal All Auto-Approved")
        self.heal_all_btn.setStyleSheet("""
            QPushButton {
                background: #1f6feb;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background: #388bfd; }
        """)
        btn_layout.addWidget(self.heal_all_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        return widget
        
    def _create_remediation_tab(self) -> QWidget:
        """Create remediation queue tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Queue table
        self.queue_table = QTableWidget()
        self.queue_table.setColumnCount(6)
        self.queue_table.setHorizontalHeaderLabels([
            "Issue", "Action", "Risk Level", "Rollback", "Status", "Approve"
        ])
        self.queue_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.queue_table.setStyleSheet("""
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
        layout.addWidget(self.queue_table)
        
        return widget
        
    def _create_history_tab(self) -> QWidget:
        """Create remediation history tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(7)
        self.history_table.setHorizontalHeaderLabels([
            "Issue ID", "Type", "Action", "Executed", "Duration", "Result", "Rollback"
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.setStyleSheet("""
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
        layout.addWidget(self.history_table)
        
        return widget
        
    def _create_policies_tab(self) -> QWidget:
        """Create healing policies tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Policies group
        policies_group = QGroupBox("Healing Policies")
        policies_group.setStyleSheet("""
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
        policies_layout = QVBoxLayout(policies_group)
        
        policies = [
            ("Auto-heal misconfigurations", "Automatically fix S3 buckets, security groups, IAM", True),
            ("Patch critical vulnerabilities", "Apply patches for CVSS 9.0+ within 24 hours", True),
            ("Rotate expired credentials", "Automatically rotate expiring certificates and keys", True),
            ("Block malicious IPs", "Auto-block IPs flagged by threat intelligence", True),
            ("Isolate compromised hosts", "Quarantine hosts showing IOC matches", False),
            ("Require approval for high-risk", "Human approval for production changes", True),
        ]
        
        for name, desc, enabled in policies:
            policy_widget = self._create_policy_widget(name, desc, enabled)
            policies_layout.addWidget(policy_widget)
            
        layout.addWidget(policies_group)
        layout.addStretch()
        
        return widget
        
    def _create_policy_widget(self, name: str, desc: str, enabled: bool) -> QFrame:
        """Create policy toggle widget"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        text_layout = QVBoxLayout()
        name_label = QLabel(name)
        name_label.setStyleSheet("color: #e6e6e6; font-weight: bold;")
        text_layout.addWidget(name_label)
        
        desc_label = QLabel(desc)
        desc_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        text_layout.addWidget(desc_label)
        
        layout.addLayout(text_layout)
        layout.addStretch()
        
        toggle = QCheckBox()
        toggle.setChecked(enabled)
        toggle.setStyleSheet("""
            QCheckBox::indicator {
                width: 40px;
                height: 20px;
                border-radius: 10px;
                background: #30363d;
            }
            QCheckBox::indicator:checked {
                background: #00ff88;
            }
        """)
        layout.addWidget(toggle)
        
        return frame
        
    def _connect_signals(self):
        """Connect signals and slots"""
        self.scan_btn.clicked.connect(self._scan_issues)
        self.heal_selected_btn.clicked.connect(self._heal_selected)
        self.heal_all_btn.clicked.connect(self._heal_all)
        
    def _scan_issues(self):
        """Scan for security issues"""
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("🔄 Scanning...")
        
        QTimer.singleShot(2000, self._scan_complete)
        
    def _scan_complete(self):
        """Handle scan completion"""
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("🔍 Scan Issues")
        
    def _heal_selected(self):
        """Heal selected issues"""
        pass
        
    def _heal_all(self):
        """Heal all auto-approved issues"""
        pass
        
    def _load_demo_data(self):
        """Load demonstration data"""
        # Active issues
        issues = [
            ("ISS-001", "Misconfiguration", "🔴 Critical", "s3-bucket-prod", "5 min ago", "✅ Yes", "🔧"),
            ("ISS-002", "Vulnerability", "🔴 Critical", "web-server-01", "12 min ago", "⏳ Pending", "🔧"),
            ("ISS-003", "Exposed Service", "🟠 High", "ssh-server", "1 hour ago", "✅ Yes", "🔧"),
            ("ISS-004", "Weak Credentials", "🟠 High", "admin-account", "2 hours ago", "✅ Yes", "🔧"),
            ("ISS-005", "Expired Cert", "🟡 Medium", "api-gateway", "3 hours ago", "✅ Yes", "🔧"),
            ("ISS-006", "Malware Detected", "🔴 Critical", "workstation-15", "15 min ago", "⏳ Pending", "🔧"),
            ("ISS-007", "Config Drift", "🟡 Medium", "firewall-rules", "30 min ago", "✅ Yes", "🔧"),
            ("ISS-008", "Excessive Permissions", "🟠 High", "iam-role-dev", "45 min ago", "✅ Yes", "🔧"),
        ]
        
        self.issues_table.setRowCount(len(issues))
        for row, issue in enumerate(issues):
            for col, value in enumerate(issue):
                item = QTableWidgetItem(value)
                if col == 2:  # Severity
                    if "Critical" in value:
                        item.setForeground(QColor("#ff6b6b"))
                    elif "High" in value:
                        item.setForeground(QColor("#ffa500"))
                self.issues_table.setItem(row, col, item)
                
        # Queue
        queue = [
            ("ISS-002", "Apply CVE-2024-1234 patch", "High", "Available", "⏳ Awaiting Approval", "✅"),
            ("ISS-006", "Isolate and quarantine", "Critical", "Available", "⏳ Awaiting Approval", "✅"),
            ("ISS-001", "Enable bucket encryption", "Low", "Available", "🔄 In Progress", "—"),
        ]
        
        self.queue_table.setRowCount(len(queue))
        for row, q in enumerate(queue):
            for col, value in enumerate(q):
                item = QTableWidgetItem(value)
                self.queue_table.setItem(row, col, item)
                
        # History
        history = [
            ("ISS-099", "Misconfiguration", "Fixed S3 ACL", "Today 10:30", "2.3s", "✅ Success", "🔙"),
            ("ISS-098", "Vulnerability", "Patched CVE-2024-0001", "Today 09:15", "45.2s", "✅ Success", "🔙"),
            ("ISS-097", "Expired Cert", "Rotated TLS cert", "Yesterday", "5.1s", "✅ Success", "🔙"),
            ("ISS-096", "Weak Password", "Forced reset", "Yesterday", "1.2s", "✅ Success", "🔙"),
            ("ISS-095", "Malware", "Quarantined host", "2 days ago", "0.8s", "✅ Success", "🔙"),
        ]
        
        self.history_table.setRowCount(len(history))
        for row, h in enumerate(history):
            for col, value in enumerate(h):
                item = QTableWidgetItem(value)
                self.history_table.setItem(row, col, item)
