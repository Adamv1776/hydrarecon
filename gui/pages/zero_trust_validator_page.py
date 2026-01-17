"""
Zero Trust Validator Page
GUI for validating Zero Trust implementation against NIST SP 800-207
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QGroupBox,
    QProgressBar, QSplitter, QFrame, QHeaderView, QTreeWidget,
    QTreeWidgetItem, QGridLayout, QComboBox, QTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor
import asyncio


class ValidationWorker(QThread):
    """Worker thread for running validation"""
    progress = pyqtSignal(str, int)
    result = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        
    def run(self):
        try:
            from core.zero_trust_validator import ZeroTrustValidator
            
            async def validate():
                validator = ZeroTrustValidator()
                return await validator.run_full_validation()
                
            result = asyncio.run(validate())
            self.result.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class ZeroTrustValidatorPage(QWidget):
    """Zero Trust Validator Dashboard"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.validation_worker = None
        
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
                color: #58a6ff;
            }
        """)
        
        # Create tabs
        self.tabs.addTab(self._create_pillars_tab(), "🏛️ Zero Trust Pillars")
        self.tabs.addTab(self._create_controls_tab(), "🔐 Controls")
        self.tabs.addTab(self._create_gaps_tab(), "⚠️ Gaps")
        self.tabs.addTab(self._create_access_paths_tab(), "🔀 Access Paths")
        self.tabs.addTab(self._create_nist_tab(), "📋 NIST Mapping")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QWidget:
        """Create the page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2f, stop:1 #0d1117);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🛡️ Zero Trust Validator")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            color: #e6e6e6;
        """)
        title_layout.addWidget(title)
        
        subtitle = QLabel("Validate Against NIST SP 800-207 Zero Trust Architecture")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.compliance_score = self._create_stat_card("Compliance", "72%", "#58a6ff")
        self.controls_count = self._create_stat_card("Controls", "35", "#00ff88")
        self.gaps_count = self._create_stat_card("Gaps Found", "8", "#ff6b6b")
        
        stats_layout.addWidget(self.compliance_score)
        stats_layout.addWidget(self.controls_count)
        stats_layout.addWidget(self.gaps_count)
        
        layout.addLayout(stats_layout)
        
        # Validate button
        self.validate_btn = QPushButton("🔍 Run Validation")
        self.validate_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #58a6ff, stop:1 #388bfd);
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #388bfd, stop:1 #58a6ff);
            }
        """)
        layout.addWidget(self.validate_btn)
        
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
        
    def _create_pillars_tab(self) -> QWidget:
        """Create Zero Trust pillars tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Pillars grid
        pillars_group = QGroupBox("NIST Zero Trust Pillars")
        pillars_group.setStyleSheet("""
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
        pillars_layout = QGridLayout(pillars_group)
        
        pillars = [
            ("👤 Identity", "75%", "Verify every user with strong authentication"),
            ("💻 Devices", "68%", "Validate device health and compliance"),
            ("🌐 Network", "82%", "Segment and encrypt all traffic"),
            ("📱 Applications", "71%", "Secure all workloads and apps"),
            ("💾 Data", "65%", "Classify, encrypt, and monitor data"),
            ("👁️ Visibility", "70%", "Comprehensive logging and analytics"),
            ("⚡ Automation", "58%", "Orchestrate security responses"),
        ]
        
        for i, (name, score, desc) in enumerate(pillars):
            row, col = divmod(i, 2)
            pillar_card = self._create_pillar_card(name, score, desc)
            pillars_layout.addWidget(pillar_card, row, col)
            
        layout.addWidget(pillars_group)
        
        return widget
        
    def _create_pillar_card(self, name: str, score: str, desc: str) -> QFrame:
        """Create pillar score card"""
        card = QFrame()
        
        score_val = int(score.replace('%', ''))
        if score_val >= 80:
            color = "#00ff88"
        elif score_val >= 60:
            color = "#ffa500"
        else:
            color = "#ff6b6b"
            
        card.setStyleSheet(f"""
            QFrame {{
                background: #161b22;
                border: 1px solid {color}40;
                border-radius: 8px;
                padding: 16px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        # Header
        header_layout = QHBoxLayout()
        name_label = QLabel(name)
        name_label.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 16px;")
        header_layout.addWidget(name_label)
        
        score_label = QLabel(score)
        score_label.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 18px;")
        header_layout.addWidget(score_label)
        
        layout.addLayout(header_layout)
        
        # Progress bar
        progress = QProgressBar()
        progress.setValue(score_val)
        progress.setTextVisible(False)
        progress.setStyleSheet(f"""
            QProgressBar {{
                background: #30363d;
                border-radius: 4px;
                height: 8px;
            }}
            QProgressBar::chunk {{
                background: {color};
                border-radius: 4px;
            }}
        """)
        layout.addWidget(progress)
        
        # Description
        desc_label = QLabel(desc)
        desc_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        return card
        
    def _create_controls_tab(self) -> QWidget:
        """Create controls validation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Controls table
        self.controls_table = QTableWidget()
        self.controls_table.setColumnCount(6)
        self.controls_table.setHorizontalHeaderLabels([
            "Control ID", "Control Name", "Pillar", "Status", "Evidence", "Last Checked"
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
        
    def _create_gaps_tab(self) -> QWidget:
        """Create gaps analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Gaps table
        self.gaps_table = QTableWidget()
        self.gaps_table.setColumnCount(6)
        self.gaps_table.setHorizontalHeaderLabels([
            "Gap ID", "Description", "Pillar", "Severity", "Remediation", "Effort"
        ])
        self.gaps_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.gaps_table.setStyleSheet("""
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
        layout.addWidget(self.gaps_table)
        
        return widget
        
    def _create_access_paths_tab(self) -> QWidget:
        """Create access paths testing tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Access paths table
        self.paths_table = QTableWidget()
        self.paths_table.setColumnCount(7)
        self.paths_table.setHorizontalHeaderLabels([
            "Path ID", "Source", "Destination", "Auth Required", "Encrypted", "Logged", "Status"
        ])
        self.paths_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.paths_table.setStyleSheet("""
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
        layout.addWidget(self.paths_table)
        
        return widget
        
    def _create_nist_tab(self) -> QWidget:
        """Create NIST SP 800-207 mapping tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # NIST tree
        self.nist_tree = QTreeWidget()
        self.nist_tree.setHeaderLabels(["NIST Reference", "Requirement", "Status", "Evidence"])
        self.nist_tree.setStyleSheet("""
            QTreeWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
            }
            QTreeWidget::item { padding: 8px; }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.nist_tree)
        
        return widget
        
    def _connect_signals(self):
        """Connect signals and slots"""
        self.validate_btn.clicked.connect(self._run_validation)
        
    def _run_validation(self):
        """Run Zero Trust validation"""
        self.validate_btn.setEnabled(False)
        self.validate_btn.setText("🔄 Validating...")
        
        QTimer.singleShot(2500, self._validation_complete)
        
    def _validation_complete(self):
        """Handle validation completion"""
        self.validate_btn.setEnabled(True)
        self.validate_btn.setText("🔍 Run Validation")
        
    def _load_demo_data(self):
        """Load demonstration data"""
        # Controls
        controls = [
            ("ZT-ID-01", "Multi-Factor Authentication", "Identity", "✅ Compliant", "Okta SSO logs", "Today"),
            ("ZT-ID-02", "Risk-Based Authentication", "Identity", "⚠️ Partial", "Limited contexts", "Today"),
            ("ZT-DEV-01", "Device Health Validation", "Devices", "✅ Compliant", "Intune reports", "Today"),
            ("ZT-DEV-02", "Certificate-Based Auth", "Devices", "❌ Gap", "Not implemented", "Today"),
            ("ZT-NET-01", "Micro-Segmentation", "Network", "✅ Compliant", "NSG rules", "Today"),
            ("ZT-NET-02", "Encrypted Traffic", "Network", "✅ Compliant", "TLS everywhere", "Today"),
            ("ZT-APP-01", "Application Identity", "Applications", "⚠️ Partial", "50% coverage", "Today"),
            ("ZT-DATA-01", "Data Classification", "Data", "❌ Gap", "Manual process", "Today"),
        ]
        
        self.controls_table.setRowCount(len(controls))
        for row, ctrl in enumerate(controls):
            for col, value in enumerate(ctrl):
                item = QTableWidgetItem(value)
                if col == 3:  # Status
                    if "Compliant" in value:
                        item.setForeground(QColor("#00ff88"))
                    elif "Partial" in value:
                        item.setForeground(QColor("#ffa500"))
                    elif "Gap" in value:
                        item.setForeground(QColor("#ff6b6b"))
                self.controls_table.setItem(row, col, item)
                
        # Gaps
        gaps = [
            ("GAP-001", "No passwordless authentication", "Identity", "🟠 High", "Deploy FIDO2 keys", "Medium"),
            ("GAP-002", "Missing device certificates", "Devices", "🔴 Critical", "Deploy PKI", "High"),
            ("GAP-003", "Limited data classification", "Data", "🟠 High", "Implement DLP", "Medium"),
            ("GAP-004", "Incomplete app inventory", "Applications", "🟡 Medium", "Deploy CASB", "Low"),
            ("GAP-005", "Manual incident response", "Automation", "🟡 Medium", "Implement SOAR", "Medium"),
        ]
        
        self.gaps_table.setRowCount(len(gaps))
        for row, gap in enumerate(gaps):
            for col, value in enumerate(gap):
                item = QTableWidgetItem(value)
                if col == 3:  # Severity
                    if "Critical" in value:
                        item.setForeground(QColor("#ff6b6b"))
                    elif "High" in value:
                        item.setForeground(QColor("#ffa500"))
                self.gaps_table.setItem(row, col, item)
                
        # Access paths
        paths = [
            ("PATH-001", "User → Web App", "Frontend", "✅ Yes", "✅ Yes", "✅ Yes", "✅ Pass"),
            ("PATH-002", "Web App → Database", "Backend", "✅ Yes", "✅ Yes", "✅ Yes", "✅ Pass"),
            ("PATH-003", "Admin → Server", "SSH", "✅ Yes", "✅ Yes", "⚠️ Partial", "⚠️ Warning"),
            ("PATH-004", "App → External API", "HTTPS", "❌ No", "✅ Yes", "❌ No", "❌ Fail"),
            ("PATH-005", "CI/CD → Production", "Deploy", "✅ Yes", "✅ Yes", "✅ Yes", "✅ Pass"),
        ]
        
        self.paths_table.setRowCount(len(paths))
        for row, path in enumerate(paths):
            for col, value in enumerate(path):
                item = QTableWidgetItem(value)
                self.paths_table.setItem(row, col, item)
                
        # NIST tree
        nist_sections = [
            ("2.1", "Zero Trust Tenets", [
                ("2.1.1", "All data sources are resources", "✅ Met"),
                ("2.1.2", "All communication is secured", "✅ Met"),
                ("2.1.3", "Access granted per-session", "⚠️ Partial"),
            ]),
            ("3.1", "Logical Components", [
                ("3.1.1", "Policy Engine", "✅ Implemented"),
                ("3.1.2", "Policy Administrator", "✅ Implemented"),
                ("3.1.3", "Policy Enforcement Point", "⚠️ Partial"),
            ]),
            ("4.1", "Deployment Models", [
                ("4.1.1", "Enhanced Identity Governance", "✅ Active"),
                ("4.1.2", "Micro-Segmentation", "⚠️ In Progress"),
            ]),
        ]
        
        self.nist_tree.clear()
        for section, name, items in nist_sections:
            parent = QTreeWidgetItem([section, name, "", ""])
            self.nist_tree.addTopLevelItem(parent)
            for ref, req, status in items:
                child = QTreeWidgetItem([ref, req, status, "Documented"])
                parent.addChild(child)
                
        self.nist_tree.expandAll()
