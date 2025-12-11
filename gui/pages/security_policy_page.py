"""
HydraRecon Security Policy Manager Page
Enterprise policy creation, enforcement, and compliance tracking
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QTextEdit,
    QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QTabWidget, QSplitter, QTreeWidget, QTreeWidgetItem,
    QGroupBox, QSpinBox, QCheckBox, QProgressBar, QMenu,
    QDialog, QDialogButtonBox, QFormLayout, QMessageBox,
    QListWidget, QListWidgetItem, QStackedWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QThread
from PyQt6.QtGui import QFont, QColor, QAction, QIcon
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import asyncio
import json


class SecurityPolicyPage(QWidget):
    """Security Policy Manager Page"""
    
    policy_selected = pyqtSignal(str)  # Policy ID
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.policies = {}
        
        self._setup_ui()
        self._connect_signals()
        self._apply_styles()
        self._load_sample_data()
    
    def _setup_ui(self):
        """Setup the policy manager interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        
        # Policies tab
        policies_tab = self._create_policies_tab()
        self.tab_widget.addTab(policies_tab, "📋 Policies")
        
        # Controls tab
        controls_tab = self._create_controls_tab()
        self.tab_widget.addTab(controls_tab, "🎛️ Controls")
        
        # Compliance tab
        compliance_tab = self._create_compliance_tab()
        self.tab_widget.addTab(compliance_tab, "✅ Compliance")
        
        # Exceptions tab
        exceptions_tab = self._create_exceptions_tab()
        self.tab_widget.addTab(exceptions_tab, "⚠️ Exceptions")
        
        # Violations tab
        violations_tab = self._create_violations_tab()
        self.tab_widget.addTab(violations_tab, "🚨 Violations")
        
        layout.addWidget(self.tab_widget)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:1 #16213e);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("📜 Security Policy Manager")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Create, manage, and enforce security policies across your organization")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(16)
        
        self.policies_label = self._create_stat_card("Policies", "0", "#00d4ff")
        stats_layout.addWidget(self.policies_label)
        
        self.controls_label = self._create_stat_card("Controls", "0", "#00ff88")
        stats_layout.addWidget(self.controls_label)
        
        self.compliance_label = self._create_stat_card("Compliance", "0%", "#ffd700")
        stats_layout.addWidget(self.compliance_label)
        
        self.violations_label = self._create_stat_card("Violations", "0", "#ff6b6b")
        stats_layout.addWidget(self.violations_label)
        
        layout.addLayout(stats_layout)
        
        # Action buttons
        btn_layout = QVBoxLayout()
        
        new_policy_btn = QPushButton("➕ New Policy")
        new_policy_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        new_policy_btn.clicked.connect(self._show_new_policy_dialog)
        btn_layout.addWidget(new_policy_btn)
        
        audit_btn = QPushButton("🔍 Run Audit")
        audit_btn.setStyleSheet("""
            QPushButton {
                background: #1f6feb;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #388bfd;
            }
        """)
        btn_layout.addWidget(audit_btn)
        
        layout.addLayout(btn_layout)
        
        return header
    
    def _create_stat_card(self, title: str, value: str, color: str) -> QFrame:
        """Create a statistics card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid {color}40;
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        card.setFixedWidth(110)
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value_label)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #8b949e; font-size: 11px;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        card.value_label = value_label
        
        return card
    
    def _create_policies_tab(self) -> QWidget:
        """Create Policies tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        search = QLineEdit()
        search.setPlaceholderText("🔍 Search policies...")
        search.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
            }
        """)
        toolbar.addWidget(search, stretch=2)
        
        type_filter = QComboBox()
        type_filter.addItems([
            "All Types", "Password", "Access Control", "Data Classification",
            "Network Security", "Incident Response", "Cloud Security"
        ])
        type_filter.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
            }
        """)
        toolbar.addWidget(type_filter)
        
        status_filter = QComboBox()
        status_filter.addItems(["All Status", "Active", "Draft", "Under Review", "Deprecated"])
        status_filter.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
            }
        """)
        toolbar.addWidget(status_filter)
        
        layout.addLayout(toolbar)
        
        # Policies table
        self.policies_table = QTableWidget()
        self.policies_table.setColumnCount(9)
        self.policies_table.setHorizontalHeaderLabels([
            "Policy ID", "Name", "Type", "Version", "Status",
            "Owner", "Controls", "Review Date", "Actions"
        ])
        self.policies_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.policies_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 10px;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        self.policies_table.doubleClicked.connect(self._show_policy_details)
        layout.addWidget(self.policies_table)
        
        return widget
    
    def _create_controls_tab(self) -> QWidget:
        """Create Controls tab"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        
        # Left panel - policy tree
        left_panel = QFrame()
        left_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border-radius: 8px;
            }
        """)
        left_layout = QVBoxLayout(left_panel)
        
        tree_label = QLabel("📋 Policy Structure")
        tree_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        tree_label.setStyleSheet("color: #00d4ff; padding: 12px;")
        left_layout.addWidget(tree_label)
        
        self.policy_tree = QTreeWidget()
        self.policy_tree.setHeaderLabels(["Policy / Control"])
        self.policy_tree.setStyleSheet("""
            QTreeWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
            }
            QTreeWidget::item {
                padding: 8px;
            }
            QTreeWidget::item:selected {
                background: #1f6feb30;
            }
        """)
        self.policy_tree.currentItemChanged.connect(self._on_control_selected)
        left_layout.addWidget(self.policy_tree)
        
        layout.addWidget(left_panel)
        
        # Right panel - control details
        right_panel = QFrame()
        right_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border-radius: 8px;
            }
        """)
        right_layout = QVBoxLayout(right_panel)
        
        details_label = QLabel("🎛️ Control Details")
        details_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        details_label.setStyleSheet("color: #00d4ff; padding: 12px;")
        right_layout.addWidget(details_label)
        
        # Control details form
        details_frame = QFrame()
        details_frame.setStyleSheet("""
            QFrame {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        form_layout = QFormLayout(details_frame)
        form_layout.setSpacing(12)
        
        self.control_id_label = QLabel("N/A")
        self.control_id_label.setStyleSheet("color: #00d4ff;")
        form_layout.addRow("Control ID:", self.control_id_label)
        
        self.control_title_label = QLabel("Select a control")
        self.control_title_label.setStyleSheet("color: #c9d1d9;")
        form_layout.addRow("Title:", self.control_title_label)
        
        self.control_enforcement_label = QLabel("N/A")
        form_layout.addRow("Enforcement:", self.control_enforcement_label)
        
        self.control_risk_label = QLabel("N/A")
        form_layout.addRow("Risk Level:", self.control_risk_label)
        
        self.control_nist_label = QLabel("N/A")
        form_layout.addRow("NIST Control:", self.control_nist_label)
        
        self.control_pci_label = QLabel("N/A")
        form_layout.addRow("PCI Requirement:", self.control_pci_label)
        
        self.control_automated_label = QLabel("No")
        form_layout.addRow("Automated Check:", self.control_automated_label)
        
        right_layout.addWidget(details_frame)
        
        # Description
        desc_label = QLabel("Description:")
        desc_label.setStyleSheet("color: #8b949e;")
        right_layout.addWidget(desc_label)
        
        self.control_desc = QTextEdit()
        self.control_desc.setReadOnly(True)
        self.control_desc.setMaximumHeight(100)
        self.control_desc.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
            }
        """)
        right_layout.addWidget(self.control_desc)
        
        right_layout.addStretch()
        
        layout.addWidget(right_panel, stretch=2)
        
        return widget
    
    def _create_compliance_tab(self) -> QWidget:
        """Create Compliance tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Summary cards
        summary_layout = QHBoxLayout()
        
        for title, value, color, icon in [
            ("Compliant", "85%", "#00ff88", "✅"),
            ("Non-Compliant", "8%", "#ff6b6b", "❌"),
            ("Partial", "5%", "#ffa500", "⚠️"),
            ("Pending Review", "2%", "#00d4ff", "🔍")
        ]:
            card = self._create_compliance_card(title, value, color, icon)
            summary_layout.addWidget(card)
        
        layout.addLayout(summary_layout)
        
        # Compliance by framework
        frameworks_frame = QFrame()
        frameworks_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        frameworks_layout = QVBoxLayout(frameworks_frame)
        
        fw_label = QLabel("📊 Compliance by Framework")
        fw_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        fw_label.setStyleSheet("color: #00d4ff;")
        frameworks_layout.addWidget(fw_label)
        
        # Framework progress bars
        frameworks = [
            ("NIST 800-53", 92),
            ("PCI-DSS", 88),
            ("ISO 27001", 85),
            ("SOC 2", 90),
            ("HIPAA", 78),
            ("GDPR", 82)
        ]
        
        for name, progress in frameworks:
            fw_row = QHBoxLayout()
            
            name_label = QLabel(name)
            name_label.setFixedWidth(120)
            name_label.setStyleSheet("color: #c9d1d9;")
            fw_row.addWidget(name_label)
            
            progress_bar = QProgressBar()
            progress_bar.setValue(progress)
            progress_bar.setTextVisible(True)
            progress_bar.setFormat(f"{progress}%")
            
            color = "#00ff88" if progress >= 90 else "#ffd700" if progress >= 80 else "#ff6b6b"
            progress_bar.setStyleSheet(f"""
                QProgressBar {{
                    background: #21262d;
                    border: none;
                    border-radius: 4px;
                    height: 20px;
                }}
                QProgressBar::chunk {{
                    background: {color};
                    border-radius: 4px;
                }}
            """)
            fw_row.addWidget(progress_bar)
            
            frameworks_layout.addLayout(fw_row)
        
        layout.addWidget(frameworks_frame)
        
        # Compliance checks table
        self.compliance_table = QTableWidget()
        self.compliance_table.setColumnCount(7)
        self.compliance_table.setHorizontalHeaderLabels([
            "Policy", "Control", "Target", "Status", "Last Check", "Evidence", "Actions"
        ])
        self.compliance_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.compliance_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 10px;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.compliance_table)
        
        return widget
    
    def _create_compliance_card(self, title: str, value: str, color: str, icon: str) -> QFrame:
        """Create a compliance summary card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #161b22;
                border: 1px solid {color}40;
                border-radius: 8px;
                padding: 16px;
            }}
        """)
        
        layout = QHBoxLayout(card)
        
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI", 24))
        layout.addWidget(icon_label)
        
        text_layout = QVBoxLayout()
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        text_layout.addWidget(value_label)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #8b949e;")
        text_layout.addWidget(title_label)
        
        layout.addLayout(text_layout)
        
        return card
    
    def _create_exceptions_tab(self) -> QWidget:
        """Create Exceptions tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        new_exception_btn = QPushButton("➕ Request Exception")
        new_exception_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        new_exception_btn.clicked.connect(self._show_exception_dialog)
        toolbar.addWidget(new_exception_btn)
        
        toolbar.addStretch()
        
        status_filter = QComboBox()
        status_filter.addItems(["All Status", "Pending", "Approved", "Rejected", "Expired"])
        status_filter.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        toolbar.addWidget(status_filter)
        
        layout.addLayout(toolbar)
        
        # Exceptions table
        self.exceptions_table = QTableWidget()
        self.exceptions_table.setColumnCount(9)
        self.exceptions_table.setHorizontalHeaderLabels([
            "Exception ID", "Policy", "Control", "Requestor", "Status",
            "Start Date", "End Date", "Approved By", "Actions"
        ])
        self.exceptions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.exceptions_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 10px;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.exceptions_table)
        
        return widget
    
    def _create_violations_tab(self) -> QWidget:
        """Create Violations tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Summary
        summary = QHBoxLayout()
        
        for title, count, color in [
            ("Open", 3, "#ff6b6b"),
            ("Under Investigation", 2, "#ffa500"),
            ("Resolved", 15, "#00ff88"),
            ("Total (30 days)", 20, "#00d4ff")
        ]:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background: #161b22;
                    border: 1px solid {color}40;
                    border-radius: 8px;
                    padding: 16px;
                }}
            """)
            card_layout = QVBoxLayout(card)
            
            count_label = QLabel(str(count))
            count_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
            count_label.setStyleSheet(f"color: {color};")
            count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_layout.addWidget(count_label)
            
            title_label = QLabel(title)
            title_label.setStyleSheet("color: #8b949e;")
            title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_layout.addWidget(title_label)
            
            summary.addWidget(card)
        
        layout.addLayout(summary)
        
        # Violations table
        self.violations_table = QTableWidget()
        self.violations_table.setColumnCount(9)
        self.violations_table.setHorizontalHeaderLabels([
            "ID", "Policy", "Violator", "Description", "Severity",
            "Detected", "Status", "Assigned To", "Actions"
        ])
        self.violations_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.violations_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 10px;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.violations_table)
        
        return widget
    
    def _connect_signals(self):
        """Connect signals"""
        pass
    
    def _apply_styles(self):
        """Apply consistent styling"""
        self.setStyleSheet("""
            QWidget {
                background: #0d1117;
                color: #c9d1d9;
            }
            QTabWidget::pane {
                border: none;
                background: transparent;
            }
            QTabBar::tab {
                background: #161b22;
                color: #8b949e;
                padding: 12px 24px;
                margin-right: 4px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background: #21262d;
                color: #00d4ff;
            }
            QTabBar::tab:hover:!selected {
                background: #1c2128;
            }
        """)
    
    def _load_sample_data(self):
        """Load sample data for demonstration"""
        # Sample policies
        policies = [
            ("POL-001", "Password Security Policy", "Password", "1.0", "Active", "CISO", 5, "2024-06-15"),
            ("POL-002", "Access Control Policy", "Access Control", "1.0", "Active", "CISO", 4, "2024-07-01"),
            ("POL-003", "Data Classification Policy", "Data Classification", "1.0", "Active", "DPO", 4, "2024-06-20"),
            ("POL-004", "Network Security Policy", "Network Security", "2.1", "Active", "Network Ops", 6, "2024-05-30"),
            ("POL-005", "Incident Response Policy", "Incident Response", "1.2", "Active", "SOC Lead", 8, "2024-04-15"),
            ("POL-006", "Cloud Security Policy", "Cloud Security", "1.0", "Draft", "Cloud Architect", 10, "2024-08-01"),
            ("POL-007", "Remote Access Policy", "Remote Access", "1.5", "Under Review", "IT Director", 5, "2024-03-30")
        ]
        
        self.policies_table.setRowCount(len(policies))
        
        for row, policy in enumerate(policies):
            for col, value in enumerate(policy):
                item = QTableWidgetItem(str(value))
                
                if col == 4:  # Status
                    colors = {
                        "Active": "#00ff88", "Draft": "#6e7681",
                        "Under Review": "#ffa500", "Deprecated": "#ff6b6b"
                    }
                    item.setForeground(QColor(colors.get(value, "#c9d1d9")))
                
                self.policies_table.setItem(row, col, item)
            
            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)
            
            view_btn = QPushButton("👁️")
            view_btn.setFixedSize(28, 28)
            view_btn.setStyleSheet("background: #1f6feb; border: none; border-radius: 4px;")
            actions_layout.addWidget(view_btn)
            
            edit_btn = QPushButton("✏️")
            edit_btn.setFixedSize(28, 28)
            edit_btn.setStyleSheet("background: #238636; border: none; border-radius: 4px;")
            actions_layout.addWidget(edit_btn)
            
            self.policies_table.setCellWidget(row, 8, actions_widget)
        
        # Load policy tree
        self._load_policy_tree()
        
        # Load compliance data
        self._load_compliance_data()
        
        # Load exceptions data
        self._load_exceptions_data()
        
        # Load violations data
        self._load_violations_data()
        
        # Update stats
        total_controls = sum(int(p[6]) for p in policies)
        self.policies_label.value_label.setText(str(len(policies)))
        self.controls_label.value_label.setText(str(total_controls))
        self.compliance_label.value_label.setText("85%")
        self.violations_label.value_label.setText("3")
    
    def _load_policy_tree(self):
        """Load policy tree structure"""
        self.policy_tree.clear()
        
        policies_data = [
            ("📋 Password Security Policy (POL-001)", [
                ("🎛️ POL-001-C01: Minimum Password Length", "Mandatory", "High"),
                ("🎛️ POL-001-C02: Password Complexity", "Mandatory", "High"),
                ("🎛️ POL-001-C03: Password Expiration", "Mandatory", "Medium"),
                ("🎛️ POL-001-C04: Password History", "Mandatory", "Medium"),
                ("🎛️ POL-001-C05: Multi-Factor Authentication", "Mandatory", "Critical")
            ]),
            ("📋 Access Control Policy (POL-002)", [
                ("🎛️ POL-002-C01: Principle of Least Privilege", "Mandatory", "High"),
                ("🎛️ POL-002-C02: Role-Based Access Control", "Mandatory", "High"),
                ("🎛️ POL-002-C03: Access Review", "Mandatory", "Medium"),
                ("🎛️ POL-002-C04: Termination Access Removal", "Mandatory", "Critical")
            ]),
            ("📋 Data Classification Policy (POL-003)", [
                ("🎛️ POL-003-C01: Data Classification Levels", "Mandatory", "High"),
                ("🎛️ POL-003-C02: Data Labeling", "Mandatory", "Medium"),
                ("🎛️ POL-003-C03: Data Encryption at Rest", "Mandatory", "Critical"),
                ("🎛️ POL-003-C04: Data Encryption in Transit", "Mandatory", "Critical")
            ])
        ]
        
        for policy_name, controls in policies_data:
            policy_item = QTreeWidgetItem(self.policy_tree, [policy_name])
            policy_item.setExpanded(True)
            
            for control_name, enforcement, risk in controls:
                control_item = QTreeWidgetItem(policy_item, [control_name])
                control_item.setData(0, Qt.ItemDataRole.UserRole, {
                    "enforcement": enforcement,
                    "risk": risk
                })
    
    def _load_compliance_data(self):
        """Load compliance check data"""
        checks = [
            ("Password Policy", "Min Password Length", "AD Server", "✅ Compliant", "2024-01-15", "Config file"),
            ("Password Policy", "MFA Required", "VPN Gateway", "✅ Compliant", "2024-01-15", "Audit log"),
            ("Access Control", "RBAC Implementation", "ERP System", "⚠️ Partial", "2024-01-14", "Access matrix"),
            ("Access Control", "Access Review", "All Systems", "❌ Non-Compliant", "2024-01-10", "Review report"),
            ("Data Classification", "Encryption at Rest", "Database Server", "✅ Compliant", "2024-01-12", "Encryption cert"),
            ("Network Security", "Firewall Rules", "Perimeter FW", "✅ Compliant", "2024-01-11", "Config export")
        ]
        
        self.compliance_table.setRowCount(len(checks))
        
        for row, check in enumerate(checks):
            for col, value in enumerate(check):
                item = QTableWidgetItem(str(value))
                
                if col == 3:  # Status
                    if "Compliant" in value and "Non" not in value:
                        item.setForeground(QColor("#00ff88"))
                    elif "Partial" in value:
                        item.setForeground(QColor("#ffa500"))
                    else:
                        item.setForeground(QColor("#ff6b6b"))
                
                self.compliance_table.setItem(row, col, item)
            
            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)
            
            view_btn = QPushButton("👁️")
            view_btn.setFixedSize(28, 28)
            view_btn.setStyleSheet("background: #1f6feb; border: none; border-radius: 4px;")
            actions_layout.addWidget(view_btn)
            
            self.compliance_table.setCellWidget(row, 6, actions_widget)
    
    def _load_exceptions_data(self):
        """Load exceptions data"""
        exceptions = [
            ("EXC-001", "Password Policy", "Password Expiration", "John Doe", "Approved", "2024-01-01", "2024-04-01", "Jane Smith"),
            ("EXC-002", "Access Control", "MFA Required", "Dev Team", "Approved", "2024-01-10", "2024-02-10", "Bob Wilson"),
            ("EXC-003", "Network Security", "VPN Required", "Remote Site", "Pending", "2024-01-15", "2024-03-15", "-"),
            ("EXC-004", "Data Classification", "Encryption", "Legacy App", "Rejected", "2024-01-05", "-", "-")
        ]
        
        self.exceptions_table.setRowCount(len(exceptions))
        
        for row, exc in enumerate(exceptions):
            for col, value in enumerate(exc):
                item = QTableWidgetItem(str(value))
                
                if col == 4:  # Status
                    colors = {"Approved": "#00ff88", "Pending": "#ffa500", "Rejected": "#ff6b6b", "Expired": "#6e7681"}
                    item.setForeground(QColor(colors.get(value, "#c9d1d9")))
                
                self.exceptions_table.setItem(row, col, item)
            
            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)
            
            view_btn = QPushButton("👁️")
            view_btn.setFixedSize(28, 28)
            view_btn.setStyleSheet("background: #1f6feb; border: none; border-radius: 4px;")
            actions_layout.addWidget(view_btn)
            
            self.exceptions_table.setCellWidget(row, 8, actions_widget)
    
    def _load_violations_data(self):
        """Load violations data"""
        violations = [
            ("VIO-001", "Password Policy", "user123", "Password shared via email", "High", "2024-01-14", "Open", "Security Team"),
            ("VIO-002", "Access Control", "admin_user", "Accessed restricted data without approval", "Critical", "2024-01-12", "Under Investigation", "CISO"),
            ("VIO-003", "Data Classification", "contractor_a", "Unencrypted PII on laptop", "High", "2024-01-10", "Open", "DPO"),
            ("VIO-004", "Remote Access", "developer_x", "VPN bypass attempt", "Medium", "2024-01-08", "Resolved", "IT Security"),
            ("VIO-005", "Password Policy", "user456", "Weak password detected", "Low", "2024-01-05", "Resolved", "Help Desk")
        ]
        
        self.violations_table.setRowCount(len(violations))
        
        for row, vio in enumerate(violations):
            for col, value in enumerate(vio):
                item = QTableWidgetItem(str(value))
                
                if col == 4:  # Severity
                    colors = {"Critical": "#dc3545", "High": "#fd7e14", "Medium": "#ffc107", "Low": "#17a2b8"}
                    item.setForeground(QColor(colors.get(value, "#c9d1d9")))
                
                if col == 6:  # Status
                    colors = {"Open": "#ff6b6b", "Under Investigation": "#ffa500", "Resolved": "#00ff88"}
                    item.setForeground(QColor(colors.get(value, "#c9d1d9")))
                
                self.violations_table.setItem(row, col, item)
            
            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)
            
            view_btn = QPushButton("👁️")
            view_btn.setFixedSize(28, 28)
            view_btn.setStyleSheet("background: #1f6feb; border: none; border-radius: 4px;")
            actions_layout.addWidget(view_btn)
            
            self.violations_table.setCellWidget(row, 8, actions_widget)
    
    def _on_control_selected(self, current, previous):
        """Handle control selection in tree"""
        if current and current.parent():
            data = current.data(0, Qt.ItemDataRole.UserRole)
            if data:
                text = current.text(0)
                
                # Parse control info
                parts = text.split(": ", 1)
                control_id = parts[0].replace("🎛️ ", "") if len(parts) > 0 else "N/A"
                title = parts[1] if len(parts) > 1 else "N/A"
                
                self.control_id_label.setText(control_id)
                self.control_title_label.setText(title)
                self.control_enforcement_label.setText(data.get("enforcement", "N/A"))
                
                risk = data.get("risk", "Medium")
                risk_colors = {"Critical": "#dc3545", "High": "#fd7e14", "Medium": "#ffc107", "Low": "#17a2b8"}
                self.control_risk_label.setText(risk)
                self.control_risk_label.setStyleSheet(f"color: {risk_colors.get(risk, '#c9d1d9')};")
                
                self.control_nist_label.setText("IA-5" if "Password" in control_id else "AC-2")
                self.control_pci_label.setText("8.2" if "Password" in control_id else "7.1")
                self.control_automated_label.setText("Yes" if "Length" in title or "Expiration" in title else "No")
                
                self.control_desc.setPlainText(f"This control requires implementation of {title.lower()} to ensure security compliance.")
    
    def _show_new_policy_dialog(self):
        """Show new policy dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Create New Policy")
        dialog.setMinimumSize(600, 700)
        dialog.setStyleSheet("""
            QDialog {
                background: #161b22;
            }
            QLabel {
                color: #c9d1d9;
            }
            QLineEdit, QComboBox, QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        
        layout = QFormLayout(dialog)
        
        id_edit = QLineEdit()
        id_edit.setPlaceholderText("e.g., POL-008")
        layout.addRow("Policy ID:", id_edit)
        
        name_edit = QLineEdit()
        name_edit.setPlaceholderText("e.g., Mobile Device Security Policy")
        layout.addRow("Policy Name:", name_edit)
        
        type_combo = QComboBox()
        type_combo.addItems([
            "Password", "Access Control", "Data Classification", "Network Security",
            "Incident Response", "Cloud Security", "Remote Access", "Mobile Device",
            "Vendor Management", "Privacy", "Physical Security"
        ])
        layout.addRow("Policy Type:", type_combo)
        
        owner_edit = QLineEdit()
        owner_edit.setPlaceholderText("Policy owner name/role")
        layout.addRow("Owner:", owner_edit)
        
        purpose_edit = QTextEdit()
        purpose_edit.setPlaceholderText("Describe the purpose of this policy...")
        purpose_edit.setMaximumHeight(100)
        layout.addRow("Purpose:", purpose_edit)
        
        scope_edit = QTextEdit()
        scope_edit.setPlaceholderText("Define the scope of this policy...")
        scope_edit.setMaximumHeight(100)
        layout.addRow("Scope:", scope_edit)
        
        frameworks = QListWidget()
        frameworks.setMaximumHeight(120)
        frameworks.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        for fw in ["NIST 800-53", "PCI-DSS", "ISO 27001", "SOC 2", "HIPAA", "GDPR"]:
            frameworks.addItem(fw)
        layout.addRow("Compliance Frameworks:", frameworks)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.exec()
    
    def _show_policy_details(self, index):
        """Show policy details"""
        row = index.row()
        policy_id = self.policies_table.item(row, 0).text()
        policy_name = self.policies_table.item(row, 1).text()
        
        QMessageBox.information(
            self, "Policy Details",
            f"Policy: {policy_name}\nID: {policy_id}\n\nFull policy view would open here."
        )
    
    def _show_exception_dialog(self):
        """Show exception request dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Request Policy Exception")
        dialog.setMinimumSize(500, 500)
        dialog.setStyleSheet("""
            QDialog {
                background: #161b22;
            }
            QLabel {
                color: #c9d1d9;
            }
            QLineEdit, QComboBox, QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        
        layout = QFormLayout(dialog)
        
        policy_combo = QComboBox()
        policy_combo.addItems([
            "Password Security Policy", "Access Control Policy",
            "Data Classification Policy", "Network Security Policy"
        ])
        layout.addRow("Policy:", policy_combo)
        
        control_combo = QComboBox()
        control_combo.addItems([
            "Minimum Password Length", "Password Complexity",
            "Password Expiration", "MFA Required"
        ])
        layout.addRow("Control:", control_combo)
        
        justification_edit = QTextEdit()
        justification_edit.setPlaceholderText("Explain the business justification for this exception...")
        justification_edit.setMaximumHeight(100)
        layout.addRow("Business Justification:", justification_edit)
        
        risk_edit = QTextEdit()
        risk_edit.setPlaceholderText("Describe the risk assessment...")
        risk_edit.setMaximumHeight(80)
        layout.addRow("Risk Assessment:", risk_edit)
        
        compensating_edit = QTextEdit()
        compensating_edit.setPlaceholderText("List any compensating controls...")
        compensating_edit.setMaximumHeight(80)
        layout.addRow("Compensating Controls:", compensating_edit)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.exec()
