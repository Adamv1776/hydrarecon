#!/usr/bin/env python3
"""
HydraRecon Patch Management Page
Enterprise patch assessment, deployment tracking, and compliance monitoring.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QTableWidget, QTableWidgetItem,
    QTabWidget, QLineEdit, QComboBox, QTextEdit, QProgressBar,
    QHeaderView, QGridLayout, QSpinBox, QCheckBox, QSplitter,
    QGroupBox, QListWidget, QListWidgetItem, QDialog, QDialogButtonBox,
    QDateTimeEdit, QTreeWidget, QTreeWidgetItem, QMessageBox,
    QFormLayout, QStackedWidget
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QDateTime
from PyQt6.QtGui import QFont, QColor

import asyncio
from datetime import datetime, timedelta


class PatchManagementPage(QWidget):
    """Patch Management interface"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.engine = None
        self._init_engine()
        self._setup_ui()
        self._connect_signals()
        self._load_data()
    
    def _init_engine(self):
        """Initialize patch management engine"""
        try:
            from core.patch_management import PatchManagementEngine
            self.engine = PatchManagementEngine()
            self.engine.register_callback(self._on_engine_event)
        except ImportError:
            self.engine = None
    
    def _on_engine_event(self, event_type: str, data: dict):
        """Handle engine events"""
        if event_type == "deployment_job_updated":
            QTimer.singleShot(100, self._refresh_deployments)
        elif event_type == "patch_sync_completed":
            QTimer.singleShot(100, self._load_patches)
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Stats cards
        stats = self._create_stats_section()
        layout.addWidget(stats)
        
        # Main tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                border-radius: 8px;
                background-color: #0d1117;
            }
            QTabBar::tab {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px 20px;
                border: 1px solid #30363d;
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 4px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #f0f6fc;
            }
            QTabBar::tab:hover:!selected {
                background-color: #21262d;
            }
        """)
        
        # Available Patches tab
        patches_tab = self._create_patches_tab()
        self.tabs.addTab(patches_tab, "📦 Available Patches")
        
        # Asset Status tab
        assets_tab = self._create_assets_tab()
        self.tabs.addTab(assets_tab, "🖥️ Asset Status")
        
        # Deployments tab
        deployments_tab = self._create_deployments_tab()
        self.tabs.addTab(deployments_tab, "🚀 Deployments")
        
        # Compliance tab
        compliance_tab = self._create_compliance_tab()
        self.tabs.addTab(compliance_tab, "✅ Compliance")
        
        # Policies tab
        policies_tab = self._create_policies_tab()
        self.tabs.addTab(policies_tab, "📋 Policies")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QFrame:
        """Create page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #238636, stop:1 #1f6feb);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_section = QVBoxLayout()
        
        title = QLabel("📦 Patch Management")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: white; background: transparent;")
        title_section.addWidget(title)
        
        subtitle = QLabel("Automated patch assessment, deployment, and compliance tracking")
        subtitle.setStyleSheet("color: rgba(255,255,255,0.8); background: transparent;")
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        
        sync_btn = QPushButton("🔄 Sync Patches")
        sync_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255,255,255,0.2);
                color: white;
                border: 1px solid rgba(255,255,255,0.3);
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255,255,255,0.3);
            }
        """)
        sync_btn.clicked.connect(self._sync_patches)
        btn_layout.addWidget(sync_btn)
        
        scan_btn = QPushButton("🔍 Scan All Assets")
        scan_btn.setStyleSheet("""
            QPushButton {
                background-color: white;
                color: #238636;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #f0f0f0;
            }
        """)
        scan_btn.clicked.connect(self._scan_all_assets)
        btn_layout.addWidget(scan_btn)
        
        layout.addLayout(btn_layout)
        
        return header
    
    def _create_stats_section(self) -> QFrame:
        """Create statistics cards"""
        container = QFrame()
        layout = QHBoxLayout(container)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 0, 0)
        
        stats = [
            ("critical_patches", "🔴 Critical Missing", "0", "#f85149"),
            ("high_patches", "🟠 High Missing", "0", "#d29922"),
            ("compliance_rate", "📊 Compliance Rate", "0%", "#238636"),
            ("pending_reboot", "🔄 Pending Reboot", "0", "#1f6feb"),
            ("deployed_30d", "✅ Deployed (30d)", "0", "#a371f7")
        ]
        
        self.stat_labels = {}
        
        for key, title, value, color in stats:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: #161b22;
                    border: 1px solid #30363d;
                    border-radius: 12px;
                    border-left: 4px solid {color};
                }}
            """)
            
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(16, 16, 16, 16)
            
            title_label = QLabel(title)
            title_label.setStyleSheet("color: #8b949e; font-size: 12px;")
            card_layout.addWidget(title_label)
            
            value_label = QLabel(value)
            value_label.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
            value_label.setStyleSheet(f"color: {color};")
            card_layout.addWidget(value_label)
            
            self.stat_labels[key] = value_label
            layout.addWidget(card)
        
        return container
    
    def _create_patches_tab(self) -> QWidget:
        """Create available patches tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Filters
        filter_frame = QFrame()
        filter_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        filter_layout = QHBoxLayout(filter_frame)
        filter_layout.setContentsMargins(16, 12, 16, 12)
        
        # Search
        self.patch_search = QLineEdit()
        self.patch_search.setPlaceholderText("🔍 Search patches by KB ID, CVE, or title...")
        self.patch_search.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
                min-width: 300px;
            }
            QLineEdit:focus {
                border-color: #58a6ff;
            }
        """)
        self.patch_search.textChanged.connect(self._filter_patches)
        filter_layout.addWidget(self.patch_search)
        
        # Severity filter
        filter_layout.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        self.severity_filter.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c9d1d9;
                min-width: 120px;
            }
        """)
        self.severity_filter.currentTextChanged.connect(self._filter_patches)
        filter_layout.addWidget(self.severity_filter)
        
        # Platform filter
        filter_layout.addWidget(QLabel("Platform:"))
        self.platform_filter = QComboBox()
        self.platform_filter.addItems(["All", "Windows", "Linux", "macOS", "Network", "Firmware", "Application"])
        self.platform_filter.setStyleSheet(self.severity_filter.styleSheet())
        self.platform_filter.currentTextChanged.connect(self._filter_patches)
        filter_layout.addWidget(self.platform_filter)
        
        filter_layout.addStretch()
        
        layout.addWidget(filter_frame)
        
        # Patches table
        self.patches_table = QTableWidget()
        self.patches_table.setColumnCount(8)
        self.patches_table.setHorizontalHeaderLabels([
            "KB/ID", "Title", "Severity", "Platform", "CVEs", "Size", "Release Date", "Status"
        ])
        self.patches_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
                color: #c9d1d9;
            }
            QTableWidget::item:selected {
                background-color: #1f6feb;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 12px;
                border: none;
                border-bottom: 1px solid #30363d;
                font-weight: bold;
            }
        """)
        self.patches_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.patches_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.patches_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        
        layout.addWidget(self.patches_table)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        approve_btn = QPushButton("✅ Approve Selected")
        approve_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
        """)
        approve_btn.clicked.connect(self._approve_patches)
        action_layout.addWidget(approve_btn)
        
        deploy_btn = QPushButton("🚀 Deploy Selected")
        deploy_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388bfd;
            }
        """)
        deploy_btn.clicked.connect(self._deploy_patches)
        action_layout.addWidget(deploy_btn)
        
        decline_btn = QPushButton("❌ Decline Selected")
        decline_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #f85149;
                border: 1px solid #f85149;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #f85149;
                color: white;
            }
        """)
        action_layout.addWidget(decline_btn)
        
        action_layout.addStretch()
        
        export_btn = QPushButton("📥 Export Patch List")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                padding: 10px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #30363d;
            }
        """)
        action_layout.addWidget(export_btn)
        
        layout.addLayout(action_layout)
        
        return widget
    
    def _create_assets_tab(self) -> QWidget:
        """Create asset status tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Asset table
        self.assets_table = QTableWidget()
        self.assets_table.setColumnCount(9)
        self.assets_table.setHorizontalHeaderLabels([
            "Asset", "Type", "Platform", "OS Version", "Critical", "High", "Medium", "Compliance", "Last Patched"
        ])
        self.assets_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
                color: #c9d1d9;
            }
            QTableWidget::item:selected {
                background-color: #1f6feb;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 12px;
                border: none;
                border-bottom: 1px solid #30363d;
                font-weight: bold;
            }
        """)
        self.assets_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.assets_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.assets_table)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        scan_selected_btn = QPushButton("🔍 Scan Selected")
        scan_selected_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388bfd;
            }
        """)
        scan_selected_btn.clicked.connect(self._scan_selected_assets)
        action_layout.addWidget(scan_selected_btn)
        
        patch_now_btn = QPushButton("⚡ Patch Now")
        patch_now_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
        """)
        patch_now_btn.clicked.connect(self._patch_selected_assets)
        action_layout.addWidget(patch_now_btn)
        
        reboot_btn = QPushButton("🔄 Request Reboot")
        reboot_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #d29922;
                border: 1px solid #d29922;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d29922;
                color: white;
            }
        """)
        action_layout.addWidget(reboot_btn)
        
        action_layout.addStretch()
        
        layout.addLayout(action_layout)
        
        return widget
    
    def _create_deployments_tab(self) -> QWidget:
        """Create deployments tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Splitter for deployment groups and jobs
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Deployment groups
        groups_frame = QFrame()
        groups_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        groups_layout = QVBoxLayout(groups_frame)
        
        groups_header = QHBoxLayout()
        groups_title = QLabel("Deployment Groups")
        groups_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        groups_title.setStyleSheet("color: #f0f6fc;")
        groups_header.addWidget(groups_title)
        
        new_group_btn = QPushButton("+ New")
        new_group_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
            }
        """)
        new_group_btn.clicked.connect(self._create_deployment_group)
        groups_header.addWidget(new_group_btn)
        
        groups_layout.addLayout(groups_header)
        
        self.groups_list = QListWidget()
        self.groups_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
                color: #c9d1d9;
            }
            QListWidget::item:selected {
                background-color: #1f6feb;
            }
        """)
        self.groups_list.itemClicked.connect(self._on_group_selected)
        groups_layout.addWidget(self.groups_list)
        
        splitter.addWidget(groups_frame)
        
        # Deployment jobs
        jobs_frame = QFrame()
        jobs_frame.setStyleSheet(groups_frame.styleSheet())
        jobs_layout = QVBoxLayout(jobs_frame)
        
        jobs_title = QLabel("Deployment Jobs")
        jobs_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        jobs_title.setStyleSheet("color: #f0f6fc;")
        jobs_layout.addWidget(jobs_title)
        
        self.jobs_table = QTableWidget()
        self.jobs_table.setColumnCount(6)
        self.jobs_table.setHorizontalHeaderLabels([
            "Asset", "Status", "Progress", "Started", "Completed", "Actions"
        ])
        self.jobs_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
            QTableWidget::item {
                padding: 10px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        self.jobs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        jobs_layout.addWidget(self.jobs_table)
        
        splitter.addWidget(jobs_frame)
        splitter.setSizes([300, 600])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_compliance_tab(self) -> QWidget:
        """Create compliance tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Compliance summary
        summary_frame = QFrame()
        summary_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        summary_layout = QHBoxLayout(summary_frame)
        summary_layout.setContentsMargins(20, 20, 20, 20)
        
        # Compliance score gauge
        gauge_layout = QVBoxLayout()
        
        self.compliance_gauge = QLabel("87%")
        self.compliance_gauge.setFont(QFont("Segoe UI", 48, QFont.Weight.Bold))
        self.compliance_gauge.setStyleSheet("color: #238636;")
        self.compliance_gauge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gauge_layout.addWidget(self.compliance_gauge)
        
        gauge_label = QLabel("Overall Compliance")
        gauge_label.setStyleSheet("color: #8b949e; font-size: 14px;")
        gauge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gauge_layout.addWidget(gauge_label)
        
        summary_layout.addLayout(gauge_layout)
        
        # Compliance breakdown
        breakdown_layout = QGridLayout()
        
        breakdown_items = [
            ("Fully Compliant", "5", "#238636"),
            ("Non-Compliant", "3", "#f85149"),
            ("Critical Missing", "2", "#f85149"),
            ("Pending Reboot", "2", "#d29922")
        ]
        
        for i, (label, value, color) in enumerate(breakdown_items):
            row, col = i // 2, i % 2
            
            item_layout = QVBoxLayout()
            value_lbl = QLabel(value)
            value_lbl.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
            value_lbl.setStyleSheet(f"color: {color};")
            item_layout.addWidget(value_lbl)
            
            label_lbl = QLabel(label)
            label_lbl.setStyleSheet("color: #8b949e;")
            item_layout.addWidget(label_lbl)
            
            breakdown_layout.addLayout(item_layout, row, col)
        
        summary_layout.addLayout(breakdown_layout)
        summary_layout.addStretch()
        
        layout.addWidget(summary_frame)
        
        # Compliance details table
        self.compliance_table = QTableWidget()
        self.compliance_table.setColumnCount(7)
        self.compliance_table.setHorizontalHeaderLabels([
            "Asset", "Platform", "Compliance Score", "Critical", "High", "Violations", "Status"
        ])
        self.compliance_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 12px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 12px;
                border: none;
            }
        """)
        self.compliance_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.compliance_table)
        
        # Generate report button
        report_layout = QHBoxLayout()
        report_layout.addStretch()
        
        report_btn = QPushButton("📊 Generate Compliance Report")
        report_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388bfd;
            }
        """)
        report_btn.clicked.connect(self._generate_compliance_report)
        report_layout.addWidget(report_btn)
        
        layout.addLayout(report_layout)
        
        return widget
    
    def _create_policies_tab(self) -> QWidget:
        """Create policies tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Policies list
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Policy list
        list_frame = QFrame()
        list_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        list_layout = QVBoxLayout(list_frame)
        
        list_header = QHBoxLayout()
        list_title = QLabel("Compliance Policies")
        list_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        list_title.setStyleSheet("color: #f0f6fc;")
        list_header.addWidget(list_title)
        
        new_policy_btn = QPushButton("+ New Policy")
        new_policy_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
            }
        """)
        new_policy_btn.clicked.connect(self._create_policy)
        list_header.addWidget(new_policy_btn)
        
        list_layout.addLayout(list_header)
        
        self.policies_list = QListWidget()
        self.policies_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
                color: #c9d1d9;
            }
            QListWidget::item:selected {
                background-color: #1f6feb;
            }
        """)
        self.policies_list.itemClicked.connect(self._on_policy_selected)
        list_layout.addWidget(self.policies_list)
        
        splitter.addWidget(list_frame)
        
        # Policy details
        details_frame = QFrame()
        details_frame.setStyleSheet(list_frame.styleSheet())
        details_layout = QVBoxLayout(details_frame)
        
        details_title = QLabel("Policy Details")
        details_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        details_title.setStyleSheet("color: #f0f6fc;")
        details_layout.addWidget(details_title)
        
        # SLA settings
        sla_group = QGroupBox("SLA Settings (days)")
        sla_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        sla_layout = QGridLayout(sla_group)
        
        sla_items = [
            ("Critical:", 7),
            ("High:", 14),
            ("Medium:", 30),
            ("Low:", 90)
        ]
        
        for i, (label, default) in enumerate(sla_items):
            sla_layout.addWidget(QLabel(label), i, 0)
            spin = QSpinBox()
            spin.setRange(1, 365)
            spin.setValue(default)
            spin.setStyleSheet("""
                QSpinBox {
                    background-color: #0d1117;
                    border: 1px solid #30363d;
                    border-radius: 4px;
                    padding: 6px;
                    color: #c9d1d9;
                }
            """)
            sla_layout.addWidget(spin, i, 1)
        
        details_layout.addWidget(sla_group)
        
        # Maintenance windows
        maint_group = QGroupBox("Maintenance Windows")
        maint_group.setStyleSheet(sla_group.styleSheet())
        maint_layout = QVBoxLayout(maint_group)
        
        self.maint_list = QListWidget()
        self.maint_list.setMaximumHeight(100)
        self.maint_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 4px;
            }
            QListWidget::item {
                padding: 6px;
                color: #c9d1d9;
            }
        """)
        self.maint_list.addItem("Saturday 02:00 - 06:00")
        self.maint_list.addItem("Sunday 02:00 - 06:00")
        maint_layout.addWidget(self.maint_list)
        
        details_layout.addWidget(maint_group)
        
        # Options
        options_group = QGroupBox("Options")
        options_group.setStyleSheet(sla_group.styleSheet())
        options_layout = QVBoxLayout(options_group)
        
        auto_approve = QCheckBox("Auto-approve low severity patches")
        auto_approve.setStyleSheet("color: #c9d1d9;")
        options_layout.addWidget(auto_approve)
        
        auto_reboot = QCheckBox("Auto-reboot during maintenance window")
        auto_reboot.setStyleSheet("color: #c9d1d9;")
        options_layout.addWidget(auto_reboot)
        
        rollback = QCheckBox("Enable automatic rollback on failure")
        rollback.setChecked(True)
        rollback.setStyleSheet("color: #c9d1d9;")
        options_layout.addWidget(rollback)
        
        details_layout.addWidget(options_group)
        details_layout.addStretch()
        
        splitter.addWidget(details_frame)
        splitter.setSizes([300, 500])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _connect_signals(self):
        """Connect UI signals"""
        pass
    
    def _load_data(self):
        """Load initial data"""
        self._load_patches()
        self._load_assets()
        self._load_deployments()
        self._load_compliance()
        self._load_policies()
        self._update_stats()
    
    def _load_patches(self):
        """Load patches into table"""
        if not self.engine:
            return
        
        patches = list(self.engine.patches.values())
        self.patches_table.setRowCount(len(patches))
        
        for row, patch in enumerate(patches):
            # KB/ID
            self.patches_table.setItem(row, 0, QTableWidgetItem(patch.kb_id))
            
            # Title
            self.patches_table.setItem(row, 1, QTableWidgetItem(patch.title))
            
            # Severity
            severity_item = QTableWidgetItem(patch.severity.value.upper())
            severity_colors = {
                "critical": "#f85149",
                "high": "#d29922",
                "medium": "#58a6ff",
                "low": "#8b949e"
            }
            severity_item.setForeground(QColor(severity_colors.get(patch.severity.value, "#c9d1d9")))
            self.patches_table.setItem(row, 2, severity_item)
            
            # Platform
            self.patches_table.setItem(row, 3, QTableWidgetItem(patch.platform.value.title()))
            
            # CVEs
            self.patches_table.setItem(row, 4, QTableWidgetItem(", ".join(patch.cve_ids[:2])))
            
            # Size
            self.patches_table.setItem(row, 5, QTableWidgetItem(f"{patch.size_mb:.1f} MB"))
            
            # Release Date
            self.patches_table.setItem(row, 6, QTableWidgetItem(patch.release_date.strftime("%Y-%m-%d")))
            
            # Status
            status_item = QTableWidgetItem(patch.status.value.title())
            status_colors = {
                "available": "#58a6ff",
                "approved": "#238636",
                "deployed": "#2ea043",
                "declined": "#f85149"
            }
            status_item.setForeground(QColor(status_colors.get(patch.status.value, "#8b949e")))
            self.patches_table.setItem(row, 7, status_item)
    
    def _load_assets(self):
        """Load assets into table"""
        if not self.engine:
            return
        
        assets = list(self.engine.asset_status.values())
        self.assets_table.setRowCount(len(assets))
        
        for row, asset in enumerate(assets):
            self.assets_table.setItem(row, 0, QTableWidgetItem(asset.asset_name))
            self.assets_table.setItem(row, 1, QTableWidgetItem(asset.asset_type))
            self.assets_table.setItem(row, 2, QTableWidgetItem(asset.platform.value.title()))
            self.assets_table.setItem(row, 3, QTableWidgetItem(asset.os_version))
            
            # Critical missing
            critical_item = QTableWidgetItem(str(asset.missing_critical))
            if asset.missing_critical > 0:
                critical_item.setForeground(QColor("#f85149"))
            self.assets_table.setItem(row, 4, critical_item)
            
            # High missing
            high_item = QTableWidgetItem(str(asset.missing_high))
            if asset.missing_high > 0:
                high_item.setForeground(QColor("#d29922"))
            self.assets_table.setItem(row, 5, high_item)
            
            # Medium missing
            self.assets_table.setItem(row, 6, QTableWidgetItem(str(asset.missing_medium)))
            
            # Compliance score
            score_item = QTableWidgetItem(f"{asset.compliance_score:.0f}%")
            if asset.compliance_score >= 80:
                score_item.setForeground(QColor("#238636"))
            elif asset.compliance_score >= 60:
                score_item.setForeground(QColor("#d29922"))
            else:
                score_item.setForeground(QColor("#f85149"))
            self.assets_table.setItem(row, 7, score_item)
            
            # Last patched
            last_patched = asset.last_patched.strftime("%Y-%m-%d") if asset.last_patched else "Never"
            self.assets_table.setItem(row, 8, QTableWidgetItem(last_patched))
    
    def _load_deployments(self):
        """Load deployment groups and jobs"""
        if not self.engine:
            return
        
        self.groups_list.clear()
        for group in self.engine.patch_groups.values():
            item = QListWidgetItem(f"📦 {group.name}")
            item.setData(Qt.ItemDataRole.UserRole, group.id)
            self.groups_list.addItem(item)
    
    def _load_compliance(self):
        """Load compliance data"""
        if not self.engine:
            return
        
        assets = list(self.engine.asset_status.values())
        self.compliance_table.setRowCount(len(assets))
        
        for row, asset in enumerate(assets):
            compliance = self.engine.check_compliance(asset.asset_id)
            
            self.compliance_table.setItem(row, 0, QTableWidgetItem(asset.asset_name))
            self.compliance_table.setItem(row, 1, QTableWidgetItem(asset.platform.value.title()))
            
            # Score with color
            score_item = QTableWidgetItem(f"{compliance['compliance_score']:.0f}%")
            if compliance['compliance_score'] >= 80:
                score_item.setForeground(QColor("#238636"))
            elif compliance['compliance_score'] >= 60:
                score_item.setForeground(QColor("#d29922"))
            else:
                score_item.setForeground(QColor("#f85149"))
            self.compliance_table.setItem(row, 2, score_item)
            
            self.compliance_table.setItem(row, 3, QTableWidgetItem(str(compliance['missing_by_severity']['critical'])))
            self.compliance_table.setItem(row, 4, QTableWidgetItem(str(compliance['missing_by_severity']['high'])))
            self.compliance_table.setItem(row, 5, QTableWidgetItem(str(len(compliance['violations']))))
            
            # Status
            status = "✅ Compliant" if compliance['compliant'] else "❌ Non-Compliant"
            status_item = QTableWidgetItem(status)
            status_item.setForeground(QColor("#238636" if compliance['compliant'] else "#f85149"))
            self.compliance_table.setItem(row, 6, status_item)
    
    def _load_policies(self):
        """Load compliance policies"""
        if not self.engine:
            return
        
        self.policies_list.clear()
        for policy in self.engine.compliance_policies.values():
            item = QListWidgetItem(f"📋 {policy.name}")
            item.setData(Qt.ItemDataRole.UserRole, policy.id)
            self.policies_list.addItem(item)
    
    def _update_stats(self):
        """Update statistics display"""
        if not self.engine:
            return
        
        metrics = self.engine.get_metrics()
        
        self.stat_labels["critical_patches"].setText(str(metrics.critical_missing))
        self.stat_labels["high_patches"].setText(str(metrics.high_missing))
        self.stat_labels["compliance_rate"].setText(f"{metrics.compliance_rate:.0f}%")
        self.stat_labels["pending_reboot"].setText(str(metrics.assets_pending_reboot))
        self.stat_labels["deployed_30d"].setText(str(metrics.patches_deployed_30d))
        
        # Update compliance gauge
        self.compliance_gauge.setText(f"{metrics.compliance_rate:.0f}%")
        if metrics.compliance_rate >= 80:
            self.compliance_gauge.setStyleSheet("color: #238636;")
        elif metrics.compliance_rate >= 60:
            self.compliance_gauge.setStyleSheet("color: #d29922;")
        else:
            self.compliance_gauge.setStyleSheet("color: #f85149;")
    
    def _filter_patches(self):
        """Filter patches based on search and filters"""
        if not self.engine:
            return
        
        search_text = self.patch_search.text().lower()
        severity = self.severity_filter.currentText().lower()
        platform = self.platform_filter.currentText().lower()
        
        for row in range(self.patches_table.rowCount()):
            show = True
            
            # Search filter
            if search_text:
                kb_id = self.patches_table.item(row, 0).text().lower()
                title = self.patches_table.item(row, 1).text().lower()
                cves = self.patches_table.item(row, 4).text().lower()
                if search_text not in kb_id and search_text not in title and search_text not in cves:
                    show = False
            
            # Severity filter
            if severity != "all" and show:
                row_severity = self.patches_table.item(row, 2).text().lower()
                if severity != row_severity:
                    show = False
            
            # Platform filter
            if platform != "all" and show:
                row_platform = self.patches_table.item(row, 3).text().lower()
                if platform != row_platform:
                    show = False
            
            self.patches_table.setRowHidden(row, not show)
    
    def _sync_patches(self):
        """Sync patches from update sources"""
        if not self.engine:
            return
        
        async def do_sync():
            await self.engine.sync_patches()
            self._load_patches()
            self._update_stats()
        
        asyncio.ensure_future(do_sync())
    
    def _scan_all_assets(self):
        """Scan all assets for patch status"""
        if not self.engine:
            return
        
        async def do_scan():
            await self.engine.scan_all_assets()
            self._load_assets()
            self._load_compliance()
            self._update_stats()
        
        asyncio.ensure_future(do_scan())
    
    def _scan_selected_assets(self):
        """Scan selected assets"""
        selected = self.assets_table.selectedItems()
        if not selected:
            return
        
        # Get unique rows
        rows = set(item.row() for item in selected)
        
        async def do_scan():
            for row in rows:
                asset_name = self.assets_table.item(row, 0).text()
                # Find asset ID by name
                for aid, status in self.engine.asset_status.items():
                    if status.asset_name == asset_name:
                        await self.engine.scan_asset(aid)
                        break
            
            self._load_assets()
            self._load_compliance()
            self._update_stats()
        
        asyncio.ensure_future(do_scan())
    
    def _approve_patches(self):
        """Approve selected patches"""
        # Implementation for approving patches
        pass
    
    def _deploy_patches(self):
        """Deploy selected patches"""
        selected = self.patches_table.selectedItems()
        if not selected:
            return
        
        dialog = DeploymentDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Create deployment group and deploy
            pass
    
    def _patch_selected_assets(self):
        """Patch selected assets immediately"""
        selected = self.assets_table.selectedItems()
        if not selected:
            return
        
        # Get selected asset IDs
        rows = set(item.row() for item in selected)
        asset_ids = []
        for row in rows:
            asset_name = self.assets_table.item(row, 0).text()
            for aid, status in self.engine.asset_status.items():
                if status.asset_name == asset_name:
                    asset_ids.append(aid)
                    break
        
        if asset_ids:
            QMessageBox.information(
                self,
                "Patch Deployment",
                f"Initiating patch deployment for {len(asset_ids)} asset(s)"
            )
    
    def _create_deployment_group(self):
        """Create a new deployment group"""
        dialog = DeploymentGroupDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._load_deployments()
    
    def _on_group_selected(self, item):
        """Handle deployment group selection"""
        group_id = item.data(Qt.ItemDataRole.UserRole)
        if group_id and self.engine and group_id in self.engine.patch_groups:
            group = self.engine.patch_groups[group_id]
            
            # Load jobs for this group
            jobs = [j for j in self.engine.deployment_jobs.values() if j.patch_group_id == group_id]
            self.jobs_table.setRowCount(len(jobs))
            
            for row, job in enumerate(jobs):
                asset_name = self.engine.asset_status.get(job.asset_id, {})
                if hasattr(asset_name, 'asset_name'):
                    asset_name = asset_name.asset_name
                else:
                    asset_name = job.asset_id
                
                self.jobs_table.setItem(row, 0, QTableWidgetItem(asset_name))
                self.jobs_table.setItem(row, 1, QTableWidgetItem(job.status.value.title()))
                
                # Progress
                progress = f"{job.install_progress:.0f}%"
                self.jobs_table.setItem(row, 2, QTableWidgetItem(progress))
                
                started = job.started_at.strftime("%Y-%m-%d %H:%M") if job.started_at else "-"
                self.jobs_table.setItem(row, 3, QTableWidgetItem(started))
                
                completed = job.completed_at.strftime("%Y-%m-%d %H:%M") if job.completed_at else "-"
                self.jobs_table.setItem(row, 4, QTableWidgetItem(completed))
    
    def _refresh_deployments(self):
        """Refresh deployments view"""
        self._load_deployments()
        # Re-select current group if any
        current = self.groups_list.currentItem()
        if current:
            self._on_group_selected(current)
    
    def _create_policy(self):
        """Create a new compliance policy"""
        dialog = PolicyDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._load_policies()
    
    def _on_policy_selected(self, item):
        """Handle policy selection"""
        policy_id = item.data(Qt.ItemDataRole.UserRole)
        # Load policy details
        pass
    
    def _generate_compliance_report(self):
        """Generate compliance report"""
        if not self.engine:
            return
        
        report = self.engine.generate_compliance_report()
        
        # Show report summary
        summary = report['summary']
        msg = f"""Compliance Report Generated

Summary:
• Total Assets: {summary['total_assets']}
• Fully Compliant: {summary['fully_compliant']}
• Non-Compliant: {summary['non_compliant']}
• Average Score: {summary['average_score']:.1f}%
• Critical Patches Missing: {summary['critical_patches_missing']}

Recommendations:
"""
        for rec in report['recommendations'][:3]:
            msg += f"• {rec}\n"
        
        QMessageBox.information(self, "Compliance Report", msg)


class DeploymentDialog(QDialog):
    """Deployment configuration dialog"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configure Deployment")
        self.setMinimumSize(500, 400)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Target selection
        target_group = QGroupBox("Target Assets")
        target_layout = QVBoxLayout(target_group)
        
        self.target_list = QListWidget()
        self.target_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        target_layout.addWidget(self.target_list)
        
        layout.addWidget(target_group)
        
        # Schedule
        schedule_group = QGroupBox("Schedule")
        schedule_layout = QFormLayout(schedule_group)
        
        self.schedule_combo = QComboBox()
        self.schedule_combo.addItems(["Deploy Now", "Schedule for Later", "Next Maintenance Window"])
        schedule_layout.addRow("When:", self.schedule_combo)
        
        self.schedule_datetime = QDateTimeEdit()
        self.schedule_datetime.setDateTime(QDateTime.currentDateTime().addDays(1))
        schedule_layout.addRow("Date/Time:", self.schedule_datetime)
        
        layout.addWidget(schedule_group)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout(options_group)
        
        self.auto_reboot = QCheckBox("Auto-reboot if required")
        options_layout.addWidget(self.auto_reboot)
        
        self.force_deploy = QCheckBox("Force deployment (skip approval)")
        options_layout.addWidget(self.force_deploy)
        
        layout.addWidget(options_group)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class DeploymentGroupDialog(QDialog):
    """Create deployment group dialog"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create Deployment Group")
        self.setMinimumSize(500, 400)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g., January Security Patches")
        form.addRow("Name:", self.name_input)
        
        self.desc_input = QTextEdit()
        self.desc_input.setMaximumHeight(80)
        form.addRow("Description:", self.desc_input)
        
        self.phase_combo = QComboBox()
        self.phase_combo.addItems(["Pilot", "Limited", "Broad", "Emergency"])
        form.addRow("Phase:", self.phase_combo)
        
        layout.addLayout(form)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class PolicyDialog(QDialog):
    """Create/edit compliance policy dialog"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create Compliance Policy")
        self.setMinimumSize(500, 500)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        
        self.name_input = QLineEdit()
        form.addRow("Policy Name:", self.name_input)
        
        self.desc_input = QTextEdit()
        self.desc_input.setMaximumHeight(60)
        form.addRow("Description:", self.desc_input)
        
        layout.addLayout(form)
        
        # SLA settings
        sla_group = QGroupBox("SLA Settings (days)")
        sla_layout = QGridLayout(sla_group)
        
        sla_items = [("Critical:", 7), ("High:", 14), ("Medium:", 30), ("Low:", 90)]
        for i, (label, default) in enumerate(sla_items):
            sla_layout.addWidget(QLabel(label), i, 0)
            spin = QSpinBox()
            spin.setRange(1, 365)
            spin.setValue(default)
            sla_layout.addWidget(spin, i, 1)
        
        layout.addWidget(sla_group)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
