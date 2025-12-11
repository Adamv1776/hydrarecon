#!/usr/bin/env python3
"""
HydraRecon Third-Party Risk Management Page
Enterprise vendor security assessment and risk management.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget,
    QTableWidgetItem, QPushButton, QLabel, QFrame, QComboBox,
    QTextEdit, QLineEdit, QSpinBox, QProgressBar, QSplitter,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QMessageBox,
    QDialog, QFormLayout, QDateEdit, QGroupBox, QScrollArea,
    QListWidget, QListWidgetItem, QCheckBox, QMenu, QStackedWidget
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QDate
from PyQt6.QtGui import QFont, QColor, QAction

import asyncio
from datetime import datetime, timedelta


class ThirdPartyRiskPage(QWidget):
    """Third-party risk management interface"""
    
    vendor_selected = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.engine = None
        self._init_engine()
        self._setup_ui()
        self._connect_signals()
        self._load_data()
    
    def _init_engine(self):
        """Initialize the TPRM engine"""
        try:
            from core.third_party_risk import ThirdPartyRiskEngine
            self.engine = ThirdPartyRiskEngine()
        except ImportError:
            self.engine = None
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Stats bar
        stats = self._create_stats_bar()
        layout.addWidget(stats)
        
        # Main content tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                background-color: #0d1117;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #21262d;
                color: #8b949e;
                padding: 10px 20px;
                margin-right: 4px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: #1f6feb;
                color: white;
            }
            QTabBar::tab:hover:!selected {
                background-color: #30363d;
            }
        """)
        
        # Add tabs
        self.tabs.addTab(self._create_dashboard_tab(), "📊 Dashboard")
        self.tabs.addTab(self._create_vendors_tab(), "🏢 Vendors")
        self.tabs.addTab(self._create_assessments_tab(), "📋 Assessments")
        self.tabs.addTab(self._create_findings_tab(), "⚠️ Findings")
        self.tabs.addTab(self._create_incidents_tab(), "🚨 Incidents")
        self.tabs.addTab(self._create_questionnaire_tab(), "📝 Questionnaire")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QFrame:
        """Create page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0d1117, stop:1 #161b22);
                border-radius: 12px;
                padding: 16px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🏢 Third-Party Risk Management")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #1f6feb;")
        
        subtitle = QLabel("Vendor security assessment and risk management")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Quick actions
        actions_layout = QHBoxLayout()
        
        add_vendor_btn = QPushButton("➕ Add Vendor")
        add_vendor_btn.setStyleSheet("""
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
        add_vendor_btn.clicked.connect(self._add_vendor)
        
        new_assessment_btn = QPushButton("📋 New Assessment")
        new_assessment_btn.setStyleSheet("""
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
        
        export_btn = QPushButton("📤 Export Report")
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
        
        actions_layout.addWidget(add_vendor_btn)
        actions_layout.addWidget(new_assessment_btn)
        actions_layout.addWidget(export_btn)
        layout.addLayout(actions_layout)
        
        return header
    
    def _create_stats_bar(self) -> QFrame:
        """Create statistics bar"""
        stats = QFrame()
        stats.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        
        layout = QHBoxLayout(stats)
        
        # Stat cards
        stat_data = [
            ("Total Vendors", "0", "#58a6ff", "total_vendors"),
            ("High Risk", "0", "#f85149", "high_risk"),
            ("Pending Assessments", "0", "#f0883e", "pending_assessments"),
            ("Open Findings", "0", "#d29922", "open_findings"),
            ("Active Incidents", "0", "#f85149", "active_incidents"),
            ("Avg Risk Score", "0", "#a371f7", "avg_risk")
        ]
        
        self.stat_labels = {}
        
        for label, value, color, key in stat_data:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: #0d1117;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 8px;
                }}
            """)
            
            card_layout = QVBoxLayout(card)
            card_layout.setSpacing(4)
            
            value_label = QLabel(value)
            value_label.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
            value_label.setStyleSheet(f"color: {color};")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.stat_labels[key] = value_label
            
            name_label = QLabel(label)
            name_label.setStyleSheet("color: #8b949e; font-size: 11px;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            card_layout.addWidget(value_label)
            card_layout.addWidget(name_label)
            
            layout.addWidget(card)
        
        return stats
    
    def _create_dashboard_tab(self) -> QWidget:
        """Create dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Risk distribution
        risk_layout = QHBoxLayout()
        
        # By tier
        tier_frame = QFrame()
        tier_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        tier_layout = QVBoxLayout(tier_frame)
        
        tier_title = QLabel("Vendors by Tier")
        tier_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        tier_title.setStyleSheet("color: #e6e6e6;")
        tier_layout.addWidget(tier_title)
        
        # Tier bars
        tiers = [
            ("Tier 1 - Critical", "#f85149", 0),
            ("Tier 2 - Important", "#f0883e", 0),
            ("Tier 3 - Moderate", "#d29922", 0),
            ("Tier 4 - Low", "#3fb950", 0)
        ]
        
        for tier_name, color, count in tiers:
            tier_row = QHBoxLayout()
            tier_label = QLabel(tier_name)
            tier_label.setStyleSheet(f"color: {color};")
            tier_label.setFixedWidth(150)
            
            tier_bar = QProgressBar()
            tier_bar.setMaximum(100)
            tier_bar.setValue(count)
            tier_bar.setStyleSheet(f"""
                QProgressBar {{
                    background-color: #21262d;
                    border-radius: 4px;
                    height: 20px;
                }}
                QProgressBar::chunk {{
                    background-color: {color};
                    border-radius: 4px;
                }}
            """)
            
            tier_count = QLabel(str(count))
            tier_count.setStyleSheet("color: #8b949e;")
            tier_count.setFixedWidth(40)
            
            tier_row.addWidget(tier_label)
            tier_row.addWidget(tier_bar)
            tier_row.addWidget(tier_count)
            tier_layout.addLayout(tier_row)
        
        risk_layout.addWidget(tier_frame)
        
        # By risk level
        risk_frame = QFrame()
        risk_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        risk_layout_inner = QVBoxLayout(risk_frame)
        
        risk_title = QLabel("Vendors by Risk Level")
        risk_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        risk_title.setStyleSheet("color: #e6e6e6;")
        risk_layout_inner.addWidget(risk_title)
        
        # Risk distribution chart
        self.risk_chart = QFrame()
        self.risk_chart.setMinimumHeight(200)
        risk_layout_inner.addWidget(self.risk_chart)
        
        risk_layout.addWidget(risk_frame)
        
        layout.addLayout(risk_layout)
        
        # Bottom section
        bottom_layout = QHBoxLayout()
        
        # Upcoming assessments
        upcoming_frame = QFrame()
        upcoming_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        upcoming_layout = QVBoxLayout(upcoming_frame)
        
        upcoming_title = QLabel("📅 Upcoming Assessments")
        upcoming_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        upcoming_title.setStyleSheet("color: #e6e6e6;")
        upcoming_layout.addWidget(upcoming_title)
        
        self.upcoming_list = QListWidget()
        self.upcoming_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #21262d;
            }
        """)
        upcoming_layout.addWidget(self.upcoming_list)
        
        bottom_layout.addWidget(upcoming_frame)
        
        # High risk vendors
        high_risk_frame = QFrame()
        high_risk_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        high_risk_layout = QVBoxLayout(high_risk_frame)
        
        high_risk_title = QLabel("⚠️ High Risk Vendors")
        high_risk_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        high_risk_title.setStyleSheet("color: #f85149;")
        high_risk_layout.addWidget(high_risk_title)
        
        self.high_risk_table = QTableWidget()
        self.high_risk_table.setColumnCount(4)
        self.high_risk_table.setHorizontalHeaderLabels(["Vendor", "Tier", "Risk Score", "Last Assessment"])
        self.high_risk_table.horizontalHeader().setStretchLastSection(True)
        self.high_risk_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 8px;
                border: none;
            }
        """)
        high_risk_layout.addWidget(self.high_risk_table)
        
        bottom_layout.addWidget(high_risk_frame)
        
        layout.addLayout(bottom_layout)
        
        return widget
    
    def _create_vendors_tab(self) -> QWidget:
        """Create vendors management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)
        
        # Filters
        filters = QFrame()
        filters.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        filters_layout = QHBoxLayout(filters)
        
        # Search
        self.vendor_search = QLineEdit()
        self.vendor_search.setPlaceholderText("🔍 Search vendors...")
        self.vendor_search.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        filters_layout.addWidget(self.vendor_search)
        
        # Tier filter
        self.tier_filter = QComboBox()
        self.tier_filter.addItems(["All Tiers", "Tier 1", "Tier 2", "Tier 3", "Tier 4"])
        self.tier_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 120px;
            }
        """)
        filters_layout.addWidget(self.tier_filter)
        
        # Risk filter
        self.vendor_risk_filter = QComboBox()
        self.vendor_risk_filter.addItems(["All Risk Levels", "Critical", "High", "Medium", "Low", "Acceptable"])
        self.vendor_risk_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 140px;
            }
        """)
        filters_layout.addWidget(self.vendor_risk_filter)
        
        # Status filter
        self.vendor_status_filter = QComboBox()
        self.vendor_status_filter.addItems(["All Statuses", "Active", "Inactive", "Onboarding", "Offboarding"])
        self.vendor_status_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 130px;
            }
        """)
        filters_layout.addWidget(self.vendor_status_filter)
        
        layout.addWidget(filters)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Vendors table
        table_frame = QFrame()
        table_frame.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        table_layout = QVBoxLayout(table_frame)
        
        self.vendors_table = QTableWidget()
        self.vendors_table.setColumnCount(7)
        self.vendors_table.setHorizontalHeaderLabels([
            "Name", "Tier", "Status", "Risk Level", "Risk Score",
            "Services", "Last Assessment"
        ])
        self.vendors_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.vendors_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.vendors_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: none;
                color: #c9d1d9;
                gridline-color: #21262d;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #1f6feb;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #21262d;
            }
            QTableWidget::item:selected {
                background-color: #388bfd33;
            }
        """)
        self.vendors_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.vendors_table.customContextMenuRequested.connect(self._show_vendor_context_menu)
        table_layout.addWidget(self.vendors_table)
        
        splitter.addWidget(table_frame)
        
        # Vendor details panel
        details_frame = QFrame()
        details_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        details_layout = QVBoxLayout(details_frame)
        
        details_title = QLabel("Vendor Details")
        details_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        details_title.setStyleSheet("color: #e6e6e6;")
        details_layout.addWidget(details_title)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        
        details_content = QWidget()
        content_layout = QFormLayout(details_content)
        content_layout.setSpacing(12)
        
        self.vendor_detail_labels = {}
        fields = [
            ("Name", "name"),
            ("Tier", "tier"),
            ("Status", "status"),
            ("Risk Level", "risk_level"),
            ("Risk Score", "risk_score"),
            ("Primary Contact", "contact"),
            ("Email", "email"),
            ("Website", "website"),
            ("Industry", "industry"),
            ("Country", "country"),
            ("Contract End", "contract_end"),
            ("Certifications", "certifications")
        ]
        
        for label, key in fields:
            value = QLabel("-")
            value.setStyleSheet("color: #c9d1d9;")
            value.setWordWrap(True)
            content_layout.addRow(
                QLabel(f"{label}:"),
                value
            )
            self.vendor_detail_labels[key] = value
        
        scroll.setWidget(details_content)
        details_layout.addWidget(scroll)
        
        # Action buttons
        actions = QHBoxLayout()
        
        edit_btn = QPushButton("✏️ Edit")
        edit_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        
        assess_btn = QPushButton("📋 Assess")
        assess_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        
        incident_btn = QPushButton("🚨 Log Incident")
        incident_btn.setStyleSheet("""
            QPushButton {
                background-color: #f85149;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        
        actions.addWidget(edit_btn)
        actions.addWidget(assess_btn)
        actions.addWidget(incident_btn)
        details_layout.addLayout(actions)
        
        splitter.addWidget(details_frame)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_assessments_tab(self) -> QWidget:
        """Create assessments tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Assessment list
        list_frame = QFrame()
        list_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        list_layout = QVBoxLayout(list_frame)
        
        list_header = QHBoxLayout()
        list_title = QLabel("Security Assessments")
        list_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        list_title.setStyleSheet("color: #e6e6e6;")
        list_header.addWidget(list_title)
        
        list_header.addStretch()
        
        new_assessment_btn = QPushButton("➕ New Assessment")
        new_assessment_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        list_header.addWidget(new_assessment_btn)
        
        list_layout.addLayout(list_header)
        
        self.assessments_table = QTableWidget()
        self.assessments_table.setColumnCount(7)
        self.assessments_table.setHorizontalHeaderLabels([
            "ID", "Vendor", "Type", "Status", "Score", "Risk Level", "Due Date"
        ])
        self.assessments_table.horizontalHeader().setStretchLastSection(True)
        self.assessments_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        list_layout.addWidget(self.assessments_table)
        
        layout.addWidget(list_frame)
        
        return widget
    
    def _create_findings_tab(self) -> QWidget:
        """Create findings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Findings summary
        summary_layout = QHBoxLayout()
        
        severities = [
            ("Critical", "#f85149", "critical_findings"),
            ("High", "#f0883e", "high_findings"),
            ("Medium", "#d29922", "medium_findings"),
            ("Low", "#3fb950", "low_findings")
        ]
        
        self.finding_counts = {}
        
        for sev, color, key in severities:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: {color}22;
                    border: 2px solid {color};
                    border-radius: 8px;
                    padding: 16px;
                }}
            """)
            card_layout = QVBoxLayout(card)
            
            count_label = QLabel("0")
            count_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
            count_label.setStyleSheet(f"color: {color};")
            count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.finding_counts[key] = count_label
            
            sev_label = QLabel(sev)
            sev_label.setStyleSheet("color: #8b949e;")
            sev_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            card_layout.addWidget(count_label)
            card_layout.addWidget(sev_label)
            
            summary_layout.addWidget(card)
        
        layout.addLayout(summary_layout)
        
        # Findings table
        findings_frame = QFrame()
        findings_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        findings_layout = QVBoxLayout(findings_frame)
        
        findings_title = QLabel("Risk Findings")
        findings_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        findings_title.setStyleSheet("color: #e6e6e6;")
        findings_layout.addWidget(findings_title)
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(7)
        self.findings_table.setHorizontalHeaderLabels([
            "ID", "Vendor", "Title", "Severity", "Risk Score", "Status", "Deadline"
        ])
        self.findings_table.horizontalHeader().setStretchLastSection(True)
        self.findings_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        findings_layout.addWidget(self.findings_table)
        
        layout.addWidget(findings_frame)
        
        return widget
    
    def _create_incidents_tab(self) -> QWidget:
        """Create incidents tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Incidents header
        header_layout = QHBoxLayout()
        
        incidents_title = QLabel("Vendor Security Incidents")
        incidents_title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        incidents_title.setStyleSheet("color: #e6e6e6;")
        header_layout.addWidget(incidents_title)
        
        header_layout.addStretch()
        
        new_incident_btn = QPushButton("🚨 Report Incident")
        new_incident_btn.setStyleSheet("""
            QPushButton {
                background-color: #f85149;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
        """)
        header_layout.addWidget(new_incident_btn)
        
        layout.addLayout(header_layout)
        
        # Incidents table
        incidents_frame = QFrame()
        incidents_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        incidents_layout = QVBoxLayout(incidents_frame)
        
        self.incidents_table = QTableWidget()
        self.incidents_table.setColumnCount(7)
        self.incidents_table.setHorizontalHeaderLabels([
            "ID", "Vendor", "Type", "Severity", "Data Impact", "Status", "Date"
        ])
        self.incidents_table.horizontalHeader().setStretchLastSection(True)
        self.incidents_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        incidents_layout.addWidget(self.incidents_table)
        
        layout.addWidget(incidents_frame)
        
        return widget
    
    def _create_questionnaire_tab(self) -> QWidget:
        """Create questionnaire management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Questionnaire sections
        sections_frame = QFrame()
        sections_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        sections_layout = QVBoxLayout(sections_frame)
        
        sections_title = QLabel("Security Questionnaire")
        sections_title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        sections_title.setStyleSheet("color: #e6e6e6;")
        sections_layout.addWidget(sections_title)
        
        sections_desc = QLabel("Configure the security questionnaire used for vendor assessments")
        sections_desc.setStyleSheet("color: #8b949e;")
        sections_layout.addWidget(sections_desc)
        
        # Question categories
        categories = [
            ("Access Control", 3, "ac"),
            ("Data Protection", 3, "dp"),
            ("Incident Response", 3, "ir"),
            ("Business Continuity", 2, "bc"),
            ("Vulnerability Management", 3, "vm"),
            ("Compliance", 2, "cc"),
            ("Network Security", 2, "ns"),
            ("Security Monitoring", 2, "sm"),
            ("Employee Security", 2, "es")
        ]
        
        for cat_name, count, prefix in categories:
            cat_frame = QFrame()
            cat_frame.setStyleSheet("""
                QFrame {
                    background-color: #0d1117;
                    border: 1px solid #21262d;
                    border-radius: 6px;
                    padding: 12px;
                    margin: 4px 0;
                }
            """)
            cat_layout = QHBoxLayout(cat_frame)
            
            cat_label = QLabel(f"📋 {cat_name}")
            cat_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
            cat_label.setStyleSheet("color: #c9d1d9;")
            
            count_label = QLabel(f"{count} questions")
            count_label.setStyleSheet("color: #8b949e;")
            
            edit_btn = QPushButton("Edit")
            edit_btn.setStyleSheet("""
                QPushButton {
                    background-color: #21262d;
                    color: #c9d1d9;
                    border: 1px solid #30363d;
                    padding: 6px 12px;
                    border-radius: 4px;
                }
            """)
            
            cat_layout.addWidget(cat_label)
            cat_layout.addStretch()
            cat_layout.addWidget(count_label)
            cat_layout.addWidget(edit_btn)
            
            sections_layout.addWidget(cat_frame)
        
        layout.addWidget(sections_frame)
        
        return widget
    
    def _connect_signals(self):
        """Connect signals"""
        self.vendors_table.itemSelectionChanged.connect(self._on_vendor_selected)
        self.vendor_search.textChanged.connect(self._filter_vendors)
        self.tier_filter.currentTextChanged.connect(self._filter_vendors)
        self.vendor_risk_filter.currentTextChanged.connect(self._filter_vendors)
    
    def _load_data(self):
        """Load initial data"""
        # Data will be loaded when the page is shown and event loop is running
        pass
    
    def showEvent(self, event):
        """Handle show event to load data when page is visible"""
        super().showEvent(event)
        if self.engine:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self._refresh_dashboard())
            except RuntimeError:
                pass

    async def _refresh_dashboard(self):
        """Refresh dashboard data"""
        if not self.engine:
            return
        
        try:
            stats = await self.engine.get_dashboard_stats()
            
            self.stat_labels["total_vendors"].setText(str(stats.get("total_vendors", 0)))
            
            high_risk = stats.get("by_risk_level", {})
            self.stat_labels["high_risk"].setText(
                str(high_risk.get("critical", 0) + high_risk.get("high", 0))
            )
            
            self.stat_labels["pending_assessments"].setText(str(stats.get("assessments_pending", 0)))
            self.stat_labels["open_findings"].setText(str(stats.get("open_findings", 0)))
            self.stat_labels["active_incidents"].setText(str(stats.get("active_incidents", 0)))
            self.stat_labels["avg_risk"].setText(str(stats.get("average_risk_score", 0)))
            
        except Exception as e:
            print(f"Dashboard refresh error: {e}")
    
    def _add_vendor(self):
        """Add new vendor"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Vendor")
        dialog.setMinimumWidth(500)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #161b22;
            }
        """)
        
        layout = QFormLayout(dialog)
        layout.setSpacing(12)
        
        name_input = QLineEdit()
        name_input.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px; border-radius: 4px;")
        layout.addRow("Vendor Name:", name_input)
        
        tier_combo = QComboBox()
        tier_combo.addItems(["Tier 1 - Critical", "Tier 2 - Important", "Tier 3 - Moderate", "Tier 4 - Low"])
        tier_combo.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px;")
        layout.addRow("Tier:", tier_combo)
        
        contact_input = QLineEdit()
        contact_input.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px; border-radius: 4px;")
        layout.addRow("Primary Contact:", contact_input)
        
        email_input = QLineEdit()
        email_input.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px; border-radius: 4px;")
        layout.addRow("Contact Email:", email_input)
        
        services_input = QTextEdit()
        services_input.setMaximumHeight(80)
        services_input.setStyleSheet("background-color: #21262d; color: #c9d1d9; border-radius: 4px;")
        layout.addRow("Services:", services_input)
        
        buttons = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        add_btn = QPushButton("Add Vendor")
        add_btn.setStyleSheet("background-color: #238636; color: white; padding: 8px 16px; border-radius: 4px;")
        add_btn.clicked.connect(dialog.accept)
        buttons.addWidget(cancel_btn)
        buttons.addWidget(add_btn)
        layout.addRow(buttons)
        
        dialog.exec()
    
    def _on_vendor_selected(self):
        """Handle vendor selection"""
        selected = self.vendors_table.selectedItems()
        if selected:
            vendor_name = self.vendors_table.item(selected[0].row(), 0).text()
            self.vendor_selected.emit(vendor_name)
    
    def _filter_vendors(self):
        """Filter vendors based on criteria"""
        pass
    
    def _show_vendor_context_menu(self, position):
        """Show context menu for vendors"""
        menu = QMenu()
        menu.setStyleSheet("""
            QMenu {
                background-color: #21262d;
                border: 1px solid #30363d;
                color: #c9d1d9;
            }
            QMenu::item:selected {
                background-color: #30363d;
            }
        """)
        
        view_action = menu.addAction("👁️ View Details")
        edit_action = menu.addAction("✏️ Edit")
        assess_action = menu.addAction("📋 New Assessment")
        menu.addSeparator()
        incident_action = menu.addAction("🚨 Log Incident")
        export_action = menu.addAction("📤 Export Report")
        
        menu.exec(self.vendors_table.mapToGlobal(position))
