"""
HydraRecon CMDB Page
Configuration Management Database GUI - Asset tracking, relationships, and change management
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QTextEdit,
    QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QTabWidget, QSplitter, QTreeWidget, QTreeWidgetItem,
    QGroupBox, QSpinBox, QCheckBox, QProgressBar, QMenu,
    QDialog, QDialogButtonBox, QFormLayout, QMessageBox,
    QListWidget, QListWidgetItem, QStackedWidget, QDateEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QThread, QDate
from PyQt6.QtGui import QFont, QColor, QAction, QIcon
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import asyncio
import json


class CMDBPage(QWidget):
    """Configuration Management Database Page"""
    
    ci_selected = pyqtSignal(str)  # CI ID selected
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.configuration_items = {}
        self.relationships = {}
        self.change_requests = {}
        
        self._setup_ui()
        self._connect_signals()
        self._apply_styles()
        self._load_sample_data()
    
    def _setup_ui(self):
        """Setup the CMDB interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        
        # Configuration Items tab
        ci_tab = self._create_ci_tab()
        self.tab_widget.addTab(ci_tab, "📦 Configuration Items")
        
        # Relationships tab
        rel_tab = self._create_relationships_tab()
        self.tab_widget.addTab(rel_tab, "🔗 Relationships")
        
        # Change Management tab
        change_tab = self._create_change_tab()
        self.tab_widget.addTab(change_tab, "📝 Change Requests")
        
        # Topology tab
        topology_tab = self._create_topology_tab()
        self.tab_widget.addTab(topology_tab, "🕸️ Topology View")
        
        # Reports tab
        reports_tab = self._create_reports_tab()
        self.tab_widget.addTab(reports_tab, "📊 Reports")
        
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
        
        title = QLabel("⚙️ Configuration Management Database")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Track assets, relationships, and changes across your infrastructure")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(16)
        
        self.total_cis_label = self._create_stat_card("Total CIs", "0", "#00d4ff")
        stats_layout.addWidget(self.total_cis_label)
        
        self.active_cis_label = self._create_stat_card("Active", "0", "#00ff88")
        stats_layout.addWidget(self.active_cis_label)
        
        self.relationships_label = self._create_stat_card("Relationships", "0", "#ff6b6b")
        stats_layout.addWidget(self.relationships_label)
        
        self.pending_changes_label = self._create_stat_card("Pending Changes", "0", "#ffa500")
        stats_layout.addWidget(self.pending_changes_label)
        
        layout.addLayout(stats_layout)
        
        # Action buttons
        btn_layout = QVBoxLayout()
        
        add_ci_btn = QPushButton("➕ Add CI")
        add_ci_btn.setStyleSheet("""
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
        add_ci_btn.clicked.connect(self._show_add_ci_dialog)
        btn_layout.addWidget(add_ci_btn)
        
        import_btn = QPushButton("📥 Import")
        import_btn.setStyleSheet("""
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
        btn_layout.addWidget(import_btn)
        
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
        card.setFixedWidth(120)
        
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
        
        # Store reference for updates
        card.value_label = value_label
        
        return card
    
    def _create_ci_tab(self) -> QWidget:
        """Create Configuration Items tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Search and filter bar
        filter_frame = QFrame()
        filter_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        filter_layout = QHBoxLayout(filter_frame)
        
        # Search
        self.ci_search = QLineEdit()
        self.ci_search.setPlaceholderText("🔍 Search configuration items...")
        self.ci_search.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
                font-size: 14px;
            }
        """)
        self.ci_search.textChanged.connect(self._filter_cis)
        filter_layout.addWidget(self.ci_search, stretch=2)
        
        # Type filter
        self.type_filter = QComboBox()
        self.type_filter.addItems([
            "All Types", "Server", "Workstation", "Network Device",
            "Firewall", "Database", "Application", "Service",
            "Container", "Virtual Machine", "Cloud Resource"
        ])
        self.type_filter.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
                min-width: 150px;
            }
        """)
        self.type_filter.currentTextChanged.connect(self._filter_cis)
        filter_layout.addWidget(self.type_filter)
        
        # Status filter
        self.status_filter = QComboBox()
        self.status_filter.addItems([
            "All Status", "Active", "Inactive", "Planned",
            "Maintenance", "Decommissioned"
        ])
        self.status_filter.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
                min-width: 130px;
            }
        """)
        self.status_filter.currentTextChanged.connect(self._filter_cis)
        filter_layout.addWidget(self.status_filter)
        
        # Criticality filter
        self.criticality_filter = QComboBox()
        self.criticality_filter.addItems([
            "All Criticality", "Critical", "High", "Medium", "Low"
        ])
        self.criticality_filter.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
                min-width: 130px;
            }
        """)
        self.criticality_filter.currentTextChanged.connect(self._filter_cis)
        filter_layout.addWidget(self.criticality_filter)
        
        layout.addWidget(filter_frame)
        
        # CI Table
        self.ci_table = QTableWidget()
        self.ci_table.setColumnCount(10)
        self.ci_table.setHorizontalHeaderLabels([
            "Name", "Type", "Status", "Criticality", "Owner",
            "IP Address", "Location", "Vulnerabilities", "Risk Score", "Actions"
        ])
        self.ci_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ci_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ci_table.setAlternatingRowColors(True)
        self.ci_table.verticalHeader().setVisible(False)
        self.ci_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
            }
            QTableWidget::item:selected {
                background: #1f6feb30;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 12px;
                border: none;
                font-weight: bold;
            }
        """)
        self.ci_table.doubleClicked.connect(self._show_ci_details)
        layout.addWidget(self.ci_table)
        
        return widget
    
    def _create_relationships_tab(self) -> QWidget:
        """Create Relationships tab"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        
        # Left panel - relationship list
        left_panel = QFrame()
        left_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border-radius: 8px;
            }
        """)
        left_layout = QVBoxLayout(left_panel)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        add_rel_btn = QPushButton("➕ Add Relationship")
        add_rel_btn.setStyleSheet("""
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
        add_rel_btn.clicked.connect(self._show_add_relationship_dialog)
        toolbar.addWidget(add_rel_btn)
        
        toolbar.addStretch()
        left_layout.addLayout(toolbar)
        
        # Relationship type filter
        rel_type_combo = QComboBox()
        rel_type_combo.addItems([
            "All Relationships", "Depends On", "Used By", "Contains",
            "Part Of", "Runs On", "Hosts", "Connects To", "Manages"
        ])
        rel_type_combo.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        left_layout.addWidget(rel_type_combo)
        
        # Relationships table
        self.rel_table = QTableWidget()
        self.rel_table.setColumnCount(5)
        self.rel_table.setHorizontalHeaderLabels([
            "Source CI", "Relationship", "Target CI", "Strength", "Actions"
        ])
        self.rel_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.rel_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        left_layout.addWidget(self.rel_table)
        
        layout.addWidget(left_panel, stretch=2)
        
        # Right panel - dependency tree
        right_panel = QFrame()
        right_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border-radius: 8px;
            }
        """)
        right_layout = QVBoxLayout(right_panel)
        
        tree_label = QLabel("🌲 Dependency Tree")
        tree_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        tree_label.setStyleSheet("color: #00d4ff; padding: 12px;")
        right_layout.addWidget(tree_label)
        
        self.dep_tree = QTreeWidget()
        self.dep_tree.setHeaderLabels(["Asset", "Type", "Status"])
        self.dep_tree.setStyleSheet("""
            QTreeWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #c9d1d9;
            }
            QTreeWidget::item {
                padding: 8px;
            }
            QTreeWidget::item:selected {
                background: #1f6feb30;
            }
        """)
        right_layout.addWidget(self.dep_tree)
        
        layout.addWidget(right_panel, stretch=1)
        
        return widget
    
    def _create_change_tab(self) -> QWidget:
        """Create Change Management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        new_change_btn = QPushButton("📝 New Change Request")
        new_change_btn.setStyleSheet("""
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
        new_change_btn.clicked.connect(self._show_new_change_dialog)
        toolbar.addWidget(new_change_btn)
        
        toolbar.addStretch()
        
        # Status filter
        change_status = QComboBox()
        change_status.addItems([
            "All Changes", "Draft", "Submitted", "Under Review",
            "Approved", "Scheduled", "In Progress", "Completed", "Rejected"
        ])
        change_status.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
                min-width: 150px;
            }
        """)
        toolbar.addWidget(change_status)
        
        layout.addLayout(toolbar)
        
        # Change requests table
        self.change_table = QTableWidget()
        self.change_table.setColumnCount(9)
        self.change_table.setHorizontalHeaderLabels([
            "ID", "Title", "Type", "Priority", "Status",
            "Requested By", "Planned Start", "Affected CIs", "Actions"
        ])
        self.change_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.change_table.setStyleSheet("""
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
        layout.addWidget(self.change_table)
        
        return widget
    
    def _create_topology_tab(self) -> QWidget:
        """Create Topology View tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        # View options
        view_label = QLabel("View:")
        view_label.setStyleSheet("color: #8b949e;")
        toolbar.addWidget(view_label)
        
        view_combo = QComboBox()
        view_combo.addItems([
            "Hierarchical", "Network", "Dependency Graph", "Cluster View"
        ])
        view_combo.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 150px;
            }
        """)
        toolbar.addWidget(view_combo)
        
        toolbar.addStretch()
        
        # Zoom controls
        zoom_out = QPushButton("➖")
        zoom_out.setFixedSize(32, 32)
        zoom_out.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: white;
            }
        """)
        toolbar.addWidget(zoom_out)
        
        self.zoom_label = QLabel("100%")
        self.zoom_label.setStyleSheet("color: #c9d1d9; min-width: 50px;")
        self.zoom_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        toolbar.addWidget(self.zoom_label)
        
        zoom_in = QPushButton("➕")
        zoom_in.setFixedSize(32, 32)
        zoom_in.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: white;
            }
        """)
        toolbar.addWidget(zoom_in)
        
        # Export
        export_btn = QPushButton("📤 Export")
        export_btn.setStyleSheet("""
            QPushButton {
                background: #1f6feb;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
            }
        """)
        toolbar.addWidget(export_btn)
        
        layout.addLayout(toolbar)
        
        # Topology visualization area
        topology_frame = QFrame()
        topology_frame.setStyleSheet("""
            QFrame {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        topology_layout = QVBoxLayout(topology_frame)
        
        # Placeholder for topology graph
        self.topology_tree = QTreeWidget()
        self.topology_tree.setHeaderLabels(["Infrastructure Topology"])
        self.topology_tree.setStyleSheet("""
            QTreeWidget {
                background: transparent;
                border: none;
                color: #c9d1d9;
                font-size: 13px;
            }
            QTreeWidget::item {
                padding: 8px;
                margin: 2px;
            }
            QTreeWidget::item:hover {
                background: #21262d;
            }
            QTreeWidget::item:selected {
                background: #1f6feb30;
            }
        """)
        topology_layout.addWidget(self.topology_tree)
        
        layout.addWidget(topology_frame)
        
        return widget
    
    def _create_reports_tab(self) -> QWidget:
        """Create Reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Report options
        options_frame = QFrame()
        options_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        options_layout = QHBoxLayout(options_frame)
        
        # Report type
        report_type_label = QLabel("Report Type:")
        report_type_label.setStyleSheet("color: #8b949e;")
        options_layout.addWidget(report_type_label)
        
        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems([
            "CMDB Summary", "CI Inventory", "Relationship Map",
            "Change History", "Compliance Status", "Data Quality",
            "Impact Analysis", "Stale CI Report", "Orphaned CIs"
        ])
        self.report_type_combo.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
                min-width: 200px;
            }
        """)
        options_layout.addWidget(self.report_type_combo)
        
        options_layout.addStretch()
        
        generate_btn = QPushButton("📊 Generate Report")
        generate_btn.setStyleSheet("""
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
        generate_btn.clicked.connect(self._generate_report)
        options_layout.addWidget(generate_btn)
        
        export_report_btn = QPushButton("📤 Export")
        export_report_btn.setStyleSheet("""
            QPushButton {
                background: #1f6feb;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
            }
        """)
        options_layout.addWidget(export_report_btn)
        
        layout.addWidget(options_frame)
        
        # Report content area
        content_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Summary panel
        summary_panel = QFrame()
        summary_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border-radius: 8px;
            }
        """)
        summary_layout = QVBoxLayout(summary_panel)
        
        summary_title = QLabel("📈 Summary Statistics")
        summary_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        summary_title.setStyleSheet("color: #00d4ff; padding: 12px;")
        summary_layout.addWidget(summary_title)
        
        # Statistics grid
        stats_grid = QGridLayout()
        stats_grid.setSpacing(12)
        
        self.report_stats = {}
        stat_items = [
            ("Total CIs", "0"),
            ("Active CIs", "0"),
            ("Relationships", "0"),
            ("Pending Changes", "0"),
            ("Compliance Score", "0%"),
            ("Data Quality", "0%"),
            ("Stale CIs", "0"),
            ("Orphaned CIs", "0")
        ]
        
        for i, (label, value) in enumerate(stat_items):
            row, col = divmod(i, 2)
            stat_card = self._create_report_stat(label, value)
            stats_grid.addWidget(stat_card, row, col)
            self.report_stats[label] = stat_card
        
        summary_layout.addLayout(stats_grid)
        summary_layout.addStretch()
        
        content_splitter.addWidget(summary_panel)
        
        # Charts panel
        charts_panel = QFrame()
        charts_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border-radius: 8px;
            }
        """)
        charts_layout = QVBoxLayout(charts_panel)
        
        charts_title = QLabel("📊 Distribution Charts")
        charts_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        charts_title.setStyleSheet("color: #00d4ff; padding: 12px;")
        charts_layout.addWidget(charts_title)
        
        # CI by Type chart placeholder
        type_chart = self._create_chart_placeholder("CIs by Type")
        charts_layout.addWidget(type_chart)
        
        # CI by Status chart placeholder
        status_chart = self._create_chart_placeholder("CIs by Status")
        charts_layout.addWidget(status_chart)
        
        content_splitter.addWidget(charts_panel)
        
        layout.addWidget(content_splitter)
        
        return widget
    
    def _create_report_stat(self, label: str, value: str) -> QFrame:
        """Create a report statistic card"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        value_label.setStyleSheet("color: #00d4ff;")
        layout.addWidget(value_label)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        layout.addWidget(name_label)
        
        card.value_label = value_label
        
        return card
    
    def _create_chart_placeholder(self, title: str) -> QFrame:
        """Create a chart placeholder"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #8b949e; font-size: 12px; padding: 8px;")
        layout.addWidget(title_label)
        
        # Simulated bar chart
        chart_area = QWidget()
        chart_layout = QHBoxLayout(chart_area)
        chart_layout.setSpacing(8)
        
        sample_data = [("Servers", 45), ("Apps", 30), ("Network", 15), ("Cloud", 10)]
        max_val = max(d[1] for d in sample_data)
        
        for name, val in sample_data:
            bar_frame = QVBoxLayout()
            
            bar = QFrame()
            bar.setFixedWidth(40)
            bar.setFixedHeight(int(val / max_val * 100))
            bar.setStyleSheet(f"""
                background: qlineargradient(y1:0, y2:1,
                    stop:0 #00d4ff, stop:1 #0066cc);
                border-radius: 4px;
            """)
            bar_frame.addStretch()
            bar_frame.addWidget(bar)
            
            label = QLabel(name)
            label.setStyleSheet("color: #8b949e; font-size: 10px;")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            bar_frame.addWidget(label)
            
            chart_layout.addLayout(bar_frame)
        
        chart_layout.addStretch()
        layout.addWidget(chart_area)
        
        return frame
    
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
        # Sample CIs
        sample_cis = [
            {
                "name": "Web Server 01", "type": "Server", "status": "Active",
                "criticality": "High", "owner": "IT Operations", "ip": "192.168.1.10",
                "location": "DC-East", "vulns": 3, "risk": 6.5
            },
            {
                "name": "Database Primary", "type": "Database", "status": "Active",
                "criticality": "Critical", "owner": "DBA Team", "ip": "192.168.1.20",
                "location": "DC-East", "vulns": 1, "risk": 8.2
            },
            {
                "name": "Load Balancer", "type": "Network Device", "status": "Active",
                "criticality": "Critical", "owner": "Network Team", "ip": "192.168.1.1",
                "location": "DC-East", "vulns": 0, "risk": 2.1
            },
            {
                "name": "App Server 01", "type": "Server", "status": "Active",
                "criticality": "High", "owner": "DevOps", "ip": "192.168.1.30",
                "location": "DC-West", "vulns": 5, "risk": 7.3
            },
            {
                "name": "Firewall Main", "type": "Firewall", "status": "Active",
                "criticality": "Critical", "owner": "Security", "ip": "10.0.0.1",
                "location": "DC-East", "vulns": 0, "risk": 1.5
            },
            {
                "name": "API Gateway", "type": "Application", "status": "Active",
                "criticality": "High", "owner": "Platform Team", "ip": "192.168.1.40",
                "location": "Cloud-AWS", "vulns": 2, "risk": 5.8
            },
            {
                "name": "Backup Server", "type": "Server", "status": "Maintenance",
                "criticality": "Medium", "owner": "IT Operations", "ip": "192.168.2.10",
                "location": "DC-Backup", "vulns": 0, "risk": 3.2
            },
            {
                "name": "K8s Cluster", "type": "Container", "status": "Active",
                "criticality": "High", "owner": "Platform Team", "ip": "192.168.3.0/24",
                "location": "Cloud-GCP", "vulns": 8, "risk": 6.9
            }
        ]
        
        self.ci_table.setRowCount(len(sample_cis))
        
        for row, ci in enumerate(sample_cis):
            self.ci_table.setItem(row, 0, QTableWidgetItem(ci["name"]))
            self.ci_table.setItem(row, 1, QTableWidgetItem(ci["type"]))
            
            status_item = QTableWidgetItem(ci["status"])
            status_colors = {
                "Active": "#00ff88", "Inactive": "#6e7681",
                "Maintenance": "#ffa500", "Decommissioned": "#ff6b6b"
            }
            status_item.setForeground(QColor(status_colors.get(ci["status"], "#c9d1d9")))
            self.ci_table.setItem(row, 2, status_item)
            
            crit_item = QTableWidgetItem(ci["criticality"])
            crit_colors = {
                "Critical": "#ff6b6b", "High": "#ffa500",
                "Medium": "#ffd700", "Low": "#00d4ff"
            }
            crit_item.setForeground(QColor(crit_colors.get(ci["criticality"], "#c9d1d9")))
            self.ci_table.setItem(row, 3, crit_item)
            
            self.ci_table.setItem(row, 4, QTableWidgetItem(ci["owner"]))
            self.ci_table.setItem(row, 5, QTableWidgetItem(ci["ip"]))
            self.ci_table.setItem(row, 6, QTableWidgetItem(ci["location"]))
            
            vuln_item = QTableWidgetItem(str(ci["vulns"]))
            if ci["vulns"] > 0:
                vuln_item.setForeground(QColor("#ff6b6b"))
            self.ci_table.setItem(row, 7, vuln_item)
            
            risk_item = QTableWidgetItem(f"{ci['risk']:.1f}")
            if ci["risk"] > 7:
                risk_item.setForeground(QColor("#ff6b6b"))
            elif ci["risk"] > 4:
                risk_item.setForeground(QColor("#ffa500"))
            else:
                risk_item.setForeground(QColor("#00ff88"))
            self.ci_table.setItem(row, 8, risk_item)
            
            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)
            
            view_btn = QPushButton("👁️")
            view_btn.setFixedSize(28, 28)
            view_btn.setStyleSheet("""
                QPushButton {
                    background: #1f6feb;
                    border: none;
                    border-radius: 4px;
                }
            """)
            actions_layout.addWidget(view_btn)
            
            edit_btn = QPushButton("✏️")
            edit_btn.setFixedSize(28, 28)
            edit_btn.setStyleSheet("""
                QPushButton {
                    background: #238636;
                    border: none;
                    border-radius: 4px;
                }
            """)
            actions_layout.addWidget(edit_btn)
            
            self.ci_table.setCellWidget(row, 9, actions_widget)
        
        # Update statistics
        self.total_cis_label.value_label.setText(str(len(sample_cis)))
        active_count = sum(1 for ci in sample_cis if ci["status"] == "Active")
        self.active_cis_label.value_label.setText(str(active_count))
        self.relationships_label.value_label.setText("12")
        self.pending_changes_label.value_label.setText("3")
        
        # Load sample relationships
        self._load_sample_relationships()
        
        # Load sample topology
        self._load_sample_topology()
        
        # Load sample changes
        self._load_sample_changes()
    
    def _load_sample_relationships(self):
        """Load sample relationship data"""
        relationships = [
            ("Web Server 01", "Depends On", "Database Primary", 0.9),
            ("App Server 01", "Depends On", "Database Primary", 0.85),
            ("Load Balancer", "Hosts", "Web Server 01", 1.0),
            ("API Gateway", "Connects To", "App Server 01", 0.8),
            ("Firewall Main", "Protects", "Load Balancer", 1.0),
            ("K8s Cluster", "Contains", "API Gateway", 0.95)
        ]
        
        self.rel_table.setRowCount(len(relationships))
        
        for row, (source, rel_type, target, strength) in enumerate(relationships):
            self.rel_table.setItem(row, 0, QTableWidgetItem(source))
            
            rel_item = QTableWidgetItem(rel_type)
            rel_item.setForeground(QColor("#00d4ff"))
            self.rel_table.setItem(row, 1, rel_item)
            
            self.rel_table.setItem(row, 2, QTableWidgetItem(target))
            
            strength_item = QTableWidgetItem(f"{strength:.0%}")
            self.rel_table.setItem(row, 3, strength_item)
            
            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)
            
            delete_btn = QPushButton("🗑️")
            delete_btn.setFixedSize(28, 28)
            delete_btn.setStyleSheet("""
                QPushButton {
                    background: #da3633;
                    border: none;
                    border-radius: 4px;
                }
            """)
            actions_layout.addWidget(delete_btn)
            
            self.rel_table.setCellWidget(row, 4, actions_widget)
    
    def _load_sample_topology(self):
        """Load sample topology tree"""
        self.topology_tree.clear()
        
        # Root node
        root = QTreeWidgetItem(self.topology_tree, ["🏢 Infrastructure"])
        root.setExpanded(True)
        
        # Network layer
        network = QTreeWidgetItem(root, ["🌐 Network Layer"])
        network.setExpanded(True)
        QTreeWidgetItem(network, ["🛡️ Firewall Main", "Firewall", "Active"])
        QTreeWidgetItem(network, ["⚖️ Load Balancer", "Network Device", "Active"])
        
        # Compute layer
        compute = QTreeWidgetItem(root, ["💻 Compute Layer"])
        compute.setExpanded(True)
        QTreeWidgetItem(compute, ["🖥️ Web Server 01", "Server", "Active"])
        QTreeWidgetItem(compute, ["🖥️ App Server 01", "Server", "Active"])
        QTreeWidgetItem(compute, ["🖥️ Backup Server", "Server", "Maintenance"])
        
        # Data layer
        data = QTreeWidgetItem(root, ["💾 Data Layer"])
        data.setExpanded(True)
        QTreeWidgetItem(data, ["🗄️ Database Primary", "Database", "Active"])
        
        # Cloud layer
        cloud = QTreeWidgetItem(root, ["☁️ Cloud Resources"])
        cloud.setExpanded(True)
        QTreeWidgetItem(cloud, ["🔗 API Gateway", "Application", "Active"])
        QTreeWidgetItem(cloud, ["🐳 K8s Cluster", "Container", "Active"])
    
    def _load_sample_changes(self):
        """Load sample change requests"""
        changes = [
            ("CHG-001", "Patch Web Server 01", "Standard", "High", "Scheduled",
             "John Doe", "2024-01-15", "Web Server 01"),
            ("CHG-002", "Database Upgrade", "Normal", "Critical", "Approved",
             "Jane Smith", "2024-01-20", "Database Primary"),
            ("CHG-003", "Firewall Rule Update", "Emergency", "High", "In Progress",
             "Bob Wilson", "2024-01-12", "Firewall Main"),
            ("CHG-004", "K8s Version Upgrade", "Major", "Medium", "Under Review",
             "Alice Brown", "2024-02-01", "K8s Cluster"),
            ("CHG-005", "Network Reconfiguration", "Normal", "High", "Draft",
             "Charlie Davis", "2024-02-10", "Load Balancer")
        ]
        
        self.change_table.setRowCount(len(changes))
        
        for row, change in enumerate(changes):
            for col, value in enumerate(change):
                item = QTableWidgetItem(str(value))
                
                # Color code status
                if col == 4:
                    status_colors = {
                        "Draft": "#6e7681", "Submitted": "#1f6feb",
                        "Under Review": "#ffa500", "Approved": "#238636",
                        "Scheduled": "#00d4ff", "In Progress": "#ffd700",
                        "Completed": "#00ff88", "Rejected": "#ff6b6b"
                    }
                    item.setForeground(QColor(status_colors.get(value, "#c9d1d9")))
                
                # Color code priority
                if col == 3:
                    prio_colors = {
                        "Critical": "#ff6b6b", "High": "#ffa500",
                        "Medium": "#ffd700", "Low": "#00d4ff"
                    }
                    item.setForeground(QColor(prio_colors.get(value, "#c9d1d9")))
                
                self.change_table.setItem(row, col, item)
            
            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)
            
            view_btn = QPushButton("👁️")
            view_btn.setFixedSize(28, 28)
            view_btn.setStyleSheet("""
                QPushButton {
                    background: #1f6feb;
                    border: none;
                    border-radius: 4px;
                }
            """)
            actions_layout.addWidget(view_btn)
            
            approve_btn = QPushButton("✅")
            approve_btn.setFixedSize(28, 28)
            approve_btn.setStyleSheet("""
                QPushButton {
                    background: #238636;
                    border: none;
                    border-radius: 4px;
                }
            """)
            actions_layout.addWidget(approve_btn)
            
            self.change_table.setCellWidget(row, 8, actions_widget)
    
    def _filter_cis(self):
        """Filter CI table based on search and filters"""
        search_text = self.ci_search.text().lower()
        type_filter = self.type_filter.currentText()
        status_filter = self.status_filter.currentText()
        crit_filter = self.criticality_filter.currentText()
        
        for row in range(self.ci_table.rowCount()):
            show = True
            
            # Text search
            if search_text:
                name = self.ci_table.item(row, 0).text().lower() if self.ci_table.item(row, 0) else ""
                ip = self.ci_table.item(row, 5).text().lower() if self.ci_table.item(row, 5) else ""
                if search_text not in name and search_text not in ip:
                    show = False
            
            # Type filter
            if type_filter != "All Types" and show:
                ci_type = self.ci_table.item(row, 1).text() if self.ci_table.item(row, 1) else ""
                if ci_type != type_filter:
                    show = False
            
            # Status filter
            if status_filter != "All Status" and show:
                status = self.ci_table.item(row, 2).text() if self.ci_table.item(row, 2) else ""
                if status != status_filter:
                    show = False
            
            # Criticality filter
            if crit_filter != "All Criticality" and show:
                crit = self.ci_table.item(row, 3).text() if self.ci_table.item(row, 3) else ""
                if crit != crit_filter:
                    show = False
            
            self.ci_table.setRowHidden(row, not show)
    
    def _show_add_ci_dialog(self):
        """Show dialog to add new CI"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Configuration Item")
        dialog.setMinimumSize(500, 600)
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
        layout.setSpacing(12)
        
        # Form fields
        name_edit = QLineEdit()
        name_edit.setPlaceholderText("Enter CI name...")
        layout.addRow("Name:", name_edit)
        
        type_combo = QComboBox()
        type_combo.addItems([
            "Server", "Workstation", "Network Device", "Firewall",
            "Database", "Application", "Service", "Container",
            "Virtual Machine", "Cloud Resource"
        ])
        layout.addRow("Type:", type_combo)
        
        status_combo = QComboBox()
        status_combo.addItems(["Active", "Inactive", "Planned", "Maintenance"])
        layout.addRow("Status:", status_combo)
        
        crit_combo = QComboBox()
        crit_combo.addItems(["Critical", "High", "Medium", "Low"])
        layout.addRow("Criticality:", crit_combo)
        
        owner_edit = QLineEdit()
        owner_edit.setPlaceholderText("Enter owner...")
        layout.addRow("Owner:", owner_edit)
        
        ip_edit = QLineEdit()
        ip_edit.setPlaceholderText("e.g., 192.168.1.10")
        layout.addRow("IP Address:", ip_edit)
        
        hostname_edit = QLineEdit()
        hostname_edit.setPlaceholderText("Enter hostname...")
        layout.addRow("Hostname:", hostname_edit)
        
        location_edit = QLineEdit()
        location_edit.setPlaceholderText("e.g., DC-East")
        layout.addRow("Location:", location_edit)
        
        desc_edit = QTextEdit()
        desc_edit.setPlaceholderText("Enter description...")
        desc_edit.setMaximumHeight(100)
        layout.addRow("Description:", desc_edit)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.exec()
    
    def _show_add_relationship_dialog(self):
        """Show dialog to add relationship"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Relationship")
        dialog.setMinimumSize(400, 300)
        dialog.setStyleSheet("""
            QDialog {
                background: #161b22;
            }
            QLabel {
                color: #c9d1d9;
            }
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        
        layout = QFormLayout(dialog)
        
        source_combo = QComboBox()
        source_combo.addItems([
            "Web Server 01", "Database Primary", "Load Balancer",
            "App Server 01", "Firewall Main", "API Gateway"
        ])
        layout.addRow("Source CI:", source_combo)
        
        rel_combo = QComboBox()
        rel_combo.addItems([
            "Depends On", "Used By", "Contains", "Part Of",
            "Runs On", "Hosts", "Connects To", "Manages"
        ])
        layout.addRow("Relationship:", rel_combo)
        
        target_combo = QComboBox()
        target_combo.addItems([
            "Web Server 01", "Database Primary", "Load Balancer",
            "App Server 01", "Firewall Main", "API Gateway"
        ])
        layout.addRow("Target CI:", target_combo)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.exec()
    
    def _show_new_change_dialog(self):
        """Show dialog to create new change request"""
        dialog = QDialog(self)
        dialog.setWindowTitle("New Change Request")
        dialog.setMinimumSize(500, 600)
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
        
        title_edit = QLineEdit()
        title_edit.setPlaceholderText("Enter change title...")
        layout.addRow("Title:", title_edit)
        
        type_combo = QComboBox()
        type_combo.addItems(["Standard", "Normal", "Emergency", "Major", "Minor"])
        layout.addRow("Type:", type_combo)
        
        priority_combo = QComboBox()
        priority_combo.addItems(["Critical", "High", "Medium", "Low"])
        layout.addRow("Priority:", priority_combo)
        
        desc_edit = QTextEdit()
        desc_edit.setPlaceholderText("Describe the change...")
        desc_edit.setMaximumHeight(100)
        layout.addRow("Description:", desc_edit)
        
        impact_edit = QTextEdit()
        impact_edit.setPlaceholderText("Describe the impact...")
        impact_edit.setMaximumHeight(80)
        layout.addRow("Impact Analysis:", impact_edit)
        
        rollback_edit = QTextEdit()
        rollback_edit.setPlaceholderText("Describe rollback procedure...")
        rollback_edit.setMaximumHeight(80)
        layout.addRow("Rollback Plan:", rollback_edit)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.exec()
    
    def _show_ci_details(self, index):
        """Show CI details dialog"""
        row = index.row()
        name = self.ci_table.item(row, 0).text() if self.ci_table.item(row, 0) else "Unknown"
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"CI Details - {name}")
        dialog.setMinimumSize(600, 500)
        dialog.setStyleSheet("""
            QDialog {
                background: #161b22;
            }
            QLabel {
                color: #c9d1d9;
            }
        """)
        
        layout = QVBoxLayout(dialog)
        
        # Header
        header = QLabel(f"📦 {name}")
        header.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        header.setStyleSheet("color: #00d4ff;")
        layout.addWidget(header)
        
        # Tabs for different info
        tabs = QTabWidget()
        
        # General tab
        general = QWidget()
        general_layout = QFormLayout(general)
        
        for col in range(self.ci_table.columnCount() - 1):
            label = self.ci_table.horizontalHeaderItem(col).text()
            value = self.ci_table.item(row, col).text() if self.ci_table.item(row, col) else "N/A"
            value_label = QLabel(value)
            value_label.setStyleSheet("color: #c9d1d9;")
            general_layout.addRow(f"{label}:", value_label)
        
        tabs.addTab(general, "General")
        
        # Relationships tab
        rels = QWidget()
        rels_layout = QVBoxLayout(rels)
        rels_list = QListWidget()
        rels_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
        """)
        rels_list.addItems([
            f"→ Depends On: Database Primary",
            f"← Used By: Load Balancer"
        ])
        rels_layout.addWidget(rels_list)
        tabs.addTab(rels, "Relationships")
        
        # History tab
        history = QWidget()
        history_layout = QVBoxLayout(history)
        history_list = QListWidget()
        history_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
        """)
        history_list.addItems([
            "2024-01-10: Created by system",
            "2024-01-11: Updated status to Active",
            "2024-01-12: Added vulnerability scan results"
        ])
        history_layout.addWidget(history_list)
        tabs.addTab(history, "History")
        
        layout.addWidget(tabs)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
            }
        """)
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)
        
        dialog.exec()
    
    def _generate_report(self):
        """Generate CMDB report"""
        report_type = self.report_type_combo.currentText()
        
        # Update stats
        self.report_stats["Total CIs"].value_label.setText("8")
        self.report_stats["Active CIs"].value_label.setText("7")
        self.report_stats["Relationships"].value_label.setText("12")
        self.report_stats["Pending Changes"].value_label.setText("3")
        self.report_stats["Compliance Score"].value_label.setText("85%")
        self.report_stats["Data Quality"].value_label.setText("92%")
        self.report_stats["Stale CIs"].value_label.setText("1")
        self.report_stats["Orphaned CIs"].value_label.setText("0")
        
        QMessageBox.information(
            self, "Report Generated",
            f"{report_type} has been generated successfully!"
        )
