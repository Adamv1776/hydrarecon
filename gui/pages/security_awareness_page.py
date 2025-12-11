#!/usr/bin/env python3
"""
HydraRecon Security Awareness Training Page
Enterprise phishing simulation and security training platform.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget,
    QTableWidgetItem, QPushButton, QLabel, QFrame, QComboBox,
    QTextEdit, QLineEdit, QSpinBox, QProgressBar, QSplitter,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QMessageBox,
    QDialog, QFormLayout, QDateEdit, QGroupBox, QScrollArea,
    QListWidget, QListWidgetItem, QCheckBox, QMenu, QFileDialog
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QDate
from PyQt6.QtGui import QFont, QColor, QAction

import asyncio
from datetime import datetime, timedelta


class SecurityAwarenessPage(QWidget):
    """Security awareness training interface"""
    
    campaign_selected = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.engine = None
        self._init_engine()
        self._setup_ui()
        self._connect_signals()
        self._load_data()
    
    def _init_engine(self):
        """Initialize the awareness engine"""
        try:
            from core.security_awareness import SecurityAwarenessEngine
            self.engine = SecurityAwarenessEngine()
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
                background-color: #f0883e;
                color: white;
            }
            QTabBar::tab:hover:!selected {
                background-color: #30363d;
            }
        """)
        
        # Add tabs
        self.tabs.addTab(self._create_dashboard_tab(), "📊 Dashboard")
        self.tabs.addTab(self._create_campaigns_tab(), "🎣 Campaigns")
        self.tabs.addTab(self._create_templates_tab(), "📧 Templates")
        self.tabs.addTab(self._create_targets_tab(), "👥 Targets")
        self.tabs.addTab(self._create_training_tab(), "📚 Training")
        self.tabs.addTab(self._create_reports_tab(), "📈 Reports")
        
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
        
        title = QLabel("🎣 Security Awareness Training")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #f0883e;")
        
        subtitle = QLabel("Phishing simulations and security training platform")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Quick actions
        actions_layout = QHBoxLayout()
        
        new_campaign_btn = QPushButton("🎣 New Campaign")
        new_campaign_btn.setStyleSheet("""
            QPushButton {
                background-color: #f0883e;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d2691e;
            }
        """)
        new_campaign_btn.clicked.connect(self._create_campaign)
        
        import_btn = QPushButton("📥 Import Targets")
        import_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
        """)
        import_btn.clicked.connect(self._import_targets)
        
        assign_btn = QPushButton("📚 Assign Training")
        assign_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #388bfd;
            }
        """)
        
        actions_layout.addWidget(new_campaign_btn)
        actions_layout.addWidget(import_btn)
        actions_layout.addWidget(assign_btn)
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
            ("Total Employees", "0", "#58a6ff", "total_employees"),
            ("Active Campaigns", "0", "#f0883e", "active_campaigns"),
            ("Overall Click Rate", "0%", "#f85149", "click_rate"),
            ("Report Rate", "0%", "#3fb950", "report_rate"),
            ("Training Completion", "0%", "#a371f7", "training_completion"),
            ("High Risk Users", "0", "#f85149", "high_risk")
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
        
        # Charts row
        charts_layout = QHBoxLayout()
        
        # Click rate trend
        trend_frame = QFrame()
        trend_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        trend_layout = QVBoxLayout(trend_frame)
        
        trend_title = QLabel("Click Rate Trend")
        trend_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        trend_title.setStyleSheet("color: #e6e6e6;")
        trend_layout.addWidget(trend_title)
        
        self.trend_chart = QFrame()
        self.trend_chart.setMinimumHeight(200)
        trend_layout.addWidget(self.trend_chart)
        
        charts_layout.addWidget(trend_frame)
        
        # Department comparison
        dept_frame = QFrame()
        dept_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        dept_layout = QVBoxLayout(dept_frame)
        
        dept_title = QLabel("Department Comparison")
        dept_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        dept_title.setStyleSheet("color: #e6e6e6;")
        dept_layout.addWidget(dept_title)
        
        self.dept_table = QTableWidget()
        self.dept_table.setColumnCount(5)
        self.dept_table.setHorizontalHeaderLabels([
            "Department", "Employees", "Click Rate", "Report Rate", "Training"
        ])
        self.dept_table.horizontalHeader().setStretchLastSection(True)
        self.dept_table.setStyleSheet("""
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
        dept_layout.addWidget(self.dept_table)
        
        charts_layout.addWidget(dept_frame)
        
        layout.addLayout(charts_layout)
        
        # Bottom section
        bottom_layout = QHBoxLayout()
        
        # Recent campaigns
        recent_frame = QFrame()
        recent_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        recent_layout = QVBoxLayout(recent_frame)
        
        recent_title = QLabel("Recent Campaigns")
        recent_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        recent_title.setStyleSheet("color: #e6e6e6;")
        recent_layout.addWidget(recent_title)
        
        self.recent_campaigns_list = QListWidget()
        self.recent_campaigns_list.setStyleSheet("""
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
            QListWidget::item:hover {
                background-color: #21262d;
            }
        """)
        recent_layout.addWidget(self.recent_campaigns_list)
        
        bottom_layout.addWidget(recent_frame)
        
        # High risk employees
        risk_frame = QFrame()
        risk_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        risk_layout = QVBoxLayout(risk_frame)
        
        risk_title = QLabel("⚠️ High Risk Employees")
        risk_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        risk_title.setStyleSheet("color: #f85149;")
        risk_layout.addWidget(risk_title)
        
        self.risk_table = QTableWidget()
        self.risk_table.setColumnCount(4)
        self.risk_table.setHorizontalHeaderLabels([
            "Name", "Department", "Risk Score", "Last Clicked"
        ])
        self.risk_table.horizontalHeader().setStretchLastSection(True)
        self.risk_table.setStyleSheet("""
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
        risk_layout.addWidget(self.risk_table)
        
        bottom_layout.addWidget(risk_frame)
        
        layout.addLayout(bottom_layout)
        
        return widget
    
    def _create_campaigns_tab(self) -> QWidget:
        """Create campaigns management tab"""
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
        self.campaign_search = QLineEdit()
        self.campaign_search.setPlaceholderText("🔍 Search campaigns...")
        self.campaign_search.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        filters_layout.addWidget(self.campaign_search)
        
        # Status filter
        self.campaign_status_filter = QComboBox()
        self.campaign_status_filter.addItems([
            "All Statuses", "Draft", "Scheduled", "Running", "Completed", "Cancelled"
        ])
        self.campaign_status_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 140px;
            }
        """)
        filters_layout.addWidget(self.campaign_status_filter)
        
        # Type filter
        self.campaign_type_filter = QComboBox()
        self.campaign_type_filter.addItems([
            "All Types", "Phishing", "Vishing", "Smishing", "USB Drop", "Training"
        ])
        self.campaign_type_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 120px;
            }
        """)
        filters_layout.addWidget(self.campaign_type_filter)
        
        filters_layout.addStretch()
        
        new_btn = QPushButton("🎣 New Campaign")
        new_btn.setStyleSheet("""
            QPushButton {
                background-color: #f0883e;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        new_btn.clicked.connect(self._create_campaign)
        filters_layout.addWidget(new_btn)
        
        layout.addWidget(filters)
        
        # Campaigns table
        self.campaigns_table = QTableWidget()
        self.campaigns_table.setColumnCount(8)
        self.campaigns_table.setHorizontalHeaderLabels([
            "Name", "Type", "Status", "Targets", "Sent", "Opened", "Clicked", "Reported"
        ])
        self.campaigns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.campaigns_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.campaigns_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #c9d1d9;
                gridline-color: #21262d;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #f0883e;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #21262d;
            }
            QTableWidget::item:selected {
                background-color: #f0883e33;
            }
        """)
        self.campaigns_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.campaigns_table.customContextMenuRequested.connect(self._show_campaign_context_menu)
        layout.addWidget(self.campaigns_table)
        
        return widget
    
    def _create_templates_tab(self) -> QWidget:
        """Create templates management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Template categories
        categories_layout = QHBoxLayout()
        
        categories = [
            ("All", "all"),
            ("IT Support", "it"),
            ("HR", "hr"),
            ("Finance", "finance"),
            ("Delivery", "delivery"),
            ("Cloud Services", "cloud"),
            ("Executive", "executive")
        ]
        
        for cat_name, cat_id in categories:
            btn = QPushButton(cat_name)
            btn.setCheckable(True)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #21262d;
                    color: #c9d1d9;
                    border: 1px solid #30363d;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
                QPushButton:checked {
                    background-color: #f0883e;
                    color: white;
                    border-color: #f0883e;
                }
                QPushButton:hover:!checked {
                    background-color: #30363d;
                }
            """)
            if cat_id == "all":
                btn.setChecked(True)
            categories_layout.addWidget(btn)
        
        categories_layout.addStretch()
        
        create_template_btn = QPushButton("➕ Create Template")
        create_template_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        categories_layout.addWidget(create_template_btn)
        
        layout.addLayout(categories_layout)
        
        # Templates grid
        templates_frame = QFrame()
        templates_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        templates_layout = QVBoxLayout(templates_frame)
        
        # Template cards (sample)
        self.templates_list = QListWidget()
        self.templates_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
            }
            QListWidget::item:hover {
                background-color: #21262d;
            }
        """)
        
        # Add sample templates
        sample_templates = [
            ("📧 IT Password Reset", "Easy", "IT Support"),
            ("📁 Shared Document", "Medium", "Cloud Services"),
            ("💰 HR Benefits Update", "Hard", "HR"),
            ("📦 Package Delivery", "Easy", "Delivery"),
            ("👔 CEO Wire Transfer", "Expert", "Executive")
        ]
        
        for name, difficulty, category in sample_templates:
            item = QListWidgetItem(f"{name}\n    Difficulty: {difficulty}  |  Category: {category}")
            self.templates_list.addItem(item)
        
        templates_layout.addWidget(self.templates_list)
        
        layout.addWidget(templates_frame)
        
        return widget
    
    def _create_targets_tab(self) -> QWidget:
        """Create targets management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)
        
        # Actions bar
        actions = QFrame()
        actions.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        actions_layout = QHBoxLayout(actions)
        
        # Search
        self.target_search = QLineEdit()
        self.target_search.setPlaceholderText("🔍 Search employees...")
        self.target_search.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        actions_layout.addWidget(self.target_search)
        
        # Department filter
        self.dept_filter = QComboBox()
        self.dept_filter.addItems(["All Departments"])
        self.dept_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 150px;
            }
        """)
        actions_layout.addWidget(self.dept_filter)
        
        # Group filter
        self.group_filter = QComboBox()
        self.group_filter.addItems(["All Groups"])
        self.group_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 120px;
            }
        """)
        actions_layout.addWidget(self.group_filter)
        
        actions_layout.addStretch()
        
        import_btn = QPushButton("📥 Import CSV")
        import_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        import_btn.clicked.connect(self._import_targets)
        
        add_btn = QPushButton("➕ Add Employee")
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        
        actions_layout.addWidget(import_btn)
        actions_layout.addWidget(add_btn)
        
        layout.addWidget(actions)
        
        # Targets table
        self.targets_table = QTableWidget()
        self.targets_table.setColumnCount(7)
        self.targets_table.setHorizontalHeaderLabels([
            "Name", "Email", "Department", "Position", "Groups", "Risk Score", "Training Status"
        ])
        self.targets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.targets_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.targets_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #c9d1d9;
                gridline-color: #21262d;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #58a6ff;
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
        layout.addWidget(self.targets_table)
        
        return widget
    
    def _create_training_tab(self) -> QWidget:
        """Create training management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Training overview
        overview_layout = QHBoxLayout()
        
        # Training modules
        modules_frame = QFrame()
        modules_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        modules_layout = QVBoxLayout(modules_frame)
        
        modules_header = QHBoxLayout()
        modules_title = QLabel("📚 Training Modules")
        modules_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        modules_title.setStyleSheet("color: #e6e6e6;")
        modules_header.addWidget(modules_title)
        
        modules_header.addStretch()
        
        add_module_btn = QPushButton("➕ Add Module")
        add_module_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        modules_header.addWidget(add_module_btn)
        
        modules_layout.addLayout(modules_header)
        
        # Module list
        self.modules_list = QListWidget()
        self.modules_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
            }
            QListWidget::item:hover {
                background-color: #21262d;
            }
        """)
        
        # Add sample modules
        sample_modules = [
            ("🎣 Phishing Awareness 101", "15 min", "Required"),
            ("🔐 Password Security", "10 min", "Required"),
            ("🎭 Social Engineering Defense", "20 min", "Required"),
            ("📊 Data Protection Basics", "12 min", "Optional"),
            ("📱 Mobile Security", "15 min", "Optional")
        ]
        
        for name, duration, status in sample_modules:
            item = QListWidgetItem(f"{name}\n    Duration: {duration}  |  {status}")
            self.modules_list.addItem(item)
        
        modules_layout.addWidget(self.modules_list)
        
        overview_layout.addWidget(modules_frame)
        
        # Training assignments
        assignments_frame = QFrame()
        assignments_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        assignments_layout = QVBoxLayout(assignments_frame)
        
        assignments_header = QHBoxLayout()
        assignments_title = QLabel("📋 Training Assignments")
        assignments_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        assignments_title.setStyleSheet("color: #e6e6e6;")
        assignments_header.addWidget(assignments_title)
        
        assignments_header.addStretch()
        
        assign_btn = QPushButton("📝 Assign Training")
        assign_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        assignments_header.addWidget(assign_btn)
        
        assignments_layout.addLayout(assignments_header)
        
        # Assignments table
        self.assignments_table = QTableWidget()
        self.assignments_table.setColumnCount(6)
        self.assignments_table.setHorizontalHeaderLabels([
            "Employee", "Module", "Status", "Due Date", "Score", "Completed"
        ])
        self.assignments_table.horizontalHeader().setStretchLastSection(True)
        self.assignments_table.setStyleSheet("""
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
        assignments_layout.addWidget(self.assignments_table)
        
        overview_layout.addWidget(assignments_frame)
        
        layout.addLayout(overview_layout)
        
        return widget
    
    def _create_reports_tab(self) -> QWidget:
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Report options
        options_frame = QFrame()
        options_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        options_layout = QHBoxLayout(options_frame)
        
        # Date range
        options_layout.addWidget(QLabel("Date Range:"))
        
        self.report_start_date = QDateEdit()
        self.report_start_date.setDate(QDate.currentDate().addMonths(-3))
        self.report_start_date.setStyleSheet("""
            QDateEdit {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        options_layout.addWidget(self.report_start_date)
        
        options_layout.addWidget(QLabel("to"))
        
        self.report_end_date = QDateEdit()
        self.report_end_date.setDate(QDate.currentDate())
        self.report_end_date.setStyleSheet("""
            QDateEdit {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        options_layout.addWidget(self.report_end_date)
        
        # Report type
        options_layout.addWidget(QLabel("Report Type:"))
        
        self.report_type = QComboBox()
        self.report_type.addItems([
            "Executive Summary",
            "Campaign Details",
            "Department Analysis",
            "Individual Performance",
            "Training Progress"
        ])
        self.report_type.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 180px;
            }
        """)
        options_layout.addWidget(self.report_type)
        
        options_layout.addStretch()
        
        generate_btn = QPushButton("📊 Generate Report")
        generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #f0883e;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
        """)
        options_layout.addWidget(generate_btn)
        
        layout.addWidget(options_frame)
        
        # Report content
        report_frame = QFrame()
        report_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        report_layout = QVBoxLayout(report_frame)
        
        report_title = QLabel("Security Awareness Report")
        report_title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        report_title.setStyleSheet("color: #e6e6e6;")
        report_layout.addWidget(report_title)
        
        self.report_content = QTextEdit()
        self.report_content.setReadOnly(True)
        self.report_content.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
                font-family: monospace;
            }
        """)
        self.report_content.setPlainText("""
╔══════════════════════════════════════════════════════════════════════╗
║                  SECURITY AWARENESS EXECUTIVE SUMMARY                  ║
╠══════════════════════════════════════════════════════════════════════╣

📊 OVERVIEW
   Select date range and report type, then click Generate Report.

📈 KEY METRICS
   • Total Employees: --
   • Phishing Tests Conducted: --
   • Overall Click Rate: --
   • Report Rate: --
   • Training Completion: --

🎯 RISK DISTRIBUTION
   • High Risk: --
   • Medium Risk: --
   • Low Risk: --

💡 RECOMMENDATIONS
   Generate a report to see recommendations based on your data.

╚══════════════════════════════════════════════════════════════════════╝
        """)
        report_layout.addWidget(self.report_content)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        pdf_btn = QPushButton("📄 Export PDF")
        pdf_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        
        csv_btn = QPushButton("📊 Export CSV")
        csv_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        
        ppt_btn = QPushButton("📑 Export PowerPoint")
        ppt_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        
        export_layout.addWidget(pdf_btn)
        export_layout.addWidget(csv_btn)
        export_layout.addWidget(ppt_btn)
        export_layout.addStretch()
        report_layout.addLayout(export_layout)
        
        layout.addWidget(report_frame)
        
        return widget
    
    def _connect_signals(self):
        """Connect signals"""
        self.campaigns_table.itemSelectionChanged.connect(self._on_campaign_selected)
        self.campaign_search.textChanged.connect(self._filter_campaigns)
    
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
            
            self.stat_labels["total_employees"].setText(str(stats.get("total_employees", 0)))
            self.stat_labels["active_campaigns"].setText(str(stats.get("active_campaigns", 0)))
            self.stat_labels["click_rate"].setText(f"{stats.get('overall_click_rate', 0)}%")
            self.stat_labels["report_rate"].setText(f"{stats.get('overall_report_rate', 0)}%")
            self.stat_labels["training_completion"].setText(f"{stats.get('training_completion_rate', 0)}%")
            self.stat_labels["high_risk"].setText(str(stats.get("high_risk_employees", 0)))
            
        except Exception as e:
            print(f"Dashboard refresh error: {e}")
    
    def _create_campaign(self):
        """Create new phishing campaign"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Phishing Campaign")
        dialog.setMinimumWidth(600)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #161b22;
            }
        """)
        
        layout = QFormLayout(dialog)
        layout.setSpacing(12)
        
        name_input = QLineEdit()
        name_input.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px; border-radius: 4px;")
        layout.addRow("Campaign Name:", name_input)
        
        type_combo = QComboBox()
        type_combo.addItems(["Phishing", "Vishing", "Smishing", "USB Drop", "Training"])
        type_combo.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px;")
        layout.addRow("Campaign Type:", type_combo)
        
        template_combo = QComboBox()
        template_combo.addItems([
            "IT Password Reset",
            "Shared Document",
            "HR Benefits Update",
            "Package Delivery",
            "CEO Wire Transfer"
        ])
        template_combo.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px;")
        layout.addRow("Email Template:", template_combo)
        
        targets_combo = QComboBox()
        targets_combo.addItems(["All Employees", "IT Department", "Finance", "Sales", "Custom Selection"])
        targets_combo.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px;")
        layout.addRow("Target Group:", targets_combo)
        
        schedule_date = QDateEdit()
        schedule_date.setDate(QDate.currentDate().addDays(1))
        schedule_date.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px;")
        layout.addRow("Schedule Date:", schedule_date)
        
        buttons = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        create_btn = QPushButton("Create Campaign")
        create_btn.setStyleSheet("background-color: #f0883e; color: white; padding: 8px 16px; border-radius: 4px;")
        create_btn.clicked.connect(dialog.accept)
        buttons.addWidget(cancel_btn)
        buttons.addWidget(create_btn)
        layout.addRow(buttons)
        
        dialog.exec()
    
    def _import_targets(self):
        """Import targets from CSV"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Targets",
            "",
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            QMessageBox.information(
                self,
                "Import Started",
                f"Importing targets from:\n{file_path}"
            )
    
    def _on_campaign_selected(self):
        """Handle campaign selection"""
        selected = self.campaigns_table.selectedItems()
        if selected:
            campaign_name = self.campaigns_table.item(selected[0].row(), 0).text()
            self.campaign_selected.emit(campaign_name)
    
    def _filter_campaigns(self):
        """Filter campaigns based on search"""
        pass
    
    def _show_campaign_context_menu(self, position):
        """Show context menu for campaigns"""
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
        start_action = menu.addAction("▶️ Start")
        pause_action = menu.addAction("⏸️ Pause")
        menu.addSeparator()
        duplicate_action = menu.addAction("📋 Duplicate")
        delete_action = menu.addAction("🗑️ Delete")
        
        menu.exec(self.campaigns_table.mapToGlobal(position))
