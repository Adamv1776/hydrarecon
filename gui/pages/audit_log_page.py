#!/usr/bin/env python3
"""
HydraRecon Audit Log Management Page
Enterprise security event logging, search, and forensic analysis interface.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QTableWidget, QTableWidgetItem,
    QTabWidget, QLineEdit, QComboBox, QTextEdit, QProgressBar,
    QHeaderView, QGridLayout, QSpinBox, QCheckBox, QSplitter,
    QGroupBox, QListWidget, QListWidgetItem, QDialog, QDialogButtonBox,
    QFormLayout, QDateTimeEdit, QTreeWidget, QTreeWidgetItem,
    QPlainTextEdit, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QDateTime
from PyQt6.QtGui import QFont, QColor, QPainter, QBrush
from PyQt6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis, QPieSeries, QBarSeries, QBarSet, QBarCategoryAxis

from datetime import datetime, timedelta


class AuditLogPage(QWidget):
    """Audit Log Management interface"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.engine = None
        self._init_engine()
        self._setup_ui()
        self._load_data()
    
    def _init_engine(self):
        """Initialize audit log engine"""
        try:
            from core.audit_log import AuditLogEngine
            self.engine = AuditLogEngine()
        except ImportError:
            self.engine = None
    
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
        
        # Event Search tab
        search_tab = self._create_search_tab()
        self.tabs.addTab(search_tab, "🔍 Event Search")
        
        # Live Events tab
        live_tab = self._create_live_tab()
        self.tabs.addTab(live_tab, "📡 Live Events")
        
        # Alerts tab
        alerts_tab = self._create_alerts_tab()
        self.tabs.addTab(alerts_tab, "🚨 Alerts")
        
        # Correlation tab
        correlation_tab = self._create_correlation_tab()
        self.tabs.addTab(correlation_tab, "🔗 Correlation Rules")
        
        # Log Sources tab
        sources_tab = self._create_sources_tab()
        self.tabs.addTab(sources_tab, "📥 Log Sources")
        
        # Reports tab
        reports_tab = self._create_reports_tab()
        self.tabs.addTab(reports_tab, "📊 Reports")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QFrame:
        """Create page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0d419d, stop:1 #1158c7);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_section = QVBoxLayout()
        
        title = QLabel("📋 Audit Log Management")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: white; background: transparent;")
        title_section.addWidget(title)
        
        subtitle = QLabel("Security event logging, correlation, and forensic analysis")
        subtitle.setStyleSheet("color: rgba(255,255,255,0.8); background: transparent;")
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        
        export_btn = QPushButton("📥 Export Logs")
        export_btn.setStyleSheet("""
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
        export_btn.clicked.connect(self._export_logs)
        btn_layout.addWidget(export_btn)
        
        search_btn = QPushButton("🔍 Advanced Search")
        search_btn.setStyleSheet("""
            QPushButton {
                background-color: white;
                color: #0d419d;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #f0f0f0;
            }
        """)
        search_btn.clicked.connect(self._show_advanced_search)
        btn_layout.addWidget(search_btn)
        
        layout.addLayout(btn_layout)
        
        return header
    
    def _create_stats_section(self) -> QFrame:
        """Create statistics cards"""
        container = QFrame()
        layout = QHBoxLayout(container)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 0, 0)
        
        stats = [
            ("total_events", "📊 Total Events (24h)", "0", "#58a6ff"),
            ("active_alerts", "🚨 Active Alerts", "0", "#f85149"),
            ("failed_auth", "❌ Failed Auth", "0", "#d29922"),
            ("log_sources", "📥 Log Sources", "0", "#238636"),
            ("events_per_min", "⚡ Events/Min", "0", "#a371f7")
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
    
    def _create_search_tab(self) -> QWidget:
        """Create event search tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Search bar
        search_frame = QFrame()
        search_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        search_layout = QVBoxLayout(search_frame)
        search_layout.setContentsMargins(16, 16, 16, 16)
        
        # Search input row
        input_row = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search events by user, IP, action, or description...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 12px;
                color: #c9d1d9;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #58a6ff;
            }
        """)
        self.search_input.returnPressed.connect(self._search_events)
        input_row.addWidget(self.search_input)
        
        search_btn = QPushButton("Search")
        search_btn.setStyleSheet("""
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
        search_btn.clicked.connect(self._search_events)
        input_row.addWidget(search_btn)
        
        search_layout.addLayout(input_row)
        
        # Filters row
        filter_row = QHBoxLayout()
        
        filter_row.addWidget(QLabel("Category:"))
        self.category_filter = QComboBox()
        self.category_filter.addItems([
            "All", "Authentication", "Authorization", "Access", 
            "Change", "Security", "System", "Network", "Data"
        ])
        self.category_filter.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 120px;
            }
        """)
        filter_row.addWidget(self.category_filter)
        
        filter_row.addWidget(QLabel("Level:"))
        self.level_filter = QComboBox()
        self.level_filter.addItems(["All", "Critical", "Error", "Warning", "Info", "Debug"])
        self.level_filter.setStyleSheet(self.category_filter.styleSheet())
        filter_row.addWidget(self.level_filter)
        
        filter_row.addWidget(QLabel("Time Range:"))
        self.time_filter = QComboBox()
        self.time_filter.addItems(["Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom"])
        self.time_filter.setStyleSheet(self.category_filter.styleSheet())
        filter_row.addWidget(self.time_filter)
        
        filter_row.addStretch()
        
        search_layout.addLayout(filter_row)
        
        layout.addWidget(search_frame)
        
        # Results table
        self.events_table = QTableWidget()
        self.events_table.setColumnCount(8)
        self.events_table.setHorizontalHeaderLabels([
            "Timestamp", "Level", "Category", "User", "Source IP", "Action", "Outcome", "Description"
        ])
        self.events_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 10px;
                border-bottom: 1px solid #21262d;
                color: #c9d1d9;
            }
            QTableWidget::item:selected {
                background-color: #1f6feb;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                border-bottom: 1px solid #30363d;
                font-weight: bold;
            }
        """)
        self.events_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.events_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.events_table.itemDoubleClicked.connect(self._show_event_details)
        
        layout.addWidget(self.events_table)
        
        # Results info
        results_layout = QHBoxLayout()
        
        self.results_label = QLabel("Showing 0 events")
        self.results_label.setStyleSheet("color: #8b949e;")
        results_layout.addWidget(self.results_label)
        
        results_layout.addStretch()
        
        prev_btn = QPushButton("← Previous")
        prev_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                padding: 8px 16px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #30363d;
            }
        """)
        results_layout.addWidget(prev_btn)
        
        next_btn = QPushButton("Next →")
        next_btn.setStyleSheet(prev_btn.styleSheet())
        results_layout.addWidget(next_btn)
        
        layout.addLayout(results_layout)
        
        return widget
    
    def _create_live_tab(self) -> QWidget:
        """Create live events tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Live stream controls
        controls = QHBoxLayout()
        
        self.stream_status = QLabel("● Live Stream Active")
        self.stream_status.setStyleSheet("color: #238636; font-weight: bold;")
        controls.addWidget(self.stream_status)
        
        controls.addStretch()
        
        pause_btn = QPushButton("⏸ Pause")
        pause_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                padding: 8px 16px;
                border-radius: 6px;
            }
        """)
        controls.addWidget(pause_btn)
        
        clear_btn = QPushButton("🗑 Clear")
        clear_btn.setStyleSheet(pause_btn.styleSheet())
        controls.addWidget(clear_btn)
        
        layout.addLayout(controls)
        
        # Live events log
        self.live_log = QPlainTextEdit()
        self.live_log.setReadOnly(True)
        self.live_log.setStyleSheet("""
            QPlainTextEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #c9d1d9;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                padding: 12px;
            }
        """)
        self.live_log.setPlaceholderText("Live events will appear here...")
        
        # Add sample log entries
        sample_logs = [
            "[2024-01-15 14:23:45] INFO  | auth | User 'admin' logged in from 192.168.1.10",
            "[2024-01-15 14:23:46] WARN  | security | Failed login attempt for 'jsmith' from 203.0.113.50",
            "[2024-01-15 14:23:47] INFO  | access | File '/data/reports/q4.xlsx' accessed by 'mwilson'",
            "[2024-01-15 14:23:48] INFO  | system | Service 'nginx' started on web01",
            "[2024-01-15 14:23:49] WARN  | network | Firewall blocked connection from 10.0.0.5 to port 22",
        ]
        self.live_log.setPlainText("\n".join(sample_logs))
        
        layout.addWidget(self.live_log)
        
        return widget
    
    def _create_alerts_tab(self) -> QWidget:
        """Create alerts tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Alert filters
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Status:"))
        self.alert_status_filter = QComboBox()
        self.alert_status_filter.addItems(["All", "New", "Investigating", "Resolved", "False Positive"])
        self.alert_status_filter.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 120px;
            }
        """)
        filter_layout.addWidget(self.alert_status_filter)
        
        filter_layout.addWidget(QLabel("Severity:"))
        self.alert_severity_filter = QComboBox()
        self.alert_severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        self.alert_severity_filter.setStyleSheet(self.alert_status_filter.styleSheet())
        filter_layout.addWidget(self.alert_severity_filter)
        
        filter_layout.addStretch()
        
        layout.addLayout(filter_layout)
        
        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(7)
        self.alerts_table.setHorizontalHeaderLabels([
            "Severity", "Title", "Rule", "Events", "First Seen", "Status", "Assigned To"
        ])
        self.alerts_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 12px;
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
            }
        """)
        self.alerts_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.alerts_table)
        
        # Alert actions
        action_layout = QHBoxLayout()
        
        investigate_btn = QPushButton("🔍 Investigate")
        investigate_btn.setStyleSheet("""
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
        action_layout.addWidget(investigate_btn)
        
        resolve_btn = QPushButton("✅ Resolve")
        resolve_btn.setStyleSheet("""
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
        action_layout.addWidget(resolve_btn)
        
        dismiss_btn = QPushButton("⛔ False Positive")
        dismiss_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #f85149;
                border: 1px solid #f85149;
                padding: 10px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #f85149;
                color: white;
            }
        """)
        action_layout.addWidget(dismiss_btn)
        
        action_layout.addStretch()
        
        layout.addLayout(action_layout)
        
        return widget
    
    def _create_correlation_tab(self) -> QWidget:
        """Create correlation rules tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Splitter for rules list and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Rules list
        rules_frame = QFrame()
        rules_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        rules_layout = QVBoxLayout(rules_frame)
        
        rules_header = QHBoxLayout()
        rules_title = QLabel("Correlation Rules")
        rules_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        rules_title.setStyleSheet("color: #f0f6fc;")
        rules_header.addWidget(rules_title)
        
        new_rule_btn = QPushButton("+ New Rule")
        new_rule_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
            }
        """)
        new_rule_btn.clicked.connect(self._create_rule)
        rules_header.addWidget(new_rule_btn)
        
        rules_layout.addLayout(rules_header)
        
        self.rules_list = QListWidget()
        self.rules_list.setStyleSheet("""
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
        self.rules_list.itemClicked.connect(self._on_rule_selected)
        rules_layout.addWidget(self.rules_list)
        
        splitter.addWidget(rules_frame)
        
        # Rule details
        details_frame = QFrame()
        details_frame.setStyleSheet(rules_frame.styleSheet())
        details_layout = QVBoxLayout(details_frame)
        
        details_title = QLabel("Rule Details")
        details_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        details_title.setStyleSheet("color: #f0f6fc;")
        details_layout.addWidget(details_title)
        
        # Rule form
        form = QFormLayout()
        
        self.rule_name = QLineEdit()
        self.rule_name.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
            }
        """)
        form.addRow("Name:", self.rule_name)
        
        self.rule_description = QTextEdit()
        self.rule_description.setMaximumHeight(80)
        self.rule_description.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
            }
        """)
        form.addRow("Description:", self.rule_description)
        
        self.rule_severity = QComboBox()
        self.rule_severity.addItems(["Critical", "High", "Medium", "Low"])
        self.rule_severity.setStyleSheet(self.alert_status_filter.styleSheet())
        form.addRow("Severity:", self.rule_severity)
        
        self.rule_threshold = QSpinBox()
        self.rule_threshold.setRange(1, 100)
        self.rule_threshold.setValue(5)
        self.rule_threshold.setStyleSheet("""
            QSpinBox {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        form.addRow("Threshold:", self.rule_threshold)
        
        self.rule_window = QSpinBox()
        self.rule_window.setRange(1, 3600)
        self.rule_window.setValue(300)
        self.rule_window.setSuffix(" seconds")
        self.rule_window.setStyleSheet(self.rule_threshold.styleSheet())
        form.addRow("Time Window:", self.rule_window)
        
        self.rule_enabled = QCheckBox("Enabled")
        self.rule_enabled.setChecked(True)
        self.rule_enabled.setStyleSheet("color: #c9d1d9;")
        form.addRow("", self.rule_enabled)
        
        details_layout.addLayout(form)
        
        # Save button
        save_btn = QPushButton("💾 Save Rule")
        save_btn.setStyleSheet("""
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
        details_layout.addWidget(save_btn)
        
        details_layout.addStretch()
        
        splitter.addWidget(details_frame)
        splitter.setSizes([350, 450])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_sources_tab(self) -> QWidget:
        """Create log sources tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Sources table
        self.sources_table = QTableWidget()
        self.sources_table.setColumnCount(7)
        self.sources_table.setHorizontalHeaderLabels([
            "Name", "Type", "Host", "Protocol", "Format", "Events", "Status"
        ])
        self.sources_table.setStyleSheet("""
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
        self.sources_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.sources_table)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        add_btn = QPushButton("➕ Add Source")
        add_btn.setStyleSheet("""
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
        add_btn.clicked.connect(self._add_log_source)
        action_layout.addWidget(add_btn)
        
        test_btn = QPushButton("🔌 Test Connection")
        test_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
        """)
        action_layout.addWidget(test_btn)
        
        action_layout.addStretch()
        
        layout.addLayout(action_layout)
        
        return widget
    
    def _create_reports_tab(self) -> QWidget:
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Report options
        reports_frame = QFrame()
        reports_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        reports_layout = QVBoxLayout(reports_frame)
        reports_layout.setContentsMargins(20, 20, 20, 20)
        
        reports_title = QLabel("Generate Audit Report")
        reports_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        reports_title.setStyleSheet("color: #f0f6fc;")
        reports_layout.addWidget(reports_title)
        
        # Report form
        form = QFormLayout()
        
        self.report_type = QComboBox()
        self.report_type.addItems([
            "Activity Report", "Security Report", 
            "Compliance Report", "Forensic Timeline"
        ])
        self.report_type.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
                min-width: 200px;
            }
        """)
        form.addRow("Report Type:", self.report_type)
        
        self.report_start = QDateTimeEdit()
        self.report_start.setDateTime(QDateTime.currentDateTime().addDays(-7))
        self.report_start.setStyleSheet("""
            QDateTimeEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
            }
        """)
        form.addRow("Start Date:", self.report_start)
        
        self.report_end = QDateTimeEdit()
        self.report_end.setDateTime(QDateTime.currentDateTime())
        self.report_end.setStyleSheet(self.report_start.styleSheet())
        form.addRow("End Date:", self.report_end)
        
        reports_layout.addLayout(form)
        
        generate_btn = QPushButton("📊 Generate Report")
        generate_btn.setStyleSheet("""
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
        generate_btn.clicked.connect(self._generate_report)
        reports_layout.addWidget(generate_btn)
        
        layout.addWidget(reports_frame)
        
        # Recent reports
        recent_frame = QFrame()
        recent_frame.setStyleSheet(reports_frame.styleSheet())
        recent_layout = QVBoxLayout(recent_frame)
        recent_layout.setContentsMargins(20, 20, 20, 20)
        
        recent_title = QLabel("Recent Reports")
        recent_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        recent_title.setStyleSheet("color: #f0f6fc;")
        recent_layout.addWidget(recent_title)
        
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(5)
        self.reports_table.setHorizontalHeaderLabels([
            "Report", "Type", "Period", "Generated", "Actions"
        ])
        self.reports_table.setStyleSheet("""
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
        self.reports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        recent_layout.addWidget(self.reports_table)
        
        layout.addWidget(recent_frame)
        
        return widget
    
    def _load_data(self):
        """Load all data"""
        self._update_stats()
        self._load_events()
        self._load_alerts()
        self._load_rules()
        self._load_sources()
    
    def _update_stats(self):
        """Update statistics"""
        if not self.engine:
            return
        
        stats = self.engine.get_statistics("24h")
        
        self.stat_labels["total_events"].setText(str(stats["total_events"]))
        self.stat_labels["active_alerts"].setText(str(stats["active_alerts"]))
        self.stat_labels["failed_auth"].setText(str(stats["by_outcome"].get("failure", 0)))
        self.stat_labels["log_sources"].setText(str(stats["log_sources"]))
        self.stat_labels["events_per_min"].setText(str(stats["total_events"] // 1440))
    
    def _load_events(self):
        """Load events into table"""
        if not self.engine:
            return
        
        events = self.engine.search_events(limit=100)
        self.events_table.setRowCount(len(events))
        
        for row, event in enumerate(events):
            # Timestamp
            self.events_table.setItem(row, 0, QTableWidgetItem(
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            ))
            
            # Level with color
            level_item = QTableWidgetItem(event.level.value.upper())
            level_colors = {
                "critical": "#f85149",
                "error": "#f85149",
                "warning": "#d29922",
                "info": "#58a6ff",
                "debug": "#8b949e"
            }
            level_item.setForeground(QColor(level_colors.get(event.level.value, "#c9d1d9")))
            self.events_table.setItem(row, 1, level_item)
            
            # Category
            self.events_table.setItem(row, 2, QTableWidgetItem(event.category.value.title()))
            
            # User
            self.events_table.setItem(row, 3, QTableWidgetItem(event.user or "-"))
            
            # Source IP
            self.events_table.setItem(row, 4, QTableWidgetItem(event.source_ip or "-"))
            
            # Action
            self.events_table.setItem(row, 5, QTableWidgetItem(event.action))
            
            # Outcome
            outcome_item = QTableWidgetItem(event.outcome.value.title())
            if event.outcome.value == "failure":
                outcome_item.setForeground(QColor("#f85149"))
            elif event.outcome.value == "success":
                outcome_item.setForeground(QColor("#238636"))
            self.events_table.setItem(row, 6, outcome_item)
            
            # Description
            self.events_table.setItem(row, 7, QTableWidgetItem(event.description))
        
        self.results_label.setText(f"Showing {len(events)} events")
    
    def _load_alerts(self):
        """Load alerts into table"""
        if not self.engine:
            return
        
        alerts = list(self.engine.alerts.values())
        alerts.sort(key=lambda a: a.first_seen, reverse=True)
        
        self.alerts_table.setRowCount(len(alerts))
        
        for row, alert in enumerate(alerts):
            # Severity with color
            severity_item = QTableWidgetItem(alert.severity.value.upper())
            severity_colors = {
                "critical": "#f85149",
                "high": "#d29922",
                "medium": "#58a6ff",
                "low": "#8b949e"
            }
            severity_item.setForeground(QColor(severity_colors.get(alert.severity.value, "#c9d1d9")))
            self.alerts_table.setItem(row, 0, severity_item)
            
            self.alerts_table.setItem(row, 1, QTableWidgetItem(alert.title))
            self.alerts_table.setItem(row, 2, QTableWidgetItem(alert.rule_name))
            self.alerts_table.setItem(row, 3, QTableWidgetItem(str(alert.event_count)))
            self.alerts_table.setItem(row, 4, QTableWidgetItem(
                alert.first_seen.strftime("%Y-%m-%d %H:%M")
            ))
            
            # Status with color
            status_item = QTableWidgetItem(alert.status.title())
            status_colors = {
                "new": "#f85149",
                "investigating": "#d29922",
                "resolved": "#238636"
            }
            status_item.setForeground(QColor(status_colors.get(alert.status, "#8b949e")))
            self.alerts_table.setItem(row, 5, status_item)
            
            self.alerts_table.setItem(row, 6, QTableWidgetItem(alert.assigned_to or "-"))
    
    def _load_rules(self):
        """Load correlation rules"""
        if not self.engine:
            return
        
        self.rules_list.clear()
        for rule in self.engine.correlation_rules.values():
            status = "✓" if rule.enabled else "○"
            item = QListWidgetItem(f"{status} {rule.name}")
            item.setData(Qt.ItemDataRole.UserRole, rule.id)
            self.rules_list.addItem(item)
    
    def _load_sources(self):
        """Load log sources"""
        if not self.engine:
            return
        
        sources = list(self.engine.log_sources.values())
        self.sources_table.setRowCount(len(sources))
        
        for row, source in enumerate(sources):
            self.sources_table.setItem(row, 0, QTableWidgetItem(source.name))
            self.sources_table.setItem(row, 1, QTableWidgetItem(source.source_type))
            self.sources_table.setItem(row, 2, QTableWidgetItem(source.host))
            self.sources_table.setItem(row, 3, QTableWidgetItem(source.protocol))
            self.sources_table.setItem(row, 4, QTableWidgetItem(source.format))
            self.sources_table.setItem(row, 5, QTableWidgetItem(str(source.events_count)))
            
            status_item = QTableWidgetItem("● Active" if source.enabled else "○ Disabled")
            status_item.setForeground(QColor("#238636" if source.enabled else "#8b949e"))
            self.sources_table.setItem(row, 6, status_item)
    
    def _search_events(self):
        """Search events based on filters"""
        if not self.engine:
            return
        
        query = self.search_input.text()
        category = self.category_filter.currentText()
        level = self.level_filter.currentText()
        time_range = self.time_filter.currentText()
        
        # Parse time range
        start_time = None
        if time_range == "Last Hour":
            start_time = datetime.now() - timedelta(hours=1)
        elif time_range == "Last 24 Hours":
            start_time = datetime.now() - timedelta(hours=24)
        elif time_range == "Last 7 Days":
            start_time = datetime.now() - timedelta(days=7)
        elif time_range == "Last 30 Days":
            start_time = datetime.now() - timedelta(days=30)
        
        # Parse filters
        from core.audit_log import EventCategory, LogLevel
        cat_filter = None
        if category != "All":
            try:
                cat_filter = EventCategory(category.lower())
            except:
                pass
        
        level_filter = None
        if level != "All":
            try:
                level_filter = LogLevel(level.lower())
            except:
                pass
        
        events = self.engine.search_events(
            query=query if query else None,
            category=cat_filter,
            level=level_filter,
            start_time=start_time
        )
        
        self.events_table.setRowCount(len(events))
        
        for row, event in enumerate(events):
            self.events_table.setItem(row, 0, QTableWidgetItem(
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            ))
            
            level_item = QTableWidgetItem(event.level.value.upper())
            level_colors = {
                "critical": "#f85149",
                "error": "#f85149",
                "warning": "#d29922",
                "info": "#58a6ff",
                "debug": "#8b949e"
            }
            level_item.setForeground(QColor(level_colors.get(event.level.value, "#c9d1d9")))
            self.events_table.setItem(row, 1, level_item)
            
            self.events_table.setItem(row, 2, QTableWidgetItem(event.category.value.title()))
            self.events_table.setItem(row, 3, QTableWidgetItem(event.user or "-"))
            self.events_table.setItem(row, 4, QTableWidgetItem(event.source_ip or "-"))
            self.events_table.setItem(row, 5, QTableWidgetItem(event.action))
            
            outcome_item = QTableWidgetItem(event.outcome.value.title())
            if event.outcome.value == "failure":
                outcome_item.setForeground(QColor("#f85149"))
            self.events_table.setItem(row, 6, outcome_item)
            
            self.events_table.setItem(row, 7, QTableWidgetItem(event.description))
        
        self.results_label.setText(f"Showing {len(events)} events")
    
    def _show_event_details(self, item):
        """Show event details dialog"""
        row = item.row()
        # Get event details and show in dialog
        QMessageBox.information(
            self,
            "Event Details",
            f"Timestamp: {self.events_table.item(row, 0).text()}\n"
            f"Level: {self.events_table.item(row, 1).text()}\n"
            f"Category: {self.events_table.item(row, 2).text()}\n"
            f"User: {self.events_table.item(row, 3).text()}\n"
            f"Source: {self.events_table.item(row, 4).text()}\n"
            f"Action: {self.events_table.item(row, 5).text()}\n"
            f"Description: {self.events_table.item(row, 7).text()}"
        )
    
    def _show_advanced_search(self):
        """Show advanced search dialog"""
        pass
    
    def _export_logs(self):
        """Export logs"""
        if not self.engine:
            return
        
        export_data = self.engine.export_events("json")
        QMessageBox.information(
            self,
            "Export Complete",
            f"Exported {len(self.engine.events)} events to JSON format"
        )
    
    def _create_rule(self):
        """Create new correlation rule"""
        pass
    
    def _on_rule_selected(self, item):
        """Handle rule selection"""
        rule_id = item.data(Qt.ItemDataRole.UserRole)
        if rule_id and self.engine and rule_id in self.engine.correlation_rules:
            rule = self.engine.correlation_rules[rule_id]
            self.rule_name.setText(rule.name)
            self.rule_description.setPlainText(rule.description)
            self.rule_threshold.setValue(rule.threshold)
            self.rule_window.setValue(rule.time_window)
            self.rule_enabled.setChecked(rule.enabled)
    
    def _add_log_source(self):
        """Add new log source"""
        pass
    
    def _generate_report(self):
        """Generate audit report"""
        if not self.engine:
            return
        
        report_type = self.report_type.currentText().lower().replace(" ", "_")
        start = self.report_start.dateTime().toPyDateTime()
        end = self.report_end.dateTime().toPyDateTime()
        
        report = self.engine.generate_report(report_type, start, end)
        
        QMessageBox.information(
            self,
            "Report Generated",
            f"Report: {report.name}\n"
            f"Events: {report.event_count}\n"
            f"Period: {start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}"
        )
