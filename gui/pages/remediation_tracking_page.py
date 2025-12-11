#!/usr/bin/env python3
"""
HydraRecon Remediation Tracking Page
Enterprise vulnerability remediation workflow management.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget,
    QTableWidgetItem, QPushButton, QLabel, QFrame, QComboBox,
    QTextEdit, QLineEdit, QSpinBox, QProgressBar, QSplitter,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QMessageBox,
    QDialog, QFormLayout, QDateEdit, QGroupBox, QScrollArea,
    QListWidget, QListWidgetItem, QCheckBox, QMenu
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QDate
from PyQt6.QtGui import QFont, QColor, QAction

import asyncio
from datetime import datetime, timedelta


class RemediationTrackingPage(QWidget):
    """Vulnerability remediation tracking interface"""
    
    task_selected = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.engine = None
        self._init_engine()
        self._setup_ui()
        self._connect_signals()
        self._load_data()
    
    def _init_engine(self):
        """Initialize the remediation tracking engine"""
        try:
            from core.remediation_tracking import RemediationTrackingEngine
            self.engine = RemediationTrackingEngine()
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
                background-color: #238636;
                color: white;
            }
            QTabBar::tab:hover:!selected {
                background-color: #30363d;
            }
        """)
        
        # Add tabs
        self.tabs.addTab(self._create_dashboard_tab(), "📊 Dashboard")
        self.tabs.addTab(self._create_tasks_tab(), "📋 Tasks")
        self.tabs.addTab(self._create_workflow_tab(), "⚡ Workflow")
        self.tabs.addTab(self._create_sla_tab(), "⏱️ SLA Tracking")
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
        
        title = QLabel("🔧 Remediation Tracking")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")
        
        subtitle = QLabel("Enterprise vulnerability remediation workflow management")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Quick actions
        actions_layout = QHBoxLayout()
        
        new_btn = QPushButton("➕ New Task")
        new_btn.setStyleSheet("""
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
        new_btn.clicked.connect(self._create_task)
        
        import_btn = QPushButton("📥 Import")
        import_btn.setStyleSheet("""
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
        
        export_btn = QPushButton("📤 Export")
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
        
        actions_layout.addWidget(new_btn)
        actions_layout.addWidget(import_btn)
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
            ("Total Tasks", "0", "#58a6ff", "total_tasks"),
            ("In Progress", "0", "#f0883e", "in_progress"),
            ("Pending Verification", "0", "#a371f7", "pending_verification"),
            ("Overdue", "0", "#f85149", "overdue"),
            ("Closed This Week", "0", "#238636", "closed_week"),
            ("SLA Compliance", "0%", "#3fb950", "sla_compliance")
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
        
        # Priority distribution
        priority_frame = QFrame()
        priority_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        priority_layout = QVBoxLayout(priority_frame)
        
        priority_title = QLabel("Tasks by Priority")
        priority_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        priority_title.setStyleSheet("color: #e6e6e6;")
        priority_layout.addWidget(priority_title)
        
        self.priority_chart = QFrame()
        self.priority_chart.setMinimumHeight(200)
        priority_layout.addWidget(self.priority_chart)
        
        charts_layout.addWidget(priority_frame)
        
        # Status distribution
        status_frame = QFrame()
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        status_layout = QVBoxLayout(status_frame)
        
        status_title = QLabel("Tasks by Status")
        status_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        status_title.setStyleSheet("color: #e6e6e6;")
        status_layout.addWidget(status_title)
        
        self.status_chart = QFrame()
        self.status_chart.setMinimumHeight(200)
        status_layout.addWidget(self.status_chart)
        
        charts_layout.addWidget(status_frame)
        
        layout.addLayout(charts_layout)
        
        # Recent activity and overdue
        bottom_layout = QHBoxLayout()
        
        # Recent activity
        activity_frame = QFrame()
        activity_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        activity_layout = QVBoxLayout(activity_frame)
        
        activity_title = QLabel("Recent Activity")
        activity_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        activity_title.setStyleSheet("color: #e6e6e6;")
        activity_layout.addWidget(activity_title)
        
        self.activity_list = QListWidget()
        self.activity_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #21262d;
            }
            QListWidget::item:hover {
                background-color: #21262d;
            }
        """)
        activity_layout.addWidget(self.activity_list)
        
        bottom_layout.addWidget(activity_frame)
        
        # Overdue tasks
        overdue_frame = QFrame()
        overdue_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        overdue_layout = QVBoxLayout(overdue_frame)
        
        overdue_title = QLabel("⚠️ Overdue Tasks")
        overdue_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        overdue_title.setStyleSheet("color: #f85149;")
        overdue_layout.addWidget(overdue_title)
        
        self.overdue_table = QTableWidget()
        self.overdue_table.setColumnCount(4)
        self.overdue_table.setHorizontalHeaderLabels(["Task", "Asset", "Assignee", "Days Overdue"])
        self.overdue_table.horizontalHeader().setStretchLastSection(True)
        self.overdue_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
                gridline-color: #21262d;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #30363d;
            }
        """)
        overdue_layout.addWidget(self.overdue_table)
        
        bottom_layout.addWidget(overdue_frame)
        
        layout.addLayout(bottom_layout)
        
        return widget
    
    def _create_tasks_tab(self) -> QWidget:
        """Create tasks management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)
        
        # Filters bar
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
        self.task_search = QLineEdit()
        self.task_search.setPlaceholderText("🔍 Search tasks...")
        self.task_search.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        filters_layout.addWidget(self.task_search)
        
        # Status filter
        self.status_filter = QComboBox()
        self.status_filter.addItems([
            "All Statuses", "Identified", "Assigned", "In Progress",
            "Pending Verification", "Verified", "Closed", "Overdue"
        ])
        self.status_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 150px;
            }
        """)
        filters_layout.addWidget(self.status_filter)
        
        # Priority filter
        self.priority_filter = QComboBox()
        self.priority_filter.addItems([
            "All Priorities", "Critical", "High", "Medium", "Low", "Informational"
        ])
        self.priority_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 150px;
            }
        """)
        filters_layout.addWidget(self.priority_filter)
        
        # Assignee filter
        self.assignee_filter = QComboBox()
        self.assignee_filter.addItems(["All Assignees"])
        self.assignee_filter.setStyleSheet("""
            QComboBox {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
                min-width: 150px;
            }
        """)
        filters_layout.addWidget(self.assignee_filter)
        
        layout.addWidget(filters)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Tasks table
        table_frame = QFrame()
        table_frame.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        table_layout = QVBoxLayout(table_frame)
        
        self.tasks_table = QTableWidget()
        self.tasks_table.setColumnCount(8)
        self.tasks_table.setHorizontalHeaderLabels([
            "ID", "Vulnerability", "Asset", "Priority", "Status",
            "Assignee", "Due Date", "SLA Status"
        ])
        self.tasks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tasks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tasks_table.setStyleSheet("""
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
                border-bottom: 2px solid #238636;
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
        self.tasks_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tasks_table.customContextMenuRequested.connect(self._show_task_context_menu)
        table_layout.addWidget(self.tasks_table)
        
        splitter.addWidget(table_frame)
        
        # Task details panel
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
        
        details_title = QLabel("Task Details")
        details_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        details_title.setStyleSheet("color: #e6e6e6;")
        details_layout.addWidget(details_title)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        
        details_content = QWidget()
        content_layout = QFormLayout(details_content)
        content_layout.setSpacing(12)
        
        self.detail_labels = {}
        fields = [
            ("ID", "id"),
            ("Vulnerability", "vulnerability"),
            ("Asset", "asset"),
            ("Severity", "severity"),
            ("Priority", "priority"),
            ("Status", "status"),
            ("Assigned To", "assignee"),
            ("Assigned By", "assigned_by"),
            ("Due Date", "due_date"),
            ("SLA Hours", "sla_hours"),
            ("CVSS Score", "cvss"),
            ("CVE IDs", "cves")
        ]
        
        for label, key in fields:
            value = QLabel("-")
            value.setStyleSheet("color: #c9d1d9;")
            value.setWordWrap(True)
            content_layout.addRow(
                QLabel(f"{label}:"),
                value
            )
            self.detail_labels[key] = value
        
        scroll.setWidget(details_content)
        details_layout.addWidget(scroll)
        
        # Action buttons
        actions = QHBoxLayout()
        
        assign_btn = QPushButton("Assign")
        assign_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        
        status_btn = QPushButton("Update Status")
        status_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        
        verify_btn = QPushButton("Verify")
        verify_btn.setStyleSheet("""
            QPushButton {
                background-color: #a371f7;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
        """)
        
        actions.addWidget(assign_btn)
        actions.addWidget(status_btn)
        actions.addWidget(verify_btn)
        details_layout.addLayout(actions)
        
        splitter.addWidget(details_frame)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_workflow_tab(self) -> QWidget:
        """Create workflow management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Workflow visualization
        workflow_frame = QFrame()
        workflow_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        workflow_layout = QVBoxLayout(workflow_frame)
        
        workflow_title = QLabel("Remediation Workflow")
        workflow_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        workflow_title.setStyleSheet("color: #e6e6e6;")
        workflow_layout.addWidget(workflow_title)
        
        # Workflow stages
        stages_layout = QHBoxLayout()
        
        stages = [
            ("Identified", "#8b949e", "→"),
            ("Assigned", "#58a6ff", "→"),
            ("In Progress", "#f0883e", "→"),
            ("Pending Verification", "#a371f7", "→"),
            ("Verified", "#3fb950", "→"),
            ("Closed", "#238636", "")
        ]
        
        for stage, color, arrow in stages:
            stage_widget = QFrame()
            stage_widget.setStyleSheet(f"""
                QFrame {{
                    background-color: {color}22;
                    border: 2px solid {color};
                    border-radius: 8px;
                    padding: 12px;
                }}
            """)
            stage_layout = QVBoxLayout(stage_widget)
            
            stage_label = QLabel(stage)
            stage_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stage_label.setStyleSheet(f"color: {color}; font-weight: bold;")
            stage_layout.addWidget(stage_label)
            
            count_label = QLabel("0")
            count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            count_label.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")
            stage_layout.addWidget(count_label)
            
            stages_layout.addWidget(stage_widget)
            
            if arrow:
                arrow_label = QLabel(arrow)
                arrow_label.setStyleSheet("color: #8b949e; font-size: 20px;")
                stages_layout.addWidget(arrow_label)
        
        workflow_layout.addLayout(stages_layout)
        layout.addWidget(workflow_frame)
        
        # Rules section
        rules_layout = QHBoxLayout()
        
        # Auto-assign rules
        assign_frame = QFrame()
        assign_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        assign_layout = QVBoxLayout(assign_frame)
        
        assign_title = QLabel("Auto-Assignment Rules")
        assign_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        assign_title.setStyleSheet("color: #e6e6e6;")
        assign_layout.addWidget(assign_title)
        
        self.assign_rules_list = QListWidget()
        self.assign_rules_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
            }
        """)
        assign_layout.addWidget(self.assign_rules_list)
        
        add_rule_btn = QPushButton("➕ Add Rule")
        add_rule_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                padding: 8px;
                border-radius: 4px;
            }
        """)
        assign_layout.addWidget(add_rule_btn)
        
        rules_layout.addWidget(assign_frame)
        
        # Escalation rules
        escalation_frame = QFrame()
        escalation_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        escalation_layout = QVBoxLayout(escalation_frame)
        
        escalation_title = QLabel("Escalation Rules")
        escalation_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        escalation_title.setStyleSheet("color: #f0883e;")
        escalation_layout.addWidget(escalation_title)
        
        self.escalation_rules_list = QListWidget()
        self.escalation_rules_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
            }
        """)
        escalation_layout.addWidget(self.escalation_rules_list)
        
        add_escalation_btn = QPushButton("➕ Add Escalation")
        add_escalation_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                padding: 8px;
                border-radius: 4px;
            }
        """)
        escalation_layout.addWidget(add_escalation_btn)
        
        rules_layout.addWidget(escalation_frame)
        
        layout.addLayout(rules_layout)
        
        return widget
    
    def _create_sla_tab(self) -> QWidget:
        """Create SLA tracking tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # SLA overview
        overview_frame = QFrame()
        overview_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        overview_layout = QVBoxLayout(overview_frame)
        
        overview_title = QLabel("SLA Configuration by Priority")
        overview_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        overview_title.setStyleSheet("color: #e6e6e6;")
        overview_layout.addWidget(overview_title)
        
        sla_table = QTableWidget()
        sla_table.setRowCount(5)
        sla_table.setColumnCount(5)
        sla_table.setHorizontalHeaderLabels([
            "Priority", "SLA (Hours)", "Warning Threshold", "Total Tasks", "Compliance %"
        ])
        sla_table.horizontalHeader().setStretchLastSection(True)
        sla_table.setStyleSheet("""
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
        
        priorities = [
            ("Critical", "24", "75%", "0", "100%"),
            ("High", "72", "75%", "0", "100%"),
            ("Medium", "168", "75%", "0", "100%"),
            ("Low", "720", "75%", "0", "100%"),
            ("Informational", "2160", "75%", "0", "100%")
        ]
        
        colors = ["#f85149", "#f0883e", "#d29922", "#3fb950", "#8b949e"]
        
        for row, (priority, sla, warn, total, comp) in enumerate(priorities):
            for col, value in enumerate([priority, sla, warn, total, comp]):
                item = QTableWidgetItem(value)
                if col == 0:
                    item.setForeground(QColor(colors[row]))
                sla_table.setItem(row, col, item)
        
        overview_layout.addWidget(sla_table)
        layout.addWidget(overview_frame)
        
        # SLA metrics
        metrics_layout = QHBoxLayout()
        
        # Compliance chart
        compliance_frame = QFrame()
        compliance_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        compliance_layout = QVBoxLayout(compliance_frame)
        
        compliance_title = QLabel("SLA Compliance Over Time")
        compliance_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        compliance_title.setStyleSheet("color: #e6e6e6;")
        compliance_layout.addWidget(compliance_title)
        
        self.compliance_chart = QFrame()
        self.compliance_chart.setMinimumHeight(200)
        compliance_layout.addWidget(self.compliance_chart)
        
        metrics_layout.addWidget(compliance_frame)
        
        # At risk tasks
        at_risk_frame = QFrame()
        at_risk_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        at_risk_layout = QVBoxLayout(at_risk_frame)
        
        at_risk_title = QLabel("⚠️ Tasks at SLA Risk")
        at_risk_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        at_risk_title.setStyleSheet("color: #f0883e;")
        at_risk_layout.addWidget(at_risk_title)
        
        self.at_risk_table = QTableWidget()
        self.at_risk_table.setColumnCount(4)
        self.at_risk_table.setHorizontalHeaderLabels(["Task", "Assignee", "SLA %", "Time Remaining"])
        self.at_risk_table.horizontalHeader().setStretchLastSection(True)
        self.at_risk_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 4px;
                color: #c9d1d9;
            }
        """)
        at_risk_layout.addWidget(self.at_risk_table)
        
        metrics_layout.addWidget(at_risk_frame)
        
        layout.addLayout(metrics_layout)
        
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
        
        self.start_date = QDateEdit()
        self.start_date.setDate(QDate.currentDate().addDays(-30))
        self.start_date.setStyleSheet("""
            QDateEdit {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        options_layout.addWidget(self.start_date)
        
        options_layout.addWidget(QLabel("to"))
        
        self.end_date = QDateEdit()
        self.end_date.setDate(QDate.currentDate())
        self.end_date.setStyleSheet("""
            QDateEdit {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        options_layout.addWidget(self.end_date)
        
        options_layout.addStretch()
        
        generate_btn = QPushButton("📊 Generate Report")
        generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
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
        
        report_title = QLabel("Remediation Report")
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
        self.report_content.setPlainText("Select date range and click Generate Report to view remediation statistics.")
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
        
        json_btn = QPushButton("📋 Export JSON")
        json_btn.setStyleSheet("""
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
        export_layout.addWidget(json_btn)
        export_layout.addStretch()
        report_layout.addLayout(export_layout)
        
        layout.addWidget(report_frame)
        
        return widget
    
    def _connect_signals(self):
        """Connect signals"""
        self.tasks_table.itemSelectionChanged.connect(self._on_task_selected)
        self.status_filter.currentTextChanged.connect(self._filter_tasks)
        self.priority_filter.currentTextChanged.connect(self._filter_tasks)
        self.task_search.textChanged.connect(self._filter_tasks)
    
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
            
            self.stat_labels["total_tasks"].setText(str(stats.get("total_tasks", 0)))
            self.stat_labels["in_progress"].setText(
                str(stats.get("status_counts", {}).get("in_progress", 0))
            )
            self.stat_labels["pending_verification"].setText(
                str(stats.get("status_counts", {}).get("pending_verification", 0))
            )
            self.stat_labels["overdue"].setText(str(stats.get("overdue_count", 0)))
            self.stat_labels["closed_week"].setText(str(stats.get("closed_this_week", 0)))
            
        except Exception as e:
            print(f"Dashboard refresh error: {e}")
    
    def _create_task(self):
        """Create new remediation task"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Remediation Task")
        dialog.setMinimumWidth(500)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #161b22;
            }
        """)
        
        layout = QFormLayout(dialog)
        layout.setSpacing(12)
        
        vuln_name = QLineEdit()
        vuln_name.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px; border-radius: 4px;")
        layout.addRow("Vulnerability:", vuln_name)
        
        asset_name = QLineEdit()
        asset_name.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px; border-radius: 4px;")
        layout.addRow("Asset:", asset_name)
        
        severity = QComboBox()
        severity.addItems(["Critical", "High", "Medium", "Low", "Info"])
        severity.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px;")
        layout.addRow("Severity:", severity)
        
        description = QTextEdit()
        description.setMaximumHeight(100)
        description.setStyleSheet("background-color: #21262d; color: #c9d1d9; border-radius: 4px;")
        layout.addRow("Description:", description)
        
        assignee = QLineEdit()
        assignee.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px; border-radius: 4px;")
        layout.addRow("Assign To:", assignee)
        
        buttons = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        create_btn = QPushButton("Create")
        create_btn.setStyleSheet("background-color: #238636; color: white; padding: 8px 16px; border-radius: 4px;")
        create_btn.clicked.connect(dialog.accept)
        buttons.addWidget(cancel_btn)
        buttons.addWidget(create_btn)
        layout.addRow(buttons)
        
        dialog.exec()
    
    def _on_task_selected(self):
        """Handle task selection"""
        selected = self.tasks_table.selectedItems()
        if selected:
            task_id = self.tasks_table.item(selected[0].row(), 0).text()
            self.task_selected.emit(task_id)
    
    def _filter_tasks(self):
        """Filter tasks based on criteria"""
        pass
    
    def _show_task_context_menu(self, position):
        """Show context menu for tasks"""
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
        assign_action = menu.addAction("👤 Assign")
        status_action = menu.addAction("📝 Update Status")
        menu.addSeparator()
        verify_action = menu.addAction("✅ Verify")
        close_action = menu.addAction("🔒 Close")
        
        menu.exec(self.tasks_table.mapToGlobal(position))
