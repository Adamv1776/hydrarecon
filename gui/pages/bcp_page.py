#!/usr/bin/env python3
"""
Business Continuity Planning Page
Comprehensive GUI for BCP/DR planning, testing, and management.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QFrame,
    QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QTreeWidget, QTreeWidgetItem, QGroupBox, QFormLayout,
    QSpinBox, QCheckBox, QListWidget, QListWidgetItem,
    QProgressBar, QMessageBox, QDialog, QDialogButtonBox,
    QScrollArea, QGridLayout, QMenu, QInputDialog, QDateEdit,
    QDoubleSpinBox, QStackedWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QDate
from PyQt6.QtGui import QFont, QColor, QAction, QBrush

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any


class BCPPage(QWidget):
    """Business Continuity Planning page"""
    
    status_message = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.current_plan = None
        self.engine = None
        self._init_engine()
        self._setup_ui()
        self._connect_signals()
        self._apply_styles()
    
    def _init_engine(self):
        """Initialize BCP engine"""
        try:
            from core.bcp import (
                BCPEngine, BCPStatus, RecoveryPriority, DisasterType,
                TestType, TestResult
            )
            self.engine = BCPEngine()
            self.BCPStatus = BCPStatus
            self.RecoveryPriority = RecoveryPriority
            self.DisasterType = DisasterType
            self.TestType = TestType
            self.TestResult = TestResult
        except ImportError:
            self.engine = None
    
    def _setup_ui(self):
        """Setup user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        
        # Create tabs
        self.tabs.addTab(self._create_overview_tab(), "📋 Overview")
        self.tabs.addTab(self._create_processes_tab(), "🔄 Business Processes")
        self.tabs.addTab(self._create_systems_tab(), "💻 Critical Systems")
        self.tabs.addTab(self._create_teams_tab(), "👥 Recovery Teams")
        self.tabs.addTab(self._create_sites_tab(), "🏢 Recovery Sites")
        self.tabs.addTab(self._create_testing_tab(), "🧪 Testing")
        self.tabs.addTab(self._create_incidents_tab(), "🚨 Incidents")
        self.tabs.addTab(self._create_compliance_tab(), "✅ Compliance")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        header = QFrame()
        header.setObjectName("header")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("📋 Business Continuity Planning")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        
        subtitle = QLabel("BCP/DR planning, testing, and incident management")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Plan selector
        plan_layout = QHBoxLayout()
        plan_layout.addWidget(QLabel("BCP Plan:"))
        
        self.plan_combo = QComboBox()
        self.plan_combo.setMinimumWidth(200)
        self.plan_combo.addItem("Select or create plan...")
        plan_layout.addWidget(self.plan_combo)
        
        new_plan_btn = QPushButton("+ New Plan")
        new_plan_btn.setObjectName("primaryButton")
        new_plan_btn.clicked.connect(self._create_new_plan)
        plan_layout.addWidget(new_plan_btn)
        
        layout.addLayout(plan_layout)
        
        return header
    
    def _create_overview_tab(self) -> QWidget:
        """Create overview tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.stat_cards = {}
        stats = [
            ("processes", "Business Processes", "0", "#00d4ff"),
            ("systems", "Critical Systems", "0", "#00ff88"),
            ("teams", "Recovery Teams", "0", "#ff6b6b"),
            ("sites", "Recovery Sites", "0", "#ffd93d"),
            ("compliance", "Compliance Score", "0%", "#9d4edd")
        ]
        
        for key, label, value, color in stats:
            card = self._create_stat_card(label, value, color)
            self.stat_cards[key] = card
            stats_layout.addWidget(card)
        
        layout.addLayout(stats_layout)
        
        # Main content splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Plan details
        details_frame = QFrame()
        details_frame.setObjectName("contentFrame")
        details_layout = QVBoxLayout(details_frame)
        
        details_header = QHBoxLayout()
        details_header.addWidget(QLabel("Plan Details"))
        details_header.addStretch()
        
        edit_btn = QPushButton("✏️ Edit")
        edit_btn.clicked.connect(self._edit_plan)
        details_header.addWidget(edit_btn)
        
        approve_btn = QPushButton("✅ Approve")
        approve_btn.clicked.connect(self._approve_plan)
        details_header.addWidget(approve_btn)
        
        details_layout.addLayout(details_header)
        
        form = QFormLayout()
        
        self.plan_name_label = QLabel("-")
        form.addRow("Name:", self.plan_name_label)
        
        self.plan_version_label = QLabel("-")
        form.addRow("Version:", self.plan_version_label)
        
        self.plan_status_label = QLabel("-")
        form.addRow("Status:", self.plan_status_label)
        
        self.plan_owner_label = QLabel("-")
        form.addRow("Owner:", self.plan_owner_label)
        
        self.plan_effective_label = QLabel("-")
        form.addRow("Effective Date:", self.plan_effective_label)
        
        self.plan_review_label = QLabel("-")
        form.addRow("Next Review:", self.plan_review_label)
        
        details_layout.addLayout(form)
        
        # Description
        details_layout.addWidget(QLabel("Scope & Description:"))
        self.plan_desc_text = QTextEdit()
        self.plan_desc_text.setReadOnly(True)
        self.plan_desc_text.setMaximumHeight(120)
        details_layout.addWidget(self.plan_desc_text)
        
        splitter.addWidget(details_frame)
        
        # Recovery sequence
        sequence_frame = QFrame()
        sequence_frame.setObjectName("contentFrame")
        sequence_layout = QVBoxLayout(sequence_frame)
        
        sequence_header = QHBoxLayout()
        sequence_header.addWidget(QLabel("Recovery Sequence"))
        sequence_header.addStretch()
        
        bia_btn = QPushButton("📊 Run BIA")
        bia_btn.clicked.connect(self._run_bia)
        sequence_header.addWidget(bia_btn)
        
        sequence_layout.addLayout(sequence_header)
        
        self.sequence_table = QTableWidget()
        self.sequence_table.setColumnCount(5)
        self.sequence_table.setHorizontalHeaderLabels([
            "Order", "Type", "Name", "RTO", "Priority"
        ])
        self.sequence_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        sequence_layout.addWidget(self.sequence_table)
        
        splitter.addWidget(sequence_frame)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        # Disaster scenarios
        scenarios_frame = QFrame()
        scenarios_frame.setObjectName("contentFrame")
        scenarios_layout = QVBoxLayout(scenarios_frame)
        
        scenarios_header = QHBoxLayout()
        scenarios_header.addWidget(QLabel("Covered Disaster Scenarios"))
        scenarios_header.addStretch()
        
        add_scenario_btn = QPushButton("+ Add Scenario")
        add_scenario_btn.clicked.connect(self._add_scenario)
        scenarios_header.addWidget(add_scenario_btn)
        
        scenarios_layout.addLayout(scenarios_header)
        
        self.scenarios_list = QListWidget()
        self.scenarios_list.setMaximumHeight(100)
        self.scenarios_list.setFlow(QListWidget.Flow.LeftToRight)
        self.scenarios_list.setWrapping(True)
        scenarios_layout.addWidget(self.scenarios_list)
        
        layout.addWidget(scenarios_frame)
        
        return widget
    
    def _create_processes_tab(self) -> QWidget:
        """Create business processes tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.process_search = QLineEdit()
        self.process_search.setPlaceholderText("🔍 Search processes...")
        toolbar.addWidget(self.process_search)
        
        dept_label = QLabel("Department:")
        toolbar.addWidget(dept_label)
        
        self.dept_filter = QComboBox()
        self.dept_filter.addItem("All Departments")
        toolbar.addWidget(self.dept_filter)
        
        toolbar.addStretch()
        
        add_process_btn = QPushButton("+ Add Process")
        add_process_btn.setObjectName("primaryButton")
        add_process_btn.clicked.connect(self._add_process_dialog)
        toolbar.addWidget(add_process_btn)
        
        layout.addLayout(toolbar)
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Processes table
        table_frame = QFrame()
        table_frame.setObjectName("contentFrame")
        table_layout = QVBoxLayout(table_frame)
        
        self.processes_table = QTableWidget()
        self.processes_table.setColumnCount(8)
        self.processes_table.setHorizontalHeaderLabels([
            "Name", "Department", "Owner", "Priority", "RTO", "RPO", "MTO", "Actions"
        ])
        self.processes_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.processes_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.processes_table.itemSelectionChanged.connect(self._on_process_selected)
        table_layout.addWidget(self.processes_table)
        
        splitter.addWidget(table_frame)
        
        # Process editor
        editor_frame = QFrame()
        editor_frame.setObjectName("contentFrame")
        editor_layout = QVBoxLayout(editor_frame)
        
        editor_layout.addWidget(QLabel("Process Details"))
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        form = QFormLayout(scroll_content)
        
        self.process_name_input = QLineEdit()
        form.addRow("Name:", self.process_name_input)
        
        self.process_desc_input = QTextEdit()
        self.process_desc_input.setMaximumHeight(80)
        form.addRow("Description:", self.process_desc_input)
        
        self.process_dept_input = QLineEdit()
        form.addRow("Department:", self.process_dept_input)
        
        self.process_owner_input = QLineEdit()
        form.addRow("Owner:", self.process_owner_input)
        
        self.process_priority_combo = QComboBox()
        if self.engine:
            for p in self.RecoveryPriority:
                self.process_priority_combo.addItem(p.value.title(), p)
        form.addRow("Priority:", self.process_priority_combo)
        
        self.process_rto_spin = QSpinBox()
        self.process_rto_spin.setRange(0, 720)
        self.process_rto_spin.setSuffix(" hours")
        form.addRow("RTO:", self.process_rto_spin)
        
        self.process_rpo_spin = QSpinBox()
        self.process_rpo_spin.setRange(0, 720)
        self.process_rpo_spin.setSuffix(" hours")
        form.addRow("RPO:", self.process_rpo_spin)
        
        self.process_mto_spin = QSpinBox()
        self.process_mto_spin.setRange(0, 2160)
        self.process_mto_spin.setSuffix(" hours")
        form.addRow("MTO:", self.process_mto_spin)
        
        self.process_revenue_spin = QDoubleSpinBox()
        self.process_revenue_spin.setRange(0, 10000000)
        self.process_revenue_spin.setPrefix("$")
        self.process_revenue_spin.setSuffix(" /hour")
        form.addRow("Revenue Impact:", self.process_revenue_spin)
        
        scroll.setWidget(scroll_content)
        editor_layout.addWidget(scroll)
        
        # Dependencies
        editor_layout.addWidget(QLabel("Dependencies:"))
        self.process_deps_list = QListWidget()
        self.process_deps_list.setMaximumHeight(100)
        editor_layout.addWidget(self.process_deps_list)
        
        # Save button
        save_btn = QPushButton("💾 Save Process")
        save_btn.setObjectName("primaryButton")
        save_btn.clicked.connect(self._save_process)
        editor_layout.addWidget(save_btn)
        
        splitter.addWidget(editor_frame)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_systems_tab(self) -> QWidget:
        """Create critical systems tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.system_search = QLineEdit()
        self.system_search.setPlaceholderText("🔍 Search systems...")
        toolbar.addWidget(self.system_search)
        
        type_label = QLabel("Type:")
        toolbar.addWidget(type_label)
        
        self.system_type_filter = QComboBox()
        self.system_type_filter.addItems([
            "All Types", "Application", "Database", "Infrastructure",
            "Network", "Storage", "Cloud Service"
        ])
        toolbar.addWidget(self.system_type_filter)
        
        toolbar.addStretch()
        
        add_system_btn = QPushButton("+ Add System")
        add_system_btn.setObjectName("primaryButton")
        add_system_btn.clicked.connect(self._add_system_dialog)
        toolbar.addWidget(add_system_btn)
        
        layout.addLayout(toolbar)
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Systems table
        table_frame = QFrame()
        table_frame.setObjectName("contentFrame")
        table_layout = QVBoxLayout(table_frame)
        
        self.systems_table = QTableWidget()
        self.systems_table.setColumnCount(8)
        self.systems_table.setHorizontalHeaderLabels([
            "Name", "Type", "Environment", "Priority", "RTO", "RPO", "Backup", "Actions"
        ])
        self.systems_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.systems_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table_layout.addWidget(self.systems_table)
        
        splitter.addWidget(table_frame)
        
        # System editor
        editor_frame = QFrame()
        editor_frame.setObjectName("contentFrame")
        editor_layout = QVBoxLayout(editor_frame)
        
        editor_layout.addWidget(QLabel("System Details"))
        
        form = QFormLayout()
        
        self.system_name_input = QLineEdit()
        form.addRow("Name:", self.system_name_input)
        
        self.system_type_combo = QComboBox()
        self.system_type_combo.addItems([
            "Application", "Database", "Infrastructure",
            "Network", "Storage", "Cloud Service"
        ])
        form.addRow("Type:", self.system_type_combo)
        
        self.system_env_combo = QComboBox()
        self.system_env_combo.addItems([
            "Production", "DR", "Staging", "Development"
        ])
        form.addRow("Environment:", self.system_env_combo)
        
        self.system_priority_combo = QComboBox()
        if self.engine:
            for p in self.RecoveryPriority:
                self.system_priority_combo.addItem(p.value.title(), p)
        form.addRow("Priority:", self.system_priority_combo)
        
        self.system_rto_spin = QSpinBox()
        self.system_rto_spin.setRange(0, 720)
        self.system_rto_spin.setSuffix(" hours")
        form.addRow("RTO:", self.system_rto_spin)
        
        self.system_rpo_spin = QSpinBox()
        self.system_rpo_spin.setRange(0, 720)
        self.system_rpo_spin.setSuffix(" hours")
        form.addRow("RPO:", self.system_rpo_spin)
        
        editor_layout.addLayout(form)
        
        # Backup strategy
        editor_layout.addWidget(QLabel("Backup Strategy:"))
        self.system_backup_input = QTextEdit()
        self.system_backup_input.setMaximumHeight(80)
        editor_layout.addWidget(self.system_backup_input)
        
        # Recovery procedure
        editor_layout.addWidget(QLabel("Recovery Procedure:"))
        self.system_recovery_input = QTextEdit()
        self.system_recovery_input.setMaximumHeight(80)
        editor_layout.addWidget(self.system_recovery_input)
        
        save_btn = QPushButton("💾 Save System")
        save_btn.setObjectName("primaryButton")
        save_btn.clicked.connect(self._save_system)
        editor_layout.addWidget(save_btn)
        
        splitter.addWidget(editor_frame)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_teams_tab(self) -> QWidget:
        """Create recovery teams tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.addStretch()
        
        add_team_btn = QPushButton("+ Add Team")
        add_team_btn.setObjectName("primaryButton")
        add_team_btn.clicked.connect(self._add_team_dialog)
        toolbar.addWidget(add_team_btn)
        
        layout.addLayout(toolbar)
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Teams list
        list_frame = QFrame()
        list_frame.setObjectName("contentFrame")
        list_layout = QVBoxLayout(list_frame)
        
        list_layout.addWidget(QLabel("Recovery Teams"))
        
        self.teams_table = QTableWidget()
        self.teams_table.setColumnCount(5)
        self.teams_table.setHorizontalHeaderLabels([
            "Team Name", "Role", "Lead", "Members", "Actions"
        ])
        self.teams_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.teams_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.teams_table.itemSelectionChanged.connect(self._on_team_selected)
        list_layout.addWidget(self.teams_table)
        
        splitter.addWidget(list_frame)
        
        # Team details
        details_frame = QFrame()
        details_frame.setObjectName("contentFrame")
        details_layout = QVBoxLayout(details_frame)
        
        details_layout.addWidget(QLabel("Team Details"))
        
        form = QFormLayout()
        
        self.team_name_input = QLineEdit()
        form.addRow("Team Name:", self.team_name_input)
        
        self.team_role_input = QLineEdit()
        form.addRow("Role:", self.team_role_input)
        
        self.team_lead_input = QLineEdit()
        form.addRow("Lead:", self.team_lead_input)
        
        self.team_alt_lead_input = QLineEdit()
        form.addRow("Alternate Lead:", self.team_alt_lead_input)
        
        self.team_location_input = QLineEdit()
        form.addRow("Assembly Location:", self.team_location_input)
        
        details_layout.addLayout(form)
        
        # Team members
        details_layout.addWidget(QLabel("Team Members:"))
        
        self.team_members_table = QTableWidget()
        self.team_members_table.setColumnCount(4)
        self.team_members_table.setHorizontalHeaderLabels([
            "Name", "Role", "Phone", "Email"
        ])
        self.team_members_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        details_layout.addWidget(self.team_members_table)
        
        member_btns = QHBoxLayout()
        add_member_btn = QPushButton("+ Add Member")
        add_member_btn.clicked.connect(self._add_team_member)
        member_btns.addWidget(add_member_btn)
        member_btns.addStretch()
        details_layout.addLayout(member_btns)
        
        # Responsibilities
        details_layout.addWidget(QLabel("Responsibilities:"))
        self.team_responsibilities = QTextEdit()
        self.team_responsibilities.setMaximumHeight(100)
        details_layout.addWidget(self.team_responsibilities)
        
        save_btn = QPushButton("💾 Save Team")
        save_btn.setObjectName("primaryButton")
        save_btn.clicked.connect(self._save_team)
        details_layout.addWidget(save_btn)
        
        splitter.addWidget(details_frame)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_sites_tab(self) -> QWidget:
        """Create recovery sites tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.addStretch()
        
        add_site_btn = QPushButton("+ Add Site")
        add_site_btn.setObjectName("primaryButton")
        add_site_btn.clicked.connect(self._add_site_dialog)
        toolbar.addWidget(add_site_btn)
        
        layout.addLayout(toolbar)
        
        # Sites grid
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        self.sites_grid = QGridLayout(scroll_content)
        self.sites_grid.setSpacing(16)
        
        # Sample site cards
        site_types = [
            ("hot", "Hot Site", "Fully operational duplicate", "#00ff88"),
            ("warm", "Warm Site", "Partially configured", "#ffd93d"),
            ("cold", "Cold Site", "Basic infrastructure only", "#00d4ff"),
            ("mobile", "Mobile Site", "Portable recovery unit", "#9d4edd")
        ]
        
        for i, (site_type, name, desc, color) in enumerate(site_types):
            card = self._create_site_card(name, desc, site_type, color)
            self.sites_grid.addWidget(card, i // 2, i % 2)
        
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        
        # Site details
        details_frame = QFrame()
        details_frame.setObjectName("contentFrame")
        details_layout = QVBoxLayout(details_frame)
        
        details_layout.addWidget(QLabel("Site Details"))
        
        form = QFormLayout()
        
        self.site_name_input = QLineEdit()
        form.addRow("Name:", self.site_name_input)
        
        self.site_type_combo = QComboBox()
        self.site_type_combo.addItems(["Hot", "Warm", "Cold", "Mobile"])
        form.addRow("Type:", self.site_type_combo)
        
        self.site_location_input = QLineEdit()
        form.addRow("Location:", self.site_location_input)
        
        self.site_activation_spin = QSpinBox()
        self.site_activation_spin.setRange(0, 168)
        self.site_activation_spin.setSuffix(" hours")
        form.addRow("Activation Time:", self.site_activation_spin)
        
        details_layout.addLayout(form)
        
        layout.addWidget(details_frame)
        
        return widget
    
    def _create_testing_tab(self) -> QWidget:
        """Create testing tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.test_status_filter = QComboBox()
        self.test_status_filter.addItems(["All", "Scheduled", "Completed", "Failed"])
        toolbar.addWidget(QLabel("Status:"))
        toolbar.addWidget(self.test_status_filter)
        
        toolbar.addStretch()
        
        schedule_btn = QPushButton("+ Schedule Test")
        schedule_btn.setObjectName("primaryButton")
        schedule_btn.clicked.connect(self._schedule_test)
        toolbar.addWidget(schedule_btn)
        
        layout.addLayout(toolbar)
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Tests table
        tests_frame = QFrame()
        tests_frame.setObjectName("contentFrame")
        tests_layout = QVBoxLayout(tests_frame)
        
        tests_layout.addWidget(QLabel("Scheduled & Completed Tests"))
        
        self.tests_table = QTableWidget()
        self.tests_table.setColumnCount(8)
        self.tests_table.setHorizontalHeaderLabels([
            "Test Name", "Type", "Scenario", "Scheduled Date", "Duration",
            "Result", "Findings", "Actions"
        ])
        self.tests_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tests_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        tests_layout.addWidget(self.tests_table)
        
        splitter.addWidget(tests_frame)
        
        # Test details/results
        results_frame = QFrame()
        results_frame.setObjectName("contentFrame")
        results_layout = QVBoxLayout(results_frame)
        
        results_header = QHBoxLayout()
        results_header.addWidget(QLabel("Test Details & Results"))
        results_header.addStretch()
        
        execute_btn = QPushButton("▶️ Execute Test")
        execute_btn.clicked.connect(self._execute_test)
        results_header.addWidget(execute_btn)
        
        results_layout.addLayout(results_header)
        
        # Test info form
        form = QFormLayout()
        
        self.test_name_input = QLineEdit()
        form.addRow("Test Name:", self.test_name_input)
        
        self.test_type_combo = QComboBox()
        if self.engine:
            for t in self.TestType:
                self.test_type_combo.addItem(t.value.replace("_", " ").title(), t)
        form.addRow("Test Type:", self.test_type_combo)
        
        self.test_scenario_combo = QComboBox()
        if self.engine:
            for d in self.DisasterType:
                self.test_scenario_combo.addItem(d.value.replace("_", " ").title(), d)
        form.addRow("Scenario:", self.test_scenario_combo)
        
        self.test_date_edit = QDateEdit()
        self.test_date_edit.setDate(QDate.currentDate())
        form.addRow("Date:", self.test_date_edit)
        
        results_layout.addLayout(form)
        
        # Objectives
        results_layout.addWidget(QLabel("Test Objectives:"))
        self.test_objectives = QTextEdit()
        self.test_objectives.setMaximumHeight(80)
        results_layout.addWidget(self.test_objectives)
        
        # Findings
        results_layout.addWidget(QLabel("Findings:"))
        self.test_findings = QTextEdit()
        self.test_findings.setMaximumHeight(80)
        results_layout.addWidget(self.test_findings)
        
        splitter.addWidget(results_frame)
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_incidents_tab(self) -> QWidget:
        """Create incidents tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Alert banner
        alert_frame = QFrame()
        alert_frame.setStyleSheet("""
            QFrame {
                background-color: #ff6b6b20;
                border: 1px solid #ff6b6b;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        alert_layout = QHBoxLayout(alert_frame)
        
        alert_icon = QLabel("🚨")
        alert_icon.setFont(QFont("Segoe UI", 24))
        alert_layout.addWidget(alert_icon)
        
        alert_text = QVBoxLayout()
        alert_title = QLabel("Incident Management")
        alert_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        alert_title.setStyleSheet("color: #ff6b6b;")
        alert_desc = QLabel("Declare, track, and resolve BCP activation incidents")
        alert_desc.setStyleSheet("color: #8b949e;")
        alert_text.addWidget(alert_title)
        alert_text.addWidget(alert_desc)
        alert_layout.addLayout(alert_text)
        
        alert_layout.addStretch()
        
        declare_btn = QPushButton("🚨 Declare Incident")
        declare_btn.setStyleSheet("""
            background-color: #ff6b6b;
            color: white;
            font-weight: bold;
            padding: 12px 24px;
            border-radius: 6px;
        """)
        declare_btn.clicked.connect(self._declare_incident)
        alert_layout.addWidget(declare_btn)
        
        layout.addWidget(alert_frame)
        
        # Active incidents
        active_frame = QFrame()
        active_frame.setObjectName("contentFrame")
        active_layout = QVBoxLayout(active_frame)
        
        active_layout.addWidget(QLabel("Active Incidents"))
        
        self.active_incidents_table = QTableWidget()
        self.active_incidents_table.setColumnCount(7)
        self.active_incidents_table.setHorizontalHeaderLabels([
            "ID", "Name", "Type", "Severity", "Declared", "Status", "Actions"
        ])
        self.active_incidents_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        active_layout.addWidget(self.active_incidents_table)
        
        layout.addWidget(active_frame)
        
        # Incident timeline
        timeline_frame = QFrame()
        timeline_frame.setObjectName("contentFrame")
        timeline_layout = QVBoxLayout(timeline_frame)
        
        timeline_layout.addWidget(QLabel("Incident Timeline"))
        
        self.timeline_list = QListWidget()
        timeline_layout.addWidget(self.timeline_list)
        
        # Action buttons
        action_btns = QHBoxLayout()
        
        update_btn = QPushButton("📝 Add Update")
        update_btn.clicked.connect(self._add_incident_update)
        action_btns.addWidget(update_btn)
        
        escalate_btn = QPushButton("⬆️ Escalate")
        escalate_btn.clicked.connect(self._escalate_incident)
        action_btns.addWidget(escalate_btn)
        
        resolve_btn = QPushButton("✅ Resolve")
        resolve_btn.setStyleSheet("background-color: #00ff88; color: black;")
        resolve_btn.clicked.connect(self._resolve_incident)
        action_btns.addWidget(resolve_btn)
        
        action_btns.addStretch()
        
        timeline_layout.addLayout(action_btns)
        
        layout.addWidget(timeline_frame)
        
        return widget
    
    def _create_compliance_tab(self) -> QWidget:
        """Create compliance tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Compliance score card
        score_frame = QFrame()
        score_frame.setObjectName("contentFrame")
        score_layout = QHBoxLayout(score_frame)
        
        score_visual = QVBoxLayout()
        self.compliance_score_label = QLabel("0%")
        self.compliance_score_label.setFont(QFont("Segoe UI", 48, QFont.Weight.Bold))
        self.compliance_score_label.setStyleSheet("color: #00ff88;")
        self.compliance_score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        score_title = QLabel("Overall Compliance Score")
        score_title.setStyleSheet("color: #8b949e;")
        score_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        score_visual.addWidget(self.compliance_score_label)
        score_visual.addWidget(score_title)
        
        score_layout.addLayout(score_visual)
        
        # Category scores
        categories_layout = QGridLayout()
        
        self.category_bars = {}
        categories = [
            ("documentation", "Documentation"),
            ("testing", "Testing"),
            ("teams", "Recovery Teams"),
            ("systems", "Critical Systems"),
            ("recovery_sites", "Recovery Sites"),
            ("communication", "Communication Plan")
        ]
        
        for i, (key, name) in enumerate(categories):
            row, col = divmod(i, 2)
            
            cat_layout = QVBoxLayout()
            cat_label = QLabel(name)
            cat_label.setStyleSheet("color: #8b949e; font-size: 12px;")
            
            cat_bar = QProgressBar()
            cat_bar.setRange(0, 100)
            cat_bar.setValue(0)
            cat_bar.setTextVisible(True)
            cat_bar.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #21262d;
                    border-radius: 4px;
                    background-color: #0d1117;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #00d4ff;
                    border-radius: 3px;
                }
            """)
            
            self.category_bars[key] = cat_bar
            
            cat_layout.addWidget(cat_label)
            cat_layout.addWidget(cat_bar)
            
            categories_layout.addLayout(cat_layout, row, col)
        
        score_layout.addLayout(categories_layout)
        
        layout.addWidget(score_frame)
        
        # Gaps and recommendations
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Gaps
        gaps_frame = QFrame()
        gaps_frame.setObjectName("contentFrame")
        gaps_layout = QVBoxLayout(gaps_frame)
        
        gaps_layout.addWidget(QLabel("Identified Gaps"))
        
        self.gaps_list = QListWidget()
        gaps_layout.addWidget(self.gaps_list)
        
        splitter.addWidget(gaps_frame)
        
        # Recommendations
        rec_frame = QFrame()
        rec_frame.setObjectName("contentFrame")
        rec_layout = QVBoxLayout(rec_frame)
        
        rec_layout.addWidget(QLabel("Recommendations"))
        
        self.recommendations_list = QListWidget()
        rec_layout.addWidget(self.recommendations_list)
        
        splitter.addWidget(rec_frame)
        
        layout.addWidget(splitter)
        
        # Check compliance button
        check_btn = QPushButton("🔄 Run Compliance Check")
        check_btn.setObjectName("primaryButton")
        check_btn.clicked.connect(self._run_compliance_check)
        layout.addWidget(check_btn)
        
        return widget
    
    def _create_stat_card(self, label: str, value: str, color: str) -> QFrame:
        """Create statistics card"""
        card = QFrame()
        card.setObjectName("statCard")
        card.setStyleSheet(f"""
            QFrame#statCard {{
                background-color: #1a1a2e;
                border: 1px solid {color}40;
                border-radius: 10px;
                padding: 16px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setSpacing(8)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setObjectName("value")
        
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(value_label)
        layout.addWidget(name_label)
        
        return card
    
    def _create_site_card(self, name: str, desc: str, site_type: str, color: str) -> QFrame:
        """Create site type card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #0d1117;
                border: 2px solid {color};
                border-radius: 12px;
                padding: 20px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        icon = QLabel("🏢")
        icon.setFont(QFont("Segoe UI", 32))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        title = QLabel(name)
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {color};")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        desc_label = QLabel(desc)
        desc_label.setStyleSheet("color: #8b949e;")
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setWordWrap(True)
        
        count_label = QLabel("0 sites configured")
        count_label.setStyleSheet("color: #8b949e; font-size: 11px;")
        count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(icon)
        layout.addWidget(title)
        layout.addWidget(desc_label)
        layout.addWidget(count_label)
        
        return card
    
    def _connect_signals(self):
        """Connect signals"""
        self.plan_combo.currentIndexChanged.connect(self._on_plan_changed)
    
    def _apply_styles(self):
        """Apply styling"""
        self.setStyleSheet("""
            QFrame#contentFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                padding: 16px;
            }
            QPushButton#primaryButton {
                background-color: #00d4ff;
                color: black;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton#primaryButton:hover {
                background-color: #00b8e6;
            }
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #21262d;
            }
            QTableWidget::item:selected {
                background-color: #1f6feb40;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #21262d;
            }
            QTabWidget::pane {
                border: none;
            }
            QTabBar::tab {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px 20px;
                margin-right: 4px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #00d4ff;
            }
        """)
    
    # Event handlers
    def _create_new_plan(self):
        """Create new BCP plan"""
        name, ok = QInputDialog.getText(self, "New BCP Plan", "Enter plan name:")
        if ok and name:
            if self.engine:
                asyncio.create_task(self._async_create_plan(name))
    
    async def _async_create_plan(self, name: str):
        """Async create plan"""
        plan = await self.engine.create_plan(
            name,
            "Business Continuity Plan",
            "Organization-wide",
            "BCP Manager"
        )
        self.current_plan = plan
        self.plan_combo.addItem(plan.name, plan.id)
        self.plan_combo.setCurrentIndex(self.plan_combo.count() - 1)
        self.status_message.emit(f"BCP Plan '{name}' created")
    
    def _on_plan_changed(self, index: int):
        """Handle plan selection change"""
        if index > 0:
            plan_id = self.plan_combo.currentData()
            if self.engine and plan_id in self.engine.plans:
                self.current_plan = self.engine.plans[plan_id]
                self._refresh_all_views()
    
    def _refresh_all_views(self):
        """Refresh all views"""
        if not self.current_plan:
            return
        
        plan = self.current_plan
        
        # Update overview
        self.plan_name_label.setText(plan.name)
        self.plan_version_label.setText(plan.version)
        self.plan_status_label.setText(plan.status.value.title())
        self.plan_owner_label.setText(plan.owner)
        self.plan_effective_label.setText(plan.effective_date.strftime("%Y-%m-%d"))
        self.plan_review_label.setText(plan.review_date.strftime("%Y-%m-%d"))
        self.plan_desc_text.setText(f"{plan.scope}\n\n{plan.description}")
        
        # Update stats
        self._update_stat("processes", str(len(plan.processes)))
        self._update_stat("systems", str(len(plan.systems)))
        self._update_stat("teams", str(len(plan.teams)))
        self._update_stat("sites", str(len(plan.sites)))
    
    def _update_stat(self, key: str, value: str):
        """Update stat card"""
        if key in self.stat_cards:
            label = self.stat_cards[key].findChild(QLabel, "value")
            if label:
                label.setText(value)
    
    def _edit_plan(self):
        """Edit current plan"""
        QMessageBox.information(self, "Edit Plan", "Plan edit dialog would open")
    
    def _approve_plan(self):
        """Approve current plan"""
        if self.current_plan:
            self.current_plan.status = self.BCPStatus.APPROVED
            self.plan_status_label.setText("Approved")
            self.status_message.emit("Plan approved")
    
    def _run_bia(self):
        """Run Business Impact Analysis"""
        if not self.current_plan or not self.engine:
            return
        asyncio.create_task(self._async_run_bia())
    
    async def _async_run_bia(self):
        """Async run BIA"""
        analysis = await self.engine.calculate_business_impact(self.current_plan.id)
        
        # Update sequence table
        sequence = analysis.get("recovery_sequence", [])
        self.sequence_table.setRowCount(len(sequence))
        
        for row, item in enumerate(sequence):
            self.sequence_table.setItem(row, 0, QTableWidgetItem(str(item["order"])))
            self.sequence_table.setItem(row, 1, QTableWidgetItem(item["type"].title()))
            self.sequence_table.setItem(row, 2, QTableWidgetItem(item["name"]))
            self.sequence_table.setItem(row, 3, QTableWidgetItem(f"{item['target_rto']}h"))
        
        self.status_message.emit("Business Impact Analysis completed")
    
    def _add_scenario(self):
        """Add disaster scenario"""
        if not self.engine:
            return
        
        scenarios = [d.value.replace("_", " ").title() for d in self.DisasterType]
        scenario, ok = QInputDialog.getItem(
            self, "Add Scenario", "Select disaster scenario:", scenarios, 0, False
        )
        if ok:
            self.scenarios_list.addItem(scenario)
    
    def _add_process_dialog(self):
        """Open add process dialog"""
        self._clear_process_form()
    
    def _clear_process_form(self):
        """Clear process form"""
        self.process_name_input.clear()
        self.process_desc_input.clear()
        self.process_dept_input.clear()
        self.process_owner_input.clear()
    
    def _on_process_selected(self):
        """Handle process selection"""
        pass
    
    def _save_process(self):
        """Save process"""
        if not self.current_plan or not self.engine:
            return
        
        name = self.process_name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Error", "Process name is required")
            return
        
        asyncio.create_task(self._async_save_process(name))
    
    async def _async_save_process(self, name: str):
        """Async save process"""
        process = await self.engine.add_business_process(
            self.current_plan.id,
            name,
            self.process_desc_input.toPlainText(),
            self.process_dept_input.text(),
            self.process_owner_input.text(),
            self.process_priority_combo.currentData(),
            self.process_rto_spin.value(),
            self.process_rpo_spin.value(),
            self.process_mto_spin.value(),
            revenue_impact_per_hour=self.process_revenue_spin.value()
        )
        self._refresh_all_views()
        self.status_message.emit(f"Process '{name}' saved")
    
    def _add_system_dialog(self):
        """Open add system dialog"""
        pass
    
    def _save_system(self):
        """Save system"""
        QMessageBox.information(self, "Save", "System saved")
    
    def _add_team_dialog(self):
        """Open add team dialog"""
        pass
    
    def _on_team_selected(self):
        """Handle team selection"""
        pass
    
    def _add_team_member(self):
        """Add team member"""
        QMessageBox.information(self, "Add Member", "Member dialog would open")
    
    def _save_team(self):
        """Save team"""
        QMessageBox.information(self, "Save", "Team saved")
    
    def _add_site_dialog(self):
        """Open add site dialog"""
        QMessageBox.information(self, "Add Site", "Site dialog would open")
    
    def _schedule_test(self):
        """Schedule BCP test"""
        QMessageBox.information(self, "Schedule Test", "Test scheduling dialog would open")
    
    def _execute_test(self):
        """Execute selected test"""
        QMessageBox.information(self, "Execute", "Test execution would begin")
    
    def _declare_incident(self):
        """Declare BCP incident"""
        if not self.current_plan or not self.engine:
            QMessageBox.warning(self, "Error", "No plan selected")
            return
        
        name, ok = QInputDialog.getText(self, "Declare Incident", "Incident name:")
        if ok and name:
            asyncio.create_task(self._async_declare_incident(name))
    
    async def _async_declare_incident(self, name: str):
        """Async declare incident"""
        incident = await self.engine.declare_incident(
            self.current_plan.id,
            name,
            self.DisasterType.CYBER_ATTACK,
            "high",
            "Incident declared",
            "BCP Manager"
        )
        self.status_message.emit(f"Incident '{name}' declared")
        
        # Add to table
        row = self.active_incidents_table.rowCount()
        self.active_incidents_table.insertRow(row)
        self.active_incidents_table.setItem(row, 0, QTableWidgetItem(incident.id[:8]))
        self.active_incidents_table.setItem(row, 1, QTableWidgetItem(name))
    
    def _add_incident_update(self):
        """Add incident update"""
        QMessageBox.information(self, "Update", "Update dialog would open")
    
    def _escalate_incident(self):
        """Escalate incident"""
        QMessageBox.information(self, "Escalate", "Incident escalated")
    
    def _resolve_incident(self):
        """Resolve incident"""
        QMessageBox.information(self, "Resolve", "Incident resolved")
    
    def _run_compliance_check(self):
        """Run compliance check"""
        if not self.current_plan or not self.engine:
            return
        
        asyncio.create_task(self._async_compliance_check())
    
    async def _async_compliance_check(self):
        """Async compliance check"""
        compliance = await self.engine.check_plan_compliance(self.current_plan.id)
        
        # Update score
        score = compliance.get("overall_score", 0)
        self.compliance_score_label.setText(f"{score:.0f}%")
        
        if score >= 80:
            self.compliance_score_label.setStyleSheet("color: #00ff88;")
        elif score >= 60:
            self.compliance_score_label.setStyleSheet("color: #ffd93d;")
        else:
            self.compliance_score_label.setStyleSheet("color: #ff6b6b;")
        
        self._update_stat("compliance", f"{score:.0f}%")
        
        # Update category bars
        categories = compliance.get("categories", {})
        for key, value in categories.items():
            if key in self.category_bars:
                self.category_bars[key].setValue(int(value))
        
        # Update gaps
        self.gaps_list.clear()
        for gap in compliance.get("gaps", []):
            self.gaps_list.addItem(f"⚠️ {gap}")
        
        # Update recommendations
        self.recommendations_list.clear()
        for rec in compliance.get("recommendations", []):
            self.recommendations_list.addItem(f"💡 {rec}")
        
        self.status_message.emit("Compliance check completed")
