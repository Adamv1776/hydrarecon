#!/usr/bin/env python3
"""
Access Control Matrix Page
Comprehensive GUI for role-based access control, permissions, and entitlement management.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QFrame,
    QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QTreeWidget, QTreeWidgetItem, QGroupBox, QFormLayout,
    QSpinBox, QCheckBox, QListWidget, QListWidgetItem,
    QProgressBar, QMessageBox, QDialog, QDialogButtonBox,
    QScrollArea, QGridLayout, QMenu, QInputDialog
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QAction, QBrush

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any


class AccessControlPage(QWidget):
    """Access Control Matrix management page"""
    
    status_message = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.current_matrix = None
        self.engine = None
        self._init_engine()
        self._setup_ui()
        self._connect_signals()
        self._apply_styles()
    
    def _init_engine(self):
        """Initialize access control engine"""
        try:
            from core.access_control import (
                AccessControlEngine, PermissionType, RoleType,
                SoDViolationType, AccessDecision, ReviewStatus
            )
            self.engine = AccessControlEngine()
            self.PermissionType = PermissionType
            self.RoleType = RoleType
            self.SoDViolationType = SoDViolationType
            self.AccessDecision = AccessDecision
            self.ReviewStatus = ReviewStatus
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
        self.tabs.addTab(self._create_matrix_tab(), "📊 Access Matrix")
        self.tabs.addTab(self._create_roles_tab(), "👥 Roles")
        self.tabs.addTab(self._create_permissions_tab(), "🔑 Permissions")
        self.tabs.addTab(self._create_users_tab(), "👤 Users")
        self.tabs.addTab(self._create_sod_tab(), "⚠️ SoD Rules")
        self.tabs.addTab(self._create_requests_tab(), "📝 Access Requests")
        self.tabs.addTab(self._create_reviews_tab(), "🔍 Reviews")
        self.tabs.addTab(self._create_reports_tab(), "📈 Reports")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        header = QFrame()
        header.setObjectName("header")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🔐 Access Control Matrix")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        
        subtitle = QLabel("Role-based access control, entitlements, and separation of duties")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Matrix selector
        matrix_layout = QHBoxLayout()
        matrix_layout.addWidget(QLabel("Matrix:"))
        
        self.matrix_combo = QComboBox()
        self.matrix_combo.setMinimumWidth(200)
        self.matrix_combo.addItem("Select or create matrix...")
        matrix_layout.addWidget(self.matrix_combo)
        
        new_matrix_btn = QPushButton("+ New Matrix")
        new_matrix_btn.setObjectName("primaryButton")
        new_matrix_btn.clicked.connect(self._create_new_matrix)
        matrix_layout.addWidget(new_matrix_btn)
        
        layout.addLayout(matrix_layout)
        
        return header
    
    def _create_matrix_tab(self) -> QWidget:
        """Create access matrix overview tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.stat_cards = {}
        stats = [
            ("total_roles", "Total Roles", "0", "#00d4ff"),
            ("total_permissions", "Total Permissions", "0", "#00ff88"),
            ("total_users", "Total Users", "0", "#ff6b6b"),
            ("active_violations", "SoD Violations", "0", "#ffd93d"),
            ("pending_requests", "Pending Requests", "0", "#9d4edd")
        ]
        
        for key, label, value, color in stats:
            card = self._create_stat_card(label, value, color)
            self.stat_cards[key] = card
            stats_layout.addWidget(card)
        
        layout.addLayout(stats_layout)
        
        # Splitter for matrix view and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Matrix visualization
        matrix_frame = QFrame()
        matrix_frame.setObjectName("contentFrame")
        matrix_layout = QVBoxLayout(matrix_frame)
        
        matrix_header = QHBoxLayout()
        matrix_header.addWidget(QLabel("Access Matrix (Role x Permission)"))
        matrix_header.addStretch()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_matrix)
        matrix_header.addWidget(refresh_btn)
        
        export_btn = QPushButton("📥 Export")
        export_btn.clicked.connect(self._export_matrix)
        matrix_header.addWidget(export_btn)
        
        matrix_layout.addLayout(matrix_header)
        
        self.matrix_table = QTableWidget()
        self.matrix_table.setAlternatingRowColors(True)
        self.matrix_table.horizontalHeader().setStretchLastSection(True)
        matrix_layout.addWidget(self.matrix_table)
        
        splitter.addWidget(matrix_frame)
        
        # Details panel
        details_frame = QFrame()
        details_frame.setObjectName("contentFrame")
        details_layout = QVBoxLayout(details_frame)
        
        details_layout.addWidget(QLabel("Selection Details"))
        
        self.details_tree = QTreeWidget()
        self.details_tree.setHeaderLabels(["Property", "Value"])
        self.details_tree.setAlternatingRowColors(True)
        details_layout.addWidget(self.details_tree)
        
        splitter.addWidget(details_frame)
        splitter.setSizes([700, 300])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_roles_tab(self) -> QWidget:
        """Create roles management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.role_search = QLineEdit()
        self.role_search.setPlaceholderText("🔍 Search roles...")
        self.role_search.textChanged.connect(self._filter_roles)
        toolbar.addWidget(self.role_search)
        
        toolbar.addStretch()
        
        add_role_btn = QPushButton("+ Add Role")
        add_role_btn.setObjectName("primaryButton")
        add_role_btn.clicked.connect(self._add_role_dialog)
        toolbar.addWidget(add_role_btn)
        
        import_btn = QPushButton("📥 Import")
        toolbar.addWidget(import_btn)
        
        layout.addLayout(toolbar)
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Roles list
        roles_frame = QFrame()
        roles_frame.setObjectName("contentFrame")
        roles_layout = QVBoxLayout(roles_frame)
        
        self.roles_table = QTableWidget()
        self.roles_table.setColumnCount(6)
        self.roles_table.setHorizontalHeaderLabels([
            "Name", "Type", "Permissions", "Users", "Risk Score", "Actions"
        ])
        self.roles_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.roles_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.roles_table.itemSelectionChanged.connect(self._on_role_selected)
        roles_layout.addWidget(self.roles_table)
        
        splitter.addWidget(roles_frame)
        
        # Role editor
        editor_frame = QFrame()
        editor_frame.setObjectName("contentFrame")
        editor_layout = QVBoxLayout(editor_frame)
        
        editor_layout.addWidget(QLabel("Role Editor"))
        
        form = QFormLayout()
        
        self.role_name_input = QLineEdit()
        form.addRow("Name:", self.role_name_input)
        
        self.role_desc_input = QTextEdit()
        self.role_desc_input.setMaximumHeight(80)
        form.addRow("Description:", self.role_desc_input)
        
        self.role_type_combo = QComboBox()
        if self.engine:
            for rt in self.RoleType:
                self.role_type_combo.addItem(rt.value.title(), rt)
        form.addRow("Type:", self.role_type_combo)
        
        self.role_risk_spin = QSpinBox()
        self.role_risk_spin.setRange(0, 10)
        form.addRow("Risk Score:", self.role_risk_spin)
        
        self.role_approval_check = QCheckBox("Requires approval")
        form.addRow("", self.role_approval_check)
        
        self.role_max_users_spin = QSpinBox()
        self.role_max_users_spin.setRange(0, 10000)
        self.role_max_users_spin.setSpecialValueText("Unlimited")
        form.addRow("Max Users:", self.role_max_users_spin)
        
        editor_layout.addLayout(form)
        
        # Permissions assignment
        editor_layout.addWidget(QLabel("Assigned Permissions:"))
        
        self.role_perms_list = QListWidget()
        self.role_perms_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        editor_layout.addWidget(self.role_perms_list)
        
        # Save button
        save_role_btn = QPushButton("💾 Save Role")
        save_role_btn.setObjectName("primaryButton")
        save_role_btn.clicked.connect(self._save_role)
        editor_layout.addWidget(save_role_btn)
        
        splitter.addWidget(editor_frame)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_permissions_tab(self) -> QWidget:
        """Create permissions management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.perm_search = QLineEdit()
        self.perm_search.setPlaceholderText("🔍 Search permissions...")
        self.perm_search.textChanged.connect(self._filter_permissions)
        toolbar.addWidget(self.perm_search)
        
        toolbar.addStretch()
        
        add_perm_btn = QPushButton("+ Add Permission")
        add_perm_btn.setObjectName("primaryButton")
        add_perm_btn.clicked.connect(self._add_permission_dialog)
        toolbar.addWidget(add_perm_btn)
        
        layout.addLayout(toolbar)
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Permissions tree by resource
        tree_frame = QFrame()
        tree_frame.setObjectName("contentFrame")
        tree_layout = QVBoxLayout(tree_frame)
        
        tree_layout.addWidget(QLabel("Permissions by Resource"))
        
        self.perms_tree = QTreeWidget()
        self.perms_tree.setHeaderLabels(["Permission", "Type", "Risk Level"])
        self.perms_tree.setAlternatingRowColors(True)
        self.perms_tree.itemClicked.connect(self._on_permission_selected)
        tree_layout.addWidget(self.perms_tree)
        
        splitter.addWidget(tree_frame)
        
        # Permission editor
        editor_frame = QFrame()
        editor_frame.setObjectName("contentFrame")
        editor_layout = QVBoxLayout(editor_frame)
        
        editor_layout.addWidget(QLabel("Permission Editor"))
        
        form = QFormLayout()
        
        self.perm_name_input = QLineEdit()
        form.addRow("Name:", self.perm_name_input)
        
        self.perm_desc_input = QTextEdit()
        self.perm_desc_input.setMaximumHeight(80)
        form.addRow("Description:", self.perm_desc_input)
        
        self.perm_type_combo = QComboBox()
        if self.engine:
            for pt in self.PermissionType:
                self.perm_type_combo.addItem(pt.value.title(), pt)
        form.addRow("Type:", self.perm_type_combo)
        
        self.perm_resource_input = QLineEdit()
        form.addRow("Resource:", self.perm_resource_input)
        
        self.perm_action_input = QLineEdit()
        form.addRow("Action:", self.perm_action_input)
        
        self.perm_scope_combo = QComboBox()
        self.perm_scope_combo.addItems(["global", "department", "team", "personal"])
        form.addRow("Scope:", self.perm_scope_combo)
        
        self.perm_risk_combo = QComboBox()
        self.perm_risk_combo.addItems(["low", "medium", "high", "critical"])
        form.addRow("Risk Level:", self.perm_risk_combo)
        
        self.perm_mfa_check = QCheckBox("Requires MFA")
        form.addRow("", self.perm_mfa_check)
        
        self.perm_time_bound_check = QCheckBox("Time-bound access")
        form.addRow("", self.perm_time_bound_check)
        
        editor_layout.addLayout(form)
        
        # Conditions
        editor_layout.addWidget(QLabel("Access Conditions (JSON):"))
        self.perm_conditions_input = QTextEdit()
        self.perm_conditions_input.setMaximumHeight(100)
        self.perm_conditions_input.setPlaceholderText('{"time": {"in": ["09:00-17:00"]}}')
        editor_layout.addWidget(self.perm_conditions_input)
        
        save_perm_btn = QPushButton("💾 Save Permission")
        save_perm_btn.setObjectName("primaryButton")
        save_perm_btn.clicked.connect(self._save_permission)
        editor_layout.addWidget(save_perm_btn)
        
        splitter.addWidget(editor_frame)
        splitter.setSizes([500, 500])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_users_tab(self) -> QWidget:
        """Create users management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.user_search = QLineEdit()
        self.user_search.setPlaceholderText("🔍 Search users...")
        self.user_search.textChanged.connect(self._filter_users)
        toolbar.addWidget(self.user_search)
        
        dept_label = QLabel("Department:")
        toolbar.addWidget(dept_label)
        
        self.dept_filter = QComboBox()
        self.dept_filter.addItem("All Departments")
        self.dept_filter.currentTextChanged.connect(self._filter_users)
        toolbar.addWidget(self.dept_filter)
        
        toolbar.addStretch()
        
        add_user_btn = QPushButton("+ Add User")
        add_user_btn.setObjectName("primaryButton")
        add_user_btn.clicked.connect(self._add_user_dialog)
        toolbar.addWidget(add_user_btn)
        
        sync_btn = QPushButton("🔄 Sync from AD")
        sync_btn.clicked.connect(self._sync_from_ad)
        toolbar.addWidget(sync_btn)
        
        layout.addLayout(toolbar)
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Users table
        users_frame = QFrame()
        users_frame.setObjectName("contentFrame")
        users_layout = QVBoxLayout(users_frame)
        
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(7)
        self.users_table.setHorizontalHeaderLabels([
            "Username", "Email", "Department", "Roles", "Risk Score", "Status", "Actions"
        ])
        self.users_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.users_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.users_table.itemSelectionChanged.connect(self._on_user_selected)
        users_layout.addWidget(self.users_table)
        
        splitter.addWidget(users_frame)
        
        # User details/editor
        details_frame = QFrame()
        details_frame.setObjectName("contentFrame")
        details_layout = QVBoxLayout(details_frame)
        
        details_layout.addWidget(QLabel("User Details"))
        
        form = QFormLayout()
        
        self.user_name_input = QLineEdit()
        form.addRow("Username:", self.user_name_input)
        
        self.user_email_input = QLineEdit()
        form.addRow("Email:", self.user_email_input)
        
        self.user_dept_input = QLineEdit()
        form.addRow("Department:", self.user_dept_input)
        
        self.user_manager_input = QLineEdit()
        form.addRow("Manager:", self.user_manager_input)
        
        self.user_status_combo = QComboBox()
        self.user_status_combo.addItems(["active", "inactive", "suspended", "terminated"])
        form.addRow("Status:", self.user_status_combo)
        
        self.user_mfa_check = QCheckBox("MFA Enabled")
        form.addRow("", self.user_mfa_check)
        
        details_layout.addLayout(form)
        
        # Assigned roles
        details_layout.addWidget(QLabel("Assigned Roles:"))
        
        self.user_roles_list = QListWidget()
        self.user_roles_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.user_roles_list.customContextMenuRequested.connect(self._user_roles_context_menu)
        details_layout.addWidget(self.user_roles_list)
        
        role_btns = QHBoxLayout()
        assign_role_btn = QPushButton("+ Assign Role")
        assign_role_btn.clicked.connect(self._assign_role_to_user)
        role_btns.addWidget(assign_role_btn)
        
        revoke_role_btn = QPushButton("- Revoke Role")
        revoke_role_btn.clicked.connect(self._revoke_role_from_user)
        role_btns.addWidget(revoke_role_btn)
        
        details_layout.addLayout(role_btns)
        
        # Effective permissions
        details_layout.addWidget(QLabel("Effective Permissions:"))
        self.effective_perms_list = QListWidget()
        details_layout.addWidget(self.effective_perms_list)
        
        save_user_btn = QPushButton("💾 Save User")
        save_user_btn.setObjectName("primaryButton")
        save_user_btn.clicked.connect(self._save_user)
        details_layout.addWidget(save_user_btn)
        
        splitter.addWidget(details_frame)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_sod_tab(self) -> QWidget:
        """Create Separation of Duties tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # SoD Rules
        rules_frame = QFrame()
        rules_frame.setObjectName("contentFrame")
        rules_layout = QVBoxLayout(rules_frame)
        
        rules_header = QHBoxLayout()
        rules_header.addWidget(QLabel("Separation of Duties Rules"))
        rules_header.addStretch()
        
        add_rule_btn = QPushButton("+ Add Rule")
        add_rule_btn.setObjectName("primaryButton")
        add_rule_btn.clicked.connect(self._add_sod_rule_dialog)
        rules_header.addWidget(add_rule_btn)
        
        check_btn = QPushButton("🔍 Check All Users")
        check_btn.clicked.connect(self._check_all_sod_violations)
        rules_header.addWidget(check_btn)
        
        rules_layout.addLayout(rules_header)
        
        self.sod_rules_table = QTableWidget()
        self.sod_rules_table.setColumnCount(6)
        self.sod_rules_table.setHorizontalHeaderLabels([
            "Rule Name", "Type", "Conflicting Items", "Severity", "Enabled", "Actions"
        ])
        self.sod_rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        rules_layout.addWidget(self.sod_rules_table)
        
        splitter.addWidget(rules_frame)
        
        # Violations
        violations_frame = QFrame()
        violations_frame.setObjectName("contentFrame")
        violations_layout = QVBoxLayout(violations_frame)
        
        violations_header = QHBoxLayout()
        violations_header.addWidget(QLabel("Active Violations"))
        violations_header.addStretch()
        
        self.violation_status_filter = QComboBox()
        self.violation_status_filter.addItems(["All", "Open", "Resolved", "Exception"])
        violations_header.addWidget(self.violation_status_filter)
        
        violations_layout.addLayout(violations_header)
        
        self.violations_table = QTableWidget()
        self.violations_table.setColumnCount(7)
        self.violations_table.setHorizontalHeaderLabels([
            "User", "Rule", "Violation Type", "Conflicting Items", "Severity", "Status", "Actions"
        ])
        self.violations_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        violations_layout.addWidget(self.violations_table)
        
        splitter.addWidget(violations_frame)
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_requests_tab(self) -> QWidget:
        """Create access requests tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.request_status_filter = QComboBox()
        self.request_status_filter.addItems(["All", "Pending", "Approved", "Denied"])
        self.request_status_filter.currentTextChanged.connect(self._filter_requests)
        toolbar.addWidget(QLabel("Status:"))
        toolbar.addWidget(self.request_status_filter)
        
        toolbar.addStretch()
        
        new_request_btn = QPushButton("+ New Request")
        new_request_btn.setObjectName("primaryButton")
        new_request_btn.clicked.connect(self._create_access_request)
        toolbar.addWidget(new_request_btn)
        
        layout.addLayout(toolbar)
        
        # Requests table
        requests_frame = QFrame()
        requests_frame.setObjectName("contentFrame")
        requests_layout = QVBoxLayout(requests_frame)
        
        self.requests_table = QTableWidget()
        self.requests_table.setColumnCount(8)
        self.requests_table.setHorizontalHeaderLabels([
            "Request ID", "User", "Requested Roles", "Justification",
            "Requested At", "Status", "Risk Score", "Actions"
        ])
        self.requests_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.requests_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        requests_layout.addWidget(self.requests_table)
        
        layout.addWidget(requests_frame)
        
        # Request details panel
        details_frame = QFrame()
        details_frame.setObjectName("contentFrame")
        details_layout = QVBoxLayout(details_frame)
        
        details_layout.addWidget(QLabel("Request Details"))
        
        self.request_details_text = QTextEdit()
        self.request_details_text.setReadOnly(True)
        self.request_details_text.setMaximumHeight(150)
        details_layout.addWidget(self.request_details_text)
        
        actions_layout = QHBoxLayout()
        
        approve_btn = QPushButton("✅ Approve")
        approve_btn.setStyleSheet("background-color: #00ff88; color: black;")
        approve_btn.clicked.connect(self._approve_request)
        actions_layout.addWidget(approve_btn)
        
        deny_btn = QPushButton("❌ Deny")
        deny_btn.setStyleSheet("background-color: #ff6b6b; color: white;")
        deny_btn.clicked.connect(self._deny_request)
        actions_layout.addWidget(deny_btn)
        
        actions_layout.addStretch()
        
        details_layout.addLayout(actions_layout)
        
        layout.addWidget(details_frame)
        
        return widget
    
    def _create_reviews_tab(self) -> QWidget:
        """Create access reviews tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        toolbar.addStretch()
        
        new_review_btn = QPushButton("+ Create Review Campaign")
        new_review_btn.setObjectName("primaryButton")
        new_review_btn.clicked.connect(self._create_review_campaign)
        toolbar.addWidget(new_review_btn)
        
        layout.addLayout(toolbar)
        
        # Active reviews
        reviews_frame = QFrame()
        reviews_frame.setObjectName("contentFrame")
        reviews_layout = QVBoxLayout(reviews_frame)
        
        reviews_layout.addWidget(QLabel("Active Review Campaigns"))
        
        self.reviews_table = QTableWidget()
        self.reviews_table.setColumnCount(8)
        self.reviews_table.setHorizontalHeaderLabels([
            "Campaign Name", "Scope", "Reviewer", "Start Date", "End Date",
            "Progress", "Status", "Actions"
        ])
        self.reviews_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        reviews_layout.addWidget(self.reviews_table)
        
        layout.addWidget(reviews_frame)
        
        # Review items
        items_frame = QFrame()
        items_frame.setObjectName("contentFrame")
        items_layout = QVBoxLayout(items_frame)
        
        items_layout.addWidget(QLabel("Review Items"))
        
        self.review_items_table = QTableWidget()
        self.review_items_table.setColumnCount(6)
        self.review_items_table.setHorizontalHeaderLabels([
            "User", "Role", "Granted By", "Granted At", "Justification", "Decision"
        ])
        self.review_items_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        items_layout.addWidget(self.review_items_table)
        
        # Review actions
        review_actions = QHBoxLayout()
        
        approve_all_btn = QPushButton("✅ Approve Selected")
        approve_all_btn.setStyleSheet("background-color: #00ff88; color: black;")
        review_actions.addWidget(approve_all_btn)
        
        revoke_btn = QPushButton("🚫 Revoke Selected")
        revoke_btn.setStyleSheet("background-color: #ff6b6b; color: white;")
        review_actions.addWidget(revoke_btn)
        
        escalate_btn = QPushButton("⬆️ Escalate")
        review_actions.addWidget(escalate_btn)
        
        review_actions.addStretch()
        
        items_layout.addLayout(review_actions)
        
        layout.addWidget(items_frame)
        
        return widget
    
    def _create_reports_tab(self) -> QWidget:
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Report types
        reports_group = QGroupBox("Available Reports")
        reports_layout = QGridLayout(reports_group)
        
        report_types = [
            ("Access Matrix Report", "Full access control matrix export", "📊"),
            ("User Access Report", "All access rights per user", "👤"),
            ("Role Membership Report", "Users per role breakdown", "👥"),
            ("SoD Violation Report", "All separation of duties violations", "⚠️"),
            ("Dormant Access Report", "Unused access rights", "💤"),
            ("Privileged Access Report", "High-risk access summary", "🔑"),
            ("Compliance Report", "Access compliance status", "📋"),
            ("Audit Trail Report", "All access changes history", "📜")
        ]
        
        for i, (name, desc, icon) in enumerate(report_types):
            row, col = divmod(i, 2)
            
            report_card = QFrame()
            report_card.setObjectName("contentFrame")
            card_layout = QVBoxLayout(report_card)
            
            title = QLabel(f"{icon} {name}")
            title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
            card_layout.addWidget(title)
            
            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color: #8b949e;")
            card_layout.addWidget(desc_label)
            
            gen_btn = QPushButton("Generate")
            gen_btn.clicked.connect(lambda checked, n=name: self._generate_report(n))
            card_layout.addWidget(gen_btn)
            
            reports_layout.addWidget(report_card, row, col)
        
        layout.addWidget(reports_group)
        
        # Report output
        output_frame = QFrame()
        output_frame.setObjectName("contentFrame")
        output_layout = QVBoxLayout(output_frame)
        
        output_header = QHBoxLayout()
        output_header.addWidget(QLabel("Report Output"))
        output_header.addStretch()
        
        export_pdf_btn = QPushButton("📄 Export PDF")
        export_pdf_btn.clicked.connect(self._export_report_pdf)
        output_header.addWidget(export_pdf_btn)
        
        export_csv_btn = QPushButton("📊 Export CSV")
        export_csv_btn.clicked.connect(self._export_report_csv)
        output_header.addWidget(export_csv_btn)
        
        output_layout.addLayout(output_header)
        
        self.report_output = QTextEdit()
        self.report_output.setReadOnly(True)
        output_layout.addWidget(self.report_output)
        
        layout.addWidget(output_frame)
        
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
    
    def _connect_signals(self):
        """Connect signals"""
        self.matrix_combo.currentIndexChanged.connect(self._on_matrix_changed)
    
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
                border-bottom: 1px solid #21262d;
                font-weight: bold;
            }
            QTreeWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
            }
            QTreeWidget::item {
                padding: 6px;
            }
            QTreeWidget::item:selected {
                background-color: #1f6feb40;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
                border-color: #00d4ff;
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
            QListWidget::item:selected {
                background-color: #1f6feb40;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
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
    def _create_new_matrix(self):
        """Create new access control matrix"""
        name, ok = QInputDialog.getText(
            self, "New Matrix", "Enter matrix name:"
        )
        if ok and name:
            if self.engine:
                asyncio.create_task(self._async_create_matrix(name))
    
    async def _async_create_matrix(self, name: str):
        """Async create matrix"""
        matrix = await self.engine.create_matrix(name)
        self.current_matrix = matrix
        self.matrix_combo.addItem(matrix.name, matrix.id)
        self.matrix_combo.setCurrentIndex(self.matrix_combo.count() - 1)
        self.status_message.emit(f"Matrix '{name}' created successfully")
    
    def _on_matrix_changed(self, index: int):
        """Handle matrix selection change"""
        if index > 0:
            matrix_id = self.matrix_combo.currentData()
            if self.engine and matrix_id in self.engine.matrices:
                self.current_matrix = self.engine.matrices[matrix_id]
                self._refresh_all_views()
    
    def _refresh_matrix(self):
        """Refresh matrix view"""
        if not self.current_matrix:
            return
        
        matrix = self.current_matrix
        
        # Update stats
        self._update_stat_card("total_roles", str(len(matrix.roles)))
        self._update_stat_card("total_permissions", str(len(matrix.permissions)))
        self._update_stat_card("total_users", str(len(matrix.users)))
        
        # Build matrix table
        permissions = list(matrix.permissions.values())
        roles = list(matrix.roles.values())
        
        self.matrix_table.setRowCount(len(roles))
        self.matrix_table.setColumnCount(len(permissions) + 1)
        
        headers = ["Role"] + [p.name for p in permissions]
        self.matrix_table.setHorizontalHeaderLabels(headers)
        
        for row, role in enumerate(roles):
            self.matrix_table.setItem(row, 0, QTableWidgetItem(role.name))
            
            for col, perm in enumerate(permissions):
                cell = QTableWidgetItem()
                if perm.id in role.permissions:
                    cell.setText("✓")
                    cell.setBackground(QBrush(QColor("#00ff8840")))
                else:
                    cell.setText("")
                cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.matrix_table.setItem(row, col + 1, cell)
    
    def _update_stat_card(self, key: str, value: str):
        """Update stat card value"""
        if key in self.stat_cards:
            card = self.stat_cards[key]
            value_label = card.findChild(QLabel, "value")
            if value_label:
                value_label.setText(value)
    
    def _refresh_all_views(self):
        """Refresh all views"""
        self._refresh_matrix()
        self._refresh_roles()
        self._refresh_permissions()
        self._refresh_users()
    
    def _refresh_roles(self):
        """Refresh roles table"""
        if not self.current_matrix:
            return
        
        roles = list(self.current_matrix.roles.values())
        self.roles_table.setRowCount(len(roles))
        
        for row, role in enumerate(roles):
            self.roles_table.setItem(row, 0, QTableWidgetItem(role.name))
            self.roles_table.setItem(row, 1, QTableWidgetItem(role.type.value.title()))
            self.roles_table.setItem(row, 2, QTableWidgetItem(str(len(role.permissions))))
            
            user_count = sum(
                1 for u in self.current_matrix.users.values()
                if role.id in u.roles
            )
            self.roles_table.setItem(row, 3, QTableWidgetItem(str(user_count)))
            self.roles_table.setItem(row, 4, QTableWidgetItem(f"{role.risk_score:.1f}"))
            
            actions = QPushButton("...")
            actions.setFixedWidth(40)
            self.roles_table.setCellWidget(row, 5, actions)
    
    def _refresh_permissions(self):
        """Refresh permissions tree"""
        if not self.current_matrix:
            return
        
        self.perms_tree.clear()
        
        # Group by resource
        resources: Dict[str, List] = {}
        for perm in self.current_matrix.permissions.values():
            if perm.resource not in resources:
                resources[perm.resource] = []
            resources[perm.resource].append(perm)
        
        for resource, perms in resources.items():
            resource_item = QTreeWidgetItem([resource, "", ""])
            resource_item.setExpanded(True)
            
            for perm in perms:
                perm_item = QTreeWidgetItem([
                    perm.name,
                    perm.type.value.title(),
                    perm.risk_level.title()
                ])
                perm_item.setData(0, Qt.ItemDataRole.UserRole, perm.id)
                resource_item.addChild(perm_item)
            
            self.perms_tree.addTopLevelItem(resource_item)
    
    def _refresh_users(self):
        """Refresh users table"""
        if not self.current_matrix:
            return
        
        users = list(self.current_matrix.users.values())
        self.users_table.setRowCount(len(users))
        
        for row, user in enumerate(users):
            self.users_table.setItem(row, 0, QTableWidgetItem(user.username))
            self.users_table.setItem(row, 1, QTableWidgetItem(user.email))
            self.users_table.setItem(row, 2, QTableWidgetItem(user.department))
            self.users_table.setItem(row, 3, QTableWidgetItem(str(len(user.roles))))
            self.users_table.setItem(row, 4, QTableWidgetItem(f"{user.risk_score:.1f}"))
            
            status_item = QTableWidgetItem(user.status.title())
            if user.status == "active":
                status_item.setForeground(QBrush(QColor("#00ff88")))
            elif user.status == "suspended":
                status_item.setForeground(QBrush(QColor("#ff6b6b")))
            self.users_table.setItem(row, 5, status_item)
            
            actions = QPushButton("...")
            actions.setFixedWidth(40)
            self.users_table.setCellWidget(row, 6, actions)
    
    # Dialogs and actions
    def _add_role_dialog(self):
        """Open add role dialog"""
        self._clear_role_editor()
    
    def _add_permission_dialog(self):
        """Open add permission dialog"""
        self._clear_permission_editor()
    
    def _add_user_dialog(self):
        """Open add user dialog"""
        self._clear_user_editor()
    
    def _add_sod_rule_dialog(self):
        """Open add SoD rule dialog"""
        QMessageBox.information(self, "Add SoD Rule", "SoD rule dialog would open here")
    
    def _clear_role_editor(self):
        """Clear role editor fields"""
        self.role_name_input.clear()
        self.role_desc_input.clear()
        self.role_type_combo.setCurrentIndex(0)
        self.role_risk_spin.setValue(0)
        self.role_approval_check.setChecked(False)
        self.role_max_users_spin.setValue(0)
    
    def _clear_permission_editor(self):
        """Clear permission editor fields"""
        self.perm_name_input.clear()
        self.perm_desc_input.clear()
        self.perm_resource_input.clear()
        self.perm_action_input.clear()
    
    def _clear_user_editor(self):
        """Clear user editor fields"""
        self.user_name_input.clear()
        self.user_email_input.clear()
        self.user_dept_input.clear()
        self.user_manager_input.clear()
    
    def _save_role(self):
        """Save role"""
        if not self.current_matrix or not self.engine:
            return
        
        name = self.role_name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Error", "Role name is required")
            return
        
        asyncio.create_task(self._async_save_role(name))
    
    async def _async_save_role(self, name: str):
        """Async save role"""
        role = await self.engine.create_role(
            self.current_matrix.id,
            name,
            self.role_desc_input.toPlainText(),
            self.role_type_combo.currentData(),
            require_approval=self.role_approval_check.isChecked(),
            max_users=self.role_max_users_spin.value(),
            risk_score=float(self.role_risk_spin.value())
        )
        self._refresh_roles()
        self.status_message.emit(f"Role '{name}' saved")
    
    def _save_permission(self):
        """Save permission"""
        if not self.current_matrix or not self.engine:
            return
        
        name = self.perm_name_input.text().strip()
        resource = self.perm_resource_input.text().strip()
        action = self.perm_action_input.text().strip()
        
        if not all([name, resource, action]):
            QMessageBox.warning(self, "Error", "Name, resource, and action are required")
            return
        
        asyncio.create_task(self._async_save_permission(name, resource, action))
    
    async def _async_save_permission(self, name: str, resource: str, action: str):
        """Async save permission"""
        perm = await self.engine.create_permission(
            self.current_matrix.id,
            name,
            self.perm_desc_input.toPlainText(),
            self.perm_type_combo.currentData(),
            resource,
            action,
            scope=self.perm_scope_combo.currentText(),
            risk_level=self.perm_risk_combo.currentText(),
            requires_mfa=self.perm_mfa_check.isChecked(),
            time_bound=self.perm_time_bound_check.isChecked()
        )
        self._refresh_permissions()
        self.status_message.emit(f"Permission '{name}' saved")
    
    def _save_user(self):
        """Save user"""
        if not self.current_matrix or not self.engine:
            return
        
        username = self.user_name_input.text().strip()
        email = self.user_email_input.text().strip()
        dept = self.user_dept_input.text().strip()
        
        if not all([username, email, dept]):
            QMessageBox.warning(self, "Error", "Username, email, and department are required")
            return
        
        asyncio.create_task(self._async_save_user(username, email, dept))
    
    async def _async_save_user(self, username: str, email: str, dept: str):
        """Async save user"""
        user = await self.engine.create_user(
            self.current_matrix.id,
            username,
            email,
            dept,
            manager=self.user_manager_input.text().strip(),
            status=self.user_status_combo.currentText(),
            mfa_enabled=self.user_mfa_check.isChecked()
        )
        self._refresh_users()
        self.status_message.emit(f"User '{username}' saved")
    
    def _on_role_selected(self):
        """Handle role selection"""
        pass
    
    def _on_permission_selected(self, item, column):
        """Handle permission selection"""
        perm_id = item.data(0, Qt.ItemDataRole.UserRole)
        if perm_id and self.current_matrix:
            perm = self.current_matrix.permissions.get(perm_id)
            if perm:
                self.perm_name_input.setText(perm.name)
                self.perm_desc_input.setText(perm.description)
                self.perm_resource_input.setText(perm.resource)
                self.perm_action_input.setText(perm.action)
    
    def _on_user_selected(self):
        """Handle user selection"""
        pass
    
    def _filter_roles(self):
        """Filter roles table"""
        pass
    
    def _filter_permissions(self):
        """Filter permissions"""
        pass
    
    def _filter_users(self):
        """Filter users table"""
        pass
    
    def _filter_requests(self):
        """Filter access requests"""
        pass
    
    def _export_matrix(self):
        """Export matrix"""
        if not self.current_matrix or not self.engine:
            return
        
        asyncio.create_task(self._async_export_matrix())
    
    async def _async_export_matrix(self):
        """Async export matrix"""
        data = await self.engine.export_matrix(self.current_matrix.id)
        self.report_output.setText(data)
        self.tabs.setCurrentIndex(7)  # Reports tab
        self.status_message.emit("Matrix exported")
    
    def _assign_role_to_user(self):
        """Assign role to selected user"""
        QMessageBox.information(self, "Assign Role", "Role assignment dialog would open")
    
    def _revoke_role_from_user(self):
        """Revoke role from selected user"""
        QMessageBox.information(self, "Revoke Role", "Role revocation dialog would open")
    
    def _user_roles_context_menu(self, pos):
        """Show context menu for user roles"""
        menu = QMenu(self)
        menu.addAction("Revoke Role", self._revoke_role_from_user)
        menu.addAction("View Details")
        menu.exec(self.user_roles_list.mapToGlobal(pos))
    
    def _sync_from_ad(self):
        """Sync users from Active Directory"""
        QMessageBox.information(
            self, "AD Sync",
            "Active Directory synchronization would be initiated"
        )
    
    def _check_all_sod_violations(self):
        """Check all users for SoD violations"""
        if not self.current_matrix or not self.engine:
            return
        
        asyncio.create_task(self._async_check_sod())
    
    async def _async_check_sod(self):
        """Async check SoD violations"""
        total_violations = 0
        for user in self.current_matrix.users.values():
            violations = await self.engine.check_sod_violations(
                self.current_matrix.id, user.id
            )
            total_violations += len(violations)
        
        self._update_stat_card("active_violations", str(total_violations))
        self.status_message.emit(f"Found {total_violations} SoD violations")
    
    def _create_access_request(self):
        """Create new access request"""
        QMessageBox.information(
            self, "New Request",
            "Access request dialog would open"
        )
    
    def _approve_request(self):
        """Approve selected request"""
        QMessageBox.information(self, "Approve", "Request approved")
    
    def _deny_request(self):
        """Deny selected request"""
        reason, ok = QInputDialog.getText(
            self, "Deny Request", "Enter denial reason:"
        )
        if ok:
            QMessageBox.information(self, "Deny", f"Request denied: {reason}")
    
    def _create_review_campaign(self):
        """Create access review campaign"""
        QMessageBox.information(
            self, "Review Campaign",
            "Review campaign dialog would open"
        )
    
    def _generate_report(self, report_type: str):
        """Generate report"""
        if not self.current_matrix or not self.engine:
            self.report_output.setText("No matrix selected")
            return
        
        asyncio.create_task(self._async_generate_report(report_type))
    
    async def _async_generate_report(self, report_type: str):
        """Async generate report"""
        import json
        report = await self.engine.generate_access_report(self.current_matrix.id)
        self.report_output.setText(json.dumps(report, indent=2, default=str))
        self.status_message.emit(f"{report_type} generated")
    
    def _export_report_pdf(self):
        """Export report as PDF"""
        QMessageBox.information(self, "Export", "PDF export would be generated")
    
    def _export_report_csv(self):
        """Export report as CSV"""
        QMessageBox.information(self, "Export", "CSV export would be generated")
