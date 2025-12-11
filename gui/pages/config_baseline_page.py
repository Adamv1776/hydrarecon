"""
HydraRecon Configuration Baseline Manager Page
Enterprise configuration baseline management and compliance checking interface
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget,
    QTableWidgetItem, QPushButton, QLabel, QLineEdit, QTextEdit,
    QComboBox, QGroupBox, QFormLayout, QHeaderView, QSplitter,
    QTreeWidget, QTreeWidgetItem, QDialog, QDialogButtonBox,
    QSpinBox, QDoubleSpinBox, QListWidget, QListWidgetItem,
    QCheckBox, QProgressBar, QFrame, QScrollArea, QGridLayout,
    QMessageBox, QStackedWidget, QToolButton, QDateEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QDate
from PyQt6.QtGui import QFont, QColor, QIcon
from datetime import datetime
import asyncio

try:
    from core.config_baseline import (
        ConfigurationBaselineEngine, ConfigurationCheck, BaselineProfile,
        ConfigurationResult, BaselineScan, RemediationTask, ComplianceReport,
        BaselineType, ComplianceLevel, Severity, AssetCategory,
        CheckType, RemediationStatus
    )
except ImportError:
    ConfigurationBaselineEngine = None


class ConfigBaselinePage(QWidget):
    """Configuration Baseline Manager Page"""
    
    status_message = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = ConfigurationBaselineEngine() if ConfigurationBaselineEngine else None
        self.setup_ui()
        self.load_data()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Main content tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3a3a5a;
                background: #1a1a2e;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #252540;
                color: #8888aa;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background: #1a1a2e;
                color: #00d4ff;
            }
            QTabBar::tab:hover:!selected {
                background: #2a2a4a;
            }
        """)
        
        # Add tabs
        self.tabs.addTab(self.create_profiles_tab(), "📋 Baseline Profiles")
        self.tabs.addTab(self.create_checks_tab(), "✅ Configuration Checks")
        self.tabs.addTab(self.create_scans_tab(), "🔍 Scans")
        self.tabs.addTab(self.create_results_tab(), "📊 Results")
        self.tabs.addTab(self.create_remediation_tab(), "🔧 Remediation")
        self.tabs.addTab(self.create_reports_tab(), "📈 Reports")
        
        layout.addWidget(self.tabs)
    
    def create_header(self) -> QWidget:
        """Create page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:1 #2a2a4a);
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_section = QVBoxLayout()
        
        title = QLabel("📐 Configuration Baseline Manager")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        title_section.addWidget(title)
        
        subtitle = QLabel("CIS, STIG, and custom baseline management and compliance checking")
        subtitle.setStyleSheet("color: #8888aa; font-size: 12px;")
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Compliance score
        score_frame = QFrame()
        score_frame.setStyleSheet("""
            background: #0a0a1a;
            border: 2px solid #00d4ff;
            border-radius: 50px;
            padding: 10px 20px;
        """)
        score_layout = QHBoxLayout(score_frame)
        
        score_label = QLabel("Overall Compliance:")
        score_label.setStyleSheet("color: #8888aa;")
        score_layout.addWidget(score_label)
        
        self.compliance_score = QLabel("--")
        self.compliance_score.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        self.compliance_score.setStyleSheet("color: #00ff88;")
        score_layout.addWidget(self.compliance_score)
        
        layout.addWidget(score_frame)
        
        # Quick actions
        actions_layout = QHBoxLayout()
        
        new_scan_btn = QPushButton("🔍 New Scan")
        new_scan_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        new_scan_btn.clicked.connect(self.new_scan_dialog)
        actions_layout.addWidget(new_scan_btn)
        
        import_btn = QPushButton("📥 Import Profile")
        import_btn.setStyleSheet(self.get_action_button_style("#00ff88"))
        import_btn.clicked.connect(self.import_profile)
        actions_layout.addWidget(import_btn)
        
        layout.addLayout(actions_layout)
        
        return header
    
    def create_profiles_tab(self) -> QWidget:
        """Create baseline profiles tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        add_profile_btn = QPushButton("➕ New Profile")
        add_profile_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        add_profile_btn.clicked.connect(self.new_profile_dialog)
        toolbar.addWidget(add_profile_btn)
        
        toolbar.addStretch()
        
        self.profile_type_filter = QComboBox()
        self.profile_type_filter.addItem("All Types", None)
        for bt in BaselineType:
            self.profile_type_filter.addItem(bt.value.upper(), bt)
        self.profile_type_filter.setStyleSheet(self.get_combo_style())
        toolbar.addWidget(self.profile_type_filter)
        
        self.profile_category_filter = QComboBox()
        self.profile_category_filter.addItem("All Categories", None)
        for cat in AssetCategory:
            self.profile_category_filter.addItem(cat.value.replace("_", " ").title(), cat)
        self.profile_category_filter.setStyleSheet(self.get_combo_style())
        toolbar.addWidget(self.profile_category_filter)
        
        layout.addLayout(toolbar)
        
        # Profiles grid
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        profiles_widget = QWidget()
        self.profiles_grid = QGridLayout(profiles_widget)
        self.profiles_grid.setSpacing(15)
        
        scroll.setWidget(profiles_widget)
        layout.addWidget(scroll)
        
        # Load profiles
        self.refresh_profiles()
        
        return widget
    
    def refresh_profiles(self):
        """Refresh profiles grid"""
        # Clear existing
        while self.profiles_grid.count():
            item = self.profiles_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        if not self.engine:
            return
        
        row, col = 0, 0
        for profile in self.engine.profiles.values():
            card = self.create_profile_card(profile)
            self.profiles_grid.addWidget(card, row, col)
            col += 1
            if col >= 3:
                col = 0
                row += 1
    
    def create_profile_card(self, profile: BaselineProfile) -> QWidget:
        """Create profile card widget"""
        card = QFrame()
        card.setFixedSize(320, 200)
        card.setStyleSheet("""
            QFrame {
                background: #252540;
                border: 1px solid #3a3a5a;
                border-radius: 10px;
            }
            QFrame:hover {
                border-color: #00d4ff;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        # Header
        header = QHBoxLayout()
        
        type_colors = {
            BaselineType.CIS: "#00d4ff",
            BaselineType.STIG: "#ff6b6b",
            BaselineType.NIST: "#00ff88",
            BaselineType.CUSTOM: "#ffaa00"
        }
        
        type_label = QLabel(profile.baseline_type.value.upper())
        color = type_colors.get(profile.baseline_type, "#8888aa")
        type_label.setStyleSheet(f"""
            background: {color};
            color: #0a0a1a;
            padding: 3px 8px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: bold;
        """)
        header.addWidget(type_label)
        
        header.addStretch()
        
        version = QLabel(f"v{profile.version}")
        version.setStyleSheet("color: #8888aa; font-size: 10px;")
        header.addWidget(version)
        
        layout.addLayout(header)
        
        # Title
        title = QLabel(profile.name)
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color: white;")
        title.setWordWrap(True)
        layout.addWidget(title)
        
        # Category
        category = QLabel(f"📂 {profile.category.value.replace('_', ' ').title()}")
        category.setStyleSheet("color: #8888aa; font-size: 11px;")
        layout.addWidget(category)
        
        # Stats
        checks_count = len(profile.checks)
        stats = QLabel(f"✅ {checks_count} checks")
        stats.setStyleSheet("color: #00ff88; font-size: 11px;")
        layout.addWidget(stats)
        
        layout.addStretch()
        
        # Actions
        actions = QHBoxLayout()
        
        scan_btn = QPushButton("🔍 Scan")
        scan_btn.setStyleSheet(self.get_button_style("#00d4ff"))
        actions.addWidget(scan_btn)
        
        view_btn = QPushButton("👁️ View")
        view_btn.setStyleSheet(self.get_button_style())
        actions.addWidget(view_btn)
        
        export_btn = QPushButton("📤")
        export_btn.setStyleSheet(self.get_button_style())
        actions.addWidget(export_btn)
        
        layout.addLayout(actions)
        
        return card
    
    def create_checks_tab(self) -> QWidget:
        """Create configuration checks tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        add_check_btn = QPushButton("➕ Add Check")
        add_check_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        add_check_btn.clicked.connect(self.new_check_dialog)
        toolbar.addWidget(add_check_btn)
        
        toolbar.addStretch()
        
        self.check_search = QLineEdit()
        self.check_search.setPlaceholderText("🔍 Search checks...")
        self.check_search.setStyleSheet(self.get_input_style())
        self.check_search.textChanged.connect(self.filter_checks)
        toolbar.addWidget(self.check_search)
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItem("All Severities", None)
        for sev in Severity:
            self.severity_filter.addItem(sev.value.title(), sev)
        self.severity_filter.setStyleSheet(self.get_combo_style())
        self.severity_filter.currentIndexChanged.connect(self.filter_checks)
        toolbar.addWidget(self.severity_filter)
        
        layout.addLayout(toolbar)
        
        # Split view
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Checks table
        checks_group = QGroupBox("Configuration Checks")
        checks_group.setStyleSheet(self.get_group_style())
        checks_layout = QVBoxLayout(checks_group)
        
        self.checks_table = QTableWidget()
        self.checks_table.setColumnCount(6)
        self.checks_table.setHorizontalHeaderLabels([
            "Check ID", "Name", "Type", "Severity", "Baseline", "Category"
        ])
        self.checks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.checks_table.setStyleSheet(self.get_table_style())
        self.checks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.checks_table.currentItemChanged.connect(self.on_check_selected)
        checks_layout.addWidget(self.checks_table)
        
        splitter.addWidget(checks_group)
        
        # Check details
        details_group = QGroupBox("Check Details")
        details_group.setStyleSheet(self.get_group_style())
        details_layout = QVBoxLayout(details_group)
        
        self.check_details = QTextEdit()
        self.check_details.setReadOnly(True)
        self.check_details.setStyleSheet(self.get_text_style())
        details_layout.addWidget(self.check_details)
        
        # Remediation steps
        remediation_label = QLabel("Remediation Steps:")
        remediation_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        details_layout.addWidget(remediation_label)
        
        self.remediation_steps = QListWidget()
        self.remediation_steps.setMaximumHeight(120)
        self.remediation_steps.setStyleSheet(self.get_list_style())
        details_layout.addWidget(self.remediation_steps)
        
        splitter.addWidget(details_group)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        # Load checks
        self.refresh_checks()
        
        return widget
    
    def refresh_checks(self):
        """Refresh checks table"""
        if not self.engine:
            return
        
        self.checks_table.setRowCount(0)
        
        for check in self.engine.checks.values():
            row = self.checks_table.rowCount()
            self.checks_table.insertRow(row)
            
            self.checks_table.setItem(row, 0, QTableWidgetItem(check.check_id))
            self.checks_table.setItem(row, 1, QTableWidgetItem(check.name))
            self.checks_table.setItem(row, 2, QTableWidgetItem(check.check_type.value.title()))
            
            severity_item = QTableWidgetItem(check.severity.value.title())
            severity_colors = {
                Severity.CRITICAL: "#ff4444",
                Severity.HIGH: "#ff8800",
                Severity.MEDIUM: "#ffaa00",
                Severity.LOW: "#00ff88"
            }
            severity_item.setForeground(QColor(severity_colors.get(check.severity, "#ffffff")))
            self.checks_table.setItem(row, 3, severity_item)
            
            self.checks_table.setItem(row, 4, QTableWidgetItem(check.baseline_type.value.upper()))
            self.checks_table.setItem(row, 5, QTableWidgetItem(check.category.value.replace("_", " ").title()))
    
    def create_scans_tab(self) -> QWidget:
        """Create scans tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        new_scan_btn = QPushButton("🔍 New Scan")
        new_scan_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        new_scan_btn.clicked.connect(self.new_scan_dialog)
        toolbar.addWidget(new_scan_btn)
        
        schedule_btn = QPushButton("📅 Schedule Scan")
        schedule_btn.setStyleSheet(self.get_button_style())
        toolbar.addWidget(schedule_btn)
        
        toolbar.addStretch()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setStyleSheet(self.get_button_style())
        refresh_btn.clicked.connect(self.refresh_scans)
        toolbar.addWidget(refresh_btn)
        
        layout.addLayout(toolbar)
        
        # Scans table
        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(8)
        self.scans_table.setHorizontalHeaderLabels([
            "Scan ID", "Profile", "Asset", "Status", "Score", 
            "Compliant", "Non-Compliant", "Date"
        ])
        self.scans_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.scans_table.setStyleSheet(self.get_table_style())
        self.scans_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.scans_table.currentItemChanged.connect(self.on_scan_selected)
        layout.addWidget(self.scans_table)
        
        # Scan summary
        summary_frame = QFrame()
        summary_frame.setStyleSheet("background: #252540; border-radius: 8px; padding: 10px;")
        summary_layout = QHBoxLayout(summary_frame)
        
        for label, value, color in [
            ("Total Scans", "0", "#00d4ff"),
            ("Avg. Score", "0%", "#00ff88"),
            ("Assets Scanned", "0", "#ffaa00"),
            ("Critical Findings", "0", "#ff6b6b")
        ]:
            card = QFrame()
            card.setStyleSheet("""
                background: #1a1a2e;
                border: 1px solid #3a3a5a;
                border-radius: 8px;
                padding: 10px;
            """)
            card_layout = QVBoxLayout(card)
            
            l = QLabel(label)
            l.setStyleSheet("color: #8888aa; font-size: 11px;")
            card_layout.addWidget(l)
            
            v = QLabel(value)
            v.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
            v.setStyleSheet(f"color: {color};")
            card_layout.addWidget(v)
            
            summary_layout.addWidget(card)
        
        layout.addWidget(summary_frame)
        
        return widget
    
    def create_results_tab(self) -> QWidget:
        """Create results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.results_scan_filter = QComboBox()
        self.results_scan_filter.addItem("Select Scan", None)
        self.results_scan_filter.setStyleSheet(self.get_combo_style())
        self.results_scan_filter.setMinimumWidth(250)
        self.results_scan_filter.currentIndexChanged.connect(self.load_scan_results)
        toolbar.addWidget(self.results_scan_filter)
        
        toolbar.addStretch()
        
        self.results_status_filter = QComboBox()
        self.results_status_filter.addItem("All Status", None)
        for level in ComplianceLevel:
            self.results_status_filter.addItem(level.value.replace("_", " ").title(), level)
        self.results_status_filter.setStyleSheet(self.get_combo_style())
        toolbar.addWidget(self.results_status_filter)
        
        export_btn = QPushButton("📤 Export Results")
        export_btn.setStyleSheet(self.get_button_style())
        toolbar.addWidget(export_btn)
        
        layout.addLayout(toolbar)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Check ID", "Name", "Status", "Expected", "Actual", "Remediation"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setStyleSheet(self.get_table_style())
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.results_table)
        
        # Compliance breakdown
        breakdown_frame = QFrame()
        breakdown_frame.setStyleSheet("background: #252540; border-radius: 8px; padding: 15px;")
        breakdown_layout = QVBoxLayout(breakdown_frame)
        
        breakdown_title = QLabel("Compliance Breakdown")
        breakdown_title.setStyleSheet("color: #00d4ff; font-weight: bold;")
        breakdown_layout.addWidget(breakdown_title)
        
        # Progress bars for each status
        for status, color in [
            ("Compliant", "#00ff88"),
            ("Non-Compliant", "#ff6b6b"),
            ("Partial", "#ffaa00"),
            ("Error", "#ff00ff")
        ]:
            row = QHBoxLayout()
            
            label = QLabel(status)
            label.setStyleSheet(f"color: {color}; min-width: 100px;")
            row.addWidget(label)
            
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setFormat("%v checks")
            bar.setStyleSheet(f"""
                QProgressBar {{
                    border: 1px solid #3a3a5a;
                    border-radius: 4px;
                    background: #1a1a2e;
                    text-align: right;
                    color: white;
                    padding-right: 5px;
                }}
                QProgressBar::chunk {{
                    background: {color};
                    border-radius: 3px;
                }}
            """)
            row.addWidget(bar)
            
            breakdown_layout.addLayout(row)
        
        layout.addWidget(breakdown_frame)
        
        return widget
    
    def create_remediation_tab(self) -> QWidget:
        """Create remediation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        create_tasks_btn = QPushButton("📋 Create Tasks from Non-Compliant")
        create_tasks_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        create_tasks_btn.clicked.connect(self.create_remediation_tasks)
        toolbar.addWidget(create_tasks_btn)
        
        toolbar.addStretch()
        
        self.task_status_filter = QComboBox()
        self.task_status_filter.addItem("All Status", None)
        for status in RemediationStatus:
            self.task_status_filter.addItem(status.value.replace("_", " ").title(), status)
        self.task_status_filter.setStyleSheet(self.get_combo_style())
        toolbar.addWidget(self.task_status_filter)
        
        self.task_assignee_filter = QComboBox()
        self.task_assignee_filter.addItem("All Assignees", None)
        self.task_assignee_filter.setStyleSheet(self.get_combo_style())
        toolbar.addWidget(self.task_assignee_filter)
        
        layout.addLayout(toolbar)
        
        # Split view
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Tasks table
        tasks_group = QGroupBox("Remediation Tasks")
        tasks_group.setStyleSheet(self.get_group_style())
        tasks_layout = QVBoxLayout(tasks_group)
        
        self.tasks_table = QTableWidget()
        self.tasks_table.setColumnCount(7)
        self.tasks_table.setHorizontalHeaderLabels([
            "Task ID", "Check", "Asset", "Priority", "Status", "Assigned To", "Due Date"
        ])
        self.tasks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tasks_table.setStyleSheet(self.get_table_style())
        self.tasks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tasks_table.currentItemChanged.connect(self.on_task_selected)
        tasks_layout.addWidget(self.tasks_table)
        
        splitter.addWidget(tasks_group)
        
        # Task details
        details_group = QGroupBox("Task Details")
        details_group.setStyleSheet(self.get_group_style())
        details_layout = QVBoxLayout(details_group)
        
        # Check info
        self.task_check_info = QTextEdit()
        self.task_check_info.setReadOnly(True)
        self.task_check_info.setMaximumHeight(150)
        self.task_check_info.setStyleSheet(self.get_text_style())
        details_layout.addWidget(self.task_check_info)
        
        # Status update
        form = QFormLayout()
        
        self.task_status_combo = QComboBox()
        for status in RemediationStatus:
            self.task_status_combo.addItem(status.value.replace("_", " ").title(), status)
        self.task_status_combo.setStyleSheet(self.get_combo_style())
        form.addRow("Status:", self.task_status_combo)
        
        self.task_notes = QTextEdit()
        self.task_notes.setMaximumHeight(80)
        self.task_notes.setStyleSheet(self.get_text_style())
        form.addRow("Notes:", self.task_notes)
        
        details_layout.addLayout(form)
        
        # Actions
        actions_layout = QHBoxLayout()
        
        update_btn = QPushButton("💾 Update Task")
        update_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        update_btn.clicked.connect(self.update_task)
        actions_layout.addWidget(update_btn)
        
        verify_btn = QPushButton("✅ Verify Fix")
        verify_btn.setStyleSheet(self.get_button_style("#00ff88"))
        verify_btn.clicked.connect(self.verify_fix)
        actions_layout.addWidget(verify_btn)
        
        details_layout.addLayout(actions_layout)
        
        splitter.addWidget(details_group)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        # Task summary
        summary_frame = QFrame()
        summary_frame.setStyleSheet("background: #252540; border-radius: 8px; padding: 10px;")
        summary_layout = QHBoxLayout(summary_frame)
        
        for status, color in [
            ("Pending", "#ffaa00"),
            ("In Progress", "#00d4ff"),
            ("Completed", "#00ff88"),
            ("Failed", "#ff6b6b")
        ]:
            card = QFrame()
            card.setStyleSheet(f"background: #1a1a2e; border: 1px solid {color}; border-radius: 8px; padding: 10px;")
            card_layout = QVBoxLayout(card)
            
            l = QLabel(status)
            l.setStyleSheet(f"color: {color}; font-weight: bold;")
            l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_layout.addWidget(l)
            
            v = QLabel("0")
            v.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
            v.setStyleSheet(f"color: {color};")
            v.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_layout.addWidget(v)
            
            summary_layout.addWidget(card)
        
        layout.addWidget(summary_frame)
        
        return widget
    
    def create_reports_tab(self) -> QWidget:
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Report options
        options_frame = QFrame()
        options_frame.setStyleSheet("background: #252540; border-radius: 8px; padding: 15px;")
        options_layout = QGridLayout(options_frame)
        
        # Date range
        options_layout.addWidget(QLabel("Date Range:"), 0, 0)
        
        self.report_start_date = QDateEdit()
        self.report_start_date.setCalendarPopup(True)
        self.report_start_date.setDate(QDate.currentDate().addMonths(-1))
        self.report_start_date.setStyleSheet(self.get_input_style())
        options_layout.addWidget(self.report_start_date, 0, 1)
        
        options_layout.addWidget(QLabel("to"), 0, 2)
        
        self.report_end_date = QDateEdit()
        self.report_end_date.setCalendarPopup(True)
        self.report_end_date.setDate(QDate.currentDate())
        self.report_end_date.setStyleSheet(self.get_input_style())
        options_layout.addWidget(self.report_end_date, 0, 3)
        
        # Report type
        options_layout.addWidget(QLabel("Report Type:"), 1, 0)
        
        self.report_type = QComboBox()
        self.report_type.addItems([
            "Compliance Summary",
            "Trend Analysis",
            "Remediation Status",
            "Audit Report",
            "Executive Summary"
        ])
        self.report_type.setStyleSheet(self.get_combo_style())
        options_layout.addWidget(self.report_type, 1, 1, 1, 2)
        
        generate_btn = QPushButton("📊 Generate Report")
        generate_btn.setStyleSheet(self.get_action_button_style("#00d4ff"))
        generate_btn.clicked.connect(self.generate_report)
        options_layout.addWidget(generate_btn, 1, 3)
        
        layout.addWidget(options_frame)
        
        # Report preview
        preview_group = QGroupBox("Report Preview")
        preview_group.setStyleSheet(self.get_group_style())
        preview_layout = QVBoxLayout(preview_group)
        
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setStyleSheet(self.get_text_style())
        self.report_preview.setHtml("""
            <h2>Configuration Baseline Compliance Report</h2>
            <p>Select options and click "Generate Report" to create a compliance report.</p>
            <h3>Available Report Types:</h3>
            <ul>
                <li><b>Compliance Summary</b> - Overall compliance status across all assets</li>
                <li><b>Trend Analysis</b> - Compliance trends over time</li>
                <li><b>Remediation Status</b> - Status of remediation tasks</li>
                <li><b>Audit Report</b> - Detailed audit trail</li>
                <li><b>Executive Summary</b> - High-level summary for leadership</li>
            </ul>
        """)
        preview_layout.addWidget(self.report_preview)
        
        # Export options
        export_layout = QHBoxLayout()
        
        export_pdf_btn = QPushButton("📄 Export PDF")
        export_pdf_btn.setStyleSheet(self.get_button_style())
        export_layout.addWidget(export_pdf_btn)
        
        export_csv_btn = QPushButton("📊 Export CSV")
        export_csv_btn.setStyleSheet(self.get_button_style())
        export_layout.addWidget(export_csv_btn)
        
        export_json_btn = QPushButton("📋 Export JSON")
        export_json_btn.setStyleSheet(self.get_button_style())
        export_layout.addWidget(export_json_btn)
        
        export_layout.addStretch()
        
        preview_layout.addLayout(export_layout)
        
        layout.addWidget(preview_group)
        
        return widget
    
    # Style methods
    def get_action_button_style(self, color: str = "#00d4ff") -> str:
        return f"""
            QPushButton {{
                background: {color};
                color: #0a0a1a;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background: {color}cc;
            }}
            QPushButton:pressed {{
                background: {color}aa;
            }}
        """
    
    def get_button_style(self, color: str = "#3a3a5a") -> str:
        return f"""
            QPushButton {{
                background: {color};
                color: white;
                border: 1px solid #4a4a6a;
                border-radius: 6px;
                padding: 8px 15px;
            }}
            QPushButton:hover {{
                background: #4a4a6a;
                border-color: #00d4ff;
            }}
        """
    
    def get_input_style(self) -> str:
        return """
            QLineEdit, QDateEdit {
                background: #252540;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 6px;
                padding: 8px 12px;
            }
            QLineEdit:focus, QDateEdit:focus {
                border-color: #00d4ff;
            }
        """
    
    def get_combo_style(self) -> str:
        return """
            QComboBox {
                background: #252540;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 6px;
                padding: 8px 12px;
                min-width: 150px;
            }
            QComboBox:hover {
                border-color: #00d4ff;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox QAbstractItemView {
                background: #252540;
                color: white;
                selection-background-color: #00d4ff;
            }
        """
    
    def get_table_style(self) -> str:
        return """
            QTableWidget {
                background: #1a1a2e;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 8px;
                gridline-color: #2a2a4a;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background: #00d4ff33;
            }
            QHeaderView::section {
                background: #252540;
                color: #00d4ff;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #00d4ff;
            }
        """
    
    def get_tree_style(self) -> str:
        return """
            QTreeWidget {
                background: #1a1a2e;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 8px;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QTreeWidget::item:selected {
                background: #00d4ff33;
            }
        """
    
    def get_list_style(self) -> str:
        return """
            QListWidget {
                background: #1a1a2e;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 6px;
            }
            QListWidget::item {
                padding: 8px;
            }
            QListWidget::item:selected {
                background: #00d4ff33;
            }
        """
    
    def get_text_style(self) -> str:
        return """
            QTextEdit {
                background: #1a1a2e;
                color: white;
                border: 1px solid #3a3a5a;
                border-radius: 6px;
                padding: 8px;
            }
        """
    
    def get_group_style(self) -> str:
        return """
            QGroupBox {
                font-weight: bold;
                color: #00d4ff;
                border: 1px solid #3a3a5a;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """
    
    # Event handlers
    def load_data(self):
        """Load initial data"""
        self.refresh_profiles()
        self.refresh_checks()
    
    def filter_checks(self):
        """Filter checks table"""
        pass
    
    def on_check_selected(self, current, previous):
        """Handle check selection"""
        if not current:
            return
        row = current.row()
        check_id = self.checks_table.item(row, 0)
        if check_id:
            self.show_check_details(check_id.text())
    
    def show_check_details(self, check_id: str):
        """Show check details"""
        if not self.engine:
            return
        
        check = self.engine.checks.get(check_id)
        if check:
            details = f"""
<h3>{check.name}</h3>
<p><b>ID:</b> {check.check_id}</p>
<p><b>Type:</b> {check.check_type.value.title()}</p>
<p><b>Severity:</b> {check.severity.value.title()}</p>
<p><b>Baseline:</b> {check.baseline_type.value.upper()}</p>
<p><b>Description:</b> {check.description}</p>
<p><b>Expected Value:</b> {check.expected_value}</p>
<p><b>Rationale:</b> {check.rationale or 'N/A'}</p>
<p><b>CIS Control:</b> {check.cis_control or 'N/A'}</p>
<p><b>NIST Control:</b> {check.nist_control or 'N/A'}</p>
            """
            self.check_details.setHtml(details)
            
            self.remediation_steps.clear()
            for step in check.remediation_steps:
                self.remediation_steps.addItem(step)
    
    def on_scan_selected(self, current, previous):
        """Handle scan selection"""
        pass
    
    def on_task_selected(self, current, previous):
        """Handle task selection"""
        pass
    
    def load_scan_results(self):
        """Load results for selected scan"""
        pass
    
    def refresh_scans(self):
        """Refresh scans table"""
        pass
    
    # Dialog methods
    def new_scan_dialog(self):
        """Show new scan dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("New Baseline Scan")
        dialog.setMinimumWidth(500)
        dialog.setStyleSheet("background: #1a1a2e; color: white;")
        
        layout = QVBoxLayout(dialog)
        
        form = QFormLayout()
        
        profile_combo = QComboBox()
        if self.engine:
            for profile in self.engine.profiles.values():
                profile_combo.addItem(profile.name, profile.profile_id)
        profile_combo.setStyleSheet(self.get_combo_style())
        form.addRow("Baseline Profile:", profile_combo)
        
        asset_input = QLineEdit()
        asset_input.setStyleSheet(self.get_input_style())
        form.addRow("Asset ID:", asset_input)
        
        asset_name_input = QLineEdit()
        asset_name_input.setStyleSheet(self.get_input_style())
        form.addRow("Asset Name:", asset_name_input)
        
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.status_message.emit("Baseline scan started")
    
    def new_profile_dialog(self):
        """Show new profile dialog"""
        self.status_message.emit("New profile dialog")
    
    def new_check_dialog(self):
        """Show new check dialog"""
        self.status_message.emit("New check dialog")
    
    def import_profile(self):
        """Import baseline profile"""
        self.status_message.emit("Import profile")
    
    def create_remediation_tasks(self):
        """Create remediation tasks from non-compliant results"""
        self.status_message.emit("Creating remediation tasks...")
    
    def update_task(self):
        """Update remediation task"""
        self.status_message.emit("Task updated")
    
    def verify_fix(self):
        """Verify fix for remediation task"""
        self.status_message.emit("Verifying fix...")
    
    def generate_report(self):
        """Generate compliance report"""
        report_type = self.report_type.currentText()
        self.status_message.emit(f"Generating {report_type}...")
        
        self.report_preview.setHtml(f"""
            <h2>{report_type}</h2>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <hr>
            <h3>Summary</h3>
            <p>This report would contain detailed compliance analysis based on the selected parameters.</p>
            <h3>Findings</h3>
            <p>Sample findings would be listed here...</p>
        """)
