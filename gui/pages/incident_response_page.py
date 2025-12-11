#!/usr/bin/env python3
"""
HydraRecon Incident Response Page
████████████████████████████████████████████████████████████████████████████████
█  ENTERPRISE INCIDENT RESPONSE - Case Management, Playbook Execution,         █
█  Evidence Collection, Timeline Analysis, and Coordinated Response            █
█  Workflow - AUTOMATED IR ORCHESTRATION                                        █
████████████████████████████████████████████████████████████████████████████████
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget, QTextEdit,
    QTreeWidget, QTreeWidgetItem, QProgressBar, QGroupBox, QFormLayout,
    QComboBox, QSpinBox, QCheckBox, QSplitter, QScrollArea, QFileDialog,
    QDialog, QListWidget, QListWidgetItem, QLineEdit, QMessageBox,
    QDateTimeEdit, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QDateTime
from PyQt6.QtGui import QFont, QColor, QIcon
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import json
import asyncio


class CreateIncidentDialog(QDialog):
    """Dialog for creating new incidents"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create New Incident")
        self.setMinimumSize(600, 500)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        
        # Title
        self.title_edit = QLineEdit()
        self.title_edit.setPlaceholderText("Brief incident title")
        form.addRow("Title:", self.title_edit)
        
        # Type
        self.type_combo = QComboBox()
        self.type_combo.addItems([
            "malware", "ransomware", "data_breach", "phishing",
            "unauthorized_access", "dos_ddos", "insider_threat", "apt",
            "lateral_movement", "privilege_escalation", "data_exfiltration",
            "cryptomining", "web_attack", "policy_violation", "other"
        ])
        form.addRow("Type:", self.type_combo)
        
        # Severity
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.severity_combo.setCurrentText("MEDIUM")
        form.addRow("Severity:", self.severity_combo)
        
        # Description
        self.description_edit = QTextEdit()
        self.description_edit.setPlaceholderText("Detailed description of the incident...")
        self.description_edit.setMaximumHeight(100)
        form.addRow("Description:", self.description_edit)
        
        # Affected Hosts
        self.hosts_edit = QLineEdit()
        self.hosts_edit.setPlaceholderText("Comma-separated list of hosts")
        form.addRow("Affected Hosts:", self.hosts_edit)
        
        # Affected Users
        self.users_edit = QLineEdit()
        self.users_edit.setPlaceholderText("Comma-separated list of users")
        form.addRow("Affected Users:", self.users_edit)
        
        # Detected At
        self.detected_edit = QDateTimeEdit()
        self.detected_edit.setDateTime(QDateTime.currentDateTime())
        form.addRow("Detected At:", self.detected_edit)
        
        # Assigned To
        self.assigned_edit = QLineEdit()
        self.assigned_edit.setPlaceholderText("Analyst name")
        form.addRow("Assigned To:", self.assigned_edit)
        
        # Tags
        self.tags_edit = QLineEdit()
        self.tags_edit.setPlaceholderText("Comma-separated tags")
        form.addRow("Tags:", self.tags_edit)
        
        layout.addLayout(form)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_data(self) -> Dict[str, Any]:
        """Get incident data from form"""
        return {
            "title": self.title_edit.text(),
            "incident_type": self.type_combo.currentText(),
            "severity": self.severity_combo.currentText(),
            "description": self.description_edit.toPlainText(),
            "affected_hosts": [h.strip() for h in self.hosts_edit.text().split(",") if h.strip()],
            "affected_users": [u.strip() for u in self.users_edit.text().split(",") if u.strip()],
            "detected_at": self.detected_edit.dateTime().toPyDateTime(),
            "assigned_to": self.assigned_edit.text() or None,
            "tags": [t.strip() for t in self.tags_edit.text().split(",") if t.strip()]
        }


class AddTimelineEventDialog(QDialog):
    """Dialog for adding timeline events"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Timeline Event")
        self.setMinimumSize(500, 400)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        
        # Timestamp
        self.timestamp_edit = QDateTimeEdit()
        self.timestamp_edit.setDateTime(QDateTime.currentDateTime())
        form.addRow("Timestamp:", self.timestamp_edit)
        
        # Event Type
        self.type_combo = QComboBox()
        self.type_combo.setEditable(True)
        self.type_combo.addItems([
            "detection", "login_attempt", "login_success", "login_failure",
            "process_execution", "file_access", "network_connection",
            "malware_detected", "alert_triggered", "containment_action",
            "investigation_update", "evidence_collected", "escalation"
        ])
        form.addRow("Event Type:", self.type_combo)
        
        # Description
        self.description_edit = QTextEdit()
        self.description_edit.setPlaceholderText("Event description...")
        self.description_edit.setMaximumHeight(100)
        form.addRow("Description:", self.description_edit)
        
        # Source
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Event source (e.g., SIEM, EDR, analyst)")
        form.addRow("Source:", self.source_edit)
        
        # Host
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("Related host (optional)")
        form.addRow("Host:", self.host_edit)
        
        # User
        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("Related user (optional)")
        form.addRow("User:", self.user_edit)
        
        # Indicators
        self.indicators_edit = QLineEdit()
        self.indicators_edit.setPlaceholderText("Comma-separated IOCs")
        form.addRow("Indicators:", self.indicators_edit)
        
        # Is Malicious
        self.malicious_check = QCheckBox("Mark as malicious activity")
        form.addRow("", self.malicious_check)
        
        layout.addLayout(form)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_data(self) -> Dict[str, Any]:
        """Get event data from form"""
        return {
            "timestamp": self.timestamp_edit.dateTime().toPyDateTime(),
            "event_type": self.type_combo.currentText(),
            "description": self.description_edit.toPlainText(),
            "source": self.source_edit.text(),
            "host": self.host_edit.text() or None,
            "user": self.user_edit.text() or None,
            "indicators": [i.strip() for i in self.indicators_edit.text().split(",") if i.strip()],
            "is_malicious": self.malicious_check.isChecked()
        }


class PlaybookExecutionThread(QThread):
    """Thread for executing playbooks"""
    progress = pyqtSignal(str, dict)
    completed = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, engine, incident_id: str, playbook_id: str):
        super().__init__()
        self.engine = engine
        self.incident_id = incident_id
        self.playbook_id = playbook_id
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                self.engine.execute_playbook(self.incident_id, self.playbook_id)
            )
            loop.close()
            self.completed.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class IncidentResponsePage(QWidget):
    """Incident Response Management Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = None
        self.current_incident = None
        self.playbook_thread = None
        self._init_engine()
        self.setup_ui()
        self.refresh_incidents()
    
    def _init_engine(self):
        """Initialize the incident response engine"""
        try:
            from core.incident_response import (
                IncidentResponseEngine, IncidentType, IncidentSeverity,
                IncidentStatus
            )
            self.engine = IncidentResponseEngine()
            self.IncidentType = IncidentType
            self.IncidentSeverity = IncidentSeverity
            self.IncidentStatus = IncidentStatus
        except ImportError as e:
            print(f"Failed to import incident response engine: {e}")
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #ff6b6b;
                background: rgba(0, 20, 40, 0.9);
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #ff6b6b;
                padding: 10px 20px;
                border: 1px solid #ff6b6b;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: rgba(255, 107, 107, 0.2);
            }
        """)
        
        # Incidents Tab
        self.tabs.addTab(self._create_incidents_tab(), "📋 Incidents")
        
        # Case Details Tab
        self.tabs.addTab(self._create_case_tab(), "🔍 Case Details")
        
        # Timeline Tab
        self.tabs.addTab(self._create_timeline_tab(), "📊 Timeline")
        
        # Playbooks Tab
        self.tabs.addTab(self._create_playbooks_tab(), "📖 Playbooks")
        
        # Evidence Tab
        self.tabs.addTab(self._create_evidence_tab(), "🔒 Evidence")
        
        # IOCs Tab
        self.tabs.addTab(self._create_iocs_tab(), "🎯 IOCs")
        
        # Metrics Tab
        self.tabs.addTab(self._create_metrics_tab(), "📈 Metrics")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(255, 107, 107, 0.2),
                    stop:0.5 rgba(255, 0, 128, 0.2),
                    stop:1 rgba(255, 107, 107, 0.2));
                border: 2px solid #ff6b6b;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🚨 INCIDENT RESPONSE CENTER")
        title.setFont(QFont("Consolas", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #ff6b6b; background: transparent; border: none;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Case Management • Playbook Execution • Evidence Collection • Timeline Analysis")
        subtitle.setStyleSheet("color: #888888; background: transparent; border: none;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Quick Stats
        stats_layout = QHBoxLayout()
        
        self.open_incidents_label = self._create_stat_widget("Open", "0", "#ff6b6b")
        stats_layout.addWidget(self.open_incidents_label)
        
        self.critical_label = self._create_stat_widget("Critical", "0", "#ff0000")
        stats_layout.addWidget(self.critical_label)
        
        self.mttr_label = self._create_stat_widget("MTTR", "0h", "#00ffff")
        stats_layout.addWidget(self.mttr_label)
        
        layout.addLayout(stats_layout)
        
        return header
    
    def _create_stat_widget(self, label: str, value: str, color: str) -> QFrame:
        """Create a stat display widget"""
        widget = QFrame()
        widget.setStyleSheet(f"""
            QFrame {{
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid {color};
                border-radius: 5px;
                padding: 5px 15px;
            }}
        """)
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setObjectName("value")
        value_label.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color}; background: transparent; border: none;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value_label)
        
        text_label = QLabel(label)
        text_label.setStyleSheet("color: #888888; font-size: 10px; background: transparent; border: none;")
        text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(text_label)
        
        return widget
    
    def _create_incidents_tab(self) -> QWidget:
        """Create incidents list tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        new_btn = QPushButton("➕ New Incident")
        new_btn.setStyleSheet("""
            QPushButton {
                background: #ff6b6b;
                color: black;
                font-weight: bold;
                padding: 8px 16px;
                border-radius: 5px;
            }
            QPushButton:hover { background: #ff8888; }
        """)
        new_btn.clicked.connect(self.create_incident)
        toolbar.addWidget(new_btn)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_incidents)
        toolbar.addWidget(refresh_btn)
        
        toolbar.addStretch()
        
        # Filters
        toolbar.addWidget(QLabel("Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "new", "triaged", "investigating", 
                                     "containing", "eradicating", "recovering", "closed"])
        self.status_filter.currentTextChanged.connect(self.refresh_incidents)
        toolbar.addWidget(self.status_filter)
        
        toolbar.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.severity_filter.currentTextChanged.connect(self.refresh_incidents)
        toolbar.addWidget(self.severity_filter)
        
        layout.addLayout(toolbar)
        
        # Incidents table
        self.incidents_table = QTableWidget()
        self.incidents_table.setColumnCount(8)
        self.incidents_table.setHorizontalHeaderLabels([
            "ID", "Title", "Type", "Severity", "Status", "Assigned", "Created", "SLA"
        ])
        self.incidents_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.incidents_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.incidents_table.setAlternatingRowColors(True)
        self.incidents_table.doubleClicked.connect(self.open_incident)
        self.incidents_table.setStyleSheet("""
            QTableWidget {
                background-color: #0a0a1a;
                gridline-color: #333;
                color: #ff6b6b;
            }
            QTableWidget::item:selected {
                background-color: rgba(255, 107, 107, 0.3);
            }
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #ff6b6b;
                padding: 8px;
                border: 1px solid #333;
                font-weight: bold;
            }
        """)
        
        layout.addWidget(self.incidents_table)
        
        return widget
    
    def _create_case_tab(self) -> QWidget:
        """Create case details tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Splitter for details and actions
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Details
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        # Case info group
        info_group = QGroupBox("📋 Case Information")
        info_layout = QFormLayout(info_group)
        
        self.case_id_label = QLabel("--")
        info_layout.addRow("Incident ID:", self.case_id_label)
        
        self.case_title_label = QLabel("--")
        self.case_title_label.setWordWrap(True)
        info_layout.addRow("Title:", self.case_title_label)
        
        self.case_type_label = QLabel("--")
        info_layout.addRow("Type:", self.case_type_label)
        
        self.case_severity_label = QLabel("--")
        info_layout.addRow("Severity:", self.case_severity_label)
        
        self.case_status_combo = QComboBox()
        self.case_status_combo.addItems([
            "new", "triaged", "investigating", "containing", 
            "eradicating", "recovering", "closed"
        ])
        self.case_status_combo.currentTextChanged.connect(self.update_case_status)
        info_layout.addRow("Status:", self.case_status_combo)
        
        self.case_assigned_label = QLabel("--")
        info_layout.addRow("Assigned To:", self.case_assigned_label)
        
        self.case_created_label = QLabel("--")
        info_layout.addRow("Created:", self.case_created_label)
        
        details_layout.addWidget(info_group)
        
        # Description group
        desc_group = QGroupBox("📝 Description")
        desc_layout = QVBoxLayout(desc_group)
        
        self.case_description = QTextEdit()
        self.case_description.setReadOnly(True)
        desc_layout.addWidget(self.case_description)
        
        details_layout.addWidget(desc_group)
        
        # Affected assets group
        assets_group = QGroupBox("🖥️ Affected Assets")
        assets_layout = QVBoxLayout(assets_group)
        
        self.affected_list = QListWidget()
        self.affected_list.setStyleSheet("""
            QListWidget {
                background: #0a0a1a;
                color: #00ffff;
                border: 1px solid #333;
            }
        """)
        assets_layout.addWidget(self.affected_list)
        
        details_layout.addWidget(assets_group)
        
        splitter.addWidget(details_widget)
        
        # Right panel - Actions
        actions_widget = QWidget()
        actions_layout = QVBoxLayout(actions_widget)
        
        # Quick actions group
        actions_group = QGroupBox("⚡ Quick Actions")
        actions_btn_layout = QVBoxLayout(actions_group)
        
        run_playbook_btn = QPushButton("📖 Run Playbook")
        run_playbook_btn.clicked.connect(self.run_playbook)
        actions_btn_layout.addWidget(run_playbook_btn)
        
        add_timeline_btn = QPushButton("📊 Add Timeline Event")
        add_timeline_btn.clicked.connect(self.add_timeline_event)
        actions_btn_layout.addWidget(add_timeline_btn)
        
        add_evidence_btn = QPushButton("🔒 Add Evidence")
        add_evidence_btn.clicked.connect(self.add_evidence)
        actions_btn_layout.addWidget(add_evidence_btn)
        
        add_ioc_btn = QPushButton("🎯 Add IOC")
        add_ioc_btn.clicked.connect(self.add_ioc)
        actions_btn_layout.addWidget(add_ioc_btn)
        
        add_task_btn = QPushButton("✅ Add Task")
        add_task_btn.clicked.connect(self.add_task)
        actions_btn_layout.addWidget(add_task_btn)
        
        close_case_btn = QPushButton("🔒 Close Incident")
        close_case_btn.setStyleSheet("background: #ff6b6b; color: black;")
        close_case_btn.clicked.connect(self.close_incident)
        actions_btn_layout.addWidget(close_case_btn)
        
        actions_layout.addWidget(actions_group)
        
        # Tasks group
        tasks_group = QGroupBox("✅ Tasks")
        tasks_layout = QVBoxLayout(tasks_group)
        
        self.tasks_list = QListWidget()
        self.tasks_list.setStyleSheet("""
            QListWidget {
                background: #0a0a1a;
                color: #00ff00;
                border: 1px solid #333;
            }
        """)
        tasks_layout.addWidget(self.tasks_list)
        
        actions_layout.addWidget(tasks_group)
        
        # Indicators group
        indicators_group = QGroupBox("🎯 Indicators")
        indicators_layout = QVBoxLayout(indicators_group)
        
        self.indicators_list = QListWidget()
        self.indicators_list.setStyleSheet("""
            QListWidget {
                background: #0a0a1a;
                color: #ffa500;
                border: 1px solid #333;
            }
        """)
        indicators_layout.addWidget(self.indicators_list)
        
        actions_layout.addWidget(indicators_group)
        
        splitter.addWidget(actions_widget)
        splitter.setSizes([500, 300])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_timeline_tab(self) -> QWidget:
        """Create timeline tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Timeline tree
        self.timeline_tree = QTreeWidget()
        self.timeline_tree.setHeaderLabels([
            "Timestamp", "Type", "Description", "Source", "Host", "Malicious"
        ])
        self.timeline_tree.setColumnWidth(0, 150)
        self.timeline_tree.setColumnWidth(1, 120)
        self.timeline_tree.setColumnWidth(2, 400)
        self.timeline_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0a0a1a;
                color: #00ffff;
                border: 1px solid #333;
            }
            QTreeWidget::item:selected {
                background-color: rgba(0, 255, 255, 0.3);
            }
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #00ffff;
                padding: 8px;
                border: 1px solid #333;
                font-weight: bold;
            }
        """)
        
        layout.addWidget(self.timeline_tree)
        
        # Timeline analysis
        analysis_group = QGroupBox("📊 Timeline Analysis")
        analysis_layout = QVBoxLayout(analysis_group)
        
        self.timeline_analysis = QTextEdit()
        self.timeline_analysis.setReadOnly(True)
        self.timeline_analysis.setMaximumHeight(200)
        self.timeline_analysis.setStyleSheet("""
            QTextEdit {
                background: #0a0a1a;
                color: #00ff00;
                border: 1px solid #00ff00;
            }
        """)
        analysis_layout.addWidget(self.timeline_analysis)
        
        analyze_btn = QPushButton("🔍 Analyze Timeline")
        analyze_btn.clicked.connect(self.analyze_timeline)
        analysis_layout.addWidget(analyze_btn)
        
        layout.addWidget(analysis_group)
        
        return widget
    
    def _create_playbooks_tab(self) -> QWidget:
        """Create playbooks tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Available playbooks
        playbooks_group = QGroupBox("📖 Available Playbooks")
        playbooks_layout = QVBoxLayout(playbooks_group)
        
        self.playbooks_table = QTableWidget()
        self.playbooks_table.setColumnCount(5)
        self.playbooks_table.setHorizontalHeaderLabels([
            "ID", "Name", "Incident Types", "Steps", "Status"
        ])
        self.playbooks_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.playbooks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.playbooks_table.setStyleSheet("""
            QTableWidget {
                background-color: #0a0a1a;
                gridline-color: #333;
                color: #ff00ff;
            }
            QTableWidget::item:selected {
                background-color: rgba(255, 0, 255, 0.3);
            }
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #ff00ff;
                padding: 8px;
                border: 1px solid #333;
                font-weight: bold;
            }
        """)
        playbooks_layout.addWidget(self.playbooks_table)
        
        layout.addWidget(playbooks_group)
        
        # Execution log
        exec_group = QGroupBox("📜 Execution Log")
        exec_layout = QVBoxLayout(exec_group)
        
        self.execution_log = QTextEdit()
        self.execution_log.setReadOnly(True)
        self.execution_log.setFont(QFont("Consolas", 10))
        self.execution_log.setStyleSheet("""
            QTextEdit {
                background: #0a0a1a;
                color: #00ff00;
                border: 1px solid #00ff00;
            }
        """)
        exec_layout.addWidget(self.execution_log)
        
        # Progress bar
        self.playbook_progress = QProgressBar()
        self.playbook_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #ff00ff;
                border-radius: 5px;
                text-align: center;
                background: #1a1a2e;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff00ff, stop:1 #00ffff);
            }
        """)
        exec_layout.addWidget(self.playbook_progress)
        
        layout.addWidget(exec_group)
        
        # Load playbooks
        self.load_playbooks()
        
        return widget
    
    def _create_evidence_tab(self) -> QWidget:
        """Create evidence tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Evidence table
        self.evidence_table = QTableWidget()
        self.evidence_table.setColumnCount(7)
        self.evidence_table.setHorizontalHeaderLabels([
            "ID", "Name", "Type", "Hash (SHA256)", "Collected", "Source", "Verified"
        ])
        self.evidence_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.evidence_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.evidence_table.setStyleSheet("""
            QTableWidget {
                background-color: #0a0a1a;
                gridline-color: #333;
                color: #00ff00;
            }
            QTableWidget::item:selected {
                background-color: rgba(0, 255, 0, 0.3);
            }
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #00ff00;
                padding: 8px;
                border: 1px solid #333;
                font-weight: bold;
            }
        """)
        
        layout.addWidget(self.evidence_table)
        
        # Evidence actions
        btn_layout = QHBoxLayout()
        
        collect_btn = QPushButton("📁 Collect File")
        collect_btn.clicked.connect(self.collect_evidence_file)
        btn_layout.addWidget(collect_btn)
        
        export_btn = QPushButton("📤 Export Package")
        export_btn.clicked.connect(self.export_evidence)
        btn_layout.addWidget(export_btn)
        
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def _create_iocs_tab(self) -> QWidget:
        """Create IOCs tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # IOC table
        self.ioc_table = QTableWidget()
        self.ioc_table.setColumnCount(7)
        self.ioc_table.setHorizontalHeaderLabels([
            "ID", "Type", "Value", "Confidence", "Source", "First Seen", "Active"
        ])
        self.ioc_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.ioc_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ioc_table.setStyleSheet("""
            QTableWidget {
                background-color: #0a0a1a;
                gridline-color: #333;
                color: #ffa500;
            }
            QTableWidget::item:selected {
                background-color: rgba(255, 165, 0, 0.3);
            }
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #ffa500;
                padding: 8px;
                border: 1px solid #333;
                font-weight: bold;
            }
        """)
        
        layout.addWidget(self.ioc_table)
        
        # IOC actions
        btn_layout = QHBoxLayout()
        
        add_ioc_btn = QPushButton("➕ Add IOC")
        add_ioc_btn.clicked.connect(self.add_ioc)
        btn_layout.addWidget(add_ioc_btn)
        
        import_btn = QPushButton("📥 Import IOCs")
        import_btn.clicked.connect(self.import_iocs)
        btn_layout.addWidget(import_btn)
        
        export_btn = QPushButton("📤 Export IOCs")
        export_btn.clicked.connect(self.export_iocs)
        btn_layout.addWidget(export_btn)
        
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def _create_metrics_tab(self) -> QWidget:
        """Create metrics tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Metrics cards
        cards_layout = QHBoxLayout()
        
        self.metric_cards = {}
        for label, color in [
            ("Total Incidents", "#00ffff"),
            ("Open", "#ff6b6b"),
            ("Closed", "#00ff00"),
            ("MTTR (hours)", "#ffa500"),
            ("SLA Breaches", "#ff0000"),
            ("False Positives", "#888888")
        ]:
            card = self._create_metric_card(label, color)
            self.metric_cards[label] = card
            cards_layout.addWidget(card)
        
        layout.addLayout(cards_layout)
        
        # Breakdown by severity
        severity_group = QGroupBox("📊 By Severity")
        severity_layout = QHBoxLayout(severity_group)
        
        self.severity_cards = {}
        for sev, color in [
            ("CRITICAL", "#ff0000"),
            ("HIGH", "#ff6b6b"),
            ("MEDIUM", "#ffa500"),
            ("LOW", "#00ff00"),
            ("INFO", "#888888")
        ]:
            card = self._create_metric_card(sev, color)
            self.severity_cards[sev] = card
            severity_layout.addWidget(card)
        
        layout.addWidget(severity_group)
        
        # Breakdown by type
        type_group = QGroupBox("📊 By Type")
        type_layout = QVBoxLayout(type_group)
        
        self.type_list = QListWidget()
        self.type_list.setStyleSheet("""
            QListWidget {
                background: #0a0a1a;
                color: #00ffff;
                border: 1px solid #333;
            }
        """)
        type_layout.addWidget(self.type_list)
        
        layout.addWidget(type_group)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh Metrics")
        refresh_btn.clicked.connect(self.refresh_metrics)
        layout.addWidget(refresh_btn)
        
        layout.addStretch()
        
        return widget
    
    def _create_metric_card(self, label: str, color: str) -> QFrame:
        """Create a metric card widget"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: rgba(0, 0, 0, 0.5);
                border: 2px solid {color};
                border-radius: 10px;
                padding: 10px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        value = QLabel("0")
        value.setObjectName("value")
        value.setFont(QFont("Consolas", 20, QFont.Weight.Bold))
        value.setStyleSheet(f"color: {color}; background: transparent; border: none;")
        value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value)
        
        text = QLabel(label)
        text.setStyleSheet("color: #888888; font-size: 10px; background: transparent; border: none;")
        text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(text)
        
        return card
    
    # ==================== Actions ====================
    
    def refresh_incidents(self):
        """Refresh incidents list"""
        if not self.engine:
            return
        
        self.incidents_table.setRowCount(0)
        
        status_filter = self.status_filter.currentText()
        severity_filter = self.severity_filter.currentText()
        
        # Get incidents
        incidents = self.engine.list_incidents()
        
        # Apply filters
        if status_filter != "All":
            status_enum = self.IncidentStatus(status_filter)
            incidents = [i for i in incidents if i.status == status_enum]
        
        if severity_filter != "All":
            severity_enum = self.IncidentSeverity[severity_filter]
            incidents = [i for i in incidents if i.severity == severity_enum]
        
        severity_colors = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff6b6b",
            "MEDIUM": "#ffa500",
            "LOW": "#00ff00",
            "INFO": "#888888"
        }
        
        for incident in incidents:
            row = self.incidents_table.rowCount()
            self.incidents_table.insertRow(row)
            
            severity_name = incident.severity.name
            color = QColor(severity_colors.get(severity_name, "#888888"))
            
            items = [
                incident.incident_id,
                incident.title,
                incident.incident_type.value,
                severity_name,
                incident.status.value,
                incident.assigned_to or "Unassigned",
                incident.created_at.strftime("%Y-%m-%d %H:%M"),
                "⚠️" if incident.sla_breach else "✓"
            ]
            
            for col, text in enumerate(items):
                item = QTableWidgetItem(str(text))
                if col == 3:  # Severity
                    item.setForeground(color)
                if col == 7 and incident.sla_breach:  # SLA
                    item.setForeground(QColor("#ff0000"))
                self.incidents_table.setItem(row, col, item)
        
        # Update header stats
        metrics = self.engine.get_metrics()
        self.open_incidents_label.findChild(QLabel, "value").setText(str(metrics.get("open", 0)))
        self.critical_label.findChild(QLabel, "value").setText(
            str(metrics.get("by_severity", {}).get("CRITICAL", 0))
        )
        self.mttr_label.findChild(QLabel, "value").setText(f"{metrics.get('mttr_hours', 0):.1f}h")
    
    def create_incident(self):
        """Create a new incident"""
        if not self.engine:
            return
        
        dialog = CreateIncidentDialog(self)
        if dialog.exec():
            data = dialog.get_data()
            
            incident_type = self.IncidentType(data["incident_type"])
            severity = self.IncidentSeverity[data["severity"]]
            
            incident = self.engine.create_incident(
                title=data["title"],
                description=data["description"],
                incident_type=incident_type,
                severity=severity,
                affected_hosts=data["affected_hosts"],
                affected_users=data["affected_users"],
                detected_at=data["detected_at"],
                assigned_to=data["assigned_to"],
                tags=data["tags"]
            )
            
            QMessageBox.information(
                self, "Incident Created",
                f"Created incident: {incident.incident_id}"
            )
            
            self.refresh_incidents()
    
    def open_incident(self):
        """Open selected incident for viewing/editing"""
        row = self.incidents_table.currentRow()
        if row < 0:
            return
        
        incident_id = self.incidents_table.item(row, 0).text()
        incident = self.engine.get_incident(incident_id)
        
        if not incident:
            return
        
        self.current_incident = incident
        self.load_case_details(incident)
        self.tabs.setCurrentIndex(1)  # Switch to Case Details tab
    
    def load_case_details(self, incident):
        """Load incident details into case tab"""
        self.case_id_label.setText(incident.incident_id)
        self.case_title_label.setText(incident.title)
        self.case_type_label.setText(incident.incident_type.value)
        
        severity_colors = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff6b6b",
            "MEDIUM": "#ffa500",
            "LOW": "#00ff00",
            "INFO": "#888888"
        }
        severity_name = incident.severity.name
        self.case_severity_label.setText(severity_name)
        self.case_severity_label.setStyleSheet(
            f"color: {severity_colors.get(severity_name, '#888888')};"
        )
        
        self.case_status_combo.blockSignals(True)
        self.case_status_combo.setCurrentText(incident.status.value)
        self.case_status_combo.blockSignals(False)
        
        self.case_assigned_label.setText(incident.assigned_to or "Unassigned")
        self.case_created_label.setText(incident.created_at.strftime("%Y-%m-%d %H:%M:%S"))
        self.case_description.setText(incident.description)
        
        # Affected assets
        self.affected_list.clear()
        for host in incident.affected_hosts:
            self.affected_list.addItem(f"🖥️ Host: {host}")
        for user in incident.affected_users:
            self.affected_list.addItem(f"👤 User: {user}")
        
        # Tasks
        self.tasks_list.clear()
        for task in incident.tasks:
            status_icon = "✅" if task.status == "completed" else "⏳" if task.status == "in_progress" else "⬜"
            self.tasks_list.addItem(f"{status_icon} {task.title}")
        
        # Indicators
        self.indicators_list.clear()
        for indicator in incident.indicators:
            self.indicators_list.addItem(f"• {indicator}")
        
        # Timeline
        self.timeline_tree.clear()
        for event in sorted(incident.timeline, key=lambda e: e.timestamp, reverse=True):
            item = QTreeWidgetItem([
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                event.event_type,
                event.description,
                event.source,
                event.host or "",
                "⚠️" if event.is_malicious else ""
            ])
            if event.is_malicious:
                item.setForeground(0, QColor("#ff0000"))
            self.timeline_tree.addTopLevelItem(item)
        
        # Evidence
        self.evidence_table.setRowCount(0)
        for evidence in incident.evidence:
            row = self.evidence_table.rowCount()
            self.evidence_table.insertRow(row)
            
            items = [
                evidence.evidence_id,
                evidence.name,
                evidence.evidence_type.value,
                (evidence.hash_sha256 or "")[:16] + "...",
                evidence.collected_at.strftime("%Y-%m-%d %H:%M"),
                evidence.source_host or "N/A",
                "✅" if evidence.is_verified else "❌"
            ]
            
            for col, text in enumerate(items):
                self.evidence_table.setItem(row, col, QTableWidgetItem(text))
    
    def update_case_status(self, status: str):
        """Update current case status"""
        if not self.current_incident or not self.engine:
            return
        
        status_enum = self.IncidentStatus(status)
        self.engine.update_incident(
            self.current_incident.incident_id,
            status=status_enum
        )
        self.refresh_incidents()
    
    def add_timeline_event(self):
        """Add timeline event to current incident"""
        if not self.current_incident:
            QMessageBox.warning(self, "Warning", "No incident selected")
            return
        
        dialog = AddTimelineEventDialog(self)
        if dialog.exec():
            data = dialog.get_data()
            
            self.engine.add_timeline_event(
                self.current_incident.incident_id,
                data["timestamp"],
                data["event_type"],
                data["description"],
                data["source"],
                host=data["host"],
                user=data["user"],
                indicators=data["indicators"],
                is_malicious=data["is_malicious"]
            )
            
            # Reload case
            self.current_incident = self.engine.get_incident(self.current_incident.incident_id)
            self.load_case_details(self.current_incident)
    
    def add_evidence(self):
        """Add evidence to current incident"""
        if not self.current_incident:
            QMessageBox.warning(self, "Warning", "No incident selected")
            return
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Evidence File", "", "All Files (*)"
        )
        
        if file_path:
            description, ok = QMessageBox.getText(
                self, "Evidence Description",
                "Enter description for this evidence:"
            ) if hasattr(QMessageBox, 'getText') else ("Collected evidence", True)
            
            evidence = self.engine.add_evidence(
                self.current_incident.incident_id,
                file_path,
                description if ok else "Collected evidence"
            )
            
            if evidence:
                QMessageBox.information(
                    self, "Evidence Added",
                    f"Evidence {evidence.evidence_id} added successfully"
                )
                self.current_incident = self.engine.get_incident(self.current_incident.incident_id)
                self.load_case_details(self.current_incident)
    
    def add_ioc(self):
        """Add IOC"""
        ioc_type, ok = QMessageBox.question(
            self, "IOC Type",
            "Select IOC type (ip, domain, hash, url, email, filename)"
        ) if False else ("ip", True)
        
        # Simple dialog for now
        value, ok = QMessageBox.question(self, "IOC Value", "Enter IOC value:") if False else ("", False)
        
        # This would be a proper dialog in production
        QMessageBox.information(self, "Info", "IOC dialog would open here")
    
    def add_task(self):
        """Add task to current incident"""
        if not self.current_incident:
            QMessageBox.warning(self, "Warning", "No incident selected")
            return
        
        # Simple task creation - would be a dialog in production
        task = self.engine.add_task(
            self.current_incident.incident_id,
            "Investigation task",
            "Review logs and identify root cause",
            priority=2
        )
        
        if task:
            self.current_incident = self.engine.get_incident(self.current_incident.incident_id)
            self.load_case_details(self.current_incident)
    
    def run_playbook(self):
        """Run playbook on current incident"""
        if not self.current_incident:
            QMessageBox.warning(self, "Warning", "No incident selected")
            return
        
        # Get matching playbooks
        playbooks = self.engine.playbook_engine.list_playbooks(
            self.current_incident.incident_type
        )
        
        if not playbooks:
            QMessageBox.warning(self, "Warning", "No matching playbooks found")
            return
        
        # Select first matching playbook
        playbook = playbooks[0]
        
        confirm = QMessageBox.question(
            self, "Run Playbook",
            f"Run playbook '{playbook.name}' on incident {self.current_incident.incident_id}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            self.execution_log.clear()
            self.execution_log.append(f"Starting playbook: {playbook.name}\n")
            self.playbook_progress.setValue(0)
            
            self.playbook_thread = PlaybookExecutionThread(
                self.engine, self.current_incident.incident_id, playbook.playbook_id
            )
            self.playbook_thread.completed.connect(self.on_playbook_complete)
            self.playbook_thread.error.connect(self.on_playbook_error)
            self.playbook_thread.start()
    
    def on_playbook_complete(self, result: Dict):
        """Handle playbook completion"""
        self.playbook_progress.setValue(100)
        
        self.execution_log.append("\n=== Execution Complete ===\n")
        self.execution_log.append(json.dumps(result, indent=2, default=str))
        
        if result.get("success"):
            QMessageBox.information(self, "Success", "Playbook executed successfully")
        else:
            QMessageBox.warning(self, "Warning", "Playbook completed with errors")
        
        self.refresh_incidents()
    
    def on_playbook_error(self, error: str):
        """Handle playbook error"""
        self.execution_log.append(f"\nERROR: {error}")
        QMessageBox.critical(self, "Error", f"Playbook execution failed: {error}")
    
    def analyze_timeline(self):
        """Analyze current incident timeline"""
        if not self.current_incident:
            QMessageBox.warning(self, "Warning", "No incident selected")
            return
        
        analysis = self.engine.analyze_timeline(self.current_incident.incident_id)
        
        if analysis:
            text = f"""Timeline Analysis for {self.current_incident.incident_id}
{'=' * 50}

Total Events: {analysis.get('total_events', 0)}
Time Span: {analysis.get('time_span', {}).get('duration_hours', 0):.1f} hours

Hosts Involved: {', '.join(analysis.get('hosts_involved', []))}
Users Involved: {', '.join(analysis.get('users_involved', []))}

Attack Phases Detected:
"""
            for phase in analysis.get('attack_phases', []):
                text += f"  • {phase['phase']}: {phase['event_count']} events\n"
            
            text += "\nPatterns Detected:\n"
            for pattern in analysis.get('patterns', []):
                text += f"  • {pattern['type']}: {pattern['description']}\n"
            
            text += "\nAnomalies:\n"
            for anomaly in analysis.get('anomalies', []):
                text += f"  • {anomaly['type']}: {anomaly['description']}\n"
            
            self.timeline_analysis.setText(text)
    
    def close_incident(self):
        """Close current incident"""
        if not self.current_incident:
            QMessageBox.warning(self, "Warning", "No incident selected")
            return
        
        confirm = QMessageBox.question(
            self, "Close Incident",
            f"Close incident {self.current_incident.incident_id}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            self.engine.close_incident(
                self.current_incident.incident_id,
                root_cause="Investigation complete",
                lessons_learned="To be documented"
            )
            
            QMessageBox.information(self, "Success", "Incident closed")
            self.refresh_incidents()
            self.current_incident = None
    
    def load_playbooks(self):
        """Load available playbooks"""
        if not self.engine:
            return
        
        self.playbooks_table.setRowCount(0)
        
        for playbook in self.engine.playbook_engine.list_playbooks():
            row = self.playbooks_table.rowCount()
            self.playbooks_table.insertRow(row)
            
            items = [
                playbook.playbook_id,
                playbook.name,
                ", ".join([t.value for t in playbook.incident_types]),
                str(len(playbook.steps)),
                "Enabled" if playbook.is_enabled else "Disabled"
            ]
            
            for col, text in enumerate(items):
                self.playbooks_table.setItem(row, col, QTableWidgetItem(text))
    
    def collect_evidence_file(self):
        """Collect file as evidence"""
        if not self.current_incident:
            QMessageBox.warning(self, "Warning", "No incident selected")
            return
        
        self.add_evidence()
    
    def export_evidence(self):
        """Export evidence package"""
        if not self.current_incident:
            QMessageBox.warning(self, "Warning", "No incident selected")
            return
        
        output_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if output_dir:
            zip_path = self.engine.evidence_collector.export_evidence_package(
                self.current_incident.incident_id, output_dir
            )
            
            if zip_path:
                QMessageBox.information(
                    self, "Success",
                    f"Evidence package exported to:\n{zip_path}"
                )
            else:
                QMessageBox.warning(self, "Warning", "No evidence to export")
    
    def import_iocs(self):
        """Import IOCs from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import IOCs", "", "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            QMessageBox.information(self, "Info", "IOC import would be processed here")
    
    def export_iocs(self):
        """Export IOCs to file"""
        if not self.engine:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export IOCs", "iocs.json", "JSON Files (*.json)"
        )
        
        if file_path:
            iocs = [
                {
                    "id": ioc.ioc_id,
                    "type": ioc.ioc_type,
                    "value": ioc.value,
                    "confidence": ioc.confidence,
                    "source": ioc.source
                }
                for ioc in self.engine.iocs.values()
            ]
            
            with open(file_path, 'w') as f:
                json.dump(iocs, f, indent=2)
            
            QMessageBox.information(self, "Success", f"Exported {len(iocs)} IOCs")
    
    def refresh_metrics(self):
        """Refresh metrics display"""
        if not self.engine:
            return
        
        metrics = self.engine.get_metrics()
        
        # Update main metrics
        self.metric_cards["Total Incidents"].findChild(QLabel, "value").setText(
            str(metrics.get("total", 0))
        )
        self.metric_cards["Open"].findChild(QLabel, "value").setText(
            str(metrics.get("open", 0))
        )
        self.metric_cards["Closed"].findChild(QLabel, "value").setText(
            str(metrics.get("closed", 0))
        )
        self.metric_cards["MTTR (hours)"].findChild(QLabel, "value").setText(
            f"{metrics.get('mttr_hours', 0):.1f}"
        )
        self.metric_cards["SLA Breaches"].findChild(QLabel, "value").setText(
            str(metrics.get("sla_breaches", 0))
        )
        self.metric_cards["False Positives"].findChild(QLabel, "value").setText(
            str(metrics.get("false_positives", 0))
        )
        
        # Update severity breakdown
        by_severity = metrics.get("by_severity", {})
        for sev, card in self.severity_cards.items():
            card.findChild(QLabel, "value").setText(str(by_severity.get(sev, 0)))
        
        # Update type breakdown
        self.type_list.clear()
        for itype, count in metrics.get("by_type", {}).items():
            if count > 0:
                self.type_list.addItem(f"{itype}: {count}")
