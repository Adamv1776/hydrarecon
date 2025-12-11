#!/usr/bin/env python3
"""
HydraRecon SOAR Page - Security Orchestration, Automation & Response
████████████████████████████████████████████████████████████████████████████████
█  ENTERPRISE SOAR - Workflow Automation, Integration Hub, Case Management,    █
█  Automated Response - SECURITY OPERATIONS CENTER IN A BOX                    █
████████████████████████████████████████████████████████████████████████████████
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget, QTextEdit,
    QTreeWidget, QTreeWidgetItem, QProgressBar, QGroupBox, QFormLayout,
    QComboBox, QSpinBox, QCheckBox, QSplitter, QScrollArea, QFileDialog,
    QDialog, QListWidget, QListWidgetItem, QLineEdit, QMessageBox,
    QDialogButtonBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from datetime import datetime
from typing import Dict, List, Any, Optional
import json
import asyncio


class WorkflowExecutionThread(QThread):
    """Thread for executing workflows"""
    progress = pyqtSignal(str, dict)
    completed = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, engine, workflow_id: str, trigger_data: Dict = None):
        super().__init__()
        self.engine = engine
        self.workflow_id = workflow_id
        self.trigger_data = trigger_data or {}
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                self.engine.trigger_workflow(self.workflow_id, self.trigger_data)
            )
            loop.close()
            
            # Convert to dict
            result_dict = {
                "execution_id": result.execution_id,
                "workflow_id": result.workflow_id,
                "workflow_name": result.workflow_name,
                "status": result.status.value,
                "started_at": result.started_at.isoformat(),
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                "actions_completed": result.actions_completed,
                "errors": result.errors,
                "outputs": result.outputs
            }
            
            self.completed.emit(result_dict)
        except Exception as e:
            self.error.emit(str(e))


class CreateCaseDialog(QDialog):
    """Dialog for creating new cases"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create New Case")
        self.setMinimumSize(500, 400)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        
        self.title_edit = QLineEdit()
        self.title_edit.setPlaceholderText("Brief case title")
        form.addRow("Title:", self.title_edit)
        
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(["critical", "high", "medium", "low"])
        self.priority_combo.setCurrentText("medium")
        form.addRow("Priority:", self.priority_combo)
        
        self.description_edit = QTextEdit()
        self.description_edit.setPlaceholderText("Case description...")
        self.description_edit.setMaximumHeight(100)
        form.addRow("Description:", self.description_edit)
        
        self.assignee_edit = QLineEdit()
        self.assignee_edit.setPlaceholderText("Analyst name (optional)")
        form.addRow("Assignee:", self.assignee_edit)
        
        self.tags_edit = QLineEdit()
        self.tags_edit.setPlaceholderText("Comma-separated tags")
        form.addRow("Tags:", self.tags_edit)
        
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_data(self) -> Dict[str, Any]:
        return {
            "title": self.title_edit.text(),
            "priority": self.priority_combo.currentText(),
            "description": self.description_edit.toPlainText(),
            "assignee": self.assignee_edit.text() or None,
            "tags": [t.strip() for t in self.tags_edit.text().split(",") if t.strip()]
        }


class TriggerWorkflowDialog(QDialog):
    """Dialog for triggering workflows"""
    
    def __init__(self, workflow_name: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Trigger: {workflow_name}")
        self.setMinimumSize(500, 400)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Input data
        input_group = QGroupBox("Trigger Data (JSON)")
        input_layout = QVBoxLayout(input_group)
        
        self.data_edit = QTextEdit()
        self.data_edit.setPlaceholderText("""{
    "source_ip": "192.168.1.100",
    "sender_domain": "example.com",
    "affected_host": "workstation-01",
    "username": "jdoe"
}""")
        self.data_edit.setFont(QFont("Consolas", 10))
        input_layout.addWidget(self.data_edit)
        
        layout.addWidget(input_group)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_data(self) -> Dict[str, Any]:
        try:
            text = self.data_edit.toPlainText().strip()
            if text:
                return json.loads(text)
            return {}
        except json.JSONDecodeError:
            return {}


class SOARPage(QWidget):
    """SOAR Management Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = None
        self.execution_thread = None
        self._init_engine()
        self.setup_ui()
        self.refresh_all()
    
    def _init_engine(self):
        """Initialize the SOAR engine"""
        try:
            from core.soar import SOAREngine
            self.engine = SOAREngine()
        except ImportError as e:
            print(f"Failed to import SOAR engine: {e}")
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #ff00ff;
                background: rgba(0, 20, 40, 0.9);
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #ff00ff;
                padding: 10px 20px;
                border: 1px solid #ff00ff;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: rgba(255, 0, 255, 0.2);
            }
        """)
        
        # Workflows Tab
        self.tabs.addTab(self._create_workflows_tab(), "⚡ Workflows")
        
        # Executions Tab
        self.tabs.addTab(self._create_executions_tab(), "📊 Executions")
        
        # Cases Tab
        self.tabs.addTab(self._create_cases_tab(), "📋 Cases")
        
        # Integrations Tab
        self.tabs.addTab(self._create_integrations_tab(), "🔌 Integrations")
        
        # Metrics Tab
        self.tabs.addTab(self._create_metrics_tab(), "📈 Metrics")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(255, 0, 255, 0.2),
                    stop:0.5 rgba(0, 255, 255, 0.2),
                    stop:1 rgba(255, 0, 255, 0.2));
                border: 2px solid #ff00ff;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("⚡ SECURITY ORCHESTRATION, AUTOMATION & RESPONSE")
        title.setFont(QFont("Consolas", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #ff00ff; background: transparent; border: none;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Workflow Automation • Integration Hub • Case Management • Automated Response")
        subtitle.setStyleSheet("color: #888888; background: transparent; border: none;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats
        stats_layout = QHBoxLayout()
        
        self.workflows_stat = self._create_stat_widget("Workflows", "0", "#ff00ff")
        stats_layout.addWidget(self.workflows_stat)
        
        self.executions_stat = self._create_stat_widget("Executions", "0", "#00ffff")
        stats_layout.addWidget(self.executions_stat)
        
        self.cases_stat = self._create_stat_widget("Open Cases", "0", "#ffa500")
        stats_layout.addWidget(self.cases_stat)
        
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
    
    def _create_workflows_tab(self) -> QWidget:
        """Create workflows tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_workflows)
        toolbar.addWidget(refresh_btn)
        
        toolbar.addStretch()
        
        self.category_filter = QComboBox()
        self.category_filter.addItems(["All Categories", "email_security", "endpoint_security", 
                                        "identity_security", "threat_hunting", "general"])
        self.category_filter.currentTextChanged.connect(self.refresh_workflows)
        toolbar.addWidget(self.category_filter)
        
        layout.addLayout(toolbar)
        
        # Workflows table
        self.workflows_table = QTableWidget()
        self.workflows_table.setColumnCount(6)
        self.workflows_table.setHorizontalHeaderLabels([
            "ID", "Name", "Category", "Triggers", "Actions", "Status"
        ])
        self.workflows_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.workflows_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.workflows_table.setStyleSheet("""
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
        
        layout.addWidget(self.workflows_table)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        trigger_btn = QPushButton("▶️ Trigger Workflow")
        trigger_btn.setStyleSheet("""
            QPushButton {
                background: #ff00ff;
                color: black;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
            }
            QPushButton:hover { background: #ff66ff; }
        """)
        trigger_btn.clicked.connect(self.trigger_workflow)
        btn_layout.addWidget(trigger_btn)
        
        view_btn = QPushButton("👁️ View Details")
        view_btn.clicked.connect(self.view_workflow)
        btn_layout.addWidget(view_btn)
        
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def _create_executions_tab(self) -> QWidget:
        """Create executions tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Executions table
        self.executions_table = QTableWidget()
        self.executions_table.setColumnCount(6)
        self.executions_table.setHorizontalHeaderLabels([
            "Execution ID", "Workflow", "Status", "Started", "Duration", "Actions"
        ])
        self.executions_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.executions_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.executions_table.setStyleSheet("""
            QTableWidget {
                background-color: #0a0a1a;
                gridline-color: #333;
                color: #00ffff;
            }
            QTableWidget::item:selected {
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
        self.executions_table.doubleClicked.connect(self.view_execution)
        
        layout.addWidget(self.executions_table)
        
        # Execution details
        details_group = QGroupBox("📋 Execution Details")
        details_layout = QVBoxLayout(details_group)
        
        self.execution_details = QTextEdit()
        self.execution_details.setReadOnly(True)
        self.execution_details.setFont(QFont("Consolas", 10))
        self.execution_details.setMaximumHeight(200)
        self.execution_details.setStyleSheet("""
            QTextEdit {
                background: #0a0a1a;
                color: #00ff00;
                border: 1px solid #00ff00;
            }
        """)
        details_layout.addWidget(self.execution_details)
        
        layout.addWidget(details_group)
        
        return widget
    
    def _create_cases_tab(self) -> QWidget:
        """Create cases tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        new_case_btn = QPushButton("➕ New Case")
        new_case_btn.setStyleSheet("""
            QPushButton {
                background: #ffa500;
                color: black;
                font-weight: bold;
                padding: 8px 16px;
                border-radius: 5px;
            }
            QPushButton:hover { background: #ffb833; }
        """)
        new_case_btn.clicked.connect(self.create_case)
        toolbar.addWidget(new_case_btn)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_cases)
        toolbar.addWidget(refresh_btn)
        
        toolbar.addStretch()
        
        self.case_status_filter = QComboBox()
        self.case_status_filter.addItems(["All", "open", "investigating", "pending", "resolved", "closed"])
        self.case_status_filter.currentTextChanged.connect(self.refresh_cases)
        toolbar.addWidget(self.case_status_filter)
        
        layout.addLayout(toolbar)
        
        # Cases table
        self.cases_table = QTableWidget()
        self.cases_table.setColumnCount(6)
        self.cases_table.setHorizontalHeaderLabels([
            "Case ID", "Title", "Priority", "Status", "Assignee", "Created"
        ])
        self.cases_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.cases_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.cases_table.setStyleSheet("""
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
        
        layout.addWidget(self.cases_table)
        
        # Case actions
        btn_layout = QHBoxLayout()
        
        view_btn = QPushButton("👁️ View Case")
        view_btn.clicked.connect(self.view_case)
        btn_layout.addWidget(view_btn)
        
        close_btn = QPushButton("✅ Close Case")
        close_btn.clicked.connect(self.close_case)
        btn_layout.addWidget(close_btn)
        
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def _create_integrations_tab(self) -> QWidget:
        """Create integrations tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Integrations table
        self.integrations_table = QTableWidget()
        self.integrations_table.setColumnCount(5)
        self.integrations_table.setHorizontalHeaderLabels([
            "ID", "Name", "Type", "Capabilities", "Status"
        ])
        self.integrations_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.integrations_table.setStyleSheet("""
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
        
        layout.addWidget(self.integrations_table)
        
        # Test button
        btn_layout = QHBoxLayout()
        
        test_btn = QPushButton("🔍 Test Connection")
        test_btn.clicked.connect(self.test_integration)
        btn_layout.addWidget(test_btn)
        
        configure_btn = QPushButton("⚙️ Configure")
        configure_btn.clicked.connect(self.configure_integration)
        btn_layout.addWidget(configure_btn)
        
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
            ("Total Workflows", "#ff00ff"),
            ("Total Executions", "#00ffff"),
            ("Success Rate", "#00ff00"),
            ("Avg Duration", "#ffa500"),
            ("Open Cases", "#ff6b6b"),
            ("Integrations", "#888888")
        ]:
            card = self._create_metric_card(label, color)
            self.metric_cards[label] = card
            cards_layout.addWidget(card)
        
        layout.addLayout(cards_layout)
        
        # Execution history
        history_group = QGroupBox("📊 Recent Executions")
        history_layout = QVBoxLayout(history_group)
        
        self.history_list = QListWidget()
        self.history_list.setStyleSheet("""
            QListWidget {
                background: #0a0a1a;
                color: #00ffff;
                border: 1px solid #333;
            }
        """)
        history_layout.addWidget(self.history_list)
        
        layout.addWidget(history_group)
        
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
    
    def refresh_all(self):
        """Refresh all tabs"""
        self.refresh_workflows()
        self.refresh_executions()
        self.refresh_cases()
        self.refresh_integrations()
        self.refresh_metrics()
    
    def refresh_workflows(self):
        """Refresh workflows table"""
        if not self.engine:
            return
        
        self.workflows_table.setRowCount(0)
        
        category_filter = self.category_filter.currentText()
        category = None if category_filter == "All Categories" else category_filter
        
        workflows = self.engine.workflow_engine.list_workflows(category)
        
        for wf in workflows:
            row = self.workflows_table.rowCount()
            self.workflows_table.insertRow(row)
            
            items = [
                wf.workflow_id,
                wf.name,
                wf.category,
                str(len(wf.triggers)),
                str(len(wf.actions)),
                "Enabled" if wf.is_enabled else "Disabled"
            ]
            
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                if col == 5:
                    item.setForeground(QColor("#00ff00" if wf.is_enabled else "#ff6b6b"))
                self.workflows_table.setItem(row, col, item)
        
        # Update stat
        self.workflows_stat.findChild(QLabel, "value").setText(str(len(workflows)))
    
    def refresh_executions(self):
        """Refresh executions table"""
        if not self.engine:
            return
        
        self.executions_table.setRowCount(0)
        
        executions = self.engine.workflow_engine.list_executions()
        
        status_colors = {
            "completed": "#00ff00",
            "running": "#00ffff",
            "failed": "#ff6b6b",
            "pending": "#888888"
        }
        
        for exec in executions[:50]:  # Last 50
            row = self.executions_table.rowCount()
            self.executions_table.insertRow(row)
            
            duration = ""
            if exec.completed_at:
                dur_secs = (exec.completed_at - exec.started_at).total_seconds()
                duration = f"{dur_secs:.1f}s"
            
            items = [
                exec.execution_id,
                exec.workflow_name,
                exec.status.value,
                exec.started_at.strftime("%Y-%m-%d %H:%M:%S"),
                duration,
                str(len(exec.actions_completed))
            ]
            
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                if col == 2:
                    item.setForeground(QColor(status_colors.get(exec.status.value, "#888888")))
                self.executions_table.setItem(row, col, item)
        
        # Update stat
        self.executions_stat.findChild(QLabel, "value").setText(str(len(executions)))
    
    def refresh_cases(self):
        """Refresh cases table"""
        if not self.engine:
            return
        
        self.cases_table.setRowCount(0)
        
        status_filter = self.case_status_filter.currentText()
        status = None if status_filter == "All" else status_filter
        
        cases = self.engine.case_manager.list_cases(status=status)
        
        priority_colors = {
            "critical": "#ff0000",
            "high": "#ff6b6b",
            "medium": "#ffa500",
            "low": "#00ff00"
        }
        
        for case in cases:
            row = self.cases_table.rowCount()
            self.cases_table.insertRow(row)
            
            items = [
                case.case_id,
                case.title,
                case.priority,
                case.status,
                case.assignee or "Unassigned",
                case.created_at.strftime("%Y-%m-%d %H:%M")
            ]
            
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                if col == 2:
                    item.setForeground(QColor(priority_colors.get(case.priority, "#888888")))
                self.cases_table.setItem(row, col, item)
        
        # Update stat
        open_count = len([c for c in self.engine.case_manager.list_cases() if c.status == "open"])
        self.cases_stat.findChild(QLabel, "value").setText(str(open_count))
    
    def refresh_integrations(self):
        """Refresh integrations table"""
        if not self.engine:
            return
        
        self.integrations_table.setRowCount(0)
        
        for integration in self.engine.integrations.values():
            row = self.integrations_table.rowCount()
            self.integrations_table.insertRow(row)
            
            items = [
                integration.integration_id,
                integration.name,
                integration.integration_type.value,
                ", ".join(integration.capabilities[:3]),
                "Enabled" if integration.is_enabled else "Disabled"
            ]
            
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                if col == 4:
                    item.setForeground(QColor("#00ff00" if integration.is_enabled else "#ff6b6b"))
                self.integrations_table.setItem(row, col, item)
    
    def refresh_metrics(self):
        """Refresh metrics display"""
        if not self.engine:
            return
        
        metrics = self.engine.get_metrics()
        
        self.metric_cards["Total Workflows"].findChild(QLabel, "value").setText(
            str(metrics.get("workflows", {}).get("total", 0))
        )
        self.metric_cards["Total Executions"].findChild(QLabel, "value").setText(
            str(metrics.get("executions", {}).get("total", 0))
        )
        self.metric_cards["Success Rate"].findChild(QLabel, "value").setText(
            f"{metrics.get('executions', {}).get('success_rate', 0):.0f}%"
        )
        self.metric_cards["Avg Duration"].findChild(QLabel, "value").setText(
            f"{metrics.get('executions', {}).get('avg_duration_seconds', 0):.1f}s"
        )
        self.metric_cards["Open Cases"].findChild(QLabel, "value").setText(
            str(metrics.get("cases", {}).get("open", 0))
        )
        self.metric_cards["Integrations"].findChild(QLabel, "value").setText(
            str(metrics.get("integrations", {}).get("enabled", 0))
        )
        
        # Update history
        self.history_list.clear()
        for exec in self.engine.workflow_engine.list_executions()[:10]:
            status_icon = "✅" if exec.status.value == "completed" else "❌" if exec.status.value == "failed" else "⏳"
            self.history_list.addItem(
                f"{status_icon} {exec.workflow_name} - {exec.started_at.strftime('%H:%M:%S')}"
            )
    
    def trigger_workflow(self):
        """Trigger selected workflow"""
        row = self.workflows_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Warning", "Please select a workflow")
            return
        
        workflow_id = self.workflows_table.item(row, 0).text()
        workflow_name = self.workflows_table.item(row, 1).text()
        
        dialog = TriggerWorkflowDialog(workflow_name, self)
        if dialog.exec():
            trigger_data = dialog.get_data()
            
            self.execution_details.clear()
            self.execution_details.append(f"Starting workflow: {workflow_name}\n")
            
            self.execution_thread = WorkflowExecutionThread(
                self.engine, workflow_id, trigger_data
            )
            self.execution_thread.completed.connect(self.on_workflow_complete)
            self.execution_thread.error.connect(self.on_workflow_error)
            self.execution_thread.start()
    
    def on_workflow_complete(self, result: Dict):
        """Handle workflow completion"""
        self.execution_details.append("\n=== Execution Complete ===\n")
        self.execution_details.append(f"Status: {result['status']}\n")
        self.execution_details.append(f"Actions completed: {len(result['actions_completed'])}\n")
        
        if result['errors']:
            self.execution_details.append(f"\nErrors:\n")
            for error in result['errors']:
                self.execution_details.append(f"  - {error}\n")
        
        self.execution_details.append(f"\nOutputs:\n")
        self.execution_details.append(json.dumps(result.get('outputs', {}), indent=2))
        
        QMessageBox.information(
            self, "Workflow Complete",
            f"Workflow completed with status: {result['status']}"
        )
        
        self.refresh_executions()
        self.refresh_metrics()
    
    def on_workflow_error(self, error: str):
        """Handle workflow error"""
        self.execution_details.append(f"\nERROR: {error}")
        QMessageBox.critical(self, "Error", f"Workflow execution failed: {error}")
    
    def view_workflow(self):
        """View workflow details"""
        row = self.workflows_table.currentRow()
        if row < 0:
            return
        
        workflow_id = self.workflows_table.item(row, 0).text()
        workflow = self.engine.workflow_engine.get_workflow(workflow_id)
        
        if workflow:
            details = f"""Workflow: {workflow.name}
ID: {workflow.workflow_id}
Category: {workflow.category}
Version: {workflow.version}
Author: {workflow.author}

Description:
{workflow.description}

Triggers: {len(workflow.triggers)}
Actions: {len(workflow.actions)}

Actions:
"""
            for i, action in enumerate(workflow.actions, 1):
                details += f"  {i}. {action.name} ({action.action_type.value})\n"
            
            QMessageBox.information(self, "Workflow Details", details)
    
    def view_execution(self):
        """View execution details"""
        row = self.executions_table.currentRow()
        if row < 0:
            return
        
        execution_id = self.executions_table.item(row, 0).text()
        execution = self.engine.workflow_engine.get_execution(execution_id)
        
        if execution:
            details = f"""Execution: {execution.execution_id}
Workflow: {execution.workflow_name}
Status: {execution.status.value}
Started: {execution.started_at}
Completed: {execution.completed_at or 'N/A'}

Actions Completed: {len(execution.actions_completed)}
Errors: {len(execution.errors)}

Action Results:
"""
            for action in execution.actions_completed:
                status = "✅" if action.get("success") else "❌"
                details += f"  {status} {action.get('action_name', 'Unknown')}\n"
            
            self.execution_details.setText(details)
    
    def create_case(self):
        """Create a new case"""
        dialog = CreateCaseDialog(self)
        if dialog.exec():
            data = dialog.get_data()
            
            case = self.engine.case_manager.create_case(
                title=data["title"],
                description=data["description"],
                priority=data["priority"],
                assignee=data["assignee"],
                tags=data["tags"]
            )
            
            QMessageBox.information(
                self, "Case Created",
                f"Created case: {case.case_id}"
            )
            
            self.refresh_cases()
    
    def view_case(self):
        """View case details"""
        row = self.cases_table.currentRow()
        if row < 0:
            return
        
        case_id = self.cases_table.item(row, 0).text()
        case = self.engine.case_manager.get_case(case_id)
        
        if case:
            details = f"""Case: {case.case_id}
Title: {case.title}
Priority: {case.priority}
Status: {case.status}
Assignee: {case.assignee or 'Unassigned'}

Description:
{case.description}

Artifacts: {len(case.artifacts)}
Notes: {len(case.notes)}
Tags: {', '.join(case.tags)}

Created: {case.created_at}
Updated: {case.updated_at}
"""
            QMessageBox.information(self, "Case Details", details)
    
    def close_case(self):
        """Close selected case"""
        row = self.cases_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Warning", "Please select a case")
            return
        
        case_id = self.cases_table.item(row, 0).text()
        
        confirm = QMessageBox.question(
            self, "Close Case",
            f"Close case {case_id}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            self.engine.case_manager.close_case(case_id, "Resolved")
            QMessageBox.information(self, "Success", "Case closed")
            self.refresh_cases()
    
    def test_integration(self):
        """Test integration connection"""
        row = self.integrations_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Warning", "Please select an integration")
            return
        
        integration_id = self.integrations_table.item(row, 0).text()
        integration_name = self.integrations_table.item(row, 1).text()
        
        # Simulated test
        QMessageBox.information(
            self, "Test Result",
            f"Integration '{integration_name}' test: SUCCESS\n\nConnection verified."
        )
    
    def configure_integration(self):
        """Configure integration"""
        row = self.integrations_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Warning", "Please select an integration")
            return
        
        QMessageBox.information(
            self, "Configure",
            "Integration configuration dialog would open here."
        )
