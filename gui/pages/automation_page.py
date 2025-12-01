#!/usr/bin/env python3
"""
HydraRecon Automation & Workflow Page
████████████████████████████████████████████████████████████████████████████████
█  ATTACK AUTOMATION CENTER - Visual Workflow Builder & Execution Monitor      █
████████████████████████████████████████████████████████████████████████████████
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTextEdit, QTableWidget, QTableWidgetItem,
    QGroupBox, QLineEdit, QProgressBar, QSplitter, QFrame,
    QListWidget, QListWidgetItem, QStackedWidget, QTreeWidget,
    QTreeWidgetItem, QHeaderView, QScrollArea, QTabWidget,
    QSpinBox, QCheckBox, QDialog, QDialogButtonBox, QFormLayout,
    QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QThread
from PyQt6.QtGui import QFont, QColor, QBrush, QIcon

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional

# Import core modules
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.automation import AutomationEngine, Workflow, WorkflowTask, TaskStatus, TaskType
except ImportError:
    AutomationEngine = None


class WorkflowExecutor(QThread):
    """Background thread for workflow execution"""
    progress = pyqtSignal(str, str, str, float)  # workflow_id, task_name, status, progress
    completed = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, engine, workflow, context):
        super().__init__()
        self.engine = engine
        self.workflow = workflow
        self.context = context
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            result = loop.run_until_complete(
                self.engine.execute_workflow(
                    self.workflow,
                    self.context,
                    self._progress_callback
                )
            )
            
            self.completed.emit(result)
        except Exception as e:
            self.error.emit(str(e))
    
    def _progress_callback(self, workflow_id, task_name, status, progress):
        self.progress.emit(workflow_id, task_name, status.value if hasattr(status, 'value') else str(status), progress)


class AutomationPage(QWidget):
    """Main automation and workflow page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.automation_engine = AutomationEngine() if AutomationEngine else None
        self.current_workflow = None
        self.executor_thread = None
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #2a3548;
                background: #151b2d;
                border-radius: 5px;
            }
            QTabBar::tab {
                background: #1a2235;
                color: #888;
                padding: 10px 20px;
                border: 1px solid #2a3548;
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #151b2d;
                color: #00ff9d;
                border-bottom: 2px solid #00ff9d;
            }
            QTabBar::tab:hover:!selected {
                background: #252d42;
            }
        """)
        
        # Workflow Templates Tab
        templates_tab = self._create_templates_tab()
        tabs.addTab(templates_tab, "📋 Workflow Templates")
        
        # Custom Workflow Builder Tab
        builder_tab = self._create_builder_tab()
        tabs.addTab(builder_tab, "🔧 Workflow Builder")
        
        # Active Workflows Tab
        active_tab = self._create_active_tab()
        tabs.addTab(active_tab, "▶️ Active Workflows")
        
        # History Tab
        history_tab = self._create_history_tab()
        tabs.addTab(history_tab, "📜 History")
        
        layout.addWidget(tabs)
    
    def _create_header(self) -> QWidget:
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #151b2d, stop:1 #1a2235);
                border: 1px solid #00ff9d;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("⚡ ATTACK AUTOMATION CENTER")
        title.setStyleSheet("color: #00ff9d; font-size: 20px; font-weight: bold;")
        subtitle = QLabel("Build and execute automated penetration testing workflows")
        subtitle.setStyleSheet("color: #888;")
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Quick stats
        stats_frame = QFrame()
        stats_frame.setStyleSheet("""
            QFrame {
                background: rgba(0, 255, 157, 0.1);
                border: 1px solid #2a3548;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        stats_layout = QHBoxLayout(stats_frame)
        
        templates_count = len(self.automation_engine.TEMPLATES) if self.automation_engine else 0
        
        for label, value in [
            ("Templates", str(templates_count)),
            ("Active", "0"),
            ("Completed", "0")
        ]:
            stat = QVBoxLayout()
            stat_label = QLabel(label)
            stat_label.setStyleSheet("color: #888; font-size: 11px;")
            stat_value = QLabel(value)
            stat_value.setStyleSheet("color: #00ff9d; font-size: 18px; font-weight: bold;")
            stat.addWidget(stat_value, alignment=Qt.AlignmentFlag.AlignCenter)
            stat.addWidget(stat_label, alignment=Qt.AlignmentFlag.AlignCenter)
            stats_layout.addLayout(stat)
        
        layout.addWidget(stats_frame)
        
        return header
    
    def _create_templates_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Template list
        templates_group = QGroupBox("Available Workflow Templates")
        templates_group.setStyleSheet("""
            QGroupBox {
                color: #00ff9d;
                font-weight: bold;
                border: 1px solid #2a3548;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        templates_layout = QVBoxLayout(templates_group)
        
        self.templates_list = QListWidget()
        self.templates_list.setStyleSheet("""
            QListWidget {
                background: #0a0e17;
                border: 1px solid #2a3548;
                border-radius: 5px;
            }
            QListWidget::item {
                padding: 15px;
                border-bottom: 1px solid #2a3548;
                color: #e0e0e0;
            }
            QListWidget::item:selected {
                background: rgba(0, 255, 157, 0.2);
                border-left: 3px solid #00ff9d;
            }
            QListWidget::item:hover {
                background: rgba(0, 255, 157, 0.1);
            }
        """)
        self.templates_list.itemClicked.connect(self._on_template_selected)
        
        # Populate templates
        if self.automation_engine:
            for template in self.automation_engine.get_available_templates():
                item = QListWidgetItem()
                item.setText(f"📋 {template['display_name']}\n    {template['description']}\n    Tasks: {template['task_count']}")
                item.setData(Qt.ItemDataRole.UserRole, template['name'])
                self.templates_list.addItem(item)
        
        templates_layout.addWidget(self.templates_list)
        
        layout.addWidget(templates_group)
        
        # Template details
        details_group = QGroupBox("Template Details")
        details_group.setStyleSheet("""
            QGroupBox {
                color: #00d4ff;
                font-weight: bold;
                border: 1px solid #2a3548;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        details_layout = QVBoxLayout(details_group)
        
        self.template_details = QTextEdit()
        self.template_details.setReadOnly(True)
        self.template_details.setStyleSheet("""
            QTextEdit {
                background: #0a0e17;
                color: #e0e0e0;
                border: 1px solid #2a3548;
                border-radius: 5px;
                font-family: 'Consolas', monospace;
            }
        """)
        details_layout.addWidget(self.template_details)
        
        layout.addWidget(details_group)
        
        # Execute button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        self.run_template_btn = QPushButton("🚀 Execute Selected Template")
        self.run_template_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff9d, stop:1 #00d4ff);
                color: #000;
                font-weight: bold;
                padding: 12px 30px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00d4ff, stop:1 #00ff9d);
            }
            QPushButton:disabled {
                background: #555;
                color: #888;
            }
        """)
        self.run_template_btn.clicked.connect(self._run_selected_template)
        btn_layout.addWidget(self.run_template_btn)
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def _create_builder_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Workflow info
        info_group = QGroupBox("Workflow Information")
        info_group.setStyleSheet("""
            QGroupBox {
                color: #00ff9d;
                font-weight: bold;
                border: 1px solid #2a3548;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        info_layout = QFormLayout(info_group)
        
        self.workflow_name = QLineEdit()
        self.workflow_name.setPlaceholderText("Enter workflow name...")
        self.workflow_name.setStyleSheet("""
            QLineEdit {
                background: #0a0e17;
                color: #e0e0e0;
                border: 1px solid #2a3548;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        info_layout.addRow("Name:", self.workflow_name)
        
        self.workflow_desc = QLineEdit()
        self.workflow_desc.setPlaceholderText("Enter description...")
        self.workflow_desc.setStyleSheet(self.workflow_name.styleSheet())
        info_layout.addRow("Description:", self.workflow_desc)
        
        layout.addWidget(info_group)
        
        # Task builder
        tasks_group = QGroupBox("Workflow Tasks")
        tasks_group.setStyleSheet("""
            QGroupBox {
                color: #00d4ff;
                font-weight: bold;
                border: 1px solid #2a3548;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        tasks_layout = QVBoxLayout(tasks_group)
        
        # Task list
        self.task_tree = QTreeWidget()
        self.task_tree.setHeaderLabels(["Task Name", "Type", "Module", "Dependencies"])
        self.task_tree.setStyleSheet("""
            QTreeWidget {
                background: #0a0e17;
                color: #e0e0e0;
                border: 1px solid #2a3548;
                border-radius: 5px;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QTreeWidget::item:selected {
                background: rgba(0, 255, 157, 0.2);
            }
            QHeaderView::section {
                background: #1a2235;
                color: #00ff9d;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #2a3548;
            }
        """)
        self.task_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tasks_layout.addWidget(self.task_tree)
        
        # Task buttons
        task_btn_layout = QHBoxLayout()
        
        add_task_btn = QPushButton("➕ Add Task")
        add_task_btn.setStyleSheet("""
            QPushButton {
                background: #1a2235;
                color: #00ff9d;
                border: 1px solid #00ff9d;
                padding: 8px 15px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: rgba(0, 255, 157, 0.2);
            }
        """)
        add_task_btn.clicked.connect(self._add_task_dialog)
        task_btn_layout.addWidget(add_task_btn)
        
        remove_task_btn = QPushButton("➖ Remove Task")
        remove_task_btn.setStyleSheet(add_task_btn.styleSheet().replace("#00ff9d", "#ff0040"))
        remove_task_btn.clicked.connect(self._remove_selected_task)
        task_btn_layout.addWidget(remove_task_btn)
        
        task_btn_layout.addStretch()
        
        save_workflow_btn = QPushButton("💾 Save Workflow")
        save_workflow_btn.setStyleSheet("""
            QPushButton {
                background: #1a2235;
                color: #00d4ff;
                border: 1px solid #00d4ff;
                padding: 8px 15px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: rgba(0, 212, 255, 0.2);
            }
        """)
        task_btn_layout.addWidget(save_workflow_btn)
        
        tasks_layout.addLayout(task_btn_layout)
        
        layout.addWidget(tasks_group)
        
        return widget
    
    def _create_active_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Active workflow display
        active_group = QGroupBox("Currently Executing Workflows")
        active_group.setStyleSheet("""
            QGroupBox {
                color: #00ff9d;
                font-weight: bold;
                border: 1px solid #2a3548;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        active_layout = QVBoxLayout(active_group)
        
        # Progress display
        self.workflow_progress = QProgressBar()
        self.workflow_progress.setStyleSheet("""
            QProgressBar {
                background: #0a0e17;
                border: 1px solid #2a3548;
                border-radius: 5px;
                height: 25px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff9d, stop:1 #00d4ff);
                border-radius: 4px;
            }
        """)
        active_layout.addWidget(self.workflow_progress)
        
        # Current task label
        self.current_task_label = QLabel("No active workflow")
        self.current_task_label.setStyleSheet("color: #888; padding: 10px;")
        active_layout.addWidget(self.current_task_label)
        
        # Task status table
        self.active_tasks_table = QTableWidget()
        self.active_tasks_table.setColumnCount(4)
        self.active_tasks_table.setHorizontalHeaderLabels(["Task", "Status", "Duration", "Result"])
        self.active_tasks_table.setStyleSheet("""
            QTableWidget {
                background: #0a0e17;
                color: #e0e0e0;
                border: 1px solid #2a3548;
                border-radius: 5px;
                gridline-color: #2a3548;
            }
            QHeaderView::section {
                background: #1a2235;
                color: #00ff9d;
                padding: 10px;
                border: none;
                border-bottom: 1px solid #2a3548;
            }
            QTableWidget::item {
                padding: 8px;
            }
        """)
        self.active_tasks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        active_layout.addWidget(self.active_tasks_table)
        
        layout.addWidget(active_group)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        pause_btn = QPushButton("⏸️ Pause")
        pause_btn.setStyleSheet("""
            QPushButton {
                background: #1a2235;
                color: #ffaa00;
                border: 1px solid #ffaa00;
                padding: 10px 20px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: rgba(255, 170, 0, 0.2);
            }
        """)
        control_layout.addWidget(pause_btn)
        
        cancel_btn = QPushButton("⏹️ Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background: #1a2235;
                color: #ff0040;
                border: 1px solid #ff0040;
                padding: 10px 20px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: rgba(255, 0, 64, 0.2);
            }
        """)
        cancel_btn.clicked.connect(self._cancel_workflow)
        control_layout.addWidget(cancel_btn)
        
        control_layout.addStretch()
        
        layout.addLayout(control_layout)
        
        # Output console
        output_group = QGroupBox("Workflow Output")
        output_group.setStyleSheet("""
            QGroupBox {
                color: #00d4ff;
                font-weight: bold;
                border: 1px solid #2a3548;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        output_layout = QVBoxLayout(output_group)
        
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setStyleSheet("""
            QTextEdit {
                background: #000;
                color: #00ff9d;
                border: 1px solid #2a3548;
                border-radius: 5px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }
        """)
        output_layout.addWidget(self.output_console)
        
        layout.addWidget(output_group)
        
        return widget
    
    def _create_history_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # History table
        history_group = QGroupBox("Workflow Execution History")
        history_group.setStyleSheet("""
            QGroupBox {
                color: #00ff9d;
                font-weight: bold;
                border: 1px solid #2a3548;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        history_layout = QVBoxLayout(history_group)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Workflow", "Status", "Started", "Duration", "Tasks", "Actions"
        ])
        self.history_table.setStyleSheet("""
            QTableWidget {
                background: #0a0e17;
                color: #e0e0e0;
                border: 1px solid #2a3548;
                border-radius: 5px;
                gridline-color: #2a3548;
            }
            QHeaderView::section {
                background: #1a2235;
                color: #00ff9d;
                padding: 10px;
                border: none;
                border-bottom: 1px solid #2a3548;
            }
        """)
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        history_layout.addWidget(self.history_table)
        
        layout.addWidget(history_group)
        
        return widget
    
    def _on_template_selected(self, item: QListWidgetItem):
        """Handle template selection"""
        template_name = item.data(Qt.ItemDataRole.UserRole)
        
        if self.automation_engine and template_name in self.automation_engine.TEMPLATES:
            template = self.automation_engine.TEMPLATES[template_name]
            
            details = f"<h3 style='color: #00ff9d;'>{template['name']}</h3>"
            details += f"<p style='color: #888;'>{template.get('description', '')}</p>"
            details += "<h4 style='color: #00d4ff;'>Tasks:</h4>"
            details += "<ul>"
            
            for i, task in enumerate(template.get('tasks', []), 1):
                status_icon = "⬜"
                details += f"<li style='color: #e0e0e0;'>{status_icon} <b>{task['name']}</b><br>"
                details += f"<span style='color: #888; font-size: 11px;'>Module: {task['module']}</span>"
                if task.get('dependencies'):
                    details += f"<br><span style='color: #666; font-size: 10px;'>Depends on: {', '.join(task['dependencies'])}</span>"
                details += "</li>"
            
            details += "</ul>"
            
            self.template_details.setHtml(details)
    
    def _run_selected_template(self):
        """Execute the selected workflow template"""
        current_item = self.templates_list.currentItem()
        if not current_item:
            return
        
        template_name = current_item.data(Qt.ItemDataRole.UserRole)
        
        if not self.automation_engine:
            self.output_console.append("[ERROR] Automation engine not available")
            return
        
        # Show target dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Configure Workflow")
        dialog.setStyleSheet("""
            QDialog {
                background: #151b2d;
            }
            QLabel {
                color: #e0e0e0;
            }
            QLineEdit {
                background: #0a0e17;
                color: #e0e0e0;
                border: 1px solid #2a3548;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        
        layout = QFormLayout(dialog)
        
        target_input = QLineEdit()
        target_input.setPlaceholderText("e.g., 192.168.1.0/24 or example.com")
        layout.addRow("Target:", target_input)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            target = target_input.text().strip()
            if not target:
                return
            
            # Create and execute workflow
            workflow = self.automation_engine.create_workflow_from_template(
                template_name,
                {"target": target}
            )
            
            self.current_workflow = workflow
            
            # Start executor thread
            self.executor_thread = WorkflowExecutor(
                self.automation_engine,
                workflow,
                {"target": target}
            )
            self.executor_thread.progress.connect(self._on_workflow_progress)
            self.executor_thread.completed.connect(self._on_workflow_completed)
            self.executor_thread.error.connect(self._on_workflow_error)
            self.executor_thread.start()
            
            # Update UI
            self.output_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] Starting workflow: {workflow.name}")
            self.output_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] Target: {target}")
            self.current_task_label.setText(f"Executing: {workflow.name}")
            self.workflow_progress.setValue(0)
            
            # Populate tasks table
            self.active_tasks_table.setRowCount(len(workflow.tasks))
            for i, task in enumerate(workflow.tasks):
                self.active_tasks_table.setItem(i, 0, QTableWidgetItem(task.name))
                status_item = QTableWidgetItem("⏳ Pending")
                status_item.setForeground(QBrush(QColor("#888")))
                self.active_tasks_table.setItem(i, 1, status_item)
                self.active_tasks_table.setItem(i, 2, QTableWidgetItem("-"))
                self.active_tasks_table.setItem(i, 3, QTableWidgetItem("-"))
    
    def _on_workflow_progress(self, workflow_id: str, task_name: str, status: str, progress: float):
        """Handle workflow progress update"""
        self.workflow_progress.setValue(int(progress))
        self.output_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] {task_name}: {status}")
        
        # Update task table
        for row in range(self.active_tasks_table.rowCount()):
            item = self.active_tasks_table.item(row, 0)
            if item and item.text() == task_name:
                status_item = self.active_tasks_table.item(row, 1)
                if status == "running":
                    status_item.setText("🔄 Running")
                    status_item.setForeground(QBrush(QColor("#00d4ff")))
                elif status == "completed":
                    status_item.setText("✅ Completed")
                    status_item.setForeground(QBrush(QColor("#00ff9d")))
                elif status == "failed":
                    status_item.setText("❌ Failed")
                    status_item.setForeground(QBrush(QColor("#ff0040")))
                elif status == "skipped":
                    status_item.setText("⏭️ Skipped")
                    status_item.setForeground(QBrush(QColor("#888")))
                break
    
    def _on_workflow_completed(self, result: dict):
        """Handle workflow completion"""
        self.workflow_progress.setValue(100)
        self.current_task_label.setText("Workflow completed!")
        
        self.output_console.append(f"\n[{datetime.now().strftime('%H:%M:%S')}] ═══════════════════════════════")
        self.output_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] Workflow completed!")
        self.output_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] Status: {result.get('status', 'unknown')}")
        self.output_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] Duration: {result.get('duration', 0):.2f}s")
        self.output_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] Tasks completed: {result.get('tasks_completed', 0)}")
        self.output_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] Tasks failed: {result.get('tasks_failed', 0)}")
        self.output_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] Tasks skipped: {result.get('tasks_skipped', 0)}")
        
        self.current_workflow = None
    
    def _on_workflow_error(self, error: str):
        """Handle workflow error"""
        self.output_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {error}")
        self.current_task_label.setText("Workflow failed!")
        self.current_workflow = None
    
    def _cancel_workflow(self):
        """Cancel the current workflow"""
        if self.current_workflow and self.automation_engine:
            self.automation_engine.cancel_workflow(self.current_workflow.id)
            self.output_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] Workflow cancelled by user")
            self.current_task_label.setText("Workflow cancelled")
    
    def _add_task_dialog(self):
        """Show dialog to add a new task"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Task")
        dialog.setMinimumWidth(400)
        dialog.setStyleSheet("""
            QDialog {
                background: #151b2d;
            }
            QLabel {
                color: #e0e0e0;
            }
            QLineEdit, QComboBox {
                background: #0a0e17;
                color: #e0e0e0;
                border: 1px solid #2a3548;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        
        layout = QFormLayout(dialog)
        
        name_input = QLineEdit()
        name_input.setPlaceholderText("Task name")
        layout.addRow("Name:", name_input)
        
        type_combo = QComboBox()
        for t in TaskType:
            type_combo.addItem(t.value)
        layout.addRow("Type:", type_combo)
        
        module_input = QLineEdit()
        module_input.setPlaceholderText("e.g., nmap.full_scan")
        layout.addRow("Module:", module_input)
        
        deps_input = QLineEdit()
        deps_input.setPlaceholderText("Comma-separated task names")
        layout.addRow("Dependencies:", deps_input)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            name = name_input.text().strip()
            if name:
                item = QTreeWidgetItem([
                    name,
                    type_combo.currentText(),
                    module_input.text().strip(),
                    deps_input.text().strip()
                ])
                self.task_tree.addTopLevelItem(item)
    
    def _remove_selected_task(self):
        """Remove selected task from the tree"""
        current = self.task_tree.currentItem()
        if current:
            index = self.task_tree.indexOfTopLevelItem(current)
            if index >= 0:
                self.task_tree.takeTopLevelItem(index)
