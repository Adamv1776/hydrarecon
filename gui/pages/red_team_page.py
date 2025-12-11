#!/usr/bin/env python3
"""
HydraRecon Red Team Automation Page
GUI for automated red team operations and adversary simulation.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QComboBox,
    QTextEdit, QTableWidget, QTableWidgetItem, QProgressBar,
    QTabWidget, QGroupBox, QCheckBox, QSpinBox, QSplitter,
    QHeaderView, QTreeWidget, QTreeWidgetItem, QMessageBox,
    QListWidget, QListWidgetItem, QDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor

import asyncio
from datetime import datetime
from typing import Optional

try:
    from ...core.red_team_automation import (
        RedTeamEngine, AdversaryEmulator, TechniqueCategory,
        OperationStatus, AttackChain
    )
    REDTEAM_AVAILABLE = True
except ImportError:
    REDTEAM_AVAILABLE = False


class OperationWorker(QThread):
    """Worker thread for operation execution"""
    progress = pyqtSignal(str, float)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, engine, chain_id, dry_run=True):
        super().__init__()
        self.engine = engine
        self.chain_id = chain_id
        self.dry_run = dry_run
    
    def run(self):
        """Run the operation"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            def callback(msg, progress):
                self.progress.emit(msg, progress)
            
            result = loop.run_until_complete(
                self.engine.execute_operation(self.chain_id, callback, self.dry_run)
            )
            
            loop.close()
            self.finished.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class TechniqueSelectionDialog(QDialog):
    """Dialog for selecting techniques"""
    
    def __init__(self, techniques, parent=None):
        super().__init__(parent)
        self.techniques = techniques
        self.selected = []
        self._setup_ui()
    
    def _setup_ui(self):
        self.setWindowTitle("Select Attack Techniques")
        self.setMinimumSize(600, 500)
        self.setStyleSheet("""
            QDialog {
                background-color: #0d1117;
            }
        """)
        
        layout = QVBoxLayout(self)
        
        # Search
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        self.search_input.textChanged.connect(self._filter_techniques)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)
        
        # Technique list
        self.technique_list = QListWidget()
        self.technique_list.setStyleSheet("""
            QListWidget {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QListWidget::item {
                padding: 8px;
            }
            QListWidget::item:selected {
                background-color: #238636;
            }
        """)
        self.technique_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        
        for tech in self.techniques:
            item = QListWidgetItem(f"[{tech['id']}] {tech['name']} - {tech['category']}")
            item.setData(Qt.ItemDataRole.UserRole, tech['id'])
            self.technique_list.addItem(item)
        
        layout.addWidget(self.technique_list)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        ok_btn = QPushButton("Select")
        ok_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 24px;
            }
        """)
        ok_btn.clicked.connect(self._accept)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 24px;
            }
        """)
        cancel_btn.clicked.connect(self.reject)
        
        btn_layout.addStretch()
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(ok_btn)
        layout.addLayout(btn_layout)
    
    def _filter_techniques(self, text):
        """Filter techniques by search text"""
        text = text.lower()
        for i in range(self.technique_list.count()):
            item = self.technique_list.item(i)
            item.setHidden(text not in item.text().lower())
    
    def _accept(self):
        """Accept selection"""
        self.selected = [
            item.data(Qt.ItemDataRole.UserRole)
            for item in self.technique_list.selectedItems()
        ]
        self.accept()


class RedTeamPage(QWidget):
    """Red Team Automation Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = RedTeamEngine() if REDTEAM_AVAILABLE else None
        self.emulator = AdversaryEmulator(self.engine) if self.engine else None
        self.current_operation: Optional[AttackChain] = None
        self.operation_worker: Optional[OperationWorker] = None
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #21262d;
                border-radius: 8px;
                background-color: #0d1117;
            }
            QTabBar::tab {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px 20px;
                border: 1px solid #21262d;
                border-bottom: none;
                border-radius: 6px 6px 0 0;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #e6e6e6;
            }
        """)
        
        # Tab 1: Operations
        self.tabs.addTab(self._create_operations_tab(), "⚔️ Operations")
        
        # Tab 2: Adversary Emulation
        self.tabs.addTab(self._create_adversary_tab(), "🎭 Adversary Emulation")
        
        # Tab 3: TTP Matrix
        self.tabs.addTab(self._create_matrix_tab(), "📊 ATT&CK Matrix")
        
        # Tab 4: Results
        self.tabs.addTab(self._create_results_tab(), "📋 Results & Reports")
        
        layout.addWidget(self.tabs, stretch=1)
    
    def _create_header(self) -> QWidget:
        """Create header section"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #f85149, stop:1 #8957e5);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("⚔️ Red Team Automation")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: 700;
            color: white;
        """)
        
        subtitle = QLabel("Automated adversary simulation and attack chain execution")
        subtitle.setStyleSheet("font-size: 14px; color: rgba(255,255,255,0.8);")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout, stretch=1)
        
        # Stats
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(24)
        
        self.stat_operations = self._create_stat_widget("Operations", "0")
        self.stat_techniques = self._create_stat_widget("Techniques", "0")
        self.stat_coverage = self._create_stat_widget("TTP Coverage", "0%")
        
        stats_layout.addWidget(self.stat_operations)
        stats_layout.addWidget(self.stat_techniques)
        stats_layout.addWidget(self.stat_coverage)
        
        layout.addLayout(stats_layout)
        
        return header
    
    def _create_stat_widget(self, label: str, value: str) -> QWidget:
        """Create a stat display widget"""
        widget = QFrame()
        widget.setStyleSheet("""
            QFrame {
                background-color: rgba(0,0,0,0.3);
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        value_label.setObjectName("value")
        
        text_label = QLabel(label)
        text_label.setStyleSheet("font-size: 11px; color: rgba(255,255,255,0.7);")
        
        layout.addWidget(value_label, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(text_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        return widget
    
    def _create_operations_tab(self) -> QWidget:
        """Create operations management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # New operation section
        new_op_group = QGroupBox("Create New Operation")
        new_op_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
            }
        """)
        
        new_op_layout = QGridLayout(new_op_group)
        new_op_layout.setSpacing(12)
        
        # Operation name
        new_op_layout.addWidget(QLabel("Operation Name:"), 0, 0)
        self.op_name_input = QLineEdit()
        self.op_name_input.setPlaceholderText("e.g., Operation Thunderstrike")
        self.op_name_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        new_op_layout.addWidget(self.op_name_input, 0, 1)
        
        # Target
        new_op_layout.addWidget(QLabel("Target Environment:"), 1, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.0/24 or target.domain.com")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        new_op_layout.addWidget(self.target_input, 1, 1)
        
        # Operation type
        new_op_layout.addWidget(QLabel("Operation Type:"), 2, 0)
        self.op_type_combo = QComboBox()
        self.op_type_combo.addItems([
            "Custom Operation",
            "Full Kill Chain",
            "Initial Access Only",
            "Credential Harvesting",
            "Lateral Movement Focus",
            "Exfiltration Simulation"
        ])
        self.op_type_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        new_op_layout.addWidget(self.op_type_combo, 2, 1)
        
        # Technique selection
        new_op_layout.addWidget(QLabel("Techniques:"), 3, 0)
        tech_layout = QHBoxLayout()
        
        self.techniques_label = QLabel("0 techniques selected")
        self.techniques_label.setStyleSheet("color: #8b949e;")
        
        select_btn = QPushButton("Select Techniques...")
        select_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 16px;
            }
        """)
        select_btn.clicked.connect(self._select_techniques)
        
        tech_layout.addWidget(self.techniques_label)
        tech_layout.addStretch()
        tech_layout.addWidget(select_btn)
        new_op_layout.addLayout(tech_layout, 3, 1)
        
        # Execution mode
        mode_layout = QHBoxLayout()
        self.dry_run_check = QCheckBox("Dry Run (No actual execution)")
        self.dry_run_check.setChecked(True)
        self.dry_run_check.setStyleSheet("color: #ffa657;")
        mode_layout.addWidget(self.dry_run_check)
        mode_layout.addStretch()
        new_op_layout.addLayout(mode_layout, 4, 0, 1, 2)
        
        layout.addWidget(new_op_group)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.create_btn = QPushButton("📝 Create Operation")
        self.create_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
        """)
        self.create_btn.clicked.connect(self._create_operation)
        
        self.execute_btn = QPushButton("▶️ Execute Operation")
        self.execute_btn.setEnabled(False)
        self.execute_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:disabled { background-color: #21262d; color: #8b949e; }
        """)
        self.execute_btn.clicked.connect(self._execute_operation)
        
        self.abort_btn = QPushButton("⏹️ Abort")
        self.abort_btn.setEnabled(False)
        self.abort_btn.setStyleSheet("""
            QPushButton {
                background-color: #f85149;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:disabled { background-color: #21262d; color: #8b949e; }
        """)
        self.abort_btn.clicked.connect(self._abort_operation)
        
        btn_layout.addWidget(self.create_btn)
        btn_layout.addWidget(self.execute_btn)
        btn_layout.addWidget(self.abort_btn)
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        # Progress
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #21262d;
                border: none;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #238636;
                border-radius: 4px;
            }
        """)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #8b949e;")
        
        progress_layout.addWidget(self.progress_bar, stretch=1)
        progress_layout.addWidget(self.status_label)
        
        layout.addLayout(progress_layout)
        
        # Operations list
        self.operations_table = QTableWidget()
        self.operations_table.setColumnCount(5)
        self.operations_table.setHorizontalHeaderLabels([
            "Operation", "Target", "Status", "Steps", "Created"
        ])
        self.operations_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                color: #e6e6e6;
                padding: 8px;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        self.operations_table.horizontalHeader().setStretchLastSection(True)
        
        layout.addWidget(self.operations_table, stretch=1)
        
        # Selected techniques storage
        self.selected_techniques = []
        
        return widget
    
    def _create_adversary_tab(self) -> QWidget:
        """Create adversary emulation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        info = QLabel(
            "Emulate real-world threat actors using their documented TTPs. "
            "These simulations help test your defenses against specific adversary groups."
        )
        info.setStyleSheet("color: #8b949e;")
        info.setWordWrap(True)
        layout.addWidget(info)
        
        # Adversary profiles
        profiles_layout = QGridLayout()
        profiles_layout.setSpacing(16)
        
        if self.emulator:
            profiles = self.emulator.list_profiles()
            for i, profile in enumerate(profiles):
                card = self._create_adversary_card(profile)
                profiles_layout.addWidget(card, i // 2, i % 2)
        
        layout.addLayout(profiles_layout)
        layout.addStretch()
        
        return widget
    
    def _create_adversary_card(self, profile: dict) -> QWidget:
        """Create adversary profile card"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 12px;
                padding: 16px;
            }
            QFrame:hover {
                border-color: #8957e5;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        # Title
        title = QLabel(profile['name'])
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6;")
        layout.addWidget(title)
        
        # Threat actor
        actor = QLabel(f"🎭 {profile['threat_actor']}")
        actor.setStyleSheet("color: #8957e5; font-size: 12px;")
        layout.addWidget(actor)
        
        # Description
        desc = QLabel(profile['description'])
        desc.setStyleSheet("color: #8b949e;")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # Industries
        industries = QLabel(f"🎯 Targets: {', '.join(profile['target_industries'])}")
        industries.setStyleSheet("color: #58a6ff; font-size: 11px;")
        layout.addWidget(industries)
        
        # Emulate button
        emulate_btn = QPushButton("🚀 Emulate")
        emulate_btn.setStyleSheet("""
            QPushButton {
                background-color: #8957e5;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px;
                font-weight: bold;
            }
        """)
        emulate_btn.clicked.connect(lambda: self._emulate_adversary(profile['id']))
        layout.addWidget(emulate_btn)
        
        return card
    
    def _create_matrix_tab(self) -> QWidget:
        """Create ATT&CK matrix view tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        info = QLabel(
            "MITRE ATT&CK Matrix coverage for current operation. "
            "Green indicates successful execution, red indicates failure."
        )
        info.setStyleSheet("color: #8b949e;")
        info.setWordWrap(True)
        layout.addWidget(info)
        
        # Matrix tree
        self.matrix_tree = QTreeWidget()
        self.matrix_tree.setHeaderLabels(["Tactic/Technique", "Status", "Details"])
        self.matrix_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                color: #e6e6e6;
            }
            QTreeWidget::item {
                padding: 8px;
            }
            QTreeWidget::item:selected {
                background-color: #21262d;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        
        # Populate with categories
        categories = [
            ("Initial Access", "#f85149"),
            ("Execution", "#ffa657"),
            ("Persistence", "#d29922"),
            ("Privilege Escalation", "#3fb950"),
            ("Defense Evasion", "#58a6ff"),
            ("Credential Access", "#a371f7"),
            ("Discovery", "#8b949e"),
            ("Lateral Movement", "#f778ba"),
            ("Collection", "#79c0ff"),
            ("Exfiltration", "#7ee787"),
            ("Impact", "#f85149")
        ]
        
        for cat_name, color in categories:
            cat_item = QTreeWidgetItem([cat_name, "", ""])
            cat_item.setForeground(0, QColor(color))
            self.matrix_tree.addTopLevelItem(cat_item)
        
        layout.addWidget(self.matrix_tree, stretch=1)
        
        return widget
    
    def _create_results_tab(self) -> QWidget:
        """Create results and reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Operation selector
        select_layout = QHBoxLayout()
        select_layout.addWidget(QLabel("Select Operation:"))
        
        self.result_op_combo = QComboBox()
        self.result_op_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
                min-width: 300px;
            }
        """)
        self.result_op_combo.currentIndexChanged.connect(self._load_operation_report)
        select_layout.addWidget(self.result_op_combo)
        select_layout.addStretch()
        
        export_btn = QPushButton("📥 Export Report")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        select_layout.addWidget(export_btn)
        
        layout.addLayout(select_layout)
        
        # Report display
        self.report_display = QTextEdit()
        self.report_display.setReadOnly(True)
        self.report_display.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                color: #e6e6e6;
                padding: 16px;
                font-family: 'Consolas', monospace;
            }
        """)
        self.report_display.setPlaceholderText("Select an operation to view its report...")
        
        layout.addWidget(self.report_display, stretch=1)
        
        return widget
    
    def _select_techniques(self):
        """Open technique selection dialog"""
        if not self.engine:
            return
        
        techniques = self.engine.get_available_techniques()
        dialog = TechniqueSelectionDialog(techniques, self)
        
        if dialog.exec():
            self.selected_techniques = dialog.selected
            self.techniques_label.setText(f"{len(self.selected_techniques)} techniques selected")
    
    def _create_operation(self):
        """Create a new operation"""
        if not self.engine:
            QMessageBox.warning(self, "Error", "Red Team module not available")
            return
        
        name = self.op_name_input.text().strip()
        target = self.target_input.text().strip()
        
        if not name or not target:
            QMessageBox.warning(self, "Error", "Please enter operation name and target")
            return
        
        op_type = self.op_type_combo.currentIndex()
        
        try:
            if op_type == 1:  # Full Kill Chain
                chain = self.engine.create_kill_chain_operation(name, target)
            elif self.selected_techniques:
                chain = self.engine.create_operation(
                    name=name,
                    description=f"Custom operation targeting {target}",
                    objective="Security assessment",
                    target=target,
                    technique_ids=self.selected_techniques
                )
            else:
                QMessageBox.warning(self, "Error", "Please select techniques or choose a preset")
                return
            
            self.current_operation = chain
            self.execute_btn.setEnabled(True)
            self._refresh_operations_table()
            
            self.status_label.setText(f"Operation '{name}' created with {len(chain.steps)} steps")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def _execute_operation(self):
        """Execute the current operation"""
        if not self.current_operation:
            return
        
        dry_run = self.dry_run_check.isChecked()
        
        if not dry_run:
            reply = QMessageBox.warning(
                self, "Confirm Execution",
                "You are about to execute a LIVE operation. "
                "This will perform actual attacks on the target.\n\n"
                "Are you authorized to perform this assessment?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        self.execute_btn.setEnabled(False)
        self.abort_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        
        self.operation_worker = OperationWorker(
            self.engine, self.current_operation.chain_id, dry_run
        )
        self.operation_worker.progress.connect(self._on_progress)
        self.operation_worker.finished.connect(self._on_finished)
        self.operation_worker.error.connect(self._on_error)
        self.operation_worker.start()
    
    def _abort_operation(self):
        """Abort the current operation"""
        if self.current_operation:
            self.engine.abort_operation(self.current_operation.chain_id)
        
        if self.operation_worker and self.operation_worker.isRunning():
            self.operation_worker.terminate()
        
        self.execute_btn.setEnabled(True)
        self.abort_btn.setEnabled(False)
        self.status_label.setText("Operation aborted")
    
    def _on_progress(self, message: str, progress: float):
        """Handle progress update"""
        self.status_label.setText(message)
        self.progress_bar.setValue(int(progress))
    
    def _on_finished(self, result):
        """Handle operation completion"""
        self.execute_btn.setEnabled(True)
        self.abort_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        
        self.current_operation = result
        self.status_label.setText(f"Operation complete: {result.status.value}")
        
        self._refresh_operations_table()
        self._update_matrix(result)
        self._update_stats()
    
    def _on_error(self, error: str):
        """Handle operation error"""
        self.execute_btn.setEnabled(True)
        self.abort_btn.setEnabled(False)
        self.status_label.setText(f"Error: {error}")
        QMessageBox.critical(self, "Operation Error", error)
    
    def _refresh_operations_table(self):
        """Refresh operations table"""
        if not self.engine:
            return
        
        operations = self.engine.list_operations()
        self.operations_table.setRowCount(len(operations))
        
        status_colors = {
            "pending": "#8b949e",
            "running": "#58a6ff",
            "success": "#3fb950",
            "partial": "#d29922",
            "failed": "#f85149",
            "aborted": "#f85149"
        }
        
        for row, op in enumerate(operations):
            self.operations_table.setItem(row, 0, QTableWidgetItem(op['name']))
            self.operations_table.setItem(row, 1, QTableWidgetItem(op['target']))
            
            status_item = QTableWidgetItem(op['status'].upper())
            status_item.setForeground(QColor(status_colors.get(op['status'], "#8b949e")))
            self.operations_table.setItem(row, 2, status_item)
            
            self.operations_table.setItem(row, 3, QTableWidgetItem(str(op['steps'])))
            self.operations_table.setItem(row, 4, QTableWidgetItem(op['created_at']))
        
        # Update combo box
        self.result_op_combo.clear()
        for op in operations:
            self.result_op_combo.addItem(op['name'], op['chain_id'])
    
    def _update_matrix(self, chain):
        """Update ATT&CK matrix display"""
        matrix = self.engine.get_ttp_matrix(chain.chain_id)
        
        # Clear existing children
        for i in range(self.matrix_tree.topLevelItemCount()):
            item = self.matrix_tree.topLevelItem(i)
            while item.childCount() > 0:
                item.removeChild(item.child(0))
        
        # Add techniques to categories
        category_map = {
            "initial_access": 0,
            "execution": 1,
            "persistence": 2,
            "privilege_escalation": 3,
            "defense_evasion": 4,
            "credential_access": 5,
            "discovery": 6,
            "lateral_movement": 7,
            "collection": 8,
            "exfiltration": 9,
            "impact": 10
        }
        
        status_colors = {
            "success": "#3fb950",
            "failed": "#f85149",
            "pending": "#8b949e",
            "running": "#58a6ff"
        }
        
        for category, techniques in matrix.items():
            cat_index = category_map.get(category, -1)
            if cat_index < 0:
                continue
            
            cat_item = self.matrix_tree.topLevelItem(cat_index)
            for tech in techniques:
                child = QTreeWidgetItem([
                    f"[{tech['technique_id']}] {tech['name']}",
                    tech['status'].upper(),
                    ""
                ])
                child.setForeground(1, QColor(status_colors.get(tech['status'], "#8b949e")))
                cat_item.addChild(child)
            
            cat_item.setExpanded(True)
    
    def _update_stats(self):
        """Update statistics display"""
        if not self.engine:
            return
        
        operations = self.engine.list_operations()
        total_ops = len(operations)
        total_techniques = len(self.engine.get_available_techniques())
        
        # Calculate coverage
        if self.current_operation:
            covered = len([c for c in self.current_operation.ttp_coverage 
                          if self.current_operation.ttp_coverage[c]])
            coverage = f"{(covered / 11) * 100:.0f}%"
        else:
            coverage = "0%"
        
        self.stat_operations.findChild(QLabel, "value").setText(str(total_ops))
        self.stat_techniques.findChild(QLabel, "value").setText(str(total_techniques))
        self.stat_coverage.findChild(QLabel, "value").setText(coverage)
    
    def _load_operation_report(self, index):
        """Load operation report"""
        if not self.engine or index < 0:
            return
        
        chain_id = self.result_op_combo.itemData(index)
        if not chain_id:
            return
        
        report = self.engine.generate_report(chain_id)
        if not report:
            return
        
        # Format report as HTML
        html = f"""
        <h2 style="color: #e6e6e6;">Operation: {report['operation']['name']}</h2>
        <p><b>Status:</b> <span style="color: {'#3fb950' if report['operation']['status'] == 'success' else '#f85149'}">
            {report['operation']['status'].upper()}</span></p>
        <p><b>Target:</b> {report['operation']['target']}</p>
        <p><b>Duration:</b> {report['operation']['duration'] or 'N/A'}</p>
        
        <h3 style="color: #8b949e;">Statistics</h3>
        <ul>
            <li>Total Steps: {report['statistics']['total_steps']}</li>
            <li>Successful: {report['statistics']['successful']}</li>
            <li>Failed: {report['statistics']['failed']}</li>
            <li>Categories Covered: {report['statistics']['categories_covered']}/11</li>
        </ul>
        
        <h3 style="color: #8b949e;">Execution Steps</h3>
        <table style="width: 100%;">
        """
        
        for step in report['steps']:
            status_color = '#3fb950' if step['status'] == 'success' else '#f85149'
            html += f"""
            <tr>
                <td style="color: #58a6ff;">[{step['technique']}]</td>
                <td style="color: #e6e6e6;">{step['technique_name']}</td>
                <td style="color: {status_color};">{step['status'].upper()}</td>
            </tr>
            """
        
        html += "</table>"
        
        self.report_display.setHtml(html)
    
    def _emulate_adversary(self, profile_id: str):
        """Start adversary emulation"""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target in the Operations tab first")
            return
        
        try:
            chain = self.engine.create_apt_operation(profile_id, target)
            self.current_operation = chain
            self.execute_btn.setEnabled(True)
            self._refresh_operations_table()
            
            self.tabs.setCurrentIndex(0)  # Switch to operations tab
            self.status_label.setText(f"Adversary emulation '{chain.name}' ready")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
