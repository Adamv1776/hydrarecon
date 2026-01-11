"""
Attack Simulation Page - Automated penetration testing scenarios
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QFrame,
    QLineEdit, QComboBox, QTextEdit, QSpinBox, QProgressBar,
    QSplitter, QTreeWidget, QTreeWidgetItem, QGroupBox,
    QFormLayout, QCheckBox, QHeaderView, QMenu, QDialog,
    QDialogButtonBox, QMessageBox, QScrollArea, QListWidget,
    QListWidgetItem, QGridLayout
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from datetime import datetime
import json


class SimulationThread(QThread):
    """Background thread for running attack simulations"""
    progress = pyqtSignal(int, int, str, str)  # step, total, name, result
    status = pyqtSignal(str)
    completed = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, engine, scenario_id, safe_mode=True):
        super().__init__()
        self.engine = engine
        self.scenario_id = scenario_id
        self.safe_mode = safe_mode
    
    def run(self):
        import asyncio
        
        def callback(step, total, step_obj, result):
            self.progress.emit(step, total, step_obj.name, result.value)
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            report = loop.run_until_complete(
                self.engine.run_scenario(self.scenario_id, self.safe_mode, callback)
            )
            
            self.completed.emit({
                "success_rate": report.success_rate,
                "detection_rate": report.detection_rate,
                "total": report.total_techniques,
                "successful": report.successful_techniques,
                "blocked": report.blocked_techniques,
                "detected": report.detected_techniques,
                "critical": len(report.critical_findings),
                "high": len(report.high_findings),
                "summary": report.executive_summary,
                "recommendations": report.recommendations
            })
            
            loop.close()
        except Exception as e:
            self.error.emit(str(e))


class AttackSimulationPage(QWidget):
    """Attack Simulation management page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = None
        self.current_scenario_id = None
        self._init_engine()
        self._setup_ui()
    
    def _init_engine(self):
        """Initialize the attack simulation engine"""
        try:
            from core.attack_simulation import AttackSimulationEngine
            self.engine = AttackSimulationEngine()
        except ImportError:
            self.engine = None
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Header
        header = QLabel("Attack Simulation")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #f85149;")
        layout.addWidget(header)
        
        subtitle = QLabel("Automated penetration testing scenarios using MITRE ATT&CK framework")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        layout.addWidget(subtitle)
        
        # Warning banner
        warning = QFrame()
        warning.setStyleSheet("""
            QFrame {
                background: rgba(219, 109, 40, 0.15);
                border: 1px solid #db6d28;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        warning_layout = QHBoxLayout(warning)
        warning_icon = QLabel("⚠️")
        warning_icon.setFont(QFont("Segoe UI", 16))
        warning_layout.addWidget(warning_icon)
        warning_text = QLabel("Attack simulations should only be run in authorized test environments. Ensure proper authorization before executing any attack scenarios.")
        warning_text.setStyleSheet("color: #db6d28;")
        warning_text.setWordWrap(True)
        warning_layout.addWidget(warning_text)
        layout.addWidget(warning)
        
        # Tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                border-radius: 8px;
                background: #0d1117;
            }
            QTabBar::tab {
                background: #21262d;
                color: #8b949e;
                padding: 12px 24px;
                border: none;
                font-weight: 600;
            }
            QTabBar::tab:selected {
                background: #30363d;
                color: #f85149;
            }
        """)
        
        # Scenarios tab
        scenarios_tab = self._create_scenarios_tab()
        tabs.addTab(scenarios_tab, "🎯 Scenarios")
        
        # Create tab
        create_tab = self._create_scenario_builder_tab()
        tabs.addTab(create_tab, "🔧 Build Scenario")
        
        # Techniques tab
        techniques_tab = self._create_techniques_tab()
        tabs.addTab(techniques_tab, "📚 Techniques")
        
        # Results tab
        results_tab = self._create_results_tab()
        tabs.addTab(results_tab, "📊 Results")
        
        # Attack Paths tab
        paths_tab = self._create_attack_paths_tab()
        tabs.addTab(paths_tab, "🛤️ Attack Paths")
        
        layout.addWidget(tabs)
    
    def _create_scenarios_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Template gallery
        templates_group = QGroupBox("Scenario Templates")
        templates_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: 600;
                border: 1px solid #30363d;
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
        templates_layout = QGridLayout(templates_group)
        
        if self.engine:
            templates = self.engine.get_templates()
            for i, template in enumerate(templates):
                card = self._create_template_card(template)
                templates_layout.addWidget(card, i // 3, i % 3)
        
        layout.addWidget(templates_group)
        
        # Active scenarios
        active_group = QGroupBox("Active Scenarios")
        active_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: 600;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        active_layout = QVBoxLayout(active_group)
        
        self.scenarios_table = QTableWidget()
        self.scenarios_table.setColumnCount(6)
        self.scenarios_table.setHorizontalHeaderLabels([
            "Name", "Category", "Status", "Progress", "Severity", "Actions"
        ])
        self.scenarios_table.horizontalHeader().setStretchLastSection(True)
        self.scenarios_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 8px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        active_layout.addWidget(self.scenarios_table)
        
        layout.addWidget(active_group)
        
        return widget
    
    def _create_template_card(self, template):
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }
            QFrame:hover {
                border-color: #f85149;
            }
        """)
        layout = QVBoxLayout(card)
        
        # Icon and name
        header = QHBoxLayout()
        severity = template.get("severity", "medium")
        severity_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢"
        }
        icon = QLabel(severity_icons.get(severity.value if hasattr(severity, 'value') else severity, "🟡"))
        icon.setFont(QFont("Segoe UI", 20))
        header.addWidget(icon)
        header.addStretch()
        layout.addLayout(header)
        
        name = QLabel(template.get("name", "Unknown"))
        name.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        name.setStyleSheet("color: #c9d1d9;")
        name.setWordWrap(True)
        layout.addWidget(name)
        
        desc = QLabel(template.get("description", "")[:100] + "...")
        desc.setStyleSheet("color: #8b949e; font-size: 12px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # Tags
        tags = template.get("tags", [])
        if tags:
            tags_layout = QHBoxLayout()
            for tag in tags[:3]:
                tag_label = QLabel(tag)
                tag_label.setStyleSheet("""
                    background: #21262d;
                    color: #8b949e;
                    padding: 4px 8px;
                    border-radius: 10px;
                    font-size: 11px;
                """)
                tags_layout.addWidget(tag_label)
            tags_layout.addStretch()
            layout.addLayout(tags_layout)
        
        # Use button
        use_btn = QPushButton("Use Template")
        use_btn.setStyleSheet("""
            QPushButton {
                background: #f85149;
                border: none;
                border-radius: 6px;
                color: white;
                padding: 8px 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #da3633;
            }
        """)
        template_id = template.get("id", "")
        use_btn.clicked.connect(lambda: self._use_template(template_id))
        layout.addWidget(use_btn)
        
        return card
    
    def _create_scenario_builder_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Scenario details
        details_frame = QFrame()
        details_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        details_layout = QFormLayout(details_frame)
        details_layout.setSpacing(12)
        
        self.scenario_name = QLineEdit()
        self.scenario_name.setPlaceholderText("Enter scenario name...")
        self.scenario_name.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
            }
        """)
        details_layout.addRow("Scenario Name:", self.scenario_name)
        
        self.scenario_desc = QTextEdit()
        self.scenario_desc.setPlaceholderText("Describe the attack scenario...")
        self.scenario_desc.setMaximumHeight(80)
        self.scenario_desc.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #c9d1d9;
            }
        """)
        details_layout.addRow("Description:", self.scenario_desc)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.0/24 or target.example.com")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
            }
        """)
        details_layout.addRow("Target:", self.target_input)
        
        self.category_combo = QComboBox()
        self.category_combo.addItems([
            "reconnaissance", "initial_access", "execution", "persistence",
            "privilege_escalation", "defense_evasion", "credential_access",
            "discovery", "lateral_movement", "collection", "exfiltration", "impact"
        ])
        self.category_combo.setStyleSheet("""
            QComboBox {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c9d1d9;
            }
        """)
        details_layout.addRow("Category:", self.category_combo)
        
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["critical", "high", "medium", "low", "info"])
        self.severity_combo.setCurrentText("medium")
        self.severity_combo.setStyleSheet("""
            QComboBox {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c9d1d9;
            }
        """)
        details_layout.addRow("Severity:", self.severity_combo)
        
        layout.addWidget(details_frame)
        
        # Technique selection
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Available techniques
        available_frame = QFrame()
        available_frame.setStyleSheet("""
            QFrame {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        available_layout = QVBoxLayout(available_frame)
        
        available_header = QLabel("Available Techniques")
        available_header.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        available_header.setStyleSheet("color: #c9d1d9; padding: 8px;")
        available_layout.addWidget(available_header)
        
        # Filter by tactic
        tactic_filter = QComboBox()
        tactic_filter.addItem("All Tactics", None)
        tactic_filter.addItems([
            "reconnaissance", "initial_access", "execution", "persistence",
            "privilege_escalation", "credential_access", "lateral_movement", "exfiltration"
        ])
        tactic_filter.setStyleSheet("""
            QComboBox {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px;
                color: #c9d1d9;
                margin: 4px;
            }
        """)
        tactic_filter.currentIndexChanged.connect(self._filter_techniques)
        available_layout.addWidget(tactic_filter)
        self.tactic_filter = tactic_filter
        
        self.available_techniques = QListWidget()
        self.available_techniques.setStyleSheet("""
            QListWidget {
                background: transparent;
                border: none;
                color: #c9d1d9;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListWidget::item:hover {
                background: #21262d;
            }
            QListWidget::item:selected {
                background: #388bfd;
            }
        """)
        self._populate_techniques()
        available_layout.addWidget(self.available_techniques)
        
        splitter.addWidget(available_frame)
        
        # Add/Remove buttons
        button_frame = QFrame()
        button_frame.setMaximumWidth(60)
        button_layout = QVBoxLayout(button_frame)
        button_layout.addStretch()
        
        add_btn = QPushButton("▶")
        add_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                border-radius: 4px;
                color: white;
                padding: 8px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        add_btn.clicked.connect(self._add_technique)
        button_layout.addWidget(add_btn)
        
        remove_btn = QPushButton("◀")
        remove_btn.setStyleSheet("""
            QPushButton {
                background: #da3633;
                border: none;
                border-radius: 4px;
                color: white;
                padding: 8px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #f85149;
            }
        """)
        remove_btn.clicked.connect(self._remove_technique)
        button_layout.addWidget(remove_btn)
        
        button_layout.addStretch()
        splitter.addWidget(button_frame)
        
        # Selected techniques
        selected_frame = QFrame()
        selected_frame.setStyleSheet("""
            QFrame {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        selected_layout = QVBoxLayout(selected_frame)
        
        selected_header = QLabel("Selected Techniques (Attack Chain)")
        selected_header.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        selected_header.setStyleSheet("color: #c9d1d9; padding: 8px;")
        selected_layout.addWidget(selected_header)
        
        self.selected_techniques = QListWidget()
        self.selected_techniques.setStyleSheet("""
            QListWidget {
                background: transparent;
                border: none;
                color: #c9d1d9;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListWidget::item:hover {
                background: #21262d;
            }
            QListWidget::item:selected {
                background: #f85149;
            }
        """)
        selected_layout.addWidget(self.selected_techniques)
        
        splitter.addWidget(selected_frame)
        
        layout.addWidget(splitter)
        
        # Action buttons
        actions = QHBoxLayout()
        actions.addStretch()
        
        self.safe_mode_check = QCheckBox("Safe Mode (Simulation Only)")
        self.safe_mode_check.setChecked(True)
        self.safe_mode_check.setStyleSheet("color: #c9d1d9;")
        actions.addWidget(self.safe_mode_check)
        
        create_btn = QPushButton("📝 Create Scenario")
        create_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
                padding: 12px 24px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #30363d;
            }
        """)
        create_btn.clicked.connect(self._create_scenario)
        actions.addWidget(create_btn)
        
        run_btn = QPushButton("🚀 Create & Run")
        run_btn.setStyleSheet("""
            QPushButton {
                background: #f85149;
                border: none;
                border-radius: 6px;
                color: white;
                padding: 12px 24px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #da3633;
            }
        """)
        run_btn.clicked.connect(self._create_and_run)
        actions.addWidget(run_btn)
        
        layout.addLayout(actions)
        
        return widget
    
    def _create_techniques_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Techniques table
        self.techniques_table = QTableWidget()
        self.techniques_table.setColumnCount(5)
        self.techniques_table.setHorizontalHeaderLabels([
            "ID", "Name", "Tactic", "Platforms", "Detection"
        ])
        self.techniques_table.horizontalHeader().setStretchLastSection(True)
        self.techniques_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 10px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 12px;
                border: none;
                font-weight: 600;
            }
        """)
        
        if self.engine:
            techniques = self.engine.get_techniques()
            for tech in techniques:
                row = self.techniques_table.rowCount()
                self.techniques_table.insertRow(row)
                
                id_item = QTableWidgetItem(tech.id)
                id_item.setForeground(QColor("#58a6ff"))
                self.techniques_table.setItem(row, 0, id_item)
                
                self.techniques_table.setItem(row, 1, QTableWidgetItem(tech.name))
                
                tactic_item = QTableWidgetItem(tech.tactic.value)
                tactic_colors = {
                    "reconnaissance": "#8b949e",
                    "initial_access": "#a371f7",
                    "execution": "#f85149",
                    "persistence": "#db6d28",
                    "privilege_escalation": "#d29922",
                    "credential_access": "#f85149",
                    "lateral_movement": "#58a6ff",
                    "exfiltration": "#da3633"
                }
                tactic_item.setForeground(QColor(tactic_colors.get(tech.tactic.value, "#c9d1d9")))
                self.techniques_table.setItem(row, 2, tactic_item)
                
                self.techniques_table.setItem(row, 3, QTableWidgetItem(", ".join(tech.platforms)))
                self.techniques_table.setItem(row, 4, QTableWidgetItem(tech.detection[:50] + "..." if len(tech.detection) > 50 else tech.detection))
        
        layout.addWidget(self.techniques_table)
        
        return widget
    
    def _create_results_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Execution controls
        control_frame = QFrame()
        control_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        control_layout = QVBoxLayout(control_frame)
        
        # Scenario selector
        selector_layout = QHBoxLayout()
        
        selector_label = QLabel("Select Scenario:")
        selector_label.setStyleSheet("color: #c9d1d9; font-weight: 600;")
        selector_layout.addWidget(selector_label)
        
        self.scenario_selector = QComboBox()
        self.scenario_selector.setMinimumWidth(300)
        self.scenario_selector.setStyleSheet("""
            QComboBox {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c9d1d9;
            }
        """)
        selector_layout.addWidget(self.scenario_selector)
        
        selector_layout.addStretch()
        
        self.run_btn = QPushButton("▶️ Run Simulation")
        self.run_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                border-radius: 6px;
                color: white;
                padding: 10px 20px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #2ea043;
            }
            QPushButton:disabled {
                background: #21262d;
                color: #484f58;
            }
        """)
        self.run_btn.clicked.connect(self._run_selected_scenario)
        selector_layout.addWidget(self.run_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background: #da3633;
                border: none;
                border-radius: 6px;
                color: white;
                padding: 10px 20px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #f85149;
            }
            QPushButton:disabled {
                background: #21262d;
                color: #484f58;
            }
        """)
        self.stop_btn.clicked.connect(self._stop_simulation)
        selector_layout.addWidget(self.stop_btn)
        
        control_layout.addLayout(selector_layout)
        
        # Progress
        self.sim_progress = QProgressBar()
        self.sim_progress.setStyleSheet("""
            QProgressBar {
                background: #21262d;
                border: none;
                border-radius: 6px;
                height: 12px;
            }
            QProgressBar::chunk {
                background: #f85149;
                border-radius: 6px;
            }
        """)
        self.sim_progress.setVisible(False)
        control_layout.addWidget(self.sim_progress)
        
        self.sim_status = QLabel("")
        self.sim_status.setStyleSheet("color: #8b949e;")
        control_layout.addWidget(self.sim_status)
        
        layout.addWidget(control_frame)
        
        # Results display
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Steps log
        log_frame = QFrame()
        log_frame.setStyleSheet("""
            QFrame {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        log_layout = QVBoxLayout(log_frame)
        
        log_header = QLabel("Execution Log")
        log_header.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        log_header.setStyleSheet("color: #c9d1d9; padding: 8px;")
        log_layout.addWidget(log_header)
        
        self.execution_log = QTextEdit()
        self.execution_log.setReadOnly(True)
        self.execution_log.setStyleSheet("""
            QTextEdit {
                background: transparent;
                border: none;
                color: #c9d1d9;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
            }
        """)
        log_layout.addWidget(self.execution_log)
        
        splitter.addWidget(log_frame)
        
        # Summary
        summary_frame = QFrame()
        summary_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        summary_layout = QVBoxLayout(summary_frame)
        
        summary_header = QLabel("Results Summary")
        summary_header.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        summary_header.setStyleSheet("color: #c9d1d9; padding: 8px;")
        summary_layout.addWidget(summary_header)
        
        # Metrics
        metrics_layout = QGridLayout()
        
        self.total_label = self._create_metric_label("Total", "0", "#58a6ff")
        metrics_layout.addWidget(self.total_label, 0, 0)
        
        self.success_label = self._create_metric_label("Successful", "0", "#3fb950")
        metrics_layout.addWidget(self.success_label, 0, 1)
        
        self.blocked_label = self._create_metric_label("Blocked", "0", "#d29922")
        metrics_layout.addWidget(self.blocked_label, 1, 0)
        
        self.detected_label = self._create_metric_label("Detected", "0", "#a371f7")
        metrics_layout.addWidget(self.detected_label, 1, 1)
        
        summary_layout.addLayout(metrics_layout)
        
        # Findings
        findings_header = QLabel("Findings")
        findings_header.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        findings_header.setStyleSheet("color: #c9d1d9; padding: 8px;")
        summary_layout.addWidget(findings_header)
        
        self.findings_text = QTextEdit()
        self.findings_text.setReadOnly(True)
        self.findings_text.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
                padding: 8px;
            }
        """)
        summary_layout.addWidget(self.findings_text)
        
        # Export button
        export_btn = QPushButton("📤 Export Report")
        export_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
                padding: 10px 20px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #30363d;
            }
        """)
        export_btn.clicked.connect(self._export_report)
        summary_layout.addWidget(export_btn)
        
        splitter.addWidget(summary_frame)
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_attack_paths_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target input
        target_frame = QFrame()
        target_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        target_layout = QHBoxLayout(target_frame)
        
        target_label = QLabel("Target:")
        target_label.setStyleSheet("color: #c9d1d9; font-weight: 600;")
        target_layout.addWidget(target_label)
        
        self.path_target = QLineEdit()
        self.path_target.setPlaceholderText("Enter target IP or hostname...")
        self.path_target.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
            }
        """)
        target_layout.addWidget(self.path_target)
        
        analyze_btn = QPushButton("🔍 Analyze Attack Paths")
        analyze_btn.setStyleSheet("""
            QPushButton {
                background: #f85149;
                border: none;
                border-radius: 6px;
                color: white;
                padding: 10px 20px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #da3633;
            }
        """)
        analyze_btn.clicked.connect(self._analyze_paths)
        target_layout.addWidget(analyze_btn)
        
        layout.addWidget(target_frame)
        
        # Attack paths display
        self.paths_list = QListWidget()
        self.paths_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #c9d1d9;
            }
            QListWidget::item {
                padding: 16px;
                border-bottom: 1px solid #21262d;
            }
            QListWidget::item:hover {
                background: #161b22;
            }
            QListWidget::item:selected {
                background: #21262d;
            }
        """)
        layout.addWidget(self.paths_list)
        
        return widget
    
    def _create_metric_label(self, title, value, color):
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        layout = QVBoxLayout(frame)
        
        value_label = QLabel(value)
        value_label.setObjectName("value")
        value_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value_label)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #8b949e;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        return frame
    
    def _populate_techniques(self):
        """Populate available techniques list"""
        self.available_techniques.clear()
        
        if not self.engine:
            return
        
        techniques = self.engine.get_techniques()
        for tech in techniques:
            item = QListWidgetItem(f"[{tech.id}] {tech.name}")
            item.setData(Qt.ItemDataRole.UserRole, tech.id)
            self.available_techniques.addItem(item)
    
    def _filter_techniques(self):
        """Filter techniques by tactic"""
        if not self.engine:
            return
        
        tactic_text = self.tactic_filter.currentText()
        self.available_techniques.clear()
        
        if tactic_text == "All Tactics":
            techniques = self.engine.get_techniques()
        else:
            from core.attack_simulation import AttackCategory
            try:
                tactic = AttackCategory(tactic_text)
                techniques = self.engine.get_techniques(tactic)
            except Exception:
                techniques = self.engine.get_techniques()
        
        for tech in techniques:
            item = QListWidgetItem(f"[{tech.id}] {tech.name}")
            item.setData(Qt.ItemDataRole.UserRole, tech.id)
            self.available_techniques.addItem(item)
    
    def _add_technique(self):
        """Add technique to selected list"""
        current = self.available_techniques.currentItem()
        if current:
            # Check if already added
            for i in range(self.selected_techniques.count()):
                if self.selected_techniques.item(i).data(Qt.ItemDataRole.UserRole) == current.data(Qt.ItemDataRole.UserRole):
                    return
            
            item = QListWidgetItem(current.text())
            item.setData(Qt.ItemDataRole.UserRole, current.data(Qt.ItemDataRole.UserRole))
            self.selected_techniques.addItem(item)
    
    def _remove_technique(self):
        """Remove technique from selected list"""
        current = self.selected_techniques.currentRow()
        if current >= 0:
            self.selected_techniques.takeItem(current)
    
    def _use_template(self, template_id):
        """Use a scenario template"""
        if not self.engine:
            return
        
        template = self.engine.library.get_scenario_template(template_id)
        if template:
            self.scenario_name.setText(template.get("name", ""))
            self.scenario_desc.setText(template.get("description", ""))
            
            # Add techniques
            self.selected_techniques.clear()
            for tech_id in template.get("techniques", []):
                tech = self.engine.library.get_technique(tech_id)
                if tech:
                    item = QListWidgetItem(f"[{tech.id}] {tech.name}")
                    item.setData(Qt.ItemDataRole.UserRole, tech.id)
                    self.selected_techniques.addItem(item)
            
            QMessageBox.information(self, "Template Loaded", f"Template '{template.get('name')}' loaded. Review and customize as needed.")
    
    def _create_scenario(self):
        """Create scenario from builder"""
        if not self.engine:
            QMessageBox.warning(self, "Error", "Attack simulation engine not available")
            return
        
        name = self.scenario_name.text().strip()
        if not name:
            QMessageBox.warning(self, "Error", "Please enter a scenario name")
            return
        
        # Collect techniques
        techniques = []
        for i in range(self.selected_techniques.count()):
            tech_id = self.selected_techniques.item(i).data(Qt.ItemDataRole.UserRole)
            techniques.append(tech_id)
        
        if not techniques:
            QMessageBox.warning(self, "Error", "Please select at least one technique")
            return
        
        # Get targets
        targets = [t.strip() for t in self.target_input.text().split(",") if t.strip()]
        
        # Create scenario
        from core.attack_simulation import AttackCategory, Severity
        
        try:
            category = AttackCategory(self.category_combo.currentText())
        except Exception:
            category = AttackCategory.EXECUTION
        
        try:
            severity = Severity(self.severity_combo.currentText())
        except Exception:
            severity = Severity.MEDIUM
        
        scenario = self.engine.create_scenario(
            name=name,
            description=self.scenario_desc.toPlainText(),
            targets=targets,
            techniques=techniques,
            category=category,
            severity=severity
        )
        
        self.current_scenario_id = scenario.id
        self._update_scenario_selector()
        
        QMessageBox.information(self, "Scenario Created", f"Scenario '{name}' created with {len(techniques)} techniques")
    
    def _create_and_run(self):
        """Create and immediately run scenario"""
        self._create_scenario()
        if self.current_scenario_id:
            self._run_simulation(self.current_scenario_id)
    
    def _update_scenario_selector(self):
        """Update scenario selector dropdown"""
        self.scenario_selector.clear()
        
        if not self.engine:
            return
        
        for scenario in self.engine.list_scenarios():
            self.scenario_selector.addItem(scenario.name, scenario.id)
    
    def _run_selected_scenario(self):
        """Run the currently selected scenario"""
        scenario_id = self.scenario_selector.currentData()
        if scenario_id:
            self._run_simulation(scenario_id)
    
    def _run_simulation(self, scenario_id):
        """Run attack simulation"""
        if not self.engine:
            return
        
        scenario = self.engine.get_scenario(scenario_id)
        if not scenario:
            QMessageBox.warning(self, "Error", "Scenario not found")
            return
        
        # Confirm execution
        reply = QMessageBox.warning(
            self, "Confirm Simulation",
            f"You are about to run attack simulation '{scenario.name}'.\n\n"
            f"Techniques: {len(scenario.steps)}\n"
            f"Safe Mode: {'Yes' if self.safe_mode_check.isChecked() else 'NO - REAL EXECUTION'}\n\n"
            "Do you want to continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Start simulation thread
        self.sim_thread = SimulationThread(
            self.engine, 
            scenario_id,
            self.safe_mode_check.isChecked()
        )
        self.sim_thread.progress.connect(self._on_sim_progress)
        self.sim_thread.completed.connect(self._on_sim_complete)
        self.sim_thread.error.connect(self._on_sim_error)
        
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.sim_progress.setVisible(True)
        self.sim_progress.setValue(0)
        
        self.execution_log.clear()
        self._log(f"Starting simulation: {scenario.name}")
        self._log(f"Safe mode: {self.safe_mode_check.isChecked()}")
        self._log("-" * 50)
        
        self.sim_thread.start()
    
    def _stop_simulation(self):
        """Stop running simulation"""
        if self.current_scenario_id and self.engine:
            self.engine.cancel_scenario(self.current_scenario_id)
            self._log("\n⏹️ Simulation cancelled by user")
    
    def _on_sim_progress(self, step, total, name, result):
        """Handle simulation progress"""
        progress = int((step / total) * 100)
        self.sim_progress.setValue(progress)
        self.sim_status.setText(f"Step {step}/{total}: {name}")
        
        result_icons = {
            "success": "✅",
            "partial": "⚡",
            "blocked": "🛡️",
            "detected": "👁️",
            "failed": "❌",
            "skipped": "⏭️"
        }
        icon = result_icons.get(result, "❓")
        self._log(f"[{step}/{total}] {icon} {name}: {result.upper()}")
    
    def _on_sim_complete(self, result):
        """Handle simulation completion"""
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.sim_progress.setVisible(False)
        self.sim_status.setText("Simulation completed")
        
        self._log("\n" + "=" * 50)
        self._log("SIMULATION COMPLETE")
        self._log("=" * 50)
        
        # Update metrics
        self.total_label.findChild(QLabel, "value").setText(str(result["total"]))
        self.success_label.findChild(QLabel, "value").setText(str(result["successful"]))
        self.blocked_label.findChild(QLabel, "value").setText(str(result["blocked"]))
        self.detected_label.findChild(QLabel, "value").setText(str(result["detected"]))
        
        # Update findings
        findings_text = f"Critical: {result['critical']}\nHigh: {result['high']}\n\n"
        findings_text += "Recommendations:\n"
        for rec in result.get("recommendations", []):
            findings_text += f"• {rec}\n"
        
        self.findings_text.setText(findings_text)
        
        # Log summary
        self._log(f"\nSuccess Rate: {result['success_rate']*100:.1f}%")
        self._log(f"Detection Rate: {result['detection_rate']*100:.1f}%")
    
    def _on_sim_error(self, error):
        """Handle simulation error"""
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.sim_progress.setVisible(False)
        self.sim_status.setText(f"Error: {error}")
        
        self._log(f"\n❌ ERROR: {error}")
    
    def _log(self, message):
        """Add message to execution log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.execution_log.append(f"[{timestamp}] {message}")
    
    def _analyze_paths(self):
        """Analyze attack paths for target"""
        if not self.engine:
            return
        
        target = self.path_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return
        
        paths = self.engine.analyze_attack_paths(target)
        
        self.paths_list.clear()
        for path in paths:
            text = f"🛤️ {path.name}\n"
            text += f"   {path.description}\n"
            text += f"   Steps: {len(path.steps)} | "
            text += f"Success Probability: {path.success_probability*100:.0f}% | "
            text += f"Risk Score: {path.risk_score:.1f}\n"
            text += "   Chain: " + " → ".join([s.technique.name if s.technique else "?" for s in path.steps[:5]])
            
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, path.id)
            
            if path.risk_score >= 8:
                item.setForeground(QColor("#f85149"))
            elif path.risk_score >= 6:
                item.setForeground(QColor("#d29922"))
            else:
                item.setForeground(QColor("#c9d1d9"))
            
            self.paths_list.addItem(item)
    
    def _export_report(self):
        """Export simulation report"""
        if not self.current_scenario_id or not self.engine:
            QMessageBox.warning(self, "Error", "No simulation results to export")
            return
        
        from PyQt6.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", "attack_simulation_report.json",
            "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                scenario = self.engine.get_scenario(self.current_scenario_id)
                if scenario:
                    report = self.engine._generate_report(scenario)
                    data = self.engine.export_report(report)
                    
                    with open(file_path, 'w') as f:
                        f.write(data)
                    
                    QMessageBox.information(self, "Export Complete", f"Report exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))
