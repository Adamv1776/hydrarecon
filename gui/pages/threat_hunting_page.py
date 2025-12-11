"""
Threat Hunting Page - GUI for proactive threat detection and hunting
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit,
    QGroupBox, QFormLayout, QLineEdit, QComboBox, QCheckBox,
    QProgressBar, QSplitter, QHeaderView, QTreeWidget,
    QTreeWidgetItem, QMessageBox, QFileDialog, QListWidget,
    QListWidgetItem, QSpinBox, QPlainTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor
from datetime import datetime
from typing import Optional, List
import json


class HuntWorker(QThread):
    """Background worker for threat hunting"""
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    log = pyqtSignal(str, str)
    
    def __init__(self, platform, hunt_type: str, params: dict):
        super().__init__()
        self.platform = platform
        self.hunt_type = hunt_type
        self.params = params
    
    def run(self):
        try:
            import asyncio
            
            self.platform.progress_callback = lambda p, s: self.progress.emit(p, s)
            self.platform.log_callback = lambda m, l: self.log.emit(m, l)
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            if self.hunt_type == "ioc_sweep":
                from core.threat_hunting import IOC
                iocs = [IOC(ioc_type=i["type"], value=i["value"], description=i.get("desc", ""))
                       for i in self.params.get("iocs", [])]
                result = loop.run_until_complete(self.platform.run_ioc_sweep(iocs))
            elif self.hunt_type == "behavioral":
                result = loop.run_until_complete(self.platform.run_behavioral_hunt(
                    self.params.get("patterns"),
                    self.params.get("timeframe", 24)
                ))
            elif self.hunt_type == "sigma":
                result = loop.run_until_complete(self.platform.run_sigma_hunt(
                    self.params.get("rules")
                ))
            elif self.hunt_type == "anomaly":
                result = loop.run_until_complete(self.platform.run_anomaly_detection())
            else:
                result = []
            
            loop.close()
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class ThreatHuntingPage(QWidget):
    """Threat Hunting Platform GUI Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.platform = None
        self.current_findings = []
        self.hunt_worker = None
        self._init_platform()
        self._init_ui()
    
    def _init_platform(self):
        """Initialize the threat hunting platform"""
        try:
            from core.threat_hunting import ThreatHuntingPlatform
            self.platform = ThreatHuntingPlatform()
        except ImportError as e:
            print(f"Could not import threat hunting platform: {e}")
    
    def _init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("🎯 Threat Hunting Platform")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #ff8800;")
        layout.addWidget(header)
        
        subtitle = QLabel("Proactive threat detection with IOC sweeps, SIGMA rules, and behavioral analytics")
        subtitle.setStyleSheet("color: #888; font-size: 12px; margin-bottom: 10px;")
        layout.addWidget(subtitle)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Hunt controls
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)
        
        # Hunt type selection
        hunt_group = QGroupBox("🔍 Hunt Type")
        hunt_layout = QVBoxLayout(hunt_group)
        
        self.hunt_type_combo = QComboBox()
        self.hunt_type_combo.addItems([
            "IOC Sweep",
            "Behavioral Hunt",
            "SIGMA Rule Hunt",
            "Anomaly Detection"
        ])
        self.hunt_type_combo.setStyleSheet("""
            QComboBox {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background: #1a1a2e;
                border: 1px solid #333;
                selection-background-color: #ff8800;
            }
        """)
        self.hunt_type_combo.currentIndexChanged.connect(self._on_hunt_type_changed)
        hunt_layout.addWidget(self.hunt_type_combo)
        
        left_layout.addWidget(hunt_group)
        
        # IOC input panel
        self.ioc_panel = QGroupBox("📝 IOC Input")
        ioc_layout = QVBoxLayout(self.ioc_panel)
        
        ioc_type_row = QHBoxLayout()
        self.ioc_type_combo = QComboBox()
        self.ioc_type_combo.addItems(["ip", "domain", "hash", "file", "url", "registry"])
        self.ioc_type_combo.setStyleSheet("""
            QComboBox {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 5px;
                color: white;
            }
        """)
        ioc_type_row.addWidget(QLabel("Type:"))
        ioc_type_row.addWidget(self.ioc_type_combo)
        ioc_layout.addLayout(ioc_type_row)
        
        self.ioc_value_input = QLineEdit()
        self.ioc_value_input.setPlaceholderText("Enter IOC value...")
        self.ioc_value_input.setStyleSheet("""
            QLineEdit {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
        """)
        ioc_layout.addWidget(self.ioc_value_input)
        
        add_ioc_btn = QPushButton("➕ Add IOC")
        add_ioc_btn.setStyleSheet("""
            QPushButton {
                background: #ff8800;
                color: black;
                border: none;
                border-radius: 5px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #cc6600;
            }
        """)
        add_ioc_btn.clicked.connect(self._add_ioc)
        ioc_layout.addWidget(add_ioc_btn)
        
        self.ioc_list = QListWidget()
        self.ioc_list.setMaximumHeight(150)
        self.ioc_list.setStyleSheet("""
            QListWidget {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                color: white;
            }
            QListWidget::item {
                padding: 5px;
            }
            QListWidget::item:selected {
                background: #ff8800;
                color: black;
            }
        """)
        ioc_layout.addWidget(self.ioc_list)
        
        import_ioc_btn = QPushButton("📂 Import from File")
        import_ioc_btn.setStyleSheet("""
            QPushButton {
                background: #16213e;
                color: #ff8800;
                border: 1px solid #ff8800;
                border-radius: 5px;
                padding: 8px;
            }
            QPushButton:hover {
                background: #ff8800;
                color: black;
            }
        """)
        import_ioc_btn.clicked.connect(self._import_iocs)
        ioc_layout.addWidget(import_ioc_btn)
        
        left_layout.addWidget(self.ioc_panel)
        
        # Behavioral options panel
        self.behavioral_panel = QGroupBox("🧠 Behavioral Options")
        behavioral_layout = QVBoxLayout(self.behavioral_panel)
        
        tf_row = QHBoxLayout()
        tf_row.addWidget(QLabel("Timeframe (hours):"))
        self.timeframe_spin = QSpinBox()
        self.timeframe_spin.setRange(1, 168)
        self.timeframe_spin.setValue(24)
        self.timeframe_spin.setStyleSheet("""
            QSpinBox {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 5px;
                color: white;
            }
        """)
        tf_row.addWidget(self.timeframe_spin)
        behavioral_layout.addLayout(tf_row)
        
        behavioral_layout.addWidget(QLabel("Select Patterns:"))
        self.pattern_list = QListWidget()
        self.pattern_list.setMaximumHeight(120)
        self.pattern_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.pattern_list.setStyleSheet("""
            QListWidget {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                color: white;
            }
            QListWidget::item:selected {
                background: #ff8800;
                color: black;
            }
        """)
        behavioral_layout.addWidget(self.pattern_list)
        
        self.behavioral_panel.hide()
        left_layout.addWidget(self.behavioral_panel)
        
        # SIGMA options panel
        self.sigma_panel = QGroupBox("📜 SIGMA Rules")
        sigma_layout = QVBoxLayout(self.sigma_panel)
        
        sigma_layout.addWidget(QLabel("Select Rules:"))
        self.sigma_list = QListWidget()
        self.sigma_list.setMaximumHeight(150)
        self.sigma_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.sigma_list.setStyleSheet("""
            QListWidget {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                color: white;
            }
            QListWidget::item:selected {
                background: #ff8800;
                color: black;
            }
        """)
        sigma_layout.addWidget(self.sigma_list)
        
        self.sigma_panel.hide()
        left_layout.addWidget(self.sigma_panel)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.hunt_btn = QPushButton("🎯 Start Hunt")
        self.hunt_btn.setStyleSheet("""
            QPushButton {
                background: #ff8800;
                color: black;
                border: none;
                border-radius: 5px;
                padding: 12px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #cc6600;
            }
            QPushButton:disabled {
                background: #555;
                color: #888;
            }
        """)
        self.hunt_btn.clicked.connect(self._start_hunt)
        btn_layout.addWidget(self.hunt_btn)
        
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background: #ff4444;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #cc3333;
            }
            QPushButton:disabled {
                background: #555;
                color: #888;
            }
        """)
        self.stop_btn.clicked.connect(self._stop_hunt)
        btn_layout.addWidget(self.stop_btn)
        
        left_layout.addLayout(btn_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 5px;
                height: 25px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff8800, stop:1 #ffaa00);
                border-radius: 4px;
            }
        """)
        left_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888;")
        left_layout.addWidget(self.status_label)
        
        # Quick stats
        stats_group = QGroupBox("📊 Hunt Statistics")
        stats_layout = QFormLayout(stats_group)
        
        self.stat_findings = QLabel("-")
        self.stat_findings.setStyleSheet("color: #ff8800; font-weight: bold;")
        stats_layout.addRow("Findings:", self.stat_findings)
        
        self.stat_critical = QLabel("-")
        self.stat_critical.setStyleSheet("color: #ff0000;")
        stats_layout.addRow("Critical:", self.stat_critical)
        
        self.stat_high = QLabel("-")
        self.stat_high.setStyleSheet("color: #ff4500;")
        stats_layout.addRow("High:", self.stat_high)
        
        self.stat_medium = QLabel("-")
        self.stat_medium.setStyleSheet("color: #ffa500;")
        stats_layout.addRow("Medium:", self.stat_medium)
        
        left_layout.addWidget(stats_group)
        
        left_layout.addStretch()
        
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(10, 0, 0, 0)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #333;
                background: #16213e;
                border-radius: 5px;
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #888;
                padding: 8px 15px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background: #16213e;
                color: #ff8800;
            }
        """)
        
        # Findings tab
        findings_tab = QWidget()
        findings_layout = QVBoxLayout(findings_tab)
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(6)
        self.findings_table.setHorizontalHeaderLabels([
            "Time", "Severity", "Category", "Title", "MITRE ATT&CK", "Assets"
        ])
        self.findings_table.horizontalHeader().setStretchLastSection(True)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.setStyleSheet("""
            QTableWidget {
                background: #1a1a2e;
                border: none;
                gridline-color: #333;
            }
            QTableWidget::item {
                padding: 8px;
                color: white;
            }
            QTableWidget::item:selected {
                background: #ff8800;
                color: black;
            }
            QHeaderView::section {
                background: #16213e;
                color: #ff8800;
                padding: 8px;
                border: none;
            }
        """)
        self.findings_table.itemSelectionChanged.connect(self._on_finding_selected)
        findings_layout.addWidget(self.findings_table)
        
        self.results_tabs.addTab(findings_tab, "🎯 Findings")
        
        # Finding details tab
        details_tab = QWidget()
        details_layout = QVBoxLayout(details_tab)
        
        self.finding_details = QTextEdit()
        self.finding_details.setReadOnly(True)
        self.finding_details.setStyleSheet("""
            QTextEdit {
                background: #1a1a2e;
                border: none;
                color: white;
                font-family: 'Consolas', 'Monaco', monospace;
            }
        """)
        details_layout.addWidget(self.finding_details)
        
        self.results_tabs.addTab(details_tab, "📋 Details")
        
        # Hypotheses tab
        hypotheses_tab = QWidget()
        hypotheses_layout = QVBoxLayout(hypotheses_tab)
        
        self.hypotheses_tree = QTreeWidget()
        self.hypotheses_tree.setHeaderLabels(["Hypothesis", "Category", "MITRE", "Data Sources"])
        self.hypotheses_tree.setStyleSheet("""
            QTreeWidget {
                background: #1a1a2e;
                border: none;
                color: white;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QTreeWidget::item:selected {
                background: #ff8800;
                color: black;
            }
            QHeaderView::section {
                background: #16213e;
                color: #ff8800;
                padding: 8px;
                border: none;
            }
        """)
        hypotheses_layout.addWidget(self.hypotheses_tree)
        
        self.results_tabs.addTab(hypotheses_tab, "💡 Hypotheses")
        
        # IOCs tab
        iocs_tab = QWidget()
        iocs_layout = QVBoxLayout(iocs_tab)
        
        self.iocs_table = QTableWidget()
        self.iocs_table.setColumnCount(5)
        self.iocs_table.setHorizontalHeaderLabels(["Type", "Value", "Source", "Confidence", "Tags"])
        self.iocs_table.horizontalHeader().setStretchLastSection(True)
        self.iocs_table.setStyleSheet("""
            QTableWidget {
                background: #1a1a2e;
                border: none;
                gridline-color: #333;
            }
            QTableWidget::item {
                padding: 8px;
                color: white;
            }
            QHeaderView::section {
                background: #16213e;
                color: #ff8800;
                padding: 8px;
                border: none;
            }
        """)
        iocs_layout.addWidget(self.iocs_table)
        
        self.results_tabs.addTab(iocs_tab, "🔍 IOCs")
        
        # Log tab
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("""
            QTextEdit {
                background: #0f0f1a;
                border: none;
                color: #ff8800;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
            }
        """)
        log_layout.addWidget(self.log_output)
        
        self.results_tabs.addTab(log_tab, "📜 Log")
        
        right_layout.addWidget(self.results_tabs)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        export_json_btn = QPushButton("📄 Export JSON")
        export_json_btn.setStyleSheet("""
            QPushButton {
                background: #16213e;
                color: #ff8800;
                border: 1px solid #ff8800;
                border-radius: 5px;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background: #ff8800;
                color: black;
            }
        """)
        export_json_btn.clicked.connect(lambda: self._export_findings("json"))
        export_layout.addWidget(export_json_btn)
        
        export_ioc_btn = QPushButton("🔍 Export IOCs")
        export_ioc_btn.setStyleSheet("""
            QPushButton {
                background: #16213e;
                color: #00d4ff;
                border: 1px solid #00d4ff;
                border-radius: 5px;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background: #00d4ff;
                color: black;
            }
        """)
        export_ioc_btn.clicked.connect(self._export_iocs)
        export_layout.addWidget(export_ioc_btn)
        
        right_layout.addLayout(export_layout)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([350, 700])
        
        layout.addWidget(splitter)
        
        # Load data
        self._load_hypotheses()
        self._load_patterns()
        self._load_sigma_rules()
    
    def _on_hunt_type_changed(self, index: int):
        """Handle hunt type change"""
        self.ioc_panel.hide()
        self.behavioral_panel.hide()
        self.sigma_panel.hide()
        
        if index == 0:  # IOC Sweep
            self.ioc_panel.show()
        elif index == 1:  # Behavioral
            self.behavioral_panel.show()
        elif index == 2:  # SIGMA
            self.sigma_panel.show()
        # Anomaly detection has no extra options
    
    def _load_hypotheses(self):
        """Load hunting hypotheses into tree"""
        if not self.platform:
            return
        
        for h in self.platform.get_hypotheses():
            item = QTreeWidgetItem([
                h.name,
                h.category.value,
                ", ".join(h.mitre_techniques),
                ", ".join([d.value for d in h.data_sources])
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, h.hypothesis_id)
            self.hypotheses_tree.addTopLevelItem(item)
    
    def _load_patterns(self):
        """Load behavior patterns into list"""
        if not self.platform:
            return
        
        for pattern in self.platform.get_behavior_patterns():
            item = QListWidgetItem(f"{pattern.name} ({pattern.category.value})")
            item.setData(Qt.ItemDataRole.UserRole, pattern.pattern_id)
            self.pattern_list.addItem(item)
    
    def _load_sigma_rules(self):
        """Load SIGMA rules into list"""
        if not self.platform:
            return
        
        for rule in self.platform.get_sigma_rules():
            item = QListWidgetItem(f"[{rule.level.value.upper()}] {rule.title}")
            item.setData(Qt.ItemDataRole.UserRole, rule.rule_id)
            self.sigma_list.addItem(item)
    
    def _add_ioc(self):
        """Add IOC to list"""
        ioc_type = self.ioc_type_combo.currentText()
        value = self.ioc_value_input.text().strip()
        
        if not value:
            return
        
        item = QListWidgetItem(f"[{ioc_type}] {value}")
        item.setData(Qt.ItemDataRole.UserRole, {"type": ioc_type, "value": value})
        self.ioc_list.addItem(item)
        self.ioc_value_input.clear()
    
    def _import_iocs(self):
        """Import IOCs from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import IOCs",
            "",
            "Text Files (*.txt);;CSV Files (*.csv);;JSON Files (*.json)"
        )
        
        if file_path:
            try:
                with open(file_path, "r") as f:
                    if file_path.endswith(".json"):
                        data = json.load(f)
                        for ioc in data:
                            item = QListWidgetItem(f"[{ioc.get('type', 'unknown')}] {ioc.get('value', '')}")
                            item.setData(Qt.ItemDataRole.UserRole, ioc)
                            self.ioc_list.addItem(item)
                    else:
                        for line in f:
                            line = line.strip()
                            if line:
                                # Auto-detect type
                                ioc_type = self._detect_ioc_type(line)
                                item = QListWidgetItem(f"[{ioc_type}] {line}")
                                item.setData(Qt.ItemDataRole.UserRole, {"type": ioc_type, "value": line})
                                self.ioc_list.addItem(item)
                
                self._log(f"Imported IOCs from {file_path}", "info")
            except Exception as e:
                QMessageBox.critical(self, "Import Error", str(e))
    
    def _detect_ioc_type(self, value: str) -> str:
        """Auto-detect IOC type"""
        import re
        
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return "ip"
        elif re.match(r"^[a-fA-F0-9]{32}$", value):
            return "hash"
        elif re.match(r"^[a-fA-F0-9]{64}$", value):
            return "hash"
        elif re.match(r"^https?://", value):
            return "url"
        elif re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.[a-zA-Z]{2,}$", value):
            return "domain"
        else:
            return "unknown"
    
    def _start_hunt(self):
        """Start threat hunt"""
        if not self.platform:
            self._log("Threat hunting platform not available", "error")
            return
        
        hunt_index = self.hunt_type_combo.currentIndex()
        
        if hunt_index == 0:
            hunt_type = "ioc_sweep"
            iocs = []
            for i in range(self.ioc_list.count()):
                ioc_data = self.ioc_list.item(i).data(Qt.ItemDataRole.UserRole)
                iocs.append(ioc_data)
            
            if not iocs:
                QMessageBox.warning(self, "Error", "Please add IOCs to sweep")
                return
            
            params = {"iocs": iocs}
        
        elif hunt_index == 1:
            hunt_type = "behavioral"
            patterns = []
            for item in self.pattern_list.selectedItems():
                patterns.append(item.data(Qt.ItemDataRole.UserRole))
            params = {
                "patterns": patterns if patterns else None,
                "timeframe": self.timeframe_spin.value()
            }
        
        elif hunt_index == 2:
            hunt_type = "sigma"
            rules = []
            for item in self.sigma_list.selectedItems():
                rules.append(item.data(Qt.ItemDataRole.UserRole))
            params = {"rules": rules if rules else None}
        
        else:
            hunt_type = "anomaly"
            params = {}
        
        # Clear previous results
        self._clear_results()
        
        # Start worker
        self.hunt_worker = HuntWorker(self.platform, hunt_type, params)
        self.hunt_worker.progress.connect(self._update_progress)
        self.hunt_worker.finished.connect(self._hunt_complete)
        self.hunt_worker.error.connect(self._hunt_error)
        self.hunt_worker.log.connect(self._log)
        
        self.hunt_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Starting hunt...")
        
        self.hunt_worker.start()
    
    def _stop_hunt(self):
        """Stop running hunt"""
        if self.hunt_worker and self.hunt_worker.isRunning():
            self.hunt_worker.terminate()
            self.hunt_worker.wait()
            self._log("Hunt stopped by user", "warning")
        
        self.hunt_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Hunt stopped")
    
    def _update_progress(self, value: int, status: str):
        """Update progress bar"""
        self.progress_bar.setValue(value)
        self.status_label.setText(status)
    
    def _hunt_complete(self, findings: list):
        """Handle hunt completion"""
        self.current_findings = findings
        self.hunt_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText(f"Hunt complete: {len(findings)} findings")
        
        self._display_findings(findings)
    
    def _hunt_error(self, error: str):
        """Handle hunt error"""
        self.hunt_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Hunt failed")
        self._log(f"Error: {error}", "error")
        QMessageBox.critical(self, "Hunt Error", error)
    
    def _clear_results(self):
        """Clear all result displays"""
        self.findings_table.setRowCount(0)
        self.finding_details.clear()
        self.iocs_table.setRowCount(0)
        self.log_output.clear()
        
        self.stat_findings.setText("-")
        self.stat_critical.setText("-")
        self.stat_high.setText("-")
        self.stat_medium.setText("-")
    
    def _display_findings(self, findings: list):
        """Display hunt findings"""
        # Update stats
        self.stat_findings.setText(str(len(findings)))
        
        critical = sum(1 for f in findings if f.severity.value == "critical")
        high = sum(1 for f in findings if f.severity.value == "high")
        medium = sum(1 for f in findings if f.severity.value == "medium")
        
        self.stat_critical.setText(str(critical))
        self.stat_high.setText(str(high))
        self.stat_medium.setText(str(medium))
        
        # Populate findings table
        self.findings_table.setRowCount(len(findings))
        
        severity_colors = {
            "critical": "#ff0000",
            "high": "#ff4500",
            "medium": "#ffa500",
            "low": "#ffff00",
            "info": "#00ff00"
        }
        
        for i, finding in enumerate(findings):
            self.findings_table.setItem(i, 0, QTableWidgetItem(finding.timestamp.strftime("%H:%M:%S")))
            
            severity_item = QTableWidgetItem(finding.severity.value.upper())
            severity_item.setForeground(QColor(severity_colors.get(finding.severity.value, "#fff")))
            self.findings_table.setItem(i, 1, severity_item)
            
            self.findings_table.setItem(i, 2, QTableWidgetItem(finding.category.value))
            self.findings_table.setItem(i, 3, QTableWidgetItem(finding.title))
            self.findings_table.setItem(i, 4, QTableWidgetItem(", ".join(finding.mitre_attack)))
            self.findings_table.setItem(i, 5, QTableWidgetItem(", ".join(finding.affected_assets[:3])))
        
        # Populate IOCs table
        all_iocs = []
        for finding in findings:
            all_iocs.extend(finding.iocs)
        
        self.iocs_table.setRowCount(len(all_iocs))
        for i, ioc in enumerate(all_iocs):
            self.iocs_table.setItem(i, 0, QTableWidgetItem(ioc.ioc_type))
            self.iocs_table.setItem(i, 1, QTableWidgetItem(ioc.value))
            self.iocs_table.setItem(i, 2, QTableWidgetItem(ioc.source))
            self.iocs_table.setItem(i, 3, QTableWidgetItem(f"{ioc.confidence}%"))
            self.iocs_table.setItem(i, 4, QTableWidgetItem(", ".join(ioc.tags)))
    
    def _on_finding_selected(self):
        """Handle finding selection"""
        selected = self.findings_table.selectedItems()
        if not selected:
            return
        
        row = selected[0].row()
        if row < len(self.current_findings):
            finding = self.current_findings[row]
            
            details = f"""
╔══════════════════════════════════════════════════════════════════╗
║  FINDING: {finding.title[:50]}
╚══════════════════════════════════════════════════════════════════╝

📋 GENERAL:
   ID:         {finding.finding_id}
   Severity:   {finding.severity.value.upper()}
   Category:   {finding.category.value}
   Time:       {finding.timestamp}

📝 DESCRIPTION:
   {finding.description}

🎯 MITRE ATT&CK:
   {', '.join(finding.mitre_attack) if finding.mitre_attack else 'N/A'}

💻 AFFECTED ASSETS:
   {chr(10).join('   • ' + a for a in finding.affected_assets) if finding.affected_assets else '   None identified'}

📊 EVIDENCE:
   {json.dumps(finding.evidence, indent=4) if finding.evidence else '   None'}

📌 RECOMMENDATIONS:
   {chr(10).join('   • ' + r for r in finding.recommendations) if finding.recommendations else '   None'}

⚠️ FALSE POSITIVE LIKELIHOOD: {finding.false_positive_likelihood}
"""
            self.finding_details.setPlainText(details)
    
    def _log(self, message: str, level: str = "info"):
        """Add log message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "info": "#ff8800",
            "warning": "#ffaa00",
            "error": "#ff4444",
            "debug": "#888888"
        }
        color = colors.get(level, "#ffffff")
        self.log_output.append(f'<span style="color: #888;">[{timestamp}]</span> <span style="color: {color};">[{level.upper()}]</span> {message}')
    
    def _export_findings(self, format: str):
        """Export findings"""
        if not self.current_findings:
            QMessageBox.warning(self, "Export Error", "No findings to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Findings",
            f"threat_hunt_findings.{format}",
            f"{format.upper()} Files (*.{format})"
        )
        
        if file_path:
            try:
                data = [{
                    "id": f.finding_id,
                    "timestamp": f.timestamp.isoformat(),
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "title": f.title,
                    "description": f.description,
                    "mitre_attack": f.mitre_attack,
                    "affected_assets": f.affected_assets,
                    "evidence": f.evidence
                } for f in self.current_findings]
                
                with open(file_path, "w") as f:
                    json.dump(data, f, indent=2)
                
                self._log(f"Findings exported to {file_path}", "info")
                QMessageBox.information(self, "Export Complete", f"Saved to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))
    
    def _export_iocs(self):
        """Export IOCs"""
        if not self.current_findings:
            QMessageBox.warning(self, "Export Error", "No IOCs to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export IOCs",
            "threat_iocs.json",
            "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                all_iocs = []
                for finding in self.current_findings:
                    for ioc in finding.iocs:
                        all_iocs.append({
                            "type": ioc.ioc_type,
                            "value": ioc.value,
                            "description": ioc.description,
                            "source": ioc.source,
                            "confidence": ioc.confidence,
                            "tags": ioc.tags
                        })
                
                with open(file_path, "w") as f:
                    json.dump(all_iocs, f, indent=2)
                
                self._log(f"IOCs exported to {file_path}", "info")
                QMessageBox.information(self, "Export Complete", f"Saved to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))
