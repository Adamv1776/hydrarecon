#!/usr/bin/env python3
"""
HydraRecon Blue Team Detection Page
GUI for defensive security monitoring and incident response.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QComboBox,
    QTextEdit, QTableWidget, QTableWidgetItem, QProgressBar,
    QTabWidget, QGroupBox, QCheckBox, QSpinBox, QSplitter,
    QHeaderView, QTreeWidget, QTreeWidgetItem, QMessageBox,
    QListWidget, QListWidgetItem, QFileDialog, QDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor

import asyncio
from datetime import datetime
from typing import Optional

try:
    from ...core.blue_team import (
        BlueTeamEngine, AlertSeverity, AlertStatus, EventType
    )
    BLUETEAM_AVAILABLE = True
except ImportError:
    BLUETEAM_AVAILABLE = False


class AnalysisWorker(QThread):
    """Worker thread for log analysis"""
    progress = pyqtSignal(str, float)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def __init__(self, engine, filepath):
        super().__init__()
        self.engine = engine
        self.filepath = filepath
    
    def run(self):
        """Run the analysis"""
        try:
            def callback(msg, progress):
                self.progress.emit(msg, progress)
            
            alerts = self.engine.analyze_log_file(self.filepath, callback)
            self.finished.emit(alerts)
            
        except Exception as e:
            self.error.emit(str(e))


class CaseDialog(QDialog):
    """Dialog for creating incident cases"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case_data = None
        self._setup_ui()
    
    def _setup_ui(self):
        self.setWindowTitle("Create Incident Case")
        self.setMinimumSize(500, 400)
        self.setStyleSheet("""
            QDialog {
                background-color: #0d1117;
            }
        """)
        
        layout = QVBoxLayout(self)
        
        # Title
        layout.addWidget(QLabel("Case Title:"))
        self.title_input = QLineEdit()
        self.title_input.setStyleSheet("""
            QLineEdit {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        layout.addWidget(self.title_input)
        
        # Description
        layout.addWidget(QLabel("Description:"))
        self.desc_input = QTextEdit()
        self.desc_input.setStyleSheet("""
            QTextEdit {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        layout.addWidget(self.desc_input)
        
        # Severity
        layout.addWidget(QLabel("Severity:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["Critical", "High", "Medium", "Low"])
        self.severity_combo.setStyleSheet("""
            QComboBox {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        layout.addWidget(self.severity_combo)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        create_btn = QPushButton("Create Case")
        create_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 24px;
            }
        """)
        create_btn.clicked.connect(self._create_case)
        
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
        btn_layout.addWidget(create_btn)
        layout.addLayout(btn_layout)
    
    def _create_case(self):
        title = self.title_input.text().strip()
        if not title:
            QMessageBox.warning(self, "Error", "Please enter a case title")
            return
        
        severity_map = {
            "Critical": AlertSeverity.CRITICAL,
            "High": AlertSeverity.HIGH,
            "Medium": AlertSeverity.MEDIUM,
            "Low": AlertSeverity.LOW
        }
        
        self.case_data = {
            "title": title,
            "description": self.desc_input.toPlainText(),
            "severity": severity_map[self.severity_combo.currentText()]
        }
        self.accept()


class BlueTeamPage(QWidget):
    """Blue Team Detection Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = BlueTeamEngine() if BLUETEAM_AVAILABLE else None
        self.analysis_worker: Optional[AnalysisWorker] = None
        self.selected_alerts = []
        
        self._setup_ui()
        self._start_auto_refresh()
    
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
        
        # Tab 1: Dashboard
        self.tabs.addTab(self._create_dashboard_tab(), "📊 Dashboard")
        
        # Tab 2: Alerts
        self.tabs.addTab(self._create_alerts_tab(), "🚨 Alerts")
        
        # Tab 3: Detection Rules
        self.tabs.addTab(self._create_rules_tab(), "📋 Detection Rules")
        
        # Tab 4: Log Analysis
        self.tabs.addTab(self._create_analysis_tab(), "🔍 Log Analysis")
        
        # Tab 5: Incidents
        self.tabs.addTab(self._create_incidents_tab(), "📁 Incidents")
        
        layout.addWidget(self.tabs, stretch=1)
    
    def _create_header(self) -> QWidget:
        """Create header section"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1f6feb, stop:1 #238636);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🛡️ Blue Team Detection & Response")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: 700;
            color: white;
        """)
        
        subtitle = QLabel("Security monitoring, threat detection, and incident response")
        subtitle.setStyleSheet("font-size: 14px; color: rgba(255,255,255,0.8);")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout, stretch=1)
        
        # Stats
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(24)
        
        self.stat_alerts = self._create_stat_widget("Active Alerts", "0")
        self.stat_critical = self._create_stat_widget("Critical", "0")
        self.stat_cases = self._create_stat_widget("Open Cases", "0")
        
        stats_layout.addWidget(self.stat_alerts)
        stats_layout.addWidget(self.stat_critical)
        stats_layout.addWidget(self.stat_cases)
        
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
    
    def _create_dashboard_tab(self) -> QWidget:
        """Create dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Alert severity breakdown
        severity_group = QGroupBox("Alert Severity Breakdown")
        severity_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        severity_layout = QHBoxLayout(severity_group)
        
        severity_items = [
            ("Critical", "0", "#f85149"),
            ("High", "0", "#ffa657"),
            ("Medium", "0", "#d29922"),
            ("Low", "0", "#3fb950"),
            ("Info", "0", "#8b949e")
        ]
        
        self.severity_labels = {}
        for name, value, color in severity_items:
            item_layout = QVBoxLayout()
            
            count_label = QLabel(value)
            count_label.setStyleSheet(f"font-size: 32px; font-weight: bold; color: {color};")
            count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.severity_labels[name.lower()] = count_label
            
            name_label = QLabel(name)
            name_label.setStyleSheet("color: #8b949e;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            item_layout.addWidget(count_label)
            item_layout.addWidget(name_label)
            severity_layout.addLayout(item_layout)
        
        layout.addWidget(severity_group)
        
        # Recent alerts and correlations
        content_layout = QHBoxLayout()
        
        # Recent alerts
        recent_group = QGroupBox("Recent Alerts")
        recent_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        recent_layout = QVBoxLayout(recent_group)
        
        self.recent_alerts_list = QListWidget()
        self.recent_alerts_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #21262d;
            }
        """)
        recent_layout.addWidget(self.recent_alerts_list)
        
        content_layout.addWidget(recent_group)
        
        # Attack correlations
        corr_group = QGroupBox("Attack Correlations")
        corr_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        corr_layout = QVBoxLayout(corr_group)
        
        self.correlations_list = QListWidget()
        self.correlations_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #21262d;
            }
        """)
        corr_layout.addWidget(self.correlations_list)
        
        content_layout.addWidget(corr_group)
        
        layout.addLayout(content_layout, stretch=1)
        
        return widget
    
    def _create_alerts_tab(self) -> QWidget:
        """Create alerts management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Filters
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low", "Info"])
        self.severity_filter.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        self.severity_filter.currentIndexChanged.connect(self._filter_alerts)
        filter_layout.addWidget(self.severity_filter)
        
        filter_layout.addWidget(QLabel("Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "New", "Investigating", "Confirmed", "False Positive", "Resolved"])
        self.status_filter.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        self.status_filter.currentIndexChanged.connect(self._filter_alerts)
        filter_layout.addWidget(self.status_filter)
        
        filter_layout.addStretch()
        
        create_case_btn = QPushButton("📁 Create Case from Selected")
        create_case_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        create_case_btn.clicked.connect(self._create_case_from_alerts)
        filter_layout.addWidget(create_case_btn)
        
        layout.addLayout(filter_layout)
        
        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(7)
        self.alerts_table.setHorizontalHeaderLabels([
            "Alert ID", "Rule", "Severity", "Status", "Source", "Event Type", "Time"
        ])
        self.alerts_table.setStyleSheet("""
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
        self.alerts_table.horizontalHeader().setStretchLastSection(True)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.alerts_table.setSelectionMode(QTableWidget.SelectionMode.MultiSelection)
        self.alerts_table.itemSelectionChanged.connect(self._on_alert_selected)
        
        layout.addWidget(self.alerts_table, stretch=1)
        
        # Alert details
        details_group = QGroupBox("Alert Details")
        details_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        details_layout = QVBoxLayout(details_group)
        
        self.alert_details = QTextEdit()
        self.alert_details.setReadOnly(True)
        self.alert_details.setMaximumHeight(150)
        self.alert_details.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                padding: 12px;
            }
        """)
        details_layout.addWidget(self.alert_details)
        
        # Status update buttons
        status_layout = QHBoxLayout()
        
        for status, color in [
            ("Investigating", "#1f6feb"),
            ("Confirmed", "#ffa657"),
            ("False Positive", "#8b949e"),
            ("Resolved", "#238636")
        ]:
            btn = QPushButton(status)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 8px 16px;
                }}
            """)
            btn.clicked.connect(lambda checked, s=status: self._update_alert_status(s))
            status_layout.addWidget(btn)
        
        status_layout.addStretch()
        details_layout.addLayout(status_layout)
        
        layout.addWidget(details_group)
        
        return widget
    
    def _create_rules_tab(self) -> QWidget:
        """Create detection rules tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        info = QLabel(
            "Detection rules based on Sigma and MITRE ATT&CK framework. "
            "Toggle rules on/off to customize detection behavior."
        )
        info.setStyleSheet("color: #8b949e;")
        info.setWordWrap(True)
        layout.addWidget(info)
        
        # Rules table
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(5)
        self.rules_table.setHorizontalHeaderLabels([
            "Rule ID", "Name", "Severity", "MITRE", "Enabled"
        ])
        self.rules_table.setStyleSheet("""
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
        self.rules_table.horizontalHeader().setStretchLastSection(True)
        
        # Populate rules
        self._populate_rules_table()
        
        layout.addWidget(self.rules_table, stretch=1)
        
        # Rule details
        self.rule_details = QTextEdit()
        self.rule_details.setReadOnly(True)
        self.rule_details.setMaximumHeight(150)
        self.rule_details.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                padding: 12px;
            }
        """)
        self.rule_details.setPlaceholderText("Select a rule to view details...")
        
        layout.addWidget(self.rule_details)
        
        return widget
    
    def _create_analysis_tab(self) -> QWidget:
        """Create log analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # File selection
        file_group = QGroupBox("Log File Analysis")
        file_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        file_layout = QVBoxLayout(file_group)
        
        select_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Select a log file to analyze...")
        self.file_path_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        browse_btn.clicked.connect(self._browse_file)
        
        select_layout.addWidget(self.file_path_input, stretch=1)
        select_layout.addWidget(browse_btn)
        file_layout.addLayout(select_layout)
        
        # Analyze button and progress
        analyze_layout = QHBoxLayout()
        
        self.analyze_btn = QPushButton("🔍 Analyze Log File")
        self.analyze_btn.setStyleSheet("""
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
        self.analyze_btn.clicked.connect(self._analyze_file)
        
        self.analysis_progress = QProgressBar()
        self.analysis_progress.setStyleSheet("""
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
        
        self.analysis_status = QLabel("Ready")
        self.analysis_status.setStyleSheet("color: #8b949e;")
        
        analyze_layout.addWidget(self.analyze_btn)
        analyze_layout.addWidget(self.analysis_progress, stretch=1)
        analyze_layout.addWidget(self.analysis_status)
        
        file_layout.addLayout(analyze_layout)
        
        layout.addWidget(file_group)
        
        # Analysis results
        self.analysis_results = QTextEdit()
        self.analysis_results.setReadOnly(True)
        self.analysis_results.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                color: #e6e6e6;
                padding: 16px;
                font-family: 'Consolas', monospace;
            }
        """)
        self.analysis_results.setPlaceholderText("Analysis results will appear here...")
        
        layout.addWidget(self.analysis_results, stretch=1)
        
        return widget
    
    def _create_incidents_tab(self) -> QWidget:
        """Create incidents management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        new_case_btn = QPushButton("➕ New Incident Case")
        new_case_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        new_case_btn.clicked.connect(self._create_new_case)
        
        controls_layout.addWidget(new_case_btn)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        # Cases table
        self.cases_table = QTableWidget()
        self.cases_table.setColumnCount(6)
        self.cases_table.setHorizontalHeaderLabels([
            "Case ID", "Title", "Severity", "Status", "Alerts", "Created"
        ])
        self.cases_table.setStyleSheet("""
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
        self.cases_table.horizontalHeader().setStretchLastSection(True)
        
        layout.addWidget(self.cases_table, stretch=1)
        
        # Case details/timeline
        details_group = QGroupBox("Case Details & Timeline")
        details_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        details_layout = QVBoxLayout(details_group)
        
        self.case_details = QTextEdit()
        self.case_details.setReadOnly(True)
        self.case_details.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                padding: 12px;
            }
        """)
        details_layout.addWidget(self.case_details)
        
        layout.addWidget(details_group)
        
        return widget
    
    def _start_auto_refresh(self):
        """Start auto-refresh timer for dashboard"""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self._refresh_dashboard)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
    
    def _refresh_dashboard(self):
        """Refresh dashboard data"""
        if not self.engine:
            return
        
        data = self.engine.get_dashboard_data()
        stats = data.get("statistics", {})
        
        # Update severity counts
        by_severity = stats.get("by_severity", {})
        for severity, count in by_severity.items():
            if severity in self.severity_labels:
                self.severity_labels[severity].setText(str(count))
        
        # Update header stats
        total_alerts = stats.get("total_alerts", 0)
        critical = by_severity.get("critical", 0)
        active_cases = data.get("active_cases", 0)
        
        self.stat_alerts.findChild(QLabel, "value").setText(str(total_alerts))
        self.stat_critical.findChild(QLabel, "value").setText(str(critical))
        self.stat_cases.findChild(QLabel, "value").setText(str(active_cases))
        
        # Update recent alerts
        self.recent_alerts_list.clear()
        for alert in data.get("recent_alerts", [])[:10]:
            item = QListWidgetItem(
                f"[{alert['severity'].upper()}] {alert['rule_name']} - {alert['source_host']}"
            )
            self.recent_alerts_list.addItem(item)
        
        # Update correlations
        self.correlations_list.clear()
        for corr in data.get("correlations", []):
            item = QListWidgetItem(
                f"🔗 Attack chain on {corr['host']}: {corr['alert_count']} alerts, "
                f"{len(corr['techniques'])} techniques"
            )
            self.correlations_list.addItem(item)
    
    def _populate_rules_table(self):
        """Populate detection rules table"""
        if not self.engine:
            return
        
        rules = self.engine.get_detection_rules()
        self.rules_table.setRowCount(len(rules))
        
        severity_colors = {
            "critical": "#f85149",
            "high": "#ffa657",
            "medium": "#d29922",
            "low": "#3fb950",
            "info": "#8b949e"
        }
        
        for row, rule in enumerate(rules):
            self.rules_table.setItem(row, 0, QTableWidgetItem(rule['rule_id']))
            self.rules_table.setItem(row, 1, QTableWidgetItem(rule['name']))
            
            severity_item = QTableWidgetItem(rule['severity'].upper())
            severity_item.setForeground(QColor(severity_colors.get(rule['severity'], "#8b949e")))
            self.rules_table.setItem(row, 2, severity_item)
            
            self.rules_table.setItem(row, 3, 
                QTableWidgetItem(", ".join(rule['mitre_techniques'])))
            
            enabled_item = QTableWidgetItem("✅" if rule['enabled'] else "❌")
            self.rules_table.setItem(row, 4, enabled_item)
    
    def _filter_alerts(self):
        """Filter alerts based on selected criteria"""
        if not self.engine:
            return
        
        severity = self.severity_filter.currentText().lower()
        status = self.status_filter.currentText().lower().replace(" ", "_")
        
        severity = None if severity == "all" else severity
        status = None if status == "all" else status
        
        alerts = self.engine.get_alerts(severity=severity, status=status)
        self._populate_alerts_table(alerts)
    
    def _populate_alerts_table(self, alerts):
        """Populate alerts table"""
        self.alerts_table.setRowCount(len(alerts))
        
        severity_colors = {
            "critical": "#f85149",
            "high": "#ffa657",
            "medium": "#d29922",
            "low": "#3fb950",
            "info": "#8b949e"
        }
        
        for row, alert in enumerate(alerts):
            self.alerts_table.setItem(row, 0, QTableWidgetItem(alert['alert_id']))
            self.alerts_table.setItem(row, 1, QTableWidgetItem(alert['rule_name']))
            
            severity_item = QTableWidgetItem(alert['severity'].upper())
            severity_item.setForeground(QColor(severity_colors.get(alert['severity'], "#8b949e")))
            self.alerts_table.setItem(row, 2, severity_item)
            
            self.alerts_table.setItem(row, 3, QTableWidgetItem(alert['status'].upper()))
            self.alerts_table.setItem(row, 4, QTableWidgetItem(alert['source_host']))
            self.alerts_table.setItem(row, 5, QTableWidgetItem(alert['event_type']))
            self.alerts_table.setItem(row, 6, QTableWidgetItem(alert['created_at']))
    
    def _on_alert_selected(self):
        """Handle alert selection"""
        selected = self.alerts_table.selectedItems()
        if not selected:
            return
        
        rows = set(item.row() for item in selected)
        self.selected_alerts = [
            self.alerts_table.item(row, 0).text()
            for row in rows
        ]
    
    def _update_alert_status(self, status: str):
        """Update selected alerts' status"""
        if not self.selected_alerts or not self.engine:
            return
        
        status_map = {
            "Investigating": AlertStatus.INVESTIGATING,
            "Confirmed": AlertStatus.CONFIRMED,
            "False Positive": AlertStatus.FALSE_POSITIVE,
            "Resolved": AlertStatus.RESOLVED
        }
        
        for alert_id in self.selected_alerts:
            self.engine.detection_engine.update_alert_status(
                alert_id, status_map[status]
            )
        
        self._filter_alerts()
    
    def _browse_file(self):
        """Browse for log file"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select Log File", "",
            "Log Files (*.log *.json *.txt);;All Files (*)"
        )
        if filepath:
            self.file_path_input.setText(filepath)
    
    def _analyze_file(self):
        """Analyze selected log file"""
        filepath = self.file_path_input.text().strip()
        if not filepath:
            QMessageBox.warning(self, "Error", "Please select a log file")
            return
        
        if not self.engine:
            QMessageBox.warning(self, "Error", "Blue Team module not available")
            return
        
        self.analyze_btn.setEnabled(False)
        self.analysis_progress.setValue(0)
        
        self.analysis_worker = AnalysisWorker(self.engine, filepath)
        self.analysis_worker.progress.connect(self._on_analysis_progress)
        self.analysis_worker.finished.connect(self._on_analysis_finished)
        self.analysis_worker.error.connect(self._on_analysis_error)
        self.analysis_worker.start()
    
    def _on_analysis_progress(self, message: str, progress: float):
        """Handle analysis progress"""
        self.analysis_status.setText(message)
        self.analysis_progress.setValue(int(progress))
    
    def _on_analysis_finished(self, alerts):
        """Handle analysis completion"""
        self.analyze_btn.setEnabled(True)
        self.analysis_progress.setValue(100)
        self.analysis_status.setText(f"Found {len(alerts)} alerts")
        
        # Update results display
        results = f"<h3>Analysis Complete</h3>"
        results += f"<p>Total alerts generated: <b>{len(alerts)}</b></p>"
        
        if alerts:
            severity_counts = {}
            for alert in alerts:
                sev = alert.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            results += "<h4>By Severity:</h4><ul>"
            for sev, count in severity_counts.items():
                results += f"<li>{sev.upper()}: {count}</li>"
            results += "</ul>"
        
        self.analysis_results.setHtml(results)
        self._filter_alerts()
        self._refresh_dashboard()
    
    def _on_analysis_error(self, error: str):
        """Handle analysis error"""
        self.analyze_btn.setEnabled(True)
        self.analysis_status.setText(f"Error: {error}")
        QMessageBox.critical(self, "Analysis Error", error)
    
    def _create_new_case(self):
        """Create new incident case"""
        dialog = CaseDialog(self)
        if dialog.exec() and dialog.case_data:
            case = self.engine.incident_manager.create_case(
                title=dialog.case_data["title"],
                description=dialog.case_data["description"],
                severity=dialog.case_data["severity"]
            )
            self._refresh_cases_table()
            QMessageBox.information(self, "Success", f"Case {case.case_id} created")
    
    def _create_case_from_alerts(self):
        """Create case from selected alerts"""
        if not self.selected_alerts:
            QMessageBox.warning(self, "Error", "Please select alerts first")
            return
        
        dialog = CaseDialog(self)
        if dialog.exec() and dialog.case_data:
            case = self.engine.incident_manager.create_case(
                title=dialog.case_data["title"],
                description=dialog.case_data["description"],
                severity=dialog.case_data["severity"],
                alert_ids=self.selected_alerts
            )
            self._refresh_cases_table()
            QMessageBox.information(
                self, "Success", 
                f"Case {case.case_id} created with {len(self.selected_alerts)} alerts"
            )
    
    def _refresh_cases_table(self):
        """Refresh incidents table"""
        if not self.engine:
            return
        
        cases = self.engine.incident_manager.list_cases()
        self.cases_table.setRowCount(len(cases))
        
        for row, case in enumerate(cases):
            self.cases_table.setItem(row, 0, QTableWidgetItem(case['case_id']))
            self.cases_table.setItem(row, 1, QTableWidgetItem(case['title']))
            self.cases_table.setItem(row, 2, QTableWidgetItem(case['severity'].upper()))
            self.cases_table.setItem(row, 3, QTableWidgetItem(case['status'].upper()))
            self.cases_table.setItem(row, 4, QTableWidgetItem(str(case['alert_count'])))
            self.cases_table.setItem(row, 5, QTableWidgetItem(case['created_at']))
