#!/usr/bin/env python3
"""
HydraRecon Vulnerability Management Page
GUI for vulnerability tracking, prioritization, and lifecycle management.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QComboBox,
    QTextEdit, QTableWidget, QTableWidgetItem, QProgressBar,
    QTabWidget, QGroupBox, QCheckBox, QSpinBox, QSplitter,
    QHeaderView, QMessageBox, QListWidget, QListWidgetItem,
    QTreeWidget, QTreeWidgetItem, QFileDialog, QDialog,
    QFormLayout, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QBrush

import asyncio
from datetime import datetime
from typing import Optional

try:
    from ...core.vuln_management import (
        VulnerabilityManagementEngine, VulnerabilitySeverity, 
        VulnerabilityStatus, AssetType
    )
    VULNMGMT_AVAILABLE = True
except ImportError:
    VULNMGMT_AVAILABLE = False


class ScanWorker(QThread):
    """Worker thread for vulnerability scanning"""
    progress = pyqtSignal(str, float)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, engine, target, scan_type):
        super().__init__()
        self.engine = engine
        self.target = target
        self.scan_type = scan_type
    
    def run(self):
        """Run the scan"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            def callback(msg, progress):
                self.progress.emit(msg, progress)
            
            result = loop.run_until_complete(
                self.engine.run_scan(self.target, self.scan_type, callback)
            )
            
            loop.close()
            self.finished.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class ImportWorker(QThread):
    """Worker thread for importing scan results"""
    progress = pyqtSignal(str, float)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, engine, filepath, scan_type):
        super().__init__()
        self.engine = engine
        self.filepath = filepath
        self.scan_type = scan_type
    
    def run(self):
        """Run the import"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            def callback(msg, progress):
                self.progress.emit(msg, progress)
            
            result = loop.run_until_complete(
                self.engine.import_scan(self.filepath, self.scan_type, callback)
            )
            
            loop.close()
            self.finished.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class VulnManagementPage(QWidget):
    """Vulnerability Management Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = VulnerabilityManagementEngine() if VULNMGMT_AVAILABLE else None
        self.scan_worker: Optional[ScanWorker] = None
        self.import_worker: Optional[ImportWorker] = None
        
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
        
        # Tab 1: Dashboard
        self.tabs.addTab(self._create_dashboard_tab(), "📊 Dashboard")
        
        # Tab 2: Vulnerabilities
        self.tabs.addTab(self._create_vulns_tab(), "🐛 Vulnerabilities")
        
        # Tab 3: Scanning
        self.tabs.addTab(self._create_scanning_tab(), "🔍 Scanning")
        
        # Tab 4: Assets
        self.tabs.addTab(self._create_assets_tab(), "💻 Assets")
        
        # Tab 5: Remediation
        self.tabs.addTab(self._create_remediation_tab(), "🔧 Remediation")
        
        layout.addWidget(self.tabs, stretch=1)
        
        # Initial dashboard refresh
        self._refresh_dashboard()
    
    def _create_header(self) -> QWidget:
        """Create header section"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #f85149, stop:1 #ffa657);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🐛 Vulnerability Management")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: 700;
            color: white;
        """)
        
        subtitle = QLabel("Track, prioritize, and remediate security vulnerabilities")
        subtitle.setStyleSheet("font-size: 14px; color: rgba(255,255,255,0.8);")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout, stretch=1)
        
        # Quick stats
        quick_stats = QHBoxLayout()
        
        self.critical_badge = QLabel("0 Critical")
        self.critical_badge.setStyleSheet("""
            background-color: rgba(0,0,0,0.3);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
        """)
        
        self.overdue_badge = QLabel("0 Overdue")
        self.overdue_badge.setStyleSheet("""
            background-color: rgba(0,0,0,0.3);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
        """)
        
        quick_stats.addWidget(self.critical_badge)
        quick_stats.addWidget(self.overdue_badge)
        
        layout.addLayout(quick_stats)
        
        return header
    
    def _create_dashboard_tab(self) -> QWidget:
        """Create dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Stats cards
        cards_layout = QHBoxLayout()
        
        self.stat_cards = {}
        stats = [
            ("total", "Total Vulns", "#8b949e"),
            ("open", "Open", "#ffa657"),
            ("critical", "Critical", "#f85149"),
            ("high", "High", "#d29922"),
            ("remediated", "Remediated", "#3fb950")
        ]
        
        for key, label, color in stats:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: #161b22;
                    border: 2px solid {color};
                    border-radius: 12px;
                }}
            """)
            
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(20, 20, 20, 20)
            
            value = QLabel("0")
            value.setStyleSheet(f"font-size: 36px; font-weight: bold; color: {color};")
            value.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name = QLabel(label)
            name.setStyleSheet("color: #8b949e; font-size: 13px;")
            name.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            card_layout.addWidget(value)
            card_layout.addWidget(name)
            
            self.stat_cards[key] = value
            cards_layout.addWidget(card)
        
        layout.addLayout(cards_layout)
        
        # Metrics row
        metrics_layout = QHBoxLayout()
        
        # MTTR
        mttr_frame = QFrame()
        mttr_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        mttr_layout = QVBoxLayout(mttr_frame)
        mttr_layout.setContentsMargins(15, 15, 15, 15)
        
        self.mttr_label = QLabel("-- days")
        self.mttr_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #58a6ff;")
        self.mttr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        mttr_name = QLabel("Mean Time to Remediate")
        mttr_name.setStyleSheet("color: #8b949e;")
        mttr_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        mttr_layout.addWidget(self.mttr_label)
        mttr_layout.addWidget(mttr_name)
        
        metrics_layout.addWidget(mttr_frame)
        
        # Assets
        assets_frame = QFrame()
        assets_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        assets_layout = QVBoxLayout(assets_frame)
        assets_layout.setContentsMargins(15, 15, 15, 15)
        
        self.assets_label = QLabel("0")
        self.assets_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #bc8cff;")
        self.assets_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        assets_name = QLabel("Total Assets")
        assets_name.setStyleSheet("color: #8b949e;")
        assets_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        assets_layout.addWidget(self.assets_label)
        assets_layout.addWidget(assets_name)
        
        metrics_layout.addWidget(assets_frame)
        
        layout.addLayout(metrics_layout)
        
        # Top vulnerabilities
        top_group = QGroupBox("Top Priority Vulnerabilities")
        top_group.setStyleSheet("""
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
        
        top_layout = QVBoxLayout(top_group)
        
        self.top_vulns_table = QTableWidget()
        self.top_vulns_table.setColumnCount(5)
        self.top_vulns_table.setHorizontalHeaderLabels([
            "ID", "Title", "Severity", "Risk Score", "Status"
        ])
        self.top_vulns_table.horizontalHeader().setStretchLastSection(True)
        self.top_vulns_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        
        top_layout.addWidget(self.top_vulns_table)
        
        layout.addWidget(top_group, stretch=1)
        
        return widget
    
    def _create_vulns_tab(self) -> QWidget:
        """Create vulnerabilities tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Filters
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        self.severity_filter.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        self.severity_filter.currentIndexChanged.connect(self._filter_vulnerabilities)
        filter_layout.addWidget(self.severity_filter)
        
        filter_layout.addWidget(QLabel("Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "New", "Confirmed", "In Progress", "Remediated"])
        self.status_filter.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        self.status_filter.currentIndexChanged.connect(self._filter_vulnerabilities)
        filter_layout.addWidget(self.status_filter)
        
        filter_layout.addStretch()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 16px;
            }
        """)
        refresh_btn.clicked.connect(self._refresh_vulnerabilities)
        filter_layout.addWidget(refresh_btn)
        
        layout.addLayout(filter_layout)
        
        # Vulnerabilities table
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(7)
        self.vulns_table.setHorizontalHeaderLabels([
            "ID", "CVE", "Title", "Severity", "Risk Score", "Status", "Affected Assets"
        ])
        self.vulns_table.horizontalHeader().setStretchLastSection(True)
        self.vulns_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        self.vulns_table.itemDoubleClicked.connect(self._show_vuln_details)
        
        layout.addWidget(self.vulns_table, stretch=1)
        
        return widget
    
    def _create_scanning_tab(self) -> QWidget:
        """Create scanning tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # New scan
        scan_group = QGroupBox("Run Vulnerability Scan")
        scan_group.setStyleSheet("""
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
        
        scan_layout = QVBoxLayout(scan_group)
        
        # Target
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        
        self.scan_target = QLineEdit()
        self.scan_target.setPlaceholderText("IP address or hostname...")
        self.scan_target.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        target_layout.addWidget(self.scan_target, stretch=1)
        
        scan_layout.addLayout(target_layout)
        
        # Scan type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Scan Type:"))
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Nmap Vuln Scan", "Quick Scan"])
        self.scan_type_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        type_layout.addWidget(self.scan_type_combo)
        type_layout.addStretch()
        
        scan_layout.addLayout(type_layout)
        
        # Scan button
        scan_btn_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("🔍 Start Scan")
        self.scan_btn.setStyleSheet("""
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
        self.scan_btn.clicked.connect(self._start_scan)
        
        self.scan_progress = QProgressBar()
        self.scan_progress.setStyleSheet("""
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
        
        self.scan_status = QLabel("Ready")
        self.scan_status.setStyleSheet("color: #8b949e;")
        
        scan_btn_layout.addWidget(self.scan_btn)
        scan_btn_layout.addWidget(self.scan_progress, stretch=1)
        scan_btn_layout.addWidget(self.scan_status)
        
        scan_layout.addLayout(scan_btn_layout)
        
        layout.addWidget(scan_group)
        
        # Import section
        import_group = QGroupBox("Import Scan Results")
        import_group.setStyleSheet("""
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
        
        import_layout = QVBoxLayout(import_group)
        
        import_info = QLabel("Import vulnerability scan results from external tools:")
        import_info.setStyleSheet("color: #8b949e;")
        import_layout.addWidget(import_info)
        
        import_btns = QHBoxLayout()
        
        nessus_btn = QPushButton("📄 Import Nessus (.nessus)")
        nessus_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        nessus_btn.clicked.connect(lambda: self._import_scan("nessus"))
        
        qualys_btn = QPushButton("📄 Import Qualys (.xml)")
        qualys_btn.setStyleSheet("""
            QPushButton {
                background-color: #8957e5;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        qualys_btn.clicked.connect(lambda: self._import_scan("qualys"))
        
        import_btns.addWidget(nessus_btn)
        import_btns.addWidget(qualys_btn)
        import_btns.addStretch()
        
        import_layout.addLayout(import_btns)
        
        layout.addWidget(import_group)
        
        # Scan history
        history_group = QGroupBox("Scan History")
        history_group.setStyleSheet("""
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
        
        history_layout = QVBoxLayout(history_group)
        
        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(5)
        self.scans_table.setHorizontalHeaderLabels([
            "Scan ID", "Type", "Target", "Vulns Found", "Date"
        ])
        self.scans_table.horizontalHeader().setStretchLastSection(True)
        self.scans_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 8px;
                border: none;
            }
        """)
        
        history_layout.addWidget(self.scans_table)
        
        layout.addWidget(history_group, stretch=1)
        
        return widget
    
    def _create_assets_tab(self) -> QWidget:
        """Create assets tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Add asset button
        add_layout = QHBoxLayout()
        
        add_btn = QPushButton("➕ Add Asset")
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        add_btn.clicked.connect(self._add_asset_dialog)
        
        add_layout.addWidget(add_btn)
        add_layout.addStretch()
        
        layout.addLayout(add_layout)
        
        # Assets table
        self.assets_table = QTableWidget()
        self.assets_table.setColumnCount(6)
        self.assets_table.setHorizontalHeaderLabels([
            "Asset ID", "Name", "Type", "IP Address", "Criticality", "Vulns"
        ])
        self.assets_table.horizontalHeader().setStretchLastSection(True)
        self.assets_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        
        layout.addWidget(self.assets_table, stretch=1)
        
        return widget
    
    def _create_remediation_tab(self) -> QWidget:
        """Create remediation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # SLA Summary
        sla_group = QGroupBox("SLA Status")
        sla_group.setStyleSheet("""
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
        
        sla_layout = QHBoxLayout(sla_group)
        
        sla_items = [
            ("Critical: 7 days", "#f85149"),
            ("High: 30 days", "#ffa657"),
            ("Medium: 90 days", "#d29922"),
            ("Low: 180 days", "#3fb950")
        ]
        
        for text, color in sla_items:
            label = QLabel(f"● {text}")
            label.setStyleSheet(f"color: {color};")
            sla_layout.addWidget(label)
        
        sla_layout.addStretch()
        
        layout.addWidget(sla_group)
        
        # Overdue vulnerabilities
        overdue_group = QGroupBox("Overdue Vulnerabilities")
        overdue_group.setStyleSheet("""
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
        
        overdue_layout = QVBoxLayout(overdue_group)
        
        self.overdue_table = QTableWidget()
        self.overdue_table.setColumnCount(5)
        self.overdue_table.setHorizontalHeaderLabels([
            "ID", "Title", "Severity", "Discovered", "Days Overdue"
        ])
        self.overdue_table.horizontalHeader().setStretchLastSection(True)
        self.overdue_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 8px;
                border: none;
            }
        """)
        
        overdue_layout.addWidget(self.overdue_table)
        
        layout.addWidget(overdue_group, stretch=1)
        
        return widget
    
    def _refresh_dashboard(self):
        """Refresh dashboard statistics"""
        if not self.engine:
            return
        
        stats = self.engine.get_dashboard_stats()
        
        # Update stat cards
        self.stat_cards["total"].setText(str(stats["total_vulnerabilities"]))
        self.stat_cards["open"].setText(str(stats["open_vulnerabilities"]))
        self.stat_cards["critical"].setText(str(stats["critical_open"]))
        self.stat_cards["high"].setText(str(stats["high_open"]))
        self.stat_cards["remediated"].setText(str(stats["remediated"]))
        
        # Update badges
        self.critical_badge.setText(f"{stats['critical_open']} Critical")
        self.overdue_badge.setText(f"{stats['overdue']} Overdue")
        
        # Update MTTR
        mttr = stats["mean_time_to_remediate"]
        self.mttr_label.setText(f"{mttr:.1f} days" if mttr > 0 else "-- days")
        
        # Update assets count
        self.assets_label.setText(str(stats["total_assets"]))
        
        # Update top vulns table
        self._update_top_vulns()
    
    def _update_top_vulns(self):
        """Update top vulnerabilities table"""
        if not self.engine:
            return
        
        prioritized = self.engine.get_prioritized_list()[:10]
        
        self.top_vulns_table.setRowCount(len(prioritized))
        for i, vuln in enumerate(prioritized):
            self.top_vulns_table.setItem(i, 0, QTableWidgetItem(vuln.vuln_id))
            self.top_vulns_table.setItem(i, 1, QTableWidgetItem(vuln.title[:50]))
            
            severity_item = QTableWidgetItem(vuln.severity.value.upper())
            severity_colors = {
                VulnerabilitySeverity.CRITICAL: "#f85149",
                VulnerabilitySeverity.HIGH: "#ffa657",
                VulnerabilitySeverity.MEDIUM: "#d29922",
                VulnerabilitySeverity.LOW: "#3fb950"
            }
            severity_item.setForeground(QBrush(QColor(
                severity_colors.get(vuln.severity, "#8b949e")
            )))
            self.top_vulns_table.setItem(i, 2, severity_item)
            
            self.top_vulns_table.setItem(i, 3, QTableWidgetItem(f"{vuln.risk_score:.1f}"))
            self.top_vulns_table.setItem(i, 4, QTableWidgetItem(vuln.status.value.replace("_", " ").title()))
    
    def _refresh_vulnerabilities(self):
        """Refresh vulnerabilities table"""
        if not self.engine:
            return
        
        vulns = list(self.engine.vulnerabilities.values())
        self._filter_vulnerabilities()
    
    def _filter_vulnerabilities(self):
        """Filter vulnerabilities based on filters"""
        if not self.engine:
            return
        
        vulns = list(self.engine.vulnerabilities.values())
        
        # Apply severity filter
        sev_filter = self.severity_filter.currentText()
        if sev_filter != "All":
            vulns = [v for v in vulns if v.severity.value.lower() == sev_filter.lower()]
        
        # Apply status filter
        status_filter = self.status_filter.currentText()
        if status_filter != "All":
            status_map = {
                "New": VulnerabilityStatus.NEW,
                "Confirmed": VulnerabilityStatus.CONFIRMED,
                "In Progress": VulnerabilityStatus.IN_PROGRESS,
                "Remediated": VulnerabilityStatus.REMEDIATED
            }
            if status_filter in status_map:
                vulns = [v for v in vulns if v.status == status_map[status_filter]]
        
        # Update table
        self.vulns_table.setRowCount(len(vulns))
        for i, vuln in enumerate(vulns):
            self.vulns_table.setItem(i, 0, QTableWidgetItem(vuln.vuln_id))
            self.vulns_table.setItem(i, 1, QTableWidgetItem(vuln.cve_id or "N/A"))
            self.vulns_table.setItem(i, 2, QTableWidgetItem(vuln.title[:40]))
            
            severity_item = QTableWidgetItem(vuln.severity.value.upper())
            severity_colors = {
                VulnerabilitySeverity.CRITICAL: "#f85149",
                VulnerabilitySeverity.HIGH: "#ffa657",
                VulnerabilitySeverity.MEDIUM: "#d29922",
                VulnerabilitySeverity.LOW: "#3fb950"
            }
            severity_item.setForeground(QBrush(QColor(
                severity_colors.get(vuln.severity, "#8b949e")
            )))
            self.vulns_table.setItem(i, 3, severity_item)
            
            self.vulns_table.setItem(i, 4, QTableWidgetItem(f"{vuln.risk_score:.1f}"))
            self.vulns_table.setItem(i, 5, QTableWidgetItem(vuln.status.value.replace("_", " ").title()))
            self.vulns_table.setItem(i, 6, QTableWidgetItem(str(len(vuln.affected_assets))))
    
    def _show_vuln_details(self, item):
        """Show vulnerability details"""
        row = item.row()
        vuln_id = self.vulns_table.item(row, 0).text()
        
        if self.engine and vuln_id in self.engine.vulnerabilities:
            vuln = self.engine.vulnerabilities[vuln_id]
            
            msg = QMessageBox(self)
            msg.setWindowTitle(f"Vulnerability: {vuln_id}")
            msg.setText(f"""
<b>{vuln.title}</b><br><br>
<b>CVE:</b> {vuln.cve_id or 'N/A'}<br>
<b>Severity:</b> {vuln.severity.value.upper()}<br>
<b>Risk Score:</b> {vuln.risk_score:.1f}<br>
<b>Status:</b> {vuln.status.value.replace('_', ' ').title()}<br><br>
<b>Description:</b><br>{vuln.description[:500]}...<br><br>
<b>Solution:</b><br>{vuln.solution or 'No solution provided'}
            """)
            msg.setIcon(QMessageBox.Icon.Information)
            msg.exec()
    
    def _start_scan(self):
        """Start vulnerability scan"""
        target = self.scan_target.text().strip()
        if not target or not self.engine:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return
        
        self.scan_btn.setEnabled(False)
        self.scan_progress.setValue(0)
        
        self.scan_worker = ScanWorker(self.engine, target, "nmap")
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.finished.connect(self._on_scan_finished)
        self.scan_worker.error.connect(self._on_scan_error)
        self.scan_worker.start()
    
    def _on_scan_progress(self, message: str, progress: float):
        """Handle scan progress"""
        self.scan_status.setText(message)
        self.scan_progress.setValue(int(progress))
    
    def _on_scan_finished(self, result):
        """Handle scan completion"""
        self.scan_btn.setEnabled(True)
        self.scan_progress.setValue(100)
        self.scan_status.setText(f"Found {result.vulnerabilities_found} vulnerabilities")
        
        # Update scan history
        self._update_scan_history()
        
        # Refresh dashboard
        self._refresh_dashboard()
        
        QMessageBox.information(self, "Scan Complete",
            f"Found {result.vulnerabilities_found} vulnerabilities:\n"
            f"Critical: {result.critical_count}\n"
            f"High: {result.high_count}\n"
            f"Medium: {result.medium_count}\n"
            f"Low: {result.low_count}")
    
    def _on_scan_error(self, error: str):
        """Handle scan error"""
        self.scan_btn.setEnabled(True)
        self.scan_status.setText(f"Error: {error}")
        QMessageBox.critical(self, "Scan Error", error)
    
    def _import_scan(self, scan_type: str):
        """Import scan results"""
        if not self.engine:
            return
        
        filter_text = "Nessus Files (*.nessus)" if scan_type == "nessus" else "XML Files (*.xml)"
        
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Import Scan Results", "", filter_text
        )
        
        if filepath:
            self.import_worker = ImportWorker(self.engine, filepath, scan_type)
            self.import_worker.progress.connect(self._on_scan_progress)
            self.import_worker.finished.connect(self._on_scan_finished)
            self.import_worker.error.connect(self._on_scan_error)
            self.import_worker.start()
    
    def _update_scan_history(self):
        """Update scan history table"""
        if not self.engine:
            return
        
        self.scans_table.setRowCount(len(self.engine.scans))
        for i, scan in enumerate(self.engine.scans):
            self.scans_table.setItem(i, 0, QTableWidgetItem(scan.scan_id))
            self.scans_table.setItem(i, 1, QTableWidgetItem(scan.scan_type.upper()))
            self.scans_table.setItem(i, 2, QTableWidgetItem(scan.target))
            self.scans_table.setItem(i, 3, QTableWidgetItem(str(scan.vulnerabilities_found)))
            self.scans_table.setItem(i, 4, QTableWidgetItem(
                scan.start_time.strftime("%Y-%m-%d %H:%M")
            ))
    
    def _add_asset_dialog(self):
        """Show add asset dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Asset")
        dialog.setMinimumWidth(400)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #0d1117;
            }
            QLabel { color: #e6e6e6; }
            QLineEdit, QComboBox, QSpinBox {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        
        layout = QFormLayout(dialog)
        
        name_input = QLineEdit()
        layout.addRow("Name:", name_input)
        
        type_combo = QComboBox()
        type_combo.addItems(["Server", "Workstation", "Network Device", "Application"])
        layout.addRow("Type:", type_combo)
        
        ip_input = QLineEdit()
        layout.addRow("IP Address:", ip_input)
        
        crit_spin = QSpinBox()
        crit_spin.setRange(1, 10)
        crit_spin.setValue(5)
        layout.addRow("Criticality:", crit_spin)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            if self.engine and name_input.text():
                type_map = {
                    "Server": AssetType.SERVER,
                    "Workstation": AssetType.WORKSTATION,
                    "Network Device": AssetType.NETWORK_DEVICE,
                    "Application": AssetType.APPLICATION
                }
                
                self.engine.add_asset(
                    name=name_input.text(),
                    asset_type=type_map.get(type_combo.currentText(), AssetType.SERVER),
                    ip_address=ip_input.text(),
                    criticality=crit_spin.value()
                )
                
                self._refresh_assets()
    
    def _refresh_assets(self):
        """Refresh assets table"""
        if not self.engine:
            return
        
        assets = list(self.engine.assets.values())
        
        self.assets_table.setRowCount(len(assets))
        for i, asset in enumerate(assets):
            self.assets_table.setItem(i, 0, QTableWidgetItem(asset.asset_id))
            self.assets_table.setItem(i, 1, QTableWidgetItem(asset.name))
            self.assets_table.setItem(i, 2, QTableWidgetItem(asset.asset_type.value))
            self.assets_table.setItem(i, 3, QTableWidgetItem(asset.ip_address))
            self.assets_table.setItem(i, 4, QTableWidgetItem(str(asset.criticality)))
            
            # Count vulns for this asset
            vuln_count = sum(
                1 for v in self.engine.vulnerabilities.values()
                if asset.asset_id in v.affected_assets or 
                   asset.ip_address in v.affected_assets
            )
            self.assets_table.setItem(i, 5, QTableWidgetItem(str(vuln_count)))
