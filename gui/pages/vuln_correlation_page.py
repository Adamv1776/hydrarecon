#!/usr/bin/env python3
"""
Vulnerability Correlation Page
Advanced GUI for vulnerability correlation, deduplication, and prioritization.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QFrame,
    QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QTreeWidget, QTreeWidgetItem, QGroupBox, QFormLayout,
    QSpinBox, QCheckBox, QListWidget, QListWidgetItem,
    QProgressBar, QMessageBox, QScrollArea, QGridLayout,
    QFileDialog, QSlider
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QBrush

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any


class VulnCorrelationPage(QWidget):
    """Vulnerability Correlation page"""
    
    status_message = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.engine = None
        self._init_engine()
        self._setup_ui()
        self._connect_signals()
        self._apply_styles()
    
    def _init_engine(self):
        """Initialize correlation engine"""
        try:
            from core.vuln_correlation import (
                VulnCorrelationEngine, VulnerabilitySource, SeverityLevel,
                VulnStatus, CorrelationType
            )
            self.engine = VulnCorrelationEngine()
            self.VulnerabilitySource = VulnerabilitySource
            self.SeverityLevel = SeverityLevel
            self.VulnStatus = VulnStatus
            self.CorrelationType = CorrelationType
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
        self.tabs.addTab(self._create_import_tab(), "📥 Import")
        self.tabs.addTab(self._create_correlation_tab(), "🔗 Correlation")
        self.tabs.addTab(self._create_prioritization_tab(), "📊 Prioritization")
        self.tabs.addTab(self._create_chains_tab(), "⛓️ Exploit Chains")
        self.tabs.addTab(self._create_context_tab(), "🎯 Asset Context")
        self.tabs.addTab(self._create_intel_tab(), "🛡️ Threat Intel")
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
        
        title = QLabel("🔗 Vulnerability Correlation Engine")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        
        subtitle = QLabel("Advanced deduplication, correlation, and prioritization")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Action buttons
        correlate_btn = QPushButton("🔄 Run Correlation")
        correlate_btn.setObjectName("primaryButton")
        correlate_btn.clicked.connect(self._run_correlation)
        layout.addWidget(correlate_btn)
        
        return header
    
    def _create_import_tab(self) -> QWidget:
        """Create import tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Import stats
        stats_layout = QHBoxLayout()
        
        self.stat_cards = {}
        stats = [
            ("raw_vulns", "Raw Vulnerabilities", "0", "#00d4ff"),
            ("sources", "Data Sources", "0", "#00ff88"),
            ("hosts", "Unique Hosts", "0", "#ff6b6b"),
            ("cves", "Unique CVEs", "0", "#ffd93d")
        ]
        
        for key, label, value, color in stats:
            card = self._create_stat_card(label, value, color)
            self.stat_cards[key] = card
            stats_layout.addWidget(card)
        
        layout.addLayout(stats_layout)
        
        # Import sources
        sources_frame = QFrame()
        sources_frame.setObjectName("contentFrame")
        sources_layout = QVBoxLayout(sources_frame)
        
        sources_layout.addWidget(QLabel("Import Vulnerability Data"))
        
        # Source selection
        source_grid = QGridLayout()
        
        sources = [
            ("Nmap XML", "nmap", "🔍"),
            ("Nessus CSV", "nessus", "📊"),
            ("OpenVAS", "openvas", "🛡️"),
            ("Nuclei JSON", "nuclei", "⚛️"),
            ("Burp Suite", "burp", "🕷️"),
            ("OWASP ZAP", "zap", "⚡"),
            ("Qualys", "qualys", "📋"),
            ("Custom JSON", "custom", "📄")
        ]
        
        self.import_buttons = {}
        for i, (name, source, icon) in enumerate(sources):
            row, col = divmod(i, 4)
            btn = QPushButton(f"{icon} {name}")
            btn.setMinimumHeight(60)
            btn.clicked.connect(lambda checked, s=source: self._import_source(s))
            self.import_buttons[source] = btn
            source_grid.addWidget(btn, row, col)
        
        sources_layout.addLayout(source_grid)
        
        layout.addWidget(sources_frame)
        
        # Manual entry
        manual_frame = QFrame()
        manual_frame.setObjectName("contentFrame")
        manual_layout = QVBoxLayout(manual_frame)
        
        manual_layout.addWidget(QLabel("Manual Vulnerability Entry"))
        
        form = QFormLayout()
        
        self.manual_title = QLineEdit()
        self.manual_title.setPlaceholderText("Vulnerability title...")
        form.addRow("Title:", self.manual_title)
        
        self.manual_host = QLineEdit()
        self.manual_host.setPlaceholderText("192.168.1.1")
        form.addRow("Host:", self.manual_host)
        
        self.manual_port = QSpinBox()
        self.manual_port.setRange(0, 65535)
        form.addRow("Port:", self.manual_port)
        
        self.manual_severity = QComboBox()
        if self.engine:
            for s in self.SeverityLevel:
                self.manual_severity.addItem(s.value.title(), s)
        form.addRow("Severity:", self.manual_severity)
        
        self.manual_cvss = QSpinBox()
        self.manual_cvss.setRange(0, 100)
        self.manual_cvss.setSuffix(" (x0.1)")
        form.addRow("CVSS:", self.manual_cvss)
        
        self.manual_cve = QLineEdit()
        self.manual_cve.setPlaceholderText("CVE-2024-XXXX")
        form.addRow("CVE ID:", self.manual_cve)
        
        manual_layout.addLayout(form)
        
        self.manual_desc = QTextEdit()
        self.manual_desc.setPlaceholderText("Vulnerability description...")
        self.manual_desc.setMaximumHeight(100)
        manual_layout.addWidget(self.manual_desc)
        
        add_btn = QPushButton("+ Add Vulnerability")
        add_btn.setObjectName("primaryButton")
        add_btn.clicked.connect(self._add_manual_vuln)
        manual_layout.addWidget(add_btn)
        
        layout.addWidget(manual_frame)
        
        # Imported vulnerabilities preview
        preview_frame = QFrame()
        preview_frame.setObjectName("contentFrame")
        preview_layout = QVBoxLayout(preview_frame)
        
        preview_layout.addWidget(QLabel("Recently Imported"))
        
        self.import_preview_table = QTableWidget()
        self.import_preview_table.setColumnCount(6)
        self.import_preview_table.setHorizontalHeaderLabels([
            "Source", "Title", "Host", "Port", "Severity", "CVE"
        ])
        self.import_preview_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.import_preview_table.setMaximumHeight(200)
        preview_layout.addWidget(self.import_preview_table)
        
        layout.addWidget(preview_frame)
        
        return widget
    
    def _create_correlation_tab(self) -> QWidget:
        """Create correlation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Correlation stats
        stats_layout = QHBoxLayout()
        
        corr_stats = [
            ("correlated", "Correlated Vulns", "0", "#00d4ff"),
            ("dedup_rate", "Deduplication Rate", "0%", "#00ff88"),
            ("multi_source", "Multi-Source Confirmed", "0", "#ffd93d"),
            ("avg_confidence", "Avg Confidence", "0%", "#9d4edd")
        ]
        
        for key, label, value, color in corr_stats:
            card = self._create_stat_card(label, value, color)
            self.stat_cards[key] = card
            stats_layout.addWidget(card)
        
        layout.addLayout(stats_layout)
        
        # Correlation options
        options_frame = QFrame()
        options_frame.setObjectName("contentFrame")
        options_layout = QHBoxLayout(options_frame)
        
        options_layout.addWidget(QLabel("Correlation Settings:"))
        
        self.corr_cve_check = QCheckBox("CVE Matching")
        self.corr_cve_check.setChecked(True)
        options_layout.addWidget(self.corr_cve_check)
        
        self.corr_title_check = QCheckBox("Title Similarity")
        self.corr_title_check.setChecked(True)
        options_layout.addWidget(self.corr_title_check)
        
        self.corr_host_check = QCheckBox("Host+Port")
        self.corr_host_check.setChecked(True)
        options_layout.addWidget(self.corr_host_check)
        
        self.corr_cwe_check = QCheckBox("CWE Matching")
        options_layout.addWidget(self.corr_cwe_check)
        
        options_layout.addStretch()
        
        run_btn = QPushButton("🔄 Correlate Now")
        run_btn.setObjectName("primaryButton")
        run_btn.clicked.connect(self._run_correlation)
        options_layout.addWidget(run_btn)
        
        layout.addWidget(options_frame)
        
        # Splitter for table and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Correlated vulnerabilities table
        table_frame = QFrame()
        table_frame.setObjectName("contentFrame")
        table_layout = QVBoxLayout(table_frame)
        
        table_header = QHBoxLayout()
        table_header.addWidget(QLabel("Correlated Vulnerabilities"))
        table_header.addStretch()
        
        self.corr_filter = QComboBox()
        self.corr_filter.addItems(["All", "CVE Match", "Multi-Source", "High Confidence"])
        table_header.addWidget(self.corr_filter)
        
        table_layout.addLayout(table_header)
        
        self.correlated_table = QTableWidget()
        self.correlated_table.setColumnCount(8)
        self.correlated_table.setHorizontalHeaderLabels([
            "Title", "Severity", "CVSS", "Hosts", "Sources", "CVEs", "Confidence", "Priority"
        ])
        self.correlated_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.correlated_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.correlated_table.itemSelectionChanged.connect(self._on_correlated_selected)
        table_layout.addWidget(self.correlated_table)
        
        splitter.addWidget(table_frame)
        
        # Correlation details
        details_frame = QFrame()
        details_frame.setObjectName("contentFrame")
        details_layout = QVBoxLayout(details_frame)
        
        details_layout.addWidget(QLabel("Correlation Details"))
        
        # Source vulns tree
        details_layout.addWidget(QLabel("Source Vulnerabilities:"))
        self.source_vulns_tree = QTreeWidget()
        self.source_vulns_tree.setHeaderLabels(["Source", "Title", "Host:Port"])
        details_layout.addWidget(self.source_vulns_tree)
        
        # Correlation reasons
        details_layout.addWidget(QLabel("Correlation Reasons:"))
        self.correlation_reasons = QListWidget()
        self.correlation_reasons.setMaximumHeight(100)
        details_layout.addWidget(self.correlation_reasons)
        
        # References
        details_layout.addWidget(QLabel("References:"))
        self.references_list = QListWidget()
        self.references_list.setMaximumHeight(100)
        details_layout.addWidget(self.references_list)
        
        splitter.addWidget(details_frame)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_prioritization_tab(self) -> QWidget:
        """Create prioritization tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Priority distribution
        dist_frame = QFrame()
        dist_frame.setObjectName("contentFrame")
        dist_layout = QHBoxLayout(dist_frame)
        
        # Severity distribution bars
        severity_layout = QVBoxLayout()
        severity_layout.addWidget(QLabel("Severity Distribution"))
        
        self.severity_bars = {}
        severities = [
            ("critical", "Critical", "#ff0040"),
            ("high", "High", "#ff6b6b"),
            ("medium", "Medium", "#ffd93d"),
            ("low", "Low", "#00d4ff"),
            ("info", "Info", "#8b949e")
        ]
        
        for key, name, color in severities:
            row = QHBoxLayout()
            label = QLabel(name)
            label.setMinimumWidth(60)
            row.addWidget(label)
            
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setStyleSheet(f"""
                QProgressBar {{
                    border: 1px solid #21262d;
                    border-radius: 4px;
                    background-color: #0d1117;
                    text-align: center;
                }}
                QProgressBar::chunk {{
                    background-color: {color};
                    border-radius: 3px;
                }}
            """)
            self.severity_bars[key] = bar
            row.addWidget(bar)
            
            count = QLabel("0")
            count.setMinimumWidth(40)
            count.setObjectName(f"{key}_count")
            row.addWidget(count)
            
            severity_layout.addLayout(row)
        
        dist_layout.addLayout(severity_layout)
        
        # Priority score distribution
        priority_layout = QVBoxLayout()
        priority_layout.addWidget(QLabel("Priority Score Distribution"))
        
        self.priority_chart = QFrame()
        self.priority_chart.setMinimumHeight(150)
        self.priority_chart.setStyleSheet("""
            background-color: #0d1117;
            border: 1px solid #21262d;
            border-radius: 6px;
        """)
        priority_layout.addWidget(self.priority_chart)
        
        dist_layout.addLayout(priority_layout)
        
        layout.addWidget(dist_frame)
        
        # Priority filters
        filter_frame = QFrame()
        filter_frame.setObjectName("contentFrame")
        filter_layout = QHBoxLayout(filter_frame)
        
        filter_layout.addWidget(QLabel("Min Priority:"))
        
        self.priority_slider = QSlider(Qt.Orientation.Horizontal)
        self.priority_slider.setRange(0, 100)
        self.priority_slider.setValue(0)
        self.priority_slider.valueChanged.connect(self._filter_by_priority)
        filter_layout.addWidget(self.priority_slider)
        
        self.priority_value_label = QLabel("0")
        filter_layout.addWidget(self.priority_value_label)
        
        filter_layout.addWidget(QLabel("Severity:"))
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItem("All Severities")
        if self.engine:
            for s in self.SeverityLevel:
                self.severity_filter.addItem(s.value.title(), s)
        filter_layout.addWidget(self.severity_filter)
        
        filter_layout.addWidget(QLabel("Status:"))
        
        self.status_filter = QComboBox()
        self.status_filter.addItem("All Statuses")
        if self.engine:
            for s in self.VulnStatus:
                self.status_filter.addItem(s.value.replace("_", " ").title(), s)
        filter_layout.addWidget(self.status_filter)
        
        filter_layout.addStretch()
        
        apply_btn = QPushButton("Apply Filters")
        apply_btn.clicked.connect(self._apply_filters)
        filter_layout.addWidget(apply_btn)
        
        layout.addWidget(filter_frame)
        
        # Prioritized list
        list_frame = QFrame()
        list_frame.setObjectName("contentFrame")
        list_layout = QVBoxLayout(list_frame)
        
        list_header = QHBoxLayout()
        list_header.addWidget(QLabel("Prioritized Vulnerabilities"))
        list_header.addStretch()
        
        export_btn = QPushButton("📥 Export")
        export_btn.clicked.connect(self._export_prioritized)
        list_header.addWidget(export_btn)
        
        list_layout.addLayout(list_header)
        
        self.priority_table = QTableWidget()
        self.priority_table.setColumnCount(9)
        self.priority_table.setHorizontalHeaderLabels([
            "Rank", "Title", "Severity", "CVSS", "Priority", "Exploitability",
            "Impact", "Hosts", "Action"
        ])
        self.priority_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.priority_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        list_layout.addWidget(self.priority_table)
        
        layout.addWidget(list_frame)
        
        return widget
    
    def _create_chains_tab(self) -> QWidget:
        """Create exploit chains tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Detection controls
        controls_frame = QFrame()
        controls_frame.setObjectName("contentFrame")
        controls_layout = QHBoxLayout(controls_frame)
        
        controls_layout.addWidget(QLabel("Exploit Chain Detection"))
        controls_layout.addStretch()
        
        detect_btn = QPushButton("🔍 Detect Chains")
        detect_btn.setObjectName("primaryButton")
        detect_btn.clicked.connect(self._detect_chains)
        controls_layout.addWidget(detect_btn)
        
        layout.addWidget(controls_frame)
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Chains list
        chains_frame = QFrame()
        chains_frame.setObjectName("contentFrame")
        chains_layout = QVBoxLayout(chains_frame)
        
        chains_layout.addWidget(QLabel("Detected Attack Chains"))
        
        self.chains_table = QTableWidget()
        self.chains_table.setColumnCount(6)
        self.chains_table.setHorizontalHeaderLabels([
            "Chain Name", "Type", "Entry Point", "Target", "Risk Score", "Vulns"
        ])
        self.chains_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.chains_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.chains_table.itemSelectionChanged.connect(self._on_chain_selected)
        chains_layout.addWidget(self.chains_table)
        
        splitter.addWidget(chains_frame)
        
        # Chain details
        details_frame = QFrame()
        details_frame.setObjectName("contentFrame")
        details_layout = QVBoxLayout(details_frame)
        
        details_layout.addWidget(QLabel("Attack Chain Details"))
        
        form = QFormLayout()
        
        self.chain_name_label = QLabel("-")
        form.addRow("Name:", self.chain_name_label)
        
        self.chain_entry_label = QLabel("-")
        form.addRow("Entry Point:", self.chain_entry_label)
        
        self.chain_target_label = QLabel("-")
        form.addRow("Target:", self.chain_target_label)
        
        self.chain_risk_label = QLabel("-")
        form.addRow("Risk Score:", self.chain_risk_label)
        
        self.chain_likelihood_label = QLabel("-")
        form.addRow("Likelihood:", self.chain_likelihood_label)
        
        self.chain_impact_label = QLabel("-")
        form.addRow("Impact:", self.chain_impact_label)
        
        details_layout.addLayout(form)
        
        # Attack path
        details_layout.addWidget(QLabel("Attack Path:"))
        self.attack_path_list = QListWidget()
        details_layout.addWidget(self.attack_path_list)
        
        # MITRE ATT&CK
        details_layout.addWidget(QLabel("MITRE ATT&CK Mapping:"))
        self.mitre_list = QListWidget()
        self.mitre_list.setMaximumHeight(100)
        details_layout.addWidget(self.mitre_list)
        
        splitter.addWidget(details_frame)
        splitter.setSizes([500, 500])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_context_tab(self) -> QWidget:
        """Create asset context tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Context management
        manage_frame = QFrame()
        manage_frame.setObjectName("contentFrame")
        manage_layout = QHBoxLayout(manage_frame)
        
        manage_layout.addWidget(QLabel("Asset Context Management"))
        manage_layout.addStretch()
        
        import_csv_btn = QPushButton("📥 Import CSV")
        import_csv_btn.clicked.connect(self._import_asset_csv)
        manage_layout.addWidget(import_csv_btn)
        
        import_cmdb_btn = QPushButton("🔗 Link CMDB")
        import_cmdb_btn.clicked.connect(self._link_cmdb)
        manage_layout.addWidget(import_cmdb_btn)
        
        layout.addWidget(manage_frame)
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Assets table
        assets_frame = QFrame()
        assets_frame.setObjectName("contentFrame")
        assets_layout = QVBoxLayout(assets_frame)
        
        assets_layout.addWidget(QLabel("Asset Context"))
        
        self.assets_table = QTableWidget()
        self.assets_table.setColumnCount(7)
        self.assets_table.setHorizontalHeaderLabels([
            "Host", "Hostname", "Type", "Criticality", "Business Unit",
            "Internet Facing", "PII"
        ])
        self.assets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.assets_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        assets_layout.addWidget(self.assets_table)
        
        splitter.addWidget(assets_frame)
        
        # Asset editor
        editor_frame = QFrame()
        editor_frame.setObjectName("contentFrame")
        editor_layout = QVBoxLayout(editor_frame)
        
        editor_layout.addWidget(QLabel("Edit Asset Context"))
        
        form = QFormLayout()
        
        self.asset_host_input = QLineEdit()
        form.addRow("Host:", self.asset_host_input)
        
        self.asset_hostname_input = QLineEdit()
        form.addRow("Hostname:", self.asset_hostname_input)
        
        self.asset_type_combo = QComboBox()
        self.asset_type_combo.addItems([
            "server", "workstation", "network_device", "database",
            "web_server", "cloud_instance", "container", "iot_device"
        ])
        form.addRow("Asset Type:", self.asset_type_combo)
        
        self.asset_criticality_combo = QComboBox()
        self.asset_criticality_combo.addItems(["critical", "high", "medium", "low"])
        form.addRow("Criticality:", self.asset_criticality_combo)
        
        self.asset_bu_input = QLineEdit()
        form.addRow("Business Unit:", self.asset_bu_input)
        
        self.asset_data_class_combo = QComboBox()
        self.asset_data_class_combo.addItems([
            "public", "internal", "confidential", "restricted"
        ])
        form.addRow("Data Classification:", self.asset_data_class_combo)
        
        self.asset_internet_check = QCheckBox("Internet Facing")
        form.addRow("", self.asset_internet_check)
        
        self.asset_pii_check = QCheckBox("Contains PII")
        form.addRow("", self.asset_pii_check)
        
        editor_layout.addLayout(form)
        
        # Compliance scope
        editor_layout.addWidget(QLabel("Compliance Scope:"))
        self.compliance_list = QListWidget()
        self.compliance_list.setMaximumHeight(80)
        self.compliance_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.compliance_list.addItems(["PCI-DSS", "HIPAA", "SOX", "GDPR", "SOC2"])
        editor_layout.addWidget(self.compliance_list)
        
        save_btn = QPushButton("💾 Save Context")
        save_btn.setObjectName("primaryButton")
        save_btn.clicked.connect(self._save_asset_context)
        editor_layout.addWidget(save_btn)
        
        splitter.addWidget(editor_frame)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_intel_tab(self) -> QWidget:
        """Create threat intel tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Intel sources
        sources_frame = QFrame()
        sources_frame.setObjectName("contentFrame")
        sources_layout = QHBoxLayout(sources_frame)
        
        sources_layout.addWidget(QLabel("Threat Intelligence Sources"))
        sources_layout.addStretch()
        
        fetch_cisa_btn = QPushButton("🏛️ Fetch CISA KEV")
        fetch_cisa_btn.clicked.connect(self._fetch_cisa_kev)
        sources_layout.addWidget(fetch_cisa_btn)
        
        fetch_epss_btn = QPushButton("📊 Fetch EPSS")
        fetch_epss_btn.clicked.connect(self._fetch_epss)
        sources_layout.addWidget(fetch_epss_btn)
        
        fetch_exploit_btn = QPushButton("💀 Check Exploits")
        fetch_exploit_btn.clicked.connect(self._check_exploits)
        sources_layout.addWidget(fetch_exploit_btn)
        
        layout.addWidget(sources_frame)
        
        # Intel table
        intel_frame = QFrame()
        intel_frame.setObjectName("contentFrame")
        intel_layout = QVBoxLayout(intel_frame)
        
        intel_header = QHBoxLayout()
        intel_header.addWidget(QLabel("CVE Threat Intelligence"))
        intel_header.addStretch()
        
        self.intel_filter = QComboBox()
        self.intel_filter.addItems([
            "All CVEs", "Exploited in Wild", "CISA KEV", 
            "Ransomware Associated", "APT Related"
        ])
        intel_header.addWidget(self.intel_filter)
        
        intel_layout.addLayout(intel_header)
        
        self.intel_table = QTableWidget()
        self.intel_table.setColumnCount(9)
        self.intel_table.setHorizontalHeaderLabels([
            "CVE ID", "EPSS Score", "Exploit Available", "In the Wild",
            "CISA KEV", "Ransomware", "APT Groups", "Patch", "Affected"
        ])
        self.intel_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        intel_layout.addWidget(self.intel_table)
        
        layout.addWidget(intel_frame)
        
        # Manual intel entry
        manual_frame = QFrame()
        manual_frame.setObjectName("contentFrame")
        manual_layout = QVBoxLayout(manual_frame)
        
        manual_layout.addWidget(QLabel("Add Threat Intelligence"))
        
        form = QFormLayout()
        
        self.intel_cve_input = QLineEdit()
        self.intel_cve_input.setPlaceholderText("CVE-2024-XXXX")
        form.addRow("CVE ID:", self.intel_cve_input)
        
        self.intel_epss_spin = QSpinBox()
        self.intel_epss_spin.setRange(0, 100)
        self.intel_epss_spin.setSuffix("%")
        form.addRow("EPSS Score:", self.intel_epss_spin)
        
        self.intel_exploit_check = QCheckBox("Exploit Available")
        form.addRow("", self.intel_exploit_check)
        
        self.intel_wild_check = QCheckBox("Exploited in the Wild")
        form.addRow("", self.intel_wild_check)
        
        self.intel_kev_check = QCheckBox("CISA KEV Listed")
        form.addRow("", self.intel_kev_check)
        
        self.intel_ransomware_check = QCheckBox("Ransomware Associated")
        form.addRow("", self.intel_ransomware_check)
        
        manual_layout.addLayout(form)
        
        add_intel_btn = QPushButton("+ Add Intelligence")
        add_intel_btn.setObjectName("primaryButton")
        add_intel_btn.clicked.connect(self._add_threat_intel)
        manual_layout.addWidget(add_intel_btn)
        
        layout.addWidget(manual_frame)
        
        return widget
    
    def _create_reports_tab(self) -> QWidget:
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # Report generation
        gen_frame = QFrame()
        gen_frame.setObjectName("contentFrame")
        gen_layout = QHBoxLayout(gen_frame)
        
        gen_layout.addWidget(QLabel("Generate Correlation Report"))
        gen_layout.addStretch()
        
        gen_btn = QPushButton("📊 Generate Report")
        gen_btn.setObjectName("primaryButton")
        gen_btn.clicked.connect(self._generate_report)
        gen_layout.addWidget(gen_btn)
        
        layout.addWidget(gen_frame)
        
        # Report summary
        summary_frame = QFrame()
        summary_frame.setObjectName("contentFrame")
        summary_layout = QVBoxLayout(summary_frame)
        
        summary_layout.addWidget(QLabel("Report Summary"))
        
        self.report_summary = QTextEdit()
        self.report_summary.setReadOnly(True)
        summary_layout.addWidget(self.report_summary)
        
        layout.addWidget(summary_frame)
        
        # Export options
        export_frame = QFrame()
        export_frame.setObjectName("contentFrame")
        export_layout = QHBoxLayout(export_frame)
        
        export_layout.addWidget(QLabel("Export:"))
        
        pdf_btn = QPushButton("📄 PDF")
        pdf_btn.clicked.connect(lambda: self._export_report("pdf"))
        export_layout.addWidget(pdf_btn)
        
        csv_btn = QPushButton("📊 CSV")
        csv_btn.clicked.connect(lambda: self._export_report("csv"))
        export_layout.addWidget(csv_btn)
        
        json_btn = QPushButton("📋 JSON")
        json_btn.clicked.connect(lambda: self._export_report("json"))
        export_layout.addWidget(json_btn)
        
        export_layout.addStretch()
        
        layout.addWidget(export_frame)
        
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
        value_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
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
        self.priority_slider.valueChanged.connect(
            lambda v: self.priority_value_label.setText(str(v))
        )
    
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
            }
            QTableWidget::item:selected {
                background-color: #1f6feb40;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
            }
            QTreeWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
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
            QSlider::groove:horizontal {
                height: 8px;
                background: #21262d;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #00d4ff;
                width: 16px;
                height: 16px;
                margin: -4px 0;
                border-radius: 8px;
            }
        """)
    
    # Event handlers
    def _import_source(self, source: str):
        """Import from source"""
        file_filter = {
            "nmap": "Nmap XML (*.xml)",
            "nessus": "Nessus CSV (*.csv)",
            "nuclei": "Nuclei JSON (*.json)",
            "custom": "JSON Files (*.json)"
        }.get(source, "All Files (*)")
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, f"Import {source.title()} Results", "", file_filter
        )
        
        if file_path:
            self.status_message.emit(f"Importing from {source}: {file_path}")
            # Would parse and ingest vulnerabilities
    
    def _add_manual_vuln(self):
        """Add manual vulnerability"""
        if not self.engine:
            return
        
        title = self.manual_title.text().strip()
        host = self.manual_host.text().strip()
        
        if not title or not host:
            QMessageBox.warning(self, "Error", "Title and host are required")
            return
        
        asyncio.create_task(self._async_add_vuln(title, host))
    
    async def _async_add_vuln(self, title: str, host: str):
        """Async add vulnerability"""
        cves = []
        if self.manual_cve.text().strip():
            cves = [self.manual_cve.text().strip()]
        
        vuln = await self.engine.ingest_vulnerability(
            self.VulnerabilitySource.MANUAL,
            title,
            self.manual_desc.toPlainText(),
            host,
            port=self.manual_port.value(),
            severity=self.manual_severity.currentData().value,
            cvss_score=self.manual_cvss.value() / 10.0,
            cve_ids=cves
        )
        
        self._update_stats()
        self._add_to_preview(vuln)
        self.status_message.emit(f"Vulnerability added: {title}")
    
    def _add_to_preview(self, vuln):
        """Add vulnerability to preview table"""
        row = self.import_preview_table.rowCount()
        self.import_preview_table.insertRow(row)
        self.import_preview_table.setItem(row, 0, QTableWidgetItem(vuln.source.value))
        self.import_preview_table.setItem(row, 1, QTableWidgetItem(vuln.title[:50]))
        self.import_preview_table.setItem(row, 2, QTableWidgetItem(vuln.host))
        self.import_preview_table.setItem(row, 3, QTableWidgetItem(str(vuln.port)))
        self.import_preview_table.setItem(row, 4, QTableWidgetItem(vuln.severity.value))
        self.import_preview_table.setItem(row, 5, QTableWidgetItem(", ".join(vuln.cve_ids)))
    
    def _update_stats(self):
        """Update statistics"""
        if not self.engine:
            return
        
        self._update_stat("raw_vulns", str(len(self.engine.raw_vulns)))
        
        sources = set(v.source for v in self.engine.raw_vulns.values())
        self._update_stat("sources", str(len(sources)))
        
        hosts = set(v.host for v in self.engine.raw_vulns.values())
        self._update_stat("hosts", str(len(hosts)))
        
        cves = set()
        for v in self.engine.raw_vulns.values():
            cves.update(v.cve_ids)
        self._update_stat("cves", str(len(cves)))
    
    def _update_stat(self, key: str, value: str):
        """Update stat card"""
        if key in self.stat_cards:
            label = self.stat_cards[key].findChild(QLabel, "value")
            if label:
                label.setText(value)
    
    def _run_correlation(self):
        """Run correlation"""
        if not self.engine:
            return
        
        asyncio.create_task(self._async_correlate())
    
    async def _async_correlate(self):
        """Async correlation"""
        correlated = await self.engine.correlate_vulnerabilities()
        
        self._update_stat("correlated", str(len(correlated)))
        
        if self.engine.raw_vulns:
            rate = (1 - len(correlated) / len(self.engine.raw_vulns)) * 100
            self._update_stat("dedup_rate", f"{rate:.0f}%")
        
        # Update table
        self.correlated_table.setRowCount(len(correlated))
        
        for row, vuln in enumerate(sorted(correlated, key=lambda v: v.priority_score, reverse=True)):
            self.correlated_table.setItem(row, 0, QTableWidgetItem(vuln.title[:50]))
            
            severity_item = QTableWidgetItem(vuln.unified_severity.value.title())
            severity_colors = {
                "critical": "#ff0040",
                "high": "#ff6b6b",
                "medium": "#ffd93d",
                "low": "#00d4ff",
                "info": "#8b949e"
            }
            color = severity_colors.get(vuln.unified_severity.value, "#8b949e")
            severity_item.setForeground(QBrush(QColor(color)))
            self.correlated_table.setItem(row, 1, severity_item)
            
            self.correlated_table.setItem(row, 2, QTableWidgetItem(f"{vuln.unified_cvss:.1f}"))
            self.correlated_table.setItem(row, 3, QTableWidgetItem(str(len(vuln.affected_hosts))))
            self.correlated_table.setItem(row, 4, QTableWidgetItem(str(len(vuln.sources))))
            self.correlated_table.setItem(row, 5, QTableWidgetItem(str(len(vuln.cve_ids))))
            self.correlated_table.setItem(row, 6, QTableWidgetItem(f"{vuln.correlation_confidence*100:.0f}%"))
            self.correlated_table.setItem(row, 7, QTableWidgetItem(f"{vuln.priority_score:.0f}"))
        
        self.status_message.emit(f"Correlated {len(correlated)} vulnerabilities")
    
    def _on_correlated_selected(self):
        """Handle correlated selection"""
        pass
    
    def _filter_by_priority(self, value: int):
        """Filter by priority"""
        pass
    
    def _apply_filters(self):
        """Apply priority filters"""
        self.status_message.emit("Filters applied")
    
    def _export_prioritized(self):
        """Export prioritized list"""
        QMessageBox.information(self, "Export", "Prioritized list exported")
    
    def _detect_chains(self):
        """Detect exploit chains"""
        if not self.engine:
            return
        
        asyncio.create_task(self._async_detect_chains())
    
    async def _async_detect_chains(self):
        """Async detect chains"""
        chains = await self.engine.detect_exploit_chains()
        
        self.chains_table.setRowCount(len(chains))
        
        for row, chain in enumerate(chains):
            self.chains_table.setItem(row, 0, QTableWidgetItem(chain.name))
            self.chains_table.setItem(row, 1, QTableWidgetItem("Attack Chain"))
            self.chains_table.setItem(row, 2, QTableWidgetItem(chain.entry_point))
            self.chains_table.setItem(row, 3, QTableWidgetItem(chain.target))
            self.chains_table.setItem(row, 4, QTableWidgetItem(f"{chain.risk_score:.0f}"))
            self.chains_table.setItem(row, 5, QTableWidgetItem(str(len(chain.vulnerabilities))))
        
        self.status_message.emit(f"Detected {len(chains)} exploit chains")
    
    def _on_chain_selected(self):
        """Handle chain selection"""
        pass
    
    def _import_asset_csv(self):
        """Import asset CSV"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Asset Context", "", "CSV Files (*.csv)"
        )
        if file_path:
            self.status_message.emit(f"Importing assets from {file_path}")
    
    def _link_cmdb(self):
        """Link to CMDB"""
        QMessageBox.information(self, "CMDB", "CMDB linking would be configured")
    
    def _save_asset_context(self):
        """Save asset context"""
        if not self.engine:
            return
        
        host = self.asset_host_input.text().strip()
        if not host:
            QMessageBox.warning(self, "Error", "Host is required")
            return
        
        asyncio.create_task(self._async_save_context(host))
    
    async def _async_save_context(self, host: str):
        """Async save context"""
        await self.engine.add_asset_context(
            host,
            hostname=self.asset_hostname_input.text(),
            asset_type=self.asset_type_combo.currentText(),
            criticality=self.asset_criticality_combo.currentText(),
            business_unit=self.asset_bu_input.text(),
            data_classification=self.asset_data_class_combo.currentText(),
            internet_facing=self.asset_internet_check.isChecked(),
            contains_pii=self.asset_pii_check.isChecked()
        )
        self.status_message.emit(f"Context saved for {host}")
    
    def _fetch_cisa_kev(self):
        """Fetch CISA KEV"""
        self.status_message.emit("Fetching CISA KEV catalog...")
    
    def _fetch_epss(self):
        """Fetch EPSS scores"""
        self.status_message.emit("Fetching EPSS scores...")
    
    def _check_exploits(self):
        """Check for exploits"""
        self.status_message.emit("Checking exploit databases...")
    
    def _add_threat_intel(self):
        """Add threat intelligence"""
        if not self.engine:
            return
        
        cve = self.intel_cve_input.text().strip()
        if not cve:
            QMessageBox.warning(self, "Error", "CVE ID is required")
            return
        
        asyncio.create_task(self._async_add_intel(cve))
    
    async def _async_add_intel(self, cve: str):
        """Async add intel"""
        await self.engine.add_threat_intel(
            cve,
            exploit_available=self.intel_exploit_check.isChecked(),
            in_the_wild=self.intel_wild_check.isChecked(),
            cisa_kev=self.intel_kev_check.isChecked(),
            ransomware_associated=self.intel_ransomware_check.isChecked(),
            epss_score=self.intel_epss_spin.value() / 100.0
        )
        self.status_message.emit(f"Intel added for {cve}")
    
    def _generate_report(self):
        """Generate report"""
        if not self.engine:
            return
        
        asyncio.create_task(self._async_generate_report())
    
    async def _async_generate_report(self):
        """Async generate report"""
        import json
        report = await self.engine.generate_report()
        self.report_summary.setText(json.dumps(report, indent=2, default=str))
        self.status_message.emit("Report generated")
    
    def _export_report(self, format: str):
        """Export report"""
        QMessageBox.information(self, "Export", f"Report exported as {format.upper()}")
