"""
Threat Intelligence Page
GUI for real-time threat intelligence aggregation and analysis
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QComboBox, QCheckBox, QProgressBar,
    QSplitter, QFrame, QHeaderView, QTreeWidget, QTreeWidgetItem,
    QGridLayout, QPlainTextEdit, QListWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor
import asyncio
import json


class ThreatAnalysisWorker(QThread):
    """Worker thread for threat analysis"""
    progress = pyqtSignal(str)
    result = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, target, config):
        super().__init__()
        self.target = target
        self.config = config
        
    def run(self):
        try:
            import sys
            sys.path.insert(0, '..')
            from core.threat_intel import ThreatIntelligence
            
            async def analyze():
                ti = ThreatIntelligence(self.config)
                self.progress.emit(f"Analyzing {self.target}...")
                return await ti.analyze_target(self.target)
                
            result = asyncio.run(analyze())
            self.result.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class IOCFeedWorker(QThread):
    """Worker thread for fetching IOC feeds"""
    progress = pyqtSignal(str)
    result = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def __init__(self, feed_type):
        super().__init__()
        self.feed_type = feed_type
        
    def run(self):
        try:
            import sys
            sys.path.insert(0, '..')
            from core.threat_intel import ThreatIntelligence
            
            async def fetch():
                ti = ThreatIntelligence()
                self.progress.emit(f"Fetching {self.feed_type} feed...")
                return await ti.get_ioc_feed(self.feed_type)
                
            result = asyncio.run(fetch())
            self.result.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class ThreatIntelPage(QWidget):
    """Threat Intelligence Dashboard"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.analysis_worker = None
        self.feed_worker = None
        self.current_report = None
        
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Setup the user interface"""
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
                border: 1px solid #30363d;
                border-radius: 8px;
                background: #0d1117;
            }
            QTabBar::tab {
                background: #21262d;
                color: #8b949e;
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #0d1117;
                color: #00ff88;
            }
        """)
        
        # Create tabs
        self.tabs.addTab(self._create_analysis_tab(), "🔍 IOC Analysis")
        self.tabs.addTab(self._create_feeds_tab(), "📡 Threat Feeds")
        self.tabs.addTab(self._create_reports_tab(), "📊 Reports")
        self.tabs.addTab(self._create_settings_tab(), "⚙️ API Settings")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QWidget:
        """Create the page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1f29, stop:1 #0d1117);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🛡️ Threat Intelligence")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            color: #e6e6e6;
        """)
        
        subtitle = QLabel("Real-time threat intelligence from Shodan, VirusTotal, AbuseIPDB & more")
        subtitle.setStyleSheet("""
            font-size: 13px;
            color: #8b949e;
        """)
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Quick stats
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(20)
        
        self.stats = {
            'queries': self._create_stat_widget("Queries Today", "0"),
            'threats': self._create_stat_widget("Threats Found", "0"),
            'feeds': self._create_stat_widget("Active Feeds", "5"),
        }
        
        for stat in self.stats.values():
            stats_layout.addWidget(stat)
        
        layout.addLayout(stats_layout)
        
        return header
    
    def _create_stat_widget(self, label: str, value: str) -> QFrame:
        """Create a stat display widget"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setObjectName(f"stat_{label.lower().replace(' ', '_')}")
        value_label.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #00ff88;
        """)
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("""
            font-size: 11px;
            color: #8b949e;
        """)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(value_label)
        layout.addWidget(name_label)
        
        return frame
    
    def _create_analysis_tab(self) -> QWidget:
        """Create IOC analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Search section
        search_group = QGroupBox("Analyze Indicator of Compromise")
        search_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
            }
        """)
        
        search_layout = QVBoxLayout(search_group)
        
        input_layout = QHBoxLayout()
        
        self.ioc_input = QLineEdit()
        self.ioc_input.setPlaceholderText("Enter IP, domain, URL, file hash, or email...")
        self.ioc_input.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 12px;
                color: #e6e6e6;
                font-size: 14px;
            }
        """)
        
        self.analyze_btn = QPushButton("🔍 Analyze")
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1f6feb, stop:1 #388bfd);
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #388bfd, stop:1 #58a6ff);
            }
        """)
        self.analyze_btn.clicked.connect(self._analyze_ioc)
        
        input_layout.addWidget(self.ioc_input)
        input_layout.addWidget(self.analyze_btn)
        search_layout.addLayout(input_layout)
        
        # IOC type indicators
        type_layout = QHBoxLayout()
        
        ioc_types = [
            ("🌐 IP Address", "#3fb950"),
            ("🔗 Domain", "#1f6feb"),
            ("🔒 URL", "#8957e5"),
            ("📁 File Hash", "#f0883e"),
            ("📧 Email", "#da3633"),
        ]
        
        for text, color in ioc_types:
            label = QLabel(text)
            label.setStyleSheet(f"""
                background: {color}20;
                color: {color};
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
            """)
            type_layout.addWidget(label)
        
        type_layout.addStretch()
        search_layout.addLayout(type_layout)
        
        layout.addWidget(search_group)
        
        # Results section
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Summary
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        summary_group = QGroupBox("Threat Summary")
        summary_group.setStyleSheet(search_group.styleSheet())
        
        summary_layout = QVBoxLayout(summary_group)
        
        self.risk_score_label = QLabel("Risk Score: --")
        self.risk_score_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #8b949e;
            padding: 10px;
        """)
        self.risk_score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        summary_layout.addWidget(self.risk_score_label)
        
        self.threat_level_label = QLabel("Threat Level: Unknown")
        self.threat_level_label.setStyleSheet("""
            font-size: 16px;
            color: #8b949e;
            padding: 5px;
        """)
        self.threat_level_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        summary_layout.addWidget(self.threat_level_label)
        
        # Source indicators
        sources_layout = QGridLayout()
        
        self.source_indicators = {}
        sources = [
            ("Shodan", "shodan"),
            ("VirusTotal", "virustotal"),
            ("AbuseIPDB", "abuseipdb"),
            ("ThreatCrowd", "threatcrowd"),
        ]
        
        for i, (name, key) in enumerate(sources):
            indicator = QLabel(f"⚪ {name}")
            indicator.setStyleSheet("color: #8b949e; padding: 5px;")
            self.source_indicators[key] = indicator
            sources_layout.addWidget(indicator, i // 2, i % 2)
        
        summary_layout.addLayout(sources_layout)
        
        # Recommendations
        self.recommendations_list = QListWidget()
        self.recommendations_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #21262d;
            }
        """)
        self.recommendations_list.setMaximumHeight(150)
        summary_layout.addWidget(QLabel("Recommendations:"))
        summary_layout.addWidget(self.recommendations_list)
        
        left_layout.addWidget(summary_group)
        splitter.addWidget(left_widget)
        
        # Right panel - Detailed Results
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        details_group = QGroupBox("Detailed Findings")
        details_group.setStyleSheet(search_group.styleSheet())
        
        details_layout = QVBoxLayout(details_group)
        
        self.indicators_table = QTableWidget()
        self.indicators_table.setColumnCount(5)
        self.indicators_table.setHorizontalHeaderLabels([
            "Type", "Value", "Threat Level", "Confidence", "Source"
        ])
        self.indicators_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.indicators_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 8px;
                color: #e6e6e6;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        details_layout.addWidget(self.indicators_table)
        
        right_layout.addWidget(details_group)
        splitter.addWidget(right_widget)
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background: #21262d;
                border: none;
                border-radius: 6px;
                height: 6px;
            }
            QProgressBar::chunk {
                background: #1f6feb;
                border-radius: 6px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        return widget
    
    def _create_feeds_tab(self) -> QWidget:
        """Create threat feeds tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Feed controls
        control_layout = QHBoxLayout()
        
        self.feed_combo = QComboBox()
        self.feed_combo.addItems([
            "All Feeds",
            "Feodo Tracker (Botnet C2)",
            "URLhaus (Malicious URLs)",
            "MalwareBazaar (File Hashes)",
        ])
        self.feed_combo.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
                min-width: 200px;
            }
        """)
        
        refresh_btn = QPushButton("🔄 Refresh Feeds")
        refresh_btn.clicked.connect(self._refresh_feeds)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }
            QPushButton:hover { background: #2ea043; }
        """)
        
        export_btn = QPushButton("📤 Export IOCs")
        export_btn.clicked.connect(self._export_iocs)
        export_btn.setStyleSheet(refresh_btn.styleSheet().replace("#238636", "#1f6feb").replace("#2ea043", "#388bfd"))
        
        control_layout.addWidget(self.feed_combo)
        control_layout.addWidget(refresh_btn)
        control_layout.addWidget(export_btn)
        control_layout.addStretch()
        
        layout.addLayout(control_layout)
        
        # Feed statistics
        stats_frame = QFrame()
        stats_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        
        stats_layout = QHBoxLayout(stats_frame)
        
        feed_stats = [
            ("Total IOCs", "0", "#3fb950"),
            ("IPs", "0", "#1f6feb"),
            ("URLs", "0", "#8957e5"),
            ("Hashes", "0", "#f0883e"),
            ("Domains", "0", "#da3633"),
        ]
        
        for name, value, color in feed_stats:
            stat_widget = QVBoxLayout()
            val_label = QLabel(value)
            val_label.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {color};")
            val_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            name_label = QLabel(name)
            name_label.setStyleSheet("font-size: 11px; color: #8b949e;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_widget.addWidget(val_label)
            stat_widget.addWidget(name_label)
            stats_layout.addLayout(stat_widget)
        
        layout.addWidget(stats_frame)
        
        # IOC feed table
        self.feed_table = QTableWidget()
        self.feed_table.setColumnCount(6)
        self.feed_table.setHorizontalHeaderLabels([
            "Type", "Value", "Threat Level", "Tags", "Source", "First Seen"
        ])
        self.feed_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.feed_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 8px;
                color: #e6e6e6;
                font-family: monospace;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.feed_table)
        
        # Feed progress
        self.feed_progress = QProgressBar()
        self.feed_progress.setVisible(False)
        self.feed_progress.setStyleSheet(self.progress_bar.styleSheet() if hasattr(self, 'progress_bar') else """
            QProgressBar {
                background: #21262d;
                border: none;
                border-radius: 6px;
                height: 6px;
            }
            QProgressBar::chunk {
                background: #1f6feb;
                border-radius: 6px;
            }
        """)
        layout.addWidget(self.feed_progress)
        
        return widget
    
    def _create_reports_tab(self) -> QWidget:
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Report history
        history_group = QGroupBox("Analysis History")
        history_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
            }
        """)
        
        history_layout = QVBoxLayout(history_group)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels([
            "Target", "Type", "Risk Score", "Threat Level", "Analyzed"
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.history_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
        """)
        history_layout.addWidget(self.history_table)
        
        # Export options
        export_layout = QHBoxLayout()
        
        export_json_btn = QPushButton("Export JSON")
        export_json_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        
        export_stix_btn = QPushButton("Export STIX 2.1")
        export_stix_btn.setStyleSheet(export_json_btn.styleSheet())
        
        export_csv_btn = QPushButton("Export CSV")
        export_csv_btn.setStyleSheet(export_json_btn.styleSheet())
        
        clear_btn = QPushButton("Clear History")
        clear_btn.setStyleSheet(export_json_btn.styleSheet().replace("#21262d", "#da3633"))
        
        export_layout.addWidget(export_json_btn)
        export_layout.addWidget(export_stix_btn)
        export_layout.addWidget(export_csv_btn)
        export_layout.addStretch()
        export_layout.addWidget(clear_btn)
        
        history_layout.addLayout(export_layout)
        layout.addWidget(history_group)
        
        return widget
    
    def _create_settings_tab(self) -> QWidget:
        """Create API settings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # API Keys
        api_group = QGroupBox("API Keys Configuration")
        api_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
            }
        """)
        
        api_layout = QGridLayout(api_group)
        
        apis = [
            ("Shodan API Key:", "shodan", "https://shodan.io"),
            ("VirusTotal API Key:", "virustotal", "https://virustotal.com"),
            ("AbuseIPDB API Key:", "abuseipdb", "https://abuseipdb.com"),
            ("AlienVault OTX Key:", "alienvault", "https://otx.alienvault.com"),
            ("URLScan.io API Key:", "urlscan", "https://urlscan.io"),
        ]
        
        self.api_inputs = {}
        
        for i, (label, key, url) in enumerate(apis):
            lbl = QLabel(label)
            lbl.setStyleSheet("color: #e6e6e6;")
            api_layout.addWidget(lbl, i, 0)
            
            input_field = QLineEdit()
            input_field.setEchoMode(QLineEdit.EchoMode.Password)
            input_field.setPlaceholderText("Enter API key...")
            input_field.setStyleSheet("""
                QLineEdit {
                    background: #0d1117;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 8px;
                    color: #e6e6e6;
                }
            """)
            self.api_inputs[key] = input_field
            api_layout.addWidget(input_field, i, 1)
            
            get_key_btn = QPushButton("Get Key")
            get_key_btn.setStyleSheet("""
                QPushButton {
                    background: #1f6feb;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 8px 12px;
                }
                QPushButton:hover { background: #388bfd; }
            """)
            api_layout.addWidget(get_key_btn, i, 2)
        
        # Save button
        save_btn = QPushButton("💾 Save API Keys")
        save_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:hover { background: #2ea043; }
        """)
        api_layout.addWidget(save_btn, len(apis), 0, 1, 3)
        
        layout.addWidget(api_group)
        
        # Status indicators
        status_group = QGroupBox("API Status")
        status_group.setStyleSheet(api_group.styleSheet())
        
        status_layout = QGridLayout(status_group)
        
        for i, (label, key, url) in enumerate(apis):
            name = label.replace(" API Key:", "")
            status_label = QLabel(f"⚪ {name}: Not configured")
            status_label.setStyleSheet("color: #8b949e;")
            status_layout.addWidget(status_label, i // 2, i % 2)
        
        layout.addWidget(status_group)
        layout.addStretch()
        
        return widget
    
    def _connect_signals(self):
        """Connect widget signals"""
        self.ioc_input.returnPressed.connect(self._analyze_ioc)
    
    def _analyze_ioc(self):
        """Start IOC analysis"""
        target = self.ioc_input.text().strip()
        if not target:
            return
        
        # Get API keys from settings
        config = {}
        for key, input_field in self.api_inputs.items():
            if input_field.text():
                config[f'{key}_api_key'] = input_field.text()
        
        self.analysis_worker = ThreatAnalysisWorker(target, config)
        self.analysis_worker.progress.connect(self._on_analysis_progress)
        self.analysis_worker.result.connect(self._on_analysis_result)
        self.analysis_worker.error.connect(self._on_analysis_error)
        
        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        
        self.analysis_worker.start()
    
    def _on_analysis_progress(self, message: str):
        """Handle analysis progress update"""
        pass  # Could update a status label
    
    def _on_analysis_result(self, report):
        """Handle analysis result"""
        self.current_report = report
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        # Update risk score
        color = self._get_threat_color(report.threat_level.value)
        self.risk_score_label.setText(f"Risk Score: {report.risk_score}/100")
        self.risk_score_label.setStyleSheet(f"""
            font-size: 24px;
            font-weight: bold;
            color: {color};
            padding: 10px;
        """)
        
        self.threat_level_label.setText(f"Threat Level: {report.threat_level.value.upper()}")
        self.threat_level_label.setStyleSheet(f"""
            font-size: 16px;
            color: {color};
            padding: 5px;
        """)
        
        # Update source indicators
        if report.shodan_data:
            self.source_indicators['shodan'].setText("🟢 Shodan")
            self.source_indicators['shodan'].setStyleSheet("color: #3fb950; padding: 5px;")
        
        if report.virustotal_data:
            self.source_indicators['virustotal'].setText("🟢 VirusTotal")
            self.source_indicators['virustotal'].setStyleSheet("color: #3fb950; padding: 5px;")
        
        if report.abuseipdb_data:
            self.source_indicators['abuseipdb'].setText("🟢 AbuseIPDB")
            self.source_indicators['abuseipdb'].setStyleSheet("color: #3fb950; padding: 5px;")
        
        # Update recommendations
        self.recommendations_list.clear()
        for rec in report.recommendations:
            self.recommendations_list.addItem(rec)
        
        # Update indicators table
        self.indicators_table.setRowCount(0)
        for indicator in report.indicators:
            row = self.indicators_table.rowCount()
            self.indicators_table.insertRow(row)
            
            self.indicators_table.setItem(row, 0, QTableWidgetItem(indicator.ioc_type.value))
            self.indicators_table.setItem(row, 1, QTableWidgetItem(indicator.value[:50]))
            
            level_item = QTableWidgetItem(indicator.threat_level.value)
            level_item.setForeground(QColor(self._get_threat_color(indicator.threat_level.value)))
            self.indicators_table.setItem(row, 2, level_item)
            
            self.indicators_table.setItem(row, 3, QTableWidgetItem(f"{indicator.confidence}%"))
            self.indicators_table.setItem(row, 4, QTableWidgetItem(", ".join(indicator.sources)))
    
    def _on_analysis_error(self, error: str):
        """Handle analysis error"""
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.risk_score_label.setText(f"Error: {error}")
        self.risk_score_label.setStyleSheet("""
            font-size: 14px;
            color: #f85149;
            padding: 10px;
        """)
    
    def _get_threat_color(self, level: str) -> str:
        """Get color for threat level"""
        colors = {
            'critical': '#da3633',
            'high': '#f85149',
            'medium': '#d29922',
            'low': '#3fb950',
            'info': '#1f6feb',
            'unknown': '#8b949e',
        }
        return colors.get(level.lower(), '#8b949e')
    
    def _refresh_feeds(self):
        """Refresh threat feeds"""
        feed_type = "all"
        if self.feed_combo.currentIndex() == 1:
            feed_type = "feodo"
        elif self.feed_combo.currentIndex() == 2:
            feed_type = "urlhaus"
        
        self.feed_worker = IOCFeedWorker(feed_type)
        self.feed_worker.result.connect(self._on_feeds_loaded)
        self.feed_worker.error.connect(lambda e: print(f"Feed error: {e}"))
        
        self.feed_progress.setVisible(True)
        self.feed_progress.setRange(0, 0)
        
        self.feed_worker.start()
    
    def _on_feeds_loaded(self, indicators: list):
        """Handle loaded feeds"""
        self.feed_progress.setVisible(False)
        
        self.feed_table.setRowCount(0)
        for indicator in indicators[:100]:  # Limit display
            row = self.feed_table.rowCount()
            self.feed_table.insertRow(row)
            
            self.feed_table.setItem(row, 0, QTableWidgetItem(indicator.ioc_type.value))
            self.feed_table.setItem(row, 1, QTableWidgetItem(indicator.value[:60]))
            
            level_item = QTableWidgetItem(indicator.threat_level.value)
            level_item.setForeground(QColor(self._get_threat_color(indicator.threat_level.value)))
            self.feed_table.setItem(row, 2, level_item)
            
            self.feed_table.setItem(row, 3, QTableWidgetItem(", ".join(indicator.tags[:3])))
            self.feed_table.setItem(row, 4, QTableWidgetItem(", ".join(indicator.sources)))
            self.feed_table.setItem(row, 5, QTableWidgetItem(
                indicator.first_seen.strftime("%Y-%m-%d") if indicator.first_seen else ""
            ))
    
    def _export_iocs(self):
        """Export IOCs"""
        # TODO: Implement export dialog
        pass
