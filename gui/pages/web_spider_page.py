#!/usr/bin/env python3
"""
Advanced Web Spider Page - Beyond Burp Suite Pro
Comprehensive web crawler GUI with AI-powered discovery and attack capabilities.
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
    QTableWidget, QTableWidgetItem, QTabWidget, QComboBox,
    QSpinBox, QCheckBox, QSplitter, QTreeWidget, QTreeWidgetItem,
    QHeaderView, QMenu, QDialog, QDialogButtonBox, QFormLayout,
    QMessageBox, QFileDialog, QListWidget, QListWidgetItem,
    QDoubleSpinBox, QPlainTextEdit, QFrame, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont, QAction, QIcon

import asyncio
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    from core.advanced_web_spider import (
        AdvancedWebSpider, AuthType, RequestMethod, ContentType,
        Endpoint, Parameter, Form, CrawlResult, ParameterLocation
    )
except ImportError:
    AdvancedWebSpider = None
    Endpoint = None
    Parameter = None
    Form = None
    CrawlResult = None
    AuthType = None
    RequestMethod = None
    ContentType = None
    ParameterLocation = None

try:
    from core.spider_ai_engine import (
        NeuralEndpointPredictor, SmartFuzzer, ResponseAnalyzer,
        ContentAnalyzer, GraphQLIntrospector, CORSAnalyzer,
        HTTPRequestSmuggler, CachePoisioningDetector
    )
except ImportError:
    NeuralEndpointPredictor = None
    SmartFuzzer = None
    ResponseAnalyzer = None
    ContentAnalyzer = None
    GraphQLIntrospector = None
    CORSAnalyzer = None
    HTTPRequestSmuggler = None
    CachePoisioningDetector = None


class SpiderWorker(QThread):
    """Worker thread for web spider"""
    
    endpoint_discovered = pyqtSignal(dict)
    form_discovered = pyqtSignal(dict)
    vulnerability_found = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)  # visited, discovered
    status_update = pyqtSignal(str)
    crawl_complete = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, target: str, config: Dict):
        super().__init__()
        self.target = target
        self.config = config
        self.spider = None
        self._running = False
    
    def run(self):
        """Run the spider in thread"""
        self._running = True
        
        try:
            self.spider = AdvancedWebSpider()
            
            # Apply configuration
            self.spider.max_depth = self.config.get('max_depth', 10)
            self.spider.max_pages = self.config.get('max_pages', 1000)
            self.spider.request_delay = self.config.get('request_delay', 0.5)
            self.spider.timeout = self.config.get('timeout', 30)
            self.spider.max_concurrent = self.config.get('max_concurrent', 10)
            self.spider.user_agent = self.config.get('user_agent', 'HydraSpider/2.0')
            
            # Set callbacks
            self.spider.on_endpoint_discovered = lambda e: self.endpoint_discovered.emit(self._endpoint_to_dict(e))
            self.spider.on_form_discovered = lambda f: self.form_discovered.emit(vars(f) if hasattr(f, '__dict__') else f)
            self.spider.on_vulnerability_found = lambda v: self.vulnerability_found.emit(v)
            self.spider.on_progress_update = lambda v, d: self.progress_update.emit(v, d)
            
            # Set authentication if provided
            auth_type_str = self.config.get('auth_type', 'NONE')
            if auth_type_str != 'NONE':
                auth_type = AuthType[auth_type_str]
                self.spider.set_authentication(auth_type, self.config.get('auth_credentials', {}))
            
            # Set custom headers
            if self.config.get('custom_headers'):
                for header in self.config['custom_headers']:
                    if ':' in header:
                        key, value = header.split(':', 1)
                        self.spider.headers[key.strip()] = value.strip()
            
            # Set cookies
            if self.config.get('cookies'):
                for cookie in self.config['cookies']:
                    if '=' in cookie:
                        key, value = cookie.split('=', 1)
                        self.spider.cookies[key.strip()] = value.strip()
            
            # Set exclusions
            for pattern in self.config.get('exclude_patterns', []):
                self.spider.add_exclude_pattern(pattern)
            
            self.status_update.emit("Starting crawl...")
            
            # Run async crawl
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.spider.crawl(self.target))
            loop.close()
            
            if self._running:
                self.crawl_complete.emit(self._result_to_dict(result))
        
        except Exception as e:
            self.error_occurred.emit(str(e))
    
    def stop(self):
        """Stop the spider"""
        self._running = False
        if self.spider:
            self.spider.stop()
    
    def _endpoint_to_dict(self, endpoint) -> Dict:
        """Convert endpoint to dict"""
        if endpoint is None:
            return {}
        try:
            return {
                'url': getattr(endpoint, 'url', ''),
                'method': getattr(endpoint.method, 'value', 'GET') if hasattr(endpoint, 'method') else 'GET',
                'content_type': getattr(endpoint.content_type, 'name', 'HTML') if hasattr(endpoint, 'content_type') else 'HTML',
                'status': endpoint.response_codes[0] if hasattr(endpoint, 'response_codes') and endpoint.response_codes else 0,
                'size': getattr(endpoint, 'response_size', 0),
                'time': getattr(endpoint, 'response_time', 0),
                'technologies': getattr(endpoint, 'technologies', []),
                'parameters': [vars(p) for p in getattr(endpoint, 'parameters', [])],
                'forms': getattr(endpoint, 'forms', []),
                'vulnerabilities': getattr(endpoint, 'vulnerabilities', []),
                'links': len(getattr(endpoint, 'links', [])),
                'comments': len(getattr(endpoint, 'comments', []))
            }
        except Exception:
            return {'url': str(endpoint), 'method': 'GET', 'status': 0}
    
    def _result_to_dict(self, result) -> Dict:
        """Convert result to dict"""
        if result is None:
            return {}
        try:
            return {
                'target': getattr(result, 'target', ''),
                'start_time': str(getattr(result, 'start_time', '')),
                'end_time': str(getattr(result, 'end_time', '')),
                'total_endpoints': len(getattr(result, 'endpoints', [])),
                'total_parameters': len(getattr(result, 'parameters', [])),
                'total_forms': len(getattr(result, 'forms', [])),
                'total_vulnerabilities': len(getattr(result, 'vulnerabilities', [])),
                'technologies': getattr(result, 'technologies', []),
                'api_endpoints': getattr(result, 'api_endpoints', []),
                'graphql_endpoints': getattr(result, 'graphql_endpoints', []),
                'websocket_endpoints': getattr(result, 'websocket_endpoints', []),
                'authentication_endpoints': getattr(result, 'authentication_endpoints', []),
                'interesting_files': getattr(result, 'interesting_files', []),
                'robots_txt': getattr(result, 'robots_txt', ''),
                'sitemap_urls': getattr(result, 'sitemap_urls', []),
                'total_requests': getattr(result, 'total_requests', 0),
                'total_errors': getattr(result, 'total_errors', 0),
                'coverage': getattr(result, 'coverage_percentage', 0)
            }
        except Exception:
            return {}


class WebSpiderPage(QWidget):
    """Advanced Web Spider Page"""
    
    def __init__(self, config=None, db=None):
        super().__init__()
        self.config = config or {}
        self.db = db
        self.worker: Optional[SpiderWorker] = None
        
        # Data storage
        self.endpoints: List[Dict] = []
        self.parameters: List[Dict] = []
        self.forms: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(5)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Header
        header_layout = QHBoxLayout()
        
        title = QLabel("🕷️ Advanced Web Spider")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #00ff88;")
        header_layout.addWidget(title)
        
        subtitle = QLabel("Beyond Burp Suite Pro - AI-Powered Discovery")
        subtitle.setStyleSheet("color: #888; font-size: 11px;")
        header_layout.addWidget(subtitle)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        
        # Left panel - Configuration
        left_panel = self._create_config_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = self._create_results_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([350, 850])
        splitter.setStretchFactor(0, 0)  # Don't stretch config panel
        splitter.setStretchFactor(1, 1)  # Stretch results panel
        layout.addWidget(splitter, 1)  # Give splitter stretch priority
        
        # Status bar
        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(0, 5, 0, 0)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #00ff88;")
        status_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        status_layout.addWidget(self.progress_bar)
        
        self.stats_label = QLabel("")
        self.stats_label.setStyleSheet("color: #888;")
        status_layout.addWidget(self.stats_label)
        
        status_layout.addStretch()
        layout.addLayout(status_layout)
    
    def _create_config_panel(self) -> QWidget:
        """Create configuration panel"""
        # Create scroll area for config panel
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setMinimumWidth(350)
        scroll.setMaximumWidth(450)
        
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(8)
        
        # Target group
        target_group = QGroupBox("🎯 Target")
        target_layout = QVBoxLayout(target_group)
        
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("URL:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com")
        url_layout.addWidget(self.target_input)
        target_layout.addLayout(url_layout)
        
        # Quick targets
        quick_layout = QHBoxLayout()
        quick_targets = [
            ("localhost:8080", "http://localhost:8080"),
            ("localhost:3000", "http://localhost:3000"),
            ("127.0.0.1", "http://127.0.0.1"),
        ]
        for name, url in quick_targets:
            btn = QPushButton(name)
            btn.setMaximumWidth(100)
            btn.clicked.connect(lambda checked, u=url: self.target_input.setText(u))
            quick_layout.addWidget(btn)
        quick_layout.addStretch()
        target_layout.addLayout(quick_layout)
        
        layout.addWidget(target_group)
        
        # Crawl settings group
        settings_group = QGroupBox("⚙️ Crawl Settings")
        settings_layout = QGridLayout(settings_group)
        
        settings_layout.addWidget(QLabel("Max Depth:"), 0, 0)
        self.max_depth_spin = QSpinBox()
        self.max_depth_spin.setRange(1, 50)
        self.max_depth_spin.setValue(10)
        settings_layout.addWidget(self.max_depth_spin, 0, 1)
        
        settings_layout.addWidget(QLabel("Max Pages:"), 0, 2)
        self.max_pages_spin = QSpinBox()
        self.max_pages_spin.setRange(10, 100000)
        self.max_pages_spin.setValue(1000)
        settings_layout.addWidget(self.max_pages_spin, 0, 3)
        
        settings_layout.addWidget(QLabel("Request Delay (s):"), 1, 0)
        self.delay_spin = QDoubleSpinBox()
        self.delay_spin.setRange(0, 10)
        self.delay_spin.setValue(0.5)
        self.delay_spin.setSingleStep(0.1)
        settings_layout.addWidget(self.delay_spin, 1, 1)
        
        settings_layout.addWidget(QLabel("Timeout (s):"), 1, 2)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 120)
        self.timeout_spin.setValue(30)
        settings_layout.addWidget(self.timeout_spin, 1, 3)
        
        settings_layout.addWidget(QLabel("Concurrent:"), 2, 0)
        self.concurrent_spin = QSpinBox()
        self.concurrent_spin.setRange(1, 50)
        self.concurrent_spin.setValue(10)
        settings_layout.addWidget(self.concurrent_spin, 2, 1)
        
        layout.addWidget(settings_group)
        
        # User Agent group
        ua_group = QGroupBox("🔧 User Agent")
        ua_layout = QVBoxLayout(ua_group)
        
        self.user_agent_combo = QComboBox()
        self.user_agent_combo.setEditable(True)
        self.user_agent_combo.addItems([
            "HydraSpider/2.0 (Advanced Security Scanner)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        ])
        ua_layout.addWidget(self.user_agent_combo)
        
        layout.addWidget(ua_group)
        
        # Authentication group
        auth_group = QGroupBox("🔐 Authentication")
        auth_layout = QFormLayout(auth_group)
        
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems(["NONE", "BASIC", "BEARER", "API_KEY", "COOKIE", "JWT"])
        self.auth_type_combo.currentTextChanged.connect(self._on_auth_type_changed)
        auth_layout.addRow("Type:", self.auth_type_combo)
        
        self.auth_user_input = QLineEdit()
        self.auth_user_input.setPlaceholderText("Username")
        self.auth_user_input.setVisible(False)
        auth_layout.addRow("Username:", self.auth_user_input)
        
        self.auth_pass_input = QLineEdit()
        self.auth_pass_input.setPlaceholderText("Password / Token / API Key")
        self.auth_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.auth_pass_input.setVisible(False)
        auth_layout.addRow("Credential:", self.auth_pass_input)
        
        layout.addWidget(auth_group)
        
        # Advanced options
        advanced_group = QGroupBox("🚀 Advanced Options")
        advanced_layout = QVBoxLayout(advanced_group)
        
        self.include_subdomains_check = QCheckBox("Include Subdomains")
        self.include_subdomains_check.setChecked(True)
        advanced_layout.addWidget(self.include_subdomains_check)
        
        self.mine_params_check = QCheckBox("Deep Parameter Mining")
        self.mine_params_check.setChecked(True)
        advanced_layout.addWidget(self.mine_params_check)
        
        self.detect_vulns_check = QCheckBox("Real-time Vulnerability Detection")
        self.detect_vulns_check.setChecked(True)
        advanced_layout.addWidget(self.detect_vulns_check)
        
        self.fingerprint_check = QCheckBox("Technology Fingerprinting")
        self.fingerprint_check.setChecked(True)
        advanced_layout.addWidget(self.fingerprint_check)
        
        self.extract_comments_check = QCheckBox("Extract Code Comments")
        self.extract_comments_check.setChecked(True)
        advanced_layout.addWidget(self.extract_comments_check)
        
        self.discover_apis_check = QCheckBox("API Endpoint Discovery")
        self.discover_apis_check.setChecked(True)
        advanced_layout.addWidget(self.discover_apis_check)
        
        layout.addWidget(advanced_group)
        
        # Custom headers
        headers_group = QGroupBox("📋 Custom Headers")
        headers_layout = QVBoxLayout(headers_group)
        
        self.headers_text = QPlainTextEdit()
        self.headers_text.setPlaceholderText("Header: Value\nX-Custom: test")
        self.headers_text.setMaximumHeight(60)
        headers_layout.addWidget(self.headers_text)
        
        layout.addWidget(headers_group)
        
        # Exclusions
        exclusions_group = QGroupBox("🚫 Exclusions")
        exclusions_layout = QVBoxLayout(exclusions_group)
        
        self.exclusions_text = QPlainTextEdit()
        self.exclusions_text.setPlaceholderText(".*\\.jpg$\n.*\\.png$\n.*/logout.*")
        self.exclusions_text.setMaximumHeight(60)
        exclusions_layout.addWidget(self.exclusions_text)
        
        layout.addWidget(exclusions_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 Start Spider")
        self.start_btn.setStyleSheet("background-color: #00aa55; font-weight: bold; padding: 10px;")
        self.start_btn.clicked.connect(self._start_crawl)
        button_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setStyleSheet("background-color: #aa5500; padding: 10px;")
        self.stop_btn.clicked.connect(self._stop_crawl)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        layout.addLayout(button_layout)
        
        # Export button
        export_layout = QHBoxLayout()
        
        self.export_btn = QPushButton("📥 Export Results")
        self.export_btn.clicked.connect(self._export_results)
        export_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.clicked.connect(self._clear_results)
        export_layout.addWidget(self.clear_btn)
        
        layout.addLayout(export_layout)
        
        layout.addStretch()
        
        scroll.setWidget(panel)
        return scroll
    
    def _create_results_panel(self) -> QWidget:
        """Create results panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Tabs for different result types
        self.results_tabs = QTabWidget()
        self.results_tabs.setDocumentMode(True)  # Cleaner look
        self.results_tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.results_tabs.setUsesScrollButtons(True)  # Enable scroll when tabs overflow
        self.results_tabs.setElideMode(Qt.TextElideMode.ElideNone)  # Don't cut text
        self.results_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #333;
                background: #1a1a2e;
            }
            QTabBar::tab {
                background: #252540;
                color: #ccc;
                padding: 6px 10px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                min-width: 50px;
            }
            QTabBar::tab:selected {
                background: #00aa55;
                color: white;
            }
            QTabBar::tab:hover {
                background: #353560;
            }
        """)
        
        # Site Map tab
        sitemap_tab = self._create_sitemap_tab()
        self.results_tabs.addTab(sitemap_tab, "🗺️ Map")
        
        # Endpoints tab
        endpoints_tab = self._create_endpoints_tab()
        self.results_tabs.addTab(endpoints_tab, "🔗 URLs")
        
        # Parameters tab
        params_tab = self._create_params_tab()
        self.results_tabs.addTab(params_tab, "📊 Params")
        
        # Forms tab
        forms_tab = self._create_forms_tab()
        self.results_tabs.addTab(forms_tab, "📝 Forms")
        
        # Vulnerabilities tab
        vulns_tab = self._create_vulns_tab()
        self.results_tabs.addTab(vulns_tab, "⚠️ Vulns")
        
        # Technologies tab
        tech_tab = self._create_tech_tab()
        self.results_tabs.addTab(tech_tab, "🔧 Tech")
        
        # API Discovery tab
        api_tab = self._create_api_tab()
        self.results_tabs.addTab(api_tab, "🌐 APIs")
        
        # AI Predictions tab
        predictions_tab = self._create_predictions_tab()
        self.results_tabs.addTab(predictions_tab, "🧠 AI")
        
        # Smart Fuzzer tab
        fuzzer_tab = self._create_fuzzer_tab()
        self.results_tabs.addTab(fuzzer_tab, "💉 Fuzz")
        
        # Content Analysis tab
        content_tab = self._create_content_tab()
        self.results_tabs.addTab(content_tab, "📝 Intel")
        
        # Advanced Attacks tab
        attacks_tab = self._create_attacks_tab()
        self.results_tabs.addTab(attacks_tab, "⚡ Attacks")
        
        layout.addWidget(self.results_tabs, 1)  # Stretch factor 1
        
        return panel
    
    def _create_sitemap_tab(self) -> QWidget:
        """Create site map tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.sitemap_tree = QTreeWidget()
        self.sitemap_tree.setHeaderLabels(["URL", "Status", "Size", "Type"])
        self.sitemap_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.sitemap_tree.customContextMenuRequested.connect(self._show_sitemap_context_menu)
        self.sitemap_tree.itemDoubleClicked.connect(self._on_sitemap_item_double_clicked)
        
        header = self.sitemap_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.sitemap_tree)
        
        return widget
    
    def _create_endpoints_tab(self) -> QWidget:
        """Create endpoints tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Filter bar
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Filter:"))
        self.endpoint_filter = QLineEdit()
        self.endpoint_filter.setPlaceholderText("Filter by URL...")
        self.endpoint_filter.textChanged.connect(self._filter_endpoints)
        filter_layout.addWidget(self.endpoint_filter)
        
        self.method_filter = QComboBox()
        self.method_filter.addItems(["All Methods", "GET", "POST", "PUT", "DELETE"])
        self.method_filter.currentTextChanged.connect(self._filter_endpoints)
        filter_layout.addWidget(self.method_filter)
        
        layout.addLayout(filter_layout)
        
        self.endpoints_table = QTableWidget()
        self.endpoints_table.setColumnCount(8)
        self.endpoints_table.setHorizontalHeaderLabels([
            "URL", "Method", "Status", "Size", "Time (ms)", "Params", "Vulns", "Tech"
        ])
        self.endpoints_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.endpoints_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.endpoints_table.customContextMenuRequested.connect(self._show_endpoint_context_menu)
        self.endpoints_table.itemDoubleClicked.connect(self._on_endpoint_double_clicked)
        self.endpoints_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.endpoints_table)
        
        return widget
    
    def _create_params_tab(self) -> QWidget:
        """Create parameters tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Stats
        stats_layout = QHBoxLayout()
        self.params_stats_label = QLabel("Total Parameters: 0")
        stats_layout.addWidget(self.params_stats_label)
        stats_layout.addStretch()
        layout.addLayout(stats_layout)
        
        self.params_table = QTableWidget()
        self.params_table.setColumnCount(6)
        self.params_table.setHorizontalHeaderLabels([
            "Name", "Location", "Type", "Value", "Reflected", "Found In"
        ])
        self.params_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.params_table.setAlternatingRowColors(True)
        self.params_table.itemDoubleClicked.connect(self._on_param_double_clicked)
        
        layout.addWidget(self.params_table)
        
        return widget
    
    def _create_forms_tab(self) -> QWidget:
        """Create forms tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.forms_table = QTableWidget()
        self.forms_table.setColumnCount(6)
        self.forms_table.setHorizontalHeaderLabels([
            "Action", "Method", "Inputs", "CSRF", "File Upload", "Type"
        ])
        self.forms_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.forms_table.setAlternatingRowColors(True)
        self.forms_table.itemDoubleClicked.connect(self._on_form_double_clicked)
        
        layout.addWidget(self.forms_table)
        
        return widget
    
    def _create_vulns_tab(self) -> QWidget:
        """Create vulnerabilities tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Stats
        stats_layout = QHBoxLayout()
        self.vulns_stats_label = QLabel("Total Findings: 0")
        self.vulns_stats_label.setStyleSheet("color: #ff5555;")
        stats_layout.addWidget(self.vulns_stats_label)
        stats_layout.addStretch()
        layout.addLayout(stats_layout)
        
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(4)
        self.vulns_table.setHorizontalHeaderLabels([
            "Type", "Severity", "URL", "Evidence"
        ])
        self.vulns_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.vulns_table.setAlternatingRowColors(True)
        self.vulns_table.itemDoubleClicked.connect(self._on_vuln_double_clicked)
        
        layout.addWidget(self.vulns_table)
        
        return widget
    
    def _create_tech_tab(self) -> QWidget:
        """Create technologies tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.tech_tree = QTreeWidget()
        self.tech_tree.setHeaderLabels(["Technology", "Count", "URLs"])
        self.tech_tree.setAlternatingRowColors(True)
        
        layout.addWidget(self.tech_tree)
        
        return widget
    
    def _create_api_tab(self) -> QWidget:
        """Create API discovery tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # API types tabs
        api_tabs = QTabWidget()
        
        # REST APIs
        rest_widget = QWidget()
        rest_layout = QVBoxLayout(rest_widget)
        self.rest_table = QTableWidget()
        self.rest_table.setColumnCount(3)
        self.rest_table.setHorizontalHeaderLabels(["URL", "Method", "Parameters"])
        self.rest_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        rest_layout.addWidget(self.rest_table)
        api_tabs.addTab(rest_widget, "REST APIs")
        
        # GraphQL
        graphql_widget = QWidget()
        graphql_layout = QVBoxLayout(graphql_widget)
        self.graphql_list = QListWidget()
        graphql_layout.addWidget(self.graphql_list)
        api_tabs.addTab(graphql_widget, "GraphQL")
        
        # WebSockets
        ws_widget = QWidget()
        ws_layout = QVBoxLayout(ws_widget)
        self.websocket_list = QListWidget()
        ws_layout.addWidget(self.websocket_list)
        api_tabs.addTab(ws_widget, "WebSockets")
        
        # Auth Endpoints
        auth_widget = QWidget()
        auth_layout = QVBoxLayout(auth_widget)
        self.auth_list = QListWidget()
        auth_layout.addWidget(self.auth_list)
        api_tabs.addTab(auth_widget, "Auth Endpoints")
        
        layout.addWidget(api_tabs)
        
        return widget
    
    def _create_predictions_tab(self) -> QWidget:
        """Create AI predictions tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info label
        info_label = QLabel("🧠 Neural Endpoint Predictor - AI-powered hidden endpoint discovery")
        info_label.setStyleSheet("color: #00ffaa; font-weight: bold;")
        layout.addWidget(info_label)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.predict_btn = QPushButton("🔮 Generate Predictions")
        self.predict_btn.clicked.connect(self._generate_predictions)
        controls_layout.addWidget(self.predict_btn)
        
        self.verify_predictions_btn = QPushButton("✅ Verify Predictions")
        self.verify_predictions_btn.clicked.connect(self._verify_predictions)
        controls_layout.addWidget(self.verify_predictions_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Predictions table
        self.predictions_table = QTableWidget()
        self.predictions_table.setColumnCount(5)
        self.predictions_table.setHorizontalHeaderLabels([
            "Predicted URL", "Confidence", "Reason", "Pattern Source", "Status"
        ])
        self.predictions_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.predictions_table.setAlternatingRowColors(True)
        layout.addWidget(self.predictions_table)
        
        return widget
    
    def _create_fuzzer_tab(self) -> QWidget:
        """Create smart fuzzer tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info label
        info_label = QLabel("💉 Context-Aware Smart Fuzzer - Intelligent payload generation based on parameter context")
        info_label.setStyleSheet("color: #ff8855; font-weight: bold;")
        layout.addWidget(info_label)
        
        # Splitter for controls and results
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Fuzzer controls
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        
        # Target parameter selection
        param_group = QGroupBox("Target Parameter")
        param_layout = QFormLayout(param_group)
        
        self.fuzz_param_combo = QComboBox()
        self.fuzz_param_combo.currentTextChanged.connect(self._on_fuzz_param_selected)
        param_layout.addRow("Parameter:", self.fuzz_param_combo)
        
        self.fuzz_location_label = QLabel("Location: -")
        param_layout.addRow(self.fuzz_location_label)
        
        self.fuzz_context_label = QLabel("Context: -")
        param_layout.addRow(self.fuzz_context_label)
        
        controls_layout.addWidget(param_group)
        
        # Attack types
        attack_group = QGroupBox("Attack Types")
        attack_layout = QVBoxLayout(attack_group)
        
        self.attack_checks = {}
        attack_types = [
            ("xss", "XSS (Cross-Site Scripting)"),
            ("sqli", "SQL Injection"),
            ("ssti", "Server-Side Template Injection"),
            ("command_injection", "Command Injection"),
            ("path_traversal", "Path Traversal / LFI"),
            ("ssrf", "Server-Side Request Forgery"),
            ("xxe", "XML External Entity"),
            ("nosqli", "NoSQL Injection"),
        ]
        
        for attack_id, attack_name in attack_types:
            check = QCheckBox(attack_name)
            check.setChecked(True)
            self.attack_checks[attack_id] = check
            attack_layout.addWidget(check)
        
        controls_layout.addWidget(attack_group)
        
        # Fuzz button
        self.start_fuzz_btn = QPushButton("🚀 Start Fuzzing")
        self.start_fuzz_btn.setStyleSheet("background-color: #aa5500; font-weight: bold; padding: 10px;")
        self.start_fuzz_btn.clicked.connect(self._start_fuzzing)
        controls_layout.addWidget(self.start_fuzz_btn)
        
        controls_layout.addStretch()
        splitter.addWidget(controls_widget)
        
        # Right: Fuzzer results
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)
        
        results_layout.addWidget(QLabel("Fuzzing Results:"))
        
        self.fuzz_results_table = QTableWidget()
        self.fuzz_results_table.setColumnCount(5)
        self.fuzz_results_table.setHorizontalHeaderLabels([
            "Payload", "Attack Type", "Status", "Length", "Interesting"
        ])
        self.fuzz_results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.fuzz_results_table.setAlternatingRowColors(True)
        results_layout.addWidget(self.fuzz_results_table)
        
        splitter.addWidget(results_widget)
        splitter.setSizes([300, 500])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_content_tab(self) -> QWidget:
        """Create content intelligence tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info label
        info_label = QLabel("📝 Content Intelligence - Extract valuable data from crawled content")
        info_label.setStyleSheet("color: #55aaff; font-weight: bold;")
        layout.addWidget(info_label)
        
        # Sub-tabs for different content types
        content_tabs = QTabWidget()
        
        # Wordlist tab
        wordlist_widget = QWidget()
        wordlist_layout = QVBoxLayout(wordlist_widget)
        
        wordlist_controls = QHBoxLayout()
        self.generate_wordlist_btn = QPushButton("📝 Generate Custom Wordlist")
        self.generate_wordlist_btn.clicked.connect(self._generate_wordlist)
        wordlist_controls.addWidget(self.generate_wordlist_btn)
        
        self.export_wordlist_btn = QPushButton("💾 Export Wordlist")
        self.export_wordlist_btn.clicked.connect(self._export_wordlist)
        wordlist_controls.addWidget(self.export_wordlist_btn)
        wordlist_controls.addStretch()
        wordlist_layout.addLayout(wordlist_controls)
        
        self.wordlist_text = QPlainTextEdit()
        self.wordlist_text.setPlaceholderText("Custom wordlist will appear here...")
        wordlist_layout.addWidget(self.wordlist_text)
        content_tabs.addTab(wordlist_widget, "Custom Wordlist")
        
        # Secrets tab
        secrets_widget = QWidget()
        secrets_layout = QVBoxLayout(secrets_widget)
        self.secrets_table = QTableWidget()
        self.secrets_table.setColumnCount(3)
        self.secrets_table.setHorizontalHeaderLabels(["Type", "Value", "Source"])
        self.secrets_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        secrets_layout.addWidget(self.secrets_table)
        content_tabs.addTab(secrets_widget, "🔐 Discovered Secrets")
        
        # Emails tab
        emails_widget = QWidget()
        emails_layout = QVBoxLayout(emails_widget)
        self.emails_list = QListWidget()
        emails_layout.addWidget(self.emails_list)
        content_tabs.addTab(emails_widget, "📧 Emails")
        
        # Subdomains tab
        subdomains_widget = QWidget()
        subdomains_layout = QVBoxLayout(subdomains_widget)
        self.subdomains_list = QListWidget()
        subdomains_layout.addWidget(self.subdomains_list)
        content_tabs.addTab(subdomains_widget, "🌐 Subdomains")
        
        # Comments tab
        comments_widget = QWidget()
        comments_layout = QVBoxLayout(comments_widget)
        self.comments_table = QTableWidget()
        self.comments_table.setColumnCount(2)
        self.comments_table.setHorizontalHeaderLabels(["Comment", "Source"])
        self.comments_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        comments_layout.addWidget(self.comments_table)
        content_tabs.addTab(comments_widget, "💬 Code Comments")
        
        layout.addWidget(content_tabs)
        
        return widget
    
    def _create_attacks_tab(self) -> QWidget:
        """Create advanced attacks tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info label
        info_label = QLabel("⚡ Advanced Attack Modules - Cutting-edge vulnerability detection")
        info_label.setStyleSheet("color: #ff5555; font-weight: bold;")
        layout.addWidget(info_label)
        
        # Attack modules tabs
        attack_tabs = QTabWidget()
        
        # CORS Analyzer
        cors_widget = QWidget()
        cors_layout = QVBoxLayout(cors_widget)
        
        cors_controls = QHBoxLayout()
        self.test_cors_btn = QPushButton("🔍 Test CORS Configuration")
        self.test_cors_btn.clicked.connect(self._test_cors)
        cors_controls.addWidget(self.test_cors_btn)
        cors_controls.addStretch()
        cors_layout.addLayout(cors_controls)
        
        self.cors_results_table = QTableWidget()
        self.cors_results_table.setColumnCount(4)
        self.cors_results_table.setHorizontalHeaderLabels(["URL", "ACAO", "ACAC", "Vulnerable"])
        self.cors_results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        cors_layout.addWidget(self.cors_results_table)
        attack_tabs.addTab(cors_widget, "🔓 CORS Misconfiguration")
        
        # HTTP Smuggling
        smuggling_widget = QWidget()
        smuggling_layout = QVBoxLayout(smuggling_widget)
        
        smuggling_controls = QHBoxLayout()
        self.test_smuggling_btn = QPushButton("🔍 Test HTTP Request Smuggling")
        self.test_smuggling_btn.clicked.connect(self._test_smuggling)
        smuggling_controls.addWidget(self.test_smuggling_btn)
        smuggling_controls.addStretch()
        smuggling_layout.addLayout(smuggling_controls)
        
        self.smuggling_results_table = QTableWidget()
        self.smuggling_results_table.setColumnCount(4)
        self.smuggling_results_table.setHorizontalHeaderLabels(["URL", "Type", "Detection", "Evidence"])
        self.smuggling_results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        smuggling_layout.addWidget(self.smuggling_results_table)
        attack_tabs.addTab(smuggling_widget, "🚢 HTTP Smuggling")
        
        # Cache Poisoning
        cache_widget = QWidget()
        cache_layout = QVBoxLayout(cache_widget)
        
        cache_controls = QHBoxLayout()
        self.test_cache_btn = QPushButton("🔍 Test Cache Poisoning")
        self.test_cache_btn.clicked.connect(self._test_cache_poisoning)
        cache_controls.addWidget(self.test_cache_btn)
        cache_controls.addStretch()
        cache_layout.addLayout(cache_controls)
        
        self.cache_results_table = QTableWidget()
        self.cache_results_table.setColumnCount(4)
        self.cache_results_table.setHorizontalHeaderLabels(["URL", "Header", "Reflected", "Cacheable"])
        self.cache_results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        cache_layout.addWidget(self.cache_results_table)
        attack_tabs.addTab(cache_widget, "☠️ Cache Poisoning")
        
        # GraphQL Introspection
        graphql_attack_widget = QWidget()
        graphql_attack_layout = QVBoxLayout(graphql_attack_widget)
        
        graphql_controls = QHBoxLayout()
        self.introspect_btn = QPushButton("🔍 Run GraphQL Introspection")
        self.introspect_btn.clicked.connect(self._run_graphql_introspection)
        graphql_controls.addWidget(self.introspect_btn)
        
        self.generate_queries_btn = QPushButton("📝 Generate Attack Queries")
        self.generate_queries_btn.clicked.connect(self._generate_graphql_queries)
        graphql_controls.addWidget(self.generate_queries_btn)
        graphql_controls.addStretch()
        graphql_attack_layout.addLayout(graphql_controls)
        
        self.graphql_schema_text = QPlainTextEdit()
        self.graphql_schema_text.setPlaceholderText("GraphQL schema will appear here...")
        graphql_attack_layout.addWidget(self.graphql_schema_text)
        attack_tabs.addTab(graphql_attack_widget, "📊 GraphQL Attack")
        
        # Anomaly Detection
        anomaly_widget = QWidget()
        anomaly_layout = QVBoxLayout(anomaly_widget)
        
        anomaly_layout.addWidget(QLabel("Response anomalies detected during crawl:"))
        
        self.anomaly_table = QTableWidget()
        self.anomaly_table.setColumnCount(4)
        self.anomaly_table.setHorizontalHeaderLabels(["URL", "Type", "Score", "Details"])
        self.anomaly_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        anomaly_layout.addWidget(self.anomaly_table)
        attack_tabs.addTab(anomaly_widget, "🎯 Anomaly Detection")
        
        layout.addWidget(attack_tabs)
        
        return widget

    def _on_auth_type_changed(self, auth_type: str):
        """Handle auth type change"""
        show_creds = auth_type != "NONE"
        self.auth_user_input.setVisible(auth_type == "BASIC")
        self.auth_pass_input.setVisible(show_creds)
    
    def _start_crawl(self):
        """Start the web spider"""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
            self.target_input.setText(target)
        
        if AdvancedWebSpider is None:
            QMessageBox.critical(self, "Error", "Advanced Web Spider module not available")
            return
        
        # Build config
        config = {
            'max_depth': self.max_depth_spin.value(),
            'max_pages': self.max_pages_spin.value(),
            'request_delay': self.delay_spin.value(),
            'timeout': self.timeout_spin.value(),
            'max_concurrent': self.concurrent_spin.value(),
            'user_agent': self.user_agent_combo.currentText(),
            'auth_type': self.auth_type_combo.currentText(),
            'auth_credentials': {
                'username': self.auth_user_input.text(),
                'token': self.auth_pass_input.text(),
                'key': self.auth_pass_input.text(),
            },
            'custom_headers': [h for h in self.headers_text.toPlainText().split('\n') if h.strip()],
            'exclude_patterns': [p for p in self.exclusions_text.toPlainText().split('\n') if p.strip()],
        }
        
        # Clear previous results
        self._clear_results()
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText("Crawling...")
        
        # Start worker
        self.worker = SpiderWorker(target, config)
        self.worker.endpoint_discovered.connect(self._on_endpoint_discovered)
        self.worker.form_discovered.connect(self._on_form_discovered)
        self.worker.vulnerability_found.connect(self._on_vulnerability_found)
        self.worker.progress_update.connect(self._on_progress_update)
        self.worker.status_update.connect(self._on_status_update)
        self.worker.crawl_complete.connect(self._on_crawl_complete)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.start()
    
    def _stop_crawl(self):
        """Stop the web spider"""
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        
        self._reset_ui()
        self.status_label.setText("Stopped")
    
    def _reset_ui(self):
        """Reset UI state"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
    
    def _clear_results(self):
        """Clear all results"""
        self.endpoints.clear()
        self.parameters.clear()
        self.forms.clear()
        self.vulnerabilities.clear()
        
        self.sitemap_tree.clear()
        self.endpoints_table.setRowCount(0)
        self.params_table.setRowCount(0)
        self.forms_table.setRowCount(0)
        self.vulns_table.setRowCount(0)
        self.tech_tree.clear()
        self.rest_table.setRowCount(0)
        self.graphql_list.clear()
        self.websocket_list.clear()
        self.auth_list.clear()
        
        self.params_stats_label.setText("Total Parameters: 0")
        self.vulns_stats_label.setText("Total Findings: 0")
        self.stats_label.setText("")
    
    def _on_endpoint_discovered(self, endpoint: Dict):
        """Handle discovered endpoint"""
        self.endpoints.append(endpoint)
        self._add_endpoint_to_table(endpoint)
        self._add_to_sitemap(endpoint)
        
        # Add parameters
        for param in endpoint.get('parameters', []):
            self.parameters.append(param)
            self._add_param_to_table(param)
        
        # Update fuzzer parameter list
        self._update_fuzz_params()
    
    def _add_endpoint_to_table(self, endpoint: Dict):
        """Add endpoint to table"""
        row = self.endpoints_table.rowCount()
        self.endpoints_table.insertRow(row)
        
        url_item = QTableWidgetItem(endpoint.get('url', ''))
        url_item.setData(Qt.ItemDataRole.UserRole, endpoint)
        self.endpoints_table.setItem(row, 0, url_item)
        
        self.endpoints_table.setItem(row, 1, QTableWidgetItem(endpoint.get('method', 'GET')))
        
        status = endpoint.get('status', 0)
        status_item = QTableWidgetItem(str(status))
        if status >= 400:
            status_item.setForeground(QColor('#ff5555'))
        elif status >= 300:
            status_item.setForeground(QColor('#ffaa55'))
        else:
            status_item.setForeground(QColor('#55ff55'))
        self.endpoints_table.setItem(row, 2, status_item)
        
        self.endpoints_table.setItem(row, 3, QTableWidgetItem(f"{endpoint.get('size', 0):,}"))
        self.endpoints_table.setItem(row, 4, QTableWidgetItem(f"{endpoint.get('time', 0)*1000:.0f}"))
        self.endpoints_table.setItem(row, 5, QTableWidgetItem(str(len(endpoint.get('parameters', [])))))
        
        vulns_count = len(endpoint.get('vulnerabilities', []))
        vuln_item = QTableWidgetItem(str(vulns_count))
        if vulns_count > 0:
            vuln_item.setForeground(QColor('#ff5555'))
        self.endpoints_table.setItem(row, 6, vuln_item)
        
        self.endpoints_table.setItem(row, 7, QTableWidgetItem(', '.join(endpoint.get('technologies', [])[:3])))
    
    def _add_to_sitemap(self, endpoint: Dict):
        """Add endpoint to sitemap tree"""
        url = endpoint.get('url', '')
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path_parts = [p for p in parsed.path.split('/') if p]
            
            # Find or create parent items
            parent = None
            current_path = f"{parsed.scheme}://{parsed.netloc}"
            
            # Check if root exists
            root_item = None
            for i in range(self.sitemap_tree.topLevelItemCount()):
                if self.sitemap_tree.topLevelItem(i).text(0) == current_path:
                    root_item = self.sitemap_tree.topLevelItem(i)
                    break
            
            if not root_item:
                root_item = QTreeWidgetItem([current_path, "", "", ""])
                self.sitemap_tree.addTopLevelItem(root_item)
            
            parent = root_item
            
            for part in path_parts:
                # Look for existing child
                found = None
                for i in range(parent.childCount()):
                    if parent.child(i).text(0) == part:
                        found = parent.child(i)
                        break
                
                if found:
                    parent = found
                else:
                    new_item = QTreeWidgetItem([part, "", "", ""])
                    parent.addChild(new_item)
                    parent = new_item
            
            # Update the leaf node with endpoint info
            parent.setText(1, str(endpoint.get('status', '')))
            parent.setText(2, f"{endpoint.get('size', 0):,}")
            parent.setText(3, endpoint.get('content_type', ''))
            parent.setData(0, Qt.ItemDataRole.UserRole, endpoint)
            
        except Exception as e:
            pass
    
    def _add_param_to_table(self, param: Dict):
        """Add parameter to table"""
        row = self.params_table.rowCount()
        self.params_table.insertRow(row)
        
        name_item = QTableWidgetItem(param.get('name', ''))
        name_item.setData(Qt.ItemDataRole.UserRole, param)
        self.params_table.setItem(row, 0, name_item)
        
        location = param.get('location', '')
        if isinstance(location, ParameterLocation):
            location = location.value
        self.params_table.setItem(row, 1, QTableWidgetItem(str(location)))
        self.params_table.setItem(row, 2, QTableWidgetItem(param.get('param_type', 'string')))
        self.params_table.setItem(row, 3, QTableWidgetItem(str(param.get('value', ''))[:50]))
        
        reflected = "✓" if param.get('reflected') else ""
        reflected_item = QTableWidgetItem(reflected)
        if param.get('reflected'):
            reflected_item.setForeground(QColor('#ff5555'))
        self.params_table.setItem(row, 4, reflected_item)
        
        self.params_table.setItem(row, 5, QTableWidgetItem(param.get('discovered_in', '')))
        
        self.params_stats_label.setText(f"Total Parameters: {self.params_table.rowCount()}")
    
    def _on_form_discovered(self, form: Dict):
        """Handle discovered form"""
        self.forms.append(form)
        
        row = self.forms_table.rowCount()
        self.forms_table.insertRow(row)
        
        action_item = QTableWidgetItem(form.get('action', ''))
        action_item.setData(Qt.ItemDataRole.UserRole, form)
        self.forms_table.setItem(row, 0, action_item)
        
        self.forms_table.setItem(row, 1, QTableWidgetItem(form.get('method', 'GET')))
        self.forms_table.setItem(row, 2, QTableWidgetItem(str(len(form.get('inputs', [])))))
        
        csrf_item = QTableWidgetItem("✓" if form.get('has_csrf_token') else "✗")
        csrf_item.setForeground(QColor('#55ff55') if form.get('has_csrf_token') else QColor('#ff5555'))
        self.forms_table.setItem(row, 3, csrf_item)
        
        upload_item = QTableWidgetItem("✓" if form.get('has_file_upload') else "")
        if form.get('has_file_upload'):
            upload_item.setForeground(QColor('#ffaa55'))
        self.forms_table.setItem(row, 4, upload_item)
        
        # Categorize form
        form_type = self._categorize_form(form)
        self.forms_table.setItem(row, 5, QTableWidgetItem(form_type))
    
    def _categorize_form(self, form: Dict) -> str:
        """Categorize form type"""
        inputs_str = str(form.get('inputs', [])).lower()
        
        if any(x in inputs_str for x in ['password', 'login', 'signin']):
            return "Login"
        if any(x in inputs_str for x in ['register', 'signup', 'create']):
            return "Registration"
        if any(x in inputs_str for x in ['search', 'query', 'q']):
            return "Search"
        if form.get('has_file_upload'):
            return "File Upload"
        if any(x in inputs_str for x in ['contact', 'message', 'email']):
            return "Contact"
        return "Generic"
    
    def _on_vulnerability_found(self, vuln: Dict):
        """Handle found vulnerability"""
        self.vulnerabilities.append(vuln)
        
        row = self.vulns_table.rowCount()
        self.vulns_table.insertRow(row)
        
        type_item = QTableWidgetItem(vuln.get('type', ''))
        type_item.setData(Qt.ItemDataRole.UserRole, vuln)
        self.vulns_table.setItem(row, 0, type_item)
        
        severity = vuln.get('severity', 'INFO')
        severity_item = QTableWidgetItem(severity)
        if severity == 'HIGH':
            severity_item.setForeground(QColor('#ff5555'))
        elif severity == 'MEDIUM':
            severity_item.setForeground(QColor('#ffaa55'))
        else:
            severity_item.setForeground(QColor('#55aaff'))
        self.vulns_table.setItem(row, 1, severity_item)
        
        self.vulns_table.setItem(row, 2, QTableWidgetItem(vuln.get('url', '')))
        self.vulns_table.setItem(row, 3, QTableWidgetItem(vuln.get('evidence', '')[:100]))
        
        self.vulns_stats_label.setText(f"Total Findings: {self.vulns_table.rowCount()}")
    
    def _on_progress_update(self, visited: int, discovered: int):
        """Handle progress update"""
        self.stats_label.setText(f"Visited: {visited} | Discovered: {discovered}")
    
    def _on_status_update(self, status: str):
        """Handle status update"""
        self.status_label.setText(status)
    
    def _on_crawl_complete(self, result: Dict):
        """Handle crawl completion"""
        self._reset_ui()
        self.status_label.setText("Complete!")
        
        # Update API tabs
        for api in result.get('api_endpoints', []):
            row = self.rest_table.rowCount()
            self.rest_table.insertRow(row)
            self.rest_table.setItem(row, 0, QTableWidgetItem(api.get('url', '')))
            self.rest_table.setItem(row, 1, QTableWidgetItem(api.get('method', 'GET')))
            self.rest_table.setItem(row, 2, QTableWidgetItem(''))
        
        for url in result.get('graphql_endpoints', []):
            self.graphql_list.addItem(url)
        
        for url in result.get('websocket_endpoints', []):
            self.websocket_list.addItem(url)
        
        for url in result.get('authentication_endpoints', []):
            self.auth_list.addItem(url)
        
        # Update technology tree
        for tech, urls in result.get('technologies', {}).items():
            tech_item = QTreeWidgetItem([tech, str(len(urls)), ''])
            for url in urls[:10]:  # Limit to 10 URLs per tech
                url_item = QTreeWidgetItem(['', '', url])
                tech_item.addChild(url_item)
            self.tech_tree.addTopLevelItem(tech_item)
        
        # Show summary
        duration = "N/A"
        try:
            start = datetime.fromisoformat(result['start_time'])
            end = datetime.fromisoformat(result['end_time'])
            duration = str(end - start)
        except:
            pass
        
        summary = f"""
Crawl Complete!

Target: {result.get('target')}
Duration: {duration}
Total Requests: {result.get('total_requests')}
Total Errors: {result.get('total_errors')}

Discovered:
- Endpoints: {result.get('total_endpoints')}
- Parameters: {result.get('total_parameters')}
- Forms: {result.get('total_forms')}
- Vulnerabilities: {result.get('total_vulnerabilities')}
- Technologies: {len(result.get('technologies', {}))}
- REST APIs: {len(result.get('api_endpoints', []))}
- GraphQL: {len(result.get('graphql_endpoints', []))}
- WebSockets: {len(result.get('websocket_endpoints', []))}
- Auth Endpoints: {len(result.get('authentication_endpoints', []))}
"""
        
        QMessageBox.information(self, "Crawl Complete", summary)
    
    def _on_error(self, error: str):
        """Handle error"""
        self._reset_ui()
        self.status_label.setText(f"Error: {error}")
        QMessageBox.critical(self, "Error", error)
    
    def _filter_endpoints(self):
        """Filter endpoints table"""
        filter_text = self.endpoint_filter.text().lower()
        method_filter = self.method_filter.currentText()
        
        for row in range(self.endpoints_table.rowCount()):
            url_item = self.endpoints_table.item(row, 0)
            method_item = self.endpoints_table.item(row, 1)
            
            url_match = filter_text in url_item.text().lower() if url_item else True
            method_match = method_filter == "All Methods" or (method_item and method_item.text() == method_filter)
            
            self.endpoints_table.setRowHidden(row, not (url_match and method_match))
    
    def _show_sitemap_context_menu(self, position):
        """Show sitemap context menu"""
        item = self.sitemap_tree.itemAt(position)
        if not item:
            return
        
        menu = QMenu(self)
        
        open_action = QAction("Open URL", self)
        open_action.triggered.connect(lambda: self._open_url(item))
        menu.addAction(open_action)
        
        copy_action = QAction("Copy URL", self)
        copy_action.triggered.connect(lambda: self._copy_url(item))
        menu.addAction(copy_action)
        
        menu.exec(self.sitemap_tree.viewport().mapToGlobal(position))
    
    def _show_endpoint_context_menu(self, position):
        """Show endpoint context menu"""
        row = self.endpoints_table.rowAt(position.y())
        if row < 0:
            return
        
        menu = QMenu(self)
        
        details_action = QAction("View Details", self)
        details_action.triggered.connect(lambda: self._show_endpoint_details(row))
        menu.addAction(details_action)
        
        copy_action = QAction("Copy URL", self)
        copy_action.triggered.connect(lambda: self._copy_endpoint_url(row))
        menu.addAction(copy_action)
        
        menu.exec(self.endpoints_table.viewport().mapToGlobal(position))
    
    def _on_endpoint_double_clicked(self, item):
        """Handle endpoint double click"""
        row = item.row()
        self._show_endpoint_details(row)
    
    def _on_sitemap_item_double_clicked(self, item, column):
        """Handle sitemap double click"""
        endpoint = item.data(0, Qt.ItemDataRole.UserRole)
        if endpoint:
            self._show_detail_dialog("Endpoint Details", endpoint)
    
    def _on_param_double_clicked(self, item):
        """Handle parameter double click"""
        param = item.data(Qt.ItemDataRole.UserRole)
        if param:
            self._show_detail_dialog("Parameter Details", param)
    
    def _on_form_double_clicked(self, item):
        """Handle form double click"""
        form = self.forms[item.row()] if item.row() < len(self.forms) else None
        if form:
            self._show_detail_dialog("Form Details", form)
    
    def _on_vuln_double_clicked(self, item):
        """Handle vulnerability double click"""
        vuln = self.vulnerabilities[item.row()] if item.row() < len(self.vulnerabilities) else None
        if vuln:
            self._show_detail_dialog("Vulnerability Details", vuln)
    
    def _show_endpoint_details(self, row: int):
        """Show endpoint details dialog"""
        url_item = self.endpoints_table.item(row, 0)
        if not url_item:
            return
        
        endpoint = url_item.data(Qt.ItemDataRole.UserRole)
        if endpoint:
            self._show_detail_dialog("Endpoint Details", endpoint)
    
    def _show_detail_dialog(self, title: str, data: Dict):
        """Show detail dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(dialog)
        
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setPlainText(json.dumps(data, indent=2, default=str))
        layout.addWidget(text_edit)
        
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        button_box.accepted.connect(dialog.accept)
        
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(lambda: self._copy_to_clipboard(json.dumps(data, indent=2, default=str)))
        button_box.addButton(copy_btn, QDialogButtonBox.ButtonRole.ActionRole)
        
        layout.addWidget(button_box)
        
        dialog.exec()
    
    def _copy_to_clipboard(self, text: str):
        """Copy text to clipboard"""
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
    
    def _open_url(self, item):
        """Open URL in browser"""
        import webbrowser
        endpoint = item.data(0, Qt.ItemDataRole.UserRole)
        if endpoint and endpoint.get('url'):
            webbrowser.open(endpoint['url'])
    
    def _copy_url(self, item):
        """Copy URL to clipboard"""
        endpoint = item.data(0, Qt.ItemDataRole.UserRole)
        if endpoint and endpoint.get('url'):
            self._copy_to_clipboard(endpoint['url'])
    
    def _copy_endpoint_url(self, row: int):
        """Copy endpoint URL"""
        url_item = self.endpoints_table.item(row, 0)
        if url_item:
            self._copy_to_clipboard(url_item.text())
    
    def _export_results(self):
        """Export results to file"""
        if not self.endpoints:
            QMessageBox.warning(self, "Export", "No results to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "spider_results.json", "JSON Files (*.json)"
        )
        
        if file_path:
            data = {
                "exported_at": datetime.now().isoformat(),
                "endpoints": self.endpoints,
                "parameters": self.parameters,
                "forms": self.forms,
                "vulnerabilities": self.vulnerabilities
            }
            
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            QMessageBox.information(self, "Export", f"Results exported to {file_path}")
    
    # ==================== AI-POWERED FEATURES ====================
    
    def _generate_predictions(self):
        """Generate AI endpoint predictions"""
        if not self.endpoints:
            QMessageBox.warning(self, "Predictions", "No endpoints discovered yet. Run the spider first.")
            return
        
        if NeuralEndpointPredictor is None:
            QMessageBox.warning(self, "Error", "AI Engine not available")
            return
        
        try:
            predictor = NeuralEndpointPredictor()
            
            # Get target from first endpoint
            discovered_urls = [e.get('url', '') for e in self.endpoints]
            target = discovered_urls[0] if discovered_urls else self.target_input.text()
            
            predictions = predictor.predict_endpoints(target, discovered_urls)
            
            self.predictions_table.setRowCount(0)
            
            for pred in predictions:
                row = self.predictions_table.rowCount()
                self.predictions_table.insertRow(row)
                
                self.predictions_table.setItem(row, 0, QTableWidgetItem(pred.url))
                
                conf_item = QTableWidgetItem(f"{pred.confidence:.0%}")
                if pred.confidence >= 0.7:
                    conf_item.setForeground(QColor('#55ff55'))
                elif pred.confidence >= 0.5:
                    conf_item.setForeground(QColor('#ffaa55'))
                else:
                    conf_item.setForeground(QColor('#aaaaaa'))
                self.predictions_table.setItem(row, 1, conf_item)
                
                self.predictions_table.setItem(row, 2, QTableWidgetItem(pred.reason))
                self.predictions_table.setItem(row, 3, QTableWidgetItem(pred.pattern_source))
                self.predictions_table.setItem(row, 4, QTableWidgetItem("Pending"))
            
            self.results_tabs.setCurrentIndex(self.results_tabs.indexOf(
                self.results_tabs.findChild(QWidget, "") or self.results_tabs.widget(7)
            ))
            
            QMessageBox.information(self, "Predictions", f"Generated {len(predictions)} endpoint predictions")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate predictions: {str(e)}")
    
    def _verify_predictions(self):
        """Verify predicted endpoints"""
        if self.predictions_table.rowCount() == 0:
            QMessageBox.warning(self, "Verify", "No predictions to verify. Generate predictions first.")
            return
        
        QMessageBox.information(self, "Verify", "Verification will test each predicted endpoint.\nThis feature runs asynchronously.")
        # TODO: Implement async verification
    
    def _on_fuzz_param_selected(self, param_name: str):
        """Handle fuzz parameter selection"""
        if not param_name:
            return
        
        # Find parameter details
        for param in self.parameters:
            if param.get('name') == param_name:
                location = param.get('location', 'unknown')
                if hasattr(location, 'value'):
                    location = location.value
                self.fuzz_location_label.setText(f"Location: {location}")
                
                # Determine context
                if SmartFuzzer:
                    fuzzer = SmartFuzzer()
                    contexts = []
                    param_lower = param_name.lower()
                    for key, ctx_list in fuzzer.param_contexts.items():
                        if key in param_lower or param_lower in key:
                            contexts.extend(ctx_list)
                    
                    if contexts:
                        self.fuzz_context_label.setText(f"Context: {', '.join(set(contexts)[:3])}")
                    else:
                        self.fuzz_context_label.setText("Context: Generic")
                break
    
    def _start_fuzzing(self):
        """Start smart fuzzing"""
        param_name = self.fuzz_param_combo.currentText()
        if not param_name:
            QMessageBox.warning(self, "Fuzzer", "Please select a parameter to fuzz")
            return
        
        if SmartFuzzer is None:
            QMessageBox.warning(self, "Error", "Smart Fuzzer not available")
            return
        
        try:
            fuzzer = SmartFuzzer()
            payloads = fuzzer.get_payloads_for_param(param_name)
            
            # Filter by selected attack types
            selected_attacks = [k for k, v in self.attack_checks.items() if v.isChecked()]
            payloads = [p for p in payloads if p.attack_type in selected_attacks]
            
            self.fuzz_results_table.setRowCount(0)
            
            for payload in payloads[:100]:  # Limit to 100 payloads
                row = self.fuzz_results_table.rowCount()
                self.fuzz_results_table.insertRow(row)
                
                self.fuzz_results_table.setItem(row, 0, QTableWidgetItem(payload.value[:100]))
                self.fuzz_results_table.setItem(row, 1, QTableWidgetItem(payload.attack_type))
                self.fuzz_results_table.setItem(row, 2, QTableWidgetItem("Pending"))
                self.fuzz_results_table.setItem(row, 3, QTableWidgetItem("-"))
                
                interesting_item = QTableWidgetItem(payload.severity)
                if payload.severity == "HIGH":
                    interesting_item.setForeground(QColor('#ff5555'))
                elif payload.severity == "MEDIUM":
                    interesting_item.setForeground(QColor('#ffaa55'))
                self.fuzz_results_table.setItem(row, 4, interesting_item)
            
            QMessageBox.information(self, "Fuzzer", f"Generated {len(payloads)} context-aware payloads for '{param_name}'")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Fuzzing failed: {str(e)}")
    
    def _generate_wordlist(self):
        """Generate custom wordlist from crawled content"""
        if not self.endpoints:
            QMessageBox.warning(self, "Wordlist", "No content available. Run the spider first.")
            return
        
        if ContentAnalyzer is None:
            QMessageBox.warning(self, "Error", "Content Analyzer not available")
            return
        
        try:
            analyzer = ContentAnalyzer()
            
            # Analyze all discovered content
            for endpoint in self.endpoints:
                url = endpoint.get('url', '')
                # We don't have the body stored, so generate from parameters and URLs
                params = endpoint.get('parameters', [])
                for param in params:
                    analyzer.words.update([param.get('name', '')])
            
            # Generate wordlist from path segments and parameters
            wordlist = []
            
            # Extract from URLs
            for endpoint in self.endpoints:
                url = endpoint.get('url', '')
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    segments = [s for s in parsed.path.split('/') if s and len(s) > 2]
                    wordlist.extend(segments)
                except:
                    pass
            
            # Extract from parameters
            for param in self.parameters:
                name = param.get('name', '')
                if name and len(name) > 2:
                    wordlist.append(name)
            
            # Deduplicate and sort
            wordlist = sorted(set(wordlist))
            
            self.wordlist_text.setPlainText('\n'.join(wordlist))
            
            # Update other content tabs
            for param in self.parameters:
                name = param.get('name', '').lower()
                value = str(param.get('value', ''))
                
                # Check for secrets
                if any(x in name for x in ['key', 'secret', 'token', 'password', 'api']):
                    if value and len(value) > 5:
                        row = self.secrets_table.rowCount()
                        self.secrets_table.insertRow(row)
                        self.secrets_table.setItem(row, 0, QTableWidgetItem(name))
                        self.secrets_table.setItem(row, 1, QTableWidgetItem(value[:100]))
                        self.secrets_table.setItem(row, 2, QTableWidgetItem(param.get('discovered_in', '')))
            
            QMessageBox.information(self, "Wordlist", f"Generated wordlist with {len(wordlist)} unique words")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Wordlist generation failed: {str(e)}")
    
    def _export_wordlist(self):
        """Export wordlist to file"""
        wordlist = self.wordlist_text.toPlainText()
        if not wordlist:
            QMessageBox.warning(self, "Export", "No wordlist to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Wordlist", "custom_wordlist.txt", "Text Files (*.txt)"
        )
        
        if file_path:
            with open(file_path, 'w') as f:
                f.write(wordlist)
            QMessageBox.information(self, "Export", f"Wordlist exported to {file_path}")
    
    def _test_cors(self):
        """Test CORS misconfiguration"""
        if not self.endpoints:
            QMessageBox.warning(self, "CORS Test", "No endpoints to test. Run the spider first.")
            return
        
        if CORSAnalyzer is None:
            QMessageBox.warning(self, "Error", "CORS Analyzer not available")
            return
        
        QMessageBox.information(self, "CORS Test", "CORS testing will be performed on all discovered endpoints.\nResults will appear in the table.")
        
        # For now, show placeholder results
        self.cors_results_table.setRowCount(0)
        
        for endpoint in self.endpoints[:20]:  # Test first 20 endpoints
            row = self.cors_results_table.rowCount()
            self.cors_results_table.insertRow(row)
            
            self.cors_results_table.setItem(row, 0, QTableWidgetItem(endpoint.get('url', '')))
            self.cors_results_table.setItem(row, 1, QTableWidgetItem("*"))  # Placeholder
            self.cors_results_table.setItem(row, 2, QTableWidgetItem("false"))
            self.cors_results_table.setItem(row, 3, QTableWidgetItem("Pending"))
    
    def _test_smuggling(self):
        """Test HTTP request smuggling"""
        QMessageBox.information(self, "HTTP Smuggling", "HTTP Request Smuggling detection is an advanced feature.\nTests for CL.TE and TE.CL vulnerabilities.")
        
        if HTTPRequestSmuggler is None:
            QMessageBox.warning(self, "Error", "HTTP Smuggler not available")
            return
        
        self.smuggling_results_table.setRowCount(0)
        # Placeholder for smuggling tests
    
    def _test_cache_poisoning(self):
        """Test cache poisoning"""
        QMessageBox.information(self, "Cache Poisoning", "Cache Poisoning detection tests for web cache deception vulnerabilities.")
        
        if CachePoisioningDetector is None:
            QMessageBox.warning(self, "Error", "Cache Poisoning Detector not available")
            return
        
        self.cache_results_table.setRowCount(0)
        # Placeholder for cache tests
    
    def _run_graphql_introspection(self):
        """Run GraphQL introspection"""
        graphql_endpoints = []
        
        # Find GraphQL endpoints
        for endpoint in self.endpoints:
            url = endpoint.get('url', '').lower()
            if 'graphql' in url:
                graphql_endpoints.append(endpoint.get('url'))
        
        if not graphql_endpoints:
            QMessageBox.warning(self, "GraphQL", "No GraphQL endpoints discovered")
            return
        
        if GraphQLIntrospector is None:
            QMessageBox.warning(self, "Error", "GraphQL Introspector not available")
            return
        
        self.graphql_schema_text.setPlainText(f"Found {len(graphql_endpoints)} GraphQL endpoints:\n\n")
        for url in graphql_endpoints:
            self.graphql_schema_text.appendPlainText(f"• {url}\n")
        
        self.graphql_schema_text.appendPlainText("\nIntrospection query ready. Click 'Generate Attack Queries' to create exploitation queries.")
    
    def _generate_graphql_queries(self):
        """Generate GraphQL attack queries"""
        if GraphQLIntrospector is None:
            QMessageBox.warning(self, "Error", "GraphQL Introspector not available")
            return
        
        introspector = GraphQLIntrospector()
        
        self.graphql_schema_text.appendPlainText("\n\n=== Generated Attack Queries ===\n")
        self.graphql_schema_text.appendPlainText("\n# Introspection Query\n")
        self.graphql_schema_text.appendPlainText(introspector.introspection_query[:500] + "...")
        
        self.graphql_schema_text.appendPlainText("\n\n# Common Attack Queries\n")
        attack_queries = [
            'query { __typename }',
            'query { user(id: "1") { id email password } }',
            'mutation { deleteUser(id: "1") }',
            'query { users { id email role } }',
            'query { admin { secretKey } }',
        ]
        
        for query in attack_queries:
            self.graphql_schema_text.appendPlainText(f"\n{query}\n")
    
    def _update_fuzz_params(self):
        """Update fuzzer parameter combo box"""
        self.fuzz_param_combo.clear()
        
        param_names = set()
        for param in self.parameters:
            name = param.get('name', '')
            if name:
                param_names.add(name)
        
        self.fuzz_param_combo.addItems(sorted(param_names))


# For standalone testing
if __name__ == "__main__":
    from PyQt6.QtWidgets import QApplication
    import sys
    
    app = QApplication(sys.argv)
    window = WebSpiderPage()
    window.setWindowTitle("Advanced Web Spider")
    window.resize(1400, 900)
    window.show()
    sys.exit(app.exec())
