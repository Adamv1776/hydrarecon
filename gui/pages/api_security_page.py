"""
API Security Testing Page - REST/GraphQL Security Analysis Interface
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QTabWidget, QTextEdit, QLineEdit, QComboBox,
    QProgressBar, QFrame, QSplitter, QGroupBox,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QMessageBox,
    QCheckBox, QSpinBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor
import asyncio
from datetime import datetime


class APIWorker(QThread):
    """Worker thread for API security operations"""
    finished = pyqtSignal(object)
    progress = pyqtSignal(str, object)
    error = pyqtSignal(str)
    
    def __init__(self, operation, *args, **kwargs):
        super().__init__()
        self.operation = operation
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.operation(*self.args, **self.kwargs))
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class APISecurityPage(QWidget):
    """API Security Testing Interface"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.tester = None
        self.current_worker = None
        self.endpoints = {}
        
        self._init_tester()
        self._setup_ui()
    
    def _init_tester(self):
        """Initialize API security tester"""
        try:
            from core.api_security import APISecurityTester
            self.tester = APISecurityTester()
            self.tester.add_callback(self._on_tester_event)
        except ImportError as e:
            print(f"API tester import error: {e}")
    
    def _on_tester_event(self, event: str, data):
        """Handle tester events"""
        pass
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3a3a4a;
                background: #1a1a2e;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #252535;
                color: #8888aa;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background: #1a1a2e;
                color: #ff6b00;
            }
        """)
        
        tabs.addTab(self._create_discovery_tab(), "🔍 Discovery")
        tabs.addTab(self._create_testing_tab(), "⚡ Testing")
        tabs.addTab(self._create_endpoints_tab(), "🔗 Endpoints")
        tabs.addTab(self._create_vulns_tab(), "⚠️ Vulnerabilities")
        tabs.addTab(self._create_fuzzing_tab(), "🔀 Fuzzing")
        
        layout.addWidget(tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:1 #252545);
                border-radius: 15px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🔗 API SECURITY TESTER")
        title.setFont(QFont("Consolas", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #ff6b00;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("REST & GraphQL Security Analysis Platform")
        subtitle.setStyleSheet("color: #8888aa; font-size: 12px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(30)
        
        self.endpoint_count = self._create_stat("Endpoints", "0")
        self.vuln_count = self._create_stat("Vulns", "0")
        self.critical_count = self._create_stat("Critical", "0")
        
        stats_layout.addWidget(self.endpoint_count)
        stats_layout.addWidget(self.vuln_count)
        stats_layout.addWidget(self.critical_count)
        
        layout.addLayout(stats_layout)
        
        return frame
    
    def _create_stat(self, label: str, value: str) -> QFrame:
        """Create stat display"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: rgba(255, 107, 0, 0.1);
                border: 1px solid #ff6b00;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(15, 10, 15, 10)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Consolas", 20, QFont.Weight.Bold))
        value_label.setStyleSheet("color: #ff6b00;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setObjectName(f"stat_{label.lower()}")
        layout.addWidget(value_label)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #8888aa; font-size: 11px;")
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_label)
        
        return frame
    
    def _create_discovery_tab(self) -> QWidget:
        """Create endpoint discovery tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Discovery controls
        discovery_group = QGroupBox("API Discovery")
        discovery_group.setStyleSheet("""
            QGroupBox {
                color: #ff6b00;
                font-weight: bold;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        discovery_layout = QGridLayout(discovery_group)
        
        # Base URL
        discovery_layout.addWidget(QLabel("Base URL:"), 0, 0)
        self.base_url = QLineEdit()
        self.base_url.setPlaceholderText("https://api.example.com")
        self.base_url.setStyleSheet("""
            QLineEdit {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                padding: 10px;
                color: white;
            }
        """)
        discovery_layout.addWidget(self.base_url, 0, 1, 1, 2)
        
        # API Type
        discovery_layout.addWidget(QLabel("API Type:"), 1, 0)
        self.api_type_combo = QComboBox()
        self.api_type_combo.addItems(["REST", "GraphQL", "SOAP", "Auto-detect"])
        self.api_type_combo.setStyleSheet("""
            QComboBox {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
        """)
        discovery_layout.addWidget(self.api_type_combo, 1, 1)
        
        # Auth type
        discovery_layout.addWidget(QLabel("Auth:"), 1, 2)
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems(["None", "Bearer Token", "API Key", "Basic Auth"])
        self.auth_type_combo.setStyleSheet("""
            QComboBox {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
        """)
        discovery_layout.addWidget(self.auth_type_combo, 1, 3)
        
        # Auth value
        discovery_layout.addWidget(QLabel("Token/Key:"), 2, 0)
        self.auth_value = QLineEdit()
        self.auth_value.setPlaceholderText("Bearer token or API key...")
        self.auth_value.setEchoMode(QLineEdit.EchoMode.Password)
        self.auth_value.setStyleSheet("""
            QLineEdit {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                padding: 10px;
                color: white;
            }
        """)
        discovery_layout.addWidget(self.auth_value, 2, 1, 1, 2)
        
        # Discover button
        self.discover_btn = QPushButton("🔍 Discover Endpoints")
        self.discover_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff6b00, stop:1 #ff9500);
                border: none;
                border-radius: 8px;
                padding: 12px 25px;
                color: white;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff8800, stop:1 #ffaa00);
            }
        """)
        self.discover_btn.clicked.connect(self._start_discovery)
        discovery_layout.addWidget(self.discover_btn, 2, 3)
        
        layout.addWidget(discovery_group)
        
        # Progress
        self.discovery_progress = QProgressBar()
        self.discovery_progress.setStyleSheet("""
            QProgressBar {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff6b00, stop:1 #ff9500);
                border-radius: 5px;
            }
        """)
        self.discovery_progress.setVisible(False)
        layout.addWidget(self.discovery_progress)
        
        # Discovery log
        self.discovery_log = QTextEdit()
        self.discovery_log.setReadOnly(True)
        self.discovery_log.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                color: #ff6b00;
                font-family: Consolas, monospace;
                padding: 10px;
            }
        """)
        self.discovery_log.setPlaceholderText("Discovery results will appear here...")
        layout.addWidget(self.discovery_log)
        
        return widget
    
    def _create_testing_tab(self) -> QWidget:
        """Create security testing tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Test controls
        test_group = QGroupBox("Security Testing")
        test_group.setStyleSheet("""
            QGroupBox {
                color: #00ff88;
                font-weight: bold;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                margin-top: 10px;
            }
        """)
        test_layout = QVBoxLayout(test_group)
        
        # Test options
        options_layout = QGridLayout()
        
        self.test_injection = QCheckBox("Injection Testing")
        self.test_injection.setChecked(True)
        self.test_injection.setStyleSheet("color: white;")
        options_layout.addWidget(self.test_injection, 0, 0)
        
        self.test_auth = QCheckBox("Authentication")
        self.test_auth.setChecked(True)
        self.test_auth.setStyleSheet("color: white;")
        options_layout.addWidget(self.test_auth, 0, 1)
        
        self.test_authz = QCheckBox("Authorization (BOLA)")
        self.test_authz.setChecked(True)
        self.test_authz.setStyleSheet("color: white;")
        options_layout.addWidget(self.test_authz, 0, 2)
        
        self.test_cors = QCheckBox("CORS")
        self.test_cors.setChecked(True)
        self.test_cors.setStyleSheet("color: white;")
        options_layout.addWidget(self.test_cors, 1, 0)
        
        self.test_headers = QCheckBox("Security Headers")
        self.test_headers.setChecked(True)
        self.test_headers.setStyleSheet("color: white;")
        options_layout.addWidget(self.test_headers, 1, 1)
        
        self.test_ratelimit = QCheckBox("Rate Limiting")
        self.test_ratelimit.setChecked(True)
        self.test_ratelimit.setStyleSheet("color: white;")
        options_layout.addWidget(self.test_ratelimit, 1, 2)
        
        test_layout.addLayout(options_layout)
        
        # Target selection
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target Endpoint:"))
        self.target_combo = QComboBox()
        self.target_combo.setMinimumWidth(400)
        self.target_combo.setStyleSheet("""
            QComboBox {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
        """)
        target_layout.addWidget(self.target_combo)
        
        self.test_all_btn = QPushButton("⚡ Test All Endpoints")
        self.test_all_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, stop:1 #00d4ff);
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                color: #1a1a2e;
                font-weight: bold;
            }
        """)
        self.test_all_btn.clicked.connect(self._test_all_endpoints)
        target_layout.addWidget(self.test_all_btn)
        
        self.test_btn = QPushButton("⚡ Test Selected")
        self.test_btn.setStyleSheet("""
            QPushButton {
                background: #ff6b00;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                color: white;
                font-weight: bold;
            }
        """)
        self.test_btn.clicked.connect(self._test_endpoint)
        target_layout.addWidget(self.test_btn)
        
        test_layout.addLayout(target_layout)
        
        layout.addWidget(test_group)
        
        # Testing progress
        self.test_progress = QProgressBar()
        self.test_progress.setStyleSheet("""
            QProgressBar {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, stop:1 #00d4ff);
            }
        """)
        self.test_progress.setVisible(False)
        layout.addWidget(self.test_progress)
        
        # Test output
        self.test_output = QTextEdit()
        self.test_output.setReadOnly(True)
        self.test_output.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                color: #00ff88;
                font-family: Consolas, monospace;
                padding: 10px;
            }
        """)
        layout.addWidget(self.test_output)
        
        return widget
    
    def _create_endpoints_tab(self) -> QWidget:
        """Create endpoints tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Endpoints table
        self.endpoints_table = QTableWidget()
        self.endpoints_table.setColumnCount(6)
        self.endpoints_table.setHorizontalHeaderLabels([
            "Method", "Path", "Auth", "Vulns", "Tested", "Actions"
        ])
        self.endpoints_table.horizontalHeader().setStretchLastSection(True)
        self.endpoints_table.setStyleSheet("""
            QTableWidget {
                background: #0d0d1a;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                color: white;
                gridline-color: #3a3a4a;
            }
            QHeaderView::section {
                background: #252535;
                color: #ff6b00;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item:selected {
                background: rgba(255, 107, 0, 0.2);
            }
        """)
        self.endpoints_table.itemClicked.connect(self._on_endpoint_selected)
        layout.addWidget(self.endpoints_table)
        
        # Endpoint details
        details_group = QGroupBox("Endpoint Details")
        details_group.setStyleSheet("""
            QGroupBox {
                color: #00d4ff;
                font-weight: bold;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
            }
        """)
        details_layout = QVBoxLayout(details_group)
        
        self.endpoint_details = QTextEdit()
        self.endpoint_details.setReadOnly(True)
        self.endpoint_details.setMaximumHeight(200)
        self.endpoint_details.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                border: none;
                color: #00d4ff;
                font-family: Consolas, monospace;
            }
        """)
        details_layout.addWidget(self.endpoint_details)
        
        layout.addWidget(details_group)
        
        return widget
    
    def _create_vulns_tab(self) -> QWidget:
        """Create vulnerabilities tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Vulnerabilities table
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(6)
        self.vulns_table.setHorizontalHeaderLabels([
            "Severity", "Type", "Title", "Endpoint", "CWE", "CVSS"
        ])
        self.vulns_table.horizontalHeader().setStretchLastSection(True)
        self.vulns_table.setStyleSheet("""
            QTableWidget {
                background: #0d0d1a;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                color: white;
                gridline-color: #3a3a4a;
            }
            QHeaderView::section {
                background: #252535;
                color: #ff0055;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        self.vulns_table.itemClicked.connect(self._on_vuln_selected)
        layout.addWidget(self.vulns_table)
        
        # Vulnerability details
        details_group = QGroupBox("Vulnerability Details")
        details_group.setStyleSheet("""
            QGroupBox {
                color: #ff0055;
                font-weight: bold;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
            }
        """)
        details_layout = QVBoxLayout(details_group)
        
        self.vuln_details = QTextEdit()
        self.vuln_details.setReadOnly(True)
        self.vuln_details.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                border: none;
                color: #ff0055;
                font-family: Consolas, monospace;
            }
        """)
        details_layout.addWidget(self.vuln_details)
        
        layout.addWidget(details_group)
        
        return widget
    
    def _create_fuzzing_tab(self) -> QWidget:
        """Create API fuzzing tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Fuzzing controls
        fuzz_group = QGroupBox("API Fuzzing")
        fuzz_group.setStyleSheet("""
            QGroupBox {
                color: #ff00ff;
                font-weight: bold;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                margin-top: 10px;
            }
        """)
        fuzz_layout = QGridLayout(fuzz_group)
        
        # Target endpoint
        fuzz_layout.addWidget(QLabel("Target:"), 0, 0)
        self.fuzz_target_combo = QComboBox()
        self.fuzz_target_combo.setStyleSheet("""
            QComboBox {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
        """)
        fuzz_layout.addWidget(self.fuzz_target_combo, 0, 1)
        
        # Parameter
        fuzz_layout.addWidget(QLabel("Parameter:"), 0, 2)
        self.fuzz_param = QLineEdit()
        self.fuzz_param.setPlaceholderText("id, user_id, etc.")
        self.fuzz_param.setStyleSheet("""
            QLineEdit {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
        """)
        fuzz_layout.addWidget(self.fuzz_param, 0, 3)
        
        # Wordlist
        fuzz_layout.addWidget(QLabel("Wordlist:"), 1, 0)
        self.fuzz_wordlist = QComboBox()
        self.fuzz_wordlist.addItems([
            "Default", "SQLi Payloads", "XSS Payloads",
            "SSRF Payloads", "Path Traversal", "Custom"
        ])
        self.fuzz_wordlist.setStyleSheet("""
            QComboBox {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
        """)
        fuzz_layout.addWidget(self.fuzz_wordlist, 1, 1)
        
        # Start fuzzing
        self.start_fuzz_btn = QPushButton("🔀 Start Fuzzing")
        self.start_fuzz_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff00ff, stop:1 #00d4ff);
                border: none;
                border-radius: 8px;
                padding: 10px 25px;
                color: white;
                font-weight: bold;
            }
        """)
        self.start_fuzz_btn.clicked.connect(self._start_fuzzing)
        fuzz_layout.addWidget(self.start_fuzz_btn, 1, 2, 1, 2)
        
        layout.addWidget(fuzz_group)
        
        # Fuzzing progress
        self.fuzz_progress = QProgressBar()
        self.fuzz_progress.setStyleSheet("""
            QProgressBar {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff00ff, stop:1 #00d4ff);
            }
        """)
        layout.addWidget(self.fuzz_progress)
        
        # Fuzz results
        self.fuzz_results = QTableWidget()
        self.fuzz_results.setColumnCount(5)
        self.fuzz_results.setHorizontalHeaderLabels([
            "Payload", "Status", "Time", "Size", "Interesting"
        ])
        self.fuzz_results.horizontalHeader().setStretchLastSection(True)
        self.fuzz_results.setStyleSheet("""
            QTableWidget {
                background: #0d0d1a;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                color: white;
                gridline-color: #3a3a4a;
            }
            QHeaderView::section {
                background: #252535;
                color: #ff00ff;
                padding: 8px;
                border: none;
            }
        """)
        layout.addWidget(self.fuzz_results)
        
        return widget
    
    def _start_discovery(self):
        """Start API endpoint discovery"""
        if not self.tester:
            QMessageBox.warning(self, "Error", "API tester not initialized")
            return
        
        url = self.base_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Error", "Please enter a base URL")
            return
        
        self.discovery_progress.setVisible(True)
        self.discovery_progress.setRange(0, 0)
        self.discover_btn.setEnabled(False)
        
        self.discovery_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Starting discovery on {url}...")
        
        # Build auth headers if provided
        headers = None
        auth_type = self.auth_type_combo.currentText()
        auth_value = self.auth_value.text().strip()
        
        if auth_type == "Bearer Token" and auth_value:
            headers = {"Authorization": f"Bearer {auth_value}"}
        elif auth_type == "API Key" and auth_value:
            headers = {"X-API-Key": auth_value}
        
        self.current_worker = APIWorker(
            self.tester.discover_endpoints,
            url,
            headers=headers
        )
        self.current_worker.finished.connect(self._on_discovery_complete)
        self.current_worker.error.connect(self._on_error)
        self.current_worker.start()
    
    def _on_discovery_complete(self, endpoints):
        """Handle discovery completion"""
        self.discovery_progress.setVisible(False)
        self.discover_btn.setEnabled(True)
        
        if endpoints:
            self.discovery_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(endpoints)} endpoints!")
            
            for endpoint in endpoints:
                self.endpoints[endpoint.id] = endpoint
                self.discovery_log.append(f"  📡 {endpoint.method} {endpoint.path}")
                
                # Add to endpoints table
                row = self.endpoints_table.rowCount()
                self.endpoints_table.insertRow(row)
                
                method_item = QTableWidgetItem(endpoint.method)
                if endpoint.method == "GET":
                    method_item.setForeground(QColor("#00ff88"))
                elif endpoint.method == "POST":
                    method_item.setForeground(QColor("#ff6b00"))
                elif endpoint.method == "DELETE":
                    method_item.setForeground(QColor("#ff0055"))
                else:
                    method_item.setForeground(QColor("#00d4ff"))
                self.endpoints_table.setItem(row, 0, method_item)
                
                self.endpoints_table.setItem(row, 1, QTableWidgetItem(endpoint.path))
                self.endpoints_table.setItem(row, 2, QTableWidgetItem("Yes" if endpoint.auth_required else "No"))
                self.endpoints_table.setItem(row, 3, QTableWidgetItem(str(len(endpoint.vulnerabilities))))
                self.endpoints_table.setItem(row, 4, QTableWidgetItem("No"))
                
                # Add to target combos
                self.target_combo.addItem(f"{endpoint.method} {endpoint.path}", endpoint.id)
                self.fuzz_target_combo.addItem(f"{endpoint.method} {endpoint.path}", endpoint.id)
            
            # Update stats
            self.endpoint_count.findChild(QLabel, "stat_endpoints").setText(str(len(self.endpoints)))
        else:
            self.discovery_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] No endpoints discovered")
    
    def _on_error(self, error):
        """Handle error"""
        self.discovery_progress.setVisible(False)
        self.test_progress.setVisible(False)
        self.discover_btn.setEnabled(True)
        self.test_btn.setEnabled(True)
        
        self.discovery_log.append(f"[ERROR] {error}")
        self.test_output.append(f"[ERROR] {error}")
    
    def _test_endpoint(self):
        """Test selected endpoint"""
        if self.target_combo.currentIndex() < 0:
            QMessageBox.warning(self, "Error", "Please select an endpoint")
            return
        
        endpoint_id = self.target_combo.currentData()
        
        self.test_progress.setVisible(True)
        self.test_progress.setRange(0, 0)
        self.test_btn.setEnabled(False)
        
        self.test_output.append(f"\n[{datetime.now().strftime('%H:%M:%S')}] Testing endpoint...")
        
        self.current_worker = APIWorker(
            self.tester.test_endpoint,
            endpoint_id
        )
        self.current_worker.finished.connect(self._on_test_complete)
        self.current_worker.error.connect(self._on_error)
        self.current_worker.start()
    
    def _test_all_endpoints(self):
        """Test all discovered endpoints"""
        if not self.endpoints:
            QMessageBox.warning(self, "Error", "No endpoints discovered yet")
            return
        
        QMessageBox.information(
            self, "Testing All",
            f"Will test {len(self.endpoints)} endpoints. This may take a while."
        )
    
    def _on_test_complete(self, vulnerabilities):
        """Handle test completion"""
        self.test_progress.setVisible(False)
        self.test_btn.setEnabled(True)
        
        if vulnerabilities:
            self.test_output.append(f"[+] Found {len(vulnerabilities)} vulnerabilities!")
            
            for vuln in vulnerabilities:
                self.test_output.append(f"  [{vuln.severity.value.upper()}] {vuln.title}")
                
                # Add to vulnerabilities table
                row = self.vulns_table.rowCount()
                self.vulns_table.insertRow(row)
                
                severity_item = QTableWidgetItem(vuln.severity.value.upper())
                if vuln.severity.value == "critical":
                    severity_item.setForeground(QColor("#ff0055"))
                elif vuln.severity.value == "high":
                    severity_item.setForeground(QColor("#ff6b00"))
                elif vuln.severity.value == "medium":
                    severity_item.setForeground(QColor("#ffcc00"))
                else:
                    severity_item.setForeground(QColor("#00ff88"))
                self.vulns_table.setItem(row, 0, severity_item)
                
                self.vulns_table.setItem(row, 1, QTableWidgetItem(vuln.vuln_type))
                self.vulns_table.setItem(row, 2, QTableWidgetItem(vuln.title))
                self.vulns_table.setItem(row, 3, QTableWidgetItem(vuln.endpoint_id[:8]))
                self.vulns_table.setItem(row, 4, QTableWidgetItem(vuln.cwe_id or "N/A"))
                self.vulns_table.setItem(row, 5, QTableWidgetItem(f"{vuln.cvss_score:.1f}"))
            
            # Update stats
            self.vuln_count.findChild(QLabel, "stat_vulns").setText(str(self.vulns_table.rowCount()))
            critical = sum(1 for v in vulnerabilities if v.severity.value == "critical")
            self.critical_count.findChild(QLabel, "stat_critical").setText(str(critical))
        else:
            self.test_output.append("[-] No vulnerabilities found")
    
    def _on_endpoint_selected(self, item):
        """Handle endpoint selection"""
        row = item.row()
        path = self.endpoints_table.item(row, 1).text()
        method = self.endpoints_table.item(row, 0).text()
        
        # Find endpoint
        for endpoint in self.endpoints.values():
            if endpoint.path == path and endpoint.method == method:
                details = f"""
╔══════════════════════════════════════╗
║         ENDPOINT DETAILS             ║
╠══════════════════════════════════════╣

  Method:      {endpoint.method}
  Path:        {endpoint.path}
  Full URL:    {endpoint.url}
  
  Auth Required: {endpoint.auth_required}
  Auth Type:     {endpoint.auth_type.value}
  
  Response Codes: {endpoint.response_codes}
  Vulnerabilities: {len(endpoint.vulnerabilities)}

╚══════════════════════════════════════╝
"""
                self.endpoint_details.setText(details)
                break
    
    def _on_vuln_selected(self, item):
        """Handle vulnerability selection"""
        row = item.row()
        
        details = f"""
╔══════════════════════════════════════╗
║       VULNERABILITY DETAILS          ║
╠══════════════════════════════════════╣

  Severity: {self.vulns_table.item(row, 0).text()}
  Type:     {self.vulns_table.item(row, 1).text()}
  Title:    {self.vulns_table.item(row, 2).text()}
  CWE:      {self.vulns_table.item(row, 4).text()}
  CVSS:     {self.vulns_table.item(row, 5).text()}

╠══════════════════════════════════════╣
║           REMEDIATION                ║
╠══════════════════════════════════════╣

  Review and fix the identified issue
  based on security best practices.

╚══════════════════════════════════════╝
"""
        self.vuln_details.setText(details)
    
    def _start_fuzzing(self):
        """Start API fuzzing"""
        if self.fuzz_target_combo.currentIndex() < 0:
            QMessageBox.warning(self, "Error", "Please select a target endpoint")
            return
        
        param = self.fuzz_param.text().strip()
        if not param:
            QMessageBox.warning(self, "Error", "Please enter a parameter to fuzz")
            return
        
        endpoint_id = self.fuzz_target_combo.currentData()
        
        self.fuzz_progress.setRange(0, 100)
        self.fuzz_progress.setValue(0)
        
        self.current_worker = APIWorker(
            self.tester.fuzz_endpoint,
            endpoint_id,
            param
        )
        self.current_worker.finished.connect(self._on_fuzzing_complete)
        self.current_worker.error.connect(self._on_error)
        self.current_worker.start()
    
    def _on_fuzzing_complete(self, results):
        """Handle fuzzing completion"""
        self.fuzz_progress.setValue(100)
        
        self.fuzz_results.setRowCount(len(results))
        
        for i, result in enumerate(results):
            self.fuzz_results.setItem(i, 0, QTableWidgetItem(result.payload[:30]))
            self.fuzz_results.setItem(i, 1, QTableWidgetItem(str(result.status_code)))
            self.fuzz_results.setItem(i, 2, QTableWidgetItem(f"{result.response_time:.2f}s"))
            self.fuzz_results.setItem(i, 3, QTableWidgetItem(str(result.response_size)))
            
            interesting = "Yes" if result.interesting else "No"
            interesting_item = QTableWidgetItem(interesting)
            if result.interesting:
                interesting_item.setForeground(QColor("#ff0055"))
            self.fuzz_results.setItem(i, 4, interesting_item)
        
        interesting_count = sum(1 for r in results if r.interesting)
        QMessageBox.information(
            self, "Fuzzing Complete",
            f"Completed {len(results)} requests\n{interesting_count} interesting responses found"
        )
