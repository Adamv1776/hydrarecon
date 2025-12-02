"""
API Discovery Page
GUI for API endpoint discovery and security testing
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QComboBox, QCheckBox, QProgressBar,
    QSplitter, QFrame, QHeaderView, QSpinBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont
import asyncio
import json

# Import the API discovery engine
import sys
sys.path.insert(0, '..')
from core.api_discovery import APIDiscoveryEngine, APISecurityTester


class DiscoveryWorker(QThread):
    """Worker thread for API discovery"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, target, deep_scan=False):
        super().__init__()
        self.target = target
        self.deep_scan = deep_scan
        
    def run(self):
        try:
            async def discover():
                async with APIDiscoveryEngine() as engine:
                    self.progress.emit(f"Discovering APIs on {self.target}...")
                    results = await engine.discover(
                        self.target,
                        deep_scan=self.deep_scan
                    )
                    
                    # Run security tests
                    tester = APISecurityTester(engine)
                    findings = await tester.run_security_tests(engine.discovered_endpoints)
                    results["security_findings"] = findings
                    
                    return results
                    
            results = asyncio.run(discover())
            self.finished.emit(results)
            
        except Exception as e:
            self.error.emit(str(e))


class APIDiscoveryPage(QWidget):
    """API Discovery and Testing Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Header
        header = QLabel("🔌 API Discovery & Security Testing")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #00ff88;
            padding-bottom: 10px;
        """)
        layout.addWidget(header)
        
        # Target input section
        target_group = QGroupBox("Target Configuration")
        target_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #1a1a2e;
            }
            QGroupBox::title {
                color: #00ff88;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        target_layout = QVBoxLayout(target_group)
        
        # URL input
        url_row = QHBoxLayout()
        url_label = QLabel("Target URL:")
        url_label.setFixedWidth(100)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://api.example.com")
        self.url_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #16213e;
                color: white;
            }
        """)
        url_row.addWidget(url_label)
        url_row.addWidget(self.url_input)
        target_layout.addLayout(url_row)
        
        # Options row
        options_row = QHBoxLayout()
        
        self.deep_scan = QCheckBox("Deep Scan")
        self.deep_scan.setStyleSheet("color: white;")
        
        self.test_security = QCheckBox("Security Testing")
        self.test_security.setChecked(True)
        self.test_security.setStyleSheet("color: white;")
        
        self.scan_btn = QPushButton("🔍 Start Discovery")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #00ff88, #00cc6a);
                color: black;
                font-weight: bold;
                padding: 10px 30px;
                border-radius: 5px;
                border: none;
            }
            QPushButton:hover {
                background: linear-gradient(135deg, #00cc6a, #00ff88);
            }
        """)
        self.scan_btn.clicked.connect(self._start_discovery)
        
        options_row.addWidget(self.deep_scan)
        options_row.addWidget(self.test_security)
        options_row.addStretch()
        options_row.addWidget(self.scan_btn)
        target_layout.addLayout(options_row)
        
        layout.addWidget(target_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #16213e;
                height: 20px;
            }
            QProgressBar::chunk {
                background: linear-gradient(90deg, #00ff88, #00cc6a);
            }
        """)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #333;
                background-color: #1a1a2e;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #16213e;
                color: #888;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #1a1a2e;
                color: #00ff88;
            }
        """)
        
        # Endpoints tab
        endpoints_widget = QWidget()
        endpoints_layout = QVBoxLayout(endpoints_widget)
        
        self.endpoints_table = QTableWidget()
        self.endpoints_table.setColumnCount(6)
        self.endpoints_table.setHorizontalHeaderLabels([
            "URL", "Method", "Type", "Auth", "Status", "Response Time"
        ])
        self.endpoints_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.endpoints_table.setStyleSheet("""
            QTableWidget {
                background-color: #16213e;
                color: white;
                border: none;
                gridline-color: #333;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #333;
            }
        """)
        endpoints_layout.addWidget(self.endpoints_table)
        
        self.results_tabs.addTab(endpoints_widget, "📡 Endpoints")
        
        # Security findings tab
        security_widget = QWidget()
        security_layout = QVBoxLayout(security_widget)
        
        self.security_table = QTableWidget()
        self.security_table.setColumnCount(4)
        self.security_table.setHorizontalHeaderLabels([
            "Type", "Severity", "Endpoint", "Description"
        ])
        self.security_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.security_table.setStyleSheet("""
            QTableWidget {
                background-color: #16213e;
                color: white;
                border: none;
                gridline-color: #333;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #333;
            }
        """)
        security_layout.addWidget(self.security_table)
        
        self.results_tabs.addTab(security_widget, "⚠️ Security Findings")
        
        # Schema tab
        schema_widget = QWidget()
        schema_layout = QVBoxLayout(schema_widget)
        
        self.schema_text = QTextEdit()
        self.schema_text.setReadOnly(True)
        self.schema_text.setStyleSheet("""
            QTextEdit {
                background-color: #16213e;
                color: #00ff88;
                border: none;
                font-family: monospace;
            }
        """)
        schema_layout.addWidget(self.schema_text)
        
        self.results_tabs.addTab(schema_widget, "📋 API Schema")
        
        # Statistics tab
        stats_widget = QWidget()
        stats_layout = QVBoxLayout(stats_widget)
        
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setStyleSheet("""
            QTextEdit {
                background-color: #16213e;
                color: white;
                border: none;
                font-family: monospace;
            }
        """)
        stats_layout.addWidget(self.stats_text)
        
        self.results_tabs.addTab(stats_widget, "📊 Statistics")
        
        layout.addWidget(self.results_tabs)
        
        # Status label
        self.status_label = QLabel("Ready to scan")
        self.status_label.setStyleSheet("color: #888;")
        layout.addWidget(self.status_label)
        
    def _start_discovery(self):
        """Start API discovery"""
        target = self.url_input.text().strip()
        
        if not target:
            self.status_label.setText("❌ Please enter a target URL")
            return
            
        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText(f"Scanning {target}...")
        
        # Start worker thread
        self.worker = DiscoveryWorker(target, self.deep_scan.isChecked())
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.start()
        
    def _on_progress(self, message):
        """Handle progress updates"""
        self.status_label.setText(message)
        
    def _on_finished(self, results):
        """Handle discovery completion"""
        self.progress_bar.setVisible(False)
        self.scan_btn.setEnabled(True)
        
        # Populate endpoints table
        endpoints = results.get("endpoints", [])
        self.endpoints_table.setRowCount(len(endpoints))
        
        for i, ep in enumerate(endpoints):
            self.endpoints_table.setItem(i, 0, QTableWidgetItem(ep.get("url", "")))
            self.endpoints_table.setItem(i, 1, QTableWidgetItem(ep.get("method", "")))
            self.endpoints_table.setItem(i, 2, QTableWidgetItem(ep.get("api_type", "")))
            self.endpoints_table.setItem(i, 3, QTableWidgetItem(ep.get("auth_type", "")))
            self.endpoints_table.setItem(i, 4, QTableWidgetItem(str(ep.get("status_code", ""))))
            self.endpoints_table.setItem(i, 5, QTableWidgetItem(f"{ep.get('response_time', 0):.3f}s"))
            
        # Populate security findings
        findings = results.get("security_findings", [])
        self.security_table.setRowCount(len(findings))
        
        for i, finding in enumerate(findings):
            self.security_table.setItem(i, 0, QTableWidgetItem(finding.get("type", "")))
            severity_item = QTableWidgetItem(finding.get("severity", ""))
            if finding.get("severity") == "CRITICAL":
                severity_item.setBackground(Qt.GlobalColor.red)
            elif finding.get("severity") == "HIGH":
                severity_item.setBackground(Qt.GlobalColor.darkRed)
            self.security_table.setItem(i, 1, severity_item)
            self.security_table.setItem(i, 2, QTableWidgetItem(finding.get("endpoint", "")))
            self.security_table.setItem(i, 3, QTableWidgetItem(finding.get("description", "")))
            
        # Show schema
        schemas = results.get("schemas", [])
        if schemas:
            self.schema_text.setText(json.dumps(schemas, indent=2))
        else:
            self.schema_text.setText("No API schemas discovered")
            
        # Show statistics
        stats = results.get("statistics", {})
        stats_text = f"""
API Discovery Results
{'='*50}

Target: {results.get('target', 'N/A')}
API Type: {results.get('api_type', 'unknown')}
Technologies: {', '.join(results.get('technologies', []))}

Endpoints Found: {stats.get('total_endpoints', 0)}
Vulnerable Endpoints: {stats.get('vulnerable_endpoints', 0)}

By Method:
{json.dumps(stats.get('by_method', {}), indent=2)}

By Status Code:
{json.dumps(stats.get('by_status', {}), indent=2)}

By Auth Type:
{json.dumps(stats.get('by_auth', {}), indent=2)}

Security Findings: {len(findings)}
"""
        self.stats_text.setText(stats_text)
        
        self.status_label.setText(f"✅ Scan complete! Found {stats.get('total_endpoints', 0)} endpoints")
        
    def _on_error(self, error):
        """Handle error"""
        self.progress_bar.setVisible(False)
        self.scan_btn.setEnabled(True)
        self.status_label.setText(f"❌ Error: {error}")
