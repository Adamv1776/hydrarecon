#!/usr/bin/env python3
"""
HydraRecon OSINT Page
Comprehensive Open Source Intelligence gathering interface.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QTabWidget, QGridLayout, QCheckBox,
    QScrollArea, QGroupBox, QTreeWidget, QTreeWidgetItem, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
import asyncio

from ..widgets import ModernLineEdit, ConsoleOutput, ScanProgressWidget, GlowingButton, SeverityBadge


class OSINTThread(QThread):
    """Background thread for OSINT gathering"""
    progress = pyqtSignal(int, str)
    finding = pyqtSignal(dict)
    result = pyqtSignal(dict)
    error = pyqtSignal(str)
    finished_scan = pyqtSignal()
    
    def __init__(self, scanner, target, modules):
        super().__init__()
        self.scanner = scanner
        self.target = target
        self.modules = modules
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            result = loop.run_until_complete(
                self.scanner.scan(self.target, modules=self.modules)
            )
            
            for finding in result.findings:
                self.finding.emit(finding)
            
            self.result.emit(result.data if result.data else {})
            
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished_scan.emit()


class OSINTPage(QWidget):
    """OSINT gathering page"""
    
    MODULES = [
        ("dns", "DNS Enumeration", "Discover DNS records and subdomains"),
        ("whois", "WHOIS Lookup", "Domain registration information"),
        ("ip_intel", "IP Intelligence", "IP geolocation and ASN data"),
        ("shodan", "Shodan Search", "Internet-connected device data"),
        ("cert_transparency", "Certificate Transparency", "SSL certificate logs"),
        ("web_tech", "Web Technology Analysis", "Identify web technologies"),
        ("email_harvest", "Email Harvesting", "Discover email addresses"),
    ]
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self.scanner = None
        self.scan_thread = None
        self._setup_ui()
        self._init_scanner()
    
    def _setup_ui(self):
        """Setup the OSINT page UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(20)
        
        # Header
        header = self._create_header()
        layout.addLayout(header)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Configuration
        left_panel = self._create_config_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = self._create_results_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([400, 800])
        layout.addWidget(splitter)
    
    def _create_header(self) -> QHBoxLayout:
        """Create the header section"""
        layout = QHBoxLayout()
        
        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)
        
        title = QLabel("OSINT Reconnaissance")
        title.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e6e6;")
        
        subtitle = QLabel("Open Source Intelligence gathering and analysis")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        return layout
    
    def _create_config_panel(self) -> QFrame:
        """Create the configuration panel"""
        panel = QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Target input
        target_label = QLabel("Target Domain/IP")
        target_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(target_label)
        
        self.target_input = ModernLineEdit("Enter domain (e.g., example.com) or IP address")
        layout.addWidget(self.target_input)
        
        # Modules selection
        modules_label = QLabel("OSINT Modules")
        modules_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(modules_label)
        
        # Module checkboxes
        self.module_checks = {}
        
        modules_scroll = QScrollArea()
        modules_scroll.setWidgetResizable(True)
        modules_scroll.setMaximumHeight(300)
        modules_scroll.setStyleSheet("""
            QScrollArea {
                background-color: transparent;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        
        modules_widget = QWidget()
        modules_layout = QVBoxLayout(modules_widget)
        modules_layout.setSpacing(8)
        
        for module_id, name, description in self.MODULES:
            module_frame = QFrame()
            module_frame.setStyleSheet("""
                QFrame {
                    background-color: #161b22;
                    border-radius: 6px;
                    padding: 4px;
                }
                QFrame:hover {
                    background-color: #1c2128;
                }
            """)
            module_row = QHBoxLayout(module_frame)
            module_row.setContentsMargins(12, 8, 12, 8)
            
            check = QCheckBox(name)
            check.setChecked(True)
            check.setStyleSheet("color: #e6e6e6; font-weight: 500;")
            self.module_checks[module_id] = check
            
            desc_label = QLabel(description)
            desc_label.setStyleSheet("color: #8b949e; font-size: 11px;")
            
            module_row.addWidget(check)
            module_row.addStretch()
            
            module_inner = QVBoxLayout()
            module_inner.setSpacing(2)
            module_inner.addWidget(module_frame)
            
            modules_layout.addLayout(module_inner)
        
        modules_scroll.setWidget(modules_widget)
        layout.addWidget(modules_scroll)
        
        # Select all/none buttons
        select_layout = QHBoxLayout()
        
        select_all = QPushButton("Select All")
        select_all.clicked.connect(lambda: self._select_modules(True))
        select_all.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        
        select_none = QPushButton("Select None")
        select_none.clicked.connect(lambda: self._select_modules(False))
        select_none.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        
        select_layout.addWidget(select_all)
        select_layout.addWidget(select_none)
        select_layout.addStretch()
        layout.addLayout(select_layout)
        
        # API Keys info
        api_frame = QFrame()
        api_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 136, 255, 0.1);
                border: 1px solid #0088ff;
                border-radius: 8px;
            }
        """)
        api_layout = QHBoxLayout(api_frame)
        api_layout.setContentsMargins(12, 8, 12, 8)
        
        api_icon = QLabel("ℹ️")
        api_text = QLabel("Configure API keys in Settings for enhanced results")
        api_text.setStyleSheet("color: #0088ff; font-size: 12px;")
        
        api_layout.addWidget(api_icon)
        api_layout.addWidget(api_text)
        api_layout.addStretch()
        
        layout.addWidget(api_frame)
        
        layout.addStretch()
        
        # Gather button
        self.gather_btn = GlowingButton("Start Gathering")
        self.gather_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                border: none;
                border-radius: 8px;
                padding: 14px;
                color: white;
                font-weight: 600;
                font-size: 15px;
            }
            QPushButton:hover { background-color: #2ea043; }
            QPushButton:disabled { background-color: #21262d; color: #484f58; }
        """)
        self.gather_btn.clicked.connect(self._start_gathering)
        layout.addWidget(self.gather_btn)
        
        # Stop button
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #da3633;
                border: none;
                border-radius: 8px;
                padding: 14px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #f85149; }
            QPushButton:disabled { background-color: #21262d; color: #484f58; }
        """)
        self.stop_btn.clicked.connect(self._stop_gathering)
        layout.addWidget(self.stop_btn)
        
        return panel
    
    def _create_results_panel(self) -> QFrame:
        """Create the results panel"""
        panel = QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Progress
        self.progress_widget = ScanProgressWidget()
        layout.addWidget(self.progress_widget)
        
        # Results tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 10px 20px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #00ff88;
                border-bottom: 2px solid #00ff88;
            }
        """)
        
        # All findings tab
        findings_tab = QWidget()
        findings_layout = QVBoxLayout(findings_tab)
        findings_layout.setContentsMargins(0, 10, 0, 0)
        
        self.findings_tree = QTreeWidget()
        self.findings_tree.setHeaderLabels(["Finding", "Source", "Severity", "Details"])
        self.findings_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0d1117;
                border: none;
                color: #e6e6e6;
            }
            QTreeWidget::item:hover { background-color: #21262d; }
            QTreeWidget::item:selected { background-color: #238636; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 10px;
            }
        """)
        self.findings_tree.setColumnWidth(0, 200)
        self.findings_tree.setColumnWidth(1, 120)
        self.findings_tree.setColumnWidth(2, 80)
        findings_layout.addWidget(self.findings_tree)
        tabs.addTab(findings_tab, "📋 All Findings")
        
        # DNS tab
        dns_tab = QWidget()
        dns_layout = QVBoxLayout(dns_tab)
        dns_layout.setContentsMargins(0, 10, 0, 0)
        
        self.dns_table = QTableWidget()
        self.dns_table.setColumnCount(3)
        self.dns_table.setHorizontalHeaderLabels(["Record Type", "Value", "TTL"])
        self.dns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.dns_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: none;
                color: #e6e6e6;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 10px;
            }
        """)
        dns_layout.addWidget(self.dns_table)
        tabs.addTab(dns_tab, "🌐 DNS")
        
        # Subdomains tab
        subdomains_tab = QWidget()
        subdomains_layout = QVBoxLayout(subdomains_tab)
        subdomains_layout.setContentsMargins(0, 10, 0, 0)
        
        self.subdomains_table = QTableWidget()
        self.subdomains_table.setColumnCount(3)
        self.subdomains_table.setHorizontalHeaderLabels(["Subdomain", "IP Address", "Status"])
        self.subdomains_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.subdomains_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: none;
                color: #e6e6e6;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 10px;
            }
        """)
        subdomains_layout.addWidget(self.subdomains_table)
        tabs.addTab(subdomains_tab, "🔗 Subdomains")
        
        # Emails tab
        emails_tab = QWidget()
        emails_layout = QVBoxLayout(emails_tab)
        emails_layout.setContentsMargins(0, 10, 0, 0)
        
        self.emails_list = QTextEdit()
        self.emails_list.setReadOnly(True)
        self.emails_list.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: none;
                color: #e6e6e6;
                font-family: monospace;
            }
        """)
        emails_layout.addWidget(self.emails_list)
        tabs.addTab(emails_tab, "📧 Emails")
        
        # Console tab
        console_tab = QWidget()
        console_layout = QVBoxLayout(console_tab)
        console_layout.setContentsMargins(0, 10, 0, 0)
        
        self.console = ConsoleOutput()
        console_layout.addWidget(self.console)
        tabs.addTab(console_tab, "📝 Console")
        
        layout.addWidget(tabs)
        
        return panel
    
    def _init_scanner(self):
        """Initialize the OSINT scanner"""
        try:
            from scanners import OSINTScanner
            self.scanner = OSINTScanner(self.config, self.db)
        except Exception as e:
            self.console.append_error(f"Failed to initialize OSINT scanner: {e}")
    
    def _select_modules(self, select: bool):
        """Select or deselect all modules"""
        for check in self.module_checks.values():
            check.setChecked(select)
    
    def _start_gathering(self):
        """Start OSINT gathering"""
        target = self.target_input.text().strip()
        
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target.")
            return
        
        # Get selected modules
        modules = [
            module_id for module_id, check in self.module_checks.items()
            if check.isChecked()
        ]
        
        if not modules:
            QMessageBox.warning(self, "Warning", "Please select at least one module.")
            return
        
        # Clear previous results
        self.findings_tree.clear()
        self.dns_table.setRowCount(0)
        self.subdomains_table.setRowCount(0)
        self.emails_list.clear()
        self.console.clear()
        
        # Update UI
        self.gather_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_widget.setProgress(0, "Starting OSINT gathering...", f"Target: {target}")
        self.progress_widget.setRunning()
        
        # Start thread
        self.scan_thread = OSINTThread(self.scanner, target, modules)
        self.scan_thread.progress.connect(self._on_progress)
        self.scan_thread.finding.connect(self._on_finding)
        self.scan_thread.result.connect(self._on_result)
        self.scan_thread.error.connect(self._on_error)
        self.scan_thread.finished_scan.connect(self._on_finished)
        self.scan_thread.start()
        
        self.console.append_command(f"OSINT gathering started on {target}")
    
    def _stop_gathering(self):
        """Stop OSINT gathering"""
        if self.scanner:
            self.scanner.cancel()
        if self.scan_thread:
            self.scan_thread.terminate()
        
        self._on_finished()
        self.console.append_warning("Gathering cancelled by user")
    
    def _on_progress(self, value: int, message: str):
        """Handle progress updates"""
        self.progress_widget.setProgress(value, message)
    
    def _on_finding(self, finding: dict):
        """Handle individual finding"""
        finding_type = finding.get('type', 'unknown')
        source = finding.get('source', 'unknown')
        title = finding.get('title', 'Unknown Finding')
        severity = finding.get('severity', 'info')
        data = finding.get('data', {})
        
        # Add to tree
        item = QTreeWidgetItem([title, source, severity, str(data)[:100]])
        
        # Color by severity
        colors = {
            'critical': '#ff4444',
            'high': '#f85149',
            'medium': '#d29922',
            'low': '#238636',
            'info': '#0088ff'
        }
        item.setForeground(2, QColor(colors.get(severity, '#8b949e')))
        
        self.findings_tree.addTopLevelItem(item)
        
        # Process specific finding types
        if finding_type == 'dns_record':
            record_type = data.get('record_type', '')
            values = data.get('values', [])
            for value in values:
                row = self.dns_table.rowCount()
                self.dns_table.insertRow(row)
                self.dns_table.setItem(row, 0, QTableWidgetItem(record_type))
                self.dns_table.setItem(row, 1, QTableWidgetItem(value))
                self.dns_table.setItem(row, 2, QTableWidgetItem('-'))
        
        elif finding_type in ['subdomains', 'ct_subdomains']:
            subdomains = data.get('subdomains', [])
            for sub in subdomains:
                if isinstance(sub, dict):
                    subdomain = sub.get('subdomain', '')
                    ips = ', '.join(sub.get('ips', []))
                    status = 'Active' if sub.get('alive') else 'Unknown'
                else:
                    subdomain = sub
                    ips = ''
                    status = 'Found'
                
                row = self.subdomains_table.rowCount()
                self.subdomains_table.insertRow(row)
                self.subdomains_table.setItem(row, 0, QTableWidgetItem(subdomain))
                self.subdomains_table.setItem(row, 1, QTableWidgetItem(ips))
                self.subdomains_table.setItem(row, 2, QTableWidgetItem(status))
        
        elif finding_type == 'emails':
            emails = data.get('emails', [])
            for email in emails:
                self.emails_list.append(email)
        
        # Log to console
        self.console.append_info(f"[{source}] {title}")
    
    def _on_result(self, data: dict):
        """Handle final results"""
        total = data.get('total_findings', 0)
        self.console.append_success(f"OSINT gathering completed: {total} findings")
    
    def _on_error(self, error: str):
        """Handle errors"""
        self.console.append_error(error)
        self.progress_widget.setError(f"Error: {error[:50]}...")
    
    def _on_finished(self):
        """Handle completion"""
        self.gather_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_widget.setCompleted()
