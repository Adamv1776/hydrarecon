#!/usr/bin/env python3
"""
HydraRecon Nmap Scanner Page
Advanced Nmap scanning interface with real-time results.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QTabWidget, QGridLayout, QCheckBox,
    QSpinBox, QGroupBox, QScrollArea, QTreeWidget, QTreeWidgetItem,
    QProgressBar, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
import asyncio

from ..widgets import (
    ModernLineEdit, ConsoleOutput, ScanProgressWidget,
    TargetInputWidget, GlowingButton, SeverityBadge
)


class NmapScanThread(QThread):
    """Background thread for Nmap scanning"""
    progress = pyqtSignal(int, str)
    result = pyqtSignal(dict)
    error = pyqtSignal(str)
    finished_scan = pyqtSignal()
    
    def __init__(self, scanner, target, profile, options):
        super().__init__()
        self.scanner = scanner
        self.target = target
        self.profile = profile
        self.options = options
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            result = loop.run_until_complete(
                self.scanner.scan(self.target, profile=self.profile, **self.options)
            )
            
            self.result.emit(result.data if result.data else {})
            
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished_scan.emit()


class NmapPage(QWidget):
    """Nmap scanner page"""
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self.scanner = None
        self.scan_thread = None
        self._setup_ui()
        self._init_scanner()
    
    def _setup_ui(self):
        """Setup the Nmap page UI"""
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
        
        title = QLabel("Nmap Scanner")
        title.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e6e6;")
        
        subtitle = QLabel("Network discovery and security auditing")
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
        target_label = QLabel("Target")
        target_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(target_label)
        
        self.target_input = ModernLineEdit("IP, hostname, or CIDR (e.g., 192.168.1.1/24)")
        layout.addWidget(self.target_input)
        
        # Scan profile
        profile_label = QLabel("Scan Profile")
        profile_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(profile_label)
        
        self.profile_combo = QComboBox()
        self.profile_combo.addItems([
            "🚀 Quick Scan (fast)",
            "📊 Standard Scan",
            "🔬 Comprehensive Scan",
            "🥷 Stealth Scan (SYN)",
            "💥 Aggressive Scan",
            "🔓 Vulnerability Scan",
            "📡 Host Discovery",
            "📶 UDP Scan",
            "🌐 Web Server Scan",
            "🔍 Full Audit"
        ])
        self.profile_combo.setCurrentIndex(1)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        self.profile_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding: 10px 14px;
                color: #e6e6e6;
            }
            QComboBox:hover { border-color: #484f58; }
            QComboBox:focus { border-color: #00ff88; }
        """)
        layout.addWidget(self.profile_combo)
        
        # Profile description
        self.profile_desc = QLabel("Standard port scan with service detection")
        self.profile_desc.setStyleSheet("color: #8b949e; font-size: 11px; font-style: italic;")
        self.profile_desc.setWordWrap(True)
        layout.addWidget(self.profile_desc)
        
        # Quick Port Buttons
        quick_ports_label = QLabel("Quick Port Selection")
        quick_ports_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(quick_ports_label)
        
        quick_btn_layout1 = QHBoxLayout()
        quick_btn_layout2 = QHBoxLayout()
        
        quick_port_options = [
            ("Top 20", "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080", "Most commonly open ports"),
            ("Top 100", "1-100,443,445,3306,3389,5900,8080,8443", "First 100 + common high ports"),
            ("Web", "80,443,8080,8443,8000,8888,9000", "Web servers and proxies"),
            ("SSH/RDP", "22,3389,5900,5901", "Remote access services"),
            ("Database", "1433,1521,3306,5432,27017,6379", "SQL and NoSQL databases"),
            ("Mail", "25,110,143,465,587,993,995", "Email services"),
            ("All Ports", "1-65535", "⚠️ Full scan (very slow)"),
            ("Common", "21,22,23,25,53,80,110,139,143,443,445,3389", "Quick essential check"),
        ]
        
        for i, (name, ports, tooltip) in enumerate(quick_port_options):
            btn = QPushButton(name)
            btn.setToolTip(f"{tooltip}")
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #21262d;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 8px 12px;
                    color: #00ff88;
                    font-size: 11px;
                }
                QPushButton:hover { background-color: #30363d; border-color: #00ff88; }
            """)
            btn.clicked.connect(lambda checked, p=ports: self.ports_input.setText(p))
            if i < 4:
                quick_btn_layout1.addWidget(btn)
            else:
                quick_btn_layout2.addWidget(btn)
        
        layout.addLayout(quick_btn_layout1)
        layout.addLayout(quick_btn_layout2)
        
        # Port specification
        ports_label = QLabel("Ports (optional)")
        ports_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(ports_label)
        
        self.ports_input = ModernLineEdit("e.g., 22,80,443 or 1-1000")
        layout.addWidget(self.ports_input)
        
        # Advanced options
        advanced_group = QGroupBox("Advanced Options")
        advanced_group.setStyleSheet("""
            QGroupBox {
                color: #e6e6e6;
                font-weight: 600;
                border: 1px solid #21262d;
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
        advanced_layout = QVBoxLayout(advanced_group)
        advanced_layout.setSpacing(10)
        
        self.os_detection = QCheckBox("OS Detection")
        self.os_detection.setChecked(True)
        self.os_detection.setStyleSheet("color: #e6e6e6;")
        
        self.service_detection = QCheckBox("Service Version Detection")
        self.service_detection.setChecked(True)
        self.service_detection.setStyleSheet("color: #e6e6e6;")
        
        self.script_scan = QCheckBox("Default Scripts")
        self.script_scan.setChecked(True)
        self.script_scan.setStyleSheet("color: #e6e6e6;")
        
        self.aggressive = QCheckBox("Aggressive Timing")
        self.aggressive.setStyleSheet("color: #e6e6e6;")
        
        advanced_layout.addWidget(self.os_detection)
        advanced_layout.addWidget(self.service_detection)
        advanced_layout.addWidget(self.script_scan)
        advanced_layout.addWidget(self.aggressive)
        
        layout.addWidget(advanced_group)
        
        # Timing
        timing_layout = QHBoxLayout()
        timing_label = QLabel("Timing Template:")
        timing_label.setStyleSheet("color: #e6e6e6;")
        
        self.timing_spin = QSpinBox()
        self.timing_spin.setRange(0, 5)
        self.timing_spin.setValue(4)
        self.timing_spin.setStyleSheet("""
            QSpinBox {
                background-color: #0d1117;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding: 6px;
                color: #e6e6e6;
            }
        """)
        
        timing_layout.addWidget(timing_label)
        timing_layout.addWidget(self.timing_spin)
        timing_layout.addStretch()
        layout.addLayout(timing_layout)
        
        layout.addStretch()
        
        # Scan button
        self.scan_btn = GlowingButton("Start Scan")
        self.scan_btn.setStyleSheet("""
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
        self.scan_btn.clicked.connect(self._start_scan)
        layout.addWidget(self.scan_btn)
        
        # Stop button
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #da3633;
                border: none;
                border-radius: 8px;
                padding: 14px;
                color: white;
                font-weight: 600;
                font-size: 15px;
            }
            QPushButton:hover { background-color: #f85149; }
            QPushButton:disabled { background-color: #21262d; color: #484f58; }
        """)
        self.stop_btn.clicked.connect(self._stop_scan)
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
        
        # Progress section
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
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #00ff88;
                border-bottom: 2px solid #00ff88;
            }
        """)
        
        # Hosts tab
        hosts_tab = QWidget()
        hosts_layout = QVBoxLayout(hosts_tab)
        hosts_layout.setContentsMargins(0, 10, 0, 0)
        
        self.hosts_tree = QTreeWidget()
        self.hosts_tree.setHeaderLabels(["Host", "State", "OS", "Ports"])
        self.hosts_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0d1117;
                border: none;
                color: #e6e6e6;
            }
            QTreeWidget::item:hover {
                background-color: #21262d;
            }
            QTreeWidget::item:selected {
                background-color: #238636;
            }
        """)
        self.hosts_tree.header().setStyleSheet("""
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 10px;
            }
        """)
        hosts_layout.addWidget(self.hosts_tree)
        tabs.addTab(hosts_tab, "Hosts")
        
        # Ports tab
        ports_tab = QWidget()
        ports_layout = QVBoxLayout(ports_tab)
        ports_layout.setContentsMargins(0, 10, 0, 0)
        
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(6)
        self.ports_table.setHorizontalHeaderLabels([
            "Port", "Protocol", "State", "Service", "Version", "Info"
        ])
        self.ports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ports_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: none;
                color: #e6e6e6;
                gridline-color: #21262d;
            }
            QTableWidget::item:selected {
                background-color: #238636;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 10px;
            }
        """)
        ports_layout.addWidget(self.ports_table)
        tabs.addTab(ports_tab, "Ports")
        
        # Scripts tab
        scripts_tab = QWidget()
        scripts_layout = QVBoxLayout(scripts_tab)
        scripts_layout.setContentsMargins(0, 10, 0, 0)
        
        self.scripts_output = ConsoleOutput()
        scripts_layout.addWidget(self.scripts_output)
        tabs.addTab(scripts_tab, "Scripts Output")
        
        # Raw output tab
        raw_tab = QWidget()
        raw_layout = QVBoxLayout(raw_tab)
        raw_layout.setContentsMargins(0, 10, 0, 0)
        
        self.raw_output = ConsoleOutput()
        raw_layout.addWidget(self.raw_output)
        tabs.addTab(raw_tab, "Raw Output")
        
        layout.addWidget(tabs)
        
        return panel
    
    def _init_scanner(self):
        """Initialize the Nmap scanner"""
        try:
            from scanners import NmapScanner
            self.scanner = NmapScanner(self.config, self.db)
            if self.scanner.nmap_available:
                self.raw_output.append_success(f"Nmap scanner initialized (v{self.scanner.nmap_version})")
            else:
                self.raw_output.append_warning("Nmap not found! Install with: sudo apt install nmap")
                self.raw_output.append_info("Scanner will show error if scan is attempted without Nmap")
        except Exception as e:
            self.scanner = None
            self.raw_output.append_error(f"Failed to initialize Nmap scanner: {e}")
    
    def _on_profile_changed(self, index: int):
        """Update profile description when changed"""
        descriptions = [
            "Fast scan of common ports - great for initial reconnaissance",
            "Standard port scan with service detection and version info",
            "Deep scan with OS detection, scripts, and traceroute",
            "SYN scan that's harder to detect - use for stealth",
            "Fast and comprehensive but noisy - may trigger IDS",
            "Run vulnerability detection scripts against open services",
            "Just find live hosts without port scanning",
            "Scan UDP ports (slow but finds hidden services)",
            "Focus on web-related ports and HTTP services",
            "Complete audit with all detection features enabled"
        ]
        if 0 <= index < len(descriptions):
            self.profile_desc.setText(descriptions[index])
    
    def _start_scan(self):
        """Start the Nmap scan"""
        target = self.target_input.text().strip()
        
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target.")
            return
        
        if self.scanner is None:
            QMessageBox.critical(self, "Error", "Nmap scanner not initialized.")
            return
        
        if not self.scanner.nmap_available:
            QMessageBox.critical(self, "Error", "Nmap is not installed!\n\nInstall with:\nsudo apt install nmap")
            return
        
        # Get profile
        profile_map = {
            0: 'quick',
            1: 'standard',
            2: 'comprehensive',
            3: 'stealth',
            4: 'aggressive',
            5: 'vuln',
            6: 'discovery',
            7: 'udp',
            8: 'web',
            9: 'full'
        }
        profile = profile_map.get(self.profile_combo.currentIndex(), 'standard')
        
        # Get options
        options = {
            'ports': self.ports_input.text().strip() or None
        }
        
        # Clear previous results
        self.hosts_tree.clear()
        self.ports_table.setRowCount(0)
        self.scripts_output.clear()
        self.raw_output.clear()
        
        # Update UI
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_widget.setProgress(0, "Starting scan...", f"Target: {target}")
        self.progress_widget.setRunning()
        
        # Start scan thread
        self.scan_thread = NmapScanThread(self.scanner, target, profile, options)
        self.scan_thread.progress.connect(self._on_progress)
        self.scan_thread.result.connect(self._on_result)
        self.scan_thread.error.connect(self._on_error)
        self.scan_thread.finished_scan.connect(self._on_finished)
        self.scan_thread.start()
        
        self.raw_output.append_command(f"nmap scan started on {target}")
    
    def _stop_scan(self):
        """Stop the current scan"""
        if self.scanner:
            self.scanner.cancel()
        if self.scan_thread:
            self.scan_thread.terminate()
        
        self._on_finished()
        self.raw_output.append_warning("Scan cancelled by user")
    
    def _on_progress(self, value: int, message: str):
        """Handle progress updates"""
        self.progress_widget.setProgress(value, message)
    
    def _on_result(self, data: dict):
        """Handle scan results"""
        if not data:
            return
        
        # Process hosts
        for host_data in data.get('hosts', []):
            ip = host_data.get('ip_address', 'Unknown')
            hostname = host_data.get('hostname', '')
            state = host_data.get('state', 'unknown')
            os_matches = host_data.get('os_matches', [])
            os_name = os_matches[0]['name'] if os_matches else 'Unknown'
            ports = host_data.get('ports', [])
            
            # Add to tree
            host_item = QTreeWidgetItem([
                f"{ip} ({hostname})" if hostname else ip,
                state,
                os_name[:30] + '...' if len(os_name) > 30 else os_name,
                str(len([p for p in ports if p.get('state') == 'open']))
            ])
            
            # Color based on state
            if state == 'up':
                host_item.setForeground(0, QColor('#00ff88'))
            
            self.hosts_tree.addTopLevelItem(host_item)
            
            # Add ports to table
            for port_data in ports:
                if port_data.get('state') == 'open':
                    row = self.ports_table.rowCount()
                    self.ports_table.insertRow(row)
                    
                    self.ports_table.setItem(row, 0, QTableWidgetItem(str(port_data.get('port', ''))))
                    self.ports_table.setItem(row, 1, QTableWidgetItem(port_data.get('protocol', '')))
                    self.ports_table.setItem(row, 2, QTableWidgetItem(port_data.get('state', '')))
                    self.ports_table.setItem(row, 3, QTableWidgetItem(port_data.get('service', '')))
                    self.ports_table.setItem(row, 4, QTableWidgetItem(port_data.get('version', '')))
                    self.ports_table.setItem(row, 5, QTableWidgetItem(port_data.get('extrainfo', '')))
                
                # Scripts output
                for script_name, script_output in port_data.get('scripts', {}).items():
                    self.scripts_output.append_info(f"Script: {script_name}")
                    self.scripts_output.append_output(script_output)
        
        # Summary
        hosts_up = data.get('hosts_up', 0)
        self.raw_output.append_success(f"Scan completed: {hosts_up} host(s) up")
    
    def _on_error(self, error: str):
        """Handle scan errors"""
        self.raw_output.append_error(error)
        self.progress_widget.setError(f"Error: {error[:50]}...")
    
    def _on_finished(self):
        """Handle scan completion"""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_widget.setCompleted()
