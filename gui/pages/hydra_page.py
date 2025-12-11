#!/usr/bin/env python3
"""
HydraRecon Hydra Attack Page
Brute-force attack interface with multiple protocol support.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QTabWidget, QGridLayout, QCheckBox,
    QSpinBox, QGroupBox, QFileDialog, QMessageBox, QListWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
import asyncio

from ..widgets import ModernLineEdit, ConsoleOutput, ScanProgressWidget, GlowingButton


class HydraScanThread(QThread):
    """Background thread for Hydra attacks"""
    progress = pyqtSignal(int, str)
    result = pyqtSignal(dict)
    credential = pyqtSignal(dict)
    error = pyqtSignal(str)
    finished_scan = pyqtSignal()
    
    def __init__(self, scanner, target, protocol, port, options):
        super().__init__()
        self.scanner = scanner
        self.target = target
        self.protocol = protocol
        self.port = port
        self.options = options
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            result = loop.run_until_complete(
                self.scanner.scan(
                    self.target,
                    protocol=self.protocol,
                    port=self.port,
                    **self.options
                )
            )
            
            # Emit found credentials
            for finding in result.findings:
                if finding.get('type') == 'credential':
                    self.credential.emit(finding)
            
            self.result.emit(result.data if result.data else {})
            
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished_scan.emit()


class HydraPage(QWidget):
    """Hydra brute-force attack page"""
    
    PROTOCOLS = [
        ("SSH", "ssh", 22),
        ("FTP", "ftp", 21),
        ("Telnet", "telnet", 23),
        ("HTTP GET", "http-get", 80),
        ("HTTP POST", "http-post", 80),
        ("HTTP Form", "http-form-post", 80),
        ("HTTPS GET", "https-get", 443),
        ("HTTPS POST", "https-post", 443),
        ("SMB", "smb", 445),
        ("MySQL", "mysql", 3306),
        ("MSSQL", "mssql", 1433),
        ("PostgreSQL", "postgres", 5432),
        ("Oracle", "oracle", 1521),
        ("VNC", "vnc", 5900),
        ("RDP", "rdp", 3389),
        ("SMTP", "smtp", 25),
        ("POP3", "pop3", 110),
        ("IMAP", "imap", 143),
        ("LDAP", "ldap", 389),
        ("Redis", "redis", 6379),
        ("MongoDB", "mongodb", 27017),
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
        """Setup the Hydra page UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(20)
        
        # Header
        header = self._create_header()
        layout.addLayout(header)
        
        # Warning banner
        warning = QFrame()
        warning.setStyleSheet("""
            QFrame {
                background-color: rgba(218, 54, 51, 0.1);
                border: 1px solid #da3633;
                border-radius: 8px;
            }
        """)
        warning_layout = QHBoxLayout(warning)
        warning_layout.setContentsMargins(16, 12, 16, 12)
        
        warning_icon = QLabel("⚠️")
        warning_icon.setStyleSheet("font-size: 18px;")
        
        warning_text = QLabel("Warning: Only use on systems you are authorized to test. Unauthorized access is illegal.")
        warning_text.setStyleSheet("color: #f85149; font-size: 13px;")
        
        warning_layout.addWidget(warning_icon)
        warning_layout.addWidget(warning_text)
        warning_layout.addStretch()
        
        layout.addWidget(warning)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Configuration
        left_panel = self._create_config_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = self._create_results_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([450, 750])
        layout.addWidget(splitter)
    
    def _create_header(self) -> QHBoxLayout:
        """Create the header section"""
        layout = QHBoxLayout()
        
        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)
        
        title = QLabel("Hydra Attack")
        title.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e6e6;")
        
        subtitle = QLabel("Password brute-force and credential testing")
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
        
        # Target section
        target_label = QLabel("Target Host")
        target_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        layout.addWidget(target_label)
        
        self.target_input = ModernLineEdit("IP address or hostname")
        layout.addWidget(self.target_input)
        
        # Protocol and Port
        proto_port_layout = QHBoxLayout()
        
        proto_layout = QVBoxLayout()
        proto_label = QLabel("Protocol")
        proto_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        proto_layout.addWidget(proto_label)
        
        self.protocol_combo = QComboBox()
        for name, _, _ in self.PROTOCOLS:
            self.protocol_combo.addItem(name)
        self.protocol_combo.currentIndexChanged.connect(self._on_protocol_changed)
        self.protocol_combo.setToolTip("Select the protocol/service to attack")
        self.protocol_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding: 10px 14px;
                color: #e6e6e6;
                min-width: 150px;
            }
        """)
        proto_layout.addWidget(self.protocol_combo)
        
        # Protocol hint
        self.proto_hint = QLabel("SSH secure shell remote access")
        self.proto_hint.setStyleSheet("color: #8b949e; font-size: 10px;")
        proto_layout.addWidget(self.proto_hint)
        
        proto_port_layout.addLayout(proto_layout)
        
        port_layout = QVBoxLayout()
        port_label = QLabel("Port")
        port_label.setStyleSheet("color: #e6e6e6; font-weight: 600;")
        port_layout.addWidget(port_label)
        
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(22)
        self.port_spin.setStyleSheet("""
            QSpinBox {
                background-color: #0d1117;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        port_layout.addWidget(self.port_spin)
        proto_port_layout.addLayout(port_layout)
        
        layout.addLayout(proto_port_layout)
        
        # Username section
        user_group = QGroupBox("Usernames")
        user_group.setStyleSheet("""
            QGroupBox {
                color: #e6e6e6;
                font-weight: 600;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
            }
        """)
        user_layout = QVBoxLayout(user_group)
        
        self.single_user = QLineEdit()
        self.single_user.setPlaceholderText("Single username (e.g., admin)")
        self.single_user.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        user_layout.addWidget(self.single_user)
        
        user_file_layout = QHBoxLayout()
        self.user_file = QLineEdit()
        self.user_file.setPlaceholderText("Or select username wordlist...")
        self.user_file.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        user_browse = QPushButton("Browse")
        user_browse.clicked.connect(lambda: self._browse_file(self.user_file))
        user_browse.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        user_file_layout.addWidget(self.user_file)
        user_file_layout.addWidget(user_browse)
        user_layout.addLayout(user_file_layout)
        
        layout.addWidget(user_group)
        
        # Password section
        pass_group = QGroupBox("Passwords")
        pass_group.setStyleSheet("""
            QGroupBox {
                color: #e6e6e6;
                font-weight: 600;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
            }
        """)
        pass_layout = QVBoxLayout(pass_group)
        
        self.single_pass = QLineEdit()
        self.single_pass.setPlaceholderText("Single password")
        self.single_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.single_pass.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        pass_layout.addWidget(self.single_pass)
        
        pass_file_layout = QHBoxLayout()
        self.pass_file = QLineEdit()
        self.pass_file.setPlaceholderText("Or select password wordlist...")
        self.pass_file.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        pass_browse = QPushButton("Browse")
        pass_browse.clicked.connect(lambda: self._browse_file(self.pass_file))
        pass_browse.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        pass_file_layout.addWidget(self.pass_file)
        pass_file_layout.addWidget(pass_browse)
        pass_layout.addLayout(pass_file_layout)
        
        layout.addWidget(pass_group)
        
        # Options
        options_layout = QHBoxLayout()
        
        tasks_label = QLabel("Tasks:")
        tasks_label.setStyleSheet("color: #e6e6e6;")
        self.tasks_spin = QSpinBox()
        self.tasks_spin.setRange(1, 64)
        self.tasks_spin.setValue(16)
        self.tasks_spin.setStyleSheet("""
            QSpinBox {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px;
                color: #e6e6e6;
            }
        """)
        
        self.stop_first = QCheckBox("Stop on first")
        self.stop_first.setChecked(True)
        self.stop_first.setStyleSheet("color: #e6e6e6;")
        
        self.verbose = QCheckBox("Verbose")
        self.verbose.setStyleSheet("color: #e6e6e6;")
        
        options_layout.addWidget(tasks_label)
        options_layout.addWidget(self.tasks_spin)
        options_layout.addWidget(self.stop_first)
        options_layout.addWidget(self.verbose)
        options_layout.addStretch()
        
        layout.addLayout(options_layout)
        
        layout.addStretch()
        
        # Attack button
        self.attack_btn = GlowingButton("Start Attack", accent_color="#da3633")
        self.attack_btn.setStyleSheet("""
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
        self.attack_btn.clicked.connect(self._start_attack)
        layout.addWidget(self.attack_btn)
        
        # Stop button
        self.stop_btn = QPushButton("Stop Attack")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 14px;
                color: #e6e6e6;
                font-weight: 600;
                font-size: 15px;
            }
            QPushButton:hover { background-color: #30363d; }
            QPushButton:disabled { background-color: #161b22; color: #484f58; }
        """)
        self.stop_btn.clicked.connect(self._stop_attack)
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
        
        # Tabs
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
        
        # Credentials found tab
        creds_tab = QWidget()
        creds_layout = QVBoxLayout(creds_tab)
        creds_layout.setContentsMargins(0, 10, 0, 0)
        
        self.creds_table = QTableWidget()
        self.creds_table.setColumnCount(5)
        self.creds_table.setHorizontalHeaderLabels([
            "Host", "Port", "Service", "Username", "Password"
        ])
        self.creds_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.creds_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: none;
                color: #e6e6e6;
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
        creds_layout.addWidget(self.creds_table)
        tabs.addTab(creds_tab, "🔑 Credentials Found")
        
        # Output tab
        output_tab = QWidget()
        output_layout = QVBoxLayout(output_tab)
        output_layout.setContentsMargins(0, 10, 0, 0)
        
        self.output_console = ConsoleOutput()
        output_layout.addWidget(self.output_console)
        tabs.addTab(output_tab, "📝 Output")
        
        layout.addWidget(tabs)
        
        return panel
    
    def _init_scanner(self):
        """Initialize the Hydra scanner"""
        try:
            from scanners import HydraScanner
            self.scanner = HydraScanner(self.config, self.db)
            if self.scanner.hydra_available:
                self.output_console.append_success(f"Hydra scanner initialized (v{self.scanner.hydra_version})")
            else:
                self.output_console.append_warning("Hydra not found! Install with: sudo apt install hydra")
                self.output_console.append_info("Scanner will show error if attack is attempted without Hydra")
        except Exception as e:
            self.scanner = None
            self.output_console.append_error(f"Failed to initialize Hydra scanner: {e}")
    
    def _on_protocol_changed(self, index: int):
        """Update port and hint when protocol changes"""
        if 0 <= index < len(self.PROTOCOLS):
            name, proto, default_port = self.PROTOCOLS[index]
            self.port_spin.setValue(default_port)
            
            # Protocol hints
            hints = {
                "ssh": "SSH secure shell - use for remote server access",
                "ftp": "FTP file transfer - often has weak credentials",
                "telnet": "Telnet legacy protocol - usually unencrypted",
                "http-get": "HTTP Basic Auth - web server authentication",
                "http-post": "HTTP POST login - form-based authentication",
                "http-form-post": "HTTP Form - for login forms",
                "https-get": "HTTPS Basic Auth - encrypted web auth",
                "https-post": "HTTPS POST - encrypted form login",
                "smb": "SMB Windows shares - domain/workgroup access",
                "mysql": "MySQL database - default: root with no password",
                "mssql": "MSSQL Server - default: sa account",
                "postgres": "PostgreSQL - default: postgres user",
                "oracle": "Oracle DB - check for scott/tiger",
                "vnc": "VNC remote desktop - often single password",
                "rdp": "RDP Windows remote - domain or local accounts",
                "smtp": "SMTP mail server - check for relaying",
                "pop3": "POP3 mail - email account access",
                "imap": "IMAP mail - email account access",
                "ldap": "LDAP directory - Active Directory",
                "redis": "Redis cache - often no auth by default",
                "mongodb": "MongoDB NoSQL - often no auth",
            }
            hint = hints.get(proto, f"Protocol: {proto}")
            if hasattr(self, 'proto_hint'):
                self.proto_hint.setText(hint)
    
    def _browse_file(self, line_edit):
        """Browse for wordlist file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", "",
            "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            line_edit.setText(file_path)
    
    def _start_attack(self):
        """Start the brute-force attack"""
        if not self.scanner:
            QMessageBox.critical(self, "Error", "Hydra scanner not initialized. Check the output console for details.")
            return
            
        if not self.scanner.hydra_available:
            QMessageBox.critical(self, "Error", "Hydra is not installed!\n\nInstall with:\nsudo apt install hydra")
            return
        
        target = self.target_input.text().strip()
        
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target host.")
            return
        
        # Get usernames
        usernames = None
        username_file = None
        if self.single_user.text().strip():
            usernames = [self.single_user.text().strip()]
        elif self.user_file.text().strip():
            username_file = self.user_file.text().strip()
        else:
            QMessageBox.warning(self, "Warning", "Please specify username(s).")
            return
        
        # Get passwords
        passwords = None
        password_file = None
        if self.single_pass.text():
            passwords = [self.single_pass.text()]
        elif self.pass_file.text().strip():
            password_file = self.pass_file.text().strip()
        else:
            QMessageBox.warning(self, "Warning", "Please specify password(s).")
            return
        
        # Get protocol and port
        idx = self.protocol_combo.currentIndex()
        _, protocol, _ = self.PROTOCOLS[idx]
        port = self.port_spin.value()
        
        # Options
        options = {
            'usernames': usernames,
            'passwords': passwords,
            'username_file': username_file,
            'password_file': password_file,
            'tasks': self.tasks_spin.value(),
            'exit_on_first': self.stop_first.isChecked(),
            'verbose': self.verbose.isChecked()
        }
        
        # Clear previous results
        self.creds_table.setRowCount(0)
        self.output_console.clear()
        
        # Update UI
        self.attack_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_widget.setProgress(0, "Starting attack...", f"Target: {target}:{port}/{protocol}")
        self.progress_widget.setRunning()
        
        # Start thread
        self.scan_thread = HydraScanThread(self.scanner, target, protocol, port, options)
        self.scan_thread.progress.connect(self._on_progress)
        self.scan_thread.credential.connect(self._on_credential)
        self.scan_thread.result.connect(self._on_result)
        self.scan_thread.error.connect(self._on_error)
        self.scan_thread.finished_scan.connect(self._on_finished)
        self.scan_thread.start()
        
        self.output_console.append_command(f"hydra attack started on {target}:{port}")
    
    def _stop_attack(self):
        """Stop the current attack"""
        if self.scanner:
            self.scanner.cancel()
        if self.scan_thread:
            self.scan_thread.terminate()
        
        self._on_finished()
        self.output_console.append_warning("Attack cancelled by user")
    
    def _on_progress(self, value: int, message: str):
        """Handle progress updates"""
        self.progress_widget.setProgress(value, message)
    
    def _on_credential(self, cred: dict):
        """Handle found credential"""
        row = self.creds_table.rowCount()
        self.creds_table.insertRow(row)
        
        self.creds_table.setItem(row, 0, QTableWidgetItem(cred.get('host', '')))
        self.creds_table.setItem(row, 1, QTableWidgetItem(str(cred.get('port', ''))))
        self.creds_table.setItem(row, 2, QTableWidgetItem(cred.get('protocol', '')))
        self.creds_table.setItem(row, 3, QTableWidgetItem(cred.get('username', '')))
        self.creds_table.setItem(row, 4, QTableWidgetItem(cred.get('password', '')))
        
        # Highlight row
        for col in range(5):
            item = self.creds_table.item(row, col)
            if item:
                item.setBackground(QColor('#1a3d1a'))
        
        self.output_console.append_success(
            f"FOUND: {cred.get('username')}:{cred.get('password')}"
        )
    
    def _on_result(self, data: dict):
        """Handle attack results"""
        creds = data.get('credentials', [])
        self.output_console.append_info(f"Attack completed: {len(creds)} credential(s) found")
    
    def _on_error(self, error: str):
        """Handle errors"""
        self.output_console.append_error(error)
        self.progress_widget.setError(f"Error: {error[:50]}...")
    
    def _on_finished(self):
        """Handle attack completion"""
        self.attack_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_widget.setCompleted()
