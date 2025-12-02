"""
Credential Spray Page
GUI for password spraying and credential testing
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QComboBox, QCheckBox, QProgressBar,
    QSplitter, QFrame, QHeaderView, QSpinBox, QListWidget,
    QListWidgetItem, QFileDialog, QDoubleSpinBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor
import asyncio


class CredentialSprayWorker(QThread):
    """Worker thread for credential spray attacks"""
    progress = pyqtSignal(str, int)
    success = pyqtSignal(dict)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, targets, usernames, passwords, protocol, options):
        super().__init__()
        self.targets = targets
        self.usernames = usernames
        self.passwords = passwords
        self.protocol = protocol
        self.options = options
        
    def run(self):
        try:
            import sys
            sys.path.insert(0, '..')
            from core.credential_spray import CredentialSprayEngine
            
            async def spray():
                engine = CredentialSprayEngine()
                results = await engine.spray(
                    targets=self.targets,
                    usernames=self.usernames,
                    passwords=self.passwords,
                    protocol=self.protocol,
                    delay=self.options.get('delay', 1.0),
                    threads=self.options.get('threads', 5),
                    callback=lambda p, t: self.progress.emit(f"Testing: {p}", t)
                )
                return results
                
            results = asyncio.run(spray())
            self.finished.emit(results)
            
        except Exception as e:
            self.error.emit(str(e))


class CredentialSprayPage(QWidget):
    """Credential Spray Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Header
        header = QLabel("🔐 Credential Spraying & Password Testing")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ff9500;
            padding-bottom: 10px;
        """)
        layout.addWidget(header)
        
        # Warning banner
        warning = QLabel("⚠️ WARNING: Only use against systems you have explicit authorization to test!")
        warning.setStyleSheet("""
            background-color: rgba(255, 149, 0, 0.2);
            color: #ff9500;
            padding: 10px;
            border: 1px solid #ff9500;
            border-radius: 5px;
            font-weight: bold;
        """)
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(warning)
        
        # Main content with tabs
        main_tabs = QTabWidget()
        main_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #333;
                background-color: #1a1a2e;
                border-radius: 5px;
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
                color: #ff9500;
            }
        """)
        
        # Password Spray tab
        spray_widget = self._create_spray_tab()
        main_tabs.addTab(spray_widget, "🎯 Password Spray")
        
        # Credential Stuffing tab
        stuffing_widget = self._create_stuffing_tab()
        main_tabs.addTab(stuffing_widget, "📋 Credential Stuffing")
        
        # Results tab
        results_widget = self._create_results_tab()
        main_tabs.addTab(results_widget, "✅ Results")
        
        layout.addWidget(main_tabs)
        
        # Status bar
        status_row = QHBoxLayout()
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888;")
        
        self.found_count = QLabel("Found: 0")
        self.found_count.setStyleSheet("color: #00ff88; font-weight: bold;")
        
        status_row.addWidget(self.status_label)
        status_row.addStretch()
        status_row.addWidget(self.found_count)
        
        layout.addLayout(status_row)
        
        # Store results
        self.valid_credentials = []
        
    def _create_spray_tab(self):
        """Create password spray configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #ff9500;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        target_layout = QVBoxLayout(target_group)
        
        # Targets input
        targets_row = QHBoxLayout()
        targets_label = QLabel("Targets:")
        targets_label.setStyleSheet("color: #888; min-width: 80px;")
        
        self.targets_input = QTextEdit()
        self.targets_input.setPlaceholderText("Enter targets (one per line):\n192.168.1.1\n192.168.1.0/24\nexample.com")
        self.targets_input.setMaximumHeight(100)
        self.targets_input.setStyleSheet("""
            QTextEdit {
                background-color: #0f0f1a;
                color: white;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        load_targets_btn = QPushButton("📁 Load")
        load_targets_btn.clicked.connect(self._load_targets)
        load_targets_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 8px 15px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        targets_row.addWidget(targets_label)
        targets_row.addWidget(self.targets_input)
        targets_row.addWidget(load_targets_btn)
        target_layout.addLayout(targets_row)
        
        # Protocol selection
        proto_row = QHBoxLayout()
        proto_label = QLabel("Protocol:")
        proto_label.setStyleSheet("color: #888; min-width: 80px;")
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems([
            "SSH", "RDP", "SMB", "FTP", "HTTP Basic", "HTTP Form",
            "LDAP", "MySQL", "MSSQL", "PostgreSQL", "MongoDB",
            "Redis", "Telnet", "VNC", "WinRM"
        ])
        self.protocol_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
                min-width: 150px;
            }
        """)
        
        port_label = QLabel("Port:")
        port_label.setStyleSheet("color: #888;")
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)
        self.port_input.setStyleSheet("""
            QSpinBox {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
            }
        """)
        
        proto_row.addWidget(proto_label)
        proto_row.addWidget(self.protocol_combo)
        proto_row.addWidget(port_label)
        proto_row.addWidget(self.port_input)
        proto_row.addStretch()
        target_layout.addLayout(proto_row)
        
        layout.addWidget(target_group)
        
        # Credentials configuration
        creds_group = QGroupBox("Credentials")
        creds_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #ff9500;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        creds_layout = QVBoxLayout(creds_group)
        
        creds_row = QHBoxLayout()
        
        # Usernames
        user_col = QVBoxLayout()
        user_label = QLabel("Usernames:")
        user_label.setStyleSheet("color: #888;")
        user_col.addWidget(user_label)
        
        self.usernames_input = QTextEdit()
        self.usernames_input.setPlaceholderText("admin\nroot\nuser\nadministrator")
        self.usernames_input.setStyleSheet("""
            QTextEdit {
                background-color: #0f0f1a;
                color: white;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        user_col.addWidget(self.usernames_input)
        
        user_btns = QHBoxLayout()
        load_users_btn = QPushButton("📁 Load")
        load_users_btn.clicked.connect(self._load_usernames)
        load_users_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 5px 10px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        common_users_btn = QPushButton("📋 Common")
        common_users_btn.clicked.connect(self._add_common_users)
        common_users_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 5px 10px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        user_btns.addWidget(load_users_btn)
        user_btns.addWidget(common_users_btn)
        user_col.addLayout(user_btns)
        
        creds_row.addLayout(user_col)
        
        # Passwords
        pass_col = QVBoxLayout()
        pass_label = QLabel("Passwords:")
        pass_label.setStyleSheet("color: #888;")
        pass_col.addWidget(pass_label)
        
        self.passwords_input = QTextEdit()
        self.passwords_input.setPlaceholderText("password\n123456\nadmin\nPassword1")
        self.passwords_input.setStyleSheet("""
            QTextEdit {
                background-color: #0f0f1a;
                color: white;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        pass_col.addWidget(self.passwords_input)
        
        pass_btns = QHBoxLayout()
        load_pass_btn = QPushButton("📁 Load")
        load_pass_btn.clicked.connect(self._load_passwords)
        load_pass_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 5px 10px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        common_pass_btn = QPushButton("📋 Common")
        common_pass_btn.clicked.connect(self._add_common_passwords)
        common_pass_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 5px 10px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        pass_btns.addWidget(load_pass_btn)
        pass_btns.addWidget(common_pass_btn)
        pass_col.addLayout(pass_btns)
        
        creds_row.addLayout(pass_col)
        creds_layout.addLayout(creds_row)
        
        layout.addWidget(creds_group)
        
        # Attack options
        options_group = QGroupBox("Attack Options")
        options_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #ff9500;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        options_layout = QHBoxLayout(options_group)
        
        # Delay
        delay_label = QLabel("Delay (sec):")
        delay_label.setStyleSheet("color: #888;")
        
        self.delay_input = QDoubleSpinBox()
        self.delay_input.setRange(0, 60)
        self.delay_input.setValue(1.0)
        self.delay_input.setSingleStep(0.5)
        self.delay_input.setStyleSheet("""
            QDoubleSpinBox {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
            }
        """)
        
        # Threads
        threads_label = QLabel("Threads:")
        threads_label.setStyleSheet("color: #888;")
        
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 50)
        self.threads_input.setValue(5)
        self.threads_input.setStyleSheet("""
            QSpinBox {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
            }
        """)
        
        # Lockout detection
        self.lockout_check = QCheckBox("Lockout Detection")
        self.lockout_check.setChecked(True)
        self.lockout_check.setStyleSheet("color: white;")
        
        # Jitter
        self.jitter_check = QCheckBox("Random Jitter")
        self.jitter_check.setChecked(True)
        self.jitter_check.setStyleSheet("color: white;")
        
        options_layout.addWidget(delay_label)
        options_layout.addWidget(self.delay_input)
        options_layout.addWidget(threads_label)
        options_layout.addWidget(self.threads_input)
        options_layout.addWidget(self.lockout_check)
        options_layout.addWidget(self.jitter_check)
        options_layout.addStretch()
        
        layout.addWidget(options_group)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #16213e;
                height: 25px;
            }
            QProgressBar::chunk {
                background: linear-gradient(90deg, #ff9500, #ff7500);
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Control buttons
        btn_row = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 Start Spray")
        self.start_btn.clicked.connect(self._start_spray)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #ff9500, #ff7500);
                color: white;
                font-weight: bold;
                padding: 15px 30px;
                border-radius: 5px;
                border: none;
                font-size: 14px;
            }
            QPushButton:hover {
                background: linear-gradient(135deg, #ff7500, #ff9500);
            }
        """)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.clicked.connect(self._stop_spray)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #333;
                color: white;
                font-weight: bold;
                padding: 15px 30px;
                border-radius: 5px;
                border: 1px solid #555;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)
        
        btn_row.addStretch()
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addStretch()
        
        layout.addLayout(btn_row)
        layout.addStretch()
        
        return widget
        
    def _create_stuffing_tab(self):
        """Create credential stuffing tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        info_label = QLabel("""
            <h3 style="color: #ff9500;">Credential Stuffing</h3>
            <p style="color: #888;">Load username:password pairs from breach databases 
            or credential dumps to test against target services.</p>
        """)
        layout.addWidget(info_label)
        
        # Combo list input
        combo_group = QGroupBox("Credential Combo List")
        combo_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #ff9500;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        combo_layout = QVBoxLayout(combo_group)
        
        self.combo_input = QTextEdit()
        self.combo_input.setPlaceholderText("username:password\nuser@email.com:pass123\nadmin:admin")
        self.combo_input.setStyleSheet("""
            QTextEdit {
                background-color: #0f0f1a;
                color: white;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        combo_layout.addWidget(self.combo_input)
        
        combo_btns = QHBoxLayout()
        load_combo_btn = QPushButton("📁 Load Combo File")
        load_combo_btn.clicked.connect(self._load_combo_file)
        load_combo_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 8px 15px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        clear_combo_btn = QPushButton("🗑️ Clear")
        clear_combo_btn.clicked.connect(lambda: self.combo_input.clear())
        clear_combo_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 8px 15px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        combo_count = QLabel("0 credentials")
        combo_count.setStyleSheet("color: #888;")
        
        combo_btns.addWidget(load_combo_btn)
        combo_btns.addWidget(clear_combo_btn)
        combo_btns.addStretch()
        combo_btns.addWidget(combo_count)
        combo_layout.addLayout(combo_btns)
        
        layout.addWidget(combo_group)
        layout.addStretch()
        
        return widget
        
    def _create_results_tab(self):
        """Create results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Valid credentials table
        table_label = QLabel("Valid Credentials Found")
        table_label.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 16px;")
        layout.addWidget(table_label)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Target", "Port", "Protocol", "Username", "Password"
        ])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background-color: #16213e;
                color: white;
                border: 1px solid #333;
                gridline-color: #333;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #333;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)
        layout.addWidget(self.results_table)
        
        # Export buttons
        export_row = QHBoxLayout()
        
        export_json_btn = QPushButton("💾 Export JSON")
        export_json_btn.clicked.connect(lambda: self._export_results("json"))
        export_json_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 8px 15px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        export_csv_btn = QPushButton("📊 Export CSV")
        export_csv_btn.clicked.connect(lambda: self._export_results("csv"))
        export_csv_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 8px 15px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        copy_btn = QPushButton("📋 Copy All")
        copy_btn.clicked.connect(self._copy_results)
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 8px 15px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        export_row.addWidget(export_json_btn)
        export_row.addWidget(export_csv_btn)
        export_row.addWidget(copy_btn)
        export_row.addStretch()
        
        layout.addLayout(export_row)
        
        return widget
        
    def _load_targets(self):
        """Load targets from file"""
        filepath, _ = QFileDialog.getOpenFileName(self, "Load Targets", "", "Text Files (*.txt);;All Files (*.*)")
        if filepath:
            with open(filepath, 'r') as f:
                self.targets_input.setPlainText(f.read())
                
    def _load_usernames(self):
        """Load usernames from file"""
        filepath, _ = QFileDialog.getOpenFileName(self, "Load Usernames", "", "Text Files (*.txt);;All Files (*.*)")
        if filepath:
            with open(filepath, 'r') as f:
                self.usernames_input.setPlainText(f.read())
                
    def _load_passwords(self):
        """Load passwords from file"""
        filepath, _ = QFileDialog.getOpenFileName(self, "Load Passwords", "", "Text Files (*.txt);;All Files (*.*)")
        if filepath:
            with open(filepath, 'r') as f:
                self.passwords_input.setPlainText(f.read())
                
    def _load_combo_file(self):
        """Load combo file"""
        filepath, _ = QFileDialog.getOpenFileName(self, "Load Combo File", "", "Text Files (*.txt);;All Files (*.*)")
        if filepath:
            with open(filepath, 'r') as f:
                self.combo_input.setPlainText(f.read())
                
    def _add_common_users(self):
        """Add common usernames"""
        common = [
            "admin", "administrator", "root", "user", "test",
            "guest", "info", "mysql", "postgres", "oracle",
            "ftp", "backup", "operator", "webmaster", "support"
        ]
        current = self.usernames_input.toPlainText()
        self.usernames_input.setPlainText(current + "\n" + "\n".join(common))
        
    def _add_common_passwords(self):
        """Add common passwords"""
        common = [
            "password", "123456", "admin", "password123", "12345678",
            "root", "toor", "pass", "test", "guest", "master",
            "changeme", "welcome", "letmein", "qwerty", "abc123"
        ]
        current = self.passwords_input.toPlainText()
        self.passwords_input.setPlainText(current + "\n" + "\n".join(common))
        
    def _start_spray(self):
        """Start password spray attack"""
        targets = [t.strip() for t in self.targets_input.toPlainText().split('\n') if t.strip()]
        usernames = [u.strip() for u in self.usernames_input.toPlainText().split('\n') if u.strip()]
        passwords = [p.strip() for p in self.passwords_input.toPlainText().split('\n') if p.strip()]
        
        if not targets:
            self.status_label.setText("❌ Please enter targets")
            return
            
        if not usernames or not passwords:
            self.status_label.setText("❌ Please enter usernames and passwords")
            return
            
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setRange(0, len(targets) * len(usernames) * len(passwords))
        self.progress_bar.setValue(0)
        
        options = {
            'delay': self.delay_input.value(),
            'threads': self.threads_input.value(),
            'lockout_detection': self.lockout_check.isChecked(),
            'jitter': self.jitter_check.isChecked()
        }
        
        protocol = self.protocol_combo.currentText().lower().replace(' ', '_')
        
        self.worker = CredentialSprayWorker(
            targets, usernames, passwords, protocol, options
        )
        self.worker.progress.connect(self._on_progress)
        self.worker.success.connect(self._on_success)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.start()
        
        self.status_label.setText("🔄 Spraying...")
        
    def _stop_spray(self):
        """Stop the spray attack"""
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.terminate()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_label.setText("⏹️ Stopped")
            
    def _on_progress(self, msg, count):
        """Handle progress update"""
        self.status_label.setText(msg)
        self.progress_bar.setValue(count)
        
    def _on_success(self, cred):
        """Handle successful credential"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(cred['target']))
        self.results_table.setItem(row, 1, QTableWidgetItem(str(cred['port'])))
        self.results_table.setItem(row, 2, QTableWidgetItem(cred['protocol']))
        self.results_table.setItem(row, 3, QTableWidgetItem(cred['username']))
        self.results_table.setItem(row, 4, QTableWidgetItem(cred['password']))
        
        self.valid_credentials.append(cred)
        self.found_count.setText(f"Found: {len(self.valid_credentials)}")
        
    def _on_finished(self, results):
        """Handle completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText(f"✅ Complete - Found {len(self.valid_credentials)} valid credentials")
        
    def _on_error(self, error):
        """Handle error"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText(f"❌ Error: {error}")
        
    def _export_results(self, format_type):
        """Export results to file"""
        if not self.valid_credentials:
            return
            
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            f"credentials.{format_type}",
            f"{format_type.upper()} Files (*.{format_type})"
        )
        
        if filepath:
            if format_type == "json":
                import json
                with open(filepath, 'w') as f:
                    json.dump(self.valid_credentials, f, indent=2)
            else:
                import csv
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['target', 'port', 'protocol', 'username', 'password'])
                    writer.writeheader()
                    writer.writerows(self.valid_credentials)
                    
            self.status_label.setText(f"✅ Exported to {filepath}")
            
    def _copy_results(self):
        """Copy results to clipboard"""
        if not self.valid_credentials:
            return
            
        from PyQt6.QtWidgets import QApplication
        text = "\n".join([
            f"{c['target']}:{c['port']}\t{c['username']}:{c['password']}"
            for c in self.valid_credentials
        ])
        QApplication.clipboard().setText(text)
        self.status_label.setText("✅ Copied to clipboard")
