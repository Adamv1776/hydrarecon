#!/usr/bin/env python3
"""
HydraRecon Password Audit Page
GUI for password security assessment and hash cracking.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QComboBox,
    QTextEdit, QTableWidget, QTableWidgetItem, QProgressBar,
    QTabWidget, QGroupBox, QCheckBox, QSpinBox, QSplitter,
    QHeaderView, QMessageBox, QListWidget, QListWidgetItem,
    QFileDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor

import asyncio
from datetime import datetime
from typing import Optional

try:
    from ...core.password_audit import (
        PasswordAuditEngine, PasswordStrength, HashType,
        ComplianceStandard
    )
    PASSWORD_AVAILABLE = True
except ImportError:
    PASSWORD_AVAILABLE = False


class AuditWorker(QThread):
    """Worker thread for password auditing"""
    progress = pyqtSignal(str, float)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, engine, passwords, standards):
        super().__init__()
        self.engine = engine
        self.passwords = passwords
        self.standards = standards
    
    def run(self):
        """Run the audit"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            def callback(msg, progress):
                self.progress.emit(msg, progress)
            
            result = loop.run_until_complete(
                self.engine.audit_passwords(
                    self.passwords, self.standards, callback
                )
            )
            
            loop.close()
            self.finished.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class CrackWorker(QThread):
    """Worker thread for hash cracking"""
    progress = pyqtSignal(str, float)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, engine, hash_value, method, wordlist):
        super().__init__()
        self.engine = engine
        self.hash_value = hash_value
        self.method = method
        self.wordlist = wordlist
    
    def run(self):
        """Run cracking"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            def callback(msg, progress):
                self.progress.emit(msg, progress)
            
            result = loop.run_until_complete(
                self.engine.crack_hash(
                    self.hash_value, self.method, self.wordlist, callback
                )
            )
            
            loop.close()
            self.finished.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class PasswordAuditPage(QWidget):
    """Password Audit Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = PasswordAuditEngine() if PASSWORD_AVAILABLE else None
        self.audit_worker: Optional[AuditWorker] = None
        self.crack_worker: Optional[CrackWorker] = None
        
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
        
        # Tab 1: Password Analyzer
        self.tabs.addTab(self._create_analyzer_tab(), "🔐 Password Analyzer")
        
        # Tab 2: Hash Cracker
        self.tabs.addTab(self._create_cracker_tab(), "🔓 Hash Cracker")
        
        # Tab 3: Bulk Audit
        self.tabs.addTab(self._create_audit_tab(), "📊 Bulk Audit")
        
        # Tab 4: Policy Compliance
        self.tabs.addTab(self._create_compliance_tab(), "📋 Compliance Check")
        
        # Tab 5: Password Generator
        self.tabs.addTab(self._create_generator_tab(), "🎲 Password Generator")
        
        layout.addWidget(self.tabs, stretch=1)
    
    def _create_header(self) -> QWidget:
        """Create header section"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #8957e5, stop:1 #d2a8ff);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🔑 Password Audit & Cracking")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: 700;
            color: white;
        """)
        
        subtitle = QLabel("Password strength analysis, hash cracking, and compliance auditing")
        subtitle.setStyleSheet("font-size: 14px; color: rgba(255,255,255,0.8);")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout, stretch=1)
        
        return header
    
    def _create_analyzer_tab(self) -> QWidget:
        """Create password analyzer tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Input section
        input_group = QGroupBox("Password Analysis")
        input_group.setStyleSheet("""
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
        
        input_layout = QVBoxLayout(input_group)
        
        # Password input
        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(QLabel("Password:"))
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password to analyze...")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 12px;
                color: #e6e6e6;
                font-size: 14px;
            }
        """)
        self.password_input.textChanged.connect(self._analyze_password_realtime)
        
        self.show_password_btn = QPushButton("👁️")
        self.show_password_btn.setFixedWidth(40)
        self.show_password_btn.setCheckable(True)
        self.show_password_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: none;
                border-radius: 6px;
                padding: 10px;
            }
        """)
        self.show_password_btn.clicked.connect(self._toggle_password_visibility)
        
        pwd_layout.addWidget(self.password_input, stretch=1)
        pwd_layout.addWidget(self.show_password_btn)
        
        input_layout.addLayout(pwd_layout)
        
        # Strength meter
        strength_layout = QHBoxLayout()
        strength_layout.addWidget(QLabel("Strength:"))
        
        self.strength_bar = QProgressBar()
        self.strength_bar.setMaximum(100)
        self.strength_bar.setStyleSheet("""
            QProgressBar {
                background-color: #21262d;
                border: none;
                border-radius: 4px;
                height: 12px;
            }
            QProgressBar::chunk {
                background-color: #f85149;
                border-radius: 4px;
            }
        """)
        
        self.strength_label = QLabel("N/A")
        self.strength_label.setMinimumWidth(100)
        self.strength_label.setStyleSheet("color: #8b949e;")
        
        strength_layout.addWidget(self.strength_bar, stretch=1)
        strength_layout.addWidget(self.strength_label)
        
        input_layout.addLayout(strength_layout)
        
        # Crack time
        self.crack_time_label = QLabel("Estimated crack time: N/A")
        self.crack_time_label.setStyleSheet("color: #8b949e; font-size: 13px;")
        input_layout.addWidget(self.crack_time_label)
        
        layout.addWidget(input_group)
        
        # Analysis results
        results_group = QGroupBox("Detailed Analysis")
        results_group.setStyleSheet("""
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
        
        results_layout = QGridLayout(results_group)
        
        # Characteristics
        self.char_checks = {}
        checks = [
            ("length", "Length ≥ 12"),
            ("uppercase", "Has Uppercase"),
            ("lowercase", "Has Lowercase"),
            ("digits", "Has Numbers"),
            ("special", "Has Special"),
            ("not_common", "Not Common"),
            ("no_patterns", "No Patterns")
        ]
        
        for i, (key, label) in enumerate(checks):
            row, col = divmod(i, 3)
            check = QLabel(f"❌ {label}")
            check.setStyleSheet("color: #f85149;")
            self.char_checks[key] = check
            results_layout.addWidget(check, row, col)
        
        layout.addWidget(results_group)
        
        # Issues and recommendations
        issues_layout = QHBoxLayout()
        
        # Issues
        issues_group = QGroupBox("Issues Found")
        issues_group.setStyleSheet("""
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
        issues_layout_inner = QVBoxLayout(issues_group)
        
        self.issues_list = QListWidget()
        self.issues_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #21262d;
            }
        """)
        issues_layout_inner.addWidget(self.issues_list)
        
        issues_layout.addWidget(issues_group)
        
        # Recommendations
        rec_group = QGroupBox("Recommendations")
        rec_group.setStyleSheet("""
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
        rec_layout = QVBoxLayout(rec_group)
        
        self.recommendations_list = QListWidget()
        self.recommendations_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #21262d;
            }
        """)
        rec_layout.addWidget(self.recommendations_list)
        
        issues_layout.addWidget(rec_group)
        
        layout.addLayout(issues_layout, stretch=1)
        
        return widget
    
    def _create_cracker_tab(self) -> QWidget:
        """Create hash cracker tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Input section
        input_group = QGroupBox("Hash Cracking")
        input_group.setStyleSheet("""
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
        
        input_layout = QVBoxLayout(input_group)
        
        # Hash input
        hash_layout = QHBoxLayout()
        hash_layout.addWidget(QLabel("Hash:"))
        
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter hash to crack...")
        self.hash_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 12px;
                color: #e6e6e6;
                font-family: 'Consolas', monospace;
            }
        """)
        hash_layout.addWidget(self.hash_input, stretch=1)
        
        identify_btn = QPushButton("Identify")
        identify_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        identify_btn.clicked.connect(self._identify_hash)
        hash_layout.addWidget(identify_btn)
        
        input_layout.addLayout(hash_layout)
        
        # Hash type and method
        options_layout = QHBoxLayout()
        
        options_layout.addWidget(QLabel("Type:"))
        self.hash_type_combo = QComboBox()
        self.hash_type_combo.addItems(["Auto-detect", "MD5", "SHA1", "SHA256", "SHA512", "NTLM"])
        self.hash_type_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        options_layout.addWidget(self.hash_type_combo)
        
        options_layout.addWidget(QLabel("Method:"))
        self.crack_method_combo = QComboBox()
        self.crack_method_combo.addItems(["Dictionary", "Rule-based", "Brute Force"])
        self.crack_method_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        options_layout.addWidget(self.crack_method_combo)
        
        options_layout.addStretch()
        
        input_layout.addLayout(options_layout)
        
        # Crack button and progress
        crack_layout = QHBoxLayout()
        
        self.crack_btn = QPushButton("🔓 Start Cracking")
        self.crack_btn.setStyleSheet("""
            QPushButton {
                background-color: #f85149;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:disabled { background-color: #21262d; color: #8b949e; }
        """)
        self.crack_btn.clicked.connect(self._start_cracking)
        
        self.crack_progress = QProgressBar()
        self.crack_progress.setStyleSheet("""
            QProgressBar {
                background-color: #21262d;
                border: none;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #f85149;
                border-radius: 4px;
            }
        """)
        
        self.crack_status = QLabel("Ready")
        self.crack_status.setStyleSheet("color: #8b949e;")
        
        crack_layout.addWidget(self.crack_btn)
        crack_layout.addWidget(self.crack_progress, stretch=1)
        crack_layout.addWidget(self.crack_status)
        
        input_layout.addLayout(crack_layout)
        
        layout.addWidget(input_group)
        
        # Results
        results_group = QGroupBox("Cracking Results")
        results_group.setStyleSheet("""
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
        
        results_layout = QVBoxLayout(results_group)
        
        self.crack_results = QTextEdit()
        self.crack_results.setReadOnly(True)
        self.crack_results.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                padding: 16px;
                font-family: 'Consolas', monospace;
            }
        """)
        self.crack_results.setPlaceholderText("Cracking results will appear here...")
        
        results_layout.addWidget(self.crack_results)
        
        layout.addWidget(results_group, stretch=1)
        
        return widget
    
    def _create_audit_tab(self) -> QWidget:
        """Create bulk audit tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Input section
        input_group = QGroupBox("Bulk Password Audit")
        input_group.setStyleSheet("""
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
        
        input_layout = QVBoxLayout(input_group)
        
        info = QLabel("Enter passwords (one per line) or load from file:")
        info.setStyleSheet("color: #8b949e;")
        input_layout.addWidget(info)
        
        self.passwords_input = QTextEdit()
        self.passwords_input.setPlaceholderText("password1\npassword2\npassword3\n...")
        self.passwords_input.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                padding: 12px;
                font-family: 'Consolas', monospace;
            }
        """)
        self.passwords_input.setMaximumHeight(150)
        input_layout.addWidget(self.passwords_input)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        load_btn = QPushButton("📂 Load File")
        load_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        load_btn.clicked.connect(self._load_passwords_file)
        
        self.audit_btn = QPushButton("📊 Run Audit")
        self.audit_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }
            QPushButton:disabled { background-color: #21262d; color: #8b949e; }
        """)
        self.audit_btn.clicked.connect(self._start_audit)
        
        self.audit_progress = QProgressBar()
        self.audit_progress.setStyleSheet("""
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
        
        controls_layout.addWidget(load_btn)
        controls_layout.addWidget(self.audit_btn)
        controls_layout.addWidget(self.audit_progress, stretch=1)
        
        input_layout.addLayout(controls_layout)
        
        layout.addWidget(input_group)
        
        # Results
        results_group = QGroupBox("Audit Results")
        results_group.setStyleSheet("""
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
        
        results_layout = QVBoxLayout(results_group)
        
        # Summary stats
        stats_layout = QHBoxLayout()
        
        self.stat_widgets = {}
        stats = [
            ("total", "Total", "#8b949e"),
            ("weak", "Weak", "#f85149"),
            ("moderate", "Moderate", "#d29922"),
            ("strong", "Strong", "#3fb950"),
            ("reused", "Reused", "#ffa657")
        ]
        
        for key, label, color in stats:
            stat_frame = QFrame()
            stat_frame.setStyleSheet(f"""
                QFrame {{
                    background-color: #161b22;
                    border: 1px solid #21262d;
                    border-radius: 8px;
                    padding: 10px;
                }}
            """)
            
            stat_layout = QVBoxLayout(stat_frame)
            stat_layout.setContentsMargins(10, 10, 10, 10)
            
            value_label = QLabel("0")
            value_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name_label = QLabel(label)
            name_label.setStyleSheet("color: #8b949e;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            stat_layout.addWidget(value_label)
            stat_layout.addWidget(name_label)
            
            self.stat_widgets[key] = value_label
            stats_layout.addWidget(stat_frame)
        
        results_layout.addLayout(stats_layout)
        
        # Patterns and recommendations
        self.audit_results = QTextEdit()
        self.audit_results.setReadOnly(True)
        self.audit_results.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                padding: 16px;
            }
        """)
        results_layout.addWidget(self.audit_results)
        
        layout.addWidget(results_group, stretch=1)
        
        return widget
    
    def _create_compliance_tab(self) -> QWidget:
        """Create compliance check tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Input section
        input_group = QGroupBox("Compliance Check")
        input_group.setStyleSheet("""
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
        
        input_layout = QVBoxLayout(input_group)
        
        # Password input
        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(QLabel("Password:"))
        
        self.compliance_password = QLineEdit()
        self.compliance_password.setPlaceholderText("Enter password to check...")
        self.compliance_password.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 12px;
                color: #e6e6e6;
            }
        """)
        pwd_layout.addWidget(self.compliance_password, stretch=1)
        
        input_layout.addLayout(pwd_layout)
        
        # Standard selection
        std_layout = QHBoxLayout()
        std_layout.addWidget(QLabel("Standard:"))
        
        self.standard_combo = QComboBox()
        self.standard_combo.addItems([
            "NIST 800-63B", "PCI DSS", "HIPAA", "CIS Benchmark", "ISO 27001"
        ])
        self.standard_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        std_layout.addWidget(self.standard_combo)
        std_layout.addStretch()
        
        check_btn = QPushButton("✅ Check Compliance")
        check_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        check_btn.clicked.connect(self._check_compliance)
        std_layout.addWidget(check_btn)
        
        input_layout.addLayout(std_layout)
        
        layout.addWidget(input_group)
        
        # Results
        results_group = QGroupBox("Compliance Results")
        results_group.setStyleSheet("""
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
        
        results_layout = QHBoxLayout(results_group)
        
        # Passed checks
        passed_layout = QVBoxLayout()
        passed_layout.addWidget(QLabel("✅ Passed Checks:"))
        
        self.passed_list = QListWidget()
        self.passed_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #3fb950;
            }
            QListWidget::item { padding: 8px; }
        """)
        passed_layout.addWidget(self.passed_list)
        
        results_layout.addLayout(passed_layout)
        
        # Failed checks
        failed_layout = QVBoxLayout()
        failed_layout.addWidget(QLabel("❌ Failed Checks:"))
        
        self.failed_list = QListWidget()
        self.failed_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #f85149;
            }
            QListWidget::item { padding: 8px; }
        """)
        failed_layout.addWidget(self.failed_list)
        
        results_layout.addLayout(failed_layout)
        
        layout.addWidget(results_group, stretch=1)
        
        return widget
    
    def _create_generator_tab(self) -> QWidget:
        """Create password generator tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Generator settings
        settings_group = QGroupBox("Password Generator")
        settings_group.setStyleSheet("""
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
        
        settings_layout = QVBoxLayout(settings_group)
        
        # Length
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Length:"))
        
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(16)
        self.length_spin.setStyleSheet("""
            QSpinBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        length_layout.addWidget(self.length_spin)
        length_layout.addStretch()
        
        settings_layout.addLayout(length_layout)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.include_special = QCheckBox("Include Special Characters")
        self.include_special.setChecked(True)
        self.include_special.setStyleSheet("color: #e6e6e6;")
        
        self.avoid_ambiguous = QCheckBox("Avoid Ambiguous Characters (0,O,l,1)")
        self.avoid_ambiguous.setChecked(True)
        self.avoid_ambiguous.setStyleSheet("color: #e6e6e6;")
        
        options_layout.addWidget(self.include_special)
        options_layout.addWidget(self.avoid_ambiguous)
        options_layout.addStretch()
        
        settings_layout.addLayout(options_layout)
        
        # Generate button
        gen_layout = QHBoxLayout()
        
        gen_btn = QPushButton("🎲 Generate Password")
        gen_btn.setStyleSheet("""
            QPushButton {
                background-color: #8957e5;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
        """)
        gen_btn.clicked.connect(self._generate_password)
        
        gen_layout.addWidget(gen_btn)
        gen_layout.addStretch()
        
        settings_layout.addLayout(gen_layout)
        
        layout.addWidget(settings_group)
        
        # Generated password
        output_group = QGroupBox("Generated Password")
        output_group.setStyleSheet("""
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
        
        output_layout = QVBoxLayout(output_group)
        
        self.generated_password = QLineEdit()
        self.generated_password.setReadOnly(True)
        self.generated_password.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 16px;
                color: #3fb950;
                font-size: 18px;
                font-family: 'Consolas', monospace;
            }
        """)
        output_layout.addWidget(self.generated_password)
        
        # Copy button
        copy_btn = QPushButton("📋 Copy to Clipboard")
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        copy_btn.clicked.connect(self._copy_password)
        
        output_layout.addWidget(copy_btn)
        
        layout.addWidget(output_group)
        layout.addStretch()
        
        return widget
    
    def _toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_btn.isChecked():
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
    
    def _analyze_password_realtime(self):
        """Analyze password in real-time"""
        password = self.password_input.text()
        
        if not password or not self.engine:
            self.strength_bar.setValue(0)
            self.strength_label.setText("N/A")
            self.crack_time_label.setText("Estimated crack time: N/A")
            self.issues_list.clear()
            self.recommendations_list.clear()
            return
        
        analysis = self.engine.analyze_password(password)
        
        # Update strength bar
        self.strength_bar.setValue(analysis.score)
        
        # Color based on strength
        colors = {
            PasswordStrength.VERY_WEAK: "#f85149",
            PasswordStrength.WEAK: "#ffa657",
            PasswordStrength.MODERATE: "#d29922",
            PasswordStrength.STRONG: "#3fb950",
            PasswordStrength.VERY_STRONG: "#238636"
        }
        
        color = colors.get(analysis.strength, "#8b949e")
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #21262d;
                border: none;
                border-radius: 4px;
                height: 12px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 4px;
            }}
        """)
        
        self.strength_label.setText(analysis.strength.value.replace("_", " ").title())
        self.strength_label.setStyleSheet(f"color: {color};")
        
        # Crack time
        self.crack_time_label.setText(f"Estimated crack time: {analysis.crack_time_display}")
        
        # Update checks
        self.char_checks["length"].setText(
            f"{'✅' if analysis.length >= 12 else '❌'} Length ≥ 12"
        )
        self.char_checks["uppercase"].setText(
            f"{'✅' if analysis.has_uppercase else '❌'} Has Uppercase"
        )
        self.char_checks["lowercase"].setText(
            f"{'✅' if analysis.has_lowercase else '❌'} Has Lowercase"
        )
        self.char_checks["digits"].setText(
            f"{'✅' if analysis.has_digits else '❌'} Has Numbers"
        )
        self.char_checks["special"].setText(
            f"{'✅' if analysis.has_special else '❌'} Has Special"
        )
        self.char_checks["not_common"].setText(
            f"{'✅' if not analysis.is_common else '❌'} Not Common"
        )
        self.char_checks["no_patterns"].setText(
            f"{'✅' if not analysis.is_dictionary_word else '❌'} No Patterns"
        )
        
        # Issues
        self.issues_list.clear()
        for issue in analysis.issues:
            self.issues_list.addItem(f"⚠️ {issue}")
        
        # Recommendations
        self.recommendations_list.clear()
        for rec in analysis.recommendations:
            self.recommendations_list.addItem(f"💡 {rec}")
    
    def _identify_hash(self):
        """Identify hash type"""
        hash_value = self.hash_input.text().strip()
        if not hash_value or not self.engine:
            return
        
        hash_type = self.engine.cracker.identify_hash(hash_value)
        if hash_type:
            self.hash_type_combo.setCurrentText(hash_type.value.upper())
            QMessageBox.information(self, "Hash Identified", 
                f"Detected hash type: {hash_type.value.upper()}")
        else:
            QMessageBox.warning(self, "Unknown Hash", 
                "Could not identify hash type")
    
    def _start_cracking(self):
        """Start hash cracking"""
        hash_value = self.hash_input.text().strip()
        if not hash_value or not self.engine:
            return
        
        method_map = {
            "Dictionary": "dictionary",
            "Rule-based": "rule_based",
            "Brute Force": "brute_force"
        }
        
        method = method_map[self.crack_method_combo.currentText()]
        
        self.crack_btn.setEnabled(False)
        self.crack_progress.setValue(0)
        
        self.crack_worker = CrackWorker(
            self.engine, hash_value, method, None
        )
        self.crack_worker.progress.connect(self._on_crack_progress)
        self.crack_worker.finished.connect(self._on_crack_finished)
        self.crack_worker.error.connect(self._on_crack_error)
        self.crack_worker.start()
    
    def _on_crack_progress(self, message: str, progress: float):
        """Handle cracking progress"""
        self.crack_status.setText(message)
        self.crack_progress.setValue(int(progress))
    
    def _on_crack_finished(self, result):
        """Handle cracking completion"""
        self.crack_btn.setEnabled(True)
        self.crack_progress.setValue(100)
        
        if result.cracked:
            self.crack_status.setText("CRACKED!")
            self.crack_results.setHtml(f"""
                <h3 style="color: #3fb950;">✅ Hash Cracked!</h3>
                <p><b>Plaintext:</b> <code style="color: #ffa657;">{result.plaintext}</code></p>
                <p><b>Method:</b> {result.method}</p>
                <p><b>Attempts:</b> {result.attempts:,}</p>
                <p><b>Time:</b> {result.time_taken:.2f} seconds</p>
            """)
        else:
            self.crack_status.setText("Not cracked")
            self.crack_results.setHtml(f"""
                <h3 style="color: #f85149;">❌ Hash Not Cracked</h3>
                <p><b>Method:</b> {result.method}</p>
                <p><b>Attempts:</b> {result.attempts:,}</p>
                <p><b>Time:</b> {result.time_taken:.2f} seconds</p>
                <p>Try a different method or larger wordlist.</p>
            """)
    
    def _on_crack_error(self, error: str):
        """Handle cracking error"""
        self.crack_btn.setEnabled(True)
        self.crack_status.setText(f"Error: {error}")
    
    def _load_passwords_file(self):
        """Load passwords from file"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Load Passwords", "",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filepath:
            try:
                with open(filepath, 'r') as f:
                    self.passwords_input.setPlainText(f.read())
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {e}")
    
    def _start_audit(self):
        """Start password audit"""
        passwords_text = self.passwords_input.toPlainText().strip()
        if not passwords_text or not self.engine:
            return
        
        passwords = [p.strip() for p in passwords_text.split('\n') if p.strip()]
        
        self.audit_btn.setEnabled(False)
        self.audit_progress.setValue(0)
        
        self.audit_worker = AuditWorker(self.engine, passwords, None)
        self.audit_worker.progress.connect(self._on_audit_progress)
        self.audit_worker.finished.connect(self._on_audit_finished)
        self.audit_worker.error.connect(self._on_audit_error)
        self.audit_worker.start()
    
    def _on_audit_progress(self, message: str, progress: float):
        """Handle audit progress"""
        self.audit_progress.setValue(int(progress))
    
    def _on_audit_finished(self, result):
        """Handle audit completion"""
        self.audit_btn.setEnabled(True)
        self.audit_progress.setValue(100)
        
        # Update stats
        self.stat_widgets["total"].setText(str(result.total_passwords))
        self.stat_widgets["weak"].setText(str(result.weak_passwords))
        self.stat_widgets["moderate"].setText(str(result.moderate_passwords))
        self.stat_widgets["strong"].setText(str(result.strong_passwords))
        self.stat_widgets["reused"].setText(str(result.reused_passwords))
        
        # Update results
        html = f"""
            <h3>Audit Complete</h3>
            <p>Audit ID: {result.audit_id}</p>
            
            <h4>Common Patterns:</h4>
            <ul>
        """
        
        for pattern in result.common_patterns[:5]:
            html += f"<li>{pattern['pattern']}: {pattern['count']} occurrences</li>"
        
        html += "</ul><h4>Recommendations:</h4><ul>"
        
        for rec in result.recommendations:
            html += f"<li>{rec}</li>"
        
        html += "</ul>"
        
        self.audit_results.setHtml(html)
    
    def _on_audit_error(self, error: str):
        """Handle audit error"""
        self.audit_btn.setEnabled(True)
        QMessageBox.critical(self, "Audit Error", error)
    
    def _check_compliance(self):
        """Check password compliance"""
        password = self.compliance_password.text().strip()
        if not password or not self.engine:
            return
        
        standard_map = {
            "NIST 800-63B": ComplianceStandard.NIST_800_63B,
            "PCI DSS": ComplianceStandard.PCI_DSS,
            "HIPAA": ComplianceStandard.HIPAA,
            "CIS Benchmark": ComplianceStandard.CIS,
            "ISO 27001": ComplianceStandard.ISO_27001
        }
        
        standard = standard_map[self.standard_combo.currentText()]
        result = self.engine.policy_checker.check_compliance(password, standard)
        
        self.passed_list.clear()
        for check in result.passed_checks:
            self.passed_list.addItem(check)
        
        self.failed_list.clear()
        for check in result.failed_checks:
            self.failed_list.addItem(check)
        
        if result.compliant:
            QMessageBox.information(self, "Compliant", 
                f"Password is compliant with {self.standard_combo.currentText()}")
        else:
            QMessageBox.warning(self, "Not Compliant",
                f"Password does NOT meet {self.standard_combo.currentText()} requirements")
    
    def _generate_password(self):
        """Generate a strong password"""
        if not self.engine:
            return
        
        password = self.engine.generate_strong_password(
            length=self.length_spin.value(),
            include_special=self.include_special.isChecked(),
            include_ambiguous=not self.avoid_ambiguous.isChecked()
        )
        
        self.generated_password.setText(password)
    
    def _copy_password(self):
        """Copy generated password to clipboard"""
        from PyQt6.QtWidgets import QApplication
        
        password = self.generated_password.text()
        if password:
            QApplication.clipboard().setText(password)
            QMessageBox.information(self, "Copied", "Password copied to clipboard!")
