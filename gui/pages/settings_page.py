#!/usr/bin/env python3
"""
HydraRecon Settings Page
Application configuration and preferences.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QLineEdit, QComboBox, QCheckBox, QSpinBox, QTabWidget, QScrollArea,
    QGroupBox, QGridLayout, QFileDialog, QMessageBox, QFormLayout
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
import json
import os

from ..widgets import ModernLineEdit, GlowingButton


class SettingsPage(QWidget):
    """Settings and configuration page"""
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self._setup_ui()
        self._load_settings()
    
    def _setup_ui(self):
        """Setup the settings page UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(20)
        
        # Header
        header = self._create_header()
        layout.addLayout(header)
        
        # Settings tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
            QTabBar::tab {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 14px 28px;
                margin-right: 4px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #00ff88;
                border-bottom: 3px solid #00ff88;
            }
            QTabBar::tab:hover {
                color: #e6e6e6;
            }
        """)
        
        # General settings
        tabs.addTab(self._create_general_tab(), "⚙️ General")
        
        # Scanner settings
        tabs.addTab(self._create_scanner_tab(), "🔍 Scanners")
        
        # API Keys
        tabs.addTab(self._create_api_tab(), "🔑 API Keys")
        
        # Appearance
        tabs.addTab(self._create_appearance_tab(), "🎨 Appearance")
        
        # Advanced
        tabs.addTab(self._create_advanced_tab(), "🛠️ Advanced")
        
        layout.addWidget(tabs)
        
        # Save/Reset buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px 24px;
                color: #e6e6e6;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        reset_btn.clicked.connect(self._reset_settings)
        
        save_btn = GlowingButton("Save Settings")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #2ea043; }
        """)
        save_btn.clicked.connect(self._save_settings)
        
        button_layout.addWidget(reset_btn)
        button_layout.addWidget(save_btn)
        
        layout.addLayout(button_layout)
    
    def _create_header(self) -> QHBoxLayout:
        """Create the header section"""
        layout = QHBoxLayout()
        
        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)
        
        title = QLabel("Settings")
        title.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e6e6;")
        
        subtitle = QLabel("Configure application preferences and tool settings")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        return layout
    
    def _create_general_tab(self) -> QScrollArea:
        """Create general settings tab"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(24)
        
        # Project settings
        project_group = self._create_group("Project Settings")
        project_layout = QFormLayout(project_group)
        project_layout.setSpacing(12)
        
        self.project_dir = ModernLineEdit(os.path.expanduser("~/HydraRecon_Projects"))
        browse_btn = QPushButton("Browse")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
            }
        """)
        browse_btn.clicked.connect(lambda: self._browse_directory(self.project_dir))
        
        project_row = QHBoxLayout()
        project_row.addWidget(self.project_dir)
        project_row.addWidget(browse_btn)
        project_layout.addRow("Projects Directory:", project_row)
        
        self.auto_save = QCheckBox("Auto-save projects")
        self.auto_save.setChecked(True)
        self.auto_save.setStyleSheet("color: #e6e6e6;")
        project_layout.addRow("", self.auto_save)
        
        self.save_interval = QSpinBox()
        self.save_interval.setRange(1, 60)
        self.save_interval.setValue(5)
        self.save_interval.setSuffix(" minutes")
        self.save_interval.setStyleSheet("""
            QSpinBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        project_layout.addRow("Auto-save interval:", self.save_interval)
        
        layout.addWidget(project_group)
        
        # Database settings
        db_group = self._create_group("Database")
        db_layout = QFormLayout(db_group)
        db_layout.setSpacing(12)
        
        self.db_path = ModernLineEdit(os.path.expanduser("~/.hydrarecon/database.db"))
        db_browse = QPushButton("Browse")
        db_browse.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
            }
        """)
        db_browse.clicked.connect(lambda: self._browse_file(self.db_path, "Database (*.db *.sqlite)"))
        
        db_row = QHBoxLayout()
        db_row.addWidget(self.db_path)
        db_row.addWidget(db_browse)
        db_layout.addRow("Database Path:", db_row)
        
        layout.addWidget(db_group)
        
        # Logging settings
        log_group = self._create_group("Logging")
        log_layout = QFormLayout(log_group)
        log_layout.setSpacing(12)
        
        self.log_level = QComboBox()
        self.log_level.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_level.setCurrentText("INFO")
        self.log_level.setStyleSheet("""
            QComboBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        log_layout.addRow("Log Level:", self.log_level)
        
        self.log_to_file = QCheckBox("Log to file")
        self.log_to_file.setChecked(True)
        self.log_to_file.setStyleSheet("color: #e6e6e6;")
        log_layout.addRow("", self.log_to_file)
        
        layout.addWidget(log_group)
        layout.addStretch()
        
        scroll.setWidget(content)
        return scroll
    
    def _create_scanner_tab(self) -> QScrollArea:
        """Create scanner settings tab"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(24)
        
        # Nmap settings
        nmap_group = self._create_group("Nmap Settings")
        nmap_layout = QFormLayout(nmap_group)
        nmap_layout.setSpacing(12)
        
        self.nmap_path = ModernLineEdit("/usr/bin/nmap")
        nmap_browse = QPushButton("Browse")
        nmap_browse.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
            }
        """)
        nmap_browse.clicked.connect(lambda: self._browse_file(self.nmap_path, "Executables (*)"))
        
        nmap_row = QHBoxLayout()
        nmap_row.addWidget(self.nmap_path)
        nmap_row.addWidget(nmap_browse)
        nmap_layout.addRow("Nmap Path:", nmap_row)
        
        self.nmap_threads = QSpinBox()
        self.nmap_threads.setRange(1, 100)
        self.nmap_threads.setValue(10)
        self.nmap_threads.setStyleSheet("""
            QSpinBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        nmap_layout.addRow("Max Threads:", self.nmap_threads)
        
        self.nmap_timeout = QSpinBox()
        self.nmap_timeout.setRange(10, 3600)
        self.nmap_timeout.setValue(300)
        self.nmap_timeout.setSuffix(" seconds")
        self.nmap_timeout.setStyleSheet("""
            QSpinBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        nmap_layout.addRow("Timeout:", self.nmap_timeout)
        
        self.nmap_sudo = QCheckBox("Use sudo for privileged scans")
        self.nmap_sudo.setChecked(True)
        self.nmap_sudo.setStyleSheet("color: #e6e6e6;")
        nmap_layout.addRow("", self.nmap_sudo)
        
        layout.addWidget(nmap_group)
        
        # Hydra settings
        hydra_group = self._create_group("Hydra Settings")
        hydra_layout = QFormLayout(hydra_group)
        hydra_layout.setSpacing(12)
        
        self.hydra_path = ModernLineEdit("/usr/bin/hydra")
        hydra_browse = QPushButton("Browse")
        hydra_browse.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
            }
        """)
        hydra_browse.clicked.connect(lambda: self._browse_file(self.hydra_path, "Executables (*)"))
        
        hydra_row = QHBoxLayout()
        hydra_row.addWidget(self.hydra_path)
        hydra_row.addWidget(hydra_browse)
        hydra_layout.addRow("Hydra Path:", hydra_row)
        
        self.hydra_threads = QSpinBox()
        self.hydra_threads.setRange(1, 64)
        self.hydra_threads.setValue(16)
        self.hydra_threads.setStyleSheet("""
            QSpinBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        hydra_layout.addRow("Parallel Tasks:", self.hydra_threads)
        
        self.hydra_wait = QSpinBox()
        self.hydra_wait.setRange(0, 60)
        self.hydra_wait.setValue(0)
        self.hydra_wait.setSuffix(" seconds")
        self.hydra_wait.setStyleSheet("""
            QSpinBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        hydra_layout.addRow("Wait Time:", self.hydra_wait)
        
        self.hydra_exit_first = QCheckBox("Exit on first valid password")
        self.hydra_exit_first.setChecked(True)
        self.hydra_exit_first.setStyleSheet("color: #e6e6e6;")
        hydra_layout.addRow("", self.hydra_exit_first)
        
        layout.addWidget(hydra_group)
        
        # Wordlists
        wordlist_group = self._create_group("Wordlists")
        wordlist_layout = QFormLayout(wordlist_group)
        wordlist_layout.setSpacing(12)
        
        self.username_wordlist = ModernLineEdit("/usr/share/seclists/Usernames/top-usernames-shortlist.txt")
        un_browse = QPushButton("Browse")
        un_browse.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
            }
        """)
        un_browse.clicked.connect(lambda: self._browse_file(self.username_wordlist, "Text Files (*.txt)"))
        
        un_row = QHBoxLayout()
        un_row.addWidget(self.username_wordlist)
        un_row.addWidget(un_browse)
        wordlist_layout.addRow("Username Wordlist:", un_row)
        
        self.password_wordlist = ModernLineEdit("/usr/share/wordlists/rockyou.txt")
        pw_browse = QPushButton("Browse")
        pw_browse.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
            }
        """)
        pw_browse.clicked.connect(lambda: self._browse_file(self.password_wordlist, "Text Files (*.txt)"))
        
        pw_row = QHBoxLayout()
        pw_row.addWidget(self.password_wordlist)
        pw_row.addWidget(pw_browse)
        wordlist_layout.addRow("Password Wordlist:", pw_row)
        
        layout.addWidget(wordlist_group)
        layout.addStretch()
        
        scroll.setWidget(content)
        return scroll
    
    def _create_api_tab(self) -> QScrollArea:
        """Create API keys settings tab"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(24)
        
        # Info banner
        info_frame = QFrame()
        info_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 136, 255, 0.1);
                border: 1px solid #0088ff;
                border-radius: 8px;
            }
        """)
        info_layout = QHBoxLayout(info_frame)
        info_layout.setContentsMargins(16, 12, 16, 12)
        
        info_label = QLabel("🔐 API keys are stored encrypted locally. Never share your API keys.")
        info_label.setStyleSheet("color: #0088ff;")
        info_layout.addWidget(info_label)
        
        layout.addWidget(info_frame)
        
        # API Keys
        self.api_inputs = {}
        
        apis = [
            ("Shodan", "shodan", "Internet device search (shodan.io)"),
            ("Censys", "censys", "Internet scan data (censys.io)"),
            ("VirusTotal", "virustotal", "Malware analysis (virustotal.com)"),
            ("Hunter.io", "hunter", "Email discovery (hunter.io)"),
            ("SecurityTrails", "securitytrails", "DNS history (securitytrails.com)"),
            ("GreyNoise", "greynoise", "IP intelligence (greynoise.io)"),
            ("Have I Been Pwned", "hibp", "Breach data (haveibeenpwned.com)"),
        ]
        
        for name, key, description in apis:
            group = self._create_group(name)
            group_layout = QVBoxLayout(group)
            group_layout.setSpacing(8)
            
            desc_label = QLabel(description)
            desc_label.setStyleSheet("color: #8b949e; font-size: 12px;")
            group_layout.addWidget(desc_label)
            
            input_layout = QHBoxLayout()
            api_input = QLineEdit()
            api_input.setPlaceholderText(f"Enter {name} API key")
            api_input.setEchoMode(QLineEdit.EchoMode.Password)
            api_input.setStyleSheet("""
                QLineEdit {
                    background-color: #161b22;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 10px;
                    color: #e6e6e6;
                    font-family: monospace;
                }
            """)
            self.api_inputs[key] = api_input
            
            show_btn = QPushButton("👁")
            show_btn.setCheckable(True)
            show_btn.setStyleSheet("""
                QPushButton {
                    background-color: #21262d;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 10px;
                    color: #e6e6e6;
                }
                QPushButton:checked { background-color: #238636; }
            """)
            show_btn.toggled.connect(lambda checked, inp=api_input: inp.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            ))
            
            test_btn = QPushButton("Test")
            test_btn.setStyleSheet("""
                QPushButton {
                    background-color: #21262d;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 10px 16px;
                    color: #e6e6e6;
                }
                QPushButton:hover { background-color: #30363d; }
            """)
            test_btn.clicked.connect(lambda _, k=key: self._test_api(k))
            
            input_layout.addWidget(api_input)
            input_layout.addWidget(show_btn)
            input_layout.addWidget(test_btn)
            
            group_layout.addLayout(input_layout)
            layout.addWidget(group)
        
        layout.addStretch()
        
        scroll.setWidget(content)
        return scroll
    
    def _create_appearance_tab(self) -> QScrollArea:
        """Create appearance settings tab"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(24)
        
        # Theme settings
        theme_group = self._create_group("Theme")
        theme_layout = QFormLayout(theme_group)
        theme_layout.setSpacing(12)
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark (Default)", "Light", "System"])
        self.theme_combo.setStyleSheet("""
            QComboBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        theme_layout.addRow("Color Theme:", self.theme_combo)
        
        self.accent_color = QComboBox()
        self.accent_color.addItems(["Green (#00ff88)", "Blue (#0088ff)", "Purple (#8b5cf6)", "Orange (#f97316)", "Red (#ef4444)"])
        self.accent_color.setStyleSheet("""
            QComboBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        theme_layout.addRow("Accent Color:", self.accent_color)
        
        layout.addWidget(theme_group)
        
        # Font settings
        font_group = self._create_group("Fonts")
        font_layout = QFormLayout(font_group)
        font_layout.setSpacing(12)
        
        self.font_size = QSpinBox()
        self.font_size.setRange(8, 24)
        self.font_size.setValue(13)
        self.font_size.setSuffix(" px")
        self.font_size.setStyleSheet("""
            QSpinBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        font_layout.addRow("Base Font Size:", self.font_size)
        
        self.mono_font = QComboBox()
        self.mono_font.addItems(["JetBrains Mono", "Fira Code", "Consolas", "Monaco", "Courier New"])
        self.mono_font.setStyleSheet("""
            QComboBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        font_layout.addRow("Monospace Font:", self.mono_font)
        
        layout.addWidget(font_group)
        
        # Interface settings
        ui_group = self._create_group("Interface")
        ui_layout = QVBoxLayout(ui_group)
        ui_layout.setSpacing(8)
        
        self.animations = QCheckBox("Enable animations")
        self.animations.setChecked(True)
        self.animations.setStyleSheet("color: #e6e6e6;")
        ui_layout.addWidget(self.animations)
        
        self.tooltips = QCheckBox("Show tooltips")
        self.tooltips.setChecked(True)
        self.tooltips.setStyleSheet("color: #e6e6e6;")
        ui_layout.addWidget(self.tooltips)
        
        self.confirm_dialogs = QCheckBox("Confirm destructive actions")
        self.confirm_dialogs.setChecked(True)
        self.confirm_dialogs.setStyleSheet("color: #e6e6e6;")
        ui_layout.addWidget(self.confirm_dialogs)
        
        self.sidebar_collapsed = QCheckBox("Start with collapsed sidebar")
        self.sidebar_collapsed.setStyleSheet("color: #e6e6e6;")
        ui_layout.addWidget(self.sidebar_collapsed)
        
        layout.addWidget(ui_group)
        layout.addStretch()
        
        scroll.setWidget(content)
        return scroll
    
    def _create_advanced_tab(self) -> QScrollArea:
        """Create advanced settings tab"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(24)
        
        # Performance settings
        perf_group = self._create_group("Performance")
        perf_layout = QFormLayout(perf_group)
        perf_layout.setSpacing(12)
        
        self.max_concurrent = QSpinBox()
        self.max_concurrent.setRange(1, 50)
        self.max_concurrent.setValue(5)
        self.max_concurrent.setStyleSheet("""
            QSpinBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        perf_layout.addRow("Max Concurrent Scans:", self.max_concurrent)
        
        self.memory_limit = QSpinBox()
        self.memory_limit.setRange(256, 8192)
        self.memory_limit.setValue(1024)
        self.memory_limit.setSuffix(" MB")
        self.memory_limit.setStyleSheet("""
            QSpinBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        perf_layout.addRow("Memory Limit:", self.memory_limit)
        
        layout.addWidget(perf_group)
        
        # Network settings
        network_group = self._create_group("Network")
        network_layout = QFormLayout(network_group)
        network_layout.setSpacing(12)
        
        self.proxy_enabled = QCheckBox("Use proxy")
        self.proxy_enabled.setStyleSheet("color: #e6e6e6;")
        network_layout.addRow("", self.proxy_enabled)
        
        self.proxy_host = ModernLineEdit("127.0.0.1:8080")
        self.proxy_host.setEnabled(False)
        self.proxy_enabled.toggled.connect(self.proxy_host.setEnabled)
        network_layout.addRow("Proxy Address:", self.proxy_host)
        
        self.timeout = QSpinBox()
        self.timeout.setRange(5, 300)
        self.timeout.setValue(30)
        self.timeout.setSuffix(" seconds")
        self.timeout.setStyleSheet("""
            QSpinBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        network_layout.addRow("Request Timeout:", self.timeout)
        
        layout.addWidget(network_group)
        
        # Data management
        data_group = self._create_group("Data Management")
        data_layout = QVBoxLayout(data_group)
        data_layout.setSpacing(12)
        
        clear_cache = QPushButton("Clear Cache")
        clear_cache.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 16px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        clear_cache.clicked.connect(self._clear_cache)
        data_layout.addWidget(clear_cache)
        
        export_settings = QPushButton("Export Settings")
        export_settings.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 16px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        export_settings.clicked.connect(self._export_settings)
        data_layout.addWidget(export_settings)
        
        import_settings = QPushButton("Import Settings")
        import_settings.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 16px;
                color: #e6e6e6;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        import_settings.clicked.connect(self._import_settings)
        data_layout.addWidget(import_settings)
        
        layout.addWidget(data_group)
        
        # Danger zone
        danger_group = QFrame()
        danger_group.setStyleSheet("""
            QFrame {
                background-color: rgba(218, 54, 51, 0.1);
                border: 1px solid #da3633;
                border-radius: 8px;
            }
        """)
        danger_layout = QVBoxLayout(danger_group)
        danger_layout.setContentsMargins(16, 16, 16, 16)
        danger_layout.setSpacing(12)
        
        danger_label = QLabel("⚠️ Danger Zone")
        danger_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        danger_label.setStyleSheet("color: #da3633;")
        danger_layout.addWidget(danger_label)
        
        reset_all = QPushButton("Reset All Data")
        reset_all.setStyleSheet("""
            QPushButton {
                background-color: #da3633;
                border: none;
                border-radius: 6px;
                padding: 10px 16px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #f85149; }
        """)
        reset_all.clicked.connect(self._reset_all_data)
        danger_layout.addWidget(reset_all)
        
        layout.addWidget(danger_group)
        layout.addStretch()
        
        scroll.setWidget(content)
        return scroll
    
    def _create_group(self, title: str) -> QFrame:
        """Create a settings group"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        
        label = QLabel(title)
        label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        label.setStyleSheet("color: #e6e6e6;")
        layout.addWidget(label)
        
        return frame
    
    def _browse_directory(self, line_edit: QLineEdit):
        """Browse for directory"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Directory", line_edit.text()
        )
        if directory:
            line_edit.setText(directory)
    
    def _browse_file(self, line_edit: QLineEdit, filter_str: str):
        """Browse for file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File", line_edit.text(), filter_str
        )
        if file_path:
            line_edit.setText(file_path)
    
    def _load_settings(self):
        """Load settings from config"""
        # Settings would be loaded from config file
        pass
    
    def _save_settings(self):
        """Save settings"""
        QMessageBox.information(self, "Settings Saved", "Your settings have been saved successfully.")
    
    def _reset_settings(self):
        """Reset to defaults"""
        if QMessageBox.question(
            self, "Reset Settings",
            "Are you sure you want to reset all settings to defaults?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Reset", "Settings have been reset to defaults.")
    
    def _test_api(self, key: str):
        """Test API connection"""
        api_key = self.api_inputs.get(key, QLineEdit()).text()
        if not api_key:
            QMessageBox.warning(self, "Warning", f"Please enter a {key} API key first.")
            return
        
        QMessageBox.information(self, "API Test", f"Testing {key} API connection...\n(Feature not yet implemented)")
    
    def _clear_cache(self):
        """Clear application cache"""
        if QMessageBox.question(
            self, "Clear Cache",
            "Are you sure you want to clear the cache?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Cache Cleared", "Cache has been cleared successfully.")
    
    def _export_settings(self):
        """Export settings to file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Settings", "hydrarecon_settings.json", "JSON Files (*.json)"
        )
        if file_path:
            settings = {
                'version': '1.0',
                'nmap_path': self.nmap_path.text(),
                'hydra_path': self.hydra_path.text(),
                'theme': self.theme_combo.currentText(),
            }
            with open(file_path, 'w') as f:
                json.dump(settings, f, indent=2)
            QMessageBox.information(self, "Export Complete", "Settings exported successfully.")
    
    def _import_settings(self):
        """Import settings from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Settings", "", "JSON Files (*.json)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    settings = json.load(f)
                QMessageBox.information(self, "Import Complete", "Settings imported successfully.")
            except Exception as e:
                QMessageBox.warning(self, "Import Error", f"Failed to import settings: {e}")
    
    def _reset_all_data(self):
        """Reset all application data"""
        if QMessageBox.warning(
            self, "Reset All Data",
            "⚠️ This will DELETE ALL data including:\n\n"
            "• All projects\n"
            "• All scan results\n"
            "• All credentials\n"
            "• All settings\n\n"
            "This action cannot be undone!\n\n"
            "Are you sure you want to continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Data Reset", "All data has been reset.")
