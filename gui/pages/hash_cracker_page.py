"""
Hash Cracker Page
Advanced GUI for hash cracking with multiple attack modes
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QComboBox, QCheckBox, QProgressBar,
    QSplitter, QFrame, QHeaderView, QSpinBox, QFileDialog,
    QGridLayout, QRadioButton, QButtonGroup, QListWidget,
    QListWidgetItem, QPlainTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor
import asyncio
import hashlib
import os


class HashCrackWorker(QThread):
    """Worker thread for hash cracking operations"""
    progress = pyqtSignal(str, int, int)  # status, current, total
    hash_cracked = pyqtSignal(str, str, str)  # hash, plaintext, method
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, hashes, attack_mode, options):
        super().__init__()
        self.hashes = hashes
        self.attack_mode = attack_mode
        self.options = options
        self.running = True
        
    def run(self):
        try:
            import sys
            sys.path.insert(0, '..')
            from core.hash_cracker import HashCracker
            
            async def crack():
                cracker = HashCracker()
                results = []
                
                for i, hash_val in enumerate(self.hashes):
                    if not self.running:
                        break
                        
                    self.progress.emit(f"Cracking hash {i+1}/{len(self.hashes)}", i, len(self.hashes))
                    
                    if self.attack_mode == "dictionary":
                        result = await cracker.crack_hash(
                            hash_val,
                            attack_type="dictionary",
                            wordlist=self.options.get('wordlist')
                        )
                    elif self.attack_mode == "brute_force":
                        result = await cracker.crack_hash(
                            hash_val,
                            attack_type="brute_force",
                            charset=self.options.get('charset', 'lower'),
                            max_length=self.options.get('max_length', 6)
                        )
                    elif self.attack_mode == "rainbow":
                        result = await cracker.crack_hash(
                            hash_val,
                            attack_type="rainbow"
                        )
                    elif self.attack_mode == "hybrid":
                        result = await cracker.crack_hash(
                            hash_val,
                            attack_type="hybrid",
                            wordlist=self.options.get('wordlist'),
                            rules=self.options.get('rules', [])
                        )
                    else:
                        result = await cracker.crack_hash(hash_val)
                    
                    if result and result.cracked:
                        self.hash_cracked.emit(hash_val, result.plaintext, self.attack_mode)
                        results.append(result)
                
                return results
                
            results = asyncio.run(crack())
            self.finished.emit(results)
            
        except Exception as e:
            self.error.emit(str(e))
    
    def stop(self):
        self.running = False


class HashIdentifyWorker(QThread):
    """Worker thread for hash identification"""
    result = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def __init__(self, hash_value):
        super().__init__()
        self.hash_value = hash_value
        
    def run(self):
        try:
            import sys
            sys.path.insert(0, '..')
            from core.hash_cracker import HashCracker
            
            async def identify():
                cracker = HashCracker()
                return await cracker.identify_hash(self.hash_value)
                
            result = asyncio.run(identify())
            self.result.emit(result if result else [])
            
        except Exception as e:
            self.error.emit(str(e))


class HashCrackerPage(QWidget):
    """Hash Cracker page with multiple attack modes"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.crack_worker = None
        self.identify_worker = None
        self.cracked_hashes = {}  # hash -> plaintext mapping
        
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
        self.tabs.addTab(self._create_crack_tab(), "🔨 Hash Cracker")
        self.tabs.addTab(self._create_identify_tab(), "🔍 Hash Identifier")
        self.tabs.addTab(self._create_generator_tab(), "⚡ Hash Generator")
        self.tabs.addTab(self._create_wordlist_tab(), "📚 Wordlists")
        self.tabs.addTab(self._create_results_tab(), "📊 Results")
        
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
        
        title = QLabel("🔨 Hash Cracker")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            color: #e6e6e6;
        """)
        
        subtitle = QLabel("Multi-mode hash cracking with rainbow tables, dictionary attacks, and brute force")
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
            'loaded': self._create_stat_widget("Loaded", "0"),
            'cracked': self._create_stat_widget("Cracked", "0"),
            'rate': self._create_stat_widget("Rate", "0 H/s"),
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
        value_label.setObjectName(f"stat_value_{label.lower()}")
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
    
    def _create_crack_tab(self) -> QWidget:
        """Create the main hash cracking tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Hash input section
        input_group = QGroupBox("Hash Input")
        input_group.setStyleSheet("""
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
        
        input_layout = QVBoxLayout(input_group)
        
        # Single hash input
        single_layout = QHBoxLayout()
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter hash to crack (e.g., 5d41402abc4b2a76b9719d911017c592)")
        self.hash_input.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
                font-family: monospace;
            }
        """)
        
        add_hash_btn = QPushButton("Add Hash")
        add_hash_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        add_hash_btn.clicked.connect(self._add_hash)
        
        single_layout.addWidget(self.hash_input)
        single_layout.addWidget(add_hash_btn)
        input_layout.addLayout(single_layout)
        
        # Load from file
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Path to hash file...")
        self.file_path.setStyleSheet(self.hash_input.styleSheet())
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_hash_file)
        browse_btn.setStyleSheet(add_hash_btn.styleSheet().replace("#238636", "#21262d").replace("#2ea043", "#30363d"))
        
        load_btn = QPushButton("Load Hashes")
        load_btn.clicked.connect(self._load_hashes_from_file)
        load_btn.setStyleSheet(add_hash_btn.styleSheet())
        
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(browse_btn)
        file_layout.addWidget(load_btn)
        input_layout.addLayout(file_layout)
        
        # Hash list
        self.hash_list = QListWidget()
        self.hash_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #e6e6e6;
                font-family: monospace;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #21262d;
            }
            QListWidget::item:selected {
                background: #1f6feb30;
            }
        """)
        self.hash_list.setMaximumHeight(150)
        input_layout.addWidget(self.hash_list)
        
        # Clear button
        clear_btn = QPushButton("Clear All Hashes")
        clear_btn.clicked.connect(self._clear_hashes)
        clear_btn.setStyleSheet(add_hash_btn.styleSheet().replace("#238636", "#da3633").replace("#2ea043", "#f85149"))
        input_layout.addWidget(clear_btn)
        
        layout.addWidget(input_group)
        
        # Attack mode section
        attack_group = QGroupBox("Attack Mode")
        attack_group.setStyleSheet(input_group.styleSheet())
        
        attack_layout = QVBoxLayout(attack_group)
        
        # Attack mode radio buttons
        mode_layout = QHBoxLayout()
        self.attack_mode_group = QButtonGroup()
        
        modes = [
            ("Dictionary Attack", "dictionary", "Uses wordlist to crack hashes"),
            ("Brute Force", "brute_force", "Try all possible combinations"),
            ("Rainbow Tables", "rainbow", "Fast lookup using precomputed tables"),
            ("Hybrid Attack", "hybrid", "Wordlist + rules for variations"),
        ]
        
        for text, value, tooltip in modes:
            radio = QRadioButton(text)
            radio.setToolTip(tooltip)
            radio.setStyleSheet("""
                QRadioButton {
                    color: #e6e6e6;
                    spacing: 8px;
                }
                QRadioButton::indicator {
                    width: 16px;
                    height: 16px;
                }
            """)
            self.attack_mode_group.addButton(radio)
            radio.setProperty("mode", value)
            if value == "dictionary":
                radio.setChecked(True)
            mode_layout.addWidget(radio)
        
        mode_layout.addStretch()
        attack_layout.addLayout(mode_layout)
        
        # Attack options
        options_layout = QGridLayout()
        
        # Wordlist selection
        options_layout.addWidget(QLabel("Wordlist:"), 0, 0)
        self.wordlist_combo = QComboBox()
        self.wordlist_combo.addItems([
            "rockyou.txt",
            "darkweb2017-top10000.txt",
            "common-passwords.txt",
            "Custom...",
        ])
        self.wordlist_combo.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        options_layout.addWidget(self.wordlist_combo, 0, 1)
        
        # Hash type
        options_layout.addWidget(QLabel("Hash Type:"), 0, 2)
        self.hash_type_combo = QComboBox()
        self.hash_type_combo.addItems([
            "Auto-detect",
            "MD5",
            "SHA1",
            "SHA256",
            "SHA512",
            "NTLM",
            "bcrypt",
            "scrypt",
            "argon2",
        ])
        self.hash_type_combo.setStyleSheet(self.wordlist_combo.styleSheet())
        options_layout.addWidget(self.hash_type_combo, 0, 3)
        
        # Brute force options
        options_layout.addWidget(QLabel("Charset:"), 1, 0)
        self.charset_combo = QComboBox()
        self.charset_combo.addItems([
            "lowercase (a-z)",
            "uppercase (A-Z)",
            "digits (0-9)",
            "alphanumeric",
            "all printable",
        ])
        self.charset_combo.setStyleSheet(self.wordlist_combo.styleSheet())
        options_layout.addWidget(self.charset_combo, 1, 1)
        
        options_layout.addWidget(QLabel("Max Length:"), 1, 2)
        self.max_length_spin = QSpinBox()
        self.max_length_spin.setRange(1, 12)
        self.max_length_spin.setValue(6)
        self.max_length_spin.setStyleSheet("""
            QSpinBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        options_layout.addWidget(self.max_length_spin, 1, 3)
        
        attack_layout.addLayout(options_layout)
        layout.addWidget(attack_group)
        
        # Progress section
        progress_group = QGroupBox("Progress")
        progress_group.setStyleSheet(input_group.styleSheet())
        
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_label = QLabel("Ready to crack hashes")
        self.progress_label.setStyleSheet("color: #8b949e;")
        progress_layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background: #21262d;
                border: none;
                border-radius: 6px;
                height: 20px;
                text-align: center;
                color: #e6e6e6;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, stop:1 #00cc6a);
                border-radius: 6px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        layout.addWidget(progress_group)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 Start Cracking")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #238636, stop:1 #2ea043);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 14px 28px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2ea043, stop:1 #3fb950);
            }
        """)
        self.start_btn.clicked.connect(self._start_cracking)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background: #da3633;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 14px 28px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #f85149;
            }
            QPushButton:disabled {
                background: #21262d;
                color: #8b949e;
            }
        """)
        self.stop_btn.clicked.connect(self._stop_cracking)
        
        control_layout.addStretch()
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addStretch()
        
        layout.addLayout(control_layout)
        layout.addStretch()
        
        return widget
    
    def _create_identify_tab(self) -> QWidget:
        """Create hash identification tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Input section
        input_group = QGroupBox("Hash to Identify")
        input_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
            }
        """)
        
        input_layout = QVBoxLayout(input_group)
        
        self.identify_input = QPlainTextEdit()
        self.identify_input.setPlaceholderText("Paste hash(es) here to identify their type...")
        self.identify_input.setMaximumHeight(100)
        self.identify_input.setStyleSheet("""
            QPlainTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
                font-family: monospace;
            }
        """)
        input_layout.addWidget(self.identify_input)
        
        identify_btn = QPushButton("🔍 Identify Hash Type")
        identify_btn.clicked.connect(self._identify_hash)
        identify_btn.setStyleSheet("""
            QPushButton {
                background: #1f6feb;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #388bfd;
            }
        """)
        input_layout.addWidget(identify_btn)
        
        layout.addWidget(input_group)
        
        # Results section
        results_group = QGroupBox("Identification Results")
        results_group.setStyleSheet(input_group.styleSheet())
        
        results_layout = QVBoxLayout(results_group)
        
        self.identify_results = QTableWidget()
        self.identify_results.setColumnCount(4)
        self.identify_results.setHorizontalHeaderLabels([
            "Hash", "Type", "Confidence", "Description"
        ])
        self.identify_results.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.identify_results.setStyleSheet("""
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
        results_layout.addWidget(self.identify_results)
        
        layout.addWidget(results_group)
        
        # Common hash types reference
        ref_group = QGroupBox("Hash Type Reference")
        ref_group.setStyleSheet(input_group.styleSheet())
        
        ref_layout = QVBoxLayout(ref_group)
        
        ref_table = QTableWidget()
        ref_table.setColumnCount(3)
        ref_table.setHorizontalHeaderLabels(["Type", "Length", "Example"])
        ref_table.setStyleSheet(self.identify_results.styleSheet())
        ref_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        references = [
            ("MD5", "32", "5d41402abc4b2a76b9719d911017c592"),
            ("SHA1", "40", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
            ("SHA256", "64", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e..."),
            ("SHA512", "128", "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caad..."),
            ("NTLM", "32", "a9fdfa038c4b75ebc76dc855dd74f0da"),
            ("bcrypt", "60", "$2a$10$N9qo8uLOickgx2ZMRZoMye..."),
        ]
        
        ref_table.setRowCount(len(references))
        for i, (type_name, length, example) in enumerate(references):
            ref_table.setItem(i, 0, QTableWidgetItem(type_name))
            ref_table.setItem(i, 1, QTableWidgetItem(length))
            ref_table.setItem(i, 2, QTableWidgetItem(example))
        
        ref_layout.addWidget(ref_table)
        layout.addWidget(ref_group)
        
        return widget
    
    def _create_generator_tab(self) -> QWidget:
        """Create hash generator tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Input section
        input_group = QGroupBox("Text to Hash")
        input_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
            }
        """)
        
        input_layout = QVBoxLayout(input_group)
        
        self.generate_input = QPlainTextEdit()
        self.generate_input.setPlaceholderText("Enter text to generate hashes...")
        self.generate_input.setMaximumHeight(100)
        self.generate_input.setStyleSheet("""
            QPlainTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        input_layout.addWidget(self.generate_input)
        
        generate_btn = QPushButton("⚡ Generate Hashes")
        generate_btn.clicked.connect(self._generate_hashes)
        generate_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        input_layout.addWidget(generate_btn)
        
        layout.addWidget(input_group)
        
        # Generated hashes
        output_group = QGroupBox("Generated Hashes")
        output_group.setStyleSheet(input_group.styleSheet())
        
        output_layout = QVBoxLayout(output_group)
        
        self.generated_hashes = QTableWidget()
        self.generated_hashes.setColumnCount(2)
        self.generated_hashes.setHorizontalHeaderLabels(["Algorithm", "Hash"])
        self.generated_hashes.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.generated_hashes.setStyleSheet("""
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
        output_layout.addWidget(self.generated_hashes)
        
        layout.addWidget(output_group)
        layout.addStretch()
        
        return widget
    
    def _create_wordlist_tab(self) -> QWidget:
        """Create wordlist management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Wordlist management
        manage_group = QGroupBox("Wordlist Management")
        manage_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
            }
        """)
        
        manage_layout = QVBoxLayout(manage_group)
        
        self.wordlist_table = QTableWidget()
        self.wordlist_table.setColumnCount(4)
        self.wordlist_table.setHorizontalHeaderLabels([
            "Name", "Size", "Words", "Status"
        ])
        self.wordlist_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.wordlist_table.setStyleSheet(self.generated_hashes.styleSheet() if hasattr(self, 'generated_hashes') else """
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
        """)
        
        # Populate with common wordlists
        wordlists = [
            ("rockyou.txt", "134 MB", "14,344,391", "Available"),
            ("darkweb2017-top10000.txt", "85 KB", "10,000", "Available"),
            ("common-passwords.txt", "4 KB", "1,000", "Available"),
            ("hashcat-rules.txt", "1 MB", "Rules", "Available"),
        ]
        
        self.wordlist_table.setRowCount(len(wordlists))
        for i, (name, size, words, status) in enumerate(wordlists):
            self.wordlist_table.setItem(i, 0, QTableWidgetItem(name))
            self.wordlist_table.setItem(i, 1, QTableWidgetItem(size))
            self.wordlist_table.setItem(i, 2, QTableWidgetItem(words))
            
            status_item = QTableWidgetItem(status)
            if status == "Available":
                status_item.setForeground(QColor("#3fb950"))
            else:
                status_item.setForeground(QColor("#f85149"))
            self.wordlist_table.setItem(i, 3, status_item)
        
        manage_layout.addWidget(self.wordlist_table)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        add_btn = QPushButton("Add Wordlist")
        add_btn.setStyleSheet("""
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
        
        download_btn = QPushButton("Download Popular")
        download_btn.setStyleSheet(add_btn.styleSheet().replace("#238636", "#1f6feb").replace("#2ea043", "#388bfd"))
        
        merge_btn = QPushButton("Merge Wordlists")
        merge_btn.setStyleSheet(add_btn.styleSheet().replace("#238636", "#6e40c9").replace("#2ea043", "#8957e5"))
        
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(download_btn)
        btn_layout.addWidget(merge_btn)
        btn_layout.addStretch()
        
        manage_layout.addLayout(btn_layout)
        layout.addWidget(manage_group)
        
        # Custom wordlist generator
        gen_group = QGroupBox("Custom Wordlist Generator")
        gen_group.setStyleSheet(manage_group.styleSheet())
        
        gen_layout = QGridLayout(gen_group)
        
        gen_layout.addWidget(QLabel("Base words:"), 0, 0)
        self.base_words = QLineEdit()
        self.base_words.setPlaceholderText("company, password, admin (comma separated)")
        self.base_words.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        gen_layout.addWidget(self.base_words, 0, 1, 1, 2)
        
        gen_layout.addWidget(QLabel("Rules:"), 1, 0)
        self.apply_rules = QCheckBox("Append numbers (0-99)")
        self.apply_rules.setChecked(True)
        gen_layout.addWidget(self.apply_rules, 1, 1)
        
        self.apply_symbols = QCheckBox("Append symbols (!@#$)")
        gen_layout.addWidget(self.apply_symbols, 1, 2)
        
        self.apply_case = QCheckBox("Case variations")
        self.apply_case.setChecked(True)
        gen_layout.addWidget(self.apply_case, 2, 1)
        
        self.apply_leet = QCheckBox("Leet speak (a->4, e->3)")
        gen_layout.addWidget(self.apply_leet, 2, 2)
        
        generate_wl_btn = QPushButton("Generate Custom Wordlist")
        generate_wl_btn.setStyleSheet(add_btn.styleSheet())
        gen_layout.addWidget(generate_wl_btn, 3, 0, 1, 3)
        
        layout.addWidget(gen_group)
        layout.addStretch()
        
        return widget
    
    def _create_results_tab(self) -> QWidget:
        """Create results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Hash", "Plaintext", "Type", "Method", "Time"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 10px;
                color: #e6e6e6;
                font-family: monospace;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 12px;
                border: none;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.results_table)
        
        # Export buttons
        btn_layout = QHBoxLayout()
        
        export_csv = QPushButton("Export CSV")
        export_csv.setStyleSheet("""
            QPushButton {
                background: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 20px;
            }
            QPushButton:hover { background: #30363d; }
        """)
        
        export_json = QPushButton("Export JSON")
        export_json.setStyleSheet(export_csv.styleSheet())
        
        clear_results = QPushButton("Clear Results")
        clear_results.clicked.connect(lambda: self.results_table.setRowCount(0))
        clear_results.setStyleSheet(export_csv.styleSheet().replace("#21262d", "#da3633").replace("#30363d", "#f85149"))
        
        btn_layout.addWidget(export_csv)
        btn_layout.addWidget(export_json)
        btn_layout.addStretch()
        btn_layout.addWidget(clear_results)
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def _connect_signals(self):
        """Connect widget signals"""
        pass
    
    def _add_hash(self):
        """Add hash to the list"""
        hash_val = self.hash_input.text().strip()
        if hash_val:
            self.hash_list.addItem(hash_val)
            self.hash_input.clear()
            self._update_stats()
    
    def _browse_hash_file(self):
        """Browse for hash file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Hash File", "", "Text files (*.txt);;All files (*)"
        )
        if file_path:
            self.file_path.setText(file_path)
    
    def _load_hashes_from_file(self):
        """Load hashes from file"""
        file_path = self.file_path.text().strip()
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        hash_val = line.strip()
                        if hash_val:
                            self.hash_list.addItem(hash_val)
                self._update_stats()
            except Exception as e:
                self.progress_label.setText(f"Error loading file: {e}")
    
    def _clear_hashes(self):
        """Clear all hashes"""
        self.hash_list.clear()
        self._update_stats()
    
    def _update_stats(self):
        """Update statistics display"""
        loaded = self.hash_list.count()
        cracked = len(self.cracked_hashes)
        
        # Update stat labels
        for child in self.stats['loaded'].findChildren(QLabel):
            if child.objectName() == "stat_value_loaded":
                child.setText(str(loaded))
        
        for child in self.stats['cracked'].findChildren(QLabel):
            if child.objectName() == "stat_value_cracked":
                child.setText(str(cracked))
    
    def _get_selected_attack_mode(self) -> str:
        """Get the currently selected attack mode"""
        for btn in self.attack_mode_group.buttons():
            if btn.isChecked():
                return btn.property("mode")
        return "dictionary"
    
    def _start_cracking(self):
        """Start the hash cracking process"""
        if self.hash_list.count() == 0:
            self.progress_label.setText("No hashes to crack!")
            return
        
        hashes = []
        for i in range(self.hash_list.count()):
            hashes.append(self.hash_list.item(i).text())
        
        attack_mode = self._get_selected_attack_mode()
        options = {
            'wordlist': self.wordlist_combo.currentText(),
            'charset': self.charset_combo.currentText().split()[0].lower(),
            'max_length': self.max_length_spin.value(),
        }
        
        self.crack_worker = HashCrackWorker(hashes, attack_mode, options)
        self.crack_worker.progress.connect(self._on_crack_progress)
        self.crack_worker.hash_cracked.connect(self._on_hash_cracked)
        self.crack_worker.finished.connect(self._on_crack_finished)
        self.crack_worker.error.connect(self._on_crack_error)
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_label.setText("Starting hash cracking...")
        
        self.crack_worker.start()
    
    def _stop_cracking(self):
        """Stop the cracking process"""
        if self.crack_worker:
            self.crack_worker.stop()
            self.crack_worker.wait()
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_label.setText("Cracking stopped by user")
    
    def _on_crack_progress(self, status: str, current: int, total: int):
        """Handle cracking progress update"""
        self.progress_label.setText(status)
        if total > 0:
            self.progress_bar.setValue(int((current / total) * 100))
    
    def _on_hash_cracked(self, hash_val: str, plaintext: str, method: str):
        """Handle cracked hash"""
        self.cracked_hashes[hash_val] = plaintext
        
        # Add to results table
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(hash_val[:32] + "..."))
        self.results_table.setItem(row, 1, QTableWidgetItem(plaintext))
        self.results_table.setItem(row, 2, QTableWidgetItem("Auto-detected"))
        self.results_table.setItem(row, 3, QTableWidgetItem(method))
        self.results_table.setItem(row, 4, QTableWidgetItem("< 1s"))
        
        self._update_stats()
    
    def _on_crack_finished(self, results):
        """Handle cracking completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        
        cracked_count = len(self.cracked_hashes)
        total_count = self.hash_list.count()
        self.progress_label.setText(
            f"Cracking complete: {cracked_count}/{total_count} hashes cracked"
        )
    
    def _on_crack_error(self, error: str):
        """Handle cracking error"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_label.setText(f"Error: {error}")
    
    def _identify_hash(self):
        """Identify hash type"""
        hash_text = self.identify_input.toPlainText().strip()
        if not hash_text:
            return
        
        hashes = hash_text.split('\n')
        self.identify_results.setRowCount(0)
        
        for hash_val in hashes:
            hash_val = hash_val.strip()
            if not hash_val:
                continue
            
            # Simple hash identification based on length and pattern
            results = self._identify_hash_type(hash_val)
            
            for hash_type, confidence, description in results:
                row = self.identify_results.rowCount()
                self.identify_results.insertRow(row)
                self.identify_results.setItem(row, 0, QTableWidgetItem(hash_val[:32] + "..." if len(hash_val) > 32 else hash_val))
                self.identify_results.setItem(row, 1, QTableWidgetItem(hash_type))
                
                conf_item = QTableWidgetItem(f"{confidence}%")
                if confidence >= 80:
                    conf_item.setForeground(QColor("#3fb950"))
                elif confidence >= 50:
                    conf_item.setForeground(QColor("#d29922"))
                else:
                    conf_item.setForeground(QColor("#f85149"))
                self.identify_results.setItem(row, 2, conf_item)
                
                self.identify_results.setItem(row, 3, QTableWidgetItem(description))
    
    def _identify_hash_type(self, hash_val: str) -> list:
        """Identify hash type based on length and pattern"""
        results = []
        length = len(hash_val)
        
        # Check if hex
        is_hex = all(c in '0123456789abcdefABCDEF' for c in hash_val)
        
        if is_hex:
            if length == 32:
                results.append(("MD5", 90, "128-bit hash, commonly used"))
                results.append(("NTLM", 70, "Windows NT LAN Manager hash"))
            elif length == 40:
                results.append(("SHA1", 90, "160-bit hash, deprecated for security"))
            elif length == 64:
                results.append(("SHA256", 90, "256-bit hash, widely used"))
            elif length == 128:
                results.append(("SHA512", 90, "512-bit hash, high security"))
        
        if hash_val.startswith('$2a$') or hash_val.startswith('$2b$'):
            results.append(("bcrypt", 95, "Password hashing function"))
        
        if hash_val.startswith('$argon2'):
            results.append(("Argon2", 95, "Memory-hard password hash"))
        
        if not results:
            results.append(("Unknown", 0, "Hash type could not be determined"))
        
        return results
    
    def _generate_hashes(self):
        """Generate hashes from input text"""
        text = self.generate_input.toPlainText()
        if not text:
            return
        
        algorithms = [
            ("MD5", hashlib.md5),
            ("SHA1", hashlib.sha1),
            ("SHA256", hashlib.sha256),
            ("SHA512", hashlib.sha512),
        ]
        
        self.generated_hashes.setRowCount(len(algorithms))
        
        for i, (name, algo) in enumerate(algorithms):
            hash_val = algo(text.encode()).hexdigest()
            self.generated_hashes.setItem(i, 0, QTableWidgetItem(name))
            self.generated_hashes.setItem(i, 1, QTableWidgetItem(hash_val))
