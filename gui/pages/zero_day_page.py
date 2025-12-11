"""
Zero-Day Exploit Framework Page
Advanced vulnerability research and exploit development interface
"""

import asyncio
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QComboBox,
    QSpinBox, QGroupBox, QTextEdit, QLineEdit, QProgressBar,
    QSplitter, QFrame, QHeaderView, QCheckBox, QMessageBox,
    QFileDialog, QListWidget, QListWidgetItem, QFormLayout,
    QPlainTextEdit, QTreeWidget, QTreeWidgetItem, QDoubleSpinBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.zero_day_framework import (
    ZeroDayFramework, Vulnerability, ExploitModule, FuzzingResult,
    ExploitType, ExploitStage, TargetArch, TargetOS, ROPGadget
)


class ExploitWorker(QThread):
    """Background worker for exploit development tasks"""
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.func(*self.args, **self.kwargs))
            self.result_ready.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class PythonHighlighter(QSyntaxHighlighter):
    """Simple Python syntax highlighter"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#ff79c6"))
        keywords = [
            "def", "class", "import", "from", "return", "if", "else", "elif",
            "for", "while", "try", "except", "finally", "with", "as", "pass",
            "break", "continue", "raise", "yield", "lambda", "and", "or", "not",
            "in", "is", "None", "True", "False"
        ]
        for word in keywords:
            self.highlighting_rules.append((f"\\b{word}\\b", keyword_format))
        
        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#f1fa8c"))
        self.highlighting_rules.append((r'"[^"\\]*(\\.[^"\\]*)*"', string_format))
        self.highlighting_rules.append((r"'[^'\\]*(\\.[^'\\]*)*'", string_format))
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6272a4"))
        self.highlighting_rules.append((r"#[^\n]*", comment_format))
        
        # Numbers
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#bd93f9"))
        self.highlighting_rules.append((r"\b0x[0-9a-fA-F]+\b", number_format))
        self.highlighting_rules.append((r"\b[0-9]+\b", number_format))
        
        # Functions
        func_format = QTextCharFormat()
        func_format.setForeground(QColor("#50fa7b"))
        self.highlighting_rules.append((r"\bdef\s+(\w+)", func_format))
    
    def highlightBlock(self, text):
        import re
        for pattern, format in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), format)


class ZeroDayPage(QWidget):
    """Zero-Day Exploit Framework GUI Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.framework = ZeroDayFramework()
        self.workers = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("💀 Zero-Day Exploit Framework")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ff0044;
            padding: 10px;
        """)
        layout.addWidget(header)
        
        # Warning banner
        warning = QLabel("⚠️ FOR AUTHORIZED SECURITY RESEARCH ONLY - UNAUTHORIZED USE IS ILLEGAL")
        warning.setStyleSheet("""
            background: #ff004422;
            border: 2px solid #ff0044;
            color: #ff0044;
            padding: 10px;
            border-radius: 4px;
            font-weight: bold;
        """)
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(warning)
        
        # Main tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #333;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #888;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #ff0044;
                color: #fff;
            }
        """)
        
        tabs.addTab(self.create_discovery_tab(), "🔍 Discovery")
        tabs.addTab(self.create_fuzzing_tab(), "🎯 Fuzzing")
        tabs.addTab(self.create_rop_tab(), "⛓️ ROP Builder")
        tabs.addTab(self.create_shellcode_tab(), "💉 Shellcode")
        tabs.addTab(self.create_exploit_tab(), "💀 Exploits")
        tabs.addTab(self.create_test_tab(), "🧪 Testing")
        
        layout.addWidget(tabs)
        
        # Status bar
        self.status_bar = QLabel("Zero-Day Framework Ready")
        self.status_bar.setStyleSheet("""
            background: #1a1a2e;
            padding: 8px;
            border-radius: 4px;
            color: #ff0044;
        """)
        layout.addWidget(self.status_bar)
    
    def create_discovery_tab(self) -> QWidget:
        """Create vulnerability discovery tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target configuration
        target_group = QGroupBox("Target Analysis")
        target_group.setStyleSheet("""
            QGroupBox { font-weight: bold; border: 2px solid #ff0044; border-radius: 8px; margin-top: 10px; padding-top: 10px; }
            QGroupBox::title { color: #ff0044; }
        """)
        target_layout = QFormLayout(target_group)
        
        # Binary path
        binary_layout = QHBoxLayout()
        self.binary_path = QLineEdit()
        self.binary_path.setPlaceholderText("/path/to/target/binary")
        binary_layout.addWidget(self.binary_path)
        
        browse_btn = QPushButton("📂")
        browse_btn.clicked.connect(self.browse_binary)
        binary_layout.addWidget(browse_btn)
        
        target_layout.addRow("Target Binary:", binary_layout)
        
        # Vulnerability type
        self.vuln_type = QComboBox()
        for vt in ExploitType:
            self.vuln_type.addItem(vt.value.replace("_", " ").title(), vt)
        target_layout.addRow("Vuln Type:", self.vuln_type)
        
        # Target info
        self.target_os = QComboBox()
        for os_type in TargetOS:
            self.target_os.addItem(os_type.value.title(), os_type)
        target_layout.addRow("Target OS:", self.target_os)
        
        self.target_arch = QComboBox()
        for arch in TargetArch:
            self.target_arch.addItem(arch.value, arch)
        target_layout.addRow("Architecture:", self.target_arch)
        
        analyze_btn = QPushButton("🔍 Analyze Binary")
        analyze_btn.clicked.connect(self.analyze_binary)
        analyze_btn.setStyleSheet("background: #ff0044; color: #fff; font-weight: bold; padding: 10px;")
        target_layout.addRow("", analyze_btn)
        
        layout.addWidget(target_group)
        
        # Analysis results
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout(results_group)
        
        self.analysis_output = QPlainTextEdit()
        self.analysis_output.setReadOnly(True)
        self.analysis_output.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ff88;
            }
        """)
        results_layout.addWidget(self.analysis_output)
        
        layout.addWidget(results_group)
        
        # Discovered vulnerabilities
        vulns_group = QGroupBox("Discovered Vulnerabilities")
        vulns_layout = QVBoxLayout(vulns_group)
        
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(5)
        self.vulns_table.setHorizontalHeaderLabels([
            "ID", "Name", "Type", "CVSS", "Zero-Day"
        ])
        self.vulns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        vulns_layout.addWidget(self.vulns_table)
        
        layout.addWidget(vulns_group)
        
        return widget
    
    def create_fuzzing_tab(self) -> QWidget:
        """Create fuzzing tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Fuzzing configuration
        config_group = QGroupBox("Fuzzer Configuration")
        config_layout = QFormLayout(config_group)
        
        # Target
        fuzz_target_layout = QHBoxLayout()
        self.fuzz_target = QLineEdit()
        self.fuzz_target.setPlaceholderText("/path/to/target")
        fuzz_target_layout.addWidget(self.fuzz_target)
        
        browse_fuzz_btn = QPushButton("📂")
        browse_fuzz_btn.clicked.connect(self.browse_fuzz_target)
        fuzz_target_layout.addWidget(browse_fuzz_btn)
        
        config_layout.addRow("Target:", fuzz_target_layout)
        
        # Iterations
        self.fuzz_iterations = QSpinBox()
        self.fuzz_iterations.setRange(100, 1000000)
        self.fuzz_iterations.setValue(10000)
        config_layout.addRow("Iterations:", self.fuzz_iterations)
        
        # Timeout
        self.fuzz_timeout = QDoubleSpinBox()
        self.fuzz_timeout.setRange(0.1, 60.0)
        self.fuzz_timeout.setValue(5.0)
        config_layout.addRow("Timeout (s):", self.fuzz_timeout)
        
        # Mutation types
        mutation_layout = QHBoxLayout()
        self.mutation_bitflip = QCheckBox("Bitflip")
        self.mutation_bitflip.setChecked(True)
        mutation_layout.addWidget(self.mutation_bitflip)
        
        self.mutation_insert = QCheckBox("Insert")
        self.mutation_insert.setChecked(True)
        mutation_layout.addWidget(self.mutation_insert)
        
        self.mutation_remove = QCheckBox("Remove")
        self.mutation_remove.setChecked(True)
        mutation_layout.addWidget(self.mutation_remove)
        
        self.mutation_havoc = QCheckBox("Havoc")
        self.mutation_havoc.setChecked(True)
        mutation_layout.addWidget(self.mutation_havoc)
        
        config_layout.addRow("Mutations:", mutation_layout)
        
        # Seed input
        self.seed_input = QLineEdit()
        self.seed_input.setPlaceholderText("Optional base input for mutation")
        config_layout.addRow("Seed Input:", self.seed_input)
        
        fuzz_btn = QPushButton("🎯 Start Fuzzing")
        fuzz_btn.clicked.connect(self.start_fuzzing)
        fuzz_btn.setStyleSheet("background: #ff6600; color: #000; font-weight: bold; padding: 10px;")
        config_layout.addRow("", fuzz_btn)
        
        layout.addWidget(config_group)
        
        # Fuzzing progress
        progress_group = QGroupBox("Fuzzing Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.fuzz_progress = QProgressBar()
        self.fuzz_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #333;
                border-radius: 5px;
                background: #1a1a2e;
                height: 25px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff0044, stop:1 #ff6600);
            }
        """)
        progress_layout.addWidget(self.fuzz_progress)
        
        self.fuzz_stats = QLabel("Executions: 0 | Crashes: 0 | Unique: 0")
        self.fuzz_stats.setStyleSheet("color: #888; padding: 5px;")
        progress_layout.addWidget(self.fuzz_stats)
        
        layout.addWidget(progress_group)
        
        # Crash results
        crashes_group = QGroupBox("Discovered Crashes")
        crashes_layout = QVBoxLayout(crashes_group)
        
        self.crashes_table = QTableWidget()
        self.crashes_table.setColumnCount(5)
        self.crashes_table.setHorizontalHeaderLabels([
            "ID", "Crash Type", "Exploitable", "Score", "Input Size"
        ])
        self.crashes_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.crashes_table.itemDoubleClicked.connect(self.show_crash_details)
        crashes_layout.addWidget(self.crashes_table)
        
        layout.addWidget(crashes_group)
        
        return widget
    
    def create_rop_tab(self) -> QWidget:
        """Create ROP gadget finder tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Gadget finder
        finder_group = QGroupBox("ROP Gadget Finder")
        finder_layout = QFormLayout(finder_group)
        
        # Binary path
        rop_binary_layout = QHBoxLayout()
        self.rop_binary = QLineEdit()
        self.rop_binary.setPlaceholderText("/path/to/binary")
        rop_binary_layout.addWidget(self.rop_binary)
        
        browse_rop_btn = QPushButton("📂")
        browse_rop_btn.clicked.connect(self.browse_rop_binary)
        rop_binary_layout.addWidget(browse_rop_btn)
        
        finder_layout.addRow("Binary:", rop_binary_layout)
        
        find_gadgets_btn = QPushButton("⛓️ Find Gadgets")
        find_gadgets_btn.clicked.connect(self.find_gadgets)
        find_gadgets_btn.setStyleSheet("background: #00ccff; color: #000; font-weight: bold; padding: 10px;")
        finder_layout.addRow("", find_gadgets_btn)
        
        layout.addWidget(finder_group)
        
        # Gadgets list
        gadgets_group = QGroupBox("Found Gadgets")
        gadgets_layout = QVBoxLayout(gadgets_group)
        
        self.gadgets_table = QTableWidget()
        self.gadgets_table.setColumnCount(4)
        self.gadgets_table.setHorizontalHeaderLabels([
            "Address", "Type", "Instructions", "Bytes"
        ])
        self.gadgets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        gadgets_layout.addWidget(self.gadgets_table)
        
        layout.addWidget(gadgets_group)
        
        # ROP chain builder
        chain_group = QGroupBox("ROP Chain Builder")
        chain_layout = QVBoxLayout(chain_group)
        
        chain_config = QHBoxLayout()
        chain_config.addWidget(QLabel("Target Function:"))
        self.chain_target = QLineEdit()
        self.chain_target.setPlaceholderText("0x401234")
        chain_config.addWidget(self.chain_target)
        
        chain_config.addWidget(QLabel("Args:"))
        self.chain_args = QLineEdit()
        self.chain_args.setPlaceholderText("0xdead, 0xbeef")
        chain_config.addWidget(self.chain_args)
        
        build_chain_btn = QPushButton("🔗 Build Chain")
        build_chain_btn.clicked.connect(self.build_rop_chain)
        chain_config.addWidget(build_chain_btn)
        
        chain_layout.addLayout(chain_config)
        
        self.rop_chain_output = QPlainTextEdit()
        self.rop_chain_output.setReadOnly(True)
        self.rop_chain_output.setMaximumHeight(150)
        self.rop_chain_output.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ff88;
            }
        """)
        chain_layout.addWidget(self.rop_chain_output)
        
        layout.addWidget(chain_group)
        
        return widget
    
    def create_shellcode_tab(self) -> QWidget:
        """Create shellcode generation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Shellcode generator
        gen_group = QGroupBox("Shellcode Generator")
        gen_layout = QFormLayout(gen_group)
        
        # Shellcode type
        self.shellcode_type = QComboBox()
        self.shellcode_type.addItems([
            "execve (/bin/sh)",
            "Reverse Shell",
            "Bind Shell",
            "Download & Execute",
            "Meterpreter Stager"
        ])
        gen_layout.addRow("Type:", self.shellcode_type)
        
        # Target OS
        self.sc_target_os = QComboBox()
        for os_type in TargetOS:
            self.sc_target_os.addItem(os_type.value.title(), os_type)
        gen_layout.addRow("Target OS:", self.sc_target_os)
        
        # Target Arch
        self.sc_target_arch = QComboBox()
        for arch in TargetArch:
            self.sc_target_arch.addItem(arch.value, arch)
        gen_layout.addRow("Architecture:", self.sc_target_arch)
        
        # Options for reverse/bind shell
        self.sc_ip = QLineEdit("127.0.0.1")
        gen_layout.addRow("LHOST:", self.sc_ip)
        
        self.sc_port = QSpinBox()
        self.sc_port.setRange(1, 65535)
        self.sc_port.setValue(4444)
        gen_layout.addRow("LPORT:", self.sc_port)
        
        # Bad characters
        self.bad_chars = QLineEdit("\\x00\\x0a\\x0d")
        gen_layout.addRow("Bad Chars:", self.bad_chars)
        
        # Encoder
        self.encoder = QComboBox()
        self.encoder.addItems(["None", "XOR", "Alphanumeric", "Unicode"])
        gen_layout.addRow("Encoder:", self.encoder)
        
        generate_btn = QPushButton("💉 Generate Shellcode")
        generate_btn.clicked.connect(self.generate_shellcode)
        generate_btn.setStyleSheet("background: #ff00ff; color: #000; font-weight: bold; padding: 10px;")
        gen_layout.addRow("", generate_btn)
        
        layout.addWidget(gen_group)
        
        # Shellcode output
        output_group = QGroupBox("Generated Shellcode")
        output_layout = QVBoxLayout(output_group)
        
        # Format selector
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))
        self.sc_format = QComboBox()
        self.sc_format.addItems(["Python", "C", "Raw Hex", "Base64", "JavaScript"])
        self.sc_format.currentTextChanged.connect(self.format_shellcode)
        format_layout.addWidget(self.sc_format)
        format_layout.addStretch()
        
        copy_btn = QPushButton("📋 Copy")
        copy_btn.clicked.connect(self.copy_shellcode)
        format_layout.addWidget(copy_btn)
        
        output_layout.addLayout(format_layout)
        
        self.shellcode_output = QPlainTextEdit()
        self.shellcode_output.setReadOnly(True)
        self.shellcode_output.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #ff00ff;
            }
        """)
        output_layout.addWidget(self.shellcode_output)
        
        # Stats
        self.sc_stats = QLabel("Size: 0 bytes | Null-free: Unknown")
        self.sc_stats.setStyleSheet("color: #888;")
        output_layout.addWidget(self.sc_stats)
        
        layout.addWidget(output_group)
        
        return widget
    
    def create_exploit_tab(self) -> QWidget:
        """Create exploit development tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Exploit list
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        exploits_group = QGroupBox("Developed Exploits")
        exploits_layout = QVBoxLayout(exploits_group)
        
        self.exploits_list = QListWidget()
        self.exploits_list.itemClicked.connect(self.load_exploit)
        exploits_layout.addWidget(self.exploits_list)
        
        exploit_buttons = QHBoxLayout()
        new_exploit_btn = QPushButton("➕ New")
        new_exploit_btn.clicked.connect(self.new_exploit)
        exploit_buttons.addWidget(new_exploit_btn)
        
        delete_exploit_btn = QPushButton("🗑️")
        delete_exploit_btn.clicked.connect(self.delete_exploit)
        exploit_buttons.addWidget(delete_exploit_btn)
        
        exploits_layout.addLayout(exploit_buttons)
        
        left_layout.addWidget(exploits_group)
        splitter.addWidget(left_panel)
        
        # Right: Exploit editor
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Exploit info
        info_group = QGroupBox("Exploit Information")
        info_layout = QFormLayout(info_group)
        
        self.exploit_name = QLineEdit()
        info_layout.addRow("Name:", self.exploit_name)
        
        self.exploit_stage = QComboBox()
        for stage in ExploitStage:
            self.exploit_stage.addItem(stage.value.replace("_", " ").title(), stage)
        info_layout.addRow("Stage:", self.exploit_stage)
        
        self.exploit_reliability = QSpinBox()
        self.exploit_reliability.setRange(0, 100)
        self.exploit_reliability.setSuffix("%")
        info_layout.addRow("Reliability:", self.exploit_reliability)
        
        right_layout.addWidget(info_group)
        
        # Code editor
        code_group = QGroupBox("Exploit Code")
        code_layout = QVBoxLayout(code_group)
        
        self.exploit_code = QPlainTextEdit()
        self.exploit_code.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                background: #1e1e2e;
                color: #f8f8f2;
            }
        """)
        self.highlighter = PythonHighlighter(self.exploit_code.document())
        code_layout.addWidget(self.exploit_code)
        
        code_buttons = QHBoxLayout()
        save_exploit_btn = QPushButton("💾 Save")
        save_exploit_btn.clicked.connect(self.save_exploit)
        code_buttons.addWidget(save_exploit_btn)
        
        export_btn = QPushButton("📤 Export")
        export_btn.clicked.connect(self.export_exploit)
        code_buttons.addWidget(export_btn)
        
        code_buttons.addStretch()
        code_layout.addLayout(code_buttons)
        
        right_layout.addWidget(code_group)
        splitter.addWidget(right_panel)
        
        splitter.setSizes([300, 700])
        layout.addWidget(splitter)
        
        return widget
    
    def create_test_tab(self) -> QWidget:
        """Create exploit testing tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Test configuration
        config_group = QGroupBox("Test Configuration")
        config_layout = QFormLayout(config_group)
        
        # Select exploit
        self.test_exploit = QComboBox()
        config_layout.addRow("Exploit:", self.test_exploit)
        
        # Target
        self.test_ip = QLineEdit("127.0.0.1")
        config_layout.addRow("Target IP:", self.test_ip)
        
        self.test_port = QSpinBox()
        self.test_port.setRange(1, 65535)
        self.test_port.setValue(9999)
        config_layout.addRow("Target Port:", self.test_port)
        
        test_btn = QPushButton("🧪 Test Exploit")
        test_btn.clicked.connect(self.test_exploit_func)
        test_btn.setStyleSheet("background: #00ff88; color: #000; font-weight: bold; padding: 10px;")
        config_layout.addRow("", test_btn)
        
        layout.addWidget(config_group)
        
        # Test output
        output_group = QGroupBox("Test Results")
        output_layout = QVBoxLayout(output_group)
        
        self.test_output = QPlainTextEdit()
        self.test_output.setReadOnly(True)
        self.test_output.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ff88;
            }
        """)
        output_layout.addWidget(self.test_output)
        
        layout.addWidget(output_group)
        
        # Statistics
        stats_group = QGroupBox("Framework Statistics")
        stats_layout = QHBoxLayout(stats_group)
        
        self.stat_cards = {}
        stat_items = [
            ("Vulnerabilities", "vulns", "#ff0044"),
            ("Zero-Days", "zdays", "#ff6600"),
            ("Exploits", "exploits", "#00ccff"),
            ("Crashes", "crashes", "#ff00ff"),
        ]
        
        for name, key, color in stat_items:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background: linear-gradient(135deg, {color}22, {color}44);
                    border: 2px solid {color};
                    border-radius: 8px;
                    padding: 10px;
                }}
            """)
            card_layout = QVBoxLayout(card)
            
            count_label = QLabel("0")
            count_label.setStyleSheet(f"font-size: 32px; font-weight: bold; color: {color};")
            count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name_label = QLabel(name)
            name_label.setStyleSheet("font-size: 12px; color: #888;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            card_layout.addWidget(count_label)
            card_layout.addWidget(name_label)
            
            self.stat_cards[key] = count_label
            stats_layout.addWidget(card)
        
        layout.addWidget(stats_group)
        
        # Update stats
        self.update_statistics()
        
        return widget
    
    # ========== Event Handlers ==========
    
    def browse_binary(self):
        """Browse for target binary"""
        filepath, _ = QFileDialog.getOpenFileName(self, "Select Binary", "", "All Files (*)")
        if filepath:
            self.binary_path.setText(filepath)
    
    def browse_fuzz_target(self):
        """Browse for fuzz target"""
        filepath, _ = QFileDialog.getOpenFileName(self, "Select Target", "", "All Files (*)")
        if filepath:
            self.fuzz_target.setText(filepath)
    
    def browse_rop_binary(self):
        """Browse for ROP binary"""
        filepath, _ = QFileDialog.getOpenFileName(self, "Select Binary", "", "All Files (*)")
        if filepath:
            self.rop_binary.setText(filepath)
    
    def analyze_binary(self):
        """Analyze a binary for vulnerabilities"""
        binary = self.binary_path.text().strip()
        if not binary:
            QMessageBox.warning(self, "Error", "Enter a binary path")
            return
        
        if not os.path.exists(binary):
            QMessageBox.warning(self, "Error", "Binary not found")
            return
        
        self.status_bar.setText("🔍 Analyzing binary...")
        self.analysis_output.setPlainText("Starting analysis...\n")
        
        vuln_type = self.vuln_type.currentData()
        
        worker = ExploitWorker(self.framework.discover_vulnerability, binary, vuln_type)
        worker.result_ready.connect(self.on_analysis_complete)
        worker.error.connect(self.on_analysis_error)
        worker.start()
        self.workers.append(worker)
    
    def on_analysis_complete(self, vuln):
        """Handle analysis completion"""
        if vuln:
            self.analysis_output.appendPlainText(f"\n✅ Vulnerability discovered!\n")
            self.analysis_output.appendPlainText(f"ID: {vuln.id}")
            self.analysis_output.appendPlainText(f"Type: {vuln.vuln_type.value}")
            self.analysis_output.appendPlainText(f"Zero-Day: {vuln.is_zero_day}")
            
            if vuln.metadata.get("static_findings"):
                self.analysis_output.appendPlainText("\n--- Static Analysis ---")
                findings = vuln.metadata["static_findings"]
                if findings.get("dangerous_functions"):
                    self.analysis_output.appendPlainText(
                        f"Dangerous functions: {', '.join(findings['dangerous_functions'])}"
                    )
                if findings.get("hardening"):
                    self.analysis_output.appendPlainText(f"Hardening: {findings['hardening']}")
            
            # Update table
            self.update_vulns_table()
            self.status_bar.setText(f"✅ Analysis complete - Vulnerability found!")
        else:
            self.analysis_output.appendPlainText("\n❌ No vulnerabilities discovered")
            self.status_bar.setText("Analysis complete - No vulnerabilities found")
    
    def on_analysis_error(self, error):
        """Handle analysis error"""
        self.analysis_output.appendPlainText(f"\n❌ Error: {error}")
        self.status_bar.setText(f"❌ Analysis error: {error}")
    
    def update_vulns_table(self):
        """Update vulnerabilities table"""
        self.vulns_table.setRowCount(0)
        for vuln in self.framework.vulnerabilities.values():
            row = self.vulns_table.rowCount()
            self.vulns_table.insertRow(row)
            self.vulns_table.setItem(row, 0, QTableWidgetItem(vuln.id[:8]))
            self.vulns_table.setItem(row, 1, QTableWidgetItem(vuln.name))
            self.vulns_table.setItem(row, 2, QTableWidgetItem(vuln.vuln_type.value))
            self.vulns_table.setItem(row, 3, QTableWidgetItem(str(vuln.cvss_score)))
            
            zday = QTableWidgetItem("✅" if vuln.is_zero_day else "❌")
            self.vulns_table.setItem(row, 4, zday)
    
    def start_fuzzing(self):
        """Start fuzzing session"""
        target = self.fuzz_target.text().strip()
        if not target or not os.path.exists(target):
            QMessageBox.warning(self, "Error", "Invalid target")
            return
        
        self.status_bar.setText("🎯 Fuzzing in progress...")
        self.fuzz_progress.setValue(0)
        
        # Build mutation list
        mutations = []
        if self.mutation_bitflip.isChecked():
            mutations.append("bitflip")
        if self.mutation_insert.isChecked():
            mutations.append("insert")
        if self.mutation_remove.isChecked():
            mutations.append("remove")
        if self.mutation_havoc.isChecked():
            mutations.append("havoc")
        
        seed = self.seed_input.text().encode() if self.seed_input.text() else b""
        generator = self.framework.create_fuzzer_generator(seed, mutations)
        
        iterations = self.fuzz_iterations.value()
        timeout = self.fuzz_timeout.value()
        
        worker = ExploitWorker(
            self.framework.fuzz_target,
            target, generator, iterations, timeout
        )
        worker.result_ready.connect(self.on_fuzzing_complete)
        worker.error.connect(self.on_fuzzing_error)
        worker.start()
        self.workers.append(worker)
    
    def on_fuzzing_complete(self, results):
        """Handle fuzzing completion"""
        self.fuzz_progress.setValue(100)
        self.crashes_table.setRowCount(0)
        
        for result in results:
            row = self.crashes_table.rowCount()
            self.crashes_table.insertRow(row)
            self.crashes_table.setItem(row, 0, QTableWidgetItem(result.id[:8]))
            self.crashes_table.setItem(row, 1, QTableWidgetItem(result.crash_type))
            self.crashes_table.setItem(row, 2, QTableWidgetItem("✅" if result.exploitable else "❌"))
            self.crashes_table.setItem(row, 3, QTableWidgetItem(f"{result.exploitability_score:.1%}"))
            self.crashes_table.setItem(row, 4, QTableWidgetItem(str(len(result.crash_input))))
        
        exploitable = sum(1 for r in results if r.exploitable)
        self.fuzz_stats.setText(f"Crashes: {len(results)} | Exploitable: {exploitable}")
        self.status_bar.setText(f"✅ Fuzzing complete - {len(results)} crashes found")
        self.update_statistics()
    
    def on_fuzzing_error(self, error):
        """Handle fuzzing error"""
        self.status_bar.setText(f"❌ Fuzzing error: {error}")
    
    def show_crash_details(self, item):
        """Show crash details"""
        row = item.row()
        crash_id = self.crashes_table.item(row, 0).text()
        
        for result in self.framework.fuzzing_results:
            if result.id.startswith(crash_id):
                details = f"""
Crash ID: {result.id}
Type: {result.crash_type}
Target: {result.target}
Exploitable: {result.exploitable}
Score: {result.exploitability_score:.1%}
Input Size: {len(result.crash_input)} bytes
Input (hex): {result.crash_input[:100].hex()}...
"""
                QMessageBox.information(self, "Crash Details", details)
                break
    
    def find_gadgets(self):
        """Find ROP gadgets"""
        binary = self.rop_binary.text().strip()
        if not binary or not os.path.exists(binary):
            QMessageBox.warning(self, "Error", "Invalid binary")
            return
        
        self.status_bar.setText("⛓️ Finding gadgets...")
        
        worker = ExploitWorker(self.framework.find_gadgets, binary)
        worker.result_ready.connect(self.on_gadgets_found)
        worker.error.connect(lambda e: self.status_bar.setText(f"❌ Error: {e}"))
        worker.start()
        self.workers.append(worker)
    
    def on_gadgets_found(self, gadgets):
        """Handle gadget discovery"""
        self.gadgets_table.setRowCount(0)
        
        for gadget in gadgets:
            row = self.gadgets_table.rowCount()
            self.gadgets_table.insertRow(row)
            self.gadgets_table.setItem(row, 0, QTableWidgetItem(f"0x{gadget.address:08x}"))
            self.gadgets_table.setItem(row, 1, QTableWidgetItem(gadget.gadget_type))
            self.gadgets_table.setItem(row, 2, QTableWidgetItem("; ".join(gadget.instructions)))
            self.gadgets_table.setItem(row, 3, QTableWidgetItem(gadget.raw_bytes.hex()))
        
        self.status_bar.setText(f"✅ Found {len(gadgets)} gadgets")
    
    def build_rop_chain(self):
        """Build ROP chain"""
        binary = self.rop_binary.text().strip()
        if binary not in self.framework.gadget_cache:
            QMessageBox.warning(self, "Error", "Find gadgets first")
            return
        
        try:
            target = int(self.chain_target.text(), 16)
            args_str = self.chain_args.text().strip()
            args = []
            if args_str:
                for arg in args_str.split(","):
                    args.append(int(arg.strip(), 16))
            
            gadgets = self.framework.gadget_cache[binary]
            chain = self.framework.build_rop_chain(gadgets, target, args)
            
            output = "ROP Chain:\n"
            output += "-" * 40 + "\n"
            for i in range(0, len(chain), 8):
                addr = int.from_bytes(chain[i:i+8], 'little')
                output += f"0x{addr:016x}\n"
            
            output += f"\nTotal size: {len(chain)} bytes\n"
            output += f"Python: {repr(chain)}"
            
            self.rop_chain_output.setPlainText(output)
            
        except ValueError as e:
            QMessageBox.warning(self, "Error", f"Invalid input: {e}")
    
    def generate_shellcode(self):
        """Generate shellcode"""
        sc_type_map = {
            "execve (/bin/sh)": "execve",
            "Reverse Shell": "reverse_shell",
            "Bind Shell": "bind_shell",
            "Download & Execute": "download_exec",
            "Meterpreter Stager": "meterpreter"
        }
        
        sc_type = sc_type_map.get(self.shellcode_type.currentText(), "execve")
        target_os = self.sc_target_os.currentData()
        target_arch = self.sc_target_arch.currentData()
        
        shellcode = self.framework.generate_shellcode(
            sc_type, target_os, target_arch,
            ip=self.sc_ip.text(),
            port=self.sc_port.value()
        )
        
        # Encode if selected
        encoder = self.encoder.currentText().lower()
        if encoder != "none" and shellcode:
            decoder, shellcode = self.framework.encode_shellcode(shellcode, encoder)
            if decoder:
                shellcode = decoder + shellcode
        
        self.current_shellcode = shellcode
        self.format_shellcode()
        
        null_free = b"\x00" not in shellcode
        self.sc_stats.setText(f"Size: {len(shellcode)} bytes | Null-free: {'✅' if null_free else '❌'}")
    
    def format_shellcode(self):
        """Format shellcode for display"""
        if not hasattr(self, 'current_shellcode') or not self.current_shellcode:
            return
        
        shellcode = self.current_shellcode
        fmt = self.sc_format.currentText()
        
        if fmt == "Python":
            output = 'shellcode = b"'
            for i, b in enumerate(shellcode):
                output += f"\\x{b:02x}"
                if (i + 1) % 16 == 0 and i < len(shellcode) - 1:
                    output += '"\nshellcode += b"'
            output += '"'
        
        elif fmt == "C":
            output = 'unsigned char shellcode[] = \n"'
            for i, b in enumerate(shellcode):
                output += f"\\x{b:02x}"
                if (i + 1) % 16 == 0 and i < len(shellcode) - 1:
                    output += '"\n"'
            output += '";'
        
        elif fmt == "Raw Hex":
            output = shellcode.hex()
        
        elif fmt == "Base64":
            import base64
            output = base64.b64encode(shellcode).decode()
        
        elif fmt == "JavaScript":
            output = "var shellcode = unescape('"
            for b in shellcode:
                output += f"%u{b:02x}"
            output += "');"
        
        else:
            output = repr(shellcode)
        
        self.shellcode_output.setPlainText(output)
    
    def copy_shellcode(self):
        """Copy shellcode to clipboard"""
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.shellcode_output.toPlainText())
        self.status_bar.setText("Shellcode copied to clipboard")
    
    def new_exploit(self):
        """Create new exploit"""
        # Check if there are vulnerabilities
        if not self.framework.vulnerabilities:
            QMessageBox.warning(self, "Error", "Discover a vulnerability first")
            return
        
        # Create exploit for first vulnerability
        vuln = list(self.framework.vulnerabilities.values())[0]
        
        worker = ExploitWorker(self.framework.develop_exploit, vuln)
        worker.result_ready.connect(self.on_exploit_created)
        worker.error.connect(lambda e: self.status_bar.setText(f"❌ Error: {e}"))
        worker.start()
        self.workers.append(worker)
    
    def on_exploit_created(self, exploit):
        """Handle exploit creation"""
        self.exploits_list.addItem(f"{exploit.name} ({exploit.id[:8]})")
        self.test_exploit.addItem(exploit.name, exploit.id)
        self.update_statistics()
        self.status_bar.setText(f"✅ Exploit created: {exploit.name}")
    
    def load_exploit(self, item):
        """Load exploit into editor"""
        text = item.text()
        exploit_id = text.split("(")[-1].rstrip(")")
        
        for exp in self.framework.exploits.values():
            if exp.id.startswith(exploit_id):
                self.exploit_name.setText(exp.name)
                self.exploit_stage.setCurrentIndex(
                    list(ExploitStage).index(exp.stage)
                )
                self.exploit_reliability.setValue(int(exp.reliability))
                self.exploit_code.setPlainText(exp.exploit_code)
                break
    
    def save_exploit(self):
        """Save current exploit"""
        self.status_bar.setText("💾 Exploit saved")
    
    def delete_exploit(self):
        """Delete selected exploit"""
        current = self.exploits_list.currentItem()
        if current:
            self.exploits_list.takeItem(self.exploits_list.row(current))
            self.status_bar.setText("🗑️ Exploit deleted")
    
    def export_exploit(self):
        """Export exploit"""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Exploit", "exploit.py",
            "Python Files (*.py);;Ruby Files (*.rb);;JSON (*.json)"
        )
        
        if filepath:
            code = self.exploit_code.toPlainText()
            with open(filepath, 'w') as f:
                f.write(code)
            self.status_bar.setText(f"📤 Exported to {filepath}")
    
    def test_exploit_func(self):
        """Test exploit against target"""
        exploit_id = self.test_exploit.currentData()
        if not exploit_id or exploit_id not in self.framework.exploits:
            QMessageBox.warning(self, "Error", "Select an exploit")
            return
        
        exploit = self.framework.exploits[exploit_id]
        target_ip = self.test_ip.text()
        target_port = self.test_port.value()
        
        self.test_output.setPlainText(f"Testing {exploit.name} against {target_ip}:{target_port}...\n")
        self.status_bar.setText("🧪 Testing exploit...")
        
        worker = ExploitWorker(
            self.framework.test_exploit,
            exploit, target_ip, target_port
        )
        worker.result_ready.connect(self.on_test_complete)
        worker.error.connect(lambda e: self.test_output.appendPlainText(f"❌ Error: {e}"))
        worker.start()
        self.workers.append(worker)
    
    def on_test_complete(self, result):
        """Handle test completion"""
        if result["success"]:
            self.test_output.appendPlainText("✅ Exploit executed successfully!")
        else:
            self.test_output.appendPlainText("❌ Exploit failed")
        
        if result.get("output"):
            self.test_output.appendPlainText(f"\nOutput:\n{result['output']}")
        if result.get("error"):
            self.test_output.appendPlainText(f"\nError: {result['error']}")
        
        self.status_bar.setText("🧪 Test complete")
    
    def update_statistics(self):
        """Update statistics cards"""
        stats = self.framework.get_statistics()
        
        if "vulns" in self.stat_cards:
            self.stat_cards["vulns"].setText(str(stats.get("total_vulnerabilities", 0)))
        if "zdays" in self.stat_cards:
            self.stat_cards["zdays"].setText(str(stats.get("zero_days", 0)))
        if "exploits" in self.stat_cards:
            self.stat_cards["exploits"].setText(str(stats.get("total_exploits", 0)))
        if "crashes" in self.stat_cards:
            self.stat_cards["crashes"].setText(str(stats.get("fuzzing_crashes", 0)))
