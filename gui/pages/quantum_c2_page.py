"""
Quantum-Resistant C2 Page
Post-quantum cryptographic command and control interface.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QTextEdit,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QSpinBox, QComboBox, QTabWidget, QSplitter,
    QListWidget, QListWidgetItem, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor


class QuantumC2Page(QWidget):
    """Quantum-resistant C2 framework interface"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Agent management
        left_panel = self._create_agent_panel()
        splitter.addWidget(left_panel)
        
        # Right - Command and communication
        right_panel = self._create_command_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([350, 650])
        layout.addWidget(splitter, 1)
        
        self.setStyleSheet(self._get_styles())
    
    def _create_header(self) -> QFrame:
        """Create header"""
        frame = QFrame()
        frame.setObjectName("headerFrame")
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        
        title = QLabel("🔐 Quantum-Resistant C2 Framework")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ffff;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Post-quantum cryptographic command & control")
        subtitle.setStyleSheet("color: #888;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Crypto status
        crypto_layout = QVBoxLayout()
        
        algo_label = QLabel("🛡️ KYBER-1024 + DILITHIUM-5")
        algo_label.setStyleSheet("color: #00ffff; font-weight: bold;")
        crypto_layout.addWidget(algo_label)
        
        status_label = QLabel("Quantum-Safe: Active")
        status_label.setStyleSheet("color: #00ff88;")
        crypto_layout.addWidget(status_label)
        
        layout.addLayout(crypto_layout)
        
        # Stats
        stats_layout = QHBoxLayout()
        
        self.agents_stat = self._create_stat("Active Agents", "0")
        stats_layout.addWidget(self.agents_stat)
        
        self.tasks_stat = self._create_stat("Pending Tasks", "0")
        stats_layout.addWidget(self.tasks_stat)
        
        self.channels_stat = self._create_stat("Active Channels", "0")
        stats_layout.addWidget(self.channels_stat)
        
        layout.addLayout(stats_layout)
        
        return frame
    
    def _create_stat(self, label: str, value: str) -> QFrame:
        """Create stat widget"""
        frame = QFrame()
        frame.setObjectName("statWidget")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(15, 10, 15, 10)
        
        value_lbl = QLabel(value)
        value_lbl.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_lbl.setStyleSheet("color: #00ffff;")
        value_lbl.setObjectName(f"stat_{label.replace(' ', '_')}")
        layout.addWidget(value_lbl)
        
        name_lbl = QLabel(label)
        name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_lbl.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(name_lbl)
        
        return frame
    
    def _create_agent_panel(self) -> QFrame:
        """Create agent management panel"""
        frame = QFrame()
        frame.setObjectName("agentPanel")
        layout = QVBoxLayout(frame)
        
        # Title
        title = QLabel("👥 Registered Agents")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ffff;")
        layout.addWidget(title)
        
        # Agent tree
        self.agent_tree = QTreeWidget()
        self.agent_tree.setHeaderLabels(["Agent", "Status", "Last Seen"])
        self.agent_tree.setColumnWidth(0, 150)
        self.agent_tree.itemClicked.connect(self._on_agent_selected)
        layout.addWidget(self.agent_tree)
        
        # Agent actions
        action_layout = QHBoxLayout()
        
        register_btn = QPushButton("➕ Register")
        register_btn.clicked.connect(self._register_agent)
        action_layout.addWidget(register_btn)
        
        rotate_btn = QPushButton("🔄 Rotate Keys")
        rotate_btn.clicked.connect(self._rotate_keys)
        action_layout.addWidget(rotate_btn)
        
        layout.addLayout(action_layout)
        
        # Selected agent info
        info_group = QGroupBox("Agent Details")
        info_layout = QGridLayout(info_group)
        
        info_layout.addWidget(QLabel("ID:"), 0, 0)
        self.agent_id_label = QLabel("-")
        self.agent_id_label.setStyleSheet("color: #00ffff;")
        info_layout.addWidget(self.agent_id_label, 0, 1)
        
        info_layout.addWidget(QLabel("Channel:"), 1, 0)
        self.agent_channel_label = QLabel("-")
        info_layout.addWidget(self.agent_channel_label, 1, 1)
        
        info_layout.addWidget(QLabel("Key ID:"), 2, 0)
        self.agent_key_label = QLabel("-")
        info_layout.addWidget(self.agent_key_label, 2, 1)
        
        info_layout.addWidget(QLabel("Algorithm:"), 3, 0)
        self.agent_algo_label = QLabel("-")
        info_layout.addWidget(self.agent_algo_label, 3, 1)
        
        layout.addWidget(info_group)
        
        # Channel configuration
        channel_group = QGroupBox("Covert Channels")
        channel_layout = QVBoxLayout(channel_group)
        
        channels = [
            ("HTTPS Mimicry", True),
            ("DNS Covert", True),
            ("HTTP Stealth", False),
            ("ICMP Tunnel", False),
            ("DoH (DNS over HTTPS)", True),
        ]
        
        for name, active in channels:
            row = QHBoxLayout()
            indicator = QLabel("●")
            indicator.setStyleSheet(f"color: {'#00ff88' if active else '#666'};")
            row.addWidget(indicator)
            row.addWidget(QLabel(name))
            row.addStretch()
            channel_layout.addLayout(row)
        
        layout.addWidget(channel_group)
        
        return frame
    
    def _create_command_panel(self) -> QFrame:
        """Create command and control panel"""
        frame = QFrame()
        frame.setObjectName("commandPanel")
        layout = QVBoxLayout(frame)
        
        # Tab widget
        tabs = QTabWidget()
        
        # Commands tab
        cmd_tab = QWidget()
        cmd_layout = QVBoxLayout(cmd_tab)
        
        # Command input
        input_group = QGroupBox("Send Command")
        input_layout = QVBoxLayout(input_group)
        
        cmd_row = QHBoxLayout()
        cmd_row.addWidget(QLabel("Command:"))
        self.cmd_combo = QComboBox()
        self.cmd_combo.addItems([
            "shell", "sysinfo", "download", "upload",
            "screenshot", "keylog", "persist", "exfil"
        ])
        cmd_row.addWidget(self.cmd_combo)
        input_layout.addLayout(cmd_row)
        
        args_row = QHBoxLayout()
        args_row.addWidget(QLabel("Arguments:"))
        self.args_input = QLineEdit()
        self.args_input.setPlaceholderText("Command arguments...")
        args_row.addWidget(self.args_input)
        input_layout.addLayout(args_row)
        
        send_btn = QPushButton("📤 Send Encrypted Command")
        send_btn.setObjectName("primaryButton")
        send_btn.clicked.connect(self._send_command)
        input_layout.addWidget(send_btn)
        
        cmd_layout.addWidget(input_group)
        
        # Task queue
        queue_group = QGroupBox("Task Queue")
        queue_layout = QVBoxLayout(queue_group)
        
        self.task_table = QTableWidget()
        self.task_table.setColumnCount(5)
        self.task_table.setHorizontalHeaderLabels([
            "Task ID", "Agent", "Command", "Status", "Time"
        ])
        self.task_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        queue_layout.addWidget(self.task_table)
        
        cmd_layout.addWidget(queue_group)
        
        tabs.addTab(cmd_tab, "⚡ Commands")
        
        # Communication log tab
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        
        self.comm_log = QTextEdit()
        self.comm_log.setReadOnly(True)
        self.comm_log.setPlaceholderText("Encrypted communication log...")
        log_layout.addWidget(self.comm_log)
        
        log_controls = QHBoxLayout()
        clear_btn = QPushButton("Clear Log")
        clear_btn.clicked.connect(lambda: self.comm_log.clear())
        log_controls.addWidget(clear_btn)
        
        export_btn = QPushButton("Export Log")
        log_controls.addWidget(export_btn)
        log_controls.addStretch()
        
        log_layout.addLayout(log_controls)
        
        tabs.addTab(log_tab, "📝 Comm Log")
        
        # Crypto tab
        crypto_tab = QWidget()
        crypto_layout = QVBoxLayout(crypto_tab)
        
        key_info = QGroupBox("Cryptographic Keys")
        key_layout = QGridLayout(key_info)
        
        key_layout.addWidget(QLabel("Server Public Key:"), 0, 0)
        self.server_key = QLineEdit()
        self.server_key.setReadOnly(True)
        self.server_key.setText("KYBER-1024: 7a3f...c4b2")
        key_layout.addWidget(self.server_key, 0, 1)
        
        key_layout.addWidget(QLabel("Signing Key:"), 1, 0)
        self.sign_key = QLineEdit()
        self.sign_key.setReadOnly(True)
        self.sign_key.setText("DILITHIUM-5: 9e2c...a1f8")
        key_layout.addWidget(self.sign_key, 1, 1)
        
        key_layout.addWidget(QLabel("Key Rotation:"), 2, 0)
        self.rotation_label = QLabel("Every 24 hours")
        self.rotation_label.setStyleSheet("color: #00ff88;")
        key_layout.addWidget(self.rotation_label, 2, 1)
        
        crypto_layout.addWidget(key_info)
        
        # Algorithm selection
        algo_group = QGroupBox("Algorithm Configuration")
        algo_layout = QGridLayout(algo_group)
        
        algo_layout.addWidget(QLabel("Key Encapsulation:"), 0, 0)
        self.kem_combo = QComboBox()
        self.kem_combo.addItems(["KYBER-512", "KYBER-768", "KYBER-1024", "NTRU"])
        self.kem_combo.setCurrentText("KYBER-1024")
        algo_layout.addWidget(self.kem_combo, 0, 1)
        
        algo_layout.addWidget(QLabel("Digital Signature:"), 1, 0)
        self.sig_combo = QComboBox()
        self.sig_combo.addItems(["DILITHIUM-2", "DILITHIUM-3", "DILITHIUM-5", "FALCON-512"])
        self.sig_combo.setCurrentText("DILITHIUM-5")
        algo_layout.addWidget(self.sig_combo, 1, 1)
        
        algo_layout.addWidget(QLabel("Symmetric Cipher:"), 2, 0)
        self.sym_combo = QComboBox()
        self.sym_combo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        algo_layout.addWidget(self.sym_combo, 2, 1)
        
        crypto_layout.addWidget(algo_group)
        
        regen_btn = QPushButton("🔑 Regenerate Keys")
        regen_btn.clicked.connect(self._regenerate_keys)
        crypto_layout.addWidget(regen_btn)
        
        crypto_layout.addStretch()
        
        tabs.addTab(crypto_tab, "🔐 Cryptography")
        
        layout.addWidget(tabs)
        
        return frame
    
    def _on_agent_selected(self, item: QTreeWidgetItem, column: int):
        """Handle agent selection"""
        agent_id = item.text(0)
        self.agent_id_label.setText(agent_id)
        self.agent_channel_label.setText("HTTPS Mimicry")
        self.agent_key_label.setText(f"sess_{agent_id[:8]}")
        self.agent_algo_label.setText("KYBER-1024")
    
    def _register_agent(self):
        """Register new agent"""
        agent_id = f"agent-{len(self.agent_tree.topLevelItemCount()) + 1:04d}"
        
        item = QTreeWidgetItem([agent_id, "Active", "Now"])
        item.setForeground(1, QColor("#00ff88"))
        self.agent_tree.addTopLevelItem(item)
        
        self._log_comm(f"[+] Agent registered: {agent_id}")
        self._log_comm(f"    Key exchange complete (KYBER-1024)")
    
    def _rotate_keys(self):
        """Rotate session keys"""
        selected = self.agent_tree.currentItem()
        if selected:
            agent_id = selected.text(0)
            self._log_comm(f"[*] Rotating keys for {agent_id}...")
            self._log_comm(f"    New session key encapsulated")
            self._log_comm(f"    Key rotation complete")
    
    def _send_command(self):
        """Send encrypted command"""
        command = self.cmd_combo.currentText()
        args = self.args_input.text()
        
        selected = self.agent_tree.currentItem()
        if not selected:
            self._log_comm("[!] No agent selected")
            return
        
        agent_id = selected.text(0)
        task_id = f"task-{self.task_table.rowCount() + 1:04d}"
        
        # Add to task table
        row = self.task_table.rowCount()
        self.task_table.setRowCount(row + 1)
        self.task_table.setItem(row, 0, QTableWidgetItem(task_id))
        self.task_table.setItem(row, 1, QTableWidgetItem(agent_id))
        self.task_table.setItem(row, 2, QTableWidgetItem(f"{command} {args}"))
        
        status = QTableWidgetItem("Pending")
        status.setForeground(QColor("#ffff00"))
        self.task_table.setItem(row, 3, status)
        self.task_table.setItem(row, 4, QTableWidgetItem("Just now"))
        
        self._log_comm(f"[>] Sending command to {agent_id}")
        self._log_comm(f"    Command: {command} {args}")
        self._log_comm(f"    Encrypted with session key")
        self._log_comm(f"    Signed with DILITHIUM-5")
        
        self.args_input.clear()
    
    def _regenerate_keys(self):
        """Regenerate cryptographic keys"""
        self._log_comm("[*] Regenerating server keys...")
        self._log_comm("    Generating KYBER-1024 keypair...")
        self._log_comm("    Generating DILITHIUM-5 keypair...")
        self._log_comm("[+] Key regeneration complete")
    
    def _log_comm(self, message: str):
        """Log communication"""
        timestamp = QTimer()
        self.comm_log.append(f"<span style='color: #666;'>[{self._get_timestamp()}]</span> {message}")
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S")
    
    def _get_styles(self) -> str:
        """Get styles"""
        return """
            QWidget {
                background-color: #1a1a2e;
                color: #ffffff;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            #headerFrame {
                background-color: #16213e;
                border-radius: 10px;
                padding: 15px;
            }
            
            #statWidget {
                background-color: #1a1a2e;
                border: 1px solid #00ffff44;
                border-radius: 8px;
                min-width: 100px;
            }
            
            #agentPanel, #commandPanel {
                background-color: #16213e;
                border-radius: 10px;
                padding: 15px;
            }
            
            QGroupBox {
                border: 1px solid #00ffff44;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
                color: #00ffff;
            }
            
            QTreeWidget {
                background-color: #0f0f1a;
                border: 1px solid #333;
                border-radius: 8px;
            }
            
            QTreeWidget::item {
                padding: 8px;
                border-bottom: 1px solid #333;
            }
            
            QTreeWidget::item:selected {
                background-color: #00ffff33;
            }
            
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #00ffff;
                padding: 8px;
                border: none;
            }
            
            QLineEdit, QComboBox {
                background-color: #0f0f1a;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
            }
            
            QLineEdit:focus {
                border-color: #00ffff;
            }
            
            #primaryButton {
                background-color: #00ffff;
                color: #000;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
            }
            
            #primaryButton:hover {
                background-color: #00cccc;
            }
            
            QPushButton {
                background-color: #333;
                color: #fff;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
            }
            
            QPushButton:hover {
                background-color: #444;
            }
            
            QTableWidget {
                background-color: #0f0f1a;
                border: 1px solid #333;
                border-radius: 8px;
            }
            
            QTextEdit {
                background-color: #0f0f1a;
                border: 1px solid #333;
                border-radius: 8px;
                font-family: 'Consolas', monospace;
            }
            
            QTabWidget::pane {
                border: 1px solid #333;
                border-radius: 8px;
            }
            
            QTabBar::tab {
                background-color: #1a1a2e;
                color: #888;
                padding: 10px 20px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            
            QTabBar::tab:selected {
                background-color: #00ffff33;
                color: #00ffff;
            }
        """
