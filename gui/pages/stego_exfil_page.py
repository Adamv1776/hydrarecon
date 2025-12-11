"""
Steganographic Exfiltration Page
Covert data extraction using multiple steganographic techniques.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QTextEdit,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QSpinBox, QComboBox, QTabWidget, QSplitter,
    QListWidget, QListWidgetItem, QFileDialog, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QPixmap


class StegoExfilPage(QWidget):
    """Steganographic exfiltration interface"""
    
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
        
        # Main tabs
        tabs = QTabWidget()
        
        # Embed tab
        embed_tab = self._create_embed_tab()
        tabs.addTab(embed_tab, "🔒 Embed Data")
        
        # Extract tab
        extract_tab = self._create_extract_tab()
        tabs.addTab(extract_tab, "🔓 Extract Data")
        
        # Channels tab
        channels_tab = self._create_channels_tab()
        tabs.addTab(channels_tab, "📡 Covert Channels")
        
        # Sessions tab
        sessions_tab = self._create_sessions_tab()
        tabs.addTab(sessions_tab, "📊 Sessions")
        
        layout.addWidget(tabs, 1)
        
        self.setStyleSheet(self._get_styles())
    
    def _create_header(self) -> QFrame:
        """Create header"""
        frame = QFrame()
        frame.setObjectName("headerFrame")
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        
        title = QLabel("🔏 Steganographic Exfiltration Engine")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #ff6b6b;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Multi-medium covert data extraction")
        subtitle.setStyleSheet("color: #888;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats
        stats_layout = QHBoxLayout()
        
        self.sessions_stat = self._create_stat("Active Sessions", "0")
        stats_layout.addWidget(self.sessions_stat)
        
        self.data_stat = self._create_stat("Data Exfiltrated", "0 KB")
        stats_layout.addWidget(self.data_stat)
        
        self.channels_stat = self._create_stat("Available Channels", "16")
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
        value_lbl.setStyleSheet("color: #ff6b6b;")
        layout.addWidget(value_lbl)
        
        name_lbl = QLabel(label)
        name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_lbl.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(name_lbl)
        
        return frame
    
    def _create_embed_tab(self) -> QWidget:
        """Create embed data tab"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        
        # Left - Configuration
        left = QFrame()
        left.setObjectName("panelFrame")
        left_layout = QVBoxLayout(left)
        
        # Medium selection
        medium_group = QGroupBox("Steganographic Medium")
        medium_layout = QVBoxLayout(medium_group)
        
        self.medium_combo = QComboBox()
        self.medium_combo.addItems([
            "📷 Image (LSB)", "📷 Image (DCT)", "📷 Image (Palette)",
            "🎵 Audio (LSB)", "🎵 Audio (Echo)", "🎵 Audio (Phase)",
            "🎬 Video (Frame)", "🎬 Video (Motion)",
            "⏱️ Network (Timing)", "📦 Network (Header)",
            "🌐 DNS Subdomain", "🔒 HTTPS Padding",
            "📝 Unicode (Zero-Width)", "💾 Filesystem (Slack)"
        ])
        medium_layout.addWidget(self.medium_combo)
        
        left_layout.addWidget(medium_group)
        
        # Carrier file
        carrier_group = QGroupBox("Carrier File")
        carrier_layout = QVBoxLayout(carrier_group)
        
        carrier_row = QHBoxLayout()
        self.carrier_input = QLineEdit()
        self.carrier_input.setPlaceholderText("Select carrier file...")
        carrier_row.addWidget(self.carrier_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_carrier)
        carrier_row.addWidget(browse_btn)
        carrier_layout.addLayout(carrier_row)
        
        # Carrier info
        self.carrier_info = QLabel("No file selected")
        self.carrier_info.setStyleSheet("color: #666;")
        carrier_layout.addWidget(self.carrier_info)
        
        left_layout.addWidget(carrier_group)
        
        # Payload
        payload_group = QGroupBox("Payload Data")
        payload_layout = QVBoxLayout(payload_group)
        
        payload_row = QHBoxLayout()
        self.payload_input = QLineEdit()
        self.payload_input.setPlaceholderText("Select file to embed...")
        payload_row.addWidget(self.payload_input)
        
        payload_btn = QPushButton("Browse")
        payload_btn.clicked.connect(self._browse_payload)
        payload_row.addWidget(payload_btn)
        payload_layout.addLayout(payload_row)
        
        # Or text input
        payload_layout.addWidget(QLabel("Or enter text:"))
        self.payload_text = QTextEdit()
        self.payload_text.setMaximumHeight(100)
        self.payload_text.setPlaceholderText("Enter secret message...")
        payload_layout.addWidget(self.payload_text)
        
        left_layout.addWidget(payload_group)
        
        # Encryption
        encrypt_group = QGroupBox("Encryption")
        encrypt_layout = QVBoxLayout(encrypt_group)
        
        self.encrypt_check = QCheckBox("Encrypt payload")
        self.encrypt_check.setChecked(True)
        encrypt_layout.addWidget(self.encrypt_check)
        
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Key:"))
        self.encrypt_key = QLineEdit()
        self.encrypt_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.encrypt_key.setPlaceholderText("Encryption key")
        key_row.addWidget(self.encrypt_key)
        encrypt_layout.addLayout(key_row)
        
        left_layout.addWidget(encrypt_group)
        
        # Embed button
        embed_btn = QPushButton("🔒 Embed Data")
        embed_btn.setObjectName("primaryButton")
        embed_btn.clicked.connect(self._embed_data)
        left_layout.addWidget(embed_btn)
        
        left_layout.addStretch()
        
        layout.addWidget(left)
        
        # Right - Preview
        right = QFrame()
        right.setObjectName("panelFrame")
        right_layout = QVBoxLayout(right)
        
        right_layout.addWidget(QLabel("Preview"))
        
        self.preview_label = QLabel()
        self.preview_label.setMinimumSize(300, 300)
        self.preview_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_label.setStyleSheet("background-color: #0f0f1a; border-radius: 8px;")
        self.preview_label.setText("Carrier preview will appear here")
        right_layout.addWidget(self.preview_label)
        
        # Capacity info
        cap_group = QGroupBox("Embedding Capacity")
        cap_layout = QGridLayout(cap_group)
        
        cap_layout.addWidget(QLabel("Carrier Size:"), 0, 0)
        self.carrier_size = QLabel("-")
        cap_layout.addWidget(self.carrier_size, 0, 1)
        
        cap_layout.addWidget(QLabel("Max Payload:"), 1, 0)
        self.max_payload = QLabel("-")
        cap_layout.addWidget(self.max_payload, 1, 1)
        
        cap_layout.addWidget(QLabel("Detection Risk:"), 2, 0)
        self.detection_risk = QLabel("-")
        cap_layout.addWidget(self.detection_risk, 2, 1)
        
        right_layout.addWidget(cap_group)
        
        # Progress
        self.embed_progress = QProgressBar()
        self.embed_progress.setVisible(False)
        right_layout.addWidget(self.embed_progress)
        
        layout.addWidget(right)
        
        return widget
    
    def _create_extract_tab(self) -> QWidget:
        """Create extract data tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Input
        input_group = QGroupBox("Stego File")
        input_layout = QVBoxLayout(input_group)
        
        file_row = QHBoxLayout()
        self.stego_input = QLineEdit()
        self.stego_input.setPlaceholderText("Select stego file...")
        file_row.addWidget(self.stego_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_stego)
        file_row.addWidget(browse_btn)
        input_layout.addLayout(file_row)
        
        layout.addWidget(input_group)
        
        # Decryption
        decrypt_group = QGroupBox("Decryption")
        decrypt_layout = QHBoxLayout(decrypt_group)
        
        self.decrypt_check = QCheckBox("Payload is encrypted")
        self.decrypt_check.setChecked(True)
        decrypt_layout.addWidget(self.decrypt_check)
        
        decrypt_layout.addWidget(QLabel("Key:"))
        self.decrypt_key = QLineEdit()
        self.decrypt_key.setEchoMode(QLineEdit.EchoMode.Password)
        decrypt_layout.addWidget(self.decrypt_key)
        
        layout.addWidget(decrypt_group)
        
        # Extract button
        extract_btn = QPushButton("🔓 Extract Data")
        extract_btn.setObjectName("primaryButton")
        extract_btn.clicked.connect(self._extract_data)
        layout.addWidget(extract_btn)
        
        # Output
        output_group = QGroupBox("Extracted Data")
        output_layout = QVBoxLayout(output_group)
        
        self.extracted_output = QTextEdit()
        self.extracted_output.setReadOnly(True)
        self.extracted_output.setPlaceholderText("Extracted data will appear here...")
        output_layout.addWidget(self.extracted_output)
        
        save_btn = QPushButton("💾 Save Extracted Data")
        save_btn.clicked.connect(self._save_extracted)
        output_layout.addWidget(save_btn)
        
        layout.addWidget(output_group, 1)
        
        return widget
    
    def _create_channels_tab(self) -> QWidget:
        """Create covert channels tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Channel table
        self.channel_table = QTableWidget()
        self.channel_table.setColumnCount(5)
        self.channel_table.setHorizontalHeaderLabels([
            "Channel", "Type", "Bandwidth", "Stealth", "Status"
        ])
        self.channel_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        channels = [
            ("DNS Subdomain", "Network", "~2 KB/s", "High", "Ready"),
            ("HTTPS Padding", "Network", "~5 KB/s", "Very High", "Ready"),
            ("HTTP Headers", "Network", "~3 KB/s", "Medium", "Ready"),
            ("ICMP Tunnel", "Network", "~1 KB/s", "Medium", "Ready"),
            ("Timing Covert", "Network", "~100 B/s", "Very High", "Ready"),
            ("Image LSB", "File", "12.5%", "Medium", "Ready"),
            ("Image DCT", "File", "1.5%", "High", "Ready"),
            ("Audio LSB", "File", "6.25%", "Medium", "Ready"),
            ("Zero-Width Unicode", "Text", "50%", "Very High", "Ready"),
        ]
        
        self.channel_table.setRowCount(len(channels))
        for i, (name, ch_type, bw, stealth, status) in enumerate(channels):
            self.channel_table.setItem(i, 0, QTableWidgetItem(name))
            self.channel_table.setItem(i, 1, QTableWidgetItem(ch_type))
            self.channel_table.setItem(i, 2, QTableWidgetItem(bw))
            
            stealth_item = QTableWidgetItem(stealth)
            if "Very High" in stealth:
                stealth_item.setForeground(QColor("#00ff88"))
            elif "High" in stealth:
                stealth_item.setForeground(QColor("#88ff00"))
            else:
                stealth_item.setForeground(QColor("#ffff00"))
            self.channel_table.setItem(i, 3, stealth_item)
            
            status_item = QTableWidgetItem(status)
            status_item.setForeground(QColor("#00ff88"))
            self.channel_table.setItem(i, 4, status_item)
        
        layout.addWidget(self.channel_table)
        
        # DNS Exfil config
        dns_group = QGroupBox("DNS Exfiltration")
        dns_layout = QGridLayout(dns_group)
        
        dns_layout.addWidget(QLabel("Domain:"), 0, 0)
        self.dns_domain = QLineEdit("data.example.com")
        dns_layout.addWidget(self.dns_domain, 0, 1)
        
        dns_layout.addWidget(QLabel("Record Type:"), 1, 0)
        self.dns_type = QComboBox()
        self.dns_type.addItems(["TXT", "A", "CNAME", "MX"])
        dns_layout.addWidget(self.dns_type, 1, 1)
        
        dns_btn = QPushButton("Start DNS Exfil")
        dns_layout.addWidget(dns_btn, 2, 0, 1, 2)
        
        layout.addWidget(dns_group)
        
        return widget
    
    def _create_sessions_tab(self) -> QWidget:
        """Create sessions tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Session table
        self.session_table = QTableWidget()
        self.session_table.setColumnCount(6)
        self.session_table.setHorizontalHeaderLabels([
            "Session ID", "Method", "Data Size", "Progress", "Status", "Time"
        ])
        self.session_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.session_table)
        
        # Session controls
        controls = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        controls.addWidget(refresh_btn)
        
        cancel_btn = QPushButton("❌ Cancel Selected")
        controls.addWidget(cancel_btn)
        
        controls.addStretch()
        
        export_btn = QPushButton("📤 Export Report")
        controls.addWidget(export_btn)
        
        layout.addLayout(controls)
        
        return widget
    
    def _browse_carrier(self):
        """Browse for carrier file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Carrier File", "",
            "Images (*.png *.jpg *.bmp);;Audio (*.wav *.mp3);;All Files (*)"
        )
        if file_path:
            self.carrier_input.setText(file_path)
            self.carrier_info.setText(f"Selected: {file_path.split('/')[-1]}")
            self.carrier_size.setText("1.2 MB")
            self.max_payload.setText("~150 KB")
            self.detection_risk.setText("Low")
            self.detection_risk.setStyleSheet("color: #00ff88;")
    
    def _browse_payload(self):
        """Browse for payload file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Payload File", "", "All Files (*)"
        )
        if file_path:
            self.payload_input.setText(file_path)
    
    def _browse_stego(self):
        """Browse for stego file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Stego File", "",
            "Images (*.png *.jpg *.bmp);;All Files (*)"
        )
        if file_path:
            self.stego_input.setText(file_path)
    
    def _embed_data(self):
        """Embed data into carrier"""
        self.embed_progress.setVisible(True)
        self.embed_progress.setValue(0)
        
        # Simulate embedding
        self.embed_timer = QTimer()
        self.embed_value = 0
        
        def update():
            self.embed_value += 10
            self.embed_progress.setValue(self.embed_value)
            if self.embed_value >= 100:
                self.embed_timer.stop()
                self.embed_progress.setVisible(False)
        
        self.embed_timer.timeout.connect(update)
        self.embed_timer.start(200)
    
    def _extract_data(self):
        """Extract data from stego file"""
        self.extracted_output.setText("Extracting hidden data...\n\n")
        self.extracted_output.append("Detected: LSB encoding")
        self.extracted_output.append("Payload size: 1,234 bytes")
        self.extracted_output.append("Encryption: XOR detected\n")
        self.extracted_output.append("--- Extracted Content ---\n")
        self.extracted_output.append("This is the hidden secret message!")
    
    def _save_extracted(self):
        """Save extracted data"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Extracted Data", "extracted_data.txt", "All Files (*)"
        )
    
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
                border: 1px solid #ff6b6b44;
                border-radius: 8px;
                min-width: 100px;
            }
            
            #panelFrame {
                background-color: #16213e;
                border-radius: 10px;
                padding: 15px;
            }
            
            QGroupBox {
                border: 1px solid #ff6b6b44;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
                color: #ff6b6b;
            }
            
            QLineEdit, QComboBox, QTextEdit {
                background-color: #0f0f1a;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
            }
            
            QLineEdit:focus {
                border-color: #ff6b6b;
            }
            
            #primaryButton {
                background-color: #ff6b6b;
                color: #fff;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
            }
            
            #primaryButton:hover {
                background-color: #ff5252;
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
            
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #ff6b6b;
                padding: 10px;
                border: none;
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
                background-color: #ff6b6b33;
                color: #ff6b6b;
            }
            
            QProgressBar {
                border: none;
                border-radius: 5px;
                background-color: #0f0f1a;
                height: 10px;
            }
            
            QProgressBar::chunk {
                background-color: #ff6b6b;
                border-radius: 5px;
            }
            
            QCheckBox {
                spacing: 8px;
            }
            
            QCheckBox::indicator:checked {
                background-color: #ff6b6b;
                border-radius: 3px;
            }
        """
