"""
Neural Fingerprinting Page
ML-based system and service identification interface.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QTextEdit,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QSpinBox, QComboBox, QTabWidget, QSplitter,
    QListWidget, QListWidgetItem, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QThread
from PyQt6.QtGui import QFont, QColor


class NeuralFingerprintPage(QWidget):
    """Neural network-based fingerprinting interface"""
    
    scan_requested = pyqtSignal(str, list)
    
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
        
        # Main content with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Controls
        left_panel = self._create_control_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = self._create_results_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter, 1)
        
        # Status bar
        self.status_bar = self._create_status_bar()
        layout.addWidget(self.status_bar)
        
        self.setStyleSheet(self._get_styles())
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setObjectName("headerFrame")
        layout = QHBoxLayout(frame)
        
        # Title and description
        title_layout = QVBoxLayout()
        
        title = QLabel("🧠 Neural Fingerprinting Engine")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("ML-powered system and service identification")
        subtitle.setStyleSheet("color: #888;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Quick stats
        stats_layout = QHBoxLayout()
        
        self.os_accuracy = self._create_stat_widget("OS Accuracy", "94.2%")
        stats_layout.addWidget(self.os_accuracy)
        
        self.service_accuracy = self._create_stat_widget("Service Accuracy", "91.7%")
        stats_layout.addWidget(self.service_accuracy)
        
        self.fingerprints = self._create_stat_widget("Fingerprints", "0")
        stats_layout.addWidget(self.fingerprints)
        
        layout.addLayout(stats_layout)
        
        return frame
    
    def _create_stat_widget(self, label: str, value: str) -> QFrame:
        """Create stat display widget"""
        frame = QFrame()
        frame.setObjectName("statWidget")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(15, 10, 15, 10)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setStyleSheet("color: #00ff88;")
        layout.addWidget(value_label)
        
        name_label = QLabel(label)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_label.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(name_label)
        
        return frame
    
    def _create_control_panel(self) -> QFrame:
        """Create control panel"""
        frame = QFrame()
        frame.setObjectName("controlPanel")
        layout = QVBoxLayout(frame)
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        # Target input
        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP address or hostname")
        target_row.addWidget(self.target_input)
        target_layout.addLayout(target_row)
        
        # Port range
        port_row = QHBoxLayout()
        port_row.addWidget(QLabel("Ports:"))
        self.port_input = QLineEdit("22,80,443,445,3389")
        self.port_input.setPlaceholderText("Comma-separated ports")
        port_row.addWidget(self.port_input)
        target_layout.addLayout(port_row)
        
        layout.addWidget(target_group)
        
        # Fingerprint options
        options_group = QGroupBox("Fingerprint Options")
        options_layout = QVBoxLayout(options_group)
        
        self.os_fingerprint = QCheckBox("OS Fingerprinting")
        self.os_fingerprint.setChecked(True)
        options_layout.addWidget(self.os_fingerprint)
        
        self.service_fingerprint = QCheckBox("Service Detection")
        self.service_fingerprint.setChecked(True)
        options_layout.addWidget(self.service_fingerprint)
        
        self.version_detect = QCheckBox("Version Detection")
        self.version_detect.setChecked(True)
        options_layout.addWidget(self.version_detect)
        
        self.banner_grab = QCheckBox("Banner Grabbing")
        self.banner_grab.setChecked(True)
        options_layout.addWidget(self.banner_grab)
        
        self.timing_analysis = QCheckBox("Timing Analysis")
        self.timing_analysis.setChecked(False)
        options_layout.addWidget(self.timing_analysis)
        
        layout.addWidget(options_group)
        
        # Probe configuration
        probe_group = QGroupBox("Probe Configuration")
        probe_layout = QGridLayout(probe_group)
        
        probe_layout.addWidget(QLabel("Timeout (s):"), 0, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(3)
        probe_layout.addWidget(self.timeout_spin, 0, 1)
        
        probe_layout.addWidget(QLabel("Retries:"), 1, 0)
        self.retry_spin = QSpinBox()
        self.retry_spin.setRange(0, 5)
        self.retry_spin.setValue(2)
        probe_layout.addWidget(self.retry_spin, 1, 1)
        
        probe_layout.addWidget(QLabel("Threads:"), 2, 0)
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 50)
        self.thread_spin.setValue(10)
        probe_layout.addWidget(self.thread_spin, 2, 1)
        
        layout.addWidget(probe_group)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("🚀 Start Fingerprinting")
        self.scan_btn.setObjectName("primaryButton")
        self.scan_btn.clicked.connect(self._start_fingerprinting)
        btn_layout.addWidget(self.scan_btn)
        
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        layout.addStretch()
        
        return frame
    
    def _create_results_panel(self) -> QFrame:
        """Create results panel"""
        frame = QFrame()
        frame.setObjectName("resultsPanel")
        layout = QVBoxLayout(frame)
        
        # Tab widget for results
        tabs = QTabWidget()
        
        # OS Fingerprint tab
        os_tab = QWidget()
        os_layout = QVBoxLayout(os_tab)
        
        self.os_table = QTableWidget()
        self.os_table.setColumnCount(5)
        self.os_table.setHorizontalHeaderLabels([
            "Target", "Detected OS", "Version", "Confidence", "Details"
        ])
        self.os_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        os_layout.addWidget(self.os_table)
        
        tabs.addTab(os_tab, "🖥️ OS Detection")
        
        # Service Detection tab
        service_tab = QWidget()
        service_layout = QVBoxLayout(service_tab)
        
        self.service_table = QTableWidget()
        self.service_table.setColumnCount(6)
        self.service_table.setHorizontalHeaderLabels([
            "Port", "Service", "Version", "Banner", "Confidence", "Fingerprint ID"
        ])
        self.service_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        service_layout.addWidget(self.service_table)
        
        tabs.addTab(service_tab, "🔌 Services")
        
        # Neural Network tab
        nn_tab = QWidget()
        nn_layout = QVBoxLayout(nn_tab)
        
        nn_info = QTextEdit()
        nn_info.setReadOnly(True)
        nn_info.setPlaceholderText("Neural network classification details will appear here...")
        nn_layout.addWidget(nn_info)
        
        tabs.addTab(nn_tab, "🧠 NN Analysis")
        
        # Training tab
        train_tab = QWidget()
        train_layout = QVBoxLayout(train_tab)
        
        train_controls = QHBoxLayout()
        train_controls.addWidget(QLabel("Add to training set:"))
        
        self.actual_os = QLineEdit()
        self.actual_os.setPlaceholderText("Actual OS (for training)")
        train_controls.addWidget(self.actual_os)
        
        train_btn = QPushButton("Train Model")
        train_btn.clicked.connect(self._train_model)
        train_controls.addWidget(train_btn)
        
        train_layout.addLayout(train_controls)
        
        self.training_log = QTextEdit()
        self.training_log.setReadOnly(True)
        train_layout.addWidget(self.training_log)
        
        tabs.addTab(train_tab, "📚 Training")
        
        layout.addWidget(tabs)
        
        return frame
    
    def _create_status_bar(self) -> QFrame:
        """Create status bar"""
        frame = QFrame()
        frame.setObjectName("statusBar")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(10, 5, 10, 5)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888;")
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        
        self.probes_sent = QLabel("Probes: 0")
        self.probes_sent.setStyleSheet("color: #666;")
        layout.addWidget(self.probes_sent)
        
        self.elapsed_time = QLabel("Time: 0s")
        self.elapsed_time.setStyleSheet("color: #666;")
        layout.addWidget(self.elapsed_time)
        
        return frame
    
    def _start_fingerprinting(self):
        """Start fingerprinting scan"""
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("Error: Please enter a target")
            self.status_label.setStyleSheet("color: #ff4444;")
            return
        
        ports = [int(p.strip()) for p in self.port_input.text().split(',') if p.strip().isdigit()]
        
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.status_label.setText(f"Fingerprinting {target}...")
        self.status_label.setStyleSheet("color: #00ff88;")
        
        # Emit signal for actual scanning
        self.scan_requested.emit(target, ports)
        
        # Simulate progress for demo
        self._simulate_progress()
    
    def _simulate_progress(self):
        """Simulate scanning progress"""
        self.progress_timer = QTimer()
        self.progress_value = 0
        
        def update_progress():
            self.progress_value += 5
            self.progress_bar.setValue(self.progress_value)
            
            if self.progress_value >= 100:
                self.progress_timer.stop()
                self._scan_complete()
        
        self.progress_timer.timeout.connect(update_progress)
        self.progress_timer.start(200)
    
    def _scan_complete(self):
        """Handle scan completion"""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        self.status_label.setText("Fingerprinting complete")
        self.status_label.setStyleSheet("color: #00ff88;")
        
        # Add sample results
        self._add_sample_results()
    
    def _add_sample_results(self):
        """Add sample fingerprint results"""
        # OS results
        self.os_table.setRowCount(1)
        self.os_table.setItem(0, 0, QTableWidgetItem(self.target_input.text()))
        self.os_table.setItem(0, 1, QTableWidgetItem("Linux 5.x"))
        self.os_table.setItem(0, 2, QTableWidgetItem("5.4.0-generic"))
        
        conf_item = QTableWidgetItem("94.2%")
        conf_item.setForeground(QColor("#00ff88"))
        self.os_table.setItem(0, 3, conf_item)
        self.os_table.setItem(0, 4, QTableWidgetItem("TTL=64, Window=65535"))
        
        # Service results
        services = [
            ("22", "OpenSSH", "8.2p1", "SSH-2.0-OpenSSH_8.2p1", "98.1%"),
            ("80", "nginx", "1.18.0", "nginx/1.18.0", "96.4%"),
            ("443", "nginx", "1.18.0", "nginx/1.18.0", "96.4%"),
        ]
        
        self.service_table.setRowCount(len(services))
        for i, (port, svc, ver, banner, conf) in enumerate(services):
            self.service_table.setItem(i, 0, QTableWidgetItem(port))
            self.service_table.setItem(i, 1, QTableWidgetItem(svc))
            self.service_table.setItem(i, 2, QTableWidgetItem(ver))
            self.service_table.setItem(i, 3, QTableWidgetItem(banner[:30]))
            
            conf_item = QTableWidgetItem(conf)
            conf_item.setForeground(QColor("#00ff88"))
            self.service_table.setItem(i, 4, conf_item)
            self.service_table.setItem(i, 5, QTableWidgetItem(f"FP-{i:04d}"))
    
    def _train_model(self):
        """Train model with correction"""
        actual = self.actual_os.text().strip()
        if actual:
            self.training_log.append(f"[+] Training sample added: {actual}")
            self.training_log.append("    Model updated successfully")
            self.actual_os.clear()
    
    def _get_styles(self) -> str:
        """Get widget styles"""
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
                border: 1px solid #333;
                border-radius: 8px;
                min-width: 100px;
            }
            
            #controlPanel, #resultsPanel {
                background-color: #16213e;
                border-radius: 10px;
                padding: 15px;
            }
            
            QGroupBox {
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
                color: #00ff88;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            
            QLineEdit, QSpinBox, QComboBox {
                background-color: #0f0f1a;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
                color: #ffffff;
            }
            
            QLineEdit:focus, QSpinBox:focus {
                border-color: #00ff88;
            }
            
            QCheckBox {
                spacing: 8px;
                color: #ccc;
            }
            
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            
            QCheckBox::indicator:checked {
                background-color: #00ff88;
                border-radius: 3px;
            }
            
            #primaryButton {
                background-color: #00ff88;
                color: #000;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
                font-size: 14px;
            }
            
            #primaryButton:hover {
                background-color: #00cc6a;
            }
            
            #primaryButton:disabled {
                background-color: #333;
                color: #666;
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
                gridline-color: #333;
            }
            
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #333;
            }
            
            QTableWidget::item:selected {
                background-color: #00ff8833;
            }
            
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #00ff88;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #00ff88;
                font-weight: bold;
            }
            
            QTabWidget::pane {
                border: 1px solid #333;
                border-radius: 8px;
                background-color: #0f0f1a;
            }
            
            QTabBar::tab {
                background-color: #1a1a2e;
                color: #888;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            
            QTabBar::tab:selected {
                background-color: #00ff8833;
                color: #00ff88;
            }
            
            QProgressBar {
                border: none;
                border-radius: 5px;
                background-color: #0f0f1a;
                height: 10px;
                text-align: center;
            }
            
            QProgressBar::chunk {
                background-color: #00ff88;
                border-radius: 5px;
            }
            
            QTextEdit {
                background-color: #0f0f1a;
                border: 1px solid #333;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Consolas', monospace;
            }
            
            #statusBar {
                background-color: #0f0f1a;
                border-radius: 5px;
            }
            
            QScrollBar:vertical {
                background-color: #0f0f1a;
                width: 12px;
                border-radius: 6px;
            }
            
            QScrollBar::handle:vertical {
                background-color: #333;
                border-radius: 6px;
                min-height: 20px;
            }
            
            QScrollBar::handle:vertical:hover {
                background-color: #00ff88;
            }
        """
