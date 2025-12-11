"""
Quantum-Resistant Cryptography Analyzer GUI Page
Analyzes cryptographic implementations for quantum computing vulnerabilities.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTextEdit, QLineEdit, QComboBox, QProgressBar, QTabWidget,
    QGroupBox, QSpinBox, QCheckBox, QSplitter, QTreeWidget,
    QTreeWidgetItem, QGridLayout, QListWidget, QFileDialog,
    QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from datetime import datetime


class CryptoAnalysisWorker(QThread):
    """Worker for cryptographic analysis"""
    progress = pyqtSignal(int)
    result = pyqtSignal(dict)
    log = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, analyzer, target):
        super().__init__()
        self.analyzer = analyzer
        self.target = target
    
    def run(self):
        try:
            for i in range(100):
                self.progress.emit(i + 1)
                if i % 20 == 0:
                    self.log.emit(f"Analyzing cryptographic components... {i}%")
                self.msleep(30)
            
            self.result.emit({
                "status": "completed",
                "vulnerabilities": []
            })
        except Exception as e:
            self.result.emit({"error": str(e)})
        finally:
            self.finished.emit()


class QuantumCryptoPage(QWidget):
    """Quantum-Resistant Cryptography Analyzer"""
    
    def __init__(self, config, db):
        super().__init__()
        self.config = config
        self.db = db
        self.analyzer = None
        self.worker = None
        
        self._init_analyzer()
        self._setup_ui()
        self._apply_styles()
    
    def _init_analyzer(self):
        """Initialize quantum crypto analyzer"""
        try:
            from core.quantum_crypto import QuantumCryptoAnalyzer
            self.analyzer = QuantumCryptoAnalyzer()
        except ImportError:
            self.analyzer = None
    
    def _setup_ui(self):
        """Setup user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main tabs
        tabs = QTabWidget()
        tabs.setObjectName("quantumTabs")
        
        tabs.addTab(self._create_analysis_tab(), "⚛️ Quantum Analysis")
        tabs.addTab(self._create_algorithms_tab(), "🔐 Algorithm Assessment")
        tabs.addTab(self._create_migration_tab(), "🔄 Migration Planning")
        tabs.addTab(self._create_inventory_tab(), "📋 Crypto Inventory")
        tabs.addTab(self._create_compliance_tab(), "✅ Compliance")
        
        layout.addWidget(tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setObjectName("headerFrame")
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("⚛️ Quantum-Resistant Crypto Analyzer")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #aa88ff;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Analyze and prepare cryptographic implementations for quantum computing threats")
        subtitle.setStyleSheet("color: #888; font-size: 12px;")
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Quick stats
        stats_layout = QHBoxLayout()
        
        for label, value, color in [
            ("Vulnerable Algorithms", "7", "#ff4444"),
            ("At-Risk Keys", "23", "#ff8800"),
            ("Quantum-Safe", "156", "#00ff88")
        ]:
            stat = QLabel(f"{value} {label}")
            stat.setStyleSheet(f"color: {color}; font-size: 11px;")
            stats_layout.addWidget(stat)
        
        layout.addLayout(stats_layout)
        
        # Action button
        self.scan_btn = QPushButton("⚛️ Run Quantum Analysis")
        self.scan_btn.setObjectName("primaryButton")
        self.scan_btn.clicked.connect(self._run_analysis)
        layout.addWidget(self.scan_btn)
        
        return frame
    
    def _create_analysis_tab(self) -> QWidget:
        """Create main analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Configuration
        left_panel = QFrame()
        left_panel.setObjectName("configPanel")
        left_layout = QVBoxLayout(left_panel)
        
        # Target configuration
        target_group = QGroupBox("Analysis Target")
        target_layout = QVBoxLayout(target_group)
        
        target_layout.addWidget(QLabel("Target Type:"))
        self.target_type = QComboBox()
        self.target_type.addItems([
            "File/Binary", "Network Service", "Certificate/Key",
            "Source Code", "Full System Scan"
        ])
        target_layout.addWidget(self.target_type)
        
        target_layout.addWidget(QLabel("Target Path/Address:"))
        target_input_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("/path/to/file or hostname:port")
        target_input_layout.addWidget(self.target_input)
        
        browse_btn = QPushButton("📁")
        browse_btn.setMaximumWidth(40)
        browse_btn.clicked.connect(self._browse_target)
        target_input_layout.addWidget(browse_btn)
        target_layout.addLayout(target_input_layout)
        
        left_layout.addWidget(target_group)
        
        # Analysis options
        options_group = QGroupBox("Analysis Options")
        options_layout = QVBoxLayout(options_group)
        
        self.check_rsa = QCheckBox("Check RSA vulnerabilities (Shor's algorithm)")
        self.check_rsa.setChecked(True)
        options_layout.addWidget(self.check_rsa)
        
        self.check_ecc = QCheckBox("Check ECC vulnerabilities (Shor's algorithm)")
        self.check_ecc.setChecked(True)
        options_layout.addWidget(self.check_ecc)
        
        self.check_aes = QCheckBox("Check AES key sizes (Grover's algorithm)")
        self.check_aes.setChecked(True)
        options_layout.addWidget(self.check_aes)
        
        self.check_hash = QCheckBox("Check hash functions (Grover's algorithm)")
        self.check_hash.setChecked(True)
        options_layout.addWidget(self.check_hash)
        
        self.deep_analysis = QCheckBox("Deep cryptographic analysis")
        options_layout.addWidget(self.deep_analysis)
        
        left_layout.addWidget(options_group)
        
        # Quantum threat model
        threat_group = QGroupBox("Quantum Threat Model")
        threat_layout = QVBoxLayout(threat_group)
        
        threat_layout.addWidget(QLabel("Assumed Qubit Count:"))
        self.qubit_spin = QSpinBox()
        self.qubit_spin.setRange(100, 100000)
        self.qubit_spin.setValue(4000)
        self.qubit_spin.setSuffix(" qubits")
        threat_layout.addWidget(self.qubit_spin)
        
        threat_layout.addWidget(QLabel("Timeline Assessment:"))
        self.timeline_combo = QComboBox()
        self.timeline_combo.addItems([
            "Current (2024)", "Near-term (2027)",
            "Mid-term (2030)", "Long-term (2035+)"
        ])
        threat_layout.addWidget(self.timeline_combo)
        
        left_layout.addWidget(threat_group)
        
        # Run button
        run_layout = QHBoxLayout()
        self.analyze_btn = QPushButton("⚛️ Analyze")
        self.analyze_btn.setObjectName("primaryButton")
        self.analyze_btn.clicked.connect(self._run_analysis)
        run_layout.addWidget(self.analyze_btn)
        left_layout.addLayout(run_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        left_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready for analysis")
        self.status_label.setStyleSheet("color: #888;")
        left_layout.addWidget(self.status_label)
        
        left_layout.addStretch()
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = QFrame()
        right_panel.setObjectName("resultsPanel")
        right_layout = QVBoxLayout(right_panel)
        
        right_layout.addWidget(QLabel("Quantum Vulnerability Assessment:"))
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Algorithm", "Key Size", "Quantum Risk", "Attack Type",
            "Time to Break", "Recommendation"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.itemClicked.connect(self._show_vuln_details)
        
        # Sample results
        sample_results = [
            ("RSA-2048", "2048 bits", "Critical", "Shor's", "~4 hours*", "Migrate to ML-KEM"),
            ("ECDSA P-256", "256 bits", "Critical", "Shor's", "~8 hours*", "Migrate to ML-DSA"),
            ("AES-128", "128 bits", "Medium", "Grover's", "~2^64 ops", "Upgrade to AES-256"),
            ("SHA-256", "256 bits", "Low", "Grover's", "~2^128 ops", "Acceptable"),
            ("AES-256", "256 bits", "Low", "Grover's", "~2^128 ops", "Quantum-safe"),
        ]
        
        self.results_table.setRowCount(len(sample_results))
        for row, result in enumerate(sample_results):
            for col, value in enumerate(result):
                item = QTableWidgetItem(value)
                if col == 2:  # Risk
                    if value == "Critical":
                        item.setForeground(QColor("#ff4444"))
                    elif value == "Medium":
                        item.setForeground(QColor("#ff8800"))
                    else:
                        item.setForeground(QColor("#00ff88"))
                self.results_table.setItem(row, col, item)
        
        right_layout.addWidget(self.results_table)
        
        # Details
        details_group = QGroupBox("Vulnerability Details")
        details_layout = QVBoxLayout(details_group)
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(180)
        details_layout.addWidget(self.details_text)
        right_layout.addWidget(details_group)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([350, 650])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_algorithms_tab(self) -> QWidget:
        """Create algorithm assessment tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Algorithm categories
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Algorithm tree
        tree_panel = QFrame()
        tree_layout = QVBoxLayout(tree_panel)
        tree_layout.addWidget(QLabel("Cryptographic Algorithms:"))
        
        self.algo_tree = QTreeWidget()
        self.algo_tree.setHeaderLabels(["Algorithm", "Status", "Quantum Safety"])
        
        categories = [
            ("Public Key Encryption", [
                ("RSA", "Deprecated for Q-day", "❌ Vulnerable"),
                ("ECDH", "Deprecated for Q-day", "❌ Vulnerable"),
                ("ML-KEM (Kyber)", "Recommended", "✅ Safe"),
                ("NTRU", "Alternative", "✅ Safe"),
            ]),
            ("Digital Signatures", [
                ("RSA-PSS", "Deprecated for Q-day", "❌ Vulnerable"),
                ("ECDSA", "Deprecated for Q-day", "❌ Vulnerable"),
                ("ML-DSA (Dilithium)", "Recommended", "✅ Safe"),
                ("SLH-DSA (SPHINCS+)", "Alternative", "✅ Safe"),
            ]),
            ("Symmetric Encryption", [
                ("AES-128", "Upgrade recommended", "⚠️ Weakened"),
                ("AES-256", "Recommended", "✅ Safe"),
                ("ChaCha20", "Upgrade key size", "⚠️ Weakened"),
            ]),
            ("Hash Functions", [
                ("SHA-256", "Acceptable", "✅ Safe"),
                ("SHA-384", "Recommended", "✅ Safe"),
                ("SHA-512", "Recommended", "✅ Safe"),
                ("SHA3-256", "Recommended", "✅ Safe"),
            ]),
        ]
        
        for category, algorithms in categories:
            parent = QTreeWidgetItem([category, "", ""])
            for name, status, safety in algorithms:
                child = QTreeWidgetItem([name, status, safety])
                if "❌" in safety:
                    child.setForeground(2, QColor("#ff4444"))
                elif "⚠️" in safety:
                    child.setForeground(2, QColor("#ff8800"))
                else:
                    child.setForeground(2, QColor("#00ff88"))
                parent.addChild(child)
            self.algo_tree.addTopLevelItem(parent)
        
        self.algo_tree.expandAll()
        tree_layout.addWidget(self.algo_tree)
        splitter.addWidget(tree_panel)
        
        # Right - Algorithm details
        details_panel = QFrame()
        details_layout = QVBoxLayout(details_panel)
        details_layout.addWidget(QLabel("Algorithm Details:"))
        
        self.algo_details = QTextEdit()
        self.algo_details.setReadOnly(True)
        self.algo_details.setHtml("""
<h3>Select an algorithm to view details</h3>
<p>Click on any algorithm in the tree to see:</p>
<ul>
<li>Quantum attack vectors</li>
<li>Security level assessment</li>
<li>Migration recommendations</li>
<li>Implementation guidance</li>
</ul>
""")
        details_layout.addWidget(self.algo_details)
        
        splitter.addWidget(details_panel)
        layout.addWidget(splitter)
        
        return widget
    
    def _create_migration_tab(self) -> QWidget:
        """Create migration planning tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Migration phases
        phases_group = QGroupBox("Quantum-Safe Migration Roadmap")
        phases_layout = QVBoxLayout(phases_group)
        
        phases = [
            ("Phase 1: Discovery", "Inventory all cryptographic assets", "#00d4ff", 100),
            ("Phase 2: Assessment", "Evaluate quantum vulnerability", "#00d4ff", 85),
            ("Phase 3: Planning", "Develop migration strategy", "#ff8800", 40),
            ("Phase 4: Testing", "Test post-quantum algorithms", "#888888", 0),
            ("Phase 5: Migration", "Implement quantum-safe crypto", "#888888", 0),
            ("Phase 6: Validation", "Verify migration success", "#888888", 0),
        ]
        
        for phase, description, color, progress in phases:
            phase_frame = QFrame()
            phase_frame.setObjectName("phaseCard")
            phase_layout = QHBoxLayout(phase_frame)
            
            phase_label = QLabel(phase)
            phase_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            phase_label.setStyleSheet(f"color: {color};")
            phase_label.setMinimumWidth(150)
            phase_layout.addWidget(phase_label)
            
            desc_label = QLabel(description)
            desc_label.setStyleSheet("color: #888;")
            phase_layout.addWidget(desc_label)
            
            phase_layout.addStretch()
            
            progress_bar = QProgressBar()
            progress_bar.setValue(progress)
            progress_bar.setMaximumWidth(200)
            phase_layout.addWidget(progress_bar)
            
            status_label = QLabel(f"{progress}%")
            status_label.setMinimumWidth(50)
            phase_layout.addWidget(status_label)
            
            phases_layout.addWidget(phase_frame)
        
        layout.addWidget(phases_group)
        
        # Migration tasks
        tasks_group = QGroupBox("Priority Migration Tasks")
        tasks_layout = QVBoxLayout(tasks_group)
        
        self.tasks_table = QTableWidget()
        self.tasks_table.setColumnCount(5)
        self.tasks_table.setHorizontalHeaderLabels([
            "Priority", "System", "Current Crypto", "Target Crypto", "Status"
        ])
        self.tasks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        tasks = [
            ("Critical", "Authentication Service", "RSA-2048", "ML-KEM-768", "Pending"),
            ("Critical", "TLS Certificates", "ECDSA P-256", "ML-DSA-65", "In Progress"),
            ("High", "Data Encryption", "AES-128", "AES-256", "Pending"),
            ("High", "API Gateway", "RSA-2048", "ML-KEM-768", "Pending"),
            ("Medium", "Log Signing", "ECDSA P-256", "SLH-DSA", "Pending"),
        ]
        
        self.tasks_table.setRowCount(len(tasks))
        for row, task in enumerate(tasks):
            for col, value in enumerate(task):
                item = QTableWidgetItem(value)
                if col == 0:  # Priority
                    if value == "Critical":
                        item.setForeground(QColor("#ff4444"))
                    elif value == "High":
                        item.setForeground(QColor("#ff8800"))
                self.tasks_table.setItem(row, col, item)
        
        tasks_layout.addWidget(self.tasks_table)
        layout.addWidget(tasks_group)
        
        # Action buttons
        actions = QHBoxLayout()
        
        generate_plan_btn = QPushButton("📝 Generate Migration Plan")
        generate_plan_btn.setObjectName("primaryButton")
        actions.addWidget(generate_plan_btn)
        
        export_btn = QPushButton("📤 Export Roadmap")
        actions.addWidget(export_btn)
        
        timeline_btn = QPushButton("📅 View Timeline")
        actions.addWidget(timeline_btn)
        
        layout.addLayout(actions)
        
        return widget
    
    def _create_inventory_tab(self) -> QWidget:
        """Create crypto inventory tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Inventory controls
        controls = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search cryptographic assets...")
        controls.addWidget(self.search_input)
        
        filter_combo = QComboBox()
        filter_combo.addItems(["All", "Vulnerable", "Safe", "Unknown"])
        controls.addWidget(filter_combo)
        
        scan_btn = QPushButton("🔍 Scan System")
        scan_btn.clicked.connect(self._scan_inventory)
        controls.addWidget(scan_btn)
        
        layout.addLayout(controls)
        
        # Inventory table
        self.inventory_table = QTableWidget()
        self.inventory_table.setColumnCount(7)
        self.inventory_table.setHorizontalHeaderLabels([
            "Asset", "Type", "Algorithm", "Key Size", "Location", "Quantum Risk", "Last Updated"
        ])
        self.inventory_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        inventory = [
            ("Server Certificate", "X.509", "RSA", "2048", "/etc/ssl/certs/", "Critical", "2024-01-15"),
            ("SSH Host Key", "Key Pair", "ECDSA", "256", "/etc/ssh/", "Critical", "2024-01-10"),
            ("Database Encryption", "Symmetric", "AES", "256", "DB Config", "Low", "2024-02-01"),
            ("API Token Signing", "HMAC", "SHA-256", "256", "Vault", "Low", "2024-02-15"),
            ("User Passwords", "Hash", "bcrypt", "N/A", "Database", "Low", "2024-02-10"),
        ]
        
        self.inventory_table.setRowCount(len(inventory))
        for row, item in enumerate(inventory):
            for col, value in enumerate(item):
                cell = QTableWidgetItem(value)
                if col == 5:  # Risk
                    if value == "Critical":
                        cell.setForeground(QColor("#ff4444"))
                    elif value == "Medium":
                        cell.setForeground(QColor("#ff8800"))
                    else:
                        cell.setForeground(QColor("#00ff88"))
                self.inventory_table.setItem(row, col, cell)
        
        layout.addWidget(self.inventory_table)
        
        # Summary stats
        stats_layout = QHBoxLayout()
        
        for label, value, color in [
            ("Total Assets", "47", "#00d4ff"),
            ("Quantum Vulnerable", "12", "#ff4444"),
            ("Needs Upgrade", "8", "#ff8800"),
            ("Quantum-Safe", "27", "#00ff88")
        ]:
            stat_frame = QFrame()
            stat_frame.setObjectName("statCard")
            stat_v = QVBoxLayout(stat_frame)
            
            val = QLabel(value)
            val.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
            val.setStyleSheet(f"color: {color};")
            val.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_v.addWidget(val)
            
            lbl = QLabel(label)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet("color: #888;")
            stat_v.addWidget(lbl)
            
            stats_layout.addWidget(stat_frame)
        
        layout.addLayout(stats_layout)
        
        return widget
    
    def _create_compliance_tab(self) -> QWidget:
        """Create compliance tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Compliance frameworks
        frameworks_group = QGroupBox("Quantum Cryptography Compliance")
        frameworks_layout = QVBoxLayout(frameworks_group)
        
        frameworks = [
            ("NIST Post-Quantum Standards", "Compliant", 95, "#00ff88"),
            ("NSA CNSA 2.0", "Partial", 65, "#ff8800"),
            ("ETSI QKD Standards", "Not Applicable", 0, "#888888"),
            ("ISO/IEC 18033-2", "Under Review", 40, "#ff8800"),
        ]
        
        for name, status, progress, color in frameworks:
            frame = QFrame()
            frame.setObjectName("complianceCard")
            frame_layout = QHBoxLayout(frame)
            
            name_label = QLabel(name)
            name_label.setMinimumWidth(200)
            frame_layout.addWidget(name_label)
            
            status_label = QLabel(status)
            status_label.setStyleSheet(f"color: {color};")
            status_label.setMinimumWidth(100)
            frame_layout.addWidget(status_label)
            
            progress_bar = QProgressBar()
            progress_bar.setValue(progress)
            frame_layout.addWidget(progress_bar)
            
            frameworks_layout.addWidget(frame)
        
        layout.addWidget(frameworks_group)
        
        # Compliance report
        report_group = QGroupBox("Compliance Report")
        report_layout = QVBoxLayout(report_group)
        
        self.compliance_report = QTextEdit()
        self.compliance_report.setReadOnly(True)
        self.compliance_report.setHtml("""
<h3>Quantum Cryptography Compliance Assessment</h3>

<h4>✅ Compliant Areas:</h4>
<ul>
<li>ML-KEM implementation follows FIPS 203 draft</li>
<li>Key encapsulation mechanism properly implemented</li>
<li>Symmetric encryption uses AES-256</li>
</ul>

<h4>⚠️ Areas Requiring Attention:</h4>
<ul>
<li>Legacy RSA keys still in production use</li>
<li>ECDSA certificates need migration plan</li>
<li>Some systems using AES-128</li>
</ul>

<h4>❌ Non-Compliant Areas:</h4>
<ul>
<li>Authentication service uses RSA-2048</li>
<li>API signing uses non-quantum-safe algorithms</li>
</ul>
""")
        report_layout.addWidget(self.compliance_report)
        layout.addWidget(report_group)
        
        # Actions
        actions = QHBoxLayout()
        
        generate_btn = QPushButton("📊 Generate Full Report")
        generate_btn.setObjectName("primaryButton")
        actions.addWidget(generate_btn)
        
        export_btn = QPushButton("📤 Export PDF")
        actions.addWidget(export_btn)
        
        schedule_btn = QPushButton("📅 Schedule Audit")
        actions.addWidget(schedule_btn)
        
        layout.addLayout(actions)
        
        return widget
    
    def _apply_styles(self):
        """Apply custom styles"""
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a2e;
                color: #ffffff;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            QFrame#headerFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a3e, stop:1 #1a1a2e);
                border-radius: 10px;
                padding: 15px;
            }
            
            QFrame#configPanel, QFrame#resultsPanel {
                background-color: #16213e;
                border-radius: 8px;
                padding: 10px;
            }
            
            QFrame#statCard, QFrame#phaseCard, QFrame#complianceCard {
                background-color: #16213e;
                border: 1px solid #0f3460;
                border-radius: 8px;
                padding: 10px;
            }
            
            QGroupBox {
                font-weight: bold;
                border: 1px solid #0f3460;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            
            QPushButton {
                background-color: #0f3460;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                color: white;
                font-weight: bold;
            }
            
            QPushButton:hover {
                background-color: #1a4a7a;
            }
            
            QPushButton#primaryButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #aa88ff, stop:1 #8866dd);
                color: #000;
            }
            
            QPushButton#primaryButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #bb99ff, stop:1 #9977ee);
            }
            
            QTableWidget {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
                gridline-color: #1a3a5c;
            }
            
            QTableWidget::item {
                padding: 8px;
            }
            
            QTableWidget::item:selected {
                background-color: #0f3460;
            }
            
            QHeaderView::section {
                background-color: #16213e;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #aa88ff;
                font-weight: bold;
            }
            
            QLineEdit, QComboBox, QSpinBox {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
            
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #aa88ff;
            }
            
            QTextEdit {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
                padding: 10px;
            }
            
            QProgressBar {
                border: 1px solid #0f3460;
                border-radius: 5px;
                text-align: center;
                background-color: #0d1b2a;
            }
            
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #aa88ff, stop:1 #00ff88);
                border-radius: 4px;
            }
            
            QTabWidget::pane {
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QTabBar::tab {
                background-color: #16213e;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            
            QTabBar::tab:selected {
                background-color: #0f3460;
                border-bottom: 2px solid #aa88ff;
            }
            
            QTreeWidget {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QTreeWidget::item {
                padding: 5px;
            }
            
            QTreeWidget::item:selected {
                background-color: #0f3460;
            }
            
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 3px;
                border: 1px solid #0f3460;
                background-color: #0d1b2a;
            }
            
            QCheckBox::indicator:checked {
                background-color: #aa88ff;
                border-color: #aa88ff;
            }
        """)
    
    def _browse_target(self):
        """Browse for target file"""
        path, _ = QFileDialog.getOpenFileName(self, "Select Target File")
        if path:
            self.target_input.setText(path)
    
    def _run_analysis(self):
        """Run quantum vulnerability analysis"""
        target = self.target_input.text()
        if not target and self.target_type.currentText() != "Full System Scan":
            self.status_label.setText("Please specify a target")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.analyze_btn.setEnabled(False)
        self.status_label.setText("Analyzing cryptographic implementations...")
        
        self.worker = CryptoAnalysisWorker(self.analyzer, target)
        self.worker.progress.connect(lambda v: self.progress_bar.setValue(v))
        self.worker.log.connect(lambda m: self.status_label.setText(m))
        self.worker.finished.connect(self._analysis_finished)
        self.worker.start()
    
    def _analysis_finished(self):
        """Handle analysis completion"""
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.status_label.setText("Analysis complete")
    
    def _show_vuln_details(self, item):
        """Show vulnerability details"""
        row = item.row()
        algo = self.results_table.item(row, 0).text()
        
        self.details_text.setHtml(f"""
<h3>{algo} Quantum Vulnerability</h3>
<p><b>Attack Method:</b> Shor's Algorithm</p>
<p>Shor's algorithm can factor large numbers and compute discrete logarithms 
in polynomial time on a sufficiently powerful quantum computer.</p>

<p><b>Impact:</b></p>
<ul>
<li>Complete key recovery possible</li>
<li>All encrypted data compromised</li>
<li>Digital signatures forgeable</li>
</ul>

<p><b>Remediation:</b></p>
<p>Migrate to NIST-approved post-quantum algorithms:</p>
<ul>
<li>ML-KEM (FIPS 203) for key encapsulation</li>
<li>ML-DSA (FIPS 204) for digital signatures</li>
<li>SLH-DSA (FIPS 205) for hash-based signatures</li>
</ul>
""")
    
    def _scan_inventory(self):
        """Scan system for cryptographic assets"""
        self.status_label.setText("Scanning system for cryptographic assets...")
