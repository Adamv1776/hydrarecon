"""
Blockchain Forensics GUI Page
Cryptocurrency tracing, wallet clustering, and transaction analysis.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTextEdit, QLineEdit, QComboBox, QProgressBar, QTabWidget,
    QGroupBox, QSpinBox, QCheckBox, QSplitter, QTreeWidget,
    QTreeWidgetItem, QGridLayout, QListWidget, QDoubleSpinBox,
    QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from datetime import datetime


class BlockchainTraceWorker(QThread):
    """Worker for blockchain tracing"""
    progress = pyqtSignal(int)
    result = pyqtSignal(dict)
    transaction_found = pyqtSignal(dict)
    finished = pyqtSignal()
    
    def __init__(self, analyzer, address, depth):
        super().__init__()
        self.analyzer = analyzer
        self.address = address
        self.depth = depth
    
    def run(self):
        try:
            for i in range(100):
                self.progress.emit(i + 1)
                if i % 20 == 0:
                    self.transaction_found.emit({
                        "hash": f"0x{i:08x}...",
                        "amount": 0.5 + i * 0.1
                    })
                self.msleep(40)
            
            self.result.emit({
                "status": "completed",
                "transactions": 47,
                "clusters": 5
            })
        except Exception as e:
            self.result.emit({"error": str(e)})
        finally:
            self.finished.emit()


class BlockchainForensicsPage(QWidget):
    """Blockchain Forensics Module GUI"""
    
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
        """Initialize blockchain analyzer"""
        try:
            from core.blockchain_forensics import BlockchainForensics
            self.analyzer = BlockchainForensics(self.config, self.db)
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
        tabs.setObjectName("blockchainTabs")
        
        tabs.addTab(self._create_tracing_tab(), "🔍 Transaction Tracing")
        tabs.addTab(self._create_wallet_tab(), "💼 Wallet Analysis")
        tabs.addTab(self._create_cluster_tab(), "🕸️ Cluster Analysis")
        tabs.addTab(self._create_mixer_tab(), "🌀 Mixer Detection")
        tabs.addTab(self._create_reports_tab(), "📊 Reports")
        
        layout.addWidget(tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setObjectName("headerFrame")
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("⛓️ Blockchain Forensics")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #f7931a;")  # Bitcoin orange
        title_layout.addWidget(title)
        
        subtitle = QLabel("Cryptocurrency tracing, wallet clustering, and transaction analysis")
        subtitle.setStyleSheet("color: #888; font-size: 12px;")
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Quick stats
        stats_layout = QHBoxLayout()
        
        for label, value, color in [
            ("Wallets Analyzed", "2,847", "#00d4ff"),
            ("Transactions Traced", "156K", "#f7931a"),
            ("Clusters Found", "89", "#00ff88")
        ]:
            stat = QLabel(f"{value} {label}")
            stat.setStyleSheet(f"color: {color}; font-size: 11px;")
            stats_layout.addWidget(stat)
        
        layout.addLayout(stats_layout)
        
        # Action button
        self.trace_btn = QPushButton("🔍 Start Trace")
        self.trace_btn.setObjectName("primaryButton")
        self.trace_btn.clicked.connect(self._start_trace)
        layout.addWidget(self.trace_btn)
        
        return frame
    
    def _create_tracing_tab(self) -> QWidget:
        """Create transaction tracing tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Configuration
        left_panel = QFrame()
        left_panel.setObjectName("configPanel")
        left_layout = QVBoxLayout(left_panel)
        
        # Address input
        address_group = QGroupBox("Target Address")
        address_layout = QVBoxLayout(address_group)
        
        address_layout.addWidget(QLabel("Blockchain:"))
        self.chain_combo = QComboBox()
        self.chain_combo.addItems([
            "Bitcoin (BTC)", "Ethereum (ETH)", "Bitcoin Cash (BCH)",
            "Litecoin (LTC)", "Monero (XMR)", "Zcash (ZEC)",
            "Binance Smart Chain", "Polygon", "Solana"
        ])
        address_layout.addWidget(self.chain_combo)
        
        address_layout.addWidget(QLabel("Address / Transaction Hash:"))
        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("Enter wallet address or tx hash...")
        address_layout.addWidget(self.address_input)
        
        left_layout.addWidget(address_group)
        
        # Tracing options
        options_group = QGroupBox("Tracing Options")
        options_layout = QVBoxLayout(options_group)
        
        options_layout.addWidget(QLabel("Trace Depth:"))
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 10)
        self.depth_spin.setValue(3)
        self.depth_spin.setSuffix(" hops")
        options_layout.addWidget(self.depth_spin)
        
        options_layout.addWidget(QLabel("Minimum Amount:"))
        self.min_amount = QDoubleSpinBox()
        self.min_amount.setRange(0, 1000000)
        self.min_amount.setValue(0.01)
        self.min_amount.setDecimals(8)
        options_layout.addWidget(self.min_amount)
        
        self.follow_mixers = QCheckBox("Follow through mixers/tumblers")
        self.follow_mixers.setChecked(True)
        options_layout.addWidget(self.follow_mixers)
        
        self.detect_exchanges = QCheckBox("Detect exchange deposits")
        self.detect_exchanges.setChecked(True)
        options_layout.addWidget(self.detect_exchanges)
        
        self.cluster_analysis = QCheckBox("Enable cluster analysis")
        self.cluster_analysis.setChecked(True)
        options_layout.addWidget(self.cluster_analysis)
        
        left_layout.addWidget(options_group)
        
        # Trace button
        trace_layout = QHBoxLayout()
        self.start_trace_btn = QPushButton("🔍 Start Trace")
        self.start_trace_btn.setObjectName("primaryButton")
        self.start_trace_btn.clicked.connect(self._start_trace)
        trace_layout.addWidget(self.start_trace_btn)
        
        self.stop_trace_btn = QPushButton("⏹ Stop")
        self.stop_trace_btn.setEnabled(False)
        trace_layout.addWidget(self.stop_trace_btn)
        left_layout.addLayout(trace_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        left_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888;")
        left_layout.addWidget(self.status_label)
        
        left_layout.addStretch()
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = QFrame()
        right_panel.setObjectName("resultsPanel")
        right_layout = QVBoxLayout(right_panel)
        
        # Transaction tree
        right_layout.addWidget(QLabel("Transaction Flow:"))
        
        self.tx_tree = QTreeWidget()
        self.tx_tree.setHeaderLabels([
            "Transaction", "Amount", "Direction", "Timestamp", "Status"
        ])
        self.tx_tree.itemClicked.connect(self._show_tx_details)
        
        # Sample data
        root = QTreeWidgetItem([
            "1A1zP1...npF", "50.00 BTC", "Root", "2009-01-03", "Genesis"
        ])
        
        child1 = QTreeWidgetItem([
            "1BvBM...Gys", "25.00 BTC", "→ Out", "2009-01-09", "Confirmed"
        ])
        child2 = QTreeWidgetItem([
            "3J98t...ySk", "25.00 BTC", "→ Out", "2009-01-10", "Confirmed"
        ])
        
        subchild = QTreeWidgetItem([
            "bc1qar...Mf", "10.00 BTC", "→ Out", "2009-01-15", "Exchange"
        ])
        subchild.setForeground(4, QColor("#f7931a"))
        child1.addChild(subchild)
        
        root.addChild(child1)
        root.addChild(child2)
        self.tx_tree.addTopLevelItem(root)
        self.tx_tree.expandAll()
        
        right_layout.addWidget(self.tx_tree)
        
        # Transaction details
        details_group = QGroupBox("Transaction Details")
        details_layout = QVBoxLayout(details_group)
        self.tx_details = QTextEdit()
        self.tx_details.setReadOnly(True)
        self.tx_details.setMaximumHeight(150)
        details_layout.addWidget(self.tx_details)
        right_layout.addWidget(details_group)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([350, 650])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_wallet_tab(self) -> QWidget:
        """Create wallet analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Wallet input
        input_layout = QHBoxLayout()
        
        self.wallet_input = QLineEdit()
        self.wallet_input.setPlaceholderText("Enter wallet address...")
        input_layout.addWidget(self.wallet_input)
        
        analyze_btn = QPushButton("🔍 Analyze Wallet")
        analyze_btn.setObjectName("primaryButton")
        analyze_btn.clicked.connect(self._analyze_wallet)
        input_layout.addWidget(analyze_btn)
        
        layout.addLayout(input_layout)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Wallet info
        info_panel = QFrame()
        info_layout = QVBoxLayout(info_panel)
        
        # Wallet profile
        profile_group = QGroupBox("Wallet Profile")
        profile_layout = QGridLayout(profile_group)
        
        profiles = [
            ("Address", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            ("Balance", "68.59 BTC ($4.2M)"),
            ("First Seen", "2009-01-03 18:15:05"),
            ("Last Activity", "2024-02-15 09:32:11"),
            ("Total Received", "99.67 BTC"),
            ("Total Sent", "31.08 BTC"),
            ("Transaction Count", "1,247"),
            ("Cluster ID", "CL-00001 (Satoshi)"),
        ]
        
        for i, (label, value) in enumerate(profiles):
            lbl = QLabel(label + ":")
            lbl.setStyleSheet("color: #888;")
            profile_layout.addWidget(lbl, i, 0)
            
            val = QLabel(value)
            val.setStyleSheet("color: #f7931a;" if "BTC" in value else "color: #fff;")
            profile_layout.addWidget(val, i, 1)
        
        info_layout.addWidget(profile_group)
        
        # Risk assessment
        risk_group = QGroupBox("Risk Assessment")
        risk_layout = QVBoxLayout(risk_group)
        
        risks = [
            ("Darknet Market", "Low", "#00ff88"),
            ("Mixer/Tumbler", "None", "#00ff88"),
            ("Ransomware", "None", "#00ff88"),
            ("Sanctioned Entity", "None", "#00ff88"),
            ("Exchange Connection", "High", "#f7931a"),
        ]
        
        for name, level, color in risks:
            risk_frame = QFrame()
            risk_h = QHBoxLayout(risk_frame)
            risk_h.setContentsMargins(0, 0, 0, 0)
            
            name_label = QLabel(name + ":")
            risk_h.addWidget(name_label)
            risk_h.addStretch()
            
            level_label = QLabel(level)
            level_label.setStyleSheet(f"color: {color}; font-weight: bold;")
            risk_h.addWidget(level_label)
            
            risk_layout.addWidget(risk_frame)
        
        info_layout.addWidget(risk_group)
        info_layout.addStretch()
        
        splitter.addWidget(info_panel)
        
        # Right - Transaction history
        history_panel = QFrame()
        history_layout = QVBoxLayout(history_panel)
        
        history_layout.addWidget(QLabel("Recent Transactions:"))
        
        self.wallet_tx_table = QTableWidget()
        self.wallet_tx_table.setColumnCount(5)
        self.wallet_tx_table.setHorizontalHeaderLabels([
            "Date", "Type", "Amount", "Counterparty", "Status"
        ])
        self.wallet_tx_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        transactions = [
            ("2024-02-15", "Received", "+0.5 BTC", "3J98t...nV9", "Confirmed"),
            ("2024-02-14", "Sent", "-0.25 BTC", "bc1q...2mf", "Confirmed"),
            ("2024-02-13", "Received", "+1.0 BTC", "1Pz...Ky9", "Confirmed"),
            ("2024-02-12", "Sent", "-0.1 BTC", "3Kz...Hj7", "Confirmed"),
            ("2024-02-11", "Received", "+0.75 BTC", "1Mn...Qw3", "Confirmed"),
        ]
        
        self.wallet_tx_table.setRowCount(len(transactions))
        for row, tx in enumerate(transactions):
            for col, value in enumerate(tx):
                item = QTableWidgetItem(value)
                if col == 1:  # Type
                    if value == "Received":
                        item.setForeground(QColor("#00ff88"))
                    else:
                        item.setForeground(QColor("#ff4444"))
                elif col == 2:  # Amount
                    if "+" in value:
                        item.setForeground(QColor("#00ff88"))
                    else:
                        item.setForeground(QColor("#ff4444"))
                self.wallet_tx_table.setItem(row, col, item)
        
        history_layout.addWidget(self.wallet_tx_table)
        
        splitter.addWidget(history_panel)
        layout.addWidget(splitter)
        
        return widget
    
    def _create_cluster_tab(self) -> QWidget:
        """Create cluster analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Cluster controls
        controls = QHBoxLayout()
        
        self.cluster_input = QLineEdit()
        self.cluster_input.setPlaceholderText("Enter address to find cluster...")
        controls.addWidget(self.cluster_input)
        
        find_btn = QPushButton("🔍 Find Cluster")
        find_btn.clicked.connect(self._find_cluster)
        controls.addWidget(find_btn)
        
        controls.addStretch()
        
        export_btn = QPushButton("📤 Export Cluster")
        controls.addWidget(export_btn)
        
        layout.addLayout(controls)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Cluster list
        cluster_panel = QFrame()
        cluster_layout = QVBoxLayout(cluster_panel)
        
        cluster_layout.addWidget(QLabel("Identified Clusters:"))
        
        self.cluster_list = QListWidget()
        
        clusters = [
            "🏦 Binance Hot Wallet (847 addresses)",
            "🏦 Coinbase (523 addresses)",
            "🎰 Online Casino (156 addresses)",
            "⚠️ Suspected Mixer (89 addresses)",
            "🔒 Ransomware (12 addresses)",
        ]
        
        for cluster in clusters:
            self.cluster_list.addItem(cluster)
        
        self.cluster_list.itemClicked.connect(self._show_cluster)
        cluster_layout.addWidget(self.cluster_list)
        
        splitter.addWidget(cluster_panel)
        
        # Right - Cluster details
        details_panel = QFrame()
        details_layout = QVBoxLayout(details_panel)
        
        # Cluster info
        info_group = QGroupBox("Cluster Information")
        info_layout = QGridLayout(info_group)
        
        info_data = [
            ("Cluster ID", "CL-00042"),
            ("Entity Type", "Exchange"),
            ("Total Addresses", "847"),
            ("Total Volume", "125,847.32 BTC"),
            ("First Transaction", "2017-12-15"),
            ("Confidence", "98.7%"),
        ]
        
        for i, (label, value) in enumerate(info_data):
            lbl = QLabel(label + ":")
            lbl.setStyleSheet("color: #888;")
            info_layout.addWidget(lbl, i, 0)
            
            val = QLabel(value)
            info_layout.addWidget(val, i, 1)
        
        details_layout.addWidget(info_group)
        
        # Cluster addresses
        addr_group = QGroupBox("Cluster Addresses")
        addr_layout = QVBoxLayout(addr_group)
        
        self.cluster_addr_table = QTableWidget()
        self.cluster_addr_table.setColumnCount(4)
        self.cluster_addr_table.setHorizontalHeaderLabels([
            "Address", "Balance", "Transactions", "Role"
        ])
        self.cluster_addr_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        addresses = [
            ("3Kz...Hj7", "1,247.5 BTC", "12,456", "Hot Wallet"),
            ("1Pz...Ky9", "856.2 BTC", "8,932", "Deposit"),
            ("bc1...2mf", "425.1 BTC", "5,621", "Deposit"),
            ("3J9...nV9", "312.8 BTC", "3,214", "Withdrawal"),
        ]
        
        self.cluster_addr_table.setRowCount(len(addresses))
        for row, addr in enumerate(addresses):
            for col, value in enumerate(addr):
                self.cluster_addr_table.setItem(row, col, QTableWidgetItem(value))
        
        addr_layout.addWidget(self.cluster_addr_table)
        details_layout.addWidget(addr_group)
        
        splitter.addWidget(details_panel)
        layout.addWidget(splitter)
        
        return widget
    
    def _create_mixer_tab(self) -> QWidget:
        """Create mixer detection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Mixer detection controls
        controls = QHBoxLayout()
        
        self.mixer_input = QLineEdit()
        self.mixer_input.setPlaceholderText("Enter transaction hash to trace through mixers...")
        controls.addWidget(self.mixer_input)
        
        detect_btn = QPushButton("🌀 Detect Mixer")
        detect_btn.setObjectName("primaryButton")
        detect_btn.clicked.connect(self._detect_mixer)
        controls.addWidget(detect_btn)
        
        layout.addLayout(controls)
        
        # Mixer analysis results
        analysis_group = QGroupBox("Mixer Analysis")
        analysis_layout = QVBoxLayout(analysis_group)
        
        self.mixer_table = QTableWidget()
        self.mixer_table.setColumnCount(6)
        self.mixer_table.setHorizontalHeaderLabels([
            "Transaction", "Mixer Type", "Input Amount", "Output Addresses",
            "Delay", "Confidence"
        ])
        self.mixer_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        mixers = [
            ("0x7f2...8a3", "CoinJoin", "2.5 BTC", "47", "~2 hours", "94%"),
            ("0x4d1...9c2", "Wasabi", "1.0 BTC", "23", "~4 hours", "89%"),
            ("0x8e3...1b7", "Tornado Cash", "10 ETH", "100", "~24 hours", "97%"),
        ]
        
        self.mixer_table.setRowCount(len(mixers))
        for row, mixer in enumerate(mixers):
            for col, value in enumerate(mixer):
                item = QTableWidgetItem(value)
                if col == 5:  # Confidence
                    conf = int(value.replace("%", ""))
                    if conf >= 90:
                        item.setForeground(QColor("#ff4444"))
                    elif conf >= 80:
                        item.setForeground(QColor("#ff8800"))
                self.mixer_table.setItem(row, col, item)
        
        analysis_layout.addWidget(self.mixer_table)
        layout.addWidget(analysis_group)
        
        # Mixer patterns
        patterns_group = QGroupBox("Known Mixer Patterns")
        patterns_layout = QVBoxLayout(patterns_group)
        
        self.patterns_text = QTextEdit()
        self.patterns_text.setReadOnly(True)
        self.patterns_text.setHtml("""
<h3>Detected Mixer Patterns</h3>

<h4>🌀 CoinJoin Detection:</h4>
<ul>
<li>Multiple inputs from different addresses</li>
<li>Equal output amounts (2.5 BTC each)</li>
<li>Same transaction timing</li>
</ul>

<h4>🌀 Wasabi Wallet Indicators:</h4>
<ul>
<li>Coordinator fee pattern detected</li>
<li>Standard mixing denomination (0.1 BTC)</li>
<li>Typical round structure</li>
</ul>

<h4>⚠️ Risk Assessment:</h4>
<p>Funds have passed through <b>2 mixing services</b> with high confidence.</p>
<p>Original source tracing may be difficult but not impossible.</p>
""")
        patterns_layout.addWidget(self.patterns_text)
        layout.addWidget(patterns_group)
        
        return widget
    
    def _create_reports_tab(self) -> QWidget:
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Report controls
        controls = QHBoxLayout()
        
        self.report_search = QLineEdit()
        self.report_search.setPlaceholderText("Search investigations...")
        controls.addWidget(self.report_search)
        
        chain_filter = QComboBox()
        chain_filter.addItems(["All Chains", "Bitcoin", "Ethereum", "Other"])
        controls.addWidget(chain_filter)
        
        controls.addStretch()
        
        new_report_btn = QPushButton("📝 New Report")
        new_report_btn.setObjectName("primaryButton")
        controls.addWidget(new_report_btn)
        
        layout.addLayout(controls)
        
        # Reports table
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(6)
        self.reports_table.setHorizontalHeaderLabels([
            "Case ID", "Subject", "Chain", "Amount Traced", "Status", "Date"
        ])
        self.reports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        reports = [
            ("CASE-001", "Ransomware Investigation", "BTC", "15.5 BTC", "Completed", "2024-02-15"),
            ("CASE-002", "Exchange Theft", "ETH", "2,500 ETH", "In Progress", "2024-02-14"),
            ("CASE-003", "Money Laundering", "BTC", "125 BTC", "In Progress", "2024-02-13"),
            ("CASE-004", "Fraud Investigation", "USDT", "$1.2M", "Completed", "2024-02-10"),
        ]
        
        self.reports_table.setRowCount(len(reports))
        for row, report in enumerate(reports):
            for col, value in enumerate(report):
                item = QTableWidgetItem(value)
                if col == 4:  # Status
                    if value == "Completed":
                        item.setForeground(QColor("#00ff88"))
                    else:
                        item.setForeground(QColor("#f7931a"))
                self.reports_table.setItem(row, col, item)
        
        layout.addWidget(self.reports_table)
        
        # Statistics
        stats_layout = QHBoxLayout()
        
        for label, value, color in [
            ("Total Cases", "47", "#00d4ff"),
            ("Amount Traced", "2,847 BTC", "#f7931a"),
            ("Recovered", "$12.5M", "#00ff88"),
            ("Active Cases", "12", "#ff8800")
        ]:
            stat_frame = QFrame()
            stat_frame.setObjectName("statCard")
            stat_v = QVBoxLayout(stat_frame)
            
            val = QLabel(value)
            val.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
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
                    stop:0 #2d2a1f, stop:1 #1a1a2e);
                border-radius: 10px;
                padding: 15px;
            }
            
            QFrame#configPanel, QFrame#resultsPanel {
                background-color: #16213e;
                border-radius: 8px;
                padding: 10px;
            }
            
            QFrame#statCard {
                background-color: #16213e;
                border: 1px solid #0f3460;
                border-radius: 8px;
                padding: 15px;
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
                    stop:0 #f7931a, stop:1 #d4790e);
                color: #000;
            }
            
            QPushButton#primaryButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ffa42b, stop:1 #e5891f);
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
                border-bottom: 2px solid #f7931a;
                font-weight: bold;
            }
            
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
            
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #f7931a;
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
                    stop:0 #f7931a, stop:1 #00ff88);
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
                border-bottom: 2px solid #f7931a;
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
            
            QListWidget {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QListWidget::item {
                padding: 10px;
            }
            
            QListWidget::item:selected {
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
                background-color: #f7931a;
                border-color: #f7931a;
            }
        """)
    
    def _start_trace(self):
        """Start blockchain trace"""
        address = self.address_input.text()
        if not address:
            self.status_label.setText("Please enter an address")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.start_trace_btn.setEnabled(False)
        self.stop_trace_btn.setEnabled(True)
        self.status_label.setText("Tracing transactions...")
        
        self.worker = BlockchainTraceWorker(
            self.analyzer, address, self.depth_spin.value()
        )
        self.worker.progress.connect(lambda v: self.progress_bar.setValue(v))
        self.worker.result.connect(self._handle_trace_result)
        self.worker.finished.connect(self._trace_finished)
        self.worker.start()
    
    def _handle_trace_result(self, result):
        """Handle trace results"""
        if "error" in result:
            self.status_label.setText(f"Error: {result['error']}")
            return
        
        self.status_label.setText(
            f"Found {result['transactions']} transactions in {result['clusters']} clusters"
        )
    
    def _trace_finished(self):
        """Handle trace completion"""
        self.progress_bar.setVisible(False)
        self.start_trace_btn.setEnabled(True)
        self.stop_trace_btn.setEnabled(False)
    
    def _show_tx_details(self, item, column):
        """Show transaction details"""
        tx = item.text(0)
        self.tx_details.setHtml(f"""
<h3>Transaction: {tx}</h3>
<p><b>Hash:</b> {tx}...</p>
<p><b>Block:</b> 123456</p>
<p><b>Confirmations:</b> 750,000+</p>
<p><b>Fee:</b> 0.0001 BTC</p>
<p><b>Size:</b> 226 bytes</p>
""")
    
    def _analyze_wallet(self):
        """Analyze wallet"""
        self.status_label.setText("Analyzing wallet...")
    
    def _find_cluster(self):
        """Find cluster for address"""
        self.status_label.setText("Finding cluster...")
    
    def _show_cluster(self, item):
        """Show cluster details"""
        pass
    
    def _detect_mixer(self):
        """Detect mixer usage"""
        self.status_label.setText("Detecting mixer patterns...")
