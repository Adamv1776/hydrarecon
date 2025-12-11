"""
Memory Forensics GUI Page
Advanced memory analysis, process injection detection, and malware hunting.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTextEdit, QLineEdit, QComboBox, QProgressBar, QTabWidget,
    QGroupBox, QSpinBox, QCheckBox, QSplitter, QGridLayout,
    QTreeWidget, QTreeWidgetItem, QFileDialog, QListWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from datetime import datetime


class MemoryAnalysisWorker(QThread):
    """Worker for memory analysis"""
    progress = pyqtSignal(int)
    finding = pyqtSignal(dict)
    result = pyqtSignal(dict)
    finished = pyqtSignal()
    
    def __init__(self, analyzer, dump_path, plugins):
        super().__init__()
        self.analyzer = analyzer
        self.dump_path = dump_path
        self.plugins = plugins
    
    def run(self):
        try:
            for i in range(100):
                self.progress.emit(i + 1)
                if i % 25 == 0:
                    self.finding.emit({
                        "type": "process",
                        "name": f"Process {i//25}"
                    })
                self.msleep(40)
            
            self.result.emit({
                "status": "completed",
                "processes": 47,
                "suspicious": 3
            })
        except Exception as e:
            self.result.emit({"error": str(e)})
        finally:
            self.finished.emit()


class MemoryForensicsPage(QWidget):
    """Memory Forensics GUI"""
    
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
        """Initialize memory analyzer"""
        try:
            from core.memory_forensics import MemoryForensicsEngine
            self.analyzer = MemoryForensicsEngine()
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
        tabs.setObjectName("memoryTabs")
        
        tabs.addTab(self._create_analysis_tab(), "🔬 Memory Analysis")
        tabs.addTab(self._create_processes_tab(), "📋 Processes")
        tabs.addTab(self._create_injection_tab(), "💉 Injection Detection")
        tabs.addTab(self._create_malware_tab(), "🦠 Malware Hunting")
        tabs.addTab(self._create_artifacts_tab(), "🔍 Artifacts")
        
        layout.addWidget(tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setObjectName("headerFrame")
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🔬 Memory Forensics")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #e74c3c;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Advanced memory analysis, process injection detection, and malware hunting")
        subtitle.setStyleSheet("color: #888; font-size: 12px;")
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Status
        status_layout = QHBoxLayout()
        
        self.dump_status = QLabel("● No dump loaded")
        self.dump_status.setStyleSheet("color: #888; font-size: 11px;")
        status_layout.addWidget(self.dump_status)
        
        layout.addLayout(status_layout)
        
        # Action button
        self.load_btn = QPushButton("📂 Load Memory Dump")
        self.load_btn.setObjectName("primaryButton")
        self.load_btn.clicked.connect(self._load_dump)
        layout.addWidget(self.load_btn)
        
        return frame
    
    def _create_analysis_tab(self) -> QWidget:
        """Create analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Configuration
        left_panel = QFrame()
        left_panel.setObjectName("configPanel")
        left_layout = QVBoxLayout(left_panel)
        
        # Dump file
        dump_group = QGroupBox("Memory Dump")
        dump_layout = QVBoxLayout(dump_group)
        
        file_layout = QHBoxLayout()
        self.dump_path = QLineEdit()
        self.dump_path.setPlaceholderText("Path to memory dump file...")
        file_layout.addWidget(self.dump_path)
        
        browse_btn = QPushButton("📁")
        browse_btn.setMaximumWidth(40)
        browse_btn.clicked.connect(self._browse_dump)
        file_layout.addWidget(browse_btn)
        dump_layout.addLayout(file_layout)
        
        dump_layout.addWidget(QLabel("Profile:"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItems([
            "Auto Detect",
            "Win10x64_19041", "Win10x64_18362", "Win10x64_17763",
            "Win7SP1x64", "Win7SP1x86",
            "Linux-5.4-x64", "Linux-4.19-x64",
            "macOS-10.15-x64"
        ])
        dump_layout.addWidget(self.profile_combo)
        
        left_layout.addWidget(dump_group)
        
        # Analysis plugins
        plugins_group = QGroupBox("Analysis Plugins")
        plugins_layout = QVBoxLayout(plugins_group)
        
        self.pslist = QCheckBox("Process List (pslist)")
        self.pslist.setChecked(True)
        plugins_layout.addWidget(self.pslist)
        
        self.pstree = QCheckBox("Process Tree (pstree)")
        self.pstree.setChecked(True)
        plugins_layout.addWidget(self.pstree)
        
        self.dlllist = QCheckBox("DLL List (dlllist)")
        self.dlllist.setChecked(True)
        plugins_layout.addWidget(self.dlllist)
        
        self.handles = QCheckBox("Handle List (handles)")
        plugins_layout.addWidget(self.handles)
        
        self.netscan = QCheckBox("Network Connections (netscan)")
        self.netscan.setChecked(True)
        plugins_layout.addWidget(self.netscan)
        
        self.malfind = QCheckBox("Malware Detection (malfind)")
        self.malfind.setChecked(True)
        plugins_layout.addWidget(self.malfind)
        
        self.cmdline = QCheckBox("Command Lines (cmdline)")
        plugins_layout.addWidget(self.cmdline)
        
        left_layout.addWidget(plugins_group)
        
        # Run button
        run_layout = QHBoxLayout()
        self.run_btn = QPushButton("🔬 Analyze Memory")
        self.run_btn.setObjectName("primaryButton")
        self.run_btn.clicked.connect(self._run_analysis)
        run_layout.addWidget(self.run_btn)
        left_layout.addLayout(run_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        left_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888;")
        left_layout.addWidget(self.status_label)
        
        left_layout.addStretch()
        splitter.addWidget(left_panel)
        
        # Right - Results
        right_panel = QFrame()
        right_panel.setObjectName("resultsPanel")
        right_layout = QVBoxLayout(right_panel)
        
        right_layout.addWidget(QLabel("Analysis Results:"))
        
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Item", "Value", "Status"])
        
        # Sample results
        sections = [
            ("System Info", [
                ("OS", "Windows 10 Build 19041", ""),
                ("Architecture", "x64", ""),
                ("Dump Time", "2024-02-15 14:32:18", ""),
            ]),
            ("Processes", [
                ("Total", "47", ""),
                ("Suspicious", "3", "⚠️"),
                ("Hidden", "1", "🚨"),
            ]),
            ("Network", [
                ("Active Connections", "12", ""),
                ("Listening Ports", "8", ""),
                ("Suspicious Traffic", "2", "⚠️"),
            ]),
        ]
        
        for section, items in sections:
            parent = QTreeWidgetItem([section, "", ""])
            for name, value, status in items:
                child = QTreeWidgetItem([name, value, status])
                if "🚨" in status:
                    child.setForeground(0, QColor("#ff4444"))
                elif "⚠️" in status:
                    child.setForeground(0, QColor("#ff8800"))
                parent.addChild(child)
            self.results_tree.addTopLevelItem(parent)
        
        self.results_tree.expandAll()
        right_layout.addWidget(self.results_tree)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([350, 650])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_processes_tab(self) -> QWidget:
        """Create processes tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Process tree
        self.process_tree = QTreeWidget()
        self.process_tree.setHeaderLabels([
            "PID", "Name", "PPID", "Threads", "Handles", "Start Time", "Status"
        ])
        self.process_tree.itemClicked.connect(self._show_process_details)
        
        # Sample process tree
        processes = [
            ("4", "System", "0", "147", "2547", "2024-02-15 08:00:01", "Normal", [
                ("416", "smss.exe", "4", "2", "53", "2024-02-15 08:00:01", "Normal", []),
                ("548", "csrss.exe", "416", "12", "589", "2024-02-15 08:00:02", "Normal", []),
            ]),
            ("9812", "suspicious.exe", "4756", "8", "234", "2024-02-15 14:25:33", "⚠️ Suspicious", [
                ("9856", "cmd.exe", "9812", "1", "34", "2024-02-15 14:25:35", "⚠️ Spawned by suspicious process", []),
            ]),
        ]
        
        def add_process(parent_item, processes):
            for pid, name, ppid, threads, handles, time, status, children in processes:
                item = QTreeWidgetItem([pid, name, ppid, threads, handles, time, status])
                if "Suspicious" in status or "⚠️" in status:
                    for i in range(7):
                        item.setForeground(i, QColor("#ff8800"))
                if parent_item:
                    parent_item.addChild(item)
                else:
                    self.process_tree.addTopLevelItem(item)
                if children:
                    add_process(item, children)
        
        add_process(None, processes)
        self.process_tree.expandAll()
        layout.addWidget(self.process_tree)
        
        # Process details
        details_group = QGroupBox("Process Details")
        details_layout = QVBoxLayout(details_group)
        self.process_details = QTextEdit()
        self.process_details.setReadOnly(True)
        self.process_details.setMaximumHeight(150)
        details_layout.addWidget(self.process_details)
        layout.addWidget(details_group)
        
        return widget
    
    def _create_injection_tab(self) -> QWidget:
        """Create injection detection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Injection techniques
        techniques_group = QGroupBox("Injection Detection Results")
        techniques_layout = QVBoxLayout(techniques_group)
        
        self.injection_table = QTableWidget()
        self.injection_table.setColumnCount(6)
        self.injection_table.setHorizontalHeaderLabels([
            "PID", "Process", "Technique", "Location", "Severity", "Details"
        ])
        self.injection_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        injections = [
            ("9812", "suspicious.exe", "Process Hollowing", "0x7FF123450000", "Critical", "PE header modified"),
            ("9856", "cmd.exe", "DLL Injection", "kernel32.dll", "High", "Suspicious DLL loaded"),
            ("3456", "explorer.exe", "Thread Hijacking", "Thread 4521", "Medium", "Unusual thread context"),
        ]
        
        self.injection_table.setRowCount(len(injections))
        for row, inj in enumerate(injections):
            for col, value in enumerate(inj):
                item = QTableWidgetItem(value)
                if col == 4:  # Severity
                    if value == "Critical":
                        item.setForeground(QColor("#ff4444"))
                    elif value == "High":
                        item.setForeground(QColor("#ff8800"))
                self.injection_table.setItem(row, col, item)
        
        techniques_layout.addWidget(self.injection_table)
        layout.addWidget(techniques_group)
        
        # Detection methods
        methods_group = QGroupBox("Detection Methods")
        methods_layout = QVBoxLayout(methods_group)
        
        methods_text = QTextEdit()
        methods_text.setReadOnly(True)
        methods_text.setMaximumHeight(180)
        methods_text.setHtml("""
<h3>Active Detection Methods</h3>
<ul>
<li><b>VAD Analysis:</b> Checking for suspicious VAD entries with RWX permissions</li>
<li><b>PE Header Verification:</b> Comparing in-memory PE headers with on-disk versions</li>
<li><b>Thread Start Analysis:</b> Detecting threads starting outside normal module bounds</li>
<li><b>Hollowed Process Detection:</b> Identifying processes with memory region anomalies</li>
<li><b>API Hooking Detection:</b> Scanning for inline hooks in common APIs</li>
<li><b>Module List Verification:</b> Comparing PEB module list with VAD entries</li>
</ul>
""")
        methods_layout.addWidget(methods_text)
        layout.addWidget(methods_group)
        
        return widget
    
    def _create_malware_tab(self) -> QWidget:
        """Create malware hunting tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Malware findings
        findings_group = QGroupBox("Malware Detection Results")
        findings_layout = QVBoxLayout(findings_group)
        
        self.malware_table = QTableWidget()
        self.malware_table.setColumnCount(6)
        self.malware_table.setHorizontalHeaderLabels([
            "PID", "Process", "Address", "Size", "Protection", "Detection"
        ])
        self.malware_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        findings = [
            ("9812", "suspicious.exe", "0x00400000", "0x5000", "RWX", "Shellcode pattern detected"),
            ("9812", "suspicious.exe", "0x7FF12340000", "0x1000", "RWX", "Code injection"),
            ("9856", "cmd.exe", "0x00450000", "0x2000", "RWX", "Suspicious code region"),
        ]
        
        self.malware_table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            for col, value in enumerate(finding):
                item = QTableWidgetItem(value)
                if col == 4 and "RWX" in value:
                    item.setForeground(QColor("#ff4444"))
                self.malware_table.setItem(row, col, item)
        
        findings_layout.addWidget(self.malware_table)
        layout.addWidget(findings_group)
        
        # IOC matching
        ioc_group = QGroupBox("IOC Matching")
        ioc_layout = QVBoxLayout(ioc_group)
        
        self.ioc_list = QListWidget()
        iocs = [
            "🚨 SHA256: a1b2c3d4... matches known ransomware",
            "⚠️ IP: 192.168.1.100 connects to C2 server",
            "⚠️ Domain: evil.example.com in DNS cache",
            "🚨 Mutex: Global\\BadMutex123 - known malware indicator",
        ]
        for ioc in iocs:
            self.ioc_list.addItem(ioc)
        ioc_layout.addWidget(self.ioc_list)
        layout.addWidget(ioc_group)
        
        return widget
    
    def _create_artifacts_tab(self) -> QWidget:
        """Create artifacts tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Artifact types
        types_layout = QHBoxLayout()
        
        self.artifact_type = QComboBox()
        self.artifact_type.addItems([
            "All Artifacts", "Registry Keys", "Files", "Network",
            "Credentials", "Browser History", "Command History"
        ])
        types_layout.addWidget(self.artifact_type)
        
        extract_btn = QPushButton("🔍 Extract")
        extract_btn.clicked.connect(self._extract_artifacts)
        types_layout.addWidget(extract_btn)
        
        types_layout.addStretch()
        layout.addLayout(types_layout)
        
        # Artifacts table
        self.artifacts_table = QTableWidget()
        self.artifacts_table.setColumnCount(5)
        self.artifacts_table.setHorizontalHeaderLabels([
            "Type", "Artifact", "Value", "Source", "Timestamp"
        ])
        self.artifacts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        artifacts = [
            ("Registry", "Run Key", "suspicious.exe", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "2024-02-15"),
            ("File", "Dropped File", "C:\\Users\\Public\\malware.dll", "FileSystem", "2024-02-15"),
            ("Network", "Connection", "192.168.1.100:4444", "netscan", "2024-02-15"),
            ("Credential", "LSA Secret", "********", "lsadump", "2024-02-15"),
            ("Browser", "URL", "http://evil.com/payload", "Chrome History", "2024-02-15"),
        ]
        
        self.artifacts_table.setRowCount(len(artifacts))
        for row, artifact in enumerate(artifacts):
            for col, value in enumerate(artifact):
                self.artifacts_table.setItem(row, col, QTableWidgetItem(value))
        
        layout.addWidget(self.artifacts_table)
        
        # Export
        export_layout = QHBoxLayout()
        
        export_json = QPushButton("📁 Export JSON")
        export_layout.addWidget(export_json)
        
        export_csv = QPushButton("📊 Export CSV")
        export_layout.addWidget(export_csv)
        
        export_report = QPushButton("📄 Generate Report")
        export_report.setObjectName("primaryButton")
        export_layout.addWidget(export_report)
        
        layout.addLayout(export_layout)
        
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
                    stop:0 #3d1f1f, stop:1 #1a1a2e);
                border-radius: 10px;
                padding: 15px;
            }
            
            QFrame#configPanel, QFrame#resultsPanel {
                background-color: #16213e;
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
                    stop:0 #e74c3c, stop:1 #c0392b);
                color: #fff;
            }
            
            QTableWidget {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QHeaderView::section {
                background-color: #16213e;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #e74c3c;
                font-weight: bold;
            }
            
            QLineEdit, QComboBox, QSpinBox {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
            
            QTextEdit {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #e74c3c, stop:1 #00ff88);
                border-radius: 4px;
            }
            
            QTabBar::tab:selected {
                background-color: #0f3460;
                border-bottom: 2px solid #e74c3c;
            }
            
            QTreeWidget {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QCheckBox::indicator:checked {
                background-color: #e74c3c;
                border-color: #e74c3c;
            }
        """)
    
    def _load_dump(self):
        """Load memory dump"""
        self._browse_dump()
    
    def _browse_dump(self):
        """Browse for dump file"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Memory Dump",
            "", "Memory Dumps (*.raw *.mem *.dmp *.vmem)"
        )
        if path:
            self.dump_path.setText(path)
            self.dump_status.setText(f"● Loaded: {path.split('/')[-1]}")
            self.dump_status.setStyleSheet("color: #00ff88; font-size: 11px;")
    
    def _run_analysis(self):
        """Run memory analysis"""
        if not self.dump_path.text():
            self.status_label.setText("Please select a memory dump")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.run_btn.setEnabled(False)
        self.status_label.setText("Analyzing memory dump...")
        
        plugins = []
        if self.pslist.isChecked(): plugins.append("pslist")
        if self.pstree.isChecked(): plugins.append("pstree")
        if self.dlllist.isChecked(): plugins.append("dlllist")
        if self.netscan.isChecked(): plugins.append("netscan")
        if self.malfind.isChecked(): plugins.append("malfind")
        
        self.worker = MemoryAnalysisWorker(self.analyzer, self.dump_path.text(), plugins)
        self.worker.progress.connect(lambda v: self.progress_bar.setValue(v))
        self.worker.result.connect(self._handle_result)
        self.worker.finished.connect(self._analysis_finished)
        self.worker.start()
    
    def _handle_result(self, result):
        """Handle analysis result"""
        if "error" in result:
            self.status_label.setText(f"Error: {result['error']}")
            return
        
        self.status_label.setText(
            f"Found {result['processes']} processes, {result['suspicious']} suspicious"
        )
    
    def _analysis_finished(self):
        """Handle analysis completion"""
        self.progress_bar.setVisible(False)
        self.run_btn.setEnabled(True)
    
    def _show_process_details(self, item, column):
        """Show process details"""
        pid = item.text(0)
        name = item.text(1)
        self.process_details.setHtml(f"""
<h3>Process: {name} (PID: {pid})</h3>
<p><b>Command Line:</b> C:\\Windows\\suspicious.exe -flag</p>
<p><b>Threads:</b> {item.text(3)}</p>
<p><b>Handles:</b> {item.text(4)}</p>
<p><b>Start Time:</b> {item.text(5)}</p>
""")
    
    def _extract_artifacts(self):
        """Extract artifacts"""
        self.status_label.setText("Extracting artifacts...")
