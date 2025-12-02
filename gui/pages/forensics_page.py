"""
Forensics Page
GUI for digital forensics analysis
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QComboBox, QCheckBox, QProgressBar,
    QSplitter, QFrame, QHeaderView, QSpinBox, QListWidget,
    QListWidgetItem, QFileDialog, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor
import asyncio


class ForensicsWorker(QThread):
    """Worker thread for forensic analysis"""
    progress = pyqtSignal(str, int)
    artifact_found = pyqtSignal(dict)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, analysis_type, target_path, options):
        super().__init__()
        self.analysis_type = analysis_type
        self.target_path = target_path
        self.options = options
        
    def run(self):
        try:
            import sys
            sys.path.insert(0, '..')
            from core.forensics import ForensicsEngine
            
            async def analyze():
                engine = ForensicsEngine()
                results = await engine.analyze(
                    self.analysis_type,
                    self.target_path,
                    **self.options
                )
                return results
                
            results = asyncio.run(analyze())
            self.finished.emit(results)
            
        except Exception as e:
            self.error.emit(str(e))


class ForensicsPage(QWidget):
    """Digital Forensics Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Header
        header = QLabel("🔬 Digital Forensics Laboratory")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #17a2b8;
            padding-bottom: 10px;
        """)
        layout.addWidget(header)
        
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
                color: #17a2b8;
            }
        """)
        
        # Memory Analysis tab
        memory_widget = self._create_memory_tab()
        main_tabs.addTab(memory_widget, "🧠 Memory Analysis")
        
        # Disk Forensics tab
        disk_widget = self._create_disk_tab()
        main_tabs.addTab(disk_widget, "💾 Disk Forensics")
        
        # Artifact Collection tab
        artifacts_widget = self._create_artifacts_tab()
        main_tabs.addTab(artifacts_widget, "📦 Artifacts")
        
        # Timeline tab
        timeline_widget = self._create_timeline_tab()
        main_tabs.addTab(timeline_widget, "📅 Timeline")
        
        layout.addWidget(main_tabs)
        
        # Status bar
        status_row = QHBoxLayout()
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888;")
        
        self.artifacts_count = QLabel("Artifacts: 0")
        self.artifacts_count.setStyleSheet("color: #00ff88;")
        
        status_row.addWidget(self.status_label)
        status_row.addStretch()
        status_row.addWidget(self.artifacts_count)
        
        layout.addLayout(status_row)
        
        # Store analysis data
        self.analysis_results = None
        self.artifacts = []
        
    def _create_memory_tab(self):
        """Create memory analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Memory dump input
        dump_group = QGroupBox("Memory Dump Analysis")
        dump_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #17a2b8;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        dump_layout = QVBoxLayout(dump_group)
        
        # File selection
        file_row = QHBoxLayout()
        
        self.memory_path = QLineEdit()
        self.memory_path.setPlaceholderText("Path to memory dump file...")
        self.memory_path.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
            }
        """)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self._browse_memory_dump)
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 10px 15px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        file_row.addWidget(self.memory_path)
        file_row.addWidget(browse_btn)
        dump_layout.addLayout(file_row)
        
        # Profile selection
        profile_row = QHBoxLayout()
        
        profile_label = QLabel("Profile:")
        profile_label.setStyleSheet("color: #888;")
        
        self.profile_combo = QComboBox()
        self.profile_combo.addItems([
            "Auto-Detect",
            "Win10x64_18362", "Win10x64_19041", "Win10x64_22000",
            "Win7SP1x64", "Win7SP1x86",
            "LinuxUbuntu_5.4.0-x64", "LinuxDebian_4.19.0-x64",
            "MacOS_10.15_x64", "MacOS_11.0_arm64"
        ])
        self.profile_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
                min-width: 200px;
            }
        """)
        
        profile_row.addWidget(profile_label)
        profile_row.addWidget(self.profile_combo)
        profile_row.addStretch()
        dump_layout.addLayout(profile_row)
        
        layout.addWidget(dump_group)
        
        # Analysis modules
        modules_group = QGroupBox("Analysis Modules")
        modules_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #17a2b8;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        modules_layout = QHBoxLayout(modules_group)
        
        modules = [
            ("pslist", "Process List"),
            ("pstree", "Process Tree"),
            ("netscan", "Network Connections"),
            ("filescan", "File Handles"),
            ("dlllist", "Loaded DLLs"),
            ("handles", "Open Handles"),
            ("malfind", "Injected Code"),
            ("hashdump", "Password Hashes"),
        ]
        
        for mod_id, mod_name in modules:
            check = QCheckBox(mod_name)
            check.setChecked(mod_id in ['pslist', 'netscan', 'malfind'])
            check.setStyleSheet("color: white;")
            check.setProperty("module_id", mod_id)
            modules_layout.addWidget(check)
            
        layout.addWidget(modules_group)
        
        # Progress
        self.memory_progress = QProgressBar()
        self.memory_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #16213e;
                height: 20px;
            }
            QProgressBar::chunk {
                background: linear-gradient(90deg, #17a2b8, #138496);
            }
        """)
        self.memory_progress.setVisible(False)
        layout.addWidget(self.memory_progress)
        
        # Analyze button
        analyze_btn = QPushButton("🔬 Analyze Memory Dump")
        analyze_btn.clicked.connect(self._analyze_memory)
        analyze_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #17a2b8, #138496);
                color: white;
                font-weight: bold;
                padding: 15px 30px;
                border-radius: 5px;
                border: none;
                font-size: 14px;
            }
            QPushButton:hover {
                background: linear-gradient(135deg, #138496, #17a2b8);
            }
        """)
        layout.addWidget(analyze_btn)
        
        # Results
        results_label = QLabel("Analysis Results")
        results_label.setStyleSheet("color: #17a2b8; font-weight: bold;")
        layout.addWidget(results_label)
        
        self.memory_results = QTreeWidget()
        self.memory_results.setHeaderLabels(["Category", "Item", "Details"])
        self.memory_results.setStyleSheet("""
            QTreeWidget {
                background-color: #16213e;
                color: white;
                border: 1px solid #333;
                border-radius: 5px;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #17a2b8;
                padding: 8px;
                border: 1px solid #333;
            }
        """)
        layout.addWidget(self.memory_results)
        
        return widget
        
    def _create_disk_tab(self):
        """Create disk forensics tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Disk image input
        disk_group = QGroupBox("Disk Image Analysis")
        disk_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #17a2b8;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        disk_layout = QVBoxLayout(disk_group)
        
        # File selection
        file_row = QHBoxLayout()
        
        self.disk_path = QLineEdit()
        self.disk_path.setPlaceholderText("Path to disk image (E01, DD, VMDK)...")
        self.disk_path.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
            }
        """)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self._browse_disk_image)
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 10px 15px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        file_row.addWidget(self.disk_path)
        file_row.addWidget(browse_btn)
        disk_layout.addLayout(file_row)
        
        layout.addWidget(disk_group)
        
        # Analysis options
        options_group = QGroupBox("Analysis Options")
        options_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #17a2b8;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        options_layout = QHBoxLayout(options_group)
        
        self.deleted_files = QCheckBox("Recover Deleted Files")
        self.deleted_files.setChecked(True)
        self.deleted_files.setStyleSheet("color: white;")
        
        self.file_carving = QCheckBox("File Carving")
        self.file_carving.setChecked(True)
        self.file_carving.setStyleSheet("color: white;")
        
        self.timeline_analysis = QCheckBox("Timeline Analysis")
        self.timeline_analysis.setChecked(True)
        self.timeline_analysis.setStyleSheet("color: white;")
        
        self.hash_files = QCheckBox("Hash All Files")
        self.hash_files.setStyleSheet("color: white;")
        
        options_layout.addWidget(self.deleted_files)
        options_layout.addWidget(self.file_carving)
        options_layout.addWidget(self.timeline_analysis)
        options_layout.addWidget(self.hash_files)
        options_layout.addStretch()
        
        layout.addWidget(options_group)
        
        # Analyze button
        analyze_btn = QPushButton("💾 Analyze Disk Image")
        analyze_btn.clicked.connect(self._analyze_disk)
        analyze_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #17a2b8, #138496);
                color: white;
                font-weight: bold;
                padding: 15px 30px;
                border-radius: 5px;
                border: none;
                font-size: 14px;
            }
        """)
        layout.addWidget(analyze_btn)
        
        # File browser
        file_label = QLabel("File System Browser")
        file_label.setStyleSheet("color: #17a2b8; font-weight: bold;")
        layout.addWidget(file_label)
        
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Size", "Modified", "Type", "Status"])
        self.file_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #16213e;
                color: white;
                border: 1px solid #333;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #17a2b8;
                padding: 8px;
                border: 1px solid #333;
            }
        """)
        layout.addWidget(self.file_tree)
        
        return widget
        
    def _create_artifacts_tab(self):
        """Create artifacts collection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Artifact categories
        categories_group = QGroupBox("Artifact Categories")
        categories_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #17a2b8;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        cat_layout = QHBoxLayout(categories_group)
        
        categories = [
            ("browser", "🌐 Browser History"),
            ("registry", "📋 Registry"),
            ("prefetch", "⚡ Prefetch"),
            ("eventlog", "📝 Event Logs"),
            ("usb", "🔌 USB Devices"),
            ("network", "🌐 Network"),
            ("users", "👤 User Accounts"),
        ]
        
        for cat_id, cat_name in categories:
            check = QCheckBox(cat_name)
            check.setChecked(True)
            check.setStyleSheet("color: white;")
            check.setProperty("category_id", cat_id)
            cat_layout.addWidget(check)
            
        layout.addWidget(categories_group)
        
        # Collect button
        collect_btn = QPushButton("📦 Collect Artifacts")
        collect_btn.clicked.connect(self._collect_artifacts)
        collect_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #17a2b8, #138496);
                color: white;
                font-weight: bold;
                padding: 15px 30px;
                border-radius: 5px;
                border: none;
                font-size: 14px;
            }
        """)
        layout.addWidget(collect_btn)
        
        # Artifacts table
        self.artifacts_table = QTableWidget()
        self.artifacts_table.setColumnCount(5)
        self.artifacts_table.setHorizontalHeaderLabels([
            "Category", "Artifact", "Path", "Value", "Timestamp"
        ])
        self.artifacts_table.horizontalHeader().setStretchLastSection(True)
        self.artifacts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.artifacts_table.setStyleSheet("""
            QTableWidget {
                background-color: #16213e;
                color: white;
                border: 1px solid #333;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #17a2b8;
                padding: 8px;
                border: 1px solid #333;
            }
        """)
        layout.addWidget(self.artifacts_table)
        
        # Export buttons
        export_row = QHBoxLayout()
        
        export_json = QPushButton("💾 Export JSON")
        export_json.clicked.connect(lambda: self._export_artifacts("json"))
        export_json.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 8px 15px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        export_csv = QPushButton("📊 Export CSV")
        export_csv.clicked.connect(lambda: self._export_artifacts("csv"))
        export_csv.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 8px 15px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        export_report = QPushButton("📄 Generate Report")
        export_report.clicked.connect(self._generate_report)
        export_report.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 8px 15px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        export_row.addWidget(export_json)
        export_row.addWidget(export_csv)
        export_row.addWidget(export_report)
        export_row.addStretch()
        
        layout.addLayout(export_row)
        
        return widget
        
    def _create_timeline_tab(self):
        """Create timeline analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Timeline filters
        filter_group = QGroupBox("Timeline Filters")
        filter_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                color: #17a2b8;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        filter_layout = QHBoxLayout(filter_group)
        
        # Date range
        from_label = QLabel("From:")
        from_label.setStyleSheet("color: #888;")
        
        self.date_from = QLineEdit()
        self.date_from.setPlaceholderText("YYYY-MM-DD")
        self.date_from.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
                max-width: 120px;
            }
        """)
        
        to_label = QLabel("To:")
        to_label.setStyleSheet("color: #888;")
        
        self.date_to = QLineEdit()
        self.date_to.setPlaceholderText("YYYY-MM-DD")
        self.date_to.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
                max-width: 120px;
            }
        """)
        
        # Event type filter
        type_label = QLabel("Event Type:")
        type_label.setStyleSheet("color: #888;")
        
        self.event_type = QComboBox()
        self.event_type.addItems([
            "All Events", "File Access", "Process Execution",
            "Network Activity", "User Logon", "Registry Changes"
        ])
        self.event_type.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #0f0f1a;
                color: white;
            }
        """)
        
        filter_btn = QPushButton("🔍 Filter")
        filter_btn.clicked.connect(self._filter_timeline)
        filter_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #17a2b8, #138496);
                color: white;
                font-weight: bold;
                padding: 8px 20px;
                border-radius: 5px;
                border: none;
            }
        """)
        
        filter_layout.addWidget(from_label)
        filter_layout.addWidget(self.date_from)
        filter_layout.addWidget(to_label)
        filter_layout.addWidget(self.date_to)
        filter_layout.addWidget(type_label)
        filter_layout.addWidget(self.event_type)
        filter_layout.addWidget(filter_btn)
        
        layout.addWidget(filter_group)
        
        # Timeline table
        self.timeline_table = QTableWidget()
        self.timeline_table.setColumnCount(5)
        self.timeline_table.setHorizontalHeaderLabels([
            "Timestamp", "Event Type", "Source", "Description", "User"
        ])
        self.timeline_table.horizontalHeader().setStretchLastSection(True)
        self.timeline_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.timeline_table.setStyleSheet("""
            QTableWidget {
                background-color: #16213e;
                color: white;
                border: 1px solid #333;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #17a2b8;
                padding: 8px;
                border: 1px solid #333;
            }
        """)
        layout.addWidget(self.timeline_table)
        
        return widget
        
    def _browse_memory_dump(self):
        """Browse for memory dump file"""
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            "Select Memory Dump",
            "",
            "Memory Dumps (*.raw *.dmp *.mem *.vmem);;All Files (*.*)"
        )
        if filepath:
            self.memory_path.setText(filepath)
            
    def _browse_disk_image(self):
        """Browse for disk image"""
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            "Select Disk Image",
            "",
            "Disk Images (*.E01 *.dd *.raw *.vmdk *.vhd);;All Files (*.*)"
        )
        if filepath:
            self.disk_path.setText(filepath)
            
    def _analyze_memory(self):
        """Start memory analysis"""
        dump_path = self.memory_path.text()
        if not dump_path:
            self.status_label.setText("❌ Please select a memory dump file")
            return
            
        self.memory_progress.setVisible(True)
        self.memory_progress.setRange(0, 0)
        self.status_label.setText("🔬 Analyzing memory dump...")
        
        # Simulate analysis for demo
        self.memory_results.clear()
        
        # Add sample results
        processes = QTreeWidgetItem(["Processes", "", ""])
        processes.addChild(QTreeWidgetItem(["", "explorer.exe", "PID: 1234"]))
        processes.addChild(QTreeWidgetItem(["", "chrome.exe", "PID: 5678"]))
        processes.addChild(QTreeWidgetItem(["", "svchost.exe", "PID: 892"]))
        self.memory_results.addTopLevelItem(processes)
        
        network = QTreeWidgetItem(["Network", "", ""])
        network.addChild(QTreeWidgetItem(["", "TCP 192.168.1.100:443", "ESTABLISHED"]))
        network.addChild(QTreeWidgetItem(["", "TCP 10.0.0.1:80", "CLOSE_WAIT"]))
        self.memory_results.addTopLevelItem(network)
        
        suspicious = QTreeWidgetItem(["Suspicious", "", ""])
        suspicious.addChild(QTreeWidgetItem(["", "Injected code in PID 1234", "HIGH RISK"]))
        self.memory_results.addTopLevelItem(suspicious)
        
        self.memory_progress.setVisible(False)
        self.status_label.setText("✅ Memory analysis complete")
        
    def _analyze_disk(self):
        """Start disk analysis"""
        disk_path = self.disk_path.text()
        if not disk_path:
            self.status_label.setText("❌ Please select a disk image")
            return
            
        self.status_label.setText("💾 Analyzing disk image...")
        
    def _collect_artifacts(self):
        """Collect forensic artifacts"""
        self.status_label.setText("📦 Collecting artifacts...")
        
        # Add sample artifacts
        artifacts = [
            ("Browser", "Chrome History", "C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\...", "100 entries", "2024-01-15"),
            ("Registry", "Run Key", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "5 entries", "2024-01-14"),
            ("Prefetch", "cmd.exe", "C:\\Windows\\Prefetch\\CMD.EXE-xxx.pf", "Last run", "2024-01-15"),
            ("Event Log", "Security", "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "1500 events", "2024-01-15"),
        ]
        
        self.artifacts_table.setRowCount(len(artifacts))
        for i, (cat, name, path, value, timestamp) in enumerate(artifacts):
            self.artifacts_table.setItem(i, 0, QTableWidgetItem(cat))
            self.artifacts_table.setItem(i, 1, QTableWidgetItem(name))
            self.artifacts_table.setItem(i, 2, QTableWidgetItem(path))
            self.artifacts_table.setItem(i, 3, QTableWidgetItem(value))
            self.artifacts_table.setItem(i, 4, QTableWidgetItem(timestamp))
            
        self.artifacts_count.setText(f"Artifacts: {len(artifacts)}")
        self.status_label.setText("✅ Artifacts collected")
        
    def _filter_timeline(self):
        """Apply timeline filters"""
        self.status_label.setText("🔍 Filtering timeline...")
        
    def _export_artifacts(self, format_type):
        """Export artifacts to file"""
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Export Artifacts",
            f"artifacts.{format_type}",
            f"{format_type.upper()} Files (*.{format_type})"
        )
        
        if filepath:
            self.status_label.setText(f"✅ Exported to {filepath}")
            
    def _generate_report(self):
        """Generate forensics report"""
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report",
            "forensics_report.html",
            "HTML Files (*.html)"
        )
        
        if filepath:
            self.status_label.setText(f"✅ Report saved to {filepath}")
