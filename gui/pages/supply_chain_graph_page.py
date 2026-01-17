"""
Supply Chain Graph Page
GUI for software supply chain security mapping
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QGroupBox,
    QProgressBar, QSplitter, QFrame, QHeaderView, QTreeWidget,
    QTreeWidgetItem, QGridLayout, QComboBox, QTextEdit, QLineEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor
import asyncio


class SBOMWorker(QThread):
    """Worker thread for SBOM analysis"""
    progress = pyqtSignal(str, int)
    result = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, path):
        super().__init__()
        self.path = path
        
    def run(self):
        try:
            from core.supply_chain_graph import SupplyChainGraph
            
            async def analyze():
                graph = SupplyChainGraph()
                return await graph.analyze_dependencies()
                
            result = asyncio.run(analyze())
            self.result.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class SupplyChainGraphPage(QWidget):
    """Supply Chain Graph Dashboard"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.sbom_worker = None
        
        self._setup_ui()
        self._connect_signals()
        self._load_demo_data()
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                border-radius: 8px;
                background: #0d1117;
            }
            QTabBar::tab {
                background: #21262d;
                color: #8b949e;
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #0d1117;
                color: #9d4edd;
            }
        """)
        
        # Create tabs
        self.tabs.addTab(self._create_dependencies_tab(), "📦 Dependencies")
        self.tabs.addTab(self._create_vulnerabilities_tab(), "🔓 Vulnerabilities")
        self.tabs.addTab(self._create_vendors_tab(), "🏢 Vendors")
        self.tabs.addTab(self._create_blast_radius_tab(), "💥 Blast Radius")
        self.tabs.addTab(self._create_sbom_tab(), "📋 SBOM")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QWidget:
        """Create the page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2a1a3a, stop:1 #0d1117);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🔗 Supply Chain Security Graph")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            color: #e6e6e6;
        """)
        title_layout.addWidget(title)
        
        subtitle = QLabel("Map Every Dependency and Its Security Impact")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.deps_count = self._create_stat_card("Dependencies", "247", "#9d4edd")
        self.vulns_count = self._create_stat_card("Vulnerabilities", "12", "#ff6b6b")
        self.vendors_count = self._create_stat_card("Vendors", "38", "#00d4ff")
        
        stats_layout.addWidget(self.deps_count)
        stats_layout.addWidget(self.vulns_count)
        stats_layout.addWidget(self.vendors_count)
        
        layout.addLayout(stats_layout)
        
        # Scan button
        self.scan_btn = QPushButton("🔍 Analyze Supply Chain")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #9d4edd, stop:1 #c77dff);
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #c77dff, stop:1 #9d4edd);
            }
        """)
        layout.addWidget(self.scan_btn)
        
        return header
    
    def _create_stat_card(self, label: str, value: str, color: str) -> QFrame:
        """Create a statistics card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #161b22;
                border: 1px solid {color}40;
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setSpacing(4)
        
        value_label = QLabel(value)
        value_label.setStyleSheet(f"color: {color}; font-size: 20px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value_label)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #8b949e; font-size: 11px;")
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_label)
        
        return card
        
    def _create_dependencies_tab(self) -> QWidget:
        """Create dependencies tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Search bar
        search_layout = QHBoxLayout()
        
        self.dep_search = QLineEdit()
        self.dep_search.setPlaceholderText("🔍 Search dependencies...")
        self.dep_search.setStyleSheet("""
            QLineEdit {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        search_layout.addWidget(self.dep_search)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "npm", "pypi", "maven", "cargo", "go"])
        self.filter_combo.setStyleSheet("""
            QComboBox {
                background: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                padding: 8px;
                border-radius: 6px;
                min-width: 100px;
            }
        """)
        search_layout.addWidget(self.filter_combo)
        
        layout.addLayout(search_layout)
        
        # Dependencies table
        self.deps_table = QTableWidget()
        self.deps_table.setColumnCount(7)
        self.deps_table.setHorizontalHeaderLabels([
            "Package", "Version", "Ecosystem", "License", "Vulns", "Depth", "Risk"
        ])
        self.deps_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.deps_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
                gridline-color: #30363d;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.deps_table)
        
        return widget
        
    def _create_vulnerabilities_tab(self) -> QWidget:
        """Create vulnerabilities tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Vulnerabilities table
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(7)
        self.vulns_table.setHorizontalHeaderLabels([
            "CVE", "Package", "Severity", "CVSS", "Exploited", "Fix Available", "Affected"
        ])
        self.vulns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.vulns_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
                gridline-color: #30363d;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.vulns_table)
        
        return widget
        
    def _create_vendors_tab(self) -> QWidget:
        """Create vendors tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Vendors table
        self.vendors_table = QTableWidget()
        self.vendors_table.setColumnCount(6)
        self.vendors_table.setHorizontalHeaderLabels([
            "Vendor", "Type", "Packages", "Trust Score", "Last Audit", "Risk Level"
        ])
        self.vendors_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.vendors_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
                gridline-color: #30363d;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.vendors_table)
        
        return widget
        
    def _create_blast_radius_tab(self) -> QWidget:
        """Create blast radius tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Visualization placeholder
        viz_frame = QFrame()
        viz_frame.setStyleSheet("""
            QFrame {
                background: #0d1117;
                border: 2px dashed #30363d;
                border-radius: 12px;
                min-height: 250px;
            }
        """)
        viz_layout = QVBoxLayout(viz_frame)
        
        viz_label = QLabel("💥 Blast Radius Visualization")
        viz_label.setStyleSheet("color: #9d4edd; font-size: 24px; font-weight: bold;")
        viz_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        viz_layout.addWidget(viz_label)
        
        viz_desc = QLabel("See how vulnerabilities propagate through your dependency tree")
        viz_desc.setStyleSheet("color: #8b949e; font-size: 14px;")
        viz_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        viz_layout.addWidget(viz_desc)
        
        layout.addWidget(viz_frame)
        
        # Blast radius details
        self.blast_table = QTableWidget()
        self.blast_table.setColumnCount(5)
        self.blast_table.setHorizontalHeaderLabels([
            "Vulnerability", "Direct Impact", "Transitive Impact", "Total Affected", "Severity"
        ])
        self.blast_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.blast_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
                gridline-color: #30363d;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.blast_table)
        
        return widget
        
    def _create_sbom_tab(self) -> QWidget:
        """Create SBOM tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # SBOM actions
        actions_layout = QHBoxLayout()
        
        self.generate_sbom_btn = QPushButton("📋 Generate SBOM")
        self.generate_sbom_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background: #2ea043; }
        """)
        actions_layout.addWidget(self.generate_sbom_btn)
        
        self.export_btn = QPushButton("📤 Export")
        self.export_btn.setStyleSheet("""
            QPushButton {
                background: #1f6feb;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background: #388bfd; }
        """)
        actions_layout.addWidget(self.export_btn)
        
        self.format_combo = QComboBox()
        self.format_combo.addItems(["CycloneDX", "SPDX", "SWID"])
        self.format_combo.setStyleSheet("""
            QComboBox {
                background: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                padding: 8px;
                border-radius: 6px;
            }
        """)
        actions_layout.addWidget(self.format_combo)
        
        actions_layout.addStretch()
        layout.addLayout(actions_layout)
        
        # SBOM preview
        self.sbom_preview = QTextEdit()
        self.sbom_preview.setReadOnly(True)
        self.sbom_preview.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6e6e6;
                font-family: monospace;
                padding: 12px;
            }
        """)
        self.sbom_preview.setPlainText('''{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "tools": [{"vendor": "HydraRecon", "name": "Supply Chain Graph", "version": "1.0.0"}],
    "component": {"type": "application", "name": "MyApp", "version": "2.1.0"}
  },
  "components": [
    {"type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
    {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
    {"type": "library", "name": "axios", "version": "1.6.0", "purl": "pkg:npm/axios@1.6.0"}
  ],
  "vulnerabilities": [
    {"id": "CVE-2024-1234", "ratings": [{"severity": "critical", "score": 9.8}]}
  ]
}''')
        layout.addWidget(self.sbom_preview)
        
        return widget
        
    def _connect_signals(self):
        """Connect signals and slots"""
        self.scan_btn.clicked.connect(self._analyze_supply_chain)
        self.generate_sbom_btn.clicked.connect(self._generate_sbom)
        
    def _analyze_supply_chain(self):
        """Analyze supply chain"""
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("🔄 Analyzing...")
        
        QTimer.singleShot(2500, self._analysis_complete)
        
    def _analysis_complete(self):
        """Handle analysis completion"""
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("🔍 Analyze Supply Chain")
        
    def _generate_sbom(self):
        """Generate SBOM"""
        self.generate_sbom_btn.setText("🔄 Generating...")
        QTimer.singleShot(1500, lambda: self.generate_sbom_btn.setText("📋 Generate SBOM"))
        
    def _load_demo_data(self):
        """Load demonstration data"""
        # Dependencies
        deps = [
            ("express", "4.18.2", "npm", "MIT", "0", "1", "🟢 Low"),
            ("lodash", "4.17.21", "npm", "MIT", "1", "1", "🟡 Medium"),
            ("log4j-core", "2.14.1", "maven", "Apache-2.0", "1", "2", "🔴 Critical"),
            ("requests", "2.31.0", "pypi", "Apache-2.0", "0", "1", "🟢 Low"),
            ("spring-core", "5.3.18", "maven", "Apache-2.0", "1", "1", "🔴 Critical"),
            ("axios", "1.6.0", "npm", "MIT", "0", "1", "🟢 Low"),
            ("django", "4.2.0", "pypi", "BSD-3", "0", "1", "🟢 Low"),
            ("react", "18.2.0", "npm", "MIT", "0", "1", "🟢 Low"),
        ]
        
        self.deps_table.setRowCount(len(deps))
        for row, dep in enumerate(deps):
            for col, value in enumerate(dep):
                item = QTableWidgetItem(value)
                self.deps_table.setItem(row, col, item)
                
        # Vulnerabilities
        vulns = [
            ("CVE-2021-44228", "log4j-core", "🔴 Critical", "10.0", "Yes", "Yes", "15 systems"),
            ("CVE-2022-22965", "spring-core", "🔴 Critical", "9.8", "Yes", "Yes", "8 systems"),
            ("CVE-2021-23337", "lodash", "🟠 High", "7.5", "No", "Yes", "23 systems"),
            ("CVE-2024-1234", "axios", "🟡 Medium", "5.3", "No", "No", "12 systems"),
        ]
        
        self.vulns_table.setRowCount(len(vulns))
        for row, vuln in enumerate(vulns):
            for col, value in enumerate(vuln):
                item = QTableWidgetItem(value)
                if col == 2:  # Severity
                    if "Critical" in value:
                        item.setForeground(QColor("#ff6b6b"))
                    elif "High" in value:
                        item.setForeground(QColor("#ffa500"))
                self.vulns_table.setItem(row, col, item)
                
        # Vendors
        vendors = [
            ("Apache Foundation", "Open Source", "12", "85/100", "2024-01-10", "🟡 Medium"),
            ("npm, Inc.", "Package Registry", "45", "90/100", "2024-01-12", "🟢 Low"),
            ("PyPI", "Package Registry", "28", "88/100", "2024-01-11", "🟢 Low"),
            ("Spring.io", "Framework", "8", "82/100", "2024-01-08", "🟡 Medium"),
            ("Facebook", "Library", "5", "95/100", "2024-01-15", "🟢 Low"),
        ]
        
        self.vendors_table.setRowCount(len(vendors))
        for row, vendor in enumerate(vendors):
            for col, value in enumerate(vendor):
                item = QTableWidgetItem(value)
                self.vendors_table.setItem(row, col, item)
                
        # Blast radius
        blast = [
            ("CVE-2021-44228", "3 packages", "12 packages", "15 systems", "🔴 Critical"),
            ("CVE-2022-22965", "1 package", "7 packages", "8 systems", "🔴 Critical"),
            ("CVE-2021-23337", "1 package", "22 packages", "23 systems", "🟠 High"),
        ]
        
        self.blast_table.setRowCount(len(blast))
        for row, b in enumerate(blast):
            for col, value in enumerate(b):
                item = QTableWidgetItem(value)
                self.blast_table.setItem(row, col, item)
