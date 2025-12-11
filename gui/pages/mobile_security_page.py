"""
Mobile Security Scanner Page - Mobile App Security Analysis Interface
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QTabWidget, QTextEdit, QLineEdit, QComboBox,
    QProgressBar, QFrame, QSplitter, QGroupBox,
    QFileDialog, QTreeWidget, QTreeWidgetItem,
    QHeaderView, QMessageBox, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor
import asyncio
from datetime import datetime


class MobileWorker(QThread):
    """Worker thread for mobile security operations"""
    finished = pyqtSignal(object)
    progress = pyqtSignal(str, object)
    error = pyqtSignal(str)
    
    def __init__(self, operation, *args, **kwargs):
        super().__init__()
        self.operation = operation
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.operation(*self.args, **self.kwargs))
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class MobileSecurityPage(QWidget):
    """Mobile Security Scanner Interface"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.scanner = None
        self.current_worker = None
        self.apps = {}
        
        self._init_scanner()
        self._setup_ui()
    
    def _init_scanner(self):
        """Initialize mobile scanner"""
        try:
            from core.mobile_security import MobileSecurityScanner
            self.scanner = MobileSecurityScanner()
            self.scanner.add_callback(self._on_scanner_event)
        except ImportError as e:
            print(f"Mobile scanner import error: {e}")
    
    def _on_scanner_event(self, event: str, data):
        """Handle scanner events"""
        pass
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3a3a4a;
                background: #1a1a2e;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #252535;
                color: #8888aa;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background: #1a1a2e;
                color: #00ff88;
            }
        """)
        
        tabs.addTab(self._create_analysis_tab(), "📱 Analysis")
        tabs.addTab(self._create_apps_tab(), "📦 Apps")
        tabs.addTab(self._create_permissions_tab(), "🔐 Permissions")
        tabs.addTab(self._create_secrets_tab(), "🔑 Secrets")
        tabs.addTab(self._create_vulns_tab(), "⚠️ Vulnerabilities")
        
        layout.addWidget(tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:1 #252545);
                border-radius: 15px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("📱 MOBILE SECURITY SCANNER")
        title.setFont(QFont("Consolas", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Android & iOS Application Security Analysis")
        subtitle.setStyleSheet("color: #8888aa; font-size: 12px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(30)
        
        self.app_count = self._create_stat("Apps", "0")
        self.vuln_count = self._create_stat("Vulns", "0")
        self.secret_count = self._create_stat("Secrets", "0")
        
        stats_layout.addWidget(self.app_count)
        stats_layout.addWidget(self.vuln_count)
        stats_layout.addWidget(self.secret_count)
        
        layout.addLayout(stats_layout)
        
        return frame
    
    def _create_stat(self, label: str, value: str) -> QFrame:
        """Create stat display"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: rgba(0, 255, 136, 0.1);
                border: 1px solid #00ff88;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(15, 10, 15, 10)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Consolas", 20, QFont.Weight.Bold))
        value_label.setStyleSheet("color: #00ff88;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setObjectName(f"stat_{label.lower()}")
        layout.addWidget(value_label)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #8888aa; font-size: 11px;")
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_label)
        
        return frame
    
    def _create_analysis_tab(self) -> QWidget:
        """Create app analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Upload section
        upload_group = QGroupBox("Application Analysis")
        upload_group.setStyleSheet("""
            QGroupBox {
                color: #00ff88;
                font-weight: bold;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        upload_layout = QGridLayout(upload_group)
        
        # File path
        upload_layout.addWidget(QLabel("App File:"), 0, 0)
        self.app_path = QLineEdit()
        self.app_path.setPlaceholderText("Select APK or IPA file...")
        self.app_path.setStyleSheet("""
            QLineEdit {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                padding: 10px;
                color: white;
            }
        """)
        upload_layout.addWidget(self.app_path, 0, 1)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.setStyleSheet("""
            QPushButton {
                background: #3a3a4a;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                color: white;
            }
            QPushButton:hover { background: #4a4a5a; }
        """)
        browse_btn.clicked.connect(self._browse_app)
        upload_layout.addWidget(browse_btn, 0, 2)
        
        # Platform selector
        upload_layout.addWidget(QLabel("Platform:"), 1, 0)
        self.platform_combo = QComboBox()
        self.platform_combo.addItems(["Auto-detect", "Android (APK)", "iOS (IPA)"])
        self.platform_combo.setStyleSheet("""
            QComboBox {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
        """)
        upload_layout.addWidget(self.platform_combo, 1, 1)
        
        # Analyze button
        self.analyze_btn = QPushButton("🔬 Analyze Application")
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, stop:1 #00d4ff);
                border: none;
                border-radius: 8px;
                padding: 15px 30px;
                color: #1a1a2e;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ffaa, stop:1 #00e4ff);
            }
        """)
        self.analyze_btn.clicked.connect(self._analyze_app)
        upload_layout.addWidget(self.analyze_btn, 1, 2)
        
        layout.addWidget(upload_group)
        
        # Progress
        self.analysis_progress = QProgressBar()
        self.analysis_progress.setStyleSheet("""
            QProgressBar {
                background: #252535;
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, stop:1 #00d4ff);
                border-radius: 5px;
            }
        """)
        self.analysis_progress.setVisible(False)
        layout.addWidget(self.analysis_progress)
        
        # Results
        results_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # App info
        info_frame = QFrame()
        info_frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
            }
        """)
        info_layout = QVBoxLayout(info_frame)
        info_layout.addWidget(QLabel("📋 Application Info"))
        
        self.app_info = QTextEdit()
        self.app_info.setReadOnly(True)
        self.app_info.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                border: none;
                color: #00d4ff;
                font-family: Consolas, monospace;
            }
        """)
        self.app_info.setPlaceholderText("Analysis results will appear here...")
        info_layout.addWidget(self.app_info)
        
        results_splitter.addWidget(info_frame)
        
        # Quick stats
        stats_frame = QFrame()
        stats_frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
            }
        """)
        stats_layout = QVBoxLayout(stats_frame)
        stats_layout.addWidget(QLabel("📊 Analysis Summary"))
        
        self.summary_tree = QTreeWidget()
        self.summary_tree.setHeaderLabels(["Category", "Count", "Risk"])
        self.summary_tree.setStyleSheet("""
            QTreeWidget {
                background: #0d0d1a;
                border: none;
                color: white;
            }
            QTreeWidget::item:selected {
                background: rgba(0, 212, 255, 0.3);
            }
        """)
        stats_layout.addWidget(self.summary_tree)
        
        results_splitter.addWidget(stats_frame)
        results_splitter.setSizes([400, 300])
        
        layout.addWidget(results_splitter)
        
        return widget
    
    def _create_apps_tab(self) -> QWidget:
        """Create analyzed apps tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Apps table
        self.apps_table = QTableWidget()
        self.apps_table.setColumnCount(6)
        self.apps_table.setHorizontalHeaderLabels([
            "Package Name", "Version", "Platform", "Risk Score", "Vulns", "Analyzed"
        ])
        self.apps_table.horizontalHeader().setStretchLastSection(True)
        self.apps_table.setStyleSheet("""
            QTableWidget {
                background: #0d0d1a;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                color: white;
                gridline-color: #3a3a4a;
            }
            QHeaderView::section {
                background: #252535;
                color: #00ff88;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item:selected {
                background: rgba(0, 255, 136, 0.2);
            }
        """)
        self.apps_table.itemClicked.connect(self._on_app_selected)
        layout.addWidget(self.apps_table)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        self.static_analysis_btn = QPushButton("🔍 Static Analysis")
        self.static_analysis_btn.setStyleSheet("""
            QPushButton {
                background: #ff6b00;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover { background: #ff8800; }
        """)
        self.static_analysis_btn.clicked.connect(self._run_static_analysis)
        btn_layout.addWidget(self.static_analysis_btn)
        
        self.export_btn = QPushButton("📄 Export Report")
        self.export_btn.setStyleSheet("""
            QPushButton {
                background: #3a3a4a;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                color: white;
            }
            QPushButton:hover { background: #4a4a5a; }
        """)
        btn_layout.addWidget(self.export_btn)
        
        btn_layout.addStretch()
        
        self.delete_btn = QPushButton("🗑️ Delete")
        self.delete_btn.setStyleSheet("""
            QPushButton {
                background: #ff0055;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                color: white;
            }
            QPushButton:hover { background: #ff2277; }
        """)
        btn_layout.addWidget(self.delete_btn)
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def _create_permissions_tab(self) -> QWidget:
        """Create permissions analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Permissions table
        self.perms_table = QTableWidget()
        self.perms_table.setColumnCount(4)
        self.perms_table.setHorizontalHeaderLabels([
            "Permission", "Risk Level", "Category", "Description"
        ])
        self.perms_table.horizontalHeader().setStretchLastSection(True)
        self.perms_table.setStyleSheet("""
            QTableWidget {
                background: #0d0d1a;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                color: white;
                gridline-color: #3a3a4a;
            }
            QHeaderView::section {
                background: #252535;
                color: #ff6b00;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.perms_table)
        
        # Permission legend
        legend_group = QGroupBox("Risk Legend")
        legend_group.setStyleSheet("""
            QGroupBox {
                color: #00d4ff;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
            }
        """)
        legend_layout = QHBoxLayout(legend_group)
        
        for level, color in [
            ("CRITICAL", "#ff0055"),
            ("HIGH", "#ff6b00"),
            ("MEDIUM", "#ffcc00"),
            ("LOW", "#00ff88"),
        ]:
            item = QLabel(f"● {level}")
            item.setStyleSheet(f"color: {color}; font-weight: bold;")
            legend_layout.addWidget(item)
        
        legend_layout.addStretch()
        layout.addWidget(legend_group)
        
        return widget
    
    def _create_secrets_tab(self) -> QWidget:
        """Create secrets discovery tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Secrets found
        secrets_group = QGroupBox("Discovered Secrets & API Keys")
        secrets_group.setStyleSheet("""
            QGroupBox {
                color: #ff0055;
                font-weight: bold;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                margin-top: 10px;
            }
        """)
        secrets_layout = QVBoxLayout(secrets_group)
        
        self.secrets_table = QTableWidget()
        self.secrets_table.setColumnCount(4)
        self.secrets_table.setHorizontalHeaderLabels([
            "Type", "Value", "Location", "Risk"
        ])
        self.secrets_table.horizontalHeader().setStretchLastSection(True)
        self.secrets_table.setStyleSheet("""
            QTableWidget {
                background: #0d0d1a;
                border: none;
                color: white;
                gridline-color: #3a3a4a;
            }
            QHeaderView::section {
                background: #252535;
                color: #ff0055;
                padding: 8px;
                border: none;
            }
        """)
        secrets_layout.addWidget(self.secrets_table)
        
        layout.addWidget(secrets_group)
        
        # URLs and endpoints
        urls_group = QGroupBox("URLs & Endpoints")
        urls_group.setStyleSheet("""
            QGroupBox {
                color: #00d4ff;
                font-weight: bold;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
            }
        """)
        urls_layout = QVBoxLayout(urls_group)
        
        self.urls_list = QListWidget()
        self.urls_list.setStyleSheet("""
            QListWidget {
                background: #0d0d1a;
                border: none;
                color: #00d4ff;
                font-family: Consolas, monospace;
            }
            QListWidget::item:selected {
                background: rgba(0, 212, 255, 0.3);
            }
        """)
        urls_layout.addWidget(self.urls_list)
        
        layout.addWidget(urls_group)
        
        return widget
    
    def _create_vulns_tab(self) -> QWidget:
        """Create vulnerabilities tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Vulnerabilities table
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(5)
        self.vulns_table.setHorizontalHeaderLabels([
            "Severity", "Category", "Title", "Location", "OWASP"
        ])
        self.vulns_table.horizontalHeader().setStretchLastSection(True)
        self.vulns_table.setStyleSheet("""
            QTableWidget {
                background: #0d0d1a;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
                color: white;
                gridline-color: #3a3a4a;
            }
            QHeaderView::section {
                background: #252535;
                color: #ff0055;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        self.vulns_table.itemClicked.connect(self._on_vuln_selected)
        layout.addWidget(self.vulns_table)
        
        # Vulnerability details
        details_group = QGroupBox("Vulnerability Details")
        details_group.setStyleSheet("""
            QGroupBox {
                color: #00ff88;
                font-weight: bold;
                border: 1px solid #3a3a4a;
                border-radius: 8px;
            }
        """)
        details_layout = QVBoxLayout(details_group)
        
        self.vuln_details = QTextEdit()
        self.vuln_details.setReadOnly(True)
        self.vuln_details.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                border: none;
                color: #00ff88;
                font-family: Consolas, monospace;
            }
        """)
        self.vuln_details.setMaximumHeight(200)
        details_layout.addWidget(self.vuln_details)
        
        layout.addWidget(details_group)
        
        return widget
    
    def _browse_app(self):
        """Browse for app file"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Mobile Application",
            "", "Mobile Apps (*.apk *.ipa);;Android APK (*.apk);;iOS IPA (*.ipa);;All Files (*)"
        )
        if path:
            self.app_path.setText(path)
            
            # Auto-detect platform
            if path.lower().endswith('.apk'):
                self.platform_combo.setCurrentIndex(1)
            elif path.lower().endswith('.ipa'):
                self.platform_combo.setCurrentIndex(2)
    
    def _analyze_app(self):
        """Analyze mobile application"""
        if not self.scanner:
            QMessageBox.warning(self, "Error", "Mobile scanner not initialized")
            return
        
        path = self.app_path.text().strip()
        if not path:
            QMessageBox.warning(self, "Error", "Please select an application file")
            return
        
        self.analysis_progress.setVisible(True)
        self.analysis_progress.setRange(0, 0)
        self.analyze_btn.setEnabled(False)
        
        # Determine analysis method
        if path.lower().endswith('.apk'):
            method = self.scanner.analyze_apk
        elif path.lower().endswith('.ipa'):
            method = self.scanner.analyze_ipa
        else:
            QMessageBox.warning(self, "Error", "Unsupported file format")
            self.analysis_progress.setVisible(False)
            self.analyze_btn.setEnabled(True)
            return
        
        self.current_worker = MobileWorker(method, path)
        self.current_worker.finished.connect(self._on_analysis_complete)
        self.current_worker.error.connect(self._on_error)
        self.current_worker.start()
    
    def _on_analysis_complete(self, app):
        """Handle analysis completion"""
        self.analysis_progress.setVisible(False)
        self.analyze_btn.setEnabled(True)
        
        if app:
            self.apps[app.id] = app
            
            # Update app info
            info = f"""
╔════════════════════════════════════════════════╗
║           APPLICATION ANALYSIS RESULTS          ║
╠════════════════════════════════════════════════╣

  📦 Package:     {app.package_name}
  📱 App Name:    {app.name}
  🔢 Version:     {app.version}
  📲 Platform:    {app.platform.value.upper()}
  
  🔐 Risk Score:  {app.risk_score:.1f}/10.0
  ⏱️  Analysis:    {app.analysis_time:.2f}s

╠════════════════════════════════════════════════╣
║               COMPONENTS FOUND                  ║
╠════════════════════════════════════════════════╣

  🔐 Permissions: {len(app.permissions)}
  📄 Activities:  {len(app.activities)}
  ⚙️  Services:    {len(app.services)}
  📡 Receivers:   {len(app.receivers)}
  💾 Providers:   {len(app.providers)}
  📚 Libraries:   {len(app.libraries)}

╠════════════════════════════════════════════════╣
║              SECURITY FINDINGS                  ║
╠════════════════════════════════════════════════╣

  ⚠️  Vulnerabilities: {len(app.vulnerabilities)}

╚════════════════════════════════════════════════╝
"""
            self.app_info.setText(info)
            
            # Update summary tree
            self.summary_tree.clear()
            
            items = [
                ("Permissions", len(app.permissions), "Review"),
                ("Activities", len(app.activities), "INFO"),
                ("Services", len(app.services), "INFO"),
                ("Vulnerabilities", len(app.vulnerabilities), "HIGH" if len(app.vulnerabilities) > 0 else "LOW"),
            ]
            
            for category, count, risk in items:
                item = QTreeWidgetItem([category, str(count), risk])
                if risk == "HIGH":
                    item.setForeground(2, QColor("#ff0055"))
                elif risk == "Review":
                    item.setForeground(2, QColor("#ff6b00"))
                else:
                    item.setForeground(2, QColor("#00ff88"))
                self.summary_tree.addTopLevelItem(item)
            
            # Add to apps table
            row = self.apps_table.rowCount()
            self.apps_table.insertRow(row)
            self.apps_table.setItem(row, 0, QTableWidgetItem(app.package_name))
            self.apps_table.setItem(row, 1, QTableWidgetItem(app.version))
            self.apps_table.setItem(row, 2, QTableWidgetItem(app.platform.value.upper()))
            
            risk_item = QTableWidgetItem(f"{app.risk_score:.1f}")
            if app.risk_score >= 7:
                risk_item.setForeground(QColor("#ff0055"))
            elif app.risk_score >= 4:
                risk_item.setForeground(QColor("#ff6b00"))
            else:
                risk_item.setForeground(QColor("#00ff88"))
            self.apps_table.setItem(row, 3, risk_item)
            
            self.apps_table.setItem(row, 4, QTableWidgetItem(str(len(app.vulnerabilities))))
            self.apps_table.setItem(row, 5, QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M")))
            
            # Update permissions tab
            self._populate_permissions(app)
            
            # Update vulnerabilities tab
            self._populate_vulnerabilities(app)
            
            # Update stats
            self.app_count.findChild(QLabel, "stat_apps").setText(str(len(self.apps)))
            total_vulns = sum(len(a.vulnerabilities) for a in self.apps.values())
            self.vuln_count.findChild(QLabel, "stat_vulns").setText(str(total_vulns))
            
            QMessageBox.information(
                self, "Analysis Complete",
                f"Successfully analyzed {app.name}\n"
                f"Found {len(app.vulnerabilities)} potential issues"
            )
    
    def _on_error(self, error):
        """Handle error"""
        self.analysis_progress.setVisible(False)
        self.analyze_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", f"Analysis failed: {error}")
    
    def _populate_permissions(self, app):
        """Populate permissions table"""
        self.perms_table.setRowCount(len(app.permissions))
        
        dangerous_perms = {
            "android.permission.READ_SMS": ("CRITICAL", "PRIVACY", "Read SMS messages"),
            "android.permission.SEND_SMS": ("CRITICAL", "FINANCIAL", "Send SMS messages"),
            "android.permission.RECORD_AUDIO": ("CRITICAL", "SURVEILLANCE", "Record audio"),
            "android.permission.CAMERA": ("HIGH", "SURVEILLANCE", "Camera access"),
            "android.permission.ACCESS_FINE_LOCATION": ("HIGH", "TRACKING", "GPS location"),
            "android.permission.READ_CONTACTS": ("HIGH", "PRIVACY", "Read contacts"),
            "android.permission.INTERNET": ("LOW", "NETWORK", "Internet access"),
        }
        
        for i, perm in enumerate(app.permissions):
            perm_name = perm.split('.')[-1]
            self.perms_table.setItem(i, 0, QTableWidgetItem(perm_name))
            
            if perm in dangerous_perms:
                risk, cat, desc = dangerous_perms[perm]
            else:
                risk, cat, desc = "LOW", "OTHER", "Standard permission"
            
            risk_item = QTableWidgetItem(risk)
            if risk == "CRITICAL":
                risk_item.setForeground(QColor("#ff0055"))
            elif risk == "HIGH":
                risk_item.setForeground(QColor("#ff6b00"))
            else:
                risk_item.setForeground(QColor("#00ff88"))
            self.perms_table.setItem(i, 1, risk_item)
            
            self.perms_table.setItem(i, 2, QTableWidgetItem(cat))
            self.perms_table.setItem(i, 3, QTableWidgetItem(desc))
    
    def _populate_vulnerabilities(self, app):
        """Populate vulnerabilities table"""
        self.vulns_table.setRowCount(len(app.vulnerabilities))
        
        for i, vuln in enumerate(app.vulnerabilities):
            severity = vuln.get("severity", "MEDIUM")
            severity_item = QTableWidgetItem(severity)
            if severity == "CRITICAL":
                severity_item.setForeground(QColor("#ff0055"))
            elif severity == "HIGH":
                severity_item.setForeground(QColor("#ff6b00"))
            elif severity == "MEDIUM":
                severity_item.setForeground(QColor("#ffcc00"))
            else:
                severity_item.setForeground(QColor("#00ff88"))
            self.vulns_table.setItem(i, 0, severity_item)
            
            self.vulns_table.setItem(i, 1, QTableWidgetItem(vuln.get("type", "Unknown")))
            self.vulns_table.setItem(i, 2, QTableWidgetItem(vuln.get("title", "")))
            self.vulns_table.setItem(i, 3, QTableWidgetItem(vuln.get("location", "N/A")[:50]))
            self.vulns_table.setItem(i, 4, QTableWidgetItem(vuln.get("owasp", "M1-M10")))
    
    def _on_app_selected(self, item):
        """Handle app selection"""
        row = item.row()
        package = self.apps_table.item(row, 0).text()
        
        for app in self.apps.values():
            if app.package_name == package:
                self._populate_permissions(app)
                self._populate_vulnerabilities(app)
                break
    
    def _on_vuln_selected(self, item):
        """Handle vulnerability selection"""
        row = item.row()
        
        # Get vulnerability details
        severity = self.vulns_table.item(row, 0).text()
        category = self.vulns_table.item(row, 1).text()
        title = self.vulns_table.item(row, 2).text()
        location = self.vulns_table.item(row, 3).text()
        
        details = f"""
╔══════════════════════════════════════╗
║         VULNERABILITY DETAILS        ║
╠══════════════════════════════════════╣

  Severity:    {severity}
  Category:    {category}
  Title:       {title}
  Location:    {location}

╠══════════════════════════════════════╣
║           RECOMMENDATION             ║
╠══════════════════════════════════════╣

  Review the identified issue and apply
  appropriate security measures based on
  the category and severity level.

╚══════════════════════════════════════╝
"""
        self.vuln_details.setText(details)
    
    def _run_static_analysis(self):
        """Run detailed static analysis"""
        if self.apps_table.currentRow() < 0:
            QMessageBox.warning(self, "Error", "Please select an application first")
            return
        
        package = self.apps_table.item(self.apps_table.currentRow(), 0).text()
        app_id = None
        for aid, app in self.apps.items():
            if app.package_name == package:
                app_id = aid
                break
        
        if app_id and self.scanner:
            self.current_worker = MobileWorker(
                self.scanner.perform_static_analysis,
                app_id
            )
            self.current_worker.finished.connect(self._on_static_analysis_complete)
            self.current_worker.error.connect(self._on_error)
            self.current_worker.start()
    
    def _on_static_analysis_complete(self, result):
        """Handle static analysis completion"""
        if result:
            # Populate secrets
            self.secrets_table.setRowCount(len(result.api_keys))
            for i, key in enumerate(result.api_keys):
                self.secrets_table.setItem(i, 0, QTableWidgetItem(key.get("type", "")))
                self.secrets_table.setItem(i, 1, QTableWidgetItem(key.get("value", "")[:50]))
                self.secrets_table.setItem(i, 2, QTableWidgetItem(key.get("file", "")))
                self.secrets_table.setItem(i, 3, QTableWidgetItem("HIGH"))
            
            # Populate URLs
            self.urls_list.clear()
            for url in result.urls[:100]:
                self.urls_list.addItem(url)
            
            # Update secret count
            self.secret_count.findChild(QLabel, "stat_secrets").setText(str(len(result.api_keys)))
            
            QMessageBox.information(
                self, "Analysis Complete",
                f"Found {len(result.api_keys)} API keys/secrets\n"
                f"Found {len(result.urls)} URLs\n"
                f"Found {len(result.findings)} security findings"
            )
