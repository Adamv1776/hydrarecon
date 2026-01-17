"""
Threat Intelligence Fusion Center GUI Page
Multi-source threat intel aggregation with ML correlation dashboard.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTextEdit, QLineEdit, QComboBox, QProgressBar, QTabWidget,
    QGroupBox, QSpinBox, QCheckBox, QSplitter, QGridLayout,
    QListWidget, QScrollArea, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from datetime import datetime


class IOCIngestWorker(QThread):
    """Worker for IOC ingestion"""
    progress = pyqtSignal(int)
    ioc_ingested = pyqtSignal(dict)
    finished = pyqtSignal(dict)
    
    def __init__(self, feed_name, iocs):
        super().__init__()
        self.feed_name = feed_name
        self.iocs = iocs
    
    def run(self):
        try:
            for i, ioc in enumerate(self.iocs):
                progress = int(((i + 1) / len(self.iocs)) * 100)
                self.progress.emit(progress)
                self.ioc_ingested.emit(ioc)
                self.msleep(50)
            
            self.finished.emit({
                "status": "completed",
                "feed": self.feed_name,
                "iocs": len(self.iocs)
            })
        except Exception as e:
            self.finished.emit({"error": str(e)})


class ThreatIntelFusionPage(QWidget):
    """Threat Intelligence Fusion Center dashboard page."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.fusion_center = None
        self.iocs = []
        self.setup_ui()
        self.load_demo_data()
    
    def setup_ui(self):
        """Setup the page UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        tabs = QTabWidget()
        tabs.addTab(self.create_dashboard_tab(), "📊 Dashboard")
        tabs.addTab(self.create_iocs_tab(), "🎯 IOC Database")
        tabs.addTab(self.create_feeds_tab(), "📡 Intel Feeds")
        tabs.addTab(self.create_actors_tab(), "👤 Threat Actors")
        tabs.addTab(self.create_campaigns_tab(), "🎪 Campaigns")
        tabs.addTab(self.create_reports_tab(), "📋 Reports")
        
        layout.addWidget(tabs)
    
    def create_header(self) -> QFrame:
        """Create header section."""
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.StyledPanel)
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1f1f2d, stop:0.5 #2d2d4d, stop:1 #3d3d6d);
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🔍 Threat Intelligence Fusion Center")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        
        subtitle = QLabel("Multi-Source Threat Intel Aggregation with ML Correlation")
        subtitle.setStyleSheet("color: #888;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Stats
        stats_layout = QHBoxLayout()
        
        self.iocs_count = self.create_stat_card("Total IOCs", "0", "#00d4ff")
        self.critical_count = self.create_stat_card("Critical", "0", "#ff6b6b")
        self.actors_count = self.create_stat_card("Actors", "4", "#ffd93d")
        self.feeds_count = self.create_stat_card("Feeds", "5", "#00ff88")
        
        stats_layout.addWidget(self.iocs_count)
        stats_layout.addWidget(self.critical_count)
        stats_layout.addWidget(self.actors_count)
        stats_layout.addWidget(self.feeds_count)
        
        layout.addLayout(stats_layout)
        
        return frame
    
    def create_stat_card(self, label: str, value: str, color: str) -> QFrame:
        """Create a statistics card."""
        card = QFrame()
        card.setFixedSize(120, 70)
        card.setStyleSheet(f"""
            QFrame {{
                background: rgba(0,0,0,0.3);
                border: 1px solid {color};
                border-radius: 8px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setObjectName("value")
        
        text_label = QLabel(label)
        text_label.setStyleSheet("color: #888; font-size: 10px;")
        text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(value_label)
        layout.addWidget(text_label)
        
        return card
    
    def create_dashboard_tab(self) -> QWidget:
        """Create main dashboard tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Threat landscape summary
        landscape_group = QGroupBox("Current Threat Landscape")
        landscape_layout = QGridLayout(landscape_group)
        
        metrics = [
            ("New IOCs (24h)", "156", "#00d4ff"),
            ("Active Campaigns", "3", "#ff6b6b"),
            ("Correlations", "47", "#ffd93d"),
            ("Alerts Generated", "12", "#6c5ce7"),
            ("High Confidence", "89%", "#00ff88"),
            ("Feed Coverage", "95%", "#ff9f43")
        ]
        
        for i, (label, value, color) in enumerate(metrics):
            card = self.create_landscape_card(label, value, color)
            landscape_layout.addWidget(card, i // 3, i % 3)
        
        layout.addWidget(landscape_group)
        
        # Splitter for trends and alerts
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Trending threats
        trends_widget = QWidget()
        trends_layout = QVBoxLayout(trends_widget)
        trends_layout.addWidget(QLabel("📈 Trending Threats"))
        
        self.trends_list = QListWidget()
        self.trends_list.addItems([
            "🔴 [CRITICAL] LockBit 3.0 Ransomware - 45 new IOCs",
            "🔴 [CRITICAL] CVE-2024-3400 Exploitation - Active",
            "🟠 [HIGH] APT29 Campaign - New C2 infrastructure",
            "🟠 [HIGH] Phishing surge - Microsoft 365 themes",
            "🟡 [MEDIUM] Cryptomining malware - Cloud targets",
            "🟢 [LOW] SSH brute force - Automated scanning"
        ])
        trends_layout.addWidget(self.trends_list)
        splitter.addWidget(trends_widget)
        
        # Recent alerts
        alerts_widget = QWidget()
        alerts_layout = QVBoxLayout(alerts_widget)
        alerts_layout.addWidget(QLabel("🚨 Recent Alerts"))
        
        self.dashboard_alerts = QTableWidget()
        self.dashboard_alerts.setColumnCount(4)
        self.dashboard_alerts.setHorizontalHeaderLabels(["Time", "Severity", "Type", "Description"])
        self.dashboard_alerts.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        alerts_layout.addWidget(self.dashboard_alerts)
        splitter.addWidget(alerts_widget)
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
        return widget
    
    def create_landscape_card(self, label: str, value: str, color: str) -> QFrame:
        """Create a landscape metric card."""
        card = QFrame()
        card.setFixedHeight(80)
        card.setStyleSheet(f"""
            QFrame {{
                background: rgba(0,0,0,0.3);
                border: 1px solid {color};
                border-radius: 8px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        text_label = QLabel(label)
        text_label.setStyleSheet("color: #888;")
        text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(value_label)
        layout.addWidget(text_label)
        
        return card
    
    def create_iocs_tab(self) -> QWidget:
        """Create IOC database tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Search and filter
        search_layout = QHBoxLayout()
        
        self.ioc_search = QLineEdit()
        self.ioc_search.setPlaceholderText("Search IOCs (IP, domain, hash, CVE...)")
        self.ioc_search.textChanged.connect(self.filter_iocs)
        search_layout.addWidget(self.ioc_search)
        
        search_layout.addWidget(QLabel("Type:"))
        self.type_filter = QComboBox()
        self.type_filter.addItems([
            "All Types", "IP Address", "Domain", "URL", "MD5", "SHA256", "CVE", "Email"
        ])
        search_layout.addWidget(self.type_filter)
        
        search_layout.addWidget(QLabel("Level:"))
        self.level_filter = QComboBox()
        self.level_filter.addItems(["All Levels", "Critical", "High", "Medium", "Low"])
        search_layout.addWidget(self.level_filter)
        
        check_btn = QPushButton("🔍 Check IOC")
        check_btn.clicked.connect(self.check_ioc)
        search_layout.addWidget(check_btn)
        
        layout.addLayout(search_layout)
        
        # Add IOC form
        add_group = QGroupBox("Add IOC")
        add_layout = QGridLayout(add_group)
        
        add_layout.addWidget(QLabel("Value:"), 0, 0)
        self.ioc_value_input = QLineEdit()
        self.ioc_value_input.setPlaceholderText("Enter IOC value...")
        add_layout.addWidget(self.ioc_value_input, 0, 1)
        
        add_layout.addWidget(QLabel("Type:"), 0, 2)
        self.ioc_type_combo = QComboBox()
        self.ioc_type_combo.addItems([
            "IP Address", "Domain", "URL", "MD5", "SHA1", "SHA256", "CVE", "Email"
        ])
        add_layout.addWidget(self.ioc_type_combo, 0, 3)
        
        add_layout.addWidget(QLabel("Level:"), 1, 0)
        self.ioc_level_combo = QComboBox()
        self.ioc_level_combo.addItems(["Critical", "High", "Medium", "Low", "Unknown"])
        add_layout.addWidget(self.ioc_level_combo, 1, 1)
        
        add_layout.addWidget(QLabel("Tags:"), 1, 2)
        self.ioc_tags_input = QLineEdit()
        self.ioc_tags_input.setPlaceholderText("tag1, tag2, ...")
        add_layout.addWidget(self.ioc_tags_input, 1, 3)
        
        add_btn = QPushButton("➕ Add IOC")
        add_btn.clicked.connect(self.add_ioc)
        add_layout.addWidget(add_btn, 2, 0, 1, 4)
        
        layout.addWidget(add_group)
        
        # IOC table
        self.iocs_table = QTableWidget()
        self.iocs_table.setColumnCount(8)
        self.iocs_table.setHorizontalHeaderLabels([
            "Value", "Type", "Level", "Confidence", "Sources", "Tags", "Last Seen", "Score"
        ])
        self.iocs_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.iocs_table)
        
        return widget
    
    def create_feeds_tab(self) -> QWidget:
        """Create intel feeds tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Add feed form
        add_group = QGroupBox("Add Intelligence Feed")
        add_layout = QGridLayout(add_group)
        
        add_layout.addWidget(QLabel("Name:"), 0, 0)
        self.feed_name_input = QLineEdit()
        add_layout.addWidget(self.feed_name_input, 0, 1)
        
        add_layout.addWidget(QLabel("URL:"), 0, 2)
        self.feed_url_input = QLineEdit()
        add_layout.addWidget(self.feed_url_input, 0, 3)
        
        add_layout.addWidget(QLabel("Type:"), 1, 0)
        self.feed_type_combo = QComboBox()
        self.feed_type_combo.addItems([
            "Open Source", "Commercial", "Government", "ISAC", "Internal"
        ])
        add_layout.addWidget(self.feed_type_combo, 1, 1)
        
        add_layout.addWidget(QLabel("Interval:"), 1, 2)
        self.feed_interval = QComboBox()
        self.feed_interval.addItems(["15 min", "1 hour", "6 hours", "24 hours"])
        add_layout.addWidget(self.feed_interval, 1, 3)
        
        add_feed_btn = QPushButton("➕ Add Feed")
        add_layout.addWidget(add_feed_btn, 2, 0, 1, 4)
        
        layout.addWidget(add_group)
        
        # Feeds table
        self.feeds_table = QTableWidget()
        self.feeds_table.setColumnCount(7)
        self.feeds_table.setHorizontalHeaderLabels([
            "Name", "Type", "URL", "Interval", "Last Update", "IOCs", "Status"
        ])
        self.feeds_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Add demo feeds
        feeds = [
            ("MISP Threat Sharing", "Open Source", "https://misp.local/feeds", "1 hour", "2 min ago", "1,247", "Active"),
            ("AlienVault OTX", "Open Source", "https://otx.alienvault.com", "6 hours", "3 hours ago", "856", "Active"),
            ("VirusTotal", "Commercial", "https://virustotal.com/api", "1 hour", "45 min ago", "2,341", "Active"),
            ("Internal Honeypot", "Internal", "-", "15 min", "Just now", "156", "Active"),
            ("CISA Known Exploited", "Government", "https://cisa.gov/kev", "24 hours", "12 hours ago", "89", "Active")
        ]
        
        for i, (name, ftype, url, interval, last, iocs, status) in enumerate(feeds):
            self.feeds_table.insertRow(i)
            self.feeds_table.setItem(i, 0, QTableWidgetItem(name))
            self.feeds_table.setItem(i, 1, QTableWidgetItem(ftype))
            self.feeds_table.setItem(i, 2, QTableWidgetItem(url))
            self.feeds_table.setItem(i, 3, QTableWidgetItem(interval))
            self.feeds_table.setItem(i, 4, QTableWidgetItem(last))
            self.feeds_table.setItem(i, 5, QTableWidgetItem(iocs))
            
            status_item = QTableWidgetItem(status)
            status_item.setForeground(QColor("#00ff88" if status == "Active" else "#ff6b6b"))
            self.feeds_table.setItem(i, 6, status_item)
        
        layout.addWidget(self.feeds_table)
        
        # Actions
        actions_layout = QHBoxLayout()
        
        refresh_all_btn = QPushButton("🔄 Refresh All Feeds")
        refresh_all_btn.clicked.connect(self.refresh_feeds)
        
        import_btn = QPushButton("📥 Import STIX/TAXII")
        export_btn = QPushButton("📤 Export IOCs")
        
        actions_layout.addWidget(refresh_all_btn)
        actions_layout.addWidget(import_btn)
        actions_layout.addWidget(export_btn)
        actions_layout.addStretch()
        
        layout.addLayout(actions_layout)
        
        return widget
    
    def create_actors_tab(self) -> QWidget:
        """Create threat actors tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Splitter for list and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Actors list
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        search = QLineEdit()
        search.setPlaceholderText("Search actors...")
        left_layout.addWidget(search)
        
        self.actors_table = QTableWidget()
        self.actors_table.setColumnCount(4)
        self.actors_table.setHorizontalHeaderLabels(["Name", "Origin", "Motivation", "Activity"])
        self.actors_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.actors_table.cellClicked.connect(self.show_actor_details)
        
        # Add demo actors
        actors = [
            ("APT29", "Russia", "Espionage", "7 days ago"),
            ("APT41", "China", "Espionage & Financial", "14 days ago"),
            ("LockBit Gang", "Unknown", "Financial", "3 days ago"),
            ("Lazarus Group", "North Korea", "Financial & Espionage", "5 days ago")
        ]
        
        for i, (name, origin, motivation, activity) in enumerate(actors):
            self.actors_table.insertRow(i)
            self.actors_table.setItem(i, 0, QTableWidgetItem(name))
            self.actors_table.setItem(i, 1, QTableWidgetItem(origin))
            self.actors_table.setItem(i, 2, QTableWidgetItem(motivation))
            self.actors_table.setItem(i, 3, QTableWidgetItem(activity))
        
        left_layout.addWidget(self.actors_table)
        splitter.addWidget(left_widget)
        
        # Actor details
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        right_layout.addWidget(QLabel("Actor Profile"))
        
        self.actor_details = QTextEdit()
        self.actor_details.setReadOnly(True)
        self.actor_details.setStyleSheet("background: #1a1a2e;")
        
        right_layout.addWidget(self.actor_details)
        
        # TTPs
        ttps_group = QGroupBox("MITRE ATT&CK TTPs")
        ttps_layout = QVBoxLayout(ttps_group)
        
        self.ttps_tree = QTreeWidget()
        self.ttps_tree.setHeaderLabels(["Technique", "Usage"])
        ttps_layout.addWidget(self.ttps_tree)
        
        right_layout.addWidget(ttps_group)
        
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        return widget
    
    def create_campaigns_tab(self) -> QWidget:
        """Create campaigns tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Campaigns table
        self.campaigns_table = QTableWidget()
        self.campaigns_table.setColumnCount(7)
        self.campaigns_table.setHorizontalHeaderLabels([
            "Name", "Actor", "Status", "Start Date", "Targets", "IOCs", "Malware"
        ])
        self.campaigns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Add demo campaigns
        campaigns = [
            ("SolarWinds", "APT29", "Concluded", "2020-03", "Government, Tech", "156", "SUNBURST"),
            ("LockBit 3.0", "LockBit Gang", "Active", "2022-06", "Global", "89", "LockBit3.0"),
            ("Operation Dream Job", "Lazarus", "Active", "2020-01", "Defense, Crypto", "67", "DRATzarus")
        ]
        
        for i, (name, actor, status, start, targets, iocs, malware) in enumerate(campaigns):
            self.campaigns_table.insertRow(i)
            self.campaigns_table.setItem(i, 0, QTableWidgetItem(name))
            self.campaigns_table.setItem(i, 1, QTableWidgetItem(actor))
            
            status_item = QTableWidgetItem(status)
            status_item.setForeground(QColor("#ff6b6b" if status == "Active" else "#888"))
            self.campaigns_table.setItem(i, 2, status_item)
            
            self.campaigns_table.setItem(i, 3, QTableWidgetItem(start))
            self.campaigns_table.setItem(i, 4, QTableWidgetItem(targets))
            self.campaigns_table.setItem(i, 5, QTableWidgetItem(iocs))
            self.campaigns_table.setItem(i, 6, QTableWidgetItem(malware))
        
        layout.addWidget(self.campaigns_table)
        
        # Campaign details
        details_group = QGroupBox("Campaign Details")
        details_layout = QVBoxLayout(details_group)
        
        self.campaign_details = QTextEdit()
        self.campaign_details.setReadOnly(True)
        self.campaign_details.setStyleSheet("background: #1a1a2e;")
        self.campaign_details.setText("""
Select a campaign to view details...

Campaign intelligence includes:
• Full timeline and attack phases
• Associated IOCs and malware families
• MITRE ATT&CK technique mapping
• Targeted sectors and regions
• Detection and mitigation guidance
""")
        
        details_layout.addWidget(self.campaign_details)
        layout.addWidget(details_group)
        
        return widget
    
    def create_reports_tab(self) -> QWidget:
        """Create reports tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Report generation
        gen_group = QGroupBox("Generate Intelligence Report")
        gen_layout = QGridLayout(gen_group)
        
        gen_layout.addWidget(QLabel("Report Type:"), 0, 0)
        self.report_type = QComboBox()
        self.report_type.addItems([
            "Threat Landscape Overview",
            "IOC Summary",
            "Actor Profile",
            "Campaign Analysis",
            "Weekly Digest"
        ])
        gen_layout.addWidget(self.report_type, 0, 1)
        
        gen_layout.addWidget(QLabel("Time Range:"), 0, 2)
        self.report_range = QComboBox()
        self.report_range.addItems(["24 hours", "7 days", "30 days", "90 days"])
        gen_layout.addWidget(self.report_range, 0, 3)
        
        gen_layout.addWidget(QLabel("Format:"), 1, 0)
        self.report_format = QComboBox()
        self.report_format.addItems(["PDF", "HTML", "JSON", "STIX 2.1"])
        gen_layout.addWidget(self.report_format, 1, 1)
        
        generate_btn = QPushButton("📊 Generate Report")
        generate_btn.clicked.connect(self.generate_report)
        gen_layout.addWidget(generate_btn, 1, 2, 1, 2)
        
        layout.addWidget(gen_group)
        
        # Report preview
        preview_group = QGroupBox("Report Preview")
        preview_layout = QVBoxLayout(preview_group)
        
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setStyleSheet("background: #0a0a1a;")
        
        preview_layout.addWidget(self.report_preview)
        layout.addWidget(preview_group)
        
        return widget
    
    def load_demo_data(self):
        """Load demo IOC data."""
        demo_iocs = [
            ("185.220.101.45", "IP Address", "High", "85%", "MISP, OTX", "apt29, c2", "1 hour ago", "78"),
            ("cozy-c2.com", "Domain", "Critical", "92%", "MISP", "apt29, c2", "2 hours ago", "95"),
            ("CVE-2024-3400", "CVE", "Critical", "100%", "CISA", "palo-alto", "3 hours ago", "100"),
            ("lockbit.onion", "Domain", "Critical", "88%", "OTX", "ransomware", "4 hours ago", "92"),
            ("45.33.32.156", "IP Address", "High", "75%", "Honeypot", "botnet", "30 min ago", "72"),
            ("secure-login-verify.com", "Domain", "Medium", "65%", "MISP", "phishing", "6 hours ago", "58")
        ]
        
        for i, (value, ioc_type, level, conf, sources, tags, seen, score) in enumerate(demo_iocs):
            self.iocs_table.insertRow(i)
            self.iocs_table.setItem(i, 0, QTableWidgetItem(value))
            self.iocs_table.setItem(i, 1, QTableWidgetItem(ioc_type))
            
            level_item = QTableWidgetItem(level)
            level_item.setForeground(QColor({
                "Critical": "#ff4444", "High": "#ff8844", "Medium": "#ffd93d", "Low": "#88ff88"
            }.get(level, "#fff")))
            self.iocs_table.setItem(i, 2, level_item)
            
            self.iocs_table.setItem(i, 3, QTableWidgetItem(conf))
            self.iocs_table.setItem(i, 4, QTableWidgetItem(sources))
            self.iocs_table.setItem(i, 5, QTableWidgetItem(tags))
            self.iocs_table.setItem(i, 6, QTableWidgetItem(seen))
            self.iocs_table.setItem(i, 7, QTableWidgetItem(score))
        
        # Update stats
        self.iocs_count.findChild(QLabel, "value").setText(str(len(demo_iocs)))
        critical = sum(1 for ioc in demo_iocs if ioc[2] == "Critical")
        self.critical_count.findChild(QLabel, "value").setText(str(critical))
    
    def filter_iocs(self, text: str):
        """Filter IOCs by search text."""
        for row in range(self.iocs_table.rowCount()):
            match = False
            for col in range(self.iocs_table.columnCount()):
                item = self.iocs_table.item(row, col)
                if item and text.lower() in item.text().lower():
                    match = True
                    break
            self.iocs_table.setRowHidden(row, not match)
    
    def check_ioc(self):
        """Check if IOC exists."""
        value = self.ioc_search.text()
        if not value:
            return
        
        # Search in table
        found = False
        for row in range(self.iocs_table.rowCount()):
            item = self.iocs_table.item(row, 0)
            if item and item.text().lower() == value.lower():
                self.iocs_table.selectRow(row)
                found = True
                break
        
        if not found:
            # Add message that IOC not found
            pass
    
    def add_ioc(self):
        """Add new IOC."""
        value = self.ioc_value_input.text()
        if not value:
            return
        
        row = self.iocs_table.rowCount()
        self.iocs_table.insertRow(row)
        
        items = [
            value,
            self.ioc_type_combo.currentText(),
            self.ioc_level_combo.currentText(),
            "50%",
            "Manual",
            self.ioc_tags_input.text(),
            "Just now",
            "50"
        ]
        
        for col, item in enumerate(items):
            cell = QTableWidgetItem(item)
            if col == 2:  # Level
                colors = {"Critical": "#ff4444", "High": "#ff8844", "Medium": "#ffd93d", "Low": "#88ff88"}
                cell.setForeground(QColor(colors.get(item, "#fff")))
            self.iocs_table.setItem(row, col, cell)
        
        # Update count
        count = self.iocs_table.rowCount()
        self.iocs_count.findChild(QLabel, "value").setText(str(count))
        
        # Clear inputs
        self.ioc_value_input.clear()
        self.ioc_tags_input.clear()
    
    def refresh_feeds(self):
        """Refresh all feeds."""
        for row in range(self.feeds_table.rowCount()):
            self.feeds_table.setItem(row, 4, QTableWidgetItem("Refreshing..."))
    
    def show_actor_details(self, row: int, col: int):
        """Show actor details."""
        name = self.actors_table.item(row, 0).text()
        
        profiles = {
            "APT29": """
═══════════════════════════════════════════════════════════════════════════════
                            THREAT ACTOR PROFILE
═══════════════════════════════════════════════════════════════════════════════

Name: APT29 (Cozy Bear, The Dukes, YTTRIUM)
Origin: Russia (State-Sponsored)
Motivation: Espionage
Sophistication: Advanced
Active Since: 2008

DESCRIPTION
─────────────────────────────────────────────────────────────────────────────

Russian state-sponsored threat actor attributed to the Foreign Intelligence
Service (SVR). Primarily targets government, diplomatic, and policy think
tanks in North America and Europe.

NOTABLE CAMPAIGNS
─────────────────────────────────────────────────────────────────────────────

• SolarWinds (2020) - Supply chain compromise
• WellMess (2020) - COVID-19 vaccine research targeting
• DNC Breach (2016) - Democratic National Committee

TARGET SECTORS
─────────────────────────────────────────────────────────────────────────────

Government • Defense • Think Tanks • Healthcare (COVID research)

ASSOCIATED IOCs: 156 | CONFIDENCE: 95%
═══════════════════════════════════════════════════════════════════════════════
""",
            "APT41": """
═══════════════════════════════════════════════════════════════════════════════
                            THREAT ACTOR PROFILE
═══════════════════════════════════════════════════════════════════════════════

Name: APT41 (Double Dragon, Wicked Panda, BARIUM)
Origin: China (State-Sponsored + Criminal)
Motivation: Espionage & Financial Gain
Sophistication: Advanced
Active Since: 2012

DESCRIPTION
─────────────────────────────────────────────────────────────────────────────

Chinese state-sponsored group with dual mission of espionage and financially
motivated attacks. Unique in conducting both state-directed operations and
cybercrime activities.

TARGET SECTORS
─────────────────────────────────────────────────────────────────────────────

Technology • Healthcare • Gaming • Telecommunications

ASSOCIATED IOCs: 89 | CONFIDENCE: 90%
═══════════════════════════════════════════════════════════════════════════════
"""
        }
        
        self.actor_details.setText(profiles.get(name, f"Profile for {name} not available"))
        
        # Update TTPs tree
        self.ttps_tree.clear()
        ttps = [
            ("T1566", "Phishing", "Frequent"),
            ("T1059", "Command and Scripting", "Common"),
            ("T1055", "Process Injection", "Common"),
            ("T1027", "Obfuscated Files", "Frequent"),
            ("T1071", "Application Layer Protocol", "Frequent")
        ]
        
        for tid, name, usage in ttps:
            item = QTreeWidgetItem([f"{tid}: {name}", usage])
            self.ttps_tree.addTopLevelItem(item)
    
    def generate_report(self):
        """Generate intelligence report."""
        report_type = self.report_type.currentText()
        time_range = self.report_range.currentText()
        
        self.report_preview.setText(f"""
═══════════════════════════════════════════════════════════════════════════════
                    THREAT INTELLIGENCE REPORT
═══════════════════════════════════════════════════════════════════════════════

Report Type: {report_type}
Time Range: {time_range}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Format: {self.report_format.currentText()}

EXECUTIVE SUMMARY
─────────────────────────────────────────────────────────────────────────────

The threat landscape continues to evolve with ransomware and APT activity
remaining the primary concerns. Key observations:

• LockBit 3.0 ransomware continues active operations globally
• APT29 has established new C2 infrastructure
• Critical vulnerability CVE-2024-3400 actively exploited
• Phishing campaigns targeting Microsoft 365 credentials increasing

KEY METRICS
─────────────────────────────────────────────────────────────────────────────

Total IOCs Tracked: {self.iocs_table.rowCount()}
Critical Threats: {self.critical_count.findChild(QLabel, "value").text()}
Active Campaigns: 3
Threat Actors Monitored: 4
Intelligence Feeds: 5

TOP THREATS
─────────────────────────────────────────────────────────────────────────────

1. 🔴 CVE-2024-3400 - Palo Alto GlobalProtect RCE
   Status: Actively Exploited | CVSS: 10.0

2. 🔴 LockBit 3.0 Ransomware Campaign
   Status: Active | Sectors: Healthcare, Manufacturing

3. 🟠 APT29 Activity
   Status: Active | New C2 infrastructure detected

RECOMMENDATIONS
─────────────────────────────────────────────────────────────────────────────

1. Patch CVE-2024-3400 immediately on all Palo Alto devices
2. Review and update ransomware defenses
3. Block known APT29 IOCs at perimeter
4. Implement enhanced email security for phishing protection
5. Share IOCs with security partners via TAXII

═══════════════════════════════════════════════════════════════════════════════
""")
