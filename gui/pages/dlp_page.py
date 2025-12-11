#!/usr/bin/env python3
"""
HydraRecon Data Loss Prevention GUI Page
Enterprise DLP monitoring and policy management interface.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget, QLineEdit,
    QComboBox, QTextEdit, QSpinBox, QCheckBox, QGroupBox, QGridLayout,
    QSplitter, QTreeWidget, QTreeWidgetItem, QProgressBar, QDialog,
    QFormLayout, QDialogButtonBox, QListWidget, QListWidgetItem, QScrollArea,
    QMessageBox
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor


class DLPPage(QWidget):
    """Data Loss Prevention management page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Stats bar
        stats = self._create_stats_bar()
        layout.addWidget(stats)
        
        # Main content tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane { 
                border: 1px solid #21262d;
                background: #0d1117;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #161b22;
                color: #8b949e;
                padding: 10px 20px;
                margin-right: 4px;
                border-radius: 6px 6px 0 0;
            }
            QTabBar::tab:selected {
                background: #dc2626;
                color: white;
            }
        """)
        
        tabs.addTab(self._create_violations_tab(), "🚨 Violations")
        tabs.addTab(self._create_policies_tab(), "📋 Policies")
        tabs.addTab(self._create_patterns_tab(), "🔍 Patterns")
        tabs.addTab(self._create_inventory_tab(), "📦 Data Inventory")
        tabs.addTab(self._create_discovery_tab(), "🔎 Discovery")
        tabs.addTab(self._create_reports_tab(), "📊 Reports")
        
        layout.addWidget(tabs, 1)
    
    def _create_header(self) -> QWidget:
        """Create page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #dc2626, stop:1 #ef4444);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        title_section = QVBoxLayout()
        
        title = QLabel("🔒 Data Loss Prevention")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: white;")
        
        subtitle = QLabel("Monitor, detect, and prevent sensitive data exfiltration")
        subtitle.setStyleSheet("font-size: 14px; color: rgba(255,255,255,0.8);")
        
        title_section.addWidget(title)
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        scan_btn = QPushButton("🔎 Start Scan")
        scan_btn.setStyleSheet("""
            QPushButton {
                background: white;
                color: #dc2626;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background: #f0f0f0; }
        """)
        scan_btn.clicked.connect(self._start_discovery_scan)
        
        policy_btn = QPushButton("📋 New Policy")
        policy_btn.setStyleSheet("""
            QPushButton {
                background: rgba(255,255,255,0.2);
                color: white;
                border: 1px solid rgba(255,255,255,0.3);
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background: rgba(255,255,255,0.3); }
        """)
        policy_btn.clicked.connect(self._create_policy)
        
        btn_layout.addWidget(scan_btn)
        btn_layout.addWidget(policy_btn)
        
        layout.addLayout(btn_layout)
        
        return header
    
    def _create_stats_bar(self) -> QWidget:
        """Create statistics bar"""
        stats = QFrame()
        stats.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(stats)
        
        stat_items = [
            ("🚨", "Violations Today", "47", "#ef4444"),
            ("🛑", "Blocked Transfers", "12", "#f97316"),
            ("📋", "Active Policies", "8", "#06b6d4"),
            ("🔍", "Patterns", "156", "#8b5cf6"),
            ("📦", "Sensitive Files", "2,847", "#22c55e")
        ]
        
        for icon, label, value, color in stat_items:
            stat_widget = self._create_stat_item(icon, label, value, color)
            layout.addWidget(stat_widget)
        
        return stats
    
    def _create_stat_item(self, icon: str, label: str, value: str, color: str) -> QWidget:
        """Create individual stat item"""
        widget = QFrame()
        widget.setStyleSheet(f"""
            QFrame {{
                background: {color}15;
                border: 1px solid {color}40;
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        
        layout = QVBoxLayout(widget)
        layout.setSpacing(4)
        
        top = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setStyleSheet("font-size: 20px;")
        top.addWidget(icon_label)
        top.addStretch()
        
        value_label = QLabel(value)
        value_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
        
        text_label = QLabel(label)
        text_label.setStyleSheet("font-size: 12px; color: #8b949e;")
        
        layout.addLayout(top)
        layout.addWidget(value_label)
        layout.addWidget(text_label)
        
        return widget
    
    def _create_violations_tab(self) -> QWidget:
        """Create violations monitoring tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Filters
        filters = QHBoxLayout()
        
        severity_combo = QComboBox()
        severity_combo.addItems(["All Severities", "Critical", "High", "Medium", "Low"])
        severity_combo.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
                min-width: 150px;
            }
        """)
        
        channel_combo = QComboBox()
        channel_combo.addItems(["All Channels", "Email", "Web Upload", "USB", "Cloud Storage", "Network"])
        channel_combo.setStyleSheet(severity_combo.styleSheet())
        
        content_combo = QComboBox()
        content_combo.addItems(["All Types", "PII", "PCI", "PHI", "Credentials", "Source Code", "Financial"])
        content_combo.setStyleSheet(severity_combo.styleSheet())
        
        time_combo = QComboBox()
        time_combo.addItems(["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"])
        time_combo.setStyleSheet(severity_combo.styleSheet())
        
        filters.addWidget(severity_combo)
        filters.addWidget(channel_combo)
        filters.addWidget(content_combo)
        filters.addWidget(time_combo)
        filters.addStretch()
        
        export_btn = QPushButton("📥 Export")
        export_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                color: white;
            }
        """)
        filters.addWidget(export_btn)
        
        layout.addLayout(filters)
        
        # Violations table
        table = QTableWidget()
        table.setColumnCount(9)
        table.setHorizontalHeaderLabels([
            "Time", "Severity", "User", "Channel", "Content Type", "Policy", "Action", "Blocked", "Details"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 10px;
                border-bottom: 1px solid #21262d;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        
        violations = [
            ("10:45:22", "critical", "jsmith", "Email", "PCI", "Credit Card Policy", "Block", True, "4 CC numbers"),
            ("10:32:15", "high", "mdoe", "Cloud Storage", "Credentials", "Secret Detection", "Warn", False, "AWS keys"),
            ("10:18:44", "high", "rjohnson", "USB", "PII", "PII Protection", "Block", True, "SSN detected"),
            ("09:55:33", "medium", "agarcia", "Web Upload", "Source Code", "Code Exfil Policy", "Log", False, "Python files"),
            ("09:42:11", "medium", "bwilson", "Email", "Financial", "Financial Data", "Warn", False, "Bank statements"),
            ("09:28:05", "low", "cthompson", "Network", "Internal", "Data Classification", "Log", False, "Internal doc"),
        ]
        
        severity_colors = {
            "critical": "#ef4444", "high": "#f97316",
            "medium": "#eab308", "low": "#22c55e"
        }
        
        table.setRowCount(len(violations))
        for row, violation in enumerate(violations):
            for col, value in enumerate(violation):
                if col == 1:  # Severity
                    item = QTableWidgetItem(str(value).upper())
                    item.setForeground(QColor(severity_colors.get(value, "#8b949e")))
                elif col == 7:  # Blocked
                    item = QTableWidgetItem("✅ Yes" if value else "❌ No")
                    item.setForeground(QColor("#22c55e" if value else "#ef4444"))
                else:
                    item = QTableWidgetItem(str(value))
                table.setItem(row, col, item)
        
        layout.addWidget(table, 1)
        
        return widget
    
    def _create_policies_tab(self) -> QWidget:
        """Create policies management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        search = QLineEdit()
        search.setPlaceholderText("🔍 Search policies...")
        search.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
            }
        """)
        toolbar.addWidget(search)
        toolbar.addStretch()
        
        add_btn = QPushButton("➕ Add Policy")
        add_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                color: white;
            }
        """)
        add_btn.clicked.connect(self._create_policy)
        toolbar.addWidget(add_btn)
        
        layout.addLayout(toolbar)
        
        # Policies table
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "Policy Name", "Description", "Channels", "Actions", "Severity", "Violations", "Status", "Edit"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        
        policies = [
            ("PCI-DSS Compliance", "Block credit card data exfiltration", "Email, Web, USB", "Block, Notify", "Critical", 45),
            ("PII Protection", "Protect personal identifiable information", "All Channels", "Block, Log", "High", 128),
            ("Credential Detection", "Detect leaked API keys and passwords", "Email, Cloud", "Warn, Notify", "High", 67),
            ("Source Code Protection", "Prevent code exfiltration", "USB, Cloud", "Block, Log", "High", 23),
            ("HIPAA Compliance", "Protect health information", "Email, Print", "Block, Notify", "Critical", 12),
            ("Financial Data", "Protect financial documents", "All Channels", "Warn, Log", "Medium", 34),
        ]
        
        table.setRowCount(len(policies))
        for row, policy in enumerate(policies):
            for col, value in enumerate(policy):
                item = QTableWidgetItem(str(value))
                table.setItem(row, col, item)
            
            # Status toggle
            status_btn = QPushButton("Enabled")
            status_btn.setStyleSheet("""
                QPushButton {
                    background: #22c55e;
                    border: none;
                    padding: 4px 8px;
                    border-radius: 4px;
                    color: white;
                    font-size: 11px;
                }
            """)
            table.setCellWidget(row, 6, status_btn)
            
            # Edit button
            edit_btn = QPushButton("✏️ Edit")
            edit_btn.setStyleSheet("""
                QPushButton {
                    background: #0969da;
                    border: none;
                    padding: 4px 8px;
                    border-radius: 4px;
                    color: white;
                }
            """)
            table.setCellWidget(row, 7, edit_btn)
        
        layout.addWidget(table, 1)
        
        return widget
    
    def _create_patterns_tab(self) -> QWidget:
        """Create patterns management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Pattern categories
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Categories tree
        categories = QTreeWidget()
        categories.setHeaderLabel("Pattern Categories")
        categories.setStyleSheet("""
            QTreeWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
            QTreeWidget::item {
                padding: 8px;
            }
            QTreeWidget::item:selected {
                background: #21262d;
            }
        """)
        categories.setMaximumWidth(250)
        
        pattern_categories = {
            "🔐 PII": ["SSN", "Email", "Phone", "Address", "Passport", "Driver License"],
            "💳 PCI": ["Credit Card", "CVV", "Bank Account", "IBAN"],
            "🏥 PHI": ["Medical Record", "NPI", "ICD Codes", "Patient Data"],
            "🔑 Credentials": ["AWS Keys", "API Keys", "Private Keys", "Passwords", "JWT Tokens"],
            "💰 Financial": ["Tax ID", "Routing Number", "Wire Instructions"],
            "💻 Source Code": ["Code Headers", "Proprietary Functions", "Trade Secrets"]
        }
        
        for category, patterns in pattern_categories.items():
            cat_item = QTreeWidgetItem([category])
            for pattern in patterns:
                QTreeWidgetItem(cat_item, [pattern])
            categories.addTopLevelItem(cat_item)
        
        categories.expandAll()
        splitter.addWidget(categories)
        
        # Pattern details
        details = QFrame()
        details.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
                padding: 20px;
            }
        """)
        
        details_layout = QVBoxLayout(details)
        
        pattern_title = QLabel("SSN Pattern")
        pattern_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e6e6e6;")
        details_layout.addWidget(pattern_title)
        
        pattern_form = QFormLayout()
        
        regex_input = QLineEdit(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b")
        regex_input.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
                font-family: monospace;
            }
        """)
        pattern_form.addRow("Regex Pattern:", regex_input)
        
        keywords_input = QLineEdit("ssn, social security, tax id")
        keywords_input.setStyleSheet(regex_input.styleSheet())
        pattern_form.addRow("Keywords:", keywords_input)
        
        threshold_spin = QSpinBox()
        threshold_spin.setValue(1)
        threshold_spin.setMinimum(1)
        threshold_spin.setMaximum(100)
        pattern_form.addRow("Match Threshold:", threshold_spin)
        
        classification_combo = QComboBox()
        classification_combo.addItems(["Public", "Internal", "Confidential", "Restricted", "Top Secret"])
        classification_combo.setCurrentIndex(3)
        pattern_form.addRow("Classification:", classification_combo)
        
        details_layout.addLayout(pattern_form)
        
        # Test area
        test_group = QGroupBox("Pattern Tester")
        test_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        test_layout = QVBoxLayout(test_group)
        
        test_input = QTextEdit()
        test_input.setPlaceholderText("Enter test content to check for pattern matches...")
        test_input.setMaximumHeight(100)
        test_layout.addWidget(test_input)
        
        test_btn = QPushButton("🔍 Test Pattern")
        test_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                color: white;
            }
        """)
        test_layout.addWidget(test_btn)
        
        details_layout.addWidget(test_group)
        details_layout.addStretch()
        
        splitter.addWidget(details)
        layout.addWidget(splitter)
        
        return widget
    
    def _create_inventory_tab(self) -> QWidget:
        """Create data inventory tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Classification breakdown
        class_frame = QFrame()
        class_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        
        class_layout = QHBoxLayout(class_frame)
        
        classifications = [
            ("🟢", "Public", "1,234", "#22c55e"),
            ("🔵", "Internal", "3,456", "#0969da"),
            ("🟡", "Confidential", "892", "#eab308"),
            ("🟠", "Restricted", "234", "#f97316"),
            ("🔴", "Top Secret", "31", "#ef4444")
        ]
        
        for icon, name, count, color in classifications:
            item = QFrame()
            item.setStyleSheet(f"""
                QFrame {{
                    background: {color}20;
                    border: 1px solid {color}40;
                    border-radius: 6px;
                    padding: 10px;
                }}
            """)
            item_layout = QVBoxLayout(item)
            
            header = QLabel(f"{icon} {name}")
            header.setStyleSheet(f"color: {color}; font-weight: bold;")
            
            value = QLabel(count)
            value.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
            
            item_layout.addWidget(header)
            item_layout.addWidget(value)
            
            class_layout.addWidget(item)
        
        layout.addWidget(class_frame)
        
        # Inventory table
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels([
            "File Path", "Classification", "Content Type", "Size", "Owner", "Discovered", "Patterns"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        
        files = [
            ("/data/customers.csv", "Restricted", "PII", "2.4 MB", "admin", "2024-01-15", "SSN, Email"),
            ("/config/database.yml", "Top Secret", "Credentials", "4 KB", "devops", "2024-01-14", "Password"),
            ("/docs/financials.xlsx", "Confidential", "Financial", "1.2 MB", "finance", "2024-01-13", "Bank Account"),
            ("/src/api/keys.py", "Restricted", "Credentials", "2 KB", "dev", "2024-01-12", "API Keys"),
            ("/hr/employees.json", "Restricted", "PII", "890 KB", "hr", "2024-01-11", "SSN, Address"),
        ]
        
        class_colors = {
            "Public": "#22c55e", "Internal": "#0969da",
            "Confidential": "#eab308", "Restricted": "#f97316",
            "Top Secret": "#ef4444"
        }
        
        table.setRowCount(len(files))
        for row, file_data in enumerate(files):
            for col, value in enumerate(file_data):
                item = QTableWidgetItem(str(value))
                if col == 1:  # Classification
                    item.setForeground(QColor(class_colors.get(value, "#8b949e")))
                table.setItem(row, col, item)
        
        layout.addWidget(table, 1)
        
        return widget
    
    def _create_discovery_tab(self) -> QWidget:
        """Create data discovery tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Scan configuration
        config_group = QGroupBox("Discovery Scan Configuration")
        config_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        
        config_layout = QFormLayout(config_group)
        
        paths_input = QLineEdit()
        paths_input.setPlaceholderText("/home, /data, /var/www, /opt")
        paths_input.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        config_layout.addRow("Scan Paths:", paths_input)
        
        extensions_input = QLineEdit()
        extensions_input.setText(".txt, .csv, .json, .xml, .yaml, .env, .conf")
        extensions_input.setStyleSheet(paths_input.styleSheet())
        config_layout.addRow("File Extensions:", extensions_input)
        
        recursive_check = QCheckBox("Recursive scan")
        recursive_check.setChecked(True)
        config_layout.addRow("", recursive_check)
        
        layout.addWidget(config_group)
        
        # Scan controls
        controls = QHBoxLayout()
        
        start_btn = QPushButton("▶️ Start Discovery Scan")
        start_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                color: white;
                font-weight: bold;
            }
        """)
        
        schedule_btn = QPushButton("📅 Schedule Scan")
        schedule_btn.setStyleSheet("""
            QPushButton {
                background: #0969da;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                color: white;
            }
        """)
        
        controls.addWidget(start_btn)
        controls.addWidget(schedule_btn)
        controls.addStretch()
        
        layout.addLayout(controls)
        
        # Scan progress/results
        progress_frame = QFrame()
        progress_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
                padding: 20px;
            }
        """)
        
        progress_layout = QVBoxLayout(progress_frame)
        
        progress_label = QLabel("Last Scan Results - Completed 2024-01-20 09:45")
        progress_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6;")
        progress_layout.addWidget(progress_label)
        
        results_grid = QGridLayout()
        
        result_items = [
            ("Files Scanned", "45,678", "#06b6d4"),
            ("Sensitive Found", "2,847", "#f97316"),
            ("New Discoveries", "156", "#22c55e"),
            ("Scan Duration", "12m 34s", "#8b949e")
        ]
        
        for i, (label, value, color) in enumerate(result_items):
            lbl = QLabel(label)
            lbl.setStyleSheet("color: #8b949e;")
            val = QLabel(value)
            val.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {color};")
            results_grid.addWidget(lbl, i // 2, (i % 2) * 2)
            results_grid.addWidget(val, i // 2, (i % 2) * 2 + 1)
        
        progress_layout.addLayout(results_grid)
        layout.addWidget(progress_frame)
        
        layout.addStretch()
        
        return widget
    
    def _create_reports_tab(self) -> QWidget:
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Report types
        report_grid = QGridLayout()
        
        report_types = [
            ("📊", "Violation Summary", "Overview of all DLP violations"),
            ("👥", "User Activity", "DLP events by user"),
            ("📁", "Data Inventory", "Sensitive data inventory report"),
            ("📋", "Policy Effectiveness", "Policy hit rates and trends"),
            ("🔍", "Discovery Report", "Data discovery scan results"),
            ("✅", "Compliance Report", "Regulatory compliance status")
        ]
        
        for i, (icon, name, desc) in enumerate(report_types):
            card = QFrame()
            card.setStyleSheet("""
                QFrame {
                    background: #161b22;
                    border: 1px solid #21262d;
                    border-radius: 8px;
                    padding: 15px;
                }
                QFrame:hover {
                    border-color: #dc2626;
                }
            """)
            
            card_layout = QVBoxLayout(card)
            
            header = QLabel(f"{icon} {name}")
            header.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6;")
            
            description = QLabel(desc)
            description.setStyleSheet("color: #8b949e;")
            
            generate_btn = QPushButton("Generate Report")
            generate_btn.setStyleSheet("""
                QPushButton {
                    background: #dc2626;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 6px;
                    color: white;
                }
            """)
            
            card_layout.addWidget(header)
            card_layout.addWidget(description)
            card_layout.addWidget(generate_btn)
            
            report_grid.addWidget(card, i // 3, i % 3)
        
        layout.addLayout(report_grid)
        layout.addStretch()
        
        return widget
    
    def _start_discovery_scan(self):
        """Start data discovery scan"""
        QMessageBox.information(
            self, "Discovery Scan",
            "Data discovery scan initiated.\n\nThis will scan configured paths for sensitive data patterns."
        )
    
    def _create_policy(self):
        """Create new DLP policy dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Create DLP Policy")
        dialog.setMinimumWidth(600)
        dialog.setStyleSheet("""
            QDialog {
                background: #0d1117;
            }
            QLabel {
                color: #e6e6e6;
            }
        """)
        
        layout = QVBoxLayout(dialog)
        
        form = QFormLayout()
        
        name_input = QLineEdit()
        name_input.setPlaceholderText("e.g., PCI-DSS Compliance")
        form.addRow("Policy Name:", name_input)
        
        desc_input = QTextEdit()
        desc_input.setMaximumHeight(80)
        desc_input.setPlaceholderText("Describe the policy purpose...")
        form.addRow("Description:", desc_input)
        
        # Channels
        channels_group = QGroupBox("Channels to Monitor")
        channels_layout = QGridLayout(channels_group)
        
        channel_options = ["Email", "Web Upload", "USB", "Cloud Storage", "Print", "Network", "Clipboard"]
        for i, channel in enumerate(channel_options):
            cb = QCheckBox(channel)
            channels_layout.addWidget(cb, i // 3, i % 3)
        
        form.addRow(channels_group)
        
        # Actions
        actions_group = QGroupBox("Actions")
        actions_layout = QHBoxLayout(actions_group)
        
        for action in ["Log", "Warn", "Block", "Quarantine", "Notify Admin"]:
            cb = QCheckBox(action)
            if action in ["Log", "Block"]:
                cb.setChecked(True)
            actions_layout.addWidget(cb)
        
        form.addRow(actions_group)
        
        severity_combo = QComboBox()
        severity_combo.addItems(["Low", "Medium", "High", "Critical"])
        severity_combo.setCurrentIndex(2)
        form.addRow("Severity:", severity_combo)
        
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.exec()
