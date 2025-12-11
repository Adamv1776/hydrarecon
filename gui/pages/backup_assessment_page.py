#!/usr/bin/env python3
"""
HydraRecon Backup & DR Assessment GUI Page
Enterprise backup security and disaster recovery assessment interface.
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


class BackupAssessmentPage(QWidget):
    """Backup & DR Assessment management page"""
    
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
        
        # Health score
        health = self._create_health_section()
        layout.addWidget(health)
        
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
                background: #0969da;
                color: white;
            }
        """)
        
        tabs.addTab(self._create_overview_tab(), "📊 Overview")
        tabs.addTab(self._create_targets_tab(), "🖥️ Backup Targets")
        tabs.addTab(self._create_jobs_tab(), "📋 Backup Jobs")
        tabs.addTab(self._create_storage_tab(), "💾 Storage")
        tabs.addTab(self._create_dr_plans_tab(), "🔄 DR Plans")
        tabs.addTab(self._create_findings_tab(), "⚠️ Findings")
        tabs.addTab(self._create_compliance_tab(), "✅ Compliance")
        
        layout.addWidget(tabs, 1)
    
    def _create_header(self) -> QWidget:
        """Create page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0969da, stop:1 #1f6feb);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        title_section = QVBoxLayout()
        
        title = QLabel("💾 Backup & DR Assessment")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: white;")
        
        subtitle = QLabel("Assess backup security and disaster recovery readiness")
        subtitle.setStyleSheet("font-size: 14px; color: rgba(255,255,255,0.8);")
        
        title_section.addWidget(title)
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        assess_btn = QPushButton("🔍 Run Assessment")
        assess_btn.setStyleSheet("""
            QPushButton {
                background: white;
                color: #0969da;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background: #f0f0f0; }
        """)
        assess_btn.clicked.connect(self._run_assessment)
        
        dr_test_btn = QPushButton("🔄 Schedule DR Test")
        dr_test_btn.setStyleSheet("""
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
        
        btn_layout.addWidget(assess_btn)
        btn_layout.addWidget(dr_test_btn)
        
        layout.addLayout(btn_layout)
        
        return header
    
    def _create_health_section(self) -> QWidget:
        """Create health score section"""
        health = QFrame()
        health.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 10px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(health)
        
        # Health score gauge
        score_widget = QFrame()
        score_layout = QVBoxLayout(score_widget)
        
        score_label = QLabel("Backup Health Score")
        score_label.setStyleSheet("font-size: 14px; color: #8b949e;")
        
        score_value = QLabel("78%")
        score_value.setStyleSheet("font-size: 48px; font-weight: bold; color: #22c55e;")
        
        score_bar = QProgressBar()
        score_bar.setValue(78)
        score_bar.setStyleSheet("""
            QProgressBar {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                height: 16px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #22c55e, stop:1 #16a34a);
                border-radius: 6px;
            }
        """)
        
        score_layout.addWidget(score_label)
        score_layout.addWidget(score_value)
        score_layout.addWidget(score_bar)
        
        layout.addWidget(score_widget)
        
        # Key metrics
        metrics = QGridLayout()
        
        metric_items = [
            ("🖥️", "Protected Systems", "45/50", "#22c55e"),
            ("✅", "Backup Success Rate", "96.5%", "#22c55e"),
            ("⚠️", "Failed Last 24h", "2", "#f97316"),
            ("🔒", "Encrypted", "92%", "#06b6d4"),
            ("📅", "DR Test Due", "15 days", "#eab308"),
            ("🔍", "Critical Findings", "3", "#ef4444")
        ]
        
        for i, (icon, label, value, color) in enumerate(metric_items):
            item = QFrame()
            item.setStyleSheet(f"""
                QFrame {{
                    background: {color}15;
                    border: 1px solid {color}40;
                    border-radius: 8px;
                    padding: 10px;
                }}
            """)
            item_layout = QVBoxLayout(item)
            
            header = QLabel(f"{icon} {label}")
            header.setStyleSheet("color: #8b949e; font-size: 12px;")
            
            val = QLabel(value)
            val.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {color};")
            
            item_layout.addWidget(header)
            item_layout.addWidget(val)
            
            metrics.addWidget(item, i // 3, i % 3)
        
        layout.addLayout(metrics)
        
        return health
    
    def _create_overview_tab(self) -> QWidget:
        """Create overview tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Quick stats grid
        grid = QGridLayout()
        
        # Backup status card
        backup_card = self._create_status_card(
            "Backup Status",
            [
                ("Total Systems", "50", "#e6e6e6"),
                ("Protected", "45", "#22c55e"),
                ("Unprotected", "5", "#ef4444"),
                ("Last 24h Success", "42", "#22c55e"),
                ("Last 24h Failed", "3", "#f97316")
            ]
        )
        grid.addWidget(backup_card, 0, 0)
        
        # Storage status card
        storage_card = self._create_status_card(
            "Storage Status",
            [
                ("Total Capacity", "50 TB", "#e6e6e6"),
                ("Used", "32 TB (64%)", "#06b6d4"),
                ("Available", "18 TB", "#22c55e"),
                ("Encrypted", "45 TB (90%)", "#8b5cf6"),
                ("Air-Gapped", "10 TB", "#f97316")
            ]
        )
        grid.addWidget(storage_card, 0, 1)
        
        # DR Readiness card
        dr_card = self._create_status_card(
            "DR Readiness",
            [
                ("Active DR Plans", "5", "#e6e6e6"),
                ("Tested This Year", "4", "#22c55e"),
                ("Testing Overdue", "1", "#f97316"),
                ("Avg RTO Achieved", "3.2 hours", "#06b6d4"),
                ("Last Test Result", "Passed", "#22c55e")
            ]
        )
        grid.addWidget(dr_card, 1, 0)
        
        # Compliance card
        compliance_card = self._create_status_card(
            "Compliance Status",
            [
                ("Frameworks", "SOC2, HIPAA, PCI", "#e6e6e6"),
                ("Overall Score", "85%", "#22c55e"),
                ("Controls Passed", "42/50", "#22c55e"),
                ("Controls Failed", "8", "#ef4444"),
                ("Next Audit", "30 days", "#eab308")
            ]
        )
        grid.addWidget(compliance_card, 1, 1)
        
        layout.addLayout(grid)
        
        return widget
    
    def _create_status_card(self, title: str, items: list) -> QWidget:
        """Create status card widget"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 10px;
                padding: 20px;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #e6e6e6;")
        layout.addWidget(title_label)
        
        for label, value, color in items:
            row = QHBoxLayout()
            
            lbl = QLabel(label)
            lbl.setStyleSheet("color: #8b949e;")
            
            val = QLabel(value)
            val.setStyleSheet(f"color: {color}; font-weight: bold;")
            
            row.addWidget(lbl)
            row.addStretch()
            row.addWidget(val)
            
            layout.addLayout(row)
        
        return card
    
    def _create_targets_tab(self) -> QWidget:
        """Create backup targets tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        search = QLineEdit()
        search.setPlaceholderText("🔍 Search systems...")
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
        
        criticality_combo = QComboBox()
        criticality_combo.addItems(["All Criticality", "Critical", "High", "Medium", "Low"])
        criticality_combo.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
                min-width: 150px;
            }
        """)
        toolbar.addWidget(criticality_combo)
        
        status_combo = QComboBox()
        status_combo.addItems(["All Status", "Protected", "Unprotected", "RPO Violation"])
        status_combo.setStyleSheet(criticality_combo.styleSheet())
        toolbar.addWidget(status_combo)
        
        toolbar.addStretch()
        
        add_btn = QPushButton("➕ Add System")
        add_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                color: white;
            }
        """)
        toolbar.addWidget(add_btn)
        
        layout.addLayout(toolbar)
        
        # Systems table
        table = QTableWidget()
        table.setColumnCount(9)
        table.setHorizontalHeaderLabels([
            "System", "IP Address", "OS", "Criticality", "RPO", "RTO", "Last Backup", "Status", "Actions"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        
        systems = [
            ("db-prod-01", "192.168.1.10", "Ubuntu 22.04", "Critical", "4h", "2h", "15 min ago", "protected"),
            ("web-prod-01", "192.168.1.20", "Ubuntu 22.04", "Critical", "4h", "1h", "30 min ago", "protected"),
            ("app-server-01", "192.168.1.30", "RHEL 8", "High", "8h", "4h", "2 hours ago", "protected"),
            ("file-server", "192.168.1.40", "Windows Server", "High", "12h", "4h", "1 day ago", "warning"),
            ("dev-server", "192.168.1.50", "Ubuntu 20.04", "Medium", "24h", "8h", "3 days ago", "violation"),
            ("backup-server", "192.168.1.60", "Ubuntu 22.04", "Critical", "1h", "30m", "5 min ago", "protected"),
        ]
        
        status_colors = {
            "protected": "#22c55e",
            "warning": "#eab308",
            "violation": "#ef4444",
            "unprotected": "#8b949e"
        }
        
        criticality_colors = {
            "Critical": "#ef4444",
            "High": "#f97316",
            "Medium": "#eab308",
            "Low": "#22c55e"
        }
        
        table.setRowCount(len(systems))
        for row, system in enumerate(systems):
            for col, value in enumerate(system):
                item = QTableWidgetItem(str(value).capitalize() if col == 7 else str(value))
                if col == 3:  # Criticality
                    item.setForeground(QColor(criticality_colors.get(value, "#8b949e")))
                elif col == 7:  # Status
                    item.setForeground(QColor(status_colors.get(value, "#8b949e")))
                table.setItem(row, col, item)
        
        layout.addWidget(table, 1)
        
        return widget
    
    def _create_jobs_tab(self) -> QWidget:
        """Create backup jobs tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Filter bar
        filters = QHBoxLayout()
        
        time_combo = QComboBox()
        time_combo.addItems(["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"])
        time_combo.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        
        status_combo = QComboBox()
        status_combo.addItems(["All Status", "Success", "Failed", "Running", "Warning"])
        status_combo.setStyleSheet(time_combo.styleSheet())
        
        type_combo = QComboBox()
        type_combo.addItems(["All Types", "Full", "Incremental", "Differential", "Snapshot"])
        type_combo.setStyleSheet(time_combo.styleSheet())
        
        filters.addWidget(time_combo)
        filters.addWidget(status_combo)
        filters.addWidget(type_combo)
        filters.addStretch()
        
        layout.addLayout(filters)
        
        # Jobs table
        table = QTableWidget()
        table.setColumnCount(9)
        table.setHorizontalHeaderLabels([
            "Job ID", "System", "Type", "Started", "Duration", "Size", "Encrypted", "Verified", "Status"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        
        jobs = [
            ("BKP-001245", "db-prod-01", "Full", "10:30:00", "45m", "125 GB", True, True, "success"),
            ("BKP-001244", "web-prod-01", "Incremental", "10:15:00", "12m", "2.5 GB", True, True, "success"),
            ("BKP-001243", "app-server", "Incremental", "10:00:00", "8m", "1.2 GB", True, False, "success"),
            ("BKP-001242", "file-server", "Full", "09:00:00", "2h 15m", "500 GB", True, True, "success"),
            ("BKP-001241", "dev-server", "Full", "08:00:00", "-", "-", False, False, "failed"),
            ("BKP-001240", "backup-server", "Snapshot", "07:45:00", "5m", "50 GB", True, True, "success"),
        ]
        
        table.setRowCount(len(jobs))
        for row, job in enumerate(jobs):
            for col, value in enumerate(job):
                if col in [6, 7]:  # Encrypted, Verified
                    item = QTableWidgetItem("✅" if value else "❌")
                    item.setForeground(QColor("#22c55e" if value else "#ef4444"))
                elif col == 8:  # Status
                    status_colors = {"success": "#22c55e", "failed": "#ef4444", "running": "#0969da"}
                    item = QTableWidgetItem(str(value).upper())
                    item.setForeground(QColor(status_colors.get(value, "#8b949e")))
                else:
                    item = QTableWidgetItem(str(value))
                table.setItem(row, col, item)
        
        layout.addWidget(table, 1)
        
        return widget
    
    def _create_storage_tab(self) -> QWidget:
        """Create storage management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Storage locations
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        
        content = QWidget()
        cards_layout = QVBoxLayout(content)
        
        storage_locations = [
            {
                "name": "Primary NAS Storage",
                "type": "NAS",
                "location": "Datacenter A",
                "capacity": 20,
                "used": 14,
                "encrypted": True,
                "air_gapped": False,
                "immutable": False
            },
            {
                "name": "AWS S3 Bucket",
                "type": "Cloud",
                "location": "us-east-1",
                "capacity": 50,
                "used": 28,
                "encrypted": True,
                "air_gapped": False,
                "immutable": True
            },
            {
                "name": "Offline Tape Library",
                "type": "Tape",
                "location": "Vault B",
                "capacity": 100,
                "used": 45,
                "encrypted": True,
                "air_gapped": True,
                "immutable": True
            },
            {
                "name": "DR Site Storage",
                "type": "SAN",
                "location": "Datacenter B",
                "capacity": 30,
                "used": 18,
                "encrypted": True,
                "air_gapped": False,
                "immutable": False
            }
        ]
        
        for storage in storage_locations:
            card = self._create_storage_card(storage)
            cards_layout.addWidget(card)
        
        cards_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)
        
        return widget
    
    def _create_storage_card(self, storage: dict) -> QWidget:
        """Create storage location card"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 10px;
                padding: 20px;
            }
            QFrame:hover {
                border-color: #0969da;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        # Header
        header = QHBoxLayout()
        
        icon_map = {"NAS": "🗄️", "Cloud": "☁️", "Tape": "📼", "SAN": "💾"}
        name_label = QLabel(f"{icon_map.get(storage['type'], '💾')} {storage['name']}")
        name_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #e6e6e6;")
        
        type_badge = QLabel(storage['type'])
        type_badge.setStyleSheet("""
            background: #0969da;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
        """)
        
        header.addWidget(name_label)
        header.addStretch()
        header.addWidget(type_badge)
        
        layout.addLayout(header)
        
        # Location
        location_label = QLabel(f"📍 {storage['location']}")
        location_label.setStyleSheet("color: #8b949e;")
        layout.addWidget(location_label)
        
        # Usage bar
        usage_pct = int((storage['used'] / storage['capacity']) * 100)
        usage_bar = QProgressBar()
        usage_bar.setValue(usage_pct)
        
        bar_color = "#22c55e" if usage_pct < 75 else "#eab308" if usage_pct < 90 else "#ef4444"
        usage_bar.setStyleSheet(f"""
            QProgressBar {{
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                height: 12px;
            }}
            QProgressBar::chunk {{
                background: {bar_color};
                border-radius: 5px;
            }}
        """)
        layout.addWidget(usage_bar)
        
        usage_text = QLabel(f"{storage['used']} TB / {storage['capacity']} TB ({usage_pct}%)")
        usage_text.setStyleSheet("color: #8b949e; font-size: 12px;")
        layout.addWidget(usage_text)
        
        # Features
        features = QHBoxLayout()
        
        feature_items = [
            ("🔒 Encrypted", storage["encrypted"]),
            ("🔌 Air-Gapped", storage["air_gapped"]),
            ("📌 Immutable", storage["immutable"])
        ]
        
        for label, enabled in feature_items:
            badge = QLabel(label)
            badge.setStyleSheet(f"""
                background: {'#22c55e20' if enabled else '#ef444420'};
                color: {'#22c55e' if enabled else '#ef4444'};
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
            """)
            features.addWidget(badge)
        
        features.addStretch()
        layout.addLayout(features)
        
        return card
    
    def _create_dr_plans_tab(self) -> QWidget:
        """Create DR plans tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # DR Plans list
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        
        content = QWidget()
        cards_layout = QVBoxLayout(content)
        
        dr_plans = [
            {
                "name": "Production Database DR",
                "scope": ["db-prod-01", "db-prod-02"],
                "rpo": "4 hours",
                "rto": "2 hours",
                "last_tested": "2024-01-10",
                "test_result": "passed",
                "owner": "DBA Team"
            },
            {
                "name": "Web Infrastructure DR",
                "scope": ["web-prod-01", "web-prod-02", "lb-01"],
                "rpo": "1 hour",
                "rto": "30 minutes",
                "last_tested": "2024-01-05",
                "test_result": "passed",
                "owner": "Web Ops"
            },
            {
                "name": "Full Site Failover",
                "scope": ["All Production Systems"],
                "rpo": "4 hours",
                "rto": "4 hours",
                "last_tested": "2023-12-15",
                "test_result": "passed_with_issues",
                "owner": "IT Operations"
            }
        ]
        
        for plan in dr_plans:
            card = self._create_dr_plan_card(plan)
            cards_layout.addWidget(card)
        
        cards_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)
        
        return widget
    
    def _create_dr_plan_card(self, plan: dict) -> QWidget:
        """Create DR plan card"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 10px;
                padding: 20px;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        # Header
        header = QHBoxLayout()
        
        name = QLabel(f"🔄 {plan['name']}")
        name.setStyleSheet("font-size: 18px; font-weight: bold; color: #e6e6e6;")
        
        result_colors = {"passed": "#22c55e", "failed": "#ef4444", "passed_with_issues": "#eab308"}
        result_text = plan['test_result'].replace("_", " ").title()
        result_badge = QLabel(result_text)
        result_badge.setStyleSheet(f"""
            background: {result_colors.get(plan['test_result'], '#8b949e')}20;
            color: {result_colors.get(plan['test_result'], '#8b949e')};
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
        """)
        
        header.addWidget(name)
        header.addStretch()
        header.addWidget(result_badge)
        
        layout.addLayout(header)
        
        # Scope
        scope_text = ", ".join(plan["scope"][:3])
        if len(plan["scope"]) > 3:
            scope_text += f" +{len(plan['scope']) - 3} more"
        scope = QLabel(f"📋 Scope: {scope_text}")
        scope.setStyleSheet("color: #8b949e;")
        layout.addWidget(scope)
        
        # Metrics
        metrics = QHBoxLayout()
        
        for label, value, icon in [
            ("RPO Target", plan["rpo"], "🎯"),
            ("RTO Target", plan["rto"], "⏱️"),
            ("Last Tested", plan["last_tested"], "📅"),
            ("Owner", plan["owner"], "👤")
        ]:
            metric = QLabel(f"{icon} {label}: {value}")
            metric.setStyleSheet("""
                background: #0d1117;
                padding: 6px 10px;
                border-radius: 4px;
                color: #e6e6e6;
                font-size: 12px;
            """)
            metrics.addWidget(metric)
        
        layout.addLayout(metrics)
        
        # Actions
        actions = QHBoxLayout()
        actions.addStretch()
        
        test_btn = QPushButton("▶️ Run Test")
        test_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                color: white;
            }
        """)
        
        edit_btn = QPushButton("✏️ Edit")
        edit_btn.setStyleSheet("""
            QPushButton {
                background: #0969da;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                color: white;
            }
        """)
        
        actions.addWidget(test_btn)
        actions.addWidget(edit_btn)
        
        layout.addLayout(actions)
        
        return card
    
    def _create_findings_tab(self) -> QWidget:
        """Create assessment findings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Findings table
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels([
            "Category", "Finding", "Risk Level", "Affected Systems", "Recommendation", "Status", "Actions"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        
        findings = [
            ("Encryption", "Unencrypted Backup Detected", "high", "dev-server", "Enable encryption", "open"),
            ("RPO Compliance", "RPO Violation", "critical", "file-server", "Increase backup frequency", "open"),
            ("Verification", "Unverified Backups", "medium", "3 systems", "Enable auto-verify", "open"),
            ("Ransomware Protection", "No Immutable Storage", "high", "Primary NAS", "Enable WORM", "in_progress"),
            ("DR Testing", "DR Plan Never Tested", "critical", "Full Site Plan", "Schedule DR test", "open"),
        ]
        
        risk_colors = {
            "critical": "#ef4444", "high": "#f97316",
            "medium": "#eab308", "low": "#22c55e"
        }
        
        status_colors = {
            "open": "#ef4444", "in_progress": "#eab308", "resolved": "#22c55e"
        }
        
        table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            for col, value in enumerate(finding):
                if col == 2:  # Risk
                    item = QTableWidgetItem(str(value).upper())
                    item.setForeground(QColor(risk_colors.get(value, "#8b949e")))
                elif col == 5:  # Status
                    item = QTableWidgetItem(str(value).replace("_", " ").title())
                    item.setForeground(QColor(status_colors.get(value, "#8b949e")))
                else:
                    item = QTableWidgetItem(str(value))
                table.setItem(row, col, item)
        
        layout.addWidget(table, 1)
        
        return widget
    
    def _create_compliance_tab(self) -> QWidget:
        """Create compliance reporting tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Framework selection
        frameworks_group = QGroupBox("Compliance Frameworks")
        frameworks_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        
        frameworks_layout = QGridLayout(frameworks_group)
        
        frameworks = [
            ("SOC 2", "Service Organization Controls", 85),
            ("HIPAA", "Healthcare Data Protection", 78),
            ("PCI-DSS", "Payment Card Industry", 92),
            ("ISO 27001", "Information Security", 80),
            ("NIST CSF", "Cybersecurity Framework", 75),
            ("GDPR", "Data Protection Regulation", 88)
        ]
        
        for i, (name, desc, score) in enumerate(frameworks):
            frame = QFrame()
            frame.setStyleSheet("""
                QFrame {
                    background: #161b22;
                    border: 1px solid #21262d;
                    border-radius: 8px;
                    padding: 15px;
                }
            """)
            
            frame_layout = QVBoxLayout(frame)
            
            header = QHBoxLayout()
            title = QLabel(name)
            title.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6;")
            
            score_label = QLabel(f"{score}%")
            score_color = "#22c55e" if score >= 80 else "#eab308" if score >= 60 else "#ef4444"
            score_label.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {score_color};")
            
            header.addWidget(title)
            header.addStretch()
            header.addWidget(score_label)
            
            frame_layout.addLayout(header)
            
            description = QLabel(desc)
            description.setStyleSheet("color: #8b949e; font-size: 12px;")
            frame_layout.addWidget(description)
            
            progress = QProgressBar()
            progress.setValue(score)
            progress.setStyleSheet(f"""
                QProgressBar {{
                    background: #0d1117;
                    border: 1px solid #21262d;
                    border-radius: 4px;
                    height: 8px;
                }}
                QProgressBar::chunk {{
                    background: {score_color};
                    border-radius: 3px;
                }}
            """)
            frame_layout.addWidget(progress)
            
            report_btn = QPushButton("📄 Generate Report")
            report_btn.setStyleSheet("""
                QPushButton {
                    background: #0969da;
                    border: none;
                    padding: 6px 12px;
                    border-radius: 4px;
                    color: white;
                    font-size: 11px;
                }
            """)
            frame_layout.addWidget(report_btn)
            
            frameworks_layout.addWidget(frame, i // 3, i % 3)
        
        layout.addWidget(frameworks_group)
        layout.addStretch()
        
        return widget
    
    def _run_assessment(self):
        """Run backup assessment"""
        QMessageBox.information(
            self, "Backup Assessment",
            "Running comprehensive backup and DR assessment...\n\n"
            "This will analyze:\n"
            "• Backup job status and success rates\n"
            "• RPO/RTO compliance\n"
            "• Storage security (encryption, air-gap)\n"
            "• DR plan testing status\n"
            "• Ransomware protection measures"
        )
