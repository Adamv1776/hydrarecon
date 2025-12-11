#!/usr/bin/env python3
"""
HydraRecon Deception Technology GUI Page
Enterprise honeypot and decoy management interface.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget, QLineEdit,
    QComboBox, QTextEdit, QSpinBox, QCheckBox, QGroupBox, QGridLayout,
    QSplitter, QTreeWidget, QTreeWidgetItem, QProgressBar, QDialog,
    QFormLayout, QDialogButtonBox, QListWidget, QListWidgetItem, QScrollArea,
    QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QColor


class DeceptionPage(QWidget):
    """Deception Technology management page"""
    
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
                background: #238636;
                color: white;
            }
        """)
        
        tabs.addTab(self._create_honeypots_tab(), "🍯 Honeypots")
        tabs.addTab(self._create_honeytokens_tab(), "🔑 Honeytokens")
        tabs.addTab(self._create_campaigns_tab(), "📋 Campaigns")
        tabs.addTab(self._create_alerts_tab(), "🚨 Alerts")
        tabs.addTab(self._create_attackers_tab(), "👤 Attacker Profiles")
        tabs.addTab(self._create_analytics_tab(), "📊 Analytics")
        
        layout.addWidget(tabs, 1)
    
    def _create_header(self) -> QWidget:
        """Create page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #8b5cf6, stop:1 #6366f1);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        title_section = QVBoxLayout()
        
        title = QLabel("🎭 Deception Technology")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: white;")
        
        subtitle = QLabel("Deploy honeypots, honeytokens, and track attacker behavior")
        subtitle.setStyleSheet("font-size: 14px; color: rgba(255,255,255,0.8);")
        
        title_section.addWidget(title)
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        deploy_btn = QPushButton("🍯 Deploy Honeypot")
        deploy_btn.setStyleSheet("""
            QPushButton {
                background: white;
                color: #6366f1;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background: #f0f0f0; }
        """)
        deploy_btn.clicked.connect(self._deploy_honeypot)
        
        token_btn = QPushButton("🔑 Create Token")
        token_btn.setStyleSheet("""
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
        token_btn.clicked.connect(self._create_honeytoken)
        
        btn_layout.addWidget(deploy_btn)
        btn_layout.addWidget(token_btn)
        
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
            ("🍯", "Active Honeypots", "12", "#8b5cf6"),
            ("⚡", "Triggered Today", "24", "#f97316"),
            ("🔑", "Honeytokens", "156", "#06b6d4"),
            ("👤", "Tracked Attackers", "8", "#ef4444"),
            ("📋", "Active Campaigns", "3", "#22c55e")
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
    
    def _create_honeypots_tab(self) -> QWidget:
        """Create honeypots management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        search = QLineEdit()
        search.setPlaceholderText("🔍 Search honeypots...")
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
        
        filter_combo = QComboBox()
        filter_combo.addItems(["All Types", "SSH", "RDP", "Web", "Database", "SMB", "FTP", "ICS/SCADA"])
        filter_combo.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
                min-width: 150px;
            }
        """)
        toolbar.addWidget(filter_combo)
        
        status_combo = QComboBox()
        status_combo.addItems(["All Status", "Active", "Triggered", "Inactive", "Compromised"])
        status_combo.setStyleSheet(filter_combo.styleSheet())
        toolbar.addWidget(status_combo)
        
        layout.addLayout(toolbar)
        
        # Honeypots table
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "Name", "Type", "IP Address", "Status", "Triggers", "Last Activity", "Interaction", "Actions"
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
        
        # Sample data
        honeypots = [
            ("SSH Honeypot - DMZ", "SSH", "192.168.1.100", "active", "45", "2 min ago", "Medium"),
            ("Web App Honeypot", "HTTP/HTTPS", "192.168.1.101", "triggered", "128", "5 min ago", "High"),
            ("Database Honeypot", "MySQL", "192.168.1.102", "active", "12", "1 hour ago", "Medium"),
            ("RDP Honeypot - IT", "RDP", "192.168.1.103", "triggered", "67", "15 min ago", "Medium"),
            ("SMB Share Decoy", "SMB/CIFS", "192.168.1.104", "active", "23", "30 min ago", "Low"),
            ("SCADA Honeypot", "Modbus/S7", "192.168.1.105", "active", "3", "2 hours ago", "High"),
        ]
        
        table.setRowCount(len(honeypots))
        for row, hp in enumerate(honeypots):
            for col, value in enumerate(hp):
                if col == 3:  # Status
                    status_colors = {
                        "active": "#22c55e", "triggered": "#f97316",
                        "inactive": "#8b949e", "compromised": "#ef4444"
                    }
                    item = QTableWidgetItem(value.capitalize())
                    item.setForeground(QColor(status_colors.get(value, "#8b949e")))
                else:
                    item = QTableWidgetItem(str(value))
                table.setItem(row, col, item)
            
            # Actions column
            actions = QWidget()
            actions_layout = QHBoxLayout(actions)
            actions_layout.setContentsMargins(4, 4, 4, 4)
            
            view_btn = QPushButton("👁️")
            view_btn.setToolTip("View Details")
            view_btn.setStyleSheet("QPushButton { background: #238636; border: none; border-radius: 4px; padding: 4px 8px; }")
            
            stop_btn = QPushButton("⏹️")
            stop_btn.setToolTip("Stop")
            stop_btn.setStyleSheet("QPushButton { background: #f97316; border: none; border-radius: 4px; padding: 4px 8px; }")
            
            delete_btn = QPushButton("🗑️")
            delete_btn.setToolTip("Delete")
            delete_btn.setStyleSheet("QPushButton { background: #ef4444; border: none; border-radius: 4px; padding: 4px 8px; }")
            
            actions_layout.addWidget(view_btn)
            actions_layout.addWidget(stop_btn)
            actions_layout.addWidget(delete_btn)
            
            table.setCellWidget(row, 7, actions)
        
        layout.addWidget(table)
        
        return widget
    
    def _create_honeytokens_tab(self) -> QWidget:
        """Create honeytokens management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Token templates
        templates_group = QGroupBox("Token Templates")
        templates_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #21262d;
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
        
        templates_layout = QGridLayout(templates_group)
        
        token_types = [
            ("🔐", "AWS Credentials", "AKIA-style access keys"),
            ("🔑", "API Keys", "Generic API tokens"),
            ("🗄️", "Database Creds", "MySQL/PostgreSQL credentials"),
            ("📄", "Config Files", ".env and config files"),
            ("🔒", "Private Keys", "SSH/RSA private keys"),
            ("🎫", "JWT Tokens", "JSON Web Tokens")
        ]
        
        for i, (icon, name, desc) in enumerate(token_types):
            btn = QPushButton(f"{icon} {name}")
            btn.setToolTip(desc)
            btn.setStyleSheet("""
                QPushButton {
                    background: #161b22;
                    border: 1px solid #21262d;
                    border-radius: 6px;
                    padding: 15px;
                    color: #e6e6e6;
                    text-align: left;
                }
                QPushButton:hover {
                    background: #21262d;
                    border-color: #8b5cf6;
                }
            """)
            templates_layout.addWidget(btn, i // 3, i % 3)
        
        layout.addWidget(templates_group)
        
        # Active tokens table
        tokens_label = QLabel("Active Honeytokens")
        tokens_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6; margin-top: 10px;")
        layout.addWidget(tokens_label)
        
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels([
            "Name", "Type", "Value (Masked)", "Planted At", "Triggered", "Last Trigger", "Actions"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
        """)
        
        tokens = [
            ("AWS-PROD-KEY", "AWS Credential", "AKIA****XXXX", "S3 config, GitHub", True, "10 min ago"),
            ("API-INTERNAL", "API Key", "sk_****_abcd", "Source code", False, "Never"),
            ("DB-ADMIN", "Database Cred", "admin:****", "Docker compose", True, "2 hours ago"),
            ("JWT-SERVICE", "JWT Token", "eyJ****", "API documentation", False, "Never"),
        ]
        
        table.setRowCount(len(tokens))
        for row, token in enumerate(tokens):
            for col, value in enumerate(token):
                if col == 4:  # Triggered
                    item = QTableWidgetItem("✅ Yes" if value else "❌ No")
                    item.setForeground(QColor("#22c55e" if value else "#8b949e"))
                else:
                    item = QTableWidgetItem(str(value))
                table.setItem(row, col, item)
        
        layout.addWidget(table, 1)
        
        return widget
    
    def _create_campaigns_tab(self) -> QWidget:
        """Create deception campaigns tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Campaign cards
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        
        content = QWidget()
        cards_layout = QVBoxLayout(content)
        
        campaigns = [
            {
                "name": "Ransomware Defense Campaign",
                "description": "Detect ransomware attack patterns and lateral movement",
                "decoys": 8,
                "tokens": 25,
                "triggers": 42,
                "status": "active",
                "duration": "30 days"
            },
            {
                "name": "Insider Threat Detection",
                "description": "Monitor for unauthorized access to sensitive decoy files",
                "decoys": 5,
                "tokens": 50,
                "triggers": 18,
                "status": "active",
                "duration": "60 days"
            },
            {
                "name": "APT Hunt Operation",
                "description": "Long-term campaign to detect advanced persistent threats",
                "decoys": 15,
                "tokens": 100,
                "triggers": 3,
                "status": "active",
                "duration": "90 days"
            }
        ]
        
        for campaign in campaigns:
            card = self._create_campaign_card(campaign)
            cards_layout.addWidget(card)
        
        cards_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)
        
        return widget
    
    def _create_campaign_card(self, campaign: dict) -> QWidget:
        """Create campaign card widget"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 10px;
                padding: 20px;
            }
            QFrame:hover {
                border-color: #8b5cf6;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        # Header
        header = QHBoxLayout()
        
        title = QLabel(campaign["name"])
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #e6e6e6;")
        
        status = QLabel(f"● {campaign['status'].capitalize()}")
        status.setStyleSheet(f"""
            color: {'#22c55e' if campaign['status'] == 'active' else '#8b949e'};
            font-weight: bold;
        """)
        
        header.addWidget(title)
        header.addStretch()
        header.addWidget(status)
        
        layout.addLayout(header)
        
        # Description
        desc = QLabel(campaign["description"])
        desc.setStyleSheet("color: #8b949e; margin: 8px 0;")
        layout.addWidget(desc)
        
        # Metrics
        metrics = QHBoxLayout()
        
        for label, value, icon in [
            ("Decoys", campaign["decoys"], "🍯"),
            ("Tokens", campaign["tokens"], "🔑"),
            ("Triggers", campaign["triggers"], "⚡"),
            ("Duration", campaign["duration"], "📅")
        ]:
            metric = QLabel(f"{icon} {label}: {value}")
            metric.setStyleSheet("""
                background: #0d1117;
                padding: 8px 12px;
                border-radius: 6px;
                color: #e6e6e6;
            """)
            metrics.addWidget(metric)
        
        metrics.addStretch()
        layout.addLayout(metrics)
        
        # Action buttons
        actions = QHBoxLayout()
        actions.addStretch()
        
        view_btn = QPushButton("View Details")
        view_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                color: white;
            }
        """)
        
        pause_btn = QPushButton("Pause")
        pause_btn.setStyleSheet("""
            QPushButton {
                background: #f97316;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                color: white;
            }
        """)
        
        actions.addWidget(view_btn)
        actions.addWidget(pause_btn)
        
        layout.addLayout(actions)
        
        return card
    
    def _create_alerts_tab(self) -> QWidget:
        """Create alerts tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Alert filters
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
        
        time_combo = QComboBox()
        time_combo.addItems(["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"])
        time_combo.setStyleSheet(severity_combo.styleSheet())
        
        filters.addWidget(severity_combo)
        filters.addWidget(time_combo)
        filters.addStretch()
        
        ack_btn = QPushButton("Acknowledge Selected")
        ack_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                color: white;
            }
        """)
        filters.addWidget(ack_btn)
        
        layout.addLayout(filters)
        
        # Alerts table
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "Time", "Severity", "Decoy", "Source IP", "Activity", "Details", "Status", "Actions"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        
        alerts = [
            ("10:32:15", "critical", "SSH Honeypot", "185.234.x.x", "Brute Force", "45 attempts", "new"),
            ("10:28:42", "high", "AWS Token", "192.168.x.x", "Token Used", "AWS API call", "new"),
            ("10:15:03", "high", "RDP Honeypot", "103.45.x.x", "Login Attempt", "admin:password", "ack"),
            ("09:45:22", "medium", "Web Honeypot", "45.33.x.x", "SQLi Attempt", "' OR 1=1--", "ack"),
            ("09:12:08", "low", "SMB Share", "192.168.x.x", "File Access", "passwords.txt", "resolved"),
        ]
        
        severity_colors = {
            "critical": "#ef4444", "high": "#f97316",
            "medium": "#eab308", "low": "#22c55e"
        }
        
        table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            for col, value in enumerate(alert):
                item = QTableWidgetItem(str(value).upper() if col == 1 else str(value))
                if col == 1:
                    item.setForeground(QColor(severity_colors.get(value, "#8b949e")))
                table.setItem(row, col, item)
        
        layout.addWidget(table, 1)
        
        return widget
    
    def _create_attackers_tab(self) -> QWidget:
        """Create attacker profiles tab"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Attacker list
        list_widget = QListWidget()
        list_widget.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
            }
            QListWidget::item:selected {
                background: #21262d;
            }
        """)
        list_widget.setMaximumWidth(300)
        
        attackers = [
            ("Threat Actor Alpha", "185.234.x.x", 95),
            ("APT-Unknown-1", "103.45.x.x", 78),
            ("Ransomware Bot", "45.33.x.x", 65),
            ("Internal Probe", "192.168.x.x", 42),
        ]
        
        for name, ip, score in attackers:
            item = QListWidgetItem(f"👤 {name}\n   {ip} | Threat: {score}%")
            list_widget.addItem(item)
        
        layout.addWidget(list_widget)
        
        # Attacker details
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
        
        detail_title = QLabel("👤 Threat Actor Alpha")
        detail_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e6e6e6;")
        details_layout.addWidget(detail_title)
        
        threat_bar = QProgressBar()
        threat_bar.setValue(95)
        threat_bar.setStyleSheet("""
            QProgressBar {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                height: 20px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #f97316, stop:1 #ef4444);
                border-radius: 5px;
            }
        """)
        details_layout.addWidget(threat_bar)
        
        info_grid = QGridLayout()
        
        info_items = [
            ("First Seen:", "2024-01-15 14:32"),
            ("Last Seen:", "2024-01-20 10:28"),
            ("Source IPs:", "185.234.x.x, 185.234.x.y"),
            ("Decoys Triggered:", "8"),
            ("Techniques:", "T1110, T1021, T1005")
        ]
        
        for i, (label, value) in enumerate(info_items):
            lbl = QLabel(label)
            lbl.setStyleSheet("color: #8b949e;")
            val = QLabel(value)
            val.setStyleSheet("color: #e6e6e6;")
            info_grid.addWidget(lbl, i, 0)
            info_grid.addWidget(val, i, 1)
        
        details_layout.addLayout(info_grid)
        details_layout.addStretch()
        
        layout.addWidget(details, 1)
        
        return widget
    
    def _create_analytics_tab(self) -> QWidget:
        """Create analytics tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Analytics grid
        grid = QGridLayout()
        
        # Activity heatmap placeholder
        heatmap = QFrame()
        heatmap.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
                min-height: 200px;
            }
        """)
        heatmap_layout = QVBoxLayout(heatmap)
        heatmap_label = QLabel("📊 Activity Heatmap")
        heatmap_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6;")
        heatmap_layout.addWidget(heatmap_label)
        heatmap_layout.addStretch()
        
        grid.addWidget(heatmap, 0, 0, 1, 2)
        
        # Attack techniques chart
        techniques = QFrame()
        techniques.setStyleSheet(heatmap.styleSheet())
        tech_layout = QVBoxLayout(techniques)
        tech_label = QLabel("🎯 MITRE ATT&CK Techniques")
        tech_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6;")
        tech_layout.addWidget(tech_label)
        tech_layout.addStretch()
        
        grid.addWidget(techniques, 1, 0)
        
        # Top decoys
        top_decoys = QFrame()
        top_decoys.setStyleSheet(heatmap.styleSheet())
        decoys_layout = QVBoxLayout(top_decoys)
        decoys_label = QLabel("🍯 Most Triggered Decoys")
        decoys_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6;")
        decoys_layout.addWidget(decoys_label)
        decoys_layout.addStretch()
        
        grid.addWidget(top_decoys, 1, 1)
        
        layout.addLayout(grid)
        
        return widget
    
    def _deploy_honeypot(self):
        """Deploy new honeypot dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Deploy Honeypot")
        dialog.setMinimumWidth(500)
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
        name_input.setPlaceholderText("e.g., SSH Honeypot - DMZ")
        form.addRow("Name:", name_input)
        
        type_combo = QComboBox()
        type_combo.addItems(["SSH", "RDP", "HTTP/HTTPS", "MySQL", "PostgreSQL", "SMB", "FTP", "Modbus/S7"])
        form.addRow("Type:", type_combo)
        
        ip_input = QLineEdit()
        ip_input.setPlaceholderText("e.g., 192.168.1.100")
        form.addRow("IP Address:", ip_input)
        
        interaction_combo = QComboBox()
        interaction_combo.addItems(["Low (Port Listener)", "Medium (Emulated)", "High (Full OS)"])
        form.addRow("Interaction Level:", interaction_combo)
        
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.exec()
    
    def _create_honeytoken(self):
        """Create honeytoken dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Honeytoken")
        dialog.setMinimumWidth(500)
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
        name_input.setPlaceholderText("e.g., AWS-PROD-KEY")
        form.addRow("Name:", name_input)
        
        type_combo = QComboBox()
        type_combo.addItems(["AWS Credential", "API Key", "Database Credential", "JWT Token", "SSH Key", "Custom"])
        form.addRow("Type:", type_combo)
        
        location_input = QLineEdit()
        location_input.setPlaceholderText("e.g., S3 bucket, GitHub repo")
        form.addRow("Plant Location:", location_input)
        
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.exec()
