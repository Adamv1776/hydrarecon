#!/usr/bin/env python3
"""
HydraRecon Risk Scoring GUI Page
Enterprise risk visualization and prioritization interface.
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


class RiskScoringPage(QWidget):
    """Risk Scoring and Prioritization page"""
    
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
        
        # Risk overview
        overview = self._create_risk_overview()
        layout.addWidget(overview)
        
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
                background: #f97316;
                color: white;
            }
        """)
        
        tabs.addTab(self._create_dashboard_tab(), "📊 Risk Dashboard")
        tabs.addTab(self._create_assets_tab(), "🖥️ Asset Risk")
        tabs.addTab(self._create_prioritization_tab(), "📋 Prioritization")
        tabs.addTab(self._create_remediation_tab(), "🔧 Remediation")
        tabs.addTab(self._create_trends_tab(), "📈 Trends")
        tabs.addTab(self._create_simulation_tab(), "🧪 What-If Analysis")
        
        layout.addWidget(tabs, 1)
    
    def _create_header(self) -> QWidget:
        """Create page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #f97316, stop:1 #ea580c);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        title_section = QVBoxLayout()
        
        title = QLabel("📊 Risk Scoring & Prioritization")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: white;")
        
        subtitle = QLabel("Quantify, prioritize, and manage security risks across your organization")
        subtitle.setStyleSheet("font-size: 14px; color: rgba(255,255,255,0.8);")
        
        title_section.addWidget(title)
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        recalc_btn = QPushButton("🔄 Recalculate Scores")
        recalc_btn.setStyleSheet("""
            QPushButton {
                background: white;
                color: #f97316;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background: #f0f0f0; }
        """)
        
        report_btn = QPushButton("📄 Generate Report")
        report_btn.setStyleSheet("""
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
        
        btn_layout.addWidget(recalc_btn)
        btn_layout.addWidget(report_btn)
        
        layout.addLayout(btn_layout)
        
        return header
    
    def _create_risk_overview(self) -> QWidget:
        """Create risk overview section"""
        overview = QFrame()
        overview.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 10px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(overview)
        
        # Overall risk score
        score_widget = QFrame()
        score_layout = QVBoxLayout(score_widget)
        
        score_label = QLabel("Organization Risk Score")
        score_label.setStyleSheet("font-size: 14px; color: #8b949e;")
        
        score_value = QLabel("68")
        score_value.setStyleSheet("font-size: 56px; font-weight: bold; color: #f97316;")
        
        score_trend = QLabel("↑ 3 points this week")
        score_trend.setStyleSheet("color: #ef4444; font-size: 12px;")
        
        score_layout.addWidget(score_label)
        score_layout.addWidget(score_value)
        score_layout.addWidget(score_trend)
        
        layout.addWidget(score_widget)
        
        # Risk distribution
        distribution = QGridLayout()
        
        risk_levels = [
            ("🔴", "Critical", "12", "#ef4444"),
            ("🟠", "High", "34", "#f97316"),
            ("🟡", "Medium", "78", "#eab308"),
            ("🟢", "Low", "156", "#22c55e"),
            ("⚪", "Info", "45", "#8b949e")
        ]
        
        for i, (icon, level, count, color) in enumerate(risk_levels):
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
            
            header = QLabel(f"{icon} {level}")
            header.setStyleSheet(f"color: {color}; font-weight: bold;")
            
            value = QLabel(count)
            value.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
            
            item_layout.addWidget(header)
            item_layout.addWidget(value)
            
            distribution.addWidget(item, 0, i)
        
        layout.addLayout(distribution)
        
        # Quick metrics
        metrics = QVBoxLayout()
        
        metric_items = [
            ("🕐", "Overdue", "8 items"),
            ("📈", "Trend", "Increasing"),
            ("🎯", "Top Priority", "CVE-2024-1234"),
            ("📋", "Tasks", "23 pending")
        ]
        
        for icon, label, value in metric_items:
            row = QHBoxLayout()
            
            lbl = QLabel(f"{icon} {label}:")
            lbl.setStyleSheet("color: #8b949e;")
            
            val = QLabel(value)
            val.setStyleSheet("color: #e6e6e6; font-weight: bold;")
            
            row.addWidget(lbl)
            row.addStretch()
            row.addWidget(val)
            
            metrics.addLayout(row)
        
        layout.addLayout(metrics)
        
        return overview
    
    def _create_dashboard_tab(self) -> QWidget:
        """Create risk dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Department risk breakdown
        dept_group = QGroupBox("Risk by Department")
        dept_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        
        dept_layout = QGridLayout(dept_group)
        
        departments = [
            ("Engineering", 72, 45),
            ("Finance", 58, 12),
            ("HR", 42, 8),
            ("IT Operations", 85, 67),
            ("Marketing", 35, 5),
            ("Sales", 48, 15)
        ]
        
        for i, (dept, score, assets) in enumerate(departments):
            card = self._create_dept_card(dept, score, assets)
            dept_layout.addWidget(card, i // 3, i % 3)
        
        layout.addWidget(dept_group)
        
        # Risk heatmap placeholder
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
        heatmap_label = QLabel("🗺️ Risk Heatmap")
        heatmap_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6;")
        heatmap_layout.addWidget(heatmap_label)
        heatmap_layout.addStretch()
        
        layout.addWidget(heatmap)
        
        return widget
    
    def _create_dept_card(self, name: str, score: int, assets: int) -> QWidget:
        """Create department risk card"""
        card = QFrame()
        
        # Determine color based on score
        if score >= 70:
            color = "#ef4444"
        elif score >= 50:
            color = "#f97316"
        elif score >= 30:
            color = "#eab308"
        else:
            color = "#22c55e"
        
        card.setStyleSheet(f"""
            QFrame {{
                background: #0d1117;
                border: 1px solid {color}40;
                border-radius: 8px;
                padding: 15px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        name_label = QLabel(name)
        name_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #e6e6e6;")
        
        score_label = QLabel(f"{score}")
        score_label.setStyleSheet(f"font-size: 32px; font-weight: bold; color: {color};")
        
        assets_label = QLabel(f"{assets} assets")
        assets_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        
        progress = QProgressBar()
        progress.setValue(score)
        progress.setStyleSheet(f"""
            QProgressBar {{
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 4px;
                height: 6px;
            }}
            QProgressBar::chunk {{
                background: {color};
                border-radius: 3px;
            }}
        """)
        
        layout.addWidget(name_label)
        layout.addWidget(score_label)
        layout.addWidget(assets_label)
        layout.addWidget(progress)
        
        return card
    
    def _create_assets_tab(self) -> QWidget:
        """Create asset risk tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Filters
        filters = QHBoxLayout()
        
        search = QLineEdit()
        search.setPlaceholderText("🔍 Search assets...")
        search.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e6e6e6;
            }
        """)
        filters.addWidget(search)
        
        criticality_combo = QComboBox()
        criticality_combo.addItems(["All Criticality", "Crown Jewel", "Critical", "High", "Medium", "Low"])
        criticality_combo.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        filters.addWidget(criticality_combo)
        
        dept_combo = QComboBox()
        dept_combo.addItems(["All Departments", "Engineering", "Finance", "HR", "IT Operations", "Marketing"])
        dept_combo.setStyleSheet(criticality_combo.styleSheet())
        filters.addWidget(dept_combo)
        
        filters.addStretch()
        
        layout.addLayout(filters)
        
        # Assets table
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "Asset", "Type", "Criticality", "Department", "Risk Score", "Risk Level", "SLA Due", "Actions"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        
        assets = [
            ("db-prod-01", "Database", "Crown Jewel", "Engineering", 92, "critical", "4 hours"),
            ("payment-api", "Application", "Critical", "Finance", 85, "high", "2 days"),
            ("web-frontend", "Application", "High", "Engineering", 72, "high", "5 days"),
            ("file-server", "Server", "Medium", "IT Ops", 58, "medium", "15 days"),
            ("dev-workstation", "Endpoint", "Low", "Engineering", 35, "low", "45 days"),
        ]
        
        risk_colors = {
            "critical": "#ef4444", "high": "#f97316",
            "medium": "#eab308", "low": "#22c55e"
        }
        
        criticality_colors = {
            "Crown Jewel": "#ef4444", "Critical": "#f97316",
            "High": "#eab308", "Medium": "#22c55e", "Low": "#8b949e"
        }
        
        table.setRowCount(len(assets))
        for row, asset in enumerate(assets):
            for col, value in enumerate(asset):
                if col == 2:  # Criticality
                    item = QTableWidgetItem(str(value))
                    item.setForeground(QColor(criticality_colors.get(value, "#8b949e")))
                elif col == 5:  # Risk Level
                    item = QTableWidgetItem(str(value).upper())
                    item.setForeground(QColor(risk_colors.get(value, "#8b949e")))
                else:
                    item = QTableWidgetItem(str(value))
                table.setItem(row, col, item)
        
        layout.addWidget(table, 1)
        
        return widget
    
    def _create_prioritization_tab(self) -> QWidget:
        """Create prioritization tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Priority queue
        priority_label = QLabel("🎯 Prioritized Risk Queue")
        priority_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #e6e6e6;")
        layout.addWidget(priority_label)
        
        # Priority list
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        
        content = QWidget()
        cards_layout = QVBoxLayout(content)
        
        priorities = [
            {"rank": 1, "name": "CVE-2024-1234 - RCE in Apache", "score": 98, "assets": 15, "exploit": "Weaponized"},
            {"rank": 2, "name": "CVE-2024-5678 - SQL Injection", "score": 92, "assets": 8, "exploit": "PoC"},
            {"rank": 3, "name": "Exposed S3 Bucket", "score": 88, "assets": 1, "exploit": "N/A"},
            {"rank": 4, "name": "Weak SSH Configuration", "score": 75, "assets": 23, "exploit": "Functional"},
            {"rank": 5, "name": "Outdated SSL Certificates", "score": 68, "assets": 12, "exploit": "N/A"},
        ]
        
        for priority in priorities:
            card = self._create_priority_card(priority)
            cards_layout.addWidget(card)
        
        cards_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)
        
        return widget
    
    def _create_priority_card(self, priority: dict) -> QWidget:
        """Create priority card"""
        card = QFrame()
        
        score = priority["score"]
        if score >= 90:
            color = "#ef4444"
            border_color = "#ef4444"
        elif score >= 70:
            color = "#f97316"
            border_color = "#f97316"
        else:
            color = "#eab308"
            border_color = "#eab308"
        
        card.setStyleSheet(f"""
            QFrame {{
                background: #161b22;
                border: 2px solid {border_color}60;
                border-left: 4px solid {border_color};
                border-radius: 8px;
                padding: 15px;
            }}
        """)
        
        layout = QHBoxLayout(card)
        
        # Rank badge
        rank = QLabel(f"#{priority['rank']}")
        rank.setStyleSheet(f"""
            background: {color};
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 16px;
            font-weight: bold;
        """)
        layout.addWidget(rank)
        
        # Details
        details = QVBoxLayout()
        
        name = QLabel(priority["name"])
        name.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6;")
        
        info = QHBoxLayout()
        
        score_label = QLabel(f"Score: {priority['score']}")
        score_label.setStyleSheet(f"color: {color}; font-weight: bold;")
        
        assets_label = QLabel(f"📦 {priority['assets']} assets")
        assets_label.setStyleSheet("color: #8b949e;")
        
        exploit_label = QLabel(f"💀 {priority['exploit']}")
        exploit_label.setStyleSheet("color: #8b949e;")
        
        info.addWidget(score_label)
        info.addWidget(assets_label)
        info.addWidget(exploit_label)
        info.addStretch()
        
        details.addWidget(name)
        details.addLayout(info)
        
        layout.addLayout(details, 1)
        
        # Actions
        remediate_btn = QPushButton("🔧 Remediate")
        remediate_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                color: white;
            }
        """)
        layout.addWidget(remediate_btn)
        
        return card
    
    def _create_remediation_tab(self) -> QWidget:
        """Create remediation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Task table
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "Priority", "Task", "Risk Score", "Effort", "Impact", "Assignee", "Due Date", "Status"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        
        tasks = [
            (1, "Patch Apache CVE-2024-1234", 98, "Medium", "-45 pts", "jsmith", "Jan 22", "in_progress"),
            (2, "Fix SQL Injection in API", 92, "High", "-38 pts", "mdoe", "Jan 25", "pending"),
            (3, "Secure S3 Bucket", 88, "Low", "-35 pts", "agarcia", "Jan 20", "completed"),
            (4, "Update SSH Config", 75, "Medium", "-28 pts", "bwilson", "Feb 1", "pending"),
            (5, "Renew SSL Certificates", 68, "Low", "-22 pts", "cthompson", "Feb 5", "pending"),
        ]
        
        status_colors = {
            "pending": "#eab308", "in_progress": "#0969da", "completed": "#22c55e"
        }
        
        table.setRowCount(len(tasks))
        for row, task in enumerate(tasks):
            for col, value in enumerate(task):
                if col == 7:  # Status
                    item = QTableWidgetItem(str(value).replace("_", " ").title())
                    item.setForeground(QColor(status_colors.get(value, "#8b949e")))
                else:
                    item = QTableWidgetItem(str(value))
                table.setItem(row, col, item)
        
        layout.addWidget(table, 1)
        
        return widget
    
    def _create_trends_tab(self) -> QWidget:
        """Create trends tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Trend chart placeholder
        chart = QFrame()
        chart.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
                min-height: 300px;
            }
        """)
        chart_layout = QVBoxLayout(chart)
        chart_label = QLabel("📈 Risk Score Trend (30 Days)")
        chart_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6;")
        chart_layout.addWidget(chart_label)
        chart_layout.addStretch()
        
        layout.addWidget(chart)
        
        # Key changes
        changes_group = QGroupBox("Recent Risk Changes")
        changes_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        
        changes_layout = QVBoxLayout(changes_group)
        
        changes = [
            ("↑", "db-prod-01", "+15", "New critical vulnerability discovered"),
            ("↓", "web-frontend", "-8", "SSL certificate updated"),
            ("↑", "payment-api", "+5", "Exploit publicly released"),
            ("↓", "file-server", "-12", "Firewall rules applied"),
        ]
        
        for direction, asset, delta, reason in changes:
            row = QHBoxLayout()
            
            dir_label = QLabel(direction)
            dir_label.setStyleSheet(f"color: {'#ef4444' if direction == '↑' else '#22c55e'}; font-size: 20px;")
            
            asset_label = QLabel(asset)
            asset_label.setStyleSheet("color: #e6e6e6; font-weight: bold;")
            
            delta_label = QLabel(delta)
            delta_label.setStyleSheet(f"color: {'#ef4444' if delta.startswith('+') else '#22c55e'}; font-weight: bold;")
            
            reason_label = QLabel(reason)
            reason_label.setStyleSheet("color: #8b949e;")
            
            row.addWidget(dir_label)
            row.addWidget(asset_label)
            row.addWidget(delta_label)
            row.addWidget(reason_label)
            row.addStretch()
            
            changes_layout.addLayout(row)
        
        layout.addWidget(changes_group)
        
        return widget
    
    def _create_simulation_tab(self) -> QWidget:
        """Create what-if analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Simulation controls
        sim_group = QGroupBox("What-If Simulation")
        sim_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        
        sim_layout = QVBoxLayout(sim_group)
        
        sim_label = QLabel("Select risk factors to simulate remediation:")
        sim_label.setStyleSheet("color: #8b949e;")
        sim_layout.addWidget(sim_label)
        
        # Risk factors checkboxes
        factors = [
            "CVE-2024-1234 - Apache RCE",
            "CVE-2024-5678 - SQL Injection",
            "Exposed S3 Bucket",
            "Weak SSH Configuration",
            "Outdated SSL Certificates"
        ]
        
        for factor in factors:
            cb = QCheckBox(factor)
            cb.setStyleSheet("color: #e6e6e6;")
            sim_layout.addWidget(cb)
        
        simulate_btn = QPushButton("🧪 Run Simulation")
        simulate_btn.setStyleSheet("""
            QPushButton {
                background: #f97316;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                color: white;
                font-weight: bold;
            }
        """)
        sim_layout.addWidget(simulate_btn)
        
        layout.addWidget(sim_group)
        
        # Simulation results
        results = QFrame()
        results.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
                padding: 20px;
            }
        """)
        
        results_layout = QVBoxLayout(results)
        
        results_title = QLabel("📊 Simulation Results")
        results_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6e6e6;")
        results_layout.addWidget(results_title)
        
        # Placeholder results
        placeholder = QLabel("Run a simulation to see projected risk score changes")
        placeholder.setStyleSheet("color: #8b949e; font-style: italic;")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        results_layout.addWidget(placeholder)
        results_layout.addStretch()
        
        layout.addWidget(results, 1)
        
        return widget
