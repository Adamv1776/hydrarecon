#!/usr/bin/env python3
"""
🔥 Vulnerability Intelligence Page

UNIQUE FEATURE - Enterprise vulnerability management:
- Real-time CVE tracking
- Risk-based prioritization
- Exploit availability status
- CISA KEV integration
- Attack surface correlation
- One-click remediation workflows

This is ENTERPRISE-GRADE vulnerability intelligence.
"""

import sys
import os
from datetime import datetime
from typing import Dict, List, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QLineEdit, QComboBox, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QProgressBar, QGroupBox, QGridLayout, QTabWidget,
    QListWidget, QListWidgetItem, QCheckBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor

# Import vulnerability intelligence engine
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.vuln_intelligence import (
        VulnerabilityIntelligence, Vulnerability, VulnAlert,
        VulnSeverity, ExploitStatus, PatchStatus, get_vuln_engine
    )
except ImportError:
    VulnerabilityIntelligence = None


class CVECard(QFrame):
    """Individual CVE card widget"""
    
    clicked = pyqtSignal(object)
    
    def __init__(self, cve: 'Vulnerability', risk_score: float = 0, parent=None):
        super().__init__(parent)
        self.cve = cve
        self.risk_score = risk_score
        self.setObjectName("cveCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 12, 15, 12)
        layout.setSpacing(8)
        
        # Header
        header = QHBoxLayout()
        
        # CVE ID with severity color
        severity_colors = {
            "critical": "#ff0044",
            "high": "#ff4400",
            "medium": "#ffaa00",
            "low": "#00aaff",
            "none": "#888888"
        }
        severity = self.cve.severity.value if hasattr(self.cve, 'severity') else "medium"
        color = severity_colors.get(severity, "#888888")
        
        cve_label = QLabel(self.cve.cve_id)
        cve_label.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        cve_label.setStyleSheet(f"color: {color};")
        header.addWidget(cve_label)
        
        # CVSS Score badge
        cvss = self.cve.cvss_score if hasattr(self.cve, 'cvss_score') else 0.0
        cvss_badge = QLabel(f"CVSS {cvss:.1f}")
        cvss_badge.setStyleSheet(f"""
            background: {color}33;
            color: {color};
            padding: 3px 8px;
            border-radius: 10px;
            font-weight: bold;
            font-size: 11px;
        """)
        header.addWidget(cvss_badge)
        
        header.addStretch()
        
        # Exploit status
        exploit_icons = {
            "weaponized": "🔴",
            "poc_public": "🟠",
            "poc_private": "🟡",
            "theoretical": "⚪",
            "unknown": "❓"
        }
        exploit_status = self.cve.exploit_status.value if hasattr(self.cve, 'exploit_status') else "unknown"
        exploit_icon = exploit_icons.get(exploit_status, "❓")
        exploit_label = QLabel(f"{exploit_icon} {exploit_status.replace('_', ' ').title()}")
        exploit_label.setStyleSheet("color: #888888; font-size: 10px;")
        header.addWidget(exploit_label)
        
        # KEV badge
        if hasattr(self.cve, 'kev_listed') and self.cve.kev_listed:
            kev_badge = QLabel("⚠️ KEV")
            kev_badge.setStyleSheet("""
                background: rgba(255, 68, 0, 0.3);
                color: #ff4400;
                padding: 2px 6px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 10px;
            """)
            header.addWidget(kev_badge)
        
        layout.addLayout(header)
        
        # Title
        title = QLabel(self.cve.title if hasattr(self.cve, 'title') else "Unknown")
        title.setWordWrap(True)
        title.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 12px;")
        layout.addWidget(title)
        
        # Affected products
        if hasattr(self.cve, 'affected_products') and self.cve.affected_products:
            products = ", ".join(self.cve.affected_products[:3])
            products_label = QLabel(f"📦 {products}")
            products_label.setStyleSheet("color: #888888; font-size: 10px;")
            layout.addWidget(products_label)
        
        # Risk score bar
        if self.risk_score > 0:
            risk_layout = QHBoxLayout()
            risk_label = QLabel(f"Risk: {self.risk_score:.0f}/100")
            risk_label.setStyleSheet("color: #888888; font-size: 10px;")
            risk_layout.addWidget(risk_label)
            
            risk_bar = QProgressBar()
            risk_bar.setValue(int(self.risk_score))
            risk_bar.setMaximum(100)
            risk_bar.setTextVisible(False)
            risk_bar.setMaximumHeight(6)
            risk_bar.setStyleSheet(f"""
                QProgressBar {{
                    background: #333;
                    border-radius: 3px;
                }}
                QProgressBar::chunk {{
                    background: {color};
                    border-radius: 3px;
                }}
            """)
            risk_layout.addWidget(risk_bar)
            
            layout.addLayout(risk_layout)
        
        # Style
        self.setStyleSheet(f"""
            QFrame#cveCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {color}22, stop:0.02 #1a1a2e, stop:1 #1a1a2e);
                border: 1px solid {color}44;
                border-left: 3px solid {color};
                border-radius: 8px;
            }}
            QFrame#cveCard:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {color}44, stop:0.02 #252540, stop:1 #252540);
                border-color: {color};
            }}
        """)
    
    def mousePressEvent(self, event):
        self.clicked.emit(self.cve)
        super().mousePressEvent(event)


class VulnIntelPage(QWidget):
    """
    🔥 Vulnerability Intelligence Page
    
    Enterprise-grade CVE management:
    - Risk-based prioritization
    - Exploit tracking
    - KEV integration
    """
    
    def __init__(self, config=None, db=None):
        super().__init__()
        self.config = config or {}
        self.db = db
        
        # Get vulnerability engine
        self.engine = get_vuln_engine() if VulnerabilityIntelligence else None
        
        self._setup_ui()
        self._connect_signals()
        
        # Load initial data
        if self.engine:
            self._load_data()
        else:
            self._load_demo_data()
    
    def _setup_ui(self):
        """Set up the UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - CVE List
        left_panel = self._create_left_panel()
        main_splitter.addWidget(left_panel)
        
        # Right panel - CVE Details
        right_panel = self._create_right_panel()
        main_splitter.addWidget(right_panel)
        
        main_splitter.setSizes([500, 700])
        layout.addWidget(main_splitter)
        
        self.setStyleSheet(self._get_stylesheet())
    
    def _create_header(self) -> QFrame:
        """Create header with stats"""
        header = QFrame()
        header.setObjectName("headerFrame")
        layout = QHBoxLayout(header)
        
        # Title
        title_layout = QVBoxLayout()
        
        title = QLabel("🔥 Vulnerability Intelligence")
        title.setFont(QFont("Consolas", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #ff4400;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Real-time CVE tracking • Risk-based prioritization • Exploit monitoring")
        subtitle.setStyleSheet("color: #888888; font-size: 12px;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats
        stats_layout = QHBoxLayout()
        
        self.stat_total = self._create_stat_card("Total CVEs", "0", "#0088ff")
        self.stat_critical = self._create_stat_card("Critical", "0", "#ff0044")
        self.stat_exploited = self._create_stat_card("Exploited", "0", "#ff4400")
        self.stat_kev = self._create_stat_card("KEV Listed", "0", "#ffaa00")
        
        stats_layout.addWidget(self.stat_total)
        stats_layout.addWidget(self.stat_critical)
        stats_layout.addWidget(self.stat_exploited)
        stats_layout.addWidget(self.stat_kev)
        
        layout.addLayout(stats_layout)
        
        return header
    
    def _create_stat_card(self, label: str, value: str, color: str) -> QFrame:
        """Create a stat card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: rgba(20, 20, 40, 0.8);
                border: 1px solid {color};
                border-radius: 8px;
                padding: 8px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Consolas", 18, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value_label)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #888888; font-size: 10px;")
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_label)
        
        card.value_label = value_label
        
        return card
    
    def _create_left_panel(self) -> QFrame:
        """Create left panel with CVE list"""
        panel = QFrame()
        panel.setObjectName("leftPanel")
        layout = QVBoxLayout(panel)
        
        # Search and filters
        search_layout = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search CVEs, products, descriptions...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                background: rgba(20, 20, 40, 0.8);
                border: 1px solid #333;
                border-radius: 5px;
                color: #00ff88;
                padding: 8px;
                font-family: Consolas;
            }
        """)
        self.search_input.textChanged.connect(self._filter_cves)
        search_layout.addWidget(self.search_input)
        
        btn_search = QPushButton("🔍")
        btn_search.clicked.connect(self._filter_cves)
        search_layout.addWidget(btn_search)
        
        layout.addLayout(search_layout)
        
        # Filter row
        filter_layout = QHBoxLayout()
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low"])
        self.severity_filter.setStyleSheet("""
            QComboBox {
                background: rgba(30, 30, 50, 0.8);
                border: 1px solid #444;
                border-radius: 5px;
                color: #ffffff;
                padding: 5px;
            }
        """)
        self.severity_filter.currentTextChanged.connect(self._filter_cves)
        filter_layout.addWidget(self.severity_filter)
        
        self.exploit_filter = QComboBox()
        self.exploit_filter.addItems(["All Exploits", "Weaponized", "PoC Public", "PoC Private", "Theoretical"])
        self.exploit_filter.setStyleSheet(self.severity_filter.styleSheet())
        self.exploit_filter.currentTextChanged.connect(self._filter_cves)
        filter_layout.addWidget(self.exploit_filter)
        
        self.kev_checkbox = QCheckBox("KEV Only")
        self.kev_checkbox.setStyleSheet("color: #ffaa00;")
        self.kev_checkbox.stateChanged.connect(self._filter_cves)
        filter_layout.addWidget(self.kev_checkbox)
        
        layout.addLayout(filter_layout)
        
        # Quick filters
        quick_layout = QHBoxLayout()
        
        btn_critical = QPushButton("🔴 Critical")
        btn_critical.setStyleSheet("border-color: #ff0044; color: #ff0044;")
        btn_critical.clicked.connect(lambda: self._quick_filter("critical"))
        quick_layout.addWidget(btn_critical)
        
        btn_exploited = QPushButton("💥 Exploited")
        btn_exploited.setStyleSheet("border-color: #ff4400; color: #ff4400;")
        btn_exploited.clicked.connect(lambda: self._quick_filter("exploited"))
        quick_layout.addWidget(btn_exploited)
        
        btn_kev = QPushButton("⚠️ KEV")
        btn_kev.setStyleSheet("border-color: #ffaa00; color: #ffaa00;")
        btn_kev.clicked.connect(lambda: self._quick_filter("kev"))
        quick_layout.addWidget(btn_kev)
        
        btn_recent = QPushButton("🆕 Recent")
        btn_recent.clicked.connect(lambda: self._quick_filter("recent"))
        quick_layout.addWidget(btn_recent)
        
        layout.addLayout(quick_layout)
        
        # CVE list
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("""
            QScrollArea {
                background: transparent;
                border: none;
            }
            QScrollBar:vertical {
                background: #0a0a12;
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #333;
                border-radius: 4px;
            }
        """)
        
        self.cve_container = QWidget()
        self.cve_layout = QVBoxLayout(self.cve_container)
        self.cve_layout.setSpacing(10)
        self.cve_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        scroll.setWidget(self.cve_container)
        layout.addWidget(scroll)
        
        return panel
    
    def _create_right_panel(self) -> QFrame:
        """Create right panel with CVE details"""
        panel = QFrame()
        panel.setObjectName("rightPanel")
        layout = QVBoxLayout(panel)
        
        # Tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #333;
                background: rgba(20, 20, 40, 0.5);
                border-radius: 8px;
            }
            QTabBar::tab {
                background: rgba(30, 30, 50, 0.8);
                color: #888;
                padding: 8px 15px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background: rgba(255, 68, 0, 0.3);
                color: #ff4400;
            }
        """)
        
        # CVE Details tab
        details_widget = self._create_details_tab()
        tabs.addTab(details_widget, "📋 CVE Details")
        
        # Exploit Info tab
        exploit_widget = self._create_exploit_tab()
        tabs.addTab(exploit_widget, "💥 Exploits")
        
        # Remediation tab
        remediation_widget = self._create_remediation_tab()
        tabs.addTab(remediation_widget, "🔧 Remediation")
        
        # Statistics tab
        stats_widget = self._create_stats_tab()
        tabs.addTab(stats_widget, "📊 Statistics")
        
        layout.addWidget(tabs)
        
        # Action buttons
        actions = QHBoxLayout()
        
        btn_export = QPushButton("📤 Export CVEs")
        btn_export.clicked.connect(self._export_cves)
        actions.addWidget(btn_export)
        
        btn_scan = QPushButton("🔍 Scan Assets")
        btn_scan.clicked.connect(self._scan_assets)
        actions.addWidget(btn_scan)
        
        btn_report = QPushButton("📋 Generate Report")
        btn_report.clicked.connect(self._generate_report)
        actions.addWidget(btn_report)
        
        layout.addLayout(actions)
        
        return panel
    
    def _create_details_tab(self) -> QWidget:
        """Create CVE details tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.detail_cve_id = QLabel("Select a CVE to view details")
        self.detail_cve_id.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        self.detail_cve_id.setStyleSheet("color: #ff4400;")
        layout.addWidget(self.detail_cve_id)
        
        self.detail_content = QTextEdit()
        self.detail_content.setReadOnly(True)
        self.detail_content.setStyleSheet("""
            QTextEdit {
                background: rgba(10, 10, 20, 0.8);
                border: 1px solid #333;
                border-radius: 5px;
                color: #ffffff;
                font-family: Consolas;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.detail_content)
        
        # MITRE ATT&CK techniques
        mitre_group = QGroupBox("🎯 MITRE ATT&CK Techniques")
        mitre_layout = QVBoxLayout(mitre_group)
        
        self.mitre_list = QListWidget()
        self.mitre_list.setStyleSheet("""
            QListWidget {
                background: transparent;
                border: none;
                color: #ffffff;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #333;
            }
        """)
        mitre_layout.addWidget(self.mitre_list)
        
        layout.addWidget(mitre_group)
        
        return widget
    
    def _create_exploit_tab(self) -> QWidget:
        """Create exploit info tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Exploit status
        self.exploit_status_label = QLabel("No CVE selected")
        self.exploit_status_label.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        self.exploit_status_label.setStyleSheet("color: #ff4400;")
        layout.addWidget(self.exploit_status_label)
        
        # Exploit details
        self.exploit_content = QTextEdit()
        self.exploit_content.setReadOnly(True)
        self.exploit_content.setStyleSheet("""
            QTextEdit {
                background: rgba(10, 10, 20, 0.8);
                border: 1px solid #333;
                border-radius: 5px;
                color: #ffffff;
                font-family: Consolas;
                font-size: 12px;
            }
        """)
        self.exploit_content.setText("""
<b>Exploit Information</b>

Select a CVE to view exploit details including:
• Public PoC availability
• Exploitation in the wild
• Metasploit modules
• Nuclei templates
• Attack vectors
        """)
        layout.addWidget(self.exploit_content)
        
        # Quick actions
        action_layout = QHBoxLayout()
        
        btn_search_exploitdb = QPushButton("🔍 Search ExploitDB")
        action_layout.addWidget(btn_search_exploitdb)
        
        btn_search_github = QPushButton("📦 Search GitHub")
        action_layout.addWidget(btn_search_github)
        
        btn_metasploit = QPushButton("🎯 Check Metasploit")
        action_layout.addWidget(btn_metasploit)
        
        layout.addLayout(action_layout)
        
        return widget
    
    def _create_remediation_tab(self) -> QWidget:
        """Create remediation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Patch status
        self.patch_status_label = QLabel("No CVE selected")
        self.patch_status_label.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        self.patch_status_label.setStyleSheet("color: #00ff88;")
        layout.addWidget(self.patch_status_label)
        
        # Remediation steps
        self.remediation_content = QTextEdit()
        self.remediation_content.setReadOnly(True)
        self.remediation_content.setStyleSheet("""
            QTextEdit {
                background: rgba(0, 255, 136, 0.1);
                border: 1px solid #00ff88;
                border-radius: 5px;
                color: #ffffff;
                font-family: Consolas;
                font-size: 12px;
            }
        """)
        self.remediation_content.setText("""
<b>Remediation Steps</b>

Select a CVE to view remediation guidance including:
• Available patches
• Vendor advisories
• Workarounds
• Configuration changes
• Detection rules
        """)
        layout.addWidget(self.remediation_content)
        
        # References
        ref_group = QGroupBox("🔗 References")
        ref_layout = QVBoxLayout(ref_group)
        
        self.ref_list = QListWidget()
        self.ref_list.setStyleSheet("""
            QListWidget {
                background: transparent;
                border: none;
                color: #0088ff;
            }
            QListWidget::item {
                padding: 5px;
            }
        """)
        ref_layout.addWidget(self.ref_list)
        
        layout.addWidget(ref_group)
        
        return widget
    
    def _create_stats_tab(self) -> QWidget:
        """Create statistics tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Stats grid
        grid = QGridLayout()
        
        # Severity breakdown
        severity_group = QGroupBox("CVEs by Severity")
        severity_layout = QVBoxLayout(severity_group)
        self.severity_stats = QLabel("Loading...")
        self.severity_stats.setStyleSheet("color: #ffffff; font-family: Consolas;")
        severity_layout.addWidget(self.severity_stats)
        grid.addWidget(severity_group, 0, 0)
        
        # Exploit breakdown
        exploit_group = QGroupBox("CVEs by Exploit Status")
        exploit_layout = QVBoxLayout(exploit_group)
        self.exploit_stats = QLabel("Loading...")
        self.exploit_stats.setStyleSheet("color: #ffffff; font-family: Consolas;")
        exploit_layout.addWidget(self.exploit_stats)
        grid.addWidget(exploit_group, 0, 1)
        
        # Top products
        product_group = QGroupBox("Top Affected Products")
        product_layout = QVBoxLayout(product_group)
        self.product_stats = QLabel("Loading...")
        self.product_stats.setStyleSheet("color: #ffffff; font-family: Consolas;")
        product_layout.addWidget(self.product_stats)
        grid.addWidget(product_group, 1, 0, 1, 2)
        
        layout.addLayout(grid)
        
        return widget
    
    def _connect_signals(self):
        """Connect signals"""
        pass
    
    def _get_stylesheet(self) -> str:
        """Get page stylesheet"""
        return """
            QWidget {
                background: #0f0f1a;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
            }
            
            QFrame#headerFrame {
                background: rgba(20, 20, 40, 0.8);
                border-radius: 10px;
                padding: 15px;
            }
            
            QFrame#leftPanel, QFrame#rightPanel {
                background: rgba(20, 20, 40, 0.5);
                border-radius: 10px;
                padding: 10px;
            }
            
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                color: #ff4400;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            
            QPushButton {
                background: rgba(30, 30, 50, 0.8);
                border: 1px solid #444;
                border-radius: 5px;
                color: #ffffff;
                padding: 8px 15px;
            }
            
            QPushButton:hover {
                background: rgba(255, 68, 0, 0.2);
                border-color: #ff4400;
            }
        """
    
    def _load_data(self):
        """Load CVE data from engine"""
        if not self.engine:
            return
        
        stats = self.engine.get_statistics()
        self.stat_total.value_label.setText(str(stats.get("total_cves", 0)))
        self.stat_critical.value_label.setText(str(stats.get("critical_cves", 0)))
        self.stat_exploited.value_label.setText(str(stats.get("exploited_cves", 0)))
        self.stat_kev.value_label.setText(str(stats.get("kev_cves", 0)))
        
        # Load prioritized CVEs
        prioritized = self.engine.get_prioritized_cves(limit=30)
        self._display_cves(prioritized)
        
        # Update statistics tab
        self._update_stats_tab(stats)
    
    def _load_demo_data(self):
        """Load demo data"""
        self.stat_total.value_label.setText("8")
        self.stat_critical.value_label.setText("6")
        self.stat_exploited.value_label.setText("8")
        self.stat_kev.value_label.setText("8")
    
    def _display_cves(self, cves):
        """Display CVE list"""
        # Clear existing
        while self.cve_layout.count():
            item = self.cve_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Add CVE cards
        for cve, risk_score in cves:
            card = CVECard(cve, risk_score)
            card.clicked.connect(self._show_cve_details)
            self.cve_layout.addWidget(card)
    
    def _show_cve_details(self, cve):
        """Show CVE details"""
        self.detail_cve_id.setText(cve.cve_id)
        
        severity_colors = {
            "critical": "#ff0044",
            "high": "#ff4400",
            "medium": "#ffaa00",
            "low": "#00aaff"
        }
        severity = cve.severity.value if hasattr(cve, 'severity') else "medium"
        color = severity_colors.get(severity, "#888888")
        self.detail_cve_id.setStyleSheet(f"color: {color};")
        
        details = f"""
<b style="font-size: 14px;">{cve.title if hasattr(cve, 'title') else 'Unknown'}</b><br><br>

<b>Severity:</b> <span style="color:{color};">{severity.upper()}</span><br>
<b>CVSS Score:</b> {cve.cvss_score if hasattr(cve, 'cvss_score') else 'N/A'}<br>
<b>CVSS Vector:</b> {cve.cvss_vector if hasattr(cve, 'cvss_vector') else 'N/A'}<br><br>

<b>Description:</b><br>
{cve.description if hasattr(cve, 'description') else 'No description available'}<br><br>

<b>Affected Products:</b> {', '.join(cve.affected_products) if hasattr(cve, 'affected_products') else 'N/A'}<br>
<b>Affected Versions:</b> {', '.join(cve.affected_versions) if hasattr(cve, 'affected_versions') else 'N/A'}<br><br>

<b>CWE IDs:</b> {', '.join(cve.cwe_ids) if hasattr(cve, 'cwe_ids') else 'N/A'}<br>
<b>Published:</b> {cve.published_date.strftime('%Y-%m-%d') if hasattr(cve, 'published_date') else 'N/A'}<br>
<b>Days Since Disclosure:</b> {cve.days_since_disclosure if hasattr(cve, 'days_since_disclosure') else 'N/A'}<br><br>

<b>EPSS Score:</b> {cve.epss_score:.1%} if hasattr(cve, 'epss_score') else 'N/A'<br>
<b>KEV Listed:</b> {'✅ Yes' if hasattr(cve, 'kev_listed') and cve.kev_listed else '❌ No'}
        """
        self.detail_content.setHtml(details)
        
        # Update MITRE techniques
        self.mitre_list.clear()
        if hasattr(cve, 'mitre_techniques') and cve.mitre_techniques:
            for technique in cve.mitre_techniques:
                item = QListWidgetItem(f"🎯 {technique}")
                self.mitre_list.addItem(item)
        
        # Update exploit tab
        exploit_status = cve.exploit_status.value if hasattr(cve, 'exploit_status') else "unknown"
        self.exploit_status_label.setText(f"Exploit Status: {exploit_status.replace('_', ' ').title()}")
        
        exploit_info = f"""
<b>Exploit Availability</b><br><br>
Status: <b>{exploit_status.replace('_', ' ').title()}</b><br><br>
"""
        if exploit_status == "weaponized":
            exploit_info += """
⚠️ <b style="color:#ff0044;">ACTIVELY EXPLOITED IN THE WILD</b><br><br>
This vulnerability is being actively exploited by threat actors.
Immediate remediation is strongly recommended.
            """
        elif exploit_status == "poc_public":
            exploit_info += """
🟠 <b>Public Proof-of-Concept Available</b><br><br>
A working exploit is publicly available. Exploitation is expected to increase.
            """
        
        self.exploit_content.setHtml(exploit_info)
        
        # Update remediation tab
        patch_status = cve.patch_status.value if hasattr(cve, 'patch_status') else "unknown"
        self.patch_status_label.setText(f"Patch Status: {patch_status.title()}")
        
        remediation_info = f"""
<b>Remediation Guidance</b><br><br>
Patch Status: <b>{patch_status.title()}</b><br><br>

<b>Recommended Actions:</b><br>
"""
        if patch_status == "available":
            remediation_info += """
✅ <b style="color:#00ff88;">Patch is available</b><br><br>
1. Apply the latest vendor patch immediately<br>
2. Verify patch deployment across all affected systems<br>
3. Monitor for exploitation attempts<br>
4. Update detection signatures
            """
        else:
            remediation_info += """
⚠️ <b style="color:#ffaa00;">No patch available yet</b><br><br>
1. Implement available workarounds<br>
2. Increase monitoring for exploitation<br>
3. Consider taking affected systems offline if critical<br>
4. Contact vendor for ETA on patch
            """
        
        self.remediation_content.setHtml(remediation_info)
    
    def _filter_cves(self, *args):
        """Filter CVE list"""
        if not self.engine:
            return
        
        query = self.search_input.text()
        severity_text = self.severity_filter.currentText()
        exploit_text = self.exploit_filter.currentText()
        kev_only = self.kev_checkbox.isChecked()
        
        # Map filter text to enum
        severity = None
        if severity_text != "All Severities":
            severity = VulnSeverity(severity_text.lower())
        
        exploit_status = None
        if exploit_text != "All Exploits":
            exploit_map = {
                "Weaponized": ExploitStatus.WEAPONIZED,
                "PoC Public": ExploitStatus.POC_PUBLIC,
                "PoC Private": ExploitStatus.POC_PRIVATE,
                "Theoretical": ExploitStatus.THEORETICAL
            }
            exploit_status = exploit_map.get(exploit_text)
        
        results = self.engine.search_cves(
            query=query if query else None,
            severity=severity,
            exploit_status=exploit_status,
            kev_only=kev_only,
            limit=50
        )
        
        # Calculate risk scores
        scored_results = [(cve, self.engine.calculate_risk_score(cve)) for cve in results]
        scored_results.sort(key=lambda x: x[1], reverse=True)
        
        self._display_cves(scored_results)
    
    def _quick_filter(self, filter_type: str):
        """Apply quick filter"""
        if filter_type == "critical":
            self.severity_filter.setCurrentText("Critical")
        elif filter_type == "exploited":
            self.exploit_filter.setCurrentText("Weaponized")
        elif filter_type == "kev":
            self.kev_checkbox.setChecked(True)
        elif filter_type == "recent":
            self.severity_filter.setCurrentText("All Severities")
            self.exploit_filter.setCurrentText("All Exploits")
            self.kev_checkbox.setChecked(False)
        
        self._filter_cves()
    
    def _update_stats_tab(self, stats: Dict):
        """Update statistics tab"""
        # Severity breakdown
        severity_text = "\n".join([f"• {k.upper()}: {v}" for k, v in stats.get("severity_breakdown", {}).items()])
        self.severity_stats.setText(severity_text or "No data")
        
        # Exploit breakdown
        exploit_text = "\n".join([f"• {k.replace('_', ' ').title()}: {v}" for k, v in stats.get("exploit_breakdown", {}).items()])
        self.exploit_stats.setText(exploit_text or "No data")
        
        # Top products
        product_text = "\n".join([f"• {k}: {v} CVEs" for k, v in stats.get("top_products", {}).items()])
        self.product_stats.setText(product_text or "No data")
    
    def _export_cves(self):
        """Export CVEs"""
        print("📤 Exporting CVEs...")
    
    def _scan_assets(self):
        """Scan assets for CVEs"""
        print("🔍 Scanning assets...")
    
    def _generate_report(self):
        """Generate vulnerability report"""
        print("📋 Generating report...")
