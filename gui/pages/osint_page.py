#!/usr/bin/env python3
"""
HydraRecon Advanced OSINT Page
████████████████████████████████████████████████████████████████████████████████
█  CUTTING-EDGE OSINT INTERFACE - Next-Generation Intelligence Platform        █
████████████████████████████████████████████████████████████████████████████████
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QTabWidget, QGridLayout, QCheckBox,
    QScrollArea, QGroupBox, QTreeWidget, QTreeWidgetItem, QMessageBox,
    QProgressBar, QStackedWidget, QSpinBox, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QTimer, pyqtProperty
from PyQt6.QtGui import QFont, QColor, QPainter, QBrush, QPen
import asyncio
import json

from ..widgets import ModernLineEdit, ConsoleOutput, ScanProgressWidget, GlowingButton


class AdvancedOSINTThread(QThread):
    """Background thread for advanced OSINT gathering"""
    progress = pyqtSignal(int, int, str)
    finding = pyqtSignal(dict)
    result = pyqtSignal(dict)
    error = pyqtSignal(str)
    finished_scan = pyqtSignal()
    
    def __init__(self, scanner, target, modules):
        super().__init__()
        self.scanner = scanner
        self.target = target
        self.modules = modules
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            def progress_cb(current, total, message):
                self.progress.emit(current, total, message)
            
            # Try advanced scanner first
            if hasattr(self.scanner, 'scan'):
                result = loop.run_until_complete(
                    self.scanner.scan(
                        self.target,
                        modules=self.modules
                    )
                )
                
                # Handle both return types
                if hasattr(result, 'findings'):
                    findings = result.findings
                    result_data = result.data if hasattr(result, 'data') else {}
                else:
                    findings = result.get('findings', [])
                    result_data = result
                
                for finding in findings:
                    self.finding.emit(finding if isinstance(finding, dict) else finding.__dict__)
                
                self.result.emit(result_data if isinstance(result_data, dict) else {})
            
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished_scan.emit()


class RiskGauge(QWidget):
    """Animated risk score gauge"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = 0
        self.setFixedSize(180, 180)
    
    def getValue(self):
        return self._value
    
    def setValue(self, val):
        self._value = val
        self.update()
    
    value = pyqtProperty(int, getValue, setValue)
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        rect = self.rect().adjusted(15, 15, -15, -15)
        
        # Background arc
        pen = QPen(QColor("#21262d"))
        pen.setWidth(12)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, 225 * 16, -270 * 16)
        
        # Value arc - color based on risk
        if self._value < 30:
            color = QColor("#238636")
        elif self._value < 60:
            color = QColor("#d29922")
        elif self._value < 80:
            color = QColor("#f85149")
        else:
            color = QColor("#ff4444")
        
        pen = QPen(color)
        pen.setWidth(12)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        span = int(-270 * 16 * (self._value / 100))
        painter.drawArc(rect, 225 * 16, span)
        
        # Value text
        painter.setPen(QPen(QColor("#ffffff")))
        font = QFont("Segoe UI", 28, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{int(self._value)}")
        
        # Label
        font = QFont("Segoe UI", 10)
        painter.setFont(font)
        painter.setPen(QPen(QColor("#8b949e")))
        label_rect = rect.adjusted(0, 45, 0, 45)
        painter.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, "RISK SCORE")


class FindingCard(QFrame):
    """Individual finding display card"""
    
    def __init__(self, finding: dict, parent=None):
        super().__init__(parent)
        self.finding = finding
        self._setup_ui()
    
    def _setup_ui(self):
        severity = self.finding.get('severity', 'info')
        
        colors = {
            'critical': ('#ff4444', 'rgba(255, 68, 68, 0.1)'),
            'high': ('#f85149', 'rgba(248, 81, 73, 0.1)'),
            'medium': ('#d29922', 'rgba(210, 153, 34, 0.1)'),
            'low': ('#238636', 'rgba(35, 134, 54, 0.1)'),
            'info': ('#0088ff', 'rgba(0, 136, 255, 0.1)')
        }
        
        border_color, bg_color = colors.get(severity, colors['info'])
        
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg_color};
                border: 1px solid {border_color};
                border-left: 4px solid {border_color};
                border-radius: 8px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        
        header = QHBoxLayout()
        
        title = QLabel(self.finding.get('title', 'Unknown'))
        title.setStyleSheet(f"color: {border_color}; font-weight: 600; font-size: 13px;")
        title.setWordWrap(True)
        
        source = QLabel(self.finding.get('source', ''))
        source.setStyleSheet("color: #8b949e; font-size: 10px;")
        
        header.addWidget(title, stretch=1)
        header.addWidget(source)
        
        layout.addLayout(header)
        
        tags = self.finding.get('tags', [])
        if tags:
            tags_layout = QHBoxLayout()
            tags_layout.setSpacing(4)
            
            for tag in tags[:4]:
                tag_label = QLabel(tag)
                tag_label.setStyleSheet("""
                    background-color: #21262d;
                    color: #8b949e;
                    padding: 2px 6px;
                    border-radius: 8px;
                    font-size: 9px;
                """)
                tags_layout.addWidget(tag_label)
            
            tags_layout.addStretch()
            layout.addLayout(tags_layout)


class OSINTPage(QWidget):
    """Advanced OSINT gathering page"""
    
    BASIC_MODULES = [
        ("dns", "🌐", "DNS Enumeration", "DNS records, subdomains, zone transfers"),
        ("whois", "📋", "WHOIS Lookup", "Domain registration and ownership"),
        ("ip_intel", "📍", "IP Intelligence", "Geolocation, ASN, network data"),
        ("cert_transparency", "🔐", "Certificate Transparency", "SSL certs from CT logs"),
        ("web_tech", "🔧", "Technology Analysis", "CMS, frameworks, servers"),
        ("email_harvest", "📧", "Email Harvesting", "Discover email addresses"),
    ]
    
    ADVANCED_MODULES = [
        ("social_media", "👥", "Social Media Intel", "Cross-platform profiles"),
        ("breach_data", "⚠️", "Breach Analysis", "Data breach exposure"),
        ("code_search", "💻", "Code Repository", "GitHub secrets exposure"),
        ("wayback", "📚", "Wayback Machine", "Historical analysis"),
        ("ssl_analysis", "🔒", "SSL Deep Analysis", "Certificate analysis"),
        ("cloud_assets", "☁️", "Cloud Discovery", "S3/Azure/GCP buckets"),
        ("threat_intel", "🎯", "Threat Intelligence", "Malicious indicators"),
        ("passive_dns", "📡", "Passive DNS", "Historical DNS"),
        ("asn_analysis", "🌍", "ASN Analysis", "BGP/network info"),
    ]
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self.scanner = None
        self.advanced_scanner = None
        self.scan_thread = None
        self.findings = []
        self.module_checks = {}
        self._setup_ui()
        self._init_scanners()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(20)
        
        header = self._create_header()
        layout.addLayout(header)
        
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        left_panel = self._create_config_panel()
        main_splitter.addWidget(left_panel)
        
        right_panel = self._create_results_panel()
        main_splitter.addWidget(right_panel)
        
        main_splitter.setSizes([420, 880])
        layout.addWidget(main_splitter)
    
    def _create_header(self) -> QHBoxLayout:
        layout = QHBoxLayout()
        
        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)
        
        title = QLabel("🔍 OSINT Intelligence Platform")
        title.setFont(QFont("Segoe UI", 26, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e6e6;")
        
        glow = QGraphicsDropShadowEffect()
        glow.setColor(QColor("#00ff88"))
        glow.setBlurRadius(15)
        glow.setOffset(0, 0)
        title.setGraphicsEffect(glow)
        
        subtitle = QLabel("Advanced Open Source Intelligence Gathering & Analysis")
        subtitle.setStyleSheet("color: #8b949e; font-size: 13px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Stats display
        self.total_findings_label = QLabel("0")
        self.total_findings_label.setStyleSheet("color: #00ff88; font-size: 22px; font-weight: bold;")
        
        findings_text = QLabel("Findings")
        findings_text.setStyleSheet("color: #8b949e; font-size: 10px;")
        
        stat_layout = QVBoxLayout()
        stat_layout.setSpacing(0)
        stat_layout.addWidget(self.total_findings_label, alignment=Qt.AlignmentFlag.AlignCenter)
        stat_layout.addWidget(findings_text, alignment=Qt.AlignmentFlag.AlignCenter)
        
        layout.addLayout(stat_layout)
        
        return layout
    
    def _create_config_panel(self) -> QFrame:
        panel = QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)
        
        # Target section
        target_frame = QFrame()
        target_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 10px;
            }
        """)
        target_layout = QVBoxLayout(target_frame)
        target_layout.setContentsMargins(14, 14, 14, 14)
        
        target_label = QLabel("🎯 Target")
        target_label.setStyleSheet("color: #00ff88; font-weight: 700; font-size: 12px;")
        target_layout.addWidget(target_label)
        
        self.target_input = ModernLineEdit("Domain, IP, email, or username")
        target_layout.addWidget(self.target_input)
        
        type_layout = QHBoxLayout()
        type_label = QLabel("Type:")
        type_label.setStyleSheet("color: #8b949e; font-size: 11px;")
        self.target_type = QComboBox()
        self.target_type.addItems(["Auto-Detect", "Domain", "IP Address", "Email", "Username"])
        self.target_type.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px;
                color: #e6e6e6;
                font-size: 11px;
            }
        """)
        type_layout.addWidget(type_label)
        type_layout.addWidget(self.target_type)
        type_layout.addStretch()
        target_layout.addLayout(type_layout)
        
        layout.addWidget(target_frame)
        
        # Modules tabs
        modules_tabs = QTabWidget()
        modules_tabs.setStyleSheet("""
            QTabWidget::pane {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #0d1117;
                color: #8b949e;
                padding: 6px 14px;
                border: none;
                font-size: 11px;
            }
            QTabBar::tab:selected {
                background-color: #161b22;
                color: #00ff88;
            }
        """)
        
        basic_tab = self._create_modules_tab(self.BASIC_MODULES)
        modules_tabs.addTab(basic_tab, "🔧 Basic")
        
        advanced_tab = self._create_modules_tab(self.ADVANCED_MODULES)
        modules_tabs.addTab(advanced_tab, "🚀 Advanced")
        
        layout.addWidget(modules_tabs)
        
        # Quick buttons with better labels
        quick_layout = QHBoxLayout()
        quick_layout.setSpacing(6)
        
        quick_actions = [
            ("Select All", "📋", self._select_all, "Enable all OSINT modules"),
            ("Clear", "🗑️", self._select_none, "Disable all modules"),
            ("🕵️ Full Recon", "🚀", self._preset_full_recon, "Complete reconnaissance preset"),
            ("⚡ Quick", "💨", self._preset_quick_scan, "Fast essential checks"),
        ]
        
        for text, icon, callback, tooltip in quick_actions:
            btn = QPushButton(text)
            btn.clicked.connect(callback)
            btn.setToolTip(tooltip)
            if "Full" in text or "Quick" in text:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #238636;
                        border: none;
                        border-radius: 6px;
                        padding: 6px 12px;
                        color: white;
                        font-size: 11px;
                        font-weight: 600;
                    }
                    QPushButton:hover { background-color: #2ea043; }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #21262d;
                        border: none;
                        border-radius: 6px;
                        padding: 6px 12px;
                        color: #e6e6e6;
                        font-size: 11px;
                    }
                    QPushButton:hover { background-color: #30363d; }
                """)
            quick_layout.addWidget(btn)
        
        layout.addLayout(quick_layout)
        
        layout.addStretch()
        
        # Action buttons
        self.gather_btn = GlowingButton("🚀 Start Intelligence Gathering")
        self.gather_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #238636, stop:1 #00ff88);
                border: none;
                border-radius: 10px;
                padding: 14px;
                color: white;
                font-weight: 700;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2ea043, stop:1 #33ff99);
            }
            QPushButton:disabled {
                background: #21262d;
                color: #484f58;
            }
        """)
        self.gather_btn.clicked.connect(self._start_gathering)
        layout.addWidget(self.gather_btn)
        
        self.stop_btn = QPushButton("⛔ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #da3633;
                border: none;
                border-radius: 10px;
                padding: 12px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #f85149; }
            QPushButton:disabled { background-color: #21262d; color: #484f58; }
        """)
        self.stop_btn.clicked.connect(self._stop_gathering)
        layout.addWidget(self.stop_btn)
        
        return panel
    
    def _create_modules_tab(self, modules: list) -> QWidget:
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)
        
        for module_id, icon, name, desc in modules:
            module_frame = QFrame()
            module_frame.setStyleSheet("""
                QFrame {
                    background-color: #0d1117;
                    border: 1px solid #21262d;
                    border-radius: 6px;
                }
                QFrame:hover {
                    border-color: #30363d;
                    background-color: #161b22;
                }
            """)
            
            module_layout = QHBoxLayout(module_frame)
            module_layout.setContentsMargins(10, 8, 10, 8)
            
            check = QCheckBox()
            check.setChecked(module_id in ['dns', 'whois', 'ip_intel', 'web_tech'])
            self.module_checks[module_id] = check
            
            icon_label = QLabel(icon)
            icon_label.setStyleSheet("font-size: 16px;")
            
            text_layout = QVBoxLayout()
            text_layout.setSpacing(0)
            
            name_label = QLabel(name)
            name_label.setStyleSheet("color: #e6e6e6; font-weight: 600; font-size: 11px;")
            
            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color: #8b949e; font-size: 9px;")
            
            text_layout.addWidget(name_label)
            text_layout.addWidget(desc_label)
            
            module_layout.addWidget(check)
            module_layout.addWidget(icon_label)
            module_layout.addLayout(text_layout)
            module_layout.addStretch()
            
            layout.addWidget(module_frame)
        
        layout.addStretch()
        scroll.setWidget(content)
        
        main_layout = QVBoxLayout(widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)
        
        return widget
    
    def _create_results_panel(self) -> QFrame:
        panel = QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)
        
        # Progress section
        progress_frame = QFrame()
        progress_frame.setStyleSheet("QFrame { background-color: #161b22; border-radius: 10px; }")
        progress_layout = QHBoxLayout(progress_frame)
        progress_layout.setContentsMargins(14, 14, 14, 14)
        
        self.risk_gauge = RiskGauge()
        progress_layout.addWidget(self.risk_gauge)
        
        progress_info = QVBoxLayout()
        progress_info.setSpacing(6)
        
        self.status_label = QLabel("Ready to gather intelligence")
        self.status_label.setStyleSheet("color: #e6e6e6; font-size: 13px; font-weight: 600;")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #21262d;
                border: none;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, stop:1 #0088ff);
                border-radius: 4px;
            }
        """)
        self.progress_bar.setValue(0)
        
        self.module_status = QLabel("Select modules and enter target")
        self.module_status.setStyleSheet("color: #8b949e; font-size: 11px;")
        
        progress_info.addWidget(self.status_label)
        progress_info.addWidget(self.progress_bar)
        progress_info.addWidget(self.module_status)
        progress_info.addStretch()
        
        progress_layout.addLayout(progress_info, stretch=1)
        layout.addWidget(progress_frame)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet("""
            QTabWidget::pane {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 8px 14px;
                margin-right: 2px;
                font-size: 11px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #00ff88;
                border-bottom: 2px solid #00ff88;
            }
        """)
        
        # Overview
        overview_tab = self._create_overview_tab()
        self.results_tabs.addTab(overview_tab, "📊 Overview")
        
        # All findings
        findings_tab = self._create_findings_tab()
        self.results_tabs.addTab(findings_tab, "📋 Findings")
        
        # DNS
        dns_tab = self._create_table_tab(["Type", "Value", "TTL"], "dns_table")
        self.results_tabs.addTab(dns_tab, "🌐 DNS")
        
        # Subdomains
        sub_tab = self._create_table_tab(["Subdomain", "IP", "Status", "Source"], "subdomains_table")
        self.results_tabs.addTab(sub_tab, "🔗 Subdomains")
        
        # Social
        social_tab = self._create_table_tab(["Platform", "Username", "URL", "Status"], "social_table")
        self.results_tabs.addTab(social_tab, "👥 Social")
        
        # Console
        console_tab = QWidget()
        console_layout = QVBoxLayout(console_tab)
        console_layout.setContentsMargins(8, 8, 8, 8)
        self.console = ConsoleOutput()
        console_layout.addWidget(self.console)
        self.results_tabs.addTab(console_tab, "📝 Console")
        
        layout.addWidget(self.results_tabs)
        
        return panel
    
    def _create_overview_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        
        # Summary cards
        cards_grid = QGridLayout()
        cards_grid.setSpacing(8)
        
        self.summary_cards = {}
        card_defs = [
            ("subdomains", "🔗", "Subdomains"),
            ("dns_records", "🌐", "DNS Records"),
            ("emails", "📧", "Emails"),
            ("social", "👥", "Social"),
            ("breaches", "⚠️", "Breaches"),
            ("cloud", "☁️", "Cloud"),
            ("certs", "🔐", "Certs"),
            ("tech", "🔧", "Tech"),
        ]
        
        for i, (key, icon, label) in enumerate(card_defs):
            card = self._create_mini_card(icon, label)
            self.summary_cards[key] = card
            cards_grid.addWidget(card, i // 4, i % 4)
        
        layout.addLayout(cards_grid)
        
        # Findings scroll
        self.overview_scroll = QScrollArea()
        self.overview_scroll.setWidgetResizable(True)
        self.overview_scroll.setStyleSheet("QScrollArea { border: none; }")
        
        self.findings_container = QWidget()
        self.findings_layout = QVBoxLayout(self.findings_container)
        self.findings_layout.setSpacing(6)
        self.findings_layout.addStretch()
        
        self.overview_scroll.setWidget(self.findings_container)
        layout.addWidget(self.overview_scroll)
        
        return widget
    
    def _create_mini_card(self, icon: str, label: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)
        
        header = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setStyleSheet("font-size: 16px;")
        header.addWidget(icon_label)
        header.addStretch()
        
        value_label = QLabel("0")
        value_label.setObjectName("value")
        value_label.setStyleSheet("color: #00ff88; font-size: 20px; font-weight: bold;")
        
        label_widget = QLabel(label)
        label_widget.setStyleSheet("color: #8b949e; font-size: 9px;")
        
        layout.addLayout(header)
        layout.addWidget(value_label)
        layout.addWidget(label_widget)
        
        return card
    
    def _create_findings_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        
        # Filter
        filter_layout = QHBoxLayout()
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low", "Info"])
        self.severity_filter.setStyleSheet("""
            QComboBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 4px 10px;
                color: #e6e6e6;
                font-size: 11px;
            }
        """)
        self.severity_filter.currentTextChanged.connect(self._filter_findings)
        
        export_btn = QPushButton("📥 Export")
        export_btn.clicked.connect(self._export_findings)
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
                color: #e6e6e6;
                font-size: 11px;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        
        filter_layout.addWidget(QLabel("Filter:"))
        filter_layout.addWidget(self.severity_filter)
        filter_layout.addStretch()
        filter_layout.addWidget(export_btn)
        
        layout.addLayout(filter_layout)
        
        self.findings_tree = QTreeWidget()
        self.findings_tree.setHeaderLabels(["Finding", "Source", "Severity", "Confidence"])
        self.findings_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                font-size: 11px;
            }
            QTreeWidget::item:hover { background-color: #21262d; }
            QTreeWidget::item:selected { background-color: #238636; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 8px;
                font-size: 10px;
            }
        """)
        self.findings_tree.setColumnWidth(0, 280)
        self.findings_tree.setColumnWidth(1, 100)
        self.findings_tree.setColumnWidth(2, 70)
        
        layout.addWidget(self.findings_tree)
        
        return widget
    
    def _create_table_tab(self, headers: list, attr_name: str) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                font-size: 11px;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                padding: 8px;
                font-size: 10px;
            }
        """)
        
        setattr(self, attr_name, table)
        layout.addWidget(table)
        
        return widget
    
    def _init_scanners(self):
        try:
            from scanners import OSINTScanner
            self.scanner = OSINTScanner(self.config, self.db)
            self.console.append_success("Basic OSINT scanner ready")
        except Exception as e:
            self.console.append_warning(f"Basic OSINT: {e}")
        
        try:
            from scanners.osint_advanced import AdvancedOSINTScanner
            self.advanced_scanner = AdvancedOSINTScanner(self.config, self.db)
            self.console.append_success("Advanced OSINT scanner ready")
        except Exception as e:
            self.console.append_warning(f"Advanced OSINT not available: {e}")
    
    def _select_all(self):
        """Select all modules"""
        for check in self.module_checks.values():
            check.setChecked(True)
    
    def _select_none(self):
        """Deselect all modules"""
        for check in self.module_checks.values():
            check.setChecked(False)
    
    def _preset_quick_scan(self):
        """Quick essential scan preset"""
        quick_modules = ['dns', 'whois', 'ip_intel', 'web_tech']
        for module_id, check in self.module_checks.items():
            check.setChecked(module_id in quick_modules)
        self.console.append_info("⚡ Quick scan preset loaded: DNS, WHOIS, IP Intel, Web Tech")
    
    def _select_all_modules(self, select: bool):
        for check in self.module_checks.values():
            check.setChecked(select)
    
    def _preset_full_recon(self):
        full_modules = ['dns', 'whois', 'ip_intel', 'cert_transparency', 'web_tech',
                       'email_harvest', 'social_media', 'wayback', 'ssl_analysis',
                       'passive_dns', 'asn_analysis']
        for module_id, check in self.module_checks.items():
            check.setChecked(module_id in full_modules)
    
    def _start_gathering(self):
        target = self.target_input.text().strip()
        
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target.")
            return
        
        modules = [m for m, c in self.module_checks.items() if c.isChecked()]
        
        if not modules:
            QMessageBox.warning(self, "Warning", "Please select at least one module.")
            return
        
        self._clear_results()
        
        self.gather_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText(f"Gathering intelligence on {target}...")
        self.progress_bar.setValue(0)
        self.findings = []
        
        # Use advanced scanner if available and advanced modules selected
        advanced_modules = [m[0] for m in self.ADVANCED_MODULES]
        has_advanced = any(m in advanced_modules for m in modules)
        
        if has_advanced and self.advanced_scanner:
            scanner = self.advanced_scanner
        elif self.scanner:
            scanner = self.scanner
            # Filter to basic only
            basic_module_ids = [m[0] for m in self.BASIC_MODULES]
            modules = [m for m in modules if m in basic_module_ids]
        else:
            QMessageBox.critical(self, "Error", "No OSINT scanner available.")
            self.gather_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            return
        
        self.scan_thread = AdvancedOSINTThread(scanner, target, modules)
        self.scan_thread.progress.connect(self._on_progress)
        self.scan_thread.finding.connect(self._on_finding)
        self.scan_thread.result.connect(self._on_result)
        self.scan_thread.error.connect(self._on_error)
        self.scan_thread.finished_scan.connect(self._on_finished)
        self.scan_thread.start()
        
        self.console.append_command(f"OSINT gathering started: {target}")
        self.console.append_info(f"Modules: {', '.join(modules)}")
    
    def _clear_results(self):
        self.findings_tree.clear()
        self.dns_table.setRowCount(0)
        self.subdomains_table.setRowCount(0)
        self.social_table.setRowCount(0)
        self.console.clear()
        self.risk_gauge.setValue(0)
        
        for card in self.summary_cards.values():
            value_label = card.findChild(QLabel, "value")
            if value_label:
                value_label.setText("0")
        
        while self.findings_layout.count() > 1:
            item = self.findings_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
    
    def _stop_gathering(self):
        if self.advanced_scanner:
            self.advanced_scanner.cancel()
        if self.scanner:
            self.scanner.cancel()
        if self.scan_thread:
            self.scan_thread.terminate()
        
        self._on_finished()
        self.console.append_warning("Gathering cancelled")
    
    def _on_progress(self, current: int, total: int, message: str):
        percent = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(percent)
        self.module_status.setText(message)
    
    def _on_finding(self, finding: dict):
        self.findings.append(finding)
        
        self._add_finding_to_tree(finding)
        self._update_summary(finding)
        self._add_finding_card(finding)
        self._process_finding(finding)
        
        self.total_findings_label.setText(str(len(self.findings)))
        
        severity = finding.get('severity', 'info')
        title = finding.get('title', 'Unknown')
        
        if severity in ['critical', 'high']:
            self.console.append_error(f"[{severity.upper()}] {title}")
        elif severity == 'medium':
            self.console.append_warning(f"[{severity.upper()}] {title}")
        else:
            self.console.append_info(f"[{severity.upper()}] {title}")
    
    def _add_finding_to_tree(self, finding: dict):
        item = QTreeWidgetItem([
            finding.get('title', 'Unknown'),
            finding.get('source', 'unknown'),
            finding.get('severity', 'info'),
            f"{finding.get('confidence', 0)}%"
        ])
        
        colors = {
            'critical': '#ff4444',
            'high': '#f85149',
            'medium': '#d29922',
            'low': '#238636',
            'info': '#0088ff'
        }
        severity = finding.get('severity', 'info')
        item.setForeground(2, QColor(colors.get(severity, '#8b949e')))
        item.setData(0, Qt.ItemDataRole.UserRole, finding)
        
        self.findings_tree.addTopLevelItem(item)
    
    def _add_finding_card(self, finding: dict):
        if finding.get('severity') in ['critical', 'high', 'medium']:
            card = FindingCard(finding)
            self.findings_layout.insertWidget(self.findings_layout.count() - 1, card)
    
    def _update_summary(self, finding: dict):
        category = finding.get('category', '')
        data = finding.get('data', {})
        
        updates = {
            'dns_record': ('dns_records', 1),
            'subdomains': ('subdomains', len(data.get('subdomains', []))),
            'ct_subdomains': ('subdomains', len(data.get('subdomains', []))),
            'emails': ('emails', len(data.get('emails', []))),
            'social_media': ('social', len([p for p in data.get('platforms', []) if p.get('exists')])),
            'breach': ('breaches', 1),
            'cloud_assets': ('cloud', len(data.get('assets', []))),
            'ssl_certificate': ('certs', 1),
            'certificates': ('certs', len(data.get('certificates', []))),
            'technologies': ('tech', len(data.get('technologies', []))),
        }
        
        if category in updates:
            key, inc = updates[category]
            if key in self.summary_cards:
                card = self.summary_cards[key]
                value_label = card.findChild(QLabel, "value")
                if value_label:
                    current = int(value_label.text())
                    value_label.setText(str(current + inc))
    
    def _process_finding(self, finding: dict):
        category = finding.get('category', '')
        data = finding.get('data', {})
        
        if category == 'dns_record':
            record_type = data.get('record_type', '')
            for value in data.get('values', []):
                row = self.dns_table.rowCount()
                self.dns_table.insertRow(row)
                self.dns_table.setItem(row, 0, QTableWidgetItem(record_type))
                self.dns_table.setItem(row, 1, QTableWidgetItem(str(value)))
                self.dns_table.setItem(row, 2, QTableWidgetItem('-'))
        
        elif category in ['subdomains', 'ct_subdomains']:
            for sub in data.get('subdomains', []):
                row = self.subdomains_table.rowCount()
                self.subdomains_table.insertRow(row)
                
                if isinstance(sub, dict):
                    self.subdomains_table.setItem(row, 0, QTableWidgetItem(sub.get('subdomain', '')))
                    self.subdomains_table.setItem(row, 1, QTableWidgetItem(', '.join(sub.get('ips', []))))
                    self.subdomains_table.setItem(row, 2, QTableWidgetItem('Active' if sub.get('alive') else '?'))
                else:
                    self.subdomains_table.setItem(row, 0, QTableWidgetItem(str(sub)))
                    self.subdomains_table.setItem(row, 1, QTableWidgetItem('-'))
                    self.subdomains_table.setItem(row, 2, QTableWidgetItem('Found'))
                
                self.subdomains_table.setItem(row, 3, QTableWidgetItem(finding.get('source', '')))
        
        elif category == 'social_media':
            for platform in data.get('platforms', []):
                if platform.get('exists'):
                    row = self.social_table.rowCount()
                    self.social_table.insertRow(row)
                    self.social_table.setItem(row, 0, QTableWidgetItem(platform.get('platform', '')))
                    self.social_table.setItem(row, 1, QTableWidgetItem(data.get('username', '')))
                    self.social_table.setItem(row, 2, QTableWidgetItem(platform.get('url', '')))
                    self.social_table.setItem(row, 3, QTableWidgetItem('✓ Found'))
    
    def _on_result(self, result: dict):
        total = result.get('total_findings', len(self.findings))
        risk = result.get('overall_risk_score', 0)
        
        self.risk_gauge.setValue(risk)
        self.console.append_success(f"Complete: {total} findings")
        self.status_label.setText(f"Complete: {total} findings")
    
    def _on_error(self, error: str):
        self.console.append_error(f"Error: {error}")
        self.status_label.setText(f"Error: {error[:40]}...")
    
    def _on_finished(self):
        self.gather_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.module_status.setText("Complete")
    
    def _filter_findings(self, text: str):
        for i in range(self.findings_tree.topLevelItemCount()):
            item = self.findings_tree.topLevelItem(i)
            if text == "All":
                item.setHidden(False)
            else:
                severity = item.text(2)
                item.setHidden(severity.lower() != text.lower())
    
    def _export_findings(self):
        if not self.findings:
            QMessageBox.information(self, "Info", "No findings to export.")
            return
        
        from PyQt6.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export", "osint_findings.json", "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.findings, f, indent=2, default=str)
                self.console.append_success(f"Exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {e}")
