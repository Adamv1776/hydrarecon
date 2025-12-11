#!/usr/bin/env python3
"""
HydraRecon AI Analysis Page
████████████████████████████████████████████████████████████████████████████████
█  AI-POWERED SECURITY ANALYSIS - Machine Learning Vulnerability Assessment,   █
█  Attack Path Modeling, Predictive Threat Analysis & Intelligent Exploit      █
█  Recommendations - NEXT-GEN AUTOMATED PENETRATION TESTING INTELLIGENCE       █
████████████████████████████████████████████████████████████████████████████████
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget, QTextEdit,
    QTreeWidget, QTreeWidgetItem, QProgressBar, QGroupBox, QFormLayout,
    QComboBox, QSpinBox, QCheckBox, QSplitter, QScrollArea, QFileDialog,
    QDialog, QListWidget, QListWidgetItem, QLineEdit, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QIcon, QTextCursor
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import json
import os


@dataclass
class AnalysisResult:
    """AI Analysis result"""
    result_id: str
    timestamp: datetime
    analysis_type: str
    target: str
    risk_score: int
    vulnerabilities: List[Dict]
    attack_paths: List[Dict]
    recommendations: List[Dict]
    executive_summary: str


class AIAnalysisThread(QThread):
    """Background thread for AI analysis"""
    progress = pyqtSignal(int, str)
    vulnerability_found = pyqtSignal(dict)
    attack_path_found = pyqtSignal(dict)
    analysis_complete = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, scan_data: Dict, analysis_type: str = "full"):
        super().__init__()
        self.scan_data = scan_data
        self.analysis_type = analysis_type
        self._stopped = False
    
    def stop(self):
        self._stopped = True
    
    def run(self):
        try:
            from core.ai_engine import AISecurityAnalyzer
            
            analyzer = AISecurityAnalyzer()
            
            self.progress.emit(10, "Initializing AI analysis engine...")
            
            if self._stopped:
                return
            
            self.progress.emit(20, "Analyzing scan data...")
            
            # Perform analysis
            analysis = analyzer.analyze_scan_results(self.scan_data)
            
            self.progress.emit(40, f"Found {len(analysis.get('vulnerabilities', []))} vulnerabilities")
            
            # Emit vulnerabilities
            for vuln in analysis.get("vulnerabilities", []):
                if self._stopped:
                    return
                vuln_dict = {
                    "cve_id": vuln.cve_id,
                    "name": vuln.name,
                    "description": vuln.description,
                    "severity": vuln.severity.name,
                    "cvss_score": vuln.cvss_score,
                    "exploit_available": vuln.exploit_available,
                    "affected_services": vuln.affected_services,
                    "tags": vuln.tags
                }
                self.vulnerability_found.emit(vuln_dict)
            
            self.progress.emit(60, "Modeling attack paths...")
            
            # Emit attack paths
            for path in analysis.get("attack_paths", []):
                if self._stopped:
                    return
                path_dict = {
                    "path_id": path.path_id,
                    "name": path.name,
                    "entry_point": path.entry_point,
                    "objective": path.objective,
                    "steps": path.steps,
                    "total_probability": path.total_probability,
                    "risk_score": path.risk_score,
                    "time_estimate": path.time_estimate,
                    "skill_required": path.skill_required,
                    "mitigations": path.mitigations
                }
                self.attack_path_found.emit(path_dict)
            
            self.progress.emit(80, "Generating recommendations...")
            
            self.progress.emit(90, "Preparing final report...")
            
            # Generate MSF resource script
            if analysis.get("exploit_suggestions"):
                msf_script = analyzer.generate_metasploit_resource(analysis["exploit_suggestions"])
                analysis["msf_resource_script"] = msf_script
            
            # Prepare final result
            result = {
                "summary": analysis.get("summary", {}),
                "risk_score": analysis.get("risk_score", 0),
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "name": v.name,
                        "description": v.description,
                        "severity": v.severity.name,
                        "cvss_score": v.cvss_score,
                        "exploit_available": v.exploit_available,
                        "affected_services": v.affected_services,
                        "tags": v.tags
                    } for v in analysis.get("vulnerabilities", [])
                ],
                "exploit_suggestions": [
                    {
                        "exploit_name": s.exploit_name,
                        "exploit_type": s.exploit_type,
                        "framework": s.framework,
                        "module_path": s.module_path,
                        "success_probability": s.success_probability,
                        "payload_options": s.payload_options,
                        "prerequisites": s.prerequisites,
                        "evasion_techniques": s.evasion_techniques
                    } for s in analysis.get("exploit_suggestions", [])
                ],
                "attack_paths": [
                    {
                        "path_id": p.path_id,
                        "name": p.name,
                        "entry_point": p.entry_point,
                        "objective": p.objective,
                        "steps": p.steps,
                        "total_probability": p.total_probability,
                        "risk_score": p.risk_score,
                        "mitigations": p.mitigations
                    } for p in analysis.get("attack_paths", [])
                ],
                "recommendations": analysis.get("recommendations", []),
                "executive_summary": analysis.get("executive_summary", ""),
                "msf_resource_script": analysis.get("msf_resource_script", "")
            }
            
            self.progress.emit(100, "Analysis complete!")
            self.analysis_complete.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class VulnerabilityDetailDialog(QDialog):
    """Dialog showing vulnerability details"""
    
    def __init__(self, vuln: Dict, parent=None):
        super().__init__(parent)
        self.vuln = vuln
        self.setWindowTitle(f"Vulnerability: {vuln.get('name', 'Unknown')}")
        self.setMinimumSize(700, 500)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel(self.vuln.get("name", "Unknown Vulnerability"))
        header.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        # CVE ID
        if self.vuln.get("cve_id"):
            cve = QLabel(f"CVE: {self.vuln['cve_id']}")
            cve.setStyleSheet("color: #ff6b6b; font-weight: bold;")
            layout.addWidget(cve)
        
        # Severity
        severity = self.vuln.get("severity", "INFO")
        severity_colors = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff6b6b",
            "MEDIUM": "#ffa500",
            "LOW": "#00ff00",
            "INFO": "#888888"
        }
        severity_label = QLabel(f"Severity: {severity}")
        severity_label.setStyleSheet(f"color: {severity_colors.get(severity, '#888888')}; font-weight: bold;")
        layout.addWidget(severity_label)
        
        # Description
        desc_group = QGroupBox("Description")
        desc_layout = QVBoxLayout(desc_group)
        desc_text = QTextEdit()
        desc_text.setPlainText(self.vuln.get("description", "No description available"))
        desc_text.setReadOnly(True)
        desc_text.setMaximumHeight(100)
        desc_layout.addWidget(desc_text)
        layout.addWidget(desc_group)
        
        # Affected Services
        services_group = QGroupBox("Affected Services")
        services_layout = QVBoxLayout(services_group)
        services_list = QListWidget()
        for service in self.vuln.get("affected_services", []):
            services_list.addItem(str(service))
        services_layout.addWidget(services_list)
        layout.addWidget(services_group)
        
        # Tags
        if self.vuln.get("tags"):
            tags_label = QLabel(f"Tags: {', '.join(self.vuln['tags'])}")
            tags_label.setStyleSheet("color: #b0b8c2;")
            layout.addWidget(tags_label)
        
        # Exploit Available
        if self.vuln.get("exploit_available"):
            exploit_label = QLabel("⚠️ EXPLOIT AVAILABLE - High Risk!")
            exploit_label.setStyleSheet("color: #ff0000; font-weight: bold; padding: 10px; background: rgba(255,0,0,0.1);")
            layout.addWidget(exploit_label)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)


class AttackPathDialog(QDialog):
    """Dialog showing attack path details"""
    
    def __init__(self, path: Dict, parent=None):
        super().__init__(parent)
        self.path = path
        self.setWindowTitle(f"Attack Path: {path.get('name', 'Unknown')}")
        self.setMinimumSize(800, 600)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel(self.path.get("name", "Unknown Attack Path"))
        header.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #ff6b6b;")
        layout.addWidget(header)
        
        # Info row
        info_layout = QHBoxLayout()
        
        prob_label = QLabel(f"Success Probability: {self.path.get('total_probability', 0)}%")
        prob_label.setStyleSheet("color: #ffa500; font-weight: bold;")
        info_layout.addWidget(prob_label)
        
        risk_label = QLabel(f"Risk Score: {self.path.get('risk_score', 0):.1f}")
        risk_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        info_layout.addWidget(risk_label)
        
        info_layout.addStretch()
        layout.addLayout(info_layout)
        
        # Entry and Objective
        entry_group = QGroupBox("Attack Vector")
        entry_group.setStyleSheet("""
            QGroupBox {
                color: #00ffff;
                font-weight: bold;
                border: 1px solid #00ffff;
                border-radius: 5px;
                margin-top: 10px;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLabel {
                color: #e6edf3;
            }
        """)
        entry_layout = QFormLayout(entry_group)
        
        entry_point_label = QLabel(self.path.get("entry_point", "Unknown"))
        entry_point_label.setStyleSheet("color: #00ff88;")
        entry_layout.addRow("Entry Point:", entry_point_label)
        
        objective_label = QLabel(self.path.get("objective", "Unknown"))
        objective_label.setStyleSheet("color: #00ff88;")
        entry_layout.addRow("Objective:", objective_label)
        layout.addWidget(entry_group)
        
        # Attack Steps
        steps_group = QGroupBox("Attack Steps")
        steps_layout = QVBoxLayout(steps_group)
        
        steps_tree = QTreeWidget()
        steps_tree.setHeaderLabels(["Step", "Action", "Technique", "Probability"])
        steps_tree.setColumnWidth(0, 60)
        steps_tree.setColumnWidth(1, 200)
        steps_tree.setColumnWidth(2, 300)
        
        for step in self.path.get("steps", []):
            item = QTreeWidgetItem([
                str(step.get("step", "")),
                step.get("action", ""),
                step.get("technique", ""),
                f"{step.get('probability', 0) * 100:.0f}%"
            ])
            steps_tree.addTopLevelItem(item)
        
        steps_layout.addWidget(steps_tree)
        layout.addWidget(steps_group)
        
        # Mitigations
        mitigation_group = QGroupBox("Recommended Mitigations")
        mitigation_layout = QVBoxLayout(mitigation_group)
        mitigation_list = QListWidget()
        for mit in self.path.get("mitigations", []):
            mitigation_list.addItem(f"• {mit}")
        mitigation_layout.addWidget(mitigation_list)
        layout.addWidget(mitigation_group)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)


class AIAnalysisPage(QWidget):
    """AI-Powered Security Analysis Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.analysis_thread = None
        self.current_result = None
        self.results_history: List[AnalysisResult] = []
        self.vulnerabilities: List[Dict] = []
        self.attack_paths: List[Dict] = []
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #00ffff;
                background: rgba(0, 20, 40, 0.9);
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #00ffff;
                padding: 10px 20px;
                border: 1px solid #00ffff;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: rgba(0, 255, 255, 0.2);
            }
        """)
        
        # Analysis Tab
        self.tabs.addTab(self._create_analysis_tab(), "🧠 AI Analysis")
        
        # Vulnerabilities Tab
        self.tabs.addTab(self._create_vulnerabilities_tab(), "🔓 Vulnerabilities")
        
        # Attack Paths Tab
        self.tabs.addTab(self._create_attack_paths_tab(), "🎯 Attack Paths")
        
        # Exploit Suggestions Tab
        self.tabs.addTab(self._create_exploits_tab(), "💀 Exploit Suggestions")
        
        # Recommendations Tab
        self.tabs.addTab(self._create_recommendations_tab(), "📋 Recommendations")
        
        # Executive Report Tab
        self.tabs.addTab(self._create_report_tab(), "📊 Executive Report")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(0, 255, 255, 0.2),
                    stop:0.5 rgba(255, 0, 128, 0.2),
                    stop:1 rgba(0, 255, 255, 0.2));
                border: 2px solid #00ffff;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🧠 AI-POWERED SECURITY ANALYSIS")
        title.setFont(QFont("Consolas", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ffff; background: transparent; border: none;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Machine Learning Vulnerability Assessment • Attack Path Modeling • Predictive Threat Intelligence")
        subtitle.setStyleSheet("color: #c9d1d9; background: transparent; border: none;")
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Risk Score Display
        self.risk_score_widget = QFrame()
        self.risk_score_widget.setStyleSheet("""
            QFrame {
                background: rgba(0, 0, 0, 0.5);
                border: 2px solid #ff6b6b;
                border-radius: 50px;
                padding: 10px;
            }
        """)
        risk_layout = QVBoxLayout(self.risk_score_widget)
        risk_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.risk_score_label = QLabel("--")
        self.risk_score_label.setFont(QFont("Consolas", 24, QFont.Weight.Bold))
        self.risk_score_label.setStyleSheet("color: #c9d1d9; background: transparent; border: none;")
        self.risk_score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        risk_layout.addWidget(self.risk_score_label)
        
        risk_text = QLabel("Risk Score")
        risk_text.setStyleSheet("color: #b0b8c2; font-size: 10px; background: transparent; border: none;")
        risk_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        risk_layout.addWidget(risk_text)
        
        layout.addWidget(self.risk_score_widget)
        
        return header
    
    def _create_analysis_tab(self) -> QWidget:
        """Create main analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Data Source Selection
        source_group = QGroupBox("📂 Analysis Data Source")
        source_layout = QVBoxLayout(source_group)
        
        # Source options
        source_options = QHBoxLayout()
        
        self.source_combo = QComboBox()
        self.source_combo.addItems([
            "Load from Nmap Scan",
            "Load from JSON File",
            "Load from Recent Scan",
            "Manual Host Entry"
        ])
        source_label = QLabel("Source:")
        source_label.setStyleSheet("color: #c9d1d9; font-weight: bold;")
        source_options.addWidget(source_label)
        source_options.addWidget(self.source_combo)
        
        self.load_btn = QPushButton("📁 Load Data")
        self.load_btn.clicked.connect(self.load_scan_data)
        source_options.addWidget(self.load_btn)
        
        source_options.addStretch()
        source_layout.addLayout(source_options)
        
        # Manual entry area
        self.manual_entry = QTextEdit()
        self.manual_entry.setPlaceholderText("""Enter scan data in JSON format or paste host details:

{
    "hosts": [
        {
            "ip": "192.168.1.100",
            "ports": [
                {"port": 22, "service": "OpenSSH", "version": "7.6p1"},
                {"port": 80, "service": "Apache", "version": "2.4.29"}
            ]
        }
    ]
}""")
        self.manual_entry.setMaximumHeight(150)
        source_layout.addWidget(self.manual_entry)
        
        layout.addWidget(source_group)
        
        # Analysis Options
        options_group = QGroupBox("⚙️ Analysis Options")
        options_layout = QHBoxLayout(options_group)
        
        checkbox_style = "color: #e6edf3; font-weight: bold;"
        
        self.deep_analysis = QCheckBox("Deep Analysis")
        self.deep_analysis.setChecked(True)
        self.deep_analysis.setStyleSheet(checkbox_style)
        options_layout.addWidget(self.deep_analysis)
        
        self.model_paths = QCheckBox("Model Attack Paths")
        self.model_paths.setChecked(True)
        self.model_paths.setStyleSheet(checkbox_style)
        options_layout.addWidget(self.model_paths)
        
        self.gen_exploits = QCheckBox("Generate Exploit Suggestions")
        self.gen_exploits.setChecked(True)
        self.gen_exploits.setStyleSheet(checkbox_style)
        options_layout.addWidget(self.gen_exploits)
        
        self.gen_msf = QCheckBox("Generate MSF Resource Script")
        self.gen_msf.setChecked(True)
        self.gen_msf.setStyleSheet(checkbox_style)
        options_layout.addWidget(self.gen_msf)
        
        options_layout.addStretch()
        layout.addWidget(options_group)
        
        # Progress section
        progress_group = QGroupBox("📊 Analysis Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #00ffff;
                border-radius: 5px;
                text-align: center;
                background: #1a1a2e;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ffff, stop:1 #ff00ff);
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to analyze")
        self.status_label.setStyleSheet("color: #c9d1d9;")
        progress_layout.addWidget(self.status_label)
        
        layout.addWidget(progress_group)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.analyze_btn = QPushButton("🚀 Start AI Analysis")
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ffff, stop:1 #ff00ff);
                color: black;
                font-weight: bold;
                padding: 15px 30px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff00ff, stop:1 #00ffff);
            }
        """)
        self.analyze_btn.clicked.connect(self.start_analysis)
        btn_layout.addWidget(self.analyze_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_analysis)
        btn_layout.addWidget(self.stop_btn)
        
        btn_layout.addStretch()
        
        self.export_btn = QPushButton("📤 Export Results")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_results)
        btn_layout.addWidget(self.export_btn)
        
        layout.addLayout(btn_layout)
        
        # Summary Cards
        summary_group = QGroupBox("📈 Analysis Summary")
        summary_layout = QHBoxLayout(summary_group)
        
        self.summary_cards = {}
        for label, color in [
            ("Total Vulns", "#00ffff"),
            ("Critical", "#ff0000"),
            ("High", "#ff6b6b"),
            ("Medium", "#ffa500"),
            ("Exploitable", "#ff00ff"),
            ("Attack Paths", "#00ff00")
        ]:
            card = self._create_summary_card(label, color)
            self.summary_cards[label] = card
            summary_layout.addWidget(card)
        
        layout.addWidget(summary_group)
        
        layout.addStretch()
        
        return widget
    
    def _create_summary_card(self, label: str, color: str) -> QFrame:
        """Create a summary statistic card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: rgba(0, 0, 0, 0.5);
                border: 2px solid {color};
                border-radius: 10px;
                padding: 10px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        value = QLabel("0")
        value.setObjectName("value")
        value.setFont(QFont("Consolas", 24, QFont.Weight.Bold))
        value.setStyleSheet(f"color: {color}; background: transparent; border: none;")
        value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(value)
        
        text = QLabel(label)
        text.setStyleSheet(f"color: #c9d1d9; font-size: 11px; background: transparent; border: none;")
        text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(text)
        
        return card
    
    def _create_vulnerabilities_tab(self) -> QWidget:
        """Create vulnerabilities display tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Filters
        filter_layout = QHBoxLayout()
        
        severity_filter_label = QLabel("Severity:")
        severity_filter_label.setStyleSheet("color: #c9d1d9; font-weight: bold;")
        filter_layout.addWidget(severity_filter_label)
        self.vuln_severity_filter = QComboBox()
        self.vuln_severity_filter.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.vuln_severity_filter.currentTextChanged.connect(self.filter_vulnerabilities)
        filter_layout.addWidget(self.vuln_severity_filter)
        
        self.exploitable_only = QCheckBox("Exploitable Only")
        self.exploitable_only.setStyleSheet("color: #e6edf3; font-weight: bold;")
        self.exploitable_only.stateChanged.connect(self.filter_vulnerabilities)
        filter_layout.addWidget(self.exploitable_only)
        
        filter_layout.addStretch()
        
        self.vuln_search = QLineEdit()
        self.vuln_search.setPlaceholderText("🔍 Search vulnerabilities...")
        self.vuln_search.textChanged.connect(self.filter_vulnerabilities)
        filter_layout.addWidget(self.vuln_search)
        
        layout.addLayout(filter_layout)
        
        # Vulnerabilities table
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(7)
        self.vuln_table.setHorizontalHeaderLabels([
            "CVE ID", "Name", "Severity", "CVSS", "Exploit", "Targets", "Tags"
        ])
        self.vuln_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.vuln_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.vuln_table.setAlternatingRowColors(True)
        self.vuln_table.doubleClicked.connect(self.show_vulnerability_details)
        self.vuln_table.setStyleSheet("""
            QTableWidget {
                background-color: #0a0a1a;
                gridline-color: #333;
                color: #00ffff;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: rgba(0, 255, 255, 0.3);
            }
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #00ffff;
                padding: 8px;
                border: 1px solid #333;
                font-weight: bold;
            }
        """)
        
        layout.addWidget(self.vuln_table)
        
        return widget
    
    def _create_attack_paths_tab(self) -> QWidget:
        """Create attack paths visualization tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Attack paths tree
        self.attack_tree = QTreeWidget()
        self.attack_tree.setHeaderLabels([
            "Path / Step", "Entry Point / Action", "Probability", "Risk Score"
        ])
        self.attack_tree.setColumnWidth(0, 200)
        self.attack_tree.setColumnWidth(1, 300)
        self.attack_tree.setColumnWidth(2, 100)
        self.attack_tree.doubleClicked.connect(self.show_attack_path_details)
        self.attack_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0a0a1a;
                color: #00ffff;
                border: 1px solid #333;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QTreeWidget::item:selected {
                background-color: rgba(255, 107, 107, 0.3);
            }
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #ff6b6b;
                padding: 8px;
                border: 1px solid #333;
                font-weight: bold;
            }
        """)
        
        layout.addWidget(self.attack_tree)
        
        # Mitigations panel
        mit_group = QGroupBox("🛡️ Recommended Mitigations")
        mit_layout = QVBoxLayout(mit_group)
        
        self.mitigations_list = QListWidget()
        self.mitigations_list.setStyleSheet("""
            QListWidget {
                background-color: #0a0a1a;
                color: #00ff00;
                border: 1px solid #00ff00;
            }
        """)
        mit_layout.addWidget(self.mitigations_list)
        
        layout.addWidget(mit_group)
        
        return widget
    
    def _create_exploits_tab(self) -> QWidget:
        """Create exploit suggestions tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Exploit suggestions table
        self.exploit_table = QTableWidget()
        self.exploit_table.setColumnCount(6)
        self.exploit_table.setHorizontalHeaderLabels([
            "Exploit Name", "Type", "Framework", "Module Path", "Success Rate", "Payloads"
        ])
        self.exploit_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.exploit_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.exploit_table.setStyleSheet("""
            QTableWidget {
                background-color: #0a0a1a;
                gridline-color: #333;
                color: #ff00ff;
            }
            QTableWidget::item:selected {
                background-color: rgba(255, 0, 255, 0.3);
            }
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #ff00ff;
                padding: 8px;
                border: 1px solid #333;
                font-weight: bold;
            }
        """)
        
        layout.addWidget(self.exploit_table)
        
        # MSF Resource Script
        msf_group = QGroupBox("📜 Metasploit Resource Script")
        msf_layout = QVBoxLayout(msf_group)
        
        self.msf_script = QTextEdit()
        self.msf_script.setReadOnly(True)
        self.msf_script.setFont(QFont("Consolas", 10))
        self.msf_script.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a1a;
                color: #00ff00;
                border: 1px solid #00ff00;
            }
        """)
        self.msf_script.setPlaceholderText("# Metasploit resource script will appear here after analysis...")
        msf_layout.addWidget(self.msf_script)
        
        # Save MSF script button
        save_msf_btn = QPushButton("💾 Save Resource Script")
        save_msf_btn.clicked.connect(self.save_msf_script)
        msf_layout.addWidget(save_msf_btn)
        
        layout.addWidget(msf_group)
        
        return widget
    
    def _create_recommendations_tab(self) -> QWidget:
        """Create recommendations tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Recommendations tree
        self.rec_tree = QTreeWidget()
        self.rec_tree.setHeaderLabels([
            "Priority", "Title", "Effort", "Impact"
        ])
        self.rec_tree.setColumnWidth(0, 100)
        self.rec_tree.setColumnWidth(1, 400)
        self.rec_tree.setColumnWidth(2, 100)
        self.rec_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0a0a1a;
                color: #00ffff;
                border: 1px solid #333;
            }
            QTreeWidget::item {
                padding: 8px;
            }
            QTreeWidget::item:selected {
                background-color: rgba(0, 255, 255, 0.3);
            }
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #00ffff;
                padding: 8px;
                border: 1px solid #333;
                font-weight: bold;
            }
        """)
        
        layout.addWidget(self.rec_tree)
        
        return widget
    
    def _create_report_tab(self) -> QWidget:
        """Create executive report tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Executive Summary
        self.exec_summary = QTextEdit()
        self.exec_summary.setReadOnly(True)
        self.exec_summary.setFont(QFont("Consolas", 11))
        self.exec_summary.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a1a;
                color: #00ffff;
                border: 2px solid #00ffff;
                padding: 15px;
            }
        """)
        self.exec_summary.setPlaceholderText("Executive summary will appear here after analysis...")
        
        layout.addWidget(self.exec_summary)
        
        # Export buttons
        btn_layout = QHBoxLayout()
        
        export_html = QPushButton("📄 Export as HTML")
        export_html.clicked.connect(lambda: self.export_report("html"))
        btn_layout.addWidget(export_html)
        
        export_pdf = QPushButton("📑 Export as PDF")
        export_pdf.clicked.connect(lambda: self.export_report("pdf"))
        btn_layout.addWidget(export_pdf)
        
        export_json = QPushButton("📋 Export as JSON")
        export_json.clicked.connect(lambda: self.export_report("json"))
        btn_layout.addWidget(export_json)
        
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def load_scan_data(self):
        """Load scan data from selected source"""
        source = self.source_combo.currentText()
        
        if source == "Load from JSON File":
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Load Scan Data", "", "JSON Files (*.json);;All Files (*)"
            )
            if file_path:
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                    self.manual_entry.setText(json.dumps(data, indent=2))
                    self.status_label.setText(f"Loaded data from {os.path.basename(file_path)}")
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to load file: {e}")
        
        elif source == "Load from Recent Scan":
            # Try to load from nmap results if available
            self.status_label.setText("Looking for recent scans...")
            # This would integrate with NmapScanner
    
    def start_analysis(self):
        """Start AI analysis"""
        try:
            # Get scan data
            text = self.manual_entry.toPlainText().strip()
            if not text:
                # Generate sample data for testing
                scan_data = {
                    "hosts": [
                        {
                            "ip": "192.168.1.100",
                            "ports": [
                                {"port": 22, "service": "ssh", "version": "OpenSSH 7.6p1"},
                                {"port": 80, "service": "http", "version": "Apache/2.4.29"},
                                {"port": 3306, "service": "mysql", "version": "MySQL 5.5.60"}
                            ]
                        },
                        {
                            "ip": "192.168.1.101",
                            "ports": [
                                {"port": 445, "service": "smb", "version": "Samba 3.5.0"},
                                {"port": 21, "service": "ftp", "version": "vsftpd 2.3.4"}
                            ]
                        }
                    ]
                }
            else:
                try:
                    scan_data = json.loads(text)
                except json.JSONDecodeError:
                    QMessageBox.warning(self, "Error", "Invalid JSON format")
                    return
            
            # Reset UI
            self.vulnerabilities.clear()
            self.attack_paths.clear()
            self.vuln_table.setRowCount(0)
            self.attack_tree.clear()
            self.exploit_table.setRowCount(0)
            self.rec_tree.clear()
            self.msf_script.clear()
            self.exec_summary.clear()
            
            for card in self.summary_cards.values():
                card.findChild(QLabel, "value").setText("0")
            
            # Start analysis thread
            self.analysis_thread = AIAnalysisThread(scan_data)
            self.analysis_thread.progress.connect(self.on_progress)
            self.analysis_thread.vulnerability_found.connect(self.on_vulnerability_found)
            self.analysis_thread.attack_path_found.connect(self.on_attack_path_found)
            self.analysis_thread.analysis_complete.connect(self.on_analysis_complete)
            self.analysis_thread.error.connect(self.on_error)
            
            self.analyze_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            
            self.analysis_thread.start()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start analysis: {e}")
    
    def stop_analysis(self):
        """Stop analysis"""
        if self.analysis_thread and self.analysis_thread.isRunning():
            self.analysis_thread.stop()
            self.analysis_thread.wait()
        
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Analysis stopped")
    
    def on_progress(self, value: int, message: str):
        """Handle progress updates"""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
    
    def on_vulnerability_found(self, vuln: Dict):
        """Handle vulnerability found"""
        self.vulnerabilities.append(vuln)
        self.add_vulnerability_to_table(vuln)
    
    def add_vulnerability_to_table(self, vuln: Dict):
        """Add vulnerability to table"""
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        
        severity_colors = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff6b6b",
            "MEDIUM": "#ffa500",
            "LOW": "#00ff00",
            "INFO": "#888888"
        }
        
        severity = vuln.get("severity", "INFO")
        color = QColor(severity_colors.get(severity, "#888888"))
        
        items = [
            vuln.get("cve_id", "N/A"),
            vuln.get("name", "Unknown"),
            severity,
            str(vuln.get("cvss_score", "N/A")),
            "✅" if vuln.get("exploit_available") else "❌",
            str(len(vuln.get("affected_services", []))),
            ", ".join(vuln.get("tags", [])[:3])
        ]
        
        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            if col == 2:  # Severity column
                item.setForeground(color)
            self.vuln_table.setItem(row, col, item)
    
    def on_attack_path_found(self, path: Dict):
        """Handle attack path found"""
        self.attack_paths.append(path)
        self.add_attack_path_to_tree(path)
    
    def add_attack_path_to_tree(self, path: Dict):
        """Add attack path to tree"""
        path_item = QTreeWidgetItem([
            path.get("path_id", ""),
            path.get("name", ""),
            f"{path.get('total_probability', 0)}%",
            f"{path.get('risk_score', 0):.1f}"
        ])
        path_item.setForeground(0, QColor("#ff6b6b"))
        
        # Add steps
        for step in path.get("steps", []):
            step_item = QTreeWidgetItem([
                f"Step {step.get('step', '')}",
                f"{step.get('action', '')} - {step.get('technique', '')}",
                f"{step.get('probability', 0) * 100:.0f}%",
                ""
            ])
            path_item.addChild(step_item)
        
        self.attack_tree.addTopLevelItem(path_item)
        
        # Add mitigations
        for mit in path.get("mitigations", []):
            self.mitigations_list.addItem(f"• {mit}")
    
    def on_analysis_complete(self, result: Dict):
        """Handle analysis complete"""
        self.current_result = result
        
        # Update summary cards
        summary = result.get("summary", {})
        self.summary_cards["Total Vulns"].findChild(QLabel, "value").setText(
            str(summary.get("total_vulnerabilities", 0))
        )
        self.summary_cards["Critical"].findChild(QLabel, "value").setText(
            str(summary.get("critical", 0))
        )
        self.summary_cards["High"].findChild(QLabel, "value").setText(
            str(summary.get("high", 0))
        )
        self.summary_cards["Medium"].findChild(QLabel, "value").setText(
            str(summary.get("medium", 0))
        )
        self.summary_cards["Exploitable"].findChild(QLabel, "value").setText(
            str(summary.get("exploitable", 0))
        )
        self.summary_cards["Attack Paths"].findChild(QLabel, "value").setText(
            str(summary.get("attack_paths", 0))
        )
        
        # Update risk score
        risk_score = result.get("risk_score", 0)
        self.risk_score_label.setText(str(risk_score))
        
        risk_color = "#ff0000" if risk_score >= 80 else "#ff6b6b" if risk_score >= 60 else "#ffa500" if risk_score >= 40 else "#00ff00"
        self.risk_score_label.setStyleSheet(f"color: {risk_color}; background: transparent; border: none;")
        
        # Update exploit suggestions
        for exploit in result.get("exploit_suggestions", []):
            row = self.exploit_table.rowCount()
            self.exploit_table.insertRow(row)
            
            items = [
                exploit.get("exploit_name", ""),
                exploit.get("exploit_type", ""),
                exploit.get("framework", ""),
                exploit.get("module_path", ""),
                f"{exploit.get('success_probability', 0)}%",
                ", ".join(exploit.get("payload_options", [])[:2])
            ]
            
            for col, text in enumerate(items):
                self.exploit_table.setItem(row, col, QTableWidgetItem(text))
        
        # Update recommendations
        for rec in result.get("recommendations", []):
            priority_colors = {
                "CRITICAL": "#ff0000",
                "HIGH": "#ff6b6b",
                "MEDIUM": "#ffa500",
                "LOW": "#00ff00"
            }
            
            rec_item = QTreeWidgetItem([
                rec.get("priority", ""),
                rec.get("title", ""),
                rec.get("effort", ""),
                rec.get("impact", "")
            ])
            
            color = QColor(priority_colors.get(rec.get("priority", ""), "#888888"))
            rec_item.setForeground(0, color)
            
            # Add description as child
            if rec.get("description"):
                desc_item = QTreeWidgetItem([
                    "", rec.get("description", ""), "", ""
                ])
                rec_item.addChild(desc_item)
            
            self.rec_tree.addTopLevelItem(rec_item)
        
        # Update MSF script
        if result.get("msf_resource_script"):
            self.msf_script.setText(result["msf_resource_script"])
        
        # Update executive summary
        if result.get("executive_summary"):
            self.exec_summary.setText(result["executive_summary"])
        
        # Enable export
        self.export_btn.setEnabled(True)
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        self.status_label.setText("✅ Analysis complete!")
    
    def on_error(self, error: str):
        """Handle analysis error"""
        QMessageBox.critical(self, "Analysis Error", f"An error occurred: {error}")
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText(f"Error: {error}")
    
    def filter_vulnerabilities(self):
        """Filter vulnerability table"""
        severity_filter = self.vuln_severity_filter.currentText()
        search_text = self.vuln_search.text().lower()
        exploitable_only = self.exploitable_only.isChecked()
        
        for row in range(self.vuln_table.rowCount()):
            show = True
            
            # Severity filter
            if severity_filter != "All":
                severity_item = self.vuln_table.item(row, 2)
                if severity_item and severity_item.text() != severity_filter:
                    show = False
            
            # Exploitable filter
            if exploitable_only:
                exploit_item = self.vuln_table.item(row, 4)
                if exploit_item and exploit_item.text() != "✅":
                    show = False
            
            # Search filter
            if search_text:
                row_text = ""
                for col in range(self.vuln_table.columnCount()):
                    item = self.vuln_table.item(row, col)
                    if item:
                        row_text += item.text().lower() + " "
                if search_text not in row_text:
                    show = False
            
            self.vuln_table.setRowHidden(row, not show)
    
    def show_vulnerability_details(self):
        """Show vulnerability details dialog"""
        row = self.vuln_table.currentRow()
        if row >= 0 and row < len(self.vulnerabilities):
            dialog = VulnerabilityDetailDialog(self.vulnerabilities[row], self)
            dialog.exec()
    
    def show_attack_path_details(self):
        """Show attack path details dialog"""
        item = self.attack_tree.currentItem()
        if item and item.parent() is None:  # Top-level item (path, not step)
            path_id = item.text(0)
            for path in self.attack_paths:
                if path.get("path_id") == path_id:
                    dialog = AttackPathDialog(path, self)
                    dialog.exec()
                    break
    
    def save_msf_script(self):
        """Save Metasploit resource script"""
        script = self.msf_script.toPlainText()
        if not script:
            QMessageBox.warning(self, "Warning", "No resource script to save")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Resource Script", "exploit.rc", "Resource Files (*.rc);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(script)
                QMessageBox.information(self, "Success", f"Resource script saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save: {e}")
    
    def export_results(self):
        """Export analysis results"""
        if not self.current_result:
            QMessageBox.warning(self, "Warning", "No analysis results to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "ai_analysis.json", "JSON Files (*.json);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.current_result, f, indent=2, default=str)
                QMessageBox.information(self, "Success", f"Results exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {e}")
    
    def export_report(self, format_type: str):
        """Export executive report"""
        if not self.current_result:
            QMessageBox.warning(self, "Warning", "No analysis results to export")
            return
        
        extensions = {"html": "HTML Files (*.html)", "pdf": "PDF Files (*.pdf)", "json": "JSON Files (*.json)"}
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", f"executive_report.{format_type}",
            f"{extensions.get(format_type, 'All Files (*)')}"
        )
        
        if file_path:
            try:
                if format_type == "json":
                    with open(file_path, 'w') as f:
                        json.dump(self.current_result, f, indent=2, default=str)
                elif format_type == "html":
                    html = self._generate_html_report()
                    with open(file_path, 'w') as f:
                        f.write(html)
                else:
                    QMessageBox.warning(self, "Info", f"{format_type.upper()} export requires additional libraries")
                    return
                
                QMessageBox.information(self, "Success", f"Report exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {e}")
    
    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        result = self.current_result
        summary = result.get("summary", {})
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>HydraRecon AI Security Analysis Report</title>
    <style>
        body {{
            background: #0a0a1a;
            color: #00ffff;
            font-family: 'Consolas', monospace;
            padding: 20px;
        }}
        h1 {{ color: #ff00ff; border-bottom: 2px solid #00ffff; padding-bottom: 10px; }}
        h2 {{ color: #00ffff; }}
        .summary-card {{
            display: inline-block;
            background: rgba(0,255,255,0.1);
            border: 1px solid #00ffff;
            padding: 15px;
            margin: 10px;
            border-radius: 10px;
            text-align: center;
        }}
        .summary-card .value {{
            font-size: 32px;
            font-weight: bold;
        }}
        .critical {{ color: #ff0000; }}
        .high {{ color: #ff6b6b; }}
        .medium {{ color: #ffa500; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #333;
            padding: 10px;
            text-align: left;
        }}
        th {{ background: #1a1a2e; }}
        pre {{
            background: #1a1a2e;
            padding: 15px;
            border: 1px solid #00ff00;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <h1>🧠 HydraRecon AI Security Analysis Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>📊 Summary</h2>
    <div class="summary-card">
        <div class="value">{summary.get('total_vulnerabilities', 0)}</div>
        <div>Total Vulnerabilities</div>
    </div>
    <div class="summary-card">
        <div class="value critical">{summary.get('critical', 0)}</div>
        <div>Critical</div>
    </div>
    <div class="summary-card">
        <div class="value high">{summary.get('high', 0)}</div>
        <div>High</div>
    </div>
    <div class="summary-card">
        <div class="value">{result.get('risk_score', 0)}</div>
        <div>Risk Score</div>
    </div>
    
    <h2>📋 Executive Summary</h2>
    <pre>{result.get('executive_summary', 'No summary available')}</pre>
    
    <h2>🔓 Vulnerabilities</h2>
    <table>
        <tr>
            <th>CVE</th>
            <th>Name</th>
            <th>Severity</th>
            <th>Exploit Available</th>
        </tr>
"""
        for vuln in result.get("vulnerabilities", []):
            severity_class = vuln.get("severity", "").lower()
            html += f"""        <tr>
            <td>{vuln.get('cve_id', 'N/A')}</td>
            <td>{vuln.get('name', '')}</td>
            <td class="{severity_class}">{vuln.get('severity', '')}</td>
            <td>{'✅' if vuln.get('exploit_available') else '❌'}</td>
        </tr>
"""
        
        html += """    </table>
    
    <h2>💀 Exploit Suggestions</h2>
    <table>
        <tr>
            <th>Name</th>
            <th>Module</th>
            <th>Success Rate</th>
        </tr>
"""
        for exploit in result.get("exploit_suggestions", []):
            html += f"""        <tr>
            <td>{exploit.get('exploit_name', '')}</td>
            <td>{exploit.get('module_path', '')}</td>
            <td>{exploit.get('success_probability', 0)}%</td>
        </tr>
"""
        
        html += """    </table>
    
    <h2>📜 Metasploit Resource Script</h2>
    <pre>"""
        html += result.get("msf_resource_script", "# No script generated")
        html += """</pre>
</body>
</html>"""
        
        return html
