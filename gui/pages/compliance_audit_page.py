#!/usr/bin/env python3
"""
HydraRecon Compliance Audit Page
GUI for regulatory compliance assessment and reporting.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QComboBox,
    QTextEdit, QTableWidget, QTableWidgetItem, QProgressBar,
    QTabWidget, QGroupBox, QCheckBox, QSpinBox, QSplitter,
    QHeaderView, QMessageBox, QListWidget, QListWidgetItem,
    QTreeWidget, QTreeWidgetItem, QFileDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QBrush

import asyncio
from datetime import datetime
from typing import Optional

try:
    from ...core.compliance_audit import (
        ComplianceAuditEngine, ComplianceFramework, ControlStatus,
        FindingSeverity
    )
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False
    ComplianceFramework = None
    ControlStatus = None
    FindingSeverity = None


class AssessmentWorker(QThread):
    """Worker thread for compliance assessment"""
    progress = pyqtSignal(str, float)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, engine, framework, target, organization, scope):
        super().__init__()
        self.engine = engine
        self.framework = framework
        self.target = target
        self.organization = organization
        self.scope = scope
    
    def run(self):
        """Run the assessment"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            def callback(msg, progress):
                self.progress.emit(msg, progress)
            
            result = loop.run_until_complete(
                self.engine.run_assessment(
                    self.framework, self.target, self.organization, 
                    self.scope, callback
                )
            )
            
            loop.close()
            self.finished.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class ComplianceAuditPage(QWidget):
    """Compliance Audit Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = ComplianceAuditEngine() if COMPLIANCE_AVAILABLE else None
        self.assessment_worker: Optional[AssessmentWorker] = None
        self.current_report = None
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the UI"""
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
                border: 1px solid #21262d;
                border-radius: 8px;
                background-color: #0d1117;
            }
            QTabBar::tab {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px 20px;
                border: 1px solid #21262d;
                border-bottom: none;
                border-radius: 6px 6px 0 0;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #e6e6e6;
            }
        """)
        
        # Tab 1: Assessment
        self.tabs.addTab(self._create_assessment_tab(), "📋 Assessment")
        
        # Tab 2: Controls
        self.tabs.addTab(self._create_controls_tab(), "🎛️ Controls")
        
        # Tab 3: Findings
        self.tabs.addTab(self._create_findings_tab(), "⚠️ Findings")
        
        # Tab 4: Gap Analysis
        self.tabs.addTab(self._create_gap_tab(), "📊 Gap Analysis")
        
        # Tab 5: Reports
        self.tabs.addTab(self._create_reports_tab(), "📄 Reports")
        
        layout.addWidget(self.tabs, stretch=1)
    
    def _create_header(self) -> QWidget:
        """Create header section"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #238636, stop:1 #3fb950);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("📋 Compliance Audit")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: 700;
            color: white;
        """)
        
        subtitle = QLabel("Regulatory compliance assessment for NIST, PCI-DSS, ISO 27001, and more")
        subtitle.setStyleSheet("font-size: 14px; color: rgba(255,255,255,0.8);")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout, stretch=1)
        
        return header
    
    def _create_assessment_tab(self) -> QWidget:
        """Create assessment tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Configuration
        config_group = QGroupBox("Assessment Configuration")
        config_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        config_layout = QGridLayout(config_group)
        
        # Framework selection
        config_layout.addWidget(QLabel("Framework:"), 0, 0)
        self.framework_combo = QComboBox()
        self.framework_combo.addItems([
            "NIST Cybersecurity Framework",
            "PCI DSS v4.0",
            "CIS Critical Security Controls",
            "ISO 27001",
            "HIPAA",
            "SOC 2"
        ])
        self.framework_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        self.framework_combo.currentIndexChanged.connect(self._update_controls_view)
        config_layout.addWidget(self.framework_combo, 0, 1)
        
        # Organization
        config_layout.addWidget(QLabel("Organization:"), 1, 0)
        self.org_input = QLineEdit()
        self.org_input.setPlaceholderText("Enter organization name...")
        self.org_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        config_layout.addWidget(self.org_input, 1, 1)
        
        # Scope
        config_layout.addWidget(QLabel("Scope:"), 2, 0)
        self.scope_input = QLineEdit()
        self.scope_input.setPlaceholderText("Enter assessment scope...")
        self.scope_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        config_layout.addWidget(self.scope_input, 2, 1)
        
        # Target (for automated scanning)
        config_layout.addWidget(QLabel("Target (optional):"), 3, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP or hostname for automated scanning...")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        config_layout.addWidget(self.target_input, 3, 1)
        
        layout.addWidget(config_group)
        
        # Run assessment
        run_layout = QHBoxLayout()
        
        self.run_btn = QPushButton("▶️ Run Assessment")
        self.run_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:disabled { background-color: #21262d; color: #8b949e; }
        """)
        self.run_btn.clicked.connect(self._start_assessment)
        
        self.assessment_progress = QProgressBar()
        self.assessment_progress.setStyleSheet("""
            QProgressBar {
                background-color: #21262d;
                border: none;
                border-radius: 4px;
                height: 10px;
            }
            QProgressBar::chunk {
                background-color: #238636;
                border-radius: 4px;
            }
        """)
        
        self.assessment_status = QLabel("Ready")
        self.assessment_status.setStyleSheet("color: #8b949e;")
        
        run_layout.addWidget(self.run_btn)
        run_layout.addWidget(self.assessment_progress, stretch=1)
        run_layout.addWidget(self.assessment_status)
        
        layout.addLayout(run_layout)
        
        # Results summary
        results_group = QGroupBox("Assessment Results")
        results_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        results_layout = QVBoxLayout(results_group)
        
        # Score cards
        cards_layout = QHBoxLayout()
        
        # Overall score
        score_frame = QFrame()
        score_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 2px solid #238636;
                border-radius: 12px;
            }
        """)
        score_frame_layout = QVBoxLayout(score_frame)
        score_frame_layout.setContentsMargins(20, 20, 20, 20)
        
        self.score_label = QLabel("--")
        self.score_label.setStyleSheet("font-size: 48px; font-weight: bold; color: #238636;")
        self.score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        score_text = QLabel("Overall Score")
        score_text.setStyleSheet("color: #8b949e;")
        score_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        score_frame_layout.addWidget(self.score_label)
        score_frame_layout.addWidget(score_text)
        
        cards_layout.addWidget(score_frame)
        
        # Control stats
        self.control_stats = {}
        stats = [
            ("passed", "Passed", "#3fb950"),
            ("partial", "Partial", "#d29922"),
            ("failed", "Failed", "#f85149"),
            ("total", "Total", "#8b949e")
        ]
        
        for key, label, color in stats:
            stat_frame = QFrame()
            stat_frame.setStyleSheet(f"""
                QFrame {{
                    background-color: #161b22;
                    border: 1px solid #21262d;
                    border-radius: 8px;
                }}
            """)
            
            stat_layout = QVBoxLayout(stat_frame)
            stat_layout.setContentsMargins(15, 15, 15, 15)
            
            value_label = QLabel("0")
            value_label.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {color};")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name_label = QLabel(label)
            name_label.setStyleSheet("color: #8b949e;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            stat_layout.addWidget(value_label)
            stat_layout.addWidget(name_label)
            
            self.control_stats[key] = value_label
            cards_layout.addWidget(stat_frame)
        
        results_layout.addLayout(cards_layout)
        
        # Executive summary
        results_layout.addWidget(QLabel("Executive Summary:"))
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setMaximumHeight(150)
        self.summary_text.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                padding: 12px;
            }
        """)
        results_layout.addWidget(self.summary_text)
        
        layout.addWidget(results_group, stretch=1)
        
        return widget
    
    def _create_controls_tab(self) -> QWidget:
        """Create controls tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Controls tree
        controls_group = QGroupBox("Framework Controls")
        controls_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        controls_layout = QVBoxLayout(controls_group)
        
        self.controls_tree = QTreeWidget()
        self.controls_tree.setHeaderLabels([
            "Control ID", "Title", "Category", "Status", "Score"
        ])
        self.controls_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTreeWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        self.controls_tree.itemClicked.connect(self._on_control_selected)
        
        controls_layout.addWidget(self.controls_tree)
        
        layout.addWidget(controls_group, stretch=1)
        
        # Control details
        details_group = QGroupBox("Control Details")
        details_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        details_layout = QVBoxLayout(details_group)
        
        self.control_details = QTextEdit()
        self.control_details.setReadOnly(True)
        self.control_details.setMaximumHeight(200)
        self.control_details.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                padding: 12px;
            }
        """)
        
        details_layout.addWidget(self.control_details)
        
        layout.addWidget(details_group)
        
        # Load initial controls
        self._update_controls_view()
        
        return widget
    
    def _create_findings_tab(self) -> QWidget:
        """Create findings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Findings summary
        summary_layout = QHBoxLayout()
        
        severities = [
            ("critical", "Critical", "#f85149"),
            ("high", "High", "#ffa657"),
            ("medium", "Medium", "#d29922"),
            ("low", "Low", "#3fb950")
        ]
        
        self.finding_counts = {}
        for key, label, color in severities:
            frame = QFrame()
            frame.setStyleSheet(f"""
                QFrame {{
                    background-color: #161b22;
                    border: 2px solid {color};
                    border-radius: 8px;
                }}
            """)
            
            frame_layout = QVBoxLayout(frame)
            frame_layout.setContentsMargins(15, 15, 15, 15)
            
            count = QLabel("0")
            count.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {color};")
            count.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name = QLabel(label)
            name.setStyleSheet("color: #8b949e;")
            name.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            frame_layout.addWidget(count)
            frame_layout.addWidget(name)
            
            self.finding_counts[key] = count
            summary_layout.addWidget(frame)
        
        layout.addLayout(summary_layout)
        
        # Findings table
        findings_group = QGroupBox("Findings List")
        findings_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        findings_layout = QVBoxLayout(findings_group)
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(5)
        self.findings_table.setHorizontalHeaderLabels([
            "Finding ID", "Control", "Severity", "Title", "Status"
        ])
        self.findings_table.horizontalHeader().setStretchLastSection(True)
        self.findings_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        
        findings_layout.addWidget(self.findings_table)
        
        layout.addWidget(findings_group, stretch=1)
        
        return widget
    
    def _create_gap_tab(self) -> QWidget:
        """Create gap analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Gap overview
        overview_group = QGroupBox("Gap Analysis Overview")
        overview_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        overview_layout = QVBoxLayout(overview_group)
        
        self.gap_summary = QLabel("Run an assessment to view gap analysis")
        self.gap_summary.setStyleSheet("color: #8b949e;")
        overview_layout.addWidget(self.gap_summary)
        
        layout.addWidget(overview_group)
        
        # Gap details
        details_group = QGroupBox("Identified Gaps")
        details_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        details_layout = QVBoxLayout(details_group)
        
        self.gaps_tree = QTreeWidget()
        self.gaps_tree.setHeaderLabels([
            "Control", "Title", "Current Score", "Gap", "Priority"
        ])
        self.gaps_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTreeWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        
        details_layout.addWidget(self.gaps_tree)
        
        layout.addWidget(details_group, stretch=1)
        
        return widget
    
    def _create_reports_tab(self) -> QWidget:
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Export options
        export_group = QGroupBox("Export Report")
        export_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        export_layout = QHBoxLayout(export_group)
        
        export_json_btn = QPushButton("📄 Export JSON")
        export_json_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        export_json_btn.clicked.connect(lambda: self._export_report("json"))
        
        export_pdf_btn = QPushButton("📑 Export PDF")
        export_pdf_btn.setStyleSheet("""
            QPushButton {
                background-color: #8957e5;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        export_pdf_btn.clicked.connect(lambda: self._export_report("pdf"))
        
        export_layout.addWidget(export_json_btn)
        export_layout.addWidget(export_pdf_btn)
        export_layout.addStretch()
        
        layout.addWidget(export_group)
        
        # Recommendations
        rec_group = QGroupBox("Recommendations")
        rec_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        rec_layout = QVBoxLayout(rec_group)
        
        self.recommendations_list = QListWidget()
        self.recommendations_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
            }
        """)
        
        rec_layout.addWidget(self.recommendations_list)
        
        layout.addWidget(rec_group, stretch=1)
        
        return widget
    
    def _get_framework_enum(self) -> ComplianceFramework:
        """Get framework enum from combo box"""
        framework_map = {
            "NIST Cybersecurity Framework": ComplianceFramework.NIST_CSF,
            "PCI DSS v4.0": ComplianceFramework.PCI_DSS,
            "CIS Critical Security Controls": ComplianceFramework.CIS_CONTROLS,
            "ISO 27001": ComplianceFramework.ISO_27001,
            "HIPAA": ComplianceFramework.HIPAA,
            "SOC 2": ComplianceFramework.SOC2
        }
        return framework_map.get(self.framework_combo.currentText(), 
                                ComplianceFramework.NIST_CSF)
    
    def _update_controls_view(self):
        """Update controls tree with framework controls"""
        if not self.engine:
            return
        
        self.controls_tree.clear()
        
        framework = self._get_framework_enum()
        controls = self.engine.get_framework_controls(framework)
        
        # Group by category
        categories: Dict[str, list] = {}
        for control in controls:
            if control.category not in categories:
                categories[control.category] = []
            categories[control.category].append(control)
        
        for category, ctrls in categories.items():
            category_item = QTreeWidgetItem([category, "", "", "", ""])
            category_item.setForeground(0, QBrush(QColor("#58a6ff")))
            
            for ctrl in ctrls:
                ctrl_item = QTreeWidgetItem([
                    ctrl.control_id,
                    ctrl.title,
                    ctrl.category,
                    "Not Assessed",
                    "--"
                ])
                category_item.addChild(ctrl_item)
            
            self.controls_tree.addTopLevelItem(category_item)
            category_item.setExpanded(True)
    
    def _on_control_selected(self, item: QTreeWidgetItem, column: int):
        """Handle control selection"""
        if item.childCount() > 0:  # Category item
            return
        
        control_id = item.text(0)
        
        framework = self._get_framework_enum()
        controls = self.engine.get_framework_controls(framework) if self.engine else []
        
        for control in controls:
            if control.control_id == control_id:
                self.control_details.setHtml(f"""
                    <h3>{control.control_id}: {control.title}</h3>
                    <p><b>Category:</b> {control.category}</p>
                    <p><b>Description:</b> {control.description}</p>
                    <p><b>Requirements:</b></p>
                    <ul>
                        {"".join(f"<li>{req}</li>" for req in control.requirements)}
                    </ul>
                """)
                break
    
    def _start_assessment(self):
        """Start compliance assessment"""
        if not self.engine:
            return
        
        framework = self._get_framework_enum()
        target = self.target_input.text().strip() or None
        organization = self.org_input.text().strip()
        scope = self.scope_input.text().strip()
        
        self.run_btn.setEnabled(False)
        self.assessment_progress.setValue(0)
        
        self.assessment_worker = AssessmentWorker(
            self.engine, framework, target, organization, scope
        )
        self.assessment_worker.progress.connect(self._on_assessment_progress)
        self.assessment_worker.finished.connect(self._on_assessment_finished)
        self.assessment_worker.error.connect(self._on_assessment_error)
        self.assessment_worker.start()
    
    def _on_assessment_progress(self, message: str, progress: float):
        """Handle assessment progress"""
        self.assessment_status.setText(message)
        self.assessment_progress.setValue(int(progress))
    
    def _on_assessment_finished(self, result):
        """Handle assessment completion"""
        self.run_btn.setEnabled(True)
        self.assessment_progress.setValue(100)
        self.assessment_status.setText("Complete")
        self.current_report = result
        
        # Update score
        score_color = "#f85149" if result.overall_score < 50 else \
                      "#d29922" if result.overall_score < 75 else "#3fb950"
        self.score_label.setText(f"{result.overall_score:.0f}%")
        self.score_label.setStyleSheet(f"font-size: 48px; font-weight: bold; color: {score_color};")
        
        # Update stats
        self.control_stats["passed"].setText(str(result.controls_passed))
        self.control_stats["partial"].setText(str(result.controls_partial))
        self.control_stats["failed"].setText(str(result.controls_failed))
        self.control_stats["total"].setText(str(result.controls_assessed))
        
        # Update summary
        self.summary_text.setPlainText(result.executive_summary)
        
        # Update controls tab
        self._update_controls_with_results(result)
        
        # Update findings tab
        self._update_findings(result)
        
        # Update gap analysis
        self._update_gap_analysis(result)
        
        # Update recommendations
        self._update_recommendations(result)
    
    def _on_assessment_error(self, error: str):
        """Handle assessment error"""
        self.run_btn.setEnabled(True)
        self.assessment_status.setText(f"Error: {error}")
        QMessageBox.critical(self, "Assessment Error", error)
    
    def _update_controls_with_results(self, result):
        """Update controls tree with assessment results"""
        for i in range(self.controls_tree.topLevelItemCount()):
            category_item = self.controls_tree.topLevelItem(i)
            for j in range(category_item.childCount()):
                ctrl_item = category_item.child(j)
                control_id = ctrl_item.text(0)
                
                for assessment in result.assessments:
                    if assessment.control.control_id == control_id:
                        status = assessment.status.value.replace("_", " ").title()
                        ctrl_item.setText(3, status)
                        ctrl_item.setText(4, f"{assessment.score:.0f}%")
                        
                        # Color code
                        if assessment.status == ControlStatus.FULLY_IMPLEMENTED:
                            color = QColor("#3fb950")
                        elif assessment.status == ControlStatus.PARTIALLY_IMPLEMENTED:
                            color = QColor("#d29922")
                        else:
                            color = QColor("#f85149")
                        
                        ctrl_item.setForeground(3, QBrush(color))
                        ctrl_item.setForeground(4, QBrush(color))
                        break
    
    def _update_findings(self, result):
        """Update findings display"""
        # Update counts
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in result.findings:
            if finding.severity == FindingSeverity.CRITICAL:
                counts["critical"] += 1
            elif finding.severity == FindingSeverity.HIGH:
                counts["high"] += 1
            elif finding.severity == FindingSeverity.MEDIUM:
                counts["medium"] += 1
            else:
                counts["low"] += 1
        
        for key, count in counts.items():
            self.finding_counts[key].setText(str(count))
        
        # Update table
        self.findings_table.setRowCount(len(result.findings))
        for i, finding in enumerate(result.findings):
            self.findings_table.setItem(i, 0, QTableWidgetItem(finding.finding_id))
            self.findings_table.setItem(i, 1, QTableWidgetItem(finding.control_id))
            self.findings_table.setItem(i, 2, QTableWidgetItem(finding.severity.value.upper()))
            self.findings_table.setItem(i, 3, QTableWidgetItem(finding.title))
            self.findings_table.setItem(i, 4, QTableWidgetItem(finding.status))
            
            # Color code severity
            severity_colors = {
                FindingSeverity.CRITICAL: "#f85149",
                FindingSeverity.HIGH: "#ffa657",
                FindingSeverity.MEDIUM: "#d29922",
                FindingSeverity.LOW: "#3fb950"
            }
            color = severity_colors.get(finding.severity, "#8b949e")
            self.findings_table.item(i, 2).setForeground(QBrush(QColor(color)))
    
    def _update_gap_analysis(self, result):
        """Update gap analysis display"""
        if not self.engine:
            return
        
        gap_analysis = self.engine.get_gap_analysis(result)
        
        self.gap_summary.setText(f"Total Gaps Identified: {gap_analysis['total_gaps']}")
        
        self.gaps_tree.clear()
        for gap in gap_analysis['gaps']:
            priority = "HIGH" if gap['current_score'] < 30 else \
                       "MEDIUM" if gap['current_score'] < 60 else "LOW"
            
            item = QTreeWidgetItem([
                gap['control_id'],
                gap['control_title'],
                f"{gap['current_score']:.0f}%",
                f"{100 - gap['current_score']:.0f}%",
                priority
            ])
            
            # Color code priority
            priority_colors = {"HIGH": "#f85149", "MEDIUM": "#d29922", "LOW": "#3fb950"}
            item.setForeground(4, QBrush(QColor(priority_colors[priority])))
            
            self.gaps_tree.addTopLevelItem(item)
    
    def _update_recommendations(self, result):
        """Update recommendations list"""
        self.recommendations_list.clear()
        for rec in result.recommendations:
            item = QListWidgetItem(f"💡 {rec}")
            self.recommendations_list.addItem(item)
    
    def _export_report(self, format: str):
        """Export compliance report"""
        if not self.current_report or not self.engine:
            QMessageBox.warning(self, "No Report", "Run an assessment first")
            return
        
        if format == "json":
            filepath, _ = QFileDialog.getSaveFileName(
                self, "Save Report", f"compliance_report_{self.current_report.report_id}.json",
                "JSON Files (*.json)"
            )
            
            if filepath:
                report_data = self.engine.export_report(self.current_report.report_id, "json")
                with open(filepath, 'w') as f:
                    f.write(report_data)
                QMessageBox.information(self, "Exported", f"Report saved to {filepath}")
        else:
            QMessageBox.information(self, "Coming Soon", "PDF export coming soon!")
