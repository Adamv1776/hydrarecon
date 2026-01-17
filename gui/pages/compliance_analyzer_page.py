"""
HydraRecon - Security Compliance Analyzer GUI
Visual compliance assessment dashboard with gap analysis
"""

import asyncio
from datetime import datetime
from typing import Optional, Dict, List
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QTextEdit, QComboBox,
    QProgressBar, QSplitter, QGroupBox, QLineEdit, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QListWidget, QListWidgetItem, QCheckBox, QDialog, QFormLayout,
    QDialogButtonBox, QStackedWidget
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush
from PyQt6.QtCharts import QChart, QChartView, QPieSeries, QBarSeries, QBarSet, QBarCategoryAxis, QValueAxis


class ComplianceScoreWidget(QFrame):
    """Circular compliance score visualization"""
    
    def __init__(self, title: str = "Overall Score", score: float = 0.0, parent=None):
        super().__init__(parent)
        self.title = title
        self.score = score
        self.setMinimumSize(180, 180)
        self.setMaximumSize(180, 180)
        
    def set_score(self, score: float):
        self.score = score
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Background
        painter.fillRect(self.rect(), QColor("#1a1a2e"))
        
        # Draw outer circle
        center = self.rect().center()
        radius = 70
        
        # Background arc
        pen = QPen(QColor("#2a2a4e"), 12)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(
            center.x() - radius, center.y() - radius,
            radius * 2, radius * 2,
            -45 * 16, -270 * 16
        )
        
        # Score arc
        score_color = self._get_score_color()
        pen = QPen(QColor(score_color), 12)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        
        angle = int(270 * (self.score / 100) * 16)
        painter.drawArc(
            center.x() - radius, center.y() - radius,
            radius * 2, radius * 2,
            -45 * 16, -angle
        )
        
        # Draw score text
        painter.setPen(QPen(QColor(score_color)))
        font = QFont("Arial", 28, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(
            self.rect(),
            Qt.AlignmentFlag.AlignCenter,
            f"{self.score:.0f}%"
        )
        
        # Draw title
        painter.setPen(QPen(QColor("#888")))
        font = QFont("Arial", 10)
        painter.setFont(font)
        title_rect = self.rect()
        title_rect.setTop(title_rect.bottom() - 30)
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignCenter, self.title)
        
    def _get_score_color(self) -> str:
        if self.score >= 80:
            return "#27ae60"
        elif self.score >= 60:
            return "#f1c40f"
        elif self.score >= 40:
            return "#e67e22"
        else:
            return "#e74c3c"


class FrameworkCard(QFrame):
    """Card displaying framework compliance summary"""
    
    clicked = pyqtSignal(str)
    
    def __init__(self, framework_data: Dict, parent=None):
        super().__init__(parent)
        self.framework_data = framework_data
        self.setup_ui()
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
    def setup_ui(self):
        score = self.framework_data.get("score", 0)
        score_color = self._get_score_color(score)
        
        self.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {score_color}20, stop:1 {score_color}10);
                border: 1px solid {score_color}40;
                border-left: 4px solid {score_color};
                border-radius: 12px;
                padding: 15px;
            }}
            QFrame:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {score_color}30, stop:1 {score_color}20);
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header with score
        header = QHBoxLayout()
        
        name = QLabel(self.framework_data.get("framework", "Unknown"))
        name.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        name.setStyleSheet(f"color: #fff; background: transparent;")
        header.addWidget(name)
        
        header.addStretch()
        
        score_label = QLabel(f"{score:.0f}%")
        score_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        score_label.setStyleSheet(f"color: {score_color}; background: transparent;")
        header.addWidget(score_label)
        
        layout.addLayout(header)
        
        # Control counts
        counts_layout = QHBoxLayout()
        
        total = self.framework_data.get("total_controls", 0)
        compliant = self.framework_data.get("compliant", 0)
        partial = self.framework_data.get("partial", 0)
        non_compliant = self.framework_data.get("non_compliant", 0)
        
        counts = [
            (f"✅ {compliant}", "#27ae60"),
            (f"⚠️ {partial}", "#f1c40f"),
            (f"❌ {non_compliant}", "#e74c3c"),
            (f"📋 {total}", "#888"),
        ]
        
        for text, color in counts:
            label = QLabel(text)
            label.setStyleSheet(f"color: {color}; font-size: 11px; background: transparent;")
            counts_layout.addWidget(label)
            
        layout.addLayout(counts_layout)
        
        # Progress bar
        progress = QProgressBar()
        progress.setMaximum(100)
        progress.setValue(int(score))
        progress.setTextVisible(False)
        progress.setMaximumHeight(8)
        progress.setStyleSheet(f"""
            QProgressBar {{
                background: #0a0a15;
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background: {score_color};
                border-radius: 4px;
            }}
        """)
        layout.addWidget(progress)
        
    def _get_score_color(self, score: float) -> str:
        if score >= 80:
            return "#27ae60"
        elif score >= 60:
            return "#f1c40f"
        elif score >= 40:
            return "#e67e22"
        else:
            return "#e74c3c"
            
    def mousePressEvent(self, event):
        self.clicked.emit(self.framework_data.get("framework", ""))
        super().mousePressEvent(event)


class GapWidget(QFrame):
    """Widget displaying a compliance gap"""
    
    def __init__(self, gap_data: Dict, parent=None):
        super().__init__(parent)
        self.gap_data = gap_data
        self.setup_ui()
        
    def setup_ui(self):
        severity = self.gap_data.get("severity", "medium")
        severity_colors = {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f1c40f",
            "low": "#27ae60",
        }
        color = severity_colors.get(severity, "#f1c40f")
        
        self.setStyleSheet(f"""
            QFrame {{
                background: {color}15;
                border-left: 4px solid {color};
                border-radius: 8px;
                padding: 12px;
                margin: 2px 0;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        
        # Header
        header = QHBoxLayout()
        
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
        title = QLabel(f"{severity_icon} {self.gap_data.get('title', 'Unknown')}")
        title.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {color}; background: transparent;")
        title.setWordWrap(True)
        header.addWidget(title, 1)
        
        control_id = QLabel(self.gap_data.get("control_id", ""))
        control_id.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
        header.addWidget(control_id)
        
        layout.addLayout(header)
        
        # Framework
        framework = QLabel(f"📋 {self.gap_data.get('framework', '')}")
        framework.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
        layout.addWidget(framework)
        
        # Remediation (truncated)
        remediation = self.gap_data.get("remediation", "")[:100]
        if len(self.gap_data.get("remediation", "")) > 100:
            remediation += "..."
        rem_label = QLabel(f"💡 {remediation}")
        rem_label.setStyleSheet("color: #aaa; font-size: 10px; background: transparent;")
        rem_label.setWordWrap(True)
        layout.addWidget(rem_label)


class ComplianceAnalyzerPage(QWidget):
    """Main page for Security Compliance Analyzer"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.analyzer = None
        self.setup_ui()
        self.load_analyzer()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Main content
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Scores
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)
        
        # Center - Frameworks
        center_panel = self.create_center_panel()
        splitter.addWidget(center_panel)
        
        # Right - Gaps
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([300, 500, 400])
        layout.addWidget(splitter, 1)
        
    def create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:0.5 #16213e, stop:1 #0f3460);
                border-radius: 15px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title
        title_section = QVBoxLayout()
        
        title = QLabel("📋 Security Compliance Analyzer")
        title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #9b59b6; background: transparent;")
        title_section.addWidget(title)
        
        subtitle = QLabel("Automated Compliance Assessment Against Major Frameworks")
        subtitle.setStyleSheet("color: #888; font-size: 12px; background: transparent;")
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Quick stats
        stats_frame = QFrame()
        stats_frame.setStyleSheet("background: transparent;")
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.setSpacing(30)
        
        self.quick_stats = {}
        quick_stats = [
            ("Total Controls", "0", "#3498db"),
            ("Compliant", "0", "#27ae60"),
            ("Gaps Found", "0", "#e74c3c"),
        ]
        
        for label, value, color in quick_stats:
            stat_widget = QVBoxLayout()
            value_label = QLabel(value)
            value_label.setFont(QFont("Arial", 20, QFont.Weight.Bold))
            value_label.setStyleSheet(f"color: {color}; background: transparent;")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_widget.addWidget(value_label)
            
            name_label = QLabel(label)
            name_label.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_widget.addWidget(name_label)
            
            self.quick_stats[label] = value_label
            stats_layout.addLayout(stat_widget)
            
        layout.addWidget(stats_frame)
        
        # Control buttons
        btn_style = """
            QPushButton {
                background: %s;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 25px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: %s;
            }
        """
        
        self.assess_btn = QPushButton("🔍 Run Assessment")
        self.assess_btn.setStyleSheet(btn_style % ("#27ae60", "#1e8449"))
        self.assess_btn.clicked.connect(self.run_assessment)
        layout.addWidget(self.assess_btn)
        
        self.report_btn = QPushButton("📄 Export Report")
        self.report_btn.setStyleSheet(btn_style % ("#3498db", "#2980b9"))
        self.report_btn.clicked.connect(self.export_report)
        layout.addWidget(self.report_btn)
        
        return frame
        
    def create_left_panel(self) -> QFrame:
        """Create left panel with score overview"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setSpacing(20)
        
        # Overall score
        score_title = QLabel("📊 Compliance Score")
        score_title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        score_title.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(score_title, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.overall_score = ComplianceScoreWidget("Overall")
        layout.addWidget(self.overall_score, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Score breakdown
        breakdown_title = QLabel("📈 Status Breakdown")
        breakdown_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        breakdown_title.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(breakdown_title)
        
        breakdown_frame = QFrame()
        breakdown_frame.setStyleSheet("background: #16213e; border-radius: 10px; padding: 15px;")
        breakdown_layout = QVBoxLayout(breakdown_frame)
        
        self.breakdown_labels = {}
        breakdowns = [
            ("Compliant", "#27ae60", "✅"),
            ("Partial", "#f1c40f", "⚠️"),
            ("Non-Compliant", "#e74c3c", "❌"),
            ("Not Assessed", "#95a5a6", "⚪"),
        ]
        
        for label, color, icon in breakdowns:
            row = QHBoxLayout()
            
            icon_label = QLabel(icon)
            icon_label.setStyleSheet("background: transparent;")
            row.addWidget(icon_label)
            
            name = QLabel(label)
            name.setStyleSheet(f"color: {color}; background: transparent;")
            row.addWidget(name)
            
            row.addStretch()
            
            count = QLabel("0")
            count.setFont(QFont("Arial", 12, QFont.Weight.Bold))
            count.setStyleSheet(f"color: {color}; background: transparent;")
            self.breakdown_labels[label] = count
            row.addWidget(count)
            
            breakdown_layout.addLayout(row)
            
        layout.addWidget(breakdown_frame)
        
        # Gap severity summary
        severity_title = QLabel("🎯 Gap Severity")
        severity_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        severity_title.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(severity_title)
        
        severity_frame = QFrame()
        severity_frame.setStyleSheet("background: #16213e; border-radius: 10px; padding: 15px;")
        severity_layout = QVBoxLayout(severity_frame)
        
        self.severity_labels = {}
        severities = [
            ("Critical", "#e74c3c", "🔴"),
            ("High", "#e67e22", "🟠"),
            ("Medium", "#f1c40f", "🟡"),
            ("Low", "#27ae60", "🟢"),
        ]
        
        for label, color, icon in severities:
            row = QHBoxLayout()
            
            icon_label = QLabel(icon)
            icon_label.setStyleSheet("background: transparent;")
            row.addWidget(icon_label)
            
            name = QLabel(label)
            name.setStyleSheet(f"color: {color}; background: transparent;")
            row.addWidget(name)
            
            row.addStretch()
            
            count = QLabel("0")
            count.setFont(QFont("Arial", 12, QFont.Weight.Bold))
            count.setStyleSheet(f"color: {color}; background: transparent;")
            self.severity_labels[label] = count
            row.addWidget(count)
            
            severity_layout.addLayout(row)
            
        layout.addWidget(severity_frame)
        
        layout.addStretch()
        
        return frame
        
    def create_center_panel(self) -> QFrame:
        """Create center panel with framework cards"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        # Header
        header = QHBoxLayout()
        
        title = QLabel("🏢 Compliance Frameworks")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #fff; background: transparent;")
        header.addWidget(title)
        
        header.addStretch()
        
        # Filter
        self.framework_filter = QComboBox()
        self.framework_filter.addItems(["All Frameworks", "NIST CSF", "CIS Controls", "PCI DSS", "HIPAA", "ISO 27001"])
        self.framework_filter.setStyleSheet("""
            QComboBox {
                background: #16213e;
                color: #fff;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px 15px;
                min-width: 150px;
            }
        """)
        self.framework_filter.currentIndexChanged.connect(self.apply_filter)
        header.addWidget(self.framework_filter)
        
        layout.addLayout(header)
        
        # Framework cards scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        
        self.frameworks_container = QWidget()
        self.frameworks_layout = QVBoxLayout(self.frameworks_container)
        self.frameworks_layout.setSpacing(15)
        self.frameworks_layout.addStretch()
        
        scroll.setWidget(self.frameworks_container)
        layout.addWidget(scroll, 1)
        
        return frame
        
    def create_right_panel(self) -> QFrame:
        """Create right panel with gaps and remediation"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        # Tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background: transparent;
            }
            QTabBar::tab {
                background: #16213e;
                color: #888;
                padding: 10px 20px;
                margin-right: 5px;
                border-radius: 5px 5px 0 0;
            }
            QTabBar::tab:selected {
                background: #0f3460;
                color: #fff;
            }
        """)
        
        # Gaps tab
        gaps_widget = QWidget()
        gaps_layout = QVBoxLayout(gaps_widget)
        
        gaps_header = QHBoxLayout()
        gaps_title = QLabel("⚠️ Compliance Gaps")
        gaps_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        gaps_title.setStyleSheet("color: #fff; background: transparent;")
        gaps_header.addWidget(gaps_title)
        
        gaps_header.addStretch()
        
        self.gap_count = QLabel("0 gaps")
        self.gap_count.setStyleSheet("color: #888; background: transparent;")
        gaps_header.addWidget(self.gap_count)
        
        gaps_layout.addLayout(gaps_header)
        
        gaps_scroll = QScrollArea()
        gaps_scroll.setWidgetResizable(True)
        gaps_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        self.gaps_container = QWidget()
        self.gaps_layout = QVBoxLayout(self.gaps_container)
        self.gaps_layout.setContentsMargins(0, 0, 0, 0)
        self.gaps_layout.setSpacing(10)
        self.gaps_layout.addStretch()
        
        gaps_scroll.setWidget(self.gaps_container)
        gaps_layout.addWidget(gaps_scroll, 1)
        
        tabs.addTab(gaps_widget, "🔍 Gaps")
        
        # Remediation tab
        remediation_widget = QWidget()
        remediation_layout = QVBoxLayout(remediation_widget)
        
        rem_title = QLabel("📋 Remediation Plan")
        rem_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        rem_title.setStyleSheet("color: #fff; background: transparent;")
        remediation_layout.addWidget(rem_title)
        
        self.remediation_table = QTableWidget()
        self.remediation_table.setColumnCount(5)
        self.remediation_table.setHorizontalHeaderLabels(["Priority", "Control", "Framework", "Severity", "Action"])
        self.remediation_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.remediation_table.setStyleSheet("""
            QTableWidget {
                background: #0a0a15;
                color: #fff;
                border: none;
                gridline-color: #333;
            }
            QTableWidget::item {
                padding: 10px;
            }
            QHeaderView::section {
                background: #16213e;
                color: #888;
                padding: 10px;
                border: none;
            }
        """)
        remediation_layout.addWidget(self.remediation_table)
        
        tabs.addTab(remediation_widget, "🛠️ Remediation")
        
        # Controls tab
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        
        ctrl_title = QLabel("📑 Control Details")
        ctrl_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        ctrl_title.setStyleSheet("color: #fff; background: transparent;")
        controls_layout.addWidget(ctrl_title)
        
        self.controls_table = QTableWidget()
        self.controls_table.setColumnCount(4)
        self.controls_table.setHorizontalHeaderLabels(["ID", "Title", "Status", "Score"])
        self.controls_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.controls_table.setStyleSheet("""
            QTableWidget {
                background: #0a0a15;
                color: #fff;
                border: none;
                gridline-color: #333;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background: #16213e;
                color: #888;
                padding: 8px;
                border: none;
            }
        """)
        controls_layout.addWidget(self.controls_table)
        
        tabs.addTab(controls_widget, "📑 Controls")
        
        layout.addWidget(tabs)
        
        return frame
        
    def load_analyzer(self):
        """Load the compliance analyzer"""
        from core.compliance_analyzer import get_compliance_analyzer
        self.analyzer = get_compliance_analyzer()
        self.refresh_display()
        
    def refresh_display(self):
        """Refresh all displays"""
        if not self.analyzer:
            return
            
        stats = self.analyzer.stats
        
        # Update quick stats
        self.quick_stats["Total Controls"].setText(str(stats["total_controls"]))
        self.quick_stats["Compliant"].setText(str(stats["compliant_controls"]))
        self.quick_stats["Gaps Found"].setText(str(len(self.analyzer.gaps)))
        
        # Update overall score
        self.overall_score.set_score(stats["overall_score"])
        
        # Update breakdown
        self.breakdown_labels["Compliant"].setText(str(stats["compliant_controls"]))
        self.breakdown_labels["Partial"].setText(str(stats["partial_controls"]))
        self.breakdown_labels["Non-Compliant"].setText(str(stats["non_compliant_controls"]))
        not_assessed = stats["total_controls"] - stats["assessed_controls"]
        self.breakdown_labels["Not Assessed"].setText(str(not_assessed))
        
        # Update severity
        self.severity_labels["Critical"].setText(str(stats["critical_gaps"]))
        self.severity_labels["High"].setText(str(stats["high_gaps"]))
        self.severity_labels["Medium"].setText(str(stats["medium_gaps"]))
        self.severity_labels["Low"].setText(str(stats["low_gaps"]))
        
        # Update framework cards
        self.update_framework_cards()
        
        # Update gaps
        self.update_gaps()
        
        # Update remediation plan
        self.update_remediation_plan()
        
        # Update controls table
        self.update_controls_table()
        
    def update_framework_cards(self):
        """Update framework cards display"""
        # Clear existing
        while self.frameworks_layout.count() > 1:
            item = self.frameworks_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        # Add framework cards
        summaries = self.analyzer.get_all_frameworks_summary()
        for summary in summaries:
            card = FrameworkCard(summary)
            card.clicked.connect(self.on_framework_clicked)
            self.frameworks_layout.insertWidget(self.frameworks_layout.count() - 1, card)
            
    def update_gaps(self):
        """Update gaps display"""
        # Clear existing
        while self.gaps_layout.count() > 1:
            item = self.gaps_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        # Add gaps (sorted by severity)
        severity_order = ["critical", "high", "medium", "low"]
        sorted_gaps = sorted(
            self.analyzer.gaps,
            key=lambda g: severity_order.index(g.severity.value) if g.severity.value in severity_order else 99
        )
        
        for gap in sorted_gaps[:20]:
            gap_data = {
                "title": gap.title,
                "control_id": gap.control_id,
                "framework": gap.framework.value,
                "severity": gap.severity.value,
                "remediation": gap.remediation,
            }
            widget = GapWidget(gap_data)
            self.gaps_layout.insertWidget(self.gaps_layout.count() - 1, widget)
            
        self.gap_count.setText(f"{len(self.analyzer.gaps)} gaps")
        
    def update_remediation_plan(self):
        """Update remediation plan table"""
        plan = self.analyzer.get_remediation_plan()
        
        self.remediation_table.setRowCount(len(plan))
        
        for i, item in enumerate(plan):
            priority_item = QTableWidgetItem(f"#{item['priority']}")
            control_item = QTableWidgetItem(item['control_id'])
            framework_item = QTableWidgetItem(item['framework'])
            
            severity = item['severity']
            severity_colors = {"critical": "#e74c3c", "high": "#e67e22", "medium": "#f1c40f", "low": "#27ae60"}
            severity_item = QTableWidgetItem(severity.upper())
            severity_item.setForeground(QColor(severity_colors.get(severity, "#888")))
            
            action_item = QTableWidgetItem(item['remediation'][:50] + "...")
            
            self.remediation_table.setItem(i, 0, priority_item)
            self.remediation_table.setItem(i, 1, control_item)
            self.remediation_table.setItem(i, 2, framework_item)
            self.remediation_table.setItem(i, 3, severity_item)
            self.remediation_table.setItem(i, 4, action_item)
            
    def update_controls_table(self):
        """Update controls table"""
        controls = list(self.analyzer.controls.values())[:50]
        
        self.controls_table.setRowCount(len(controls))
        
        status_colors = {
            "compliant": "#27ae60",
            "partial": "#f1c40f",
            "non_compliant": "#e74c3c",
            "not_assessed": "#95a5a6",
        }
        
        for i, control in enumerate(controls):
            id_item = QTableWidgetItem(control.id)
            title_item = QTableWidgetItem(control.title[:50])
            
            status_item = QTableWidgetItem(control.status.value.replace("_", " ").title())
            status_item.setForeground(QColor(status_colors.get(control.status.value, "#888")))
            
            score_item = QTableWidgetItem(f"{control.score:.0f}%")
            
            self.controls_table.setItem(i, 0, id_item)
            self.controls_table.setItem(i, 1, title_item)
            self.controls_table.setItem(i, 2, status_item)
            self.controls_table.setItem(i, 3, score_item)
            
    def on_framework_clicked(self, framework: str):
        """Handle framework card click"""
        # Filter controls table by framework
        pass
        
    def apply_filter(self):
        """Apply framework filter"""
        pass
        
    def run_assessment(self):
        """Run compliance assessment"""
        self.assess_btn.setEnabled(False)
        self.assess_btn.setText("🔍 Running...")
        
        QTimer.singleShot(2000, self.assessment_complete)
        
    def assessment_complete(self):
        """Handle assessment completion"""
        self.assess_btn.setEnabled(True)
        self.assess_btn.setText("🔍 Run Assessment")
        self.refresh_display()
        
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.information(
            self, "Assessment Complete",
            f"Compliance assessment completed!\n\n"
            f"Overall Score: {self.analyzer.stats['overall_score']:.0f}%\n"
            f"Gaps Found: {len(self.analyzer.gaps)}"
        )
        
    def export_report(self):
        """Export compliance report"""
        from PyQt6.QtWidgets import QFileDialog, QMessageBox
        import json
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Report", "compliance_report.json", "JSON Files (*.json)"
        )
        
        if filepath:
            report = {
                "generated_at": datetime.now().isoformat(),
                "overall_score": self.analyzer.stats["overall_score"],
                "statistics": self.analyzer.stats,
                "frameworks": self.analyzer.get_all_frameworks_summary(),
                "gaps": [
                    {
                        "id": g.id,
                        "control_id": g.control_id,
                        "framework": g.framework.value,
                        "title": g.title,
                        "severity": g.severity.value,
                        "remediation": g.remediation,
                    }
                    for g in self.analyzer.gaps
                ],
                "remediation_plan": self.analyzer.get_remediation_plan(),
            }
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
                
            QMessageBox.information(
                self, "Export Complete",
                f"Report exported to {filepath}"
            )
