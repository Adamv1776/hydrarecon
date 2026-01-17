"""
HydraRecon - Executive Security Dashboard GUI
C-Suite ready security metrics visualization
"""

from datetime import datetime
from typing import Optional, Dict, List
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QProgressBar, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush


class RiskGaugeWidget(QFrame):
    """Large gauge widget for risk score"""
    
    def __init__(self, title: str = "Risk Score", parent=None):
        super().__init__(parent)
        self.title = title
        self.score = 0.0
        self.setMinimumSize(200, 200)
        
    def set_score(self, score: float):
        self.score = score
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Background
        painter.fillRect(self.rect(), QColor("#1a1a2e"))
        
        center = self.rect().center()
        radius = min(self.width(), self.height()) // 2 - 20
        
        # Draw background arc
        pen = QPen(QColor("#2a2a4e"), 15)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(
            center.x() - radius, center.y() - radius,
            radius * 2, radius * 2,
            -30 * 16, -300 * 16
        )
        
        # Score color
        if self.score >= 80:
            color = "#27ae60"
        elif self.score >= 60:
            color = "#f1c40f"
        elif self.score >= 40:
            color = "#e67e22"
        else:
            color = "#e74c3c"
            
        # Draw score arc
        pen = QPen(QColor(color), 15)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        
        angle = int(300 * (self.score / 100) * 16)
        painter.drawArc(
            center.x() - radius, center.y() - radius,
            radius * 2, radius * 2,
            -30 * 16, -angle
        )
        
        # Draw score text
        painter.setPen(QPen(QColor(color)))
        font = QFont("Arial", 32, QFont.Weight.Bold)
        painter.setFont(font)
        
        score_rect = self.rect()
        score_rect.setTop(score_rect.center().y() - 20)
        painter.drawText(score_rect, Qt.AlignmentFlag.AlignHCenter, f"{self.score:.0f}")
        
        # Draw title
        painter.setPen(QPen(QColor("#888")))
        font = QFont("Arial", 11)
        painter.setFont(font)
        title_rect = self.rect()
        title_rect.setTop(title_rect.center().y() + 30)
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignHCenter, self.title)


class MetricCard(QFrame):
    """Executive metric card"""
    
    def __init__(self, metric_data: Dict, parent=None):
        super().__init__(parent)
        self.metric_data = metric_data
        self.setup_ui()
        
    def setup_ui(self):
        change = self.metric_data.get("change", 0)
        color = self.metric_data.get("color", "#3498db")
        
        # Positive change is good for most metrics
        change_color = "#27ae60" if change < 0 else "#e74c3c"
        if "ROI" in self.metric_data.get("name", "") or "Score" in self.metric_data.get("name", ""):
            change_color = "#27ae60" if change > 0 else "#e74c3c"
            
        self.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {color}20, stop:1 {color}10);
                border: 1px solid {color}40;
                border-radius: 15px;
                padding: 20px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Icon and value
        header = QHBoxLayout()
        
        icon = QLabel(self.metric_data.get("icon", "📊"))
        icon.setFont(QFont("Arial", 24))
        icon.setStyleSheet("background: transparent;")
        header.addWidget(icon)
        
        header.addStretch()
        
        value = QLabel(self.metric_data.get("value", "0"))
        value.setFont(QFont("Arial", 28, QFont.Weight.Bold))
        value.setStyleSheet(f"color: {color}; background: transparent;")
        header.addWidget(value)
        
        layout.addLayout(header)
        
        # Name
        name = QLabel(self.metric_data.get("name", "Metric"))
        name.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        name.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(name)
        
        # Change
        change_str = f"+{change:.1f}%" if change > 0 else f"{change:.1f}%"
        change_label = QLabel(f"{change_str} {self.metric_data.get('change_period', '')}")
        change_label.setStyleSheet(f"color: {change_color}; font-size: 11px; background: transparent;")
        layout.addWidget(change_label)


class KPIRow(QFrame):
    """KPI row widget"""
    
    def __init__(self, kpi_data: Dict, parent=None):
        super().__init__(parent)
        self.kpi_data = kpi_data
        self.setup_ui()
        
    def setup_ui(self):
        risk = self.kpi_data.get("risk", "medium")
        risk_colors = {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f1c40f",
            "low": "#27ae60",
            "minimal": "#3498db",
        }
        color = risk_colors.get(risk, "#f1c40f")
        
        self.setStyleSheet(f"""
            QFrame {{
                background: {color}10;
                border-left: 3px solid {color};
                border-radius: 8px;
                padding: 12px;
                margin: 3px 0;
            }}
        """)
        
        layout = QHBoxLayout(self)
        
        # Name and description
        info = QVBoxLayout()
        
        name = QLabel(self.kpi_data.get("name", "KPI"))
        name.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        name.setStyleSheet("color: #fff; background: transparent;")
        info.addWidget(name)
        
        desc = QLabel(self.kpi_data.get("description", "")[:60])
        desc.setStyleSheet("color: #666; font-size: 10px; background: transparent;")
        info.addWidget(desc)
        
        layout.addLayout(info, 2)
        
        # Current value
        current = QLabel(f"{self.kpi_data.get('current', 0)} {self.kpi_data.get('unit', '')}")
        current.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        current.setStyleSheet(f"color: {color}; background: transparent;")
        current.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(current, 1)
        
        # Target
        target = QLabel(f"Target: {self.kpi_data.get('target', 0)}")
        target.setStyleSheet("color: #888; font-size: 10px; background: transparent;")
        target.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(target, 1)
        
        # Trend
        trend = self.kpi_data.get("trend", "stable")
        trend_icon = {"improving": "📈", "stable": "➡️", "declining": "📉"}.get(trend, "➡️")
        trend_pct = self.kpi_data.get("trend_percent", 0)
        trend_color = "#27ae60" if trend == "improving" else ("#e74c3c" if trend == "declining" else "#888")
        
        trend_label = QLabel(f"{trend_icon} {trend_pct:+.1f}%")
        trend_label.setStyleSheet(f"color: {trend_color}; background: transparent;")
        trend_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(trend_label, 1)


class ExecutiveDashboardPage(QWidget):
    """Executive Security Dashboard page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.dashboard = None
        self.setup_ui()
        self.load_dashboard()
        
        # Auto-refresh
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_display)
        self.refresh_timer.start(60000)  # Refresh every minute
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Main content
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Top - Key metrics
        top_section = self.create_metrics_section()
        splitter.addWidget(top_section)
        
        # Bottom - Details
        bottom_section = self.create_details_section()
        splitter.addWidget(bottom_section)
        
        splitter.setSizes([350, 500])
        layout.addWidget(splitter, 1)
        
    def create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0f3460, stop:0.5 #16213e, stop:1 #1a1a2e);
                border-radius: 15px;
                padding: 25px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title
        title_section = QVBoxLayout()
        
        title = QLabel("📊 Executive Security Dashboard")
        title.setFont(QFont("Arial", 26, QFont.Weight.Bold))
        title.setStyleSheet("color: #3498db; background: transparent;")
        title_section.addWidget(title)
        
        subtitle = QLabel("Real-time Security Posture for C-Suite Decision Making")
        subtitle.setStyleSheet("color: #888; font-size: 13px; background: transparent;")
        title_section.addWidget(subtitle)
        
        timestamp = QLabel(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        timestamp.setStyleSheet("color: #666; font-size: 11px; background: transparent;")
        title_section.addWidget(timestamp)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Risk gauge
        self.risk_gauge = RiskGaugeWidget("Cyber Risk Score")
        layout.addWidget(self.risk_gauge)
        
        # Buttons
        btn_section = QVBoxLayout()
        
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
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setStyleSheet(btn_style % ("#3498db", "#2980b9"))
        refresh_btn.clicked.connect(self.refresh_display)
        btn_section.addWidget(refresh_btn)
        
        report_btn = QPushButton("📄 Board Report")
        report_btn.setStyleSheet(btn_style % ("#27ae60", "#1e8449"))
        report_btn.clicked.connect(self.export_board_report)
        btn_section.addWidget(report_btn)
        
        layout.addLayout(btn_section)
        
        return frame
        
    def create_metrics_section(self) -> QFrame:
        """Create key metrics section"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 15px;
                padding: 20px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        # Title
        title = QLabel("📈 Key Performance Indicators")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(title)
        
        # Metrics grid
        self.metrics_grid = QGridLayout()
        self.metrics_grid.setSpacing(15)
        layout.addLayout(self.metrics_grid)
        
        return frame
        
    def create_details_section(self) -> QFrame:
        """Create details section with tabs"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 15px;
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
                padding: 12px 25px;
                margin-right: 5px;
                border-radius: 8px 8px 0 0;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: #0f3460;
                color: #fff;
            }
        """)
        
        # KPIs tab
        kpis_widget = QWidget()
        kpis_layout = QVBoxLayout(kpis_widget)
        
        kpis_scroll = QScrollArea()
        kpis_scroll.setWidgetResizable(True)
        kpis_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        self.kpis_container = QWidget()
        self.kpis_layout = QVBoxLayout(self.kpis_container)
        self.kpis_layout.setSpacing(8)
        
        kpis_scroll.setWidget(self.kpis_container)
        kpis_layout.addWidget(kpis_scroll)
        
        tabs.addTab(kpis_widget, "📊 Security KPIs")
        
        # Incidents tab
        incidents_widget = QWidget()
        incidents_layout = QVBoxLayout(incidents_widget)
        
        self.incidents_table = QTableWidget()
        self.incidents_table.setColumnCount(5)
        self.incidents_table.setHorizontalHeaderLabels(["ID", "Title", "Severity", "Status", "Impact"])
        self.incidents_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.incidents_table.setStyleSheet("""
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
                font-weight: bold;
            }
        """)
        incidents_layout.addWidget(self.incidents_table)
        
        tabs.addTab(incidents_widget, "🚨 Recent Incidents")
        
        # Compliance tab
        compliance_widget = QWidget()
        compliance_layout = QVBoxLayout(compliance_widget)
        
        self.compliance_table = QTableWidget()
        self.compliance_table.setColumnCount(5)
        self.compliance_table.setHorizontalHeaderLabels(["Framework", "Score", "Passed", "Failed", "Next Audit"])
        self.compliance_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.compliance_table.setStyleSheet("""
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
                font-weight: bold;
            }
        """)
        compliance_layout.addWidget(self.compliance_table)
        
        tabs.addTab(compliance_widget, "📋 Compliance")
        
        # Risk indicators tab
        risk_widget = QWidget()
        risk_layout = QVBoxLayout(risk_widget)
        
        self.risk_list = QListWidget()
        self.risk_list.setStyleSheet("""
            QListWidget {
                background: #0a0a15;
                color: #fff;
                border: none;
            }
            QListWidget::item {
                padding: 15px;
                border-bottom: 1px solid #333;
            }
        """)
        risk_layout.addWidget(self.risk_list)
        
        tabs.addTab(risk_widget, "🎯 Risk Indicators")
        
        layout.addWidget(tabs)
        
        return frame
        
    def load_dashboard(self):
        """Load the executive dashboard"""
        from core.executive_dashboard import get_executive_dashboard
        self.dashboard = get_executive_dashboard()
        self.refresh_display()
        
    def refresh_display(self):
        """Refresh all displays"""
        if not self.dashboard:
            return
            
        summary = self.dashboard.get_executive_summary()
        
        # Update risk gauge
        self.risk_gauge.set_score(summary["overall_risk_score"])
        
        # Update metrics grid
        self.update_metrics_grid()
        
        # Update KPIs
        self.update_kpis()
        
        # Update incidents
        self.update_incidents()
        
        # Update compliance
        self.update_compliance()
        
        # Update risk indicators
        self.update_risk_indicators()
        
    def update_metrics_grid(self):
        """Update metrics grid"""
        # Clear existing
        while self.metrics_grid.count():
            item = self.metrics_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        # Add metric cards
        metrics = self.dashboard.get_executive_metrics()
        for i, metric in enumerate(metrics):
            card = MetricCard({
                "name": metric.name,
                "value": metric.value,
                "change": metric.change,
                "change_period": metric.change_period,
                "icon": metric.icon,
                "color": metric.color,
            })
            row = i // 3
            col = i % 3
            self.metrics_grid.addWidget(card, row, col)
            
    def update_kpis(self):
        """Update KPIs display"""
        # Clear existing
        while self.kpis_layout.count():
            item = self.kpis_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        # Add KPI rows
        kpis = self.dashboard.get_kpi_summary()
        for kpi in kpis:
            row = KPIRow(kpi)
            self.kpis_layout.addWidget(row)
            
    def update_incidents(self):
        """Update incidents table"""
        summary = self.dashboard.get_incident_summary()
        incidents = summary.get("incidents", [])
        
        self.incidents_table.setRowCount(len(incidents))
        
        severity_colors = {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f1c40f",
            "low": "#27ae60",
        }
        
        for i, incident in enumerate(incidents):
            id_item = QTableWidgetItem(incident["id"])
            title_item = QTableWidgetItem(incident["title"])
            
            severity = incident["severity"]
            severity_item = QTableWidgetItem(severity.upper())
            severity_item.setForeground(QColor(severity_colors.get(severity, "#888")))
            
            status_item = QTableWidgetItem(incident["status"])
            impact_item = QTableWidgetItem(incident["impact"][:40] + "...")
            
            self.incidents_table.setItem(i, 0, id_item)
            self.incidents_table.setItem(i, 1, title_item)
            self.incidents_table.setItem(i, 2, severity_item)
            self.incidents_table.setItem(i, 3, status_item)
            self.incidents_table.setItem(i, 4, impact_item)
            
    def update_compliance(self):
        """Update compliance table"""
        summary = self.dashboard.get_compliance_summary()
        frameworks = summary.get("frameworks", [])
        
        self.compliance_table.setRowCount(len(frameworks))
        
        for i, fw in enumerate(frameworks):
            name_item = QTableWidgetItem(fw["name"])
            
            score = fw["score"]
            score_item = QTableWidgetItem(f"{score:.1f}%")
            if score >= 90:
                score_item.setForeground(QColor("#27ae60"))
            elif score >= 80:
                score_item.setForeground(QColor("#f1c40f"))
            else:
                score_item.setForeground(QColor("#e74c3c"))
                
            passed_item = QTableWidgetItem(str(fw["passed"]))
            passed_item.setForeground(QColor("#27ae60"))
            
            failed_item = QTableWidgetItem(str(fw["failed"]))
            failed_item.setForeground(QColor("#e74c3c"))
            
            days = fw["days_until_audit"]
            audit_item = QTableWidgetItem(f"{days} days")
            if days < 30:
                audit_item.setForeground(QColor("#e74c3c"))
            elif days < 90:
                audit_item.setForeground(QColor("#f1c40f"))
                
            self.compliance_table.setItem(i, 0, name_item)
            self.compliance_table.setItem(i, 1, score_item)
            self.compliance_table.setItem(i, 2, passed_item)
            self.compliance_table.setItem(i, 3, failed_item)
            self.compliance_table.setItem(i, 4, audit_item)
            
    def update_risk_indicators(self):
        """Update risk indicators"""
        self.risk_list.clear()
        
        posture = self.dashboard.get_risk_posture()
        indicators = posture.get("indicators", [])
        
        for indicator in indicators:
            trend = indicator["trend"]
            trend_icon = {"improving": "📈", "stable": "➡️", "declining": "📉"}.get(trend, "➡️")
            
            score = indicator["score"]
            risk_icon = "🟢" if score < 30 else ("🟡" if score < 50 else ("🟠" if score < 70 else "🔴"))
            
            text = f"{risk_icon} {indicator['name']} ({indicator['category']})\n"
            text += f"   Score: {score:.1f} {trend_icon} | {indicator['status']}"
            
            item = QListWidgetItem(text)
            self.risk_list.addItem(item)
            
    def export_board_report(self):
        """Export board-ready report"""
        from PyQt6.QtWidgets import QFileDialog, QMessageBox
        import json
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Board Report", 
            f"board_report_{datetime.now().strftime('%Y%m%d')}.json",
            "JSON Files (*.json)"
        )
        
        if filepath:
            report = self.dashboard.generate_board_report()
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
                
            QMessageBox.information(
                self, "Export Complete",
                f"Board report exported to {filepath}"
            )
