"""
Security Dashboard Page - Real-time security posture monitoring
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QFrame,
    QLineEdit, QComboBox, QTextEdit, QProgressBar,
    QSplitter, QTreeWidget, QTreeWidgetItem, QGroupBox,
    QGridLayout, QScrollArea, QListWidget, QListWidgetItem,
    QHeaderView, QMenu
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from datetime import datetime


class DashboardUpdateThread(QThread):
    """Background thread for dashboard updates"""
    updated = pyqtSignal(dict)
    
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.running = True
    
    def run(self):
        import asyncio
        import time
        
        while self.running:
            try:
                # Get dashboard summary
                summary = self.engine.get_dashboard_summary()
                self.updated.emit(summary)
            except Exception as e:
                pass
            
            time.sleep(10)  # Update every 10 seconds
    
    def stop(self):
        self.running = False


class SecurityDashboardPage(QWidget):
    """Security Dashboard page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = None
        self._init_engine()
        self._setup_ui()
        self._start_updates()
    
    def _init_engine(self):
        """Initialize the security dashboard engine"""
        try:
            from core.security_dashboard import SecurityDashboardEngine
            self.engine = SecurityDashboardEngine()
            # Add some sample data
            self._add_sample_data()
        except ImportError:
            self.engine = None
    
    def _add_sample_data(self):
        """Add sample data for demonstration"""
        if not self.engine:
            return
        
        # Set some initial metric values
        self.engine.update_metric("vuln_critical", 3)
        self.engine.update_metric("vuln_high", 12)
        self.engine.update_metric("vuln_medium", 45)
        self.engine.update_metric("vuln_low", 89)
        self.engine.update_metric("total_assets", 156)
        self.engine.update_metric("active_assets", 142)
        self.engine.update_metric("unpatched_systems", 8)
        self.engine.update_metric("threats_detected", 5)
        self.engine.update_metric("attacks_blocked", 127)
        self.engine.update_metric("open_incidents", 4)
        self.engine.update_metric("compliance_score", 87)
        self.engine.update_metric("patch_compliance", 92)
        self.engine.update_metric("endpoint_coverage", 98)
        self.engine.update_metric("mean_time_detect", 12)
        self.engine.update_metric("mean_time_respond", 45)
        
        # Calculate initial risk score
        self.engine.calculate_risk_score()
        
        # Add some sample alerts
        from core.security_dashboard import AlertSeverity
        
        self.engine.create_alert(
            "Critical vulnerability detected on web server",
            "CVE-2024-1234 found on prod-web-01, immediate patching required",
            AlertSeverity.CRITICAL,
            "Vulnerability Scanner",
            "Vulnerability"
        )
        
        self.engine.create_alert(
            "Unusual outbound traffic detected",
            "High volume data transfer from workstation WS-0045",
            AlertSeverity.HIGH,
            "Network Monitor",
            "Threat"
        )
        
        self.engine.create_alert(
            "Failed login attempts exceeded threshold",
            "Multiple failed SSH login attempts from IP 45.33.22.11",
            AlertSeverity.MEDIUM,
            "SIEM",
            "Attack"
        )
        
        # Add some events
        self.engine.add_event(
            "scan_completed",
            "Vulnerability scan completed",
            "Full network vulnerability scan finished with 159 findings",
            AlertSeverity.INFO,
            "Scanner"
        )
        
        self.engine.add_event(
            "attack_blocked",
            "SQL injection blocked",
            "WAF blocked SQL injection attempt on /api/users endpoint",
            AlertSeverity.MEDIUM,
            "WAF"
        )
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Header
        header_layout = QHBoxLayout()
        
        title = QLabel("Security Dashboard")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
                padding: 8px 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #30363d;
            }
        """)
        refresh_btn.clicked.connect(self._refresh_dashboard)
        header_layout.addWidget(refresh_btn)
        
        # Last updated
        self.last_updated_label = QLabel("Last updated: --")
        self.last_updated_label.setStyleSheet("color: #8b949e;")
        header_layout.addWidget(self.last_updated_label)
        
        layout.addLayout(header_layout)
        
        # Scroll area for dashboard content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(16)
        
        # Top row - Risk score and key metrics
        top_row = QHBoxLayout()
        
        # Risk score gauge
        risk_frame = self._create_risk_gauge()
        top_row.addWidget(risk_frame)
        
        # Key metrics
        metrics_frame = self._create_key_metrics()
        top_row.addWidget(metrics_frame, stretch=2)
        
        content_layout.addLayout(top_row)
        
        # Second row - Alerts and Timeline
        second_row = QHBoxLayout()
        
        # Alert summary
        alerts_frame = self._create_alerts_panel()
        second_row.addWidget(alerts_frame)
        
        # Timeline
        timeline_frame = self._create_timeline_panel()
        second_row.addWidget(timeline_frame)
        
        content_layout.addLayout(second_row)
        
        # Third row - Detailed metrics
        third_row = QHBoxLayout()
        
        # Vulnerability breakdown
        vuln_frame = self._create_vulnerability_panel()
        third_row.addWidget(vuln_frame)
        
        # Compliance metrics
        compliance_frame = self._create_compliance_panel()
        third_row.addWidget(compliance_frame)
        
        # Performance metrics
        perf_frame = self._create_performance_panel()
        third_row.addWidget(perf_frame)
        
        content_layout.addLayout(third_row)
        
        scroll.setWidget(content)
        layout.addWidget(scroll)
    
    def _create_risk_gauge(self):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        frame.setMinimumWidth(280)
        frame.setMaximumWidth(320)
        
        layout = QVBoxLayout(frame)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        header = QLabel("Overall Risk Score")
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setStyleSheet("color: #c9d1d9;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        layout.addSpacing(20)
        
        # Score display
        self.risk_score_label = QLabel("0.0")
        self.risk_score_label.setFont(QFont("Segoe UI", 48, QFont.Weight.Bold))
        self.risk_score_label.setStyleSheet("color: #3fb950;")
        self.risk_score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.risk_score_label)
        
        self.risk_grade_label = QLabel("Grade: A")
        self.risk_grade_label.setFont(QFont("Segoe UI", 16))
        self.risk_grade_label.setStyleSheet("color: #3fb950;")
        self.risk_grade_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.risk_grade_label)
        
        layout.addSpacing(10)
        
        # Score breakdown
        breakdown_label = QLabel("Risk Breakdown")
        breakdown_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        layout.addWidget(breakdown_label)
        
        self.breakdown_bars = {}
        categories = [
            ("vulnerabilities", "Vulnerabilities"),
            ("compliance", "Compliance"),
            ("patching", "Patching"),
            ("threats", "Threats"),
            ("incidents", "Incidents")
        ]
        
        for key, label in categories:
            row = QHBoxLayout()
            
            name = QLabel(label)
            name.setStyleSheet("color: #8b949e; font-size: 11px;")
            name.setMinimumWidth(80)
            row.addWidget(name)
            
            bar = QProgressBar()
            bar.setMaximum(100)
            bar.setValue(0)
            bar.setTextVisible(False)
            bar.setMaximumHeight(8)
            bar.setStyleSheet("""
                QProgressBar {
                    background: #21262d;
                    border: none;
                    border-radius: 4px;
                }
                QProgressBar::chunk {
                    background: #3fb950;
                    border-radius: 4px;
                }
            """)
            self.breakdown_bars[key] = bar
            row.addWidget(bar)
            
            layout.addLayout(row)
        
        return frame
    
    def _create_key_metrics(self):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        header = QLabel("Key Metrics")
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setStyleSheet("color: #c9d1d9;")
        layout.addWidget(header)
        
        # Metrics grid
        grid = QGridLayout()
        grid.setSpacing(12)
        
        self.metric_cards = {}
        metrics = [
            ("total_assets", "Total Assets", "🖥️", "#58a6ff"),
            ("active_assets", "Active Assets", "✅", "#3fb950"),
            ("open_incidents", "Open Incidents", "🚨", "#f85149"),
            ("threats_detected", "Threats Detected", "👁️", "#d29922"),
            ("attacks_blocked", "Attacks Blocked", "🛡️", "#a371f7"),
            ("unpatched_systems", "Unpatched Systems", "⚠️", "#db6d28")
        ]
        
        for i, (key, label, icon, color) in enumerate(metrics):
            card = self._create_metric_card(key, label, icon, color)
            self.metric_cards[key] = card
            grid.addWidget(card, i // 3, i % 3)
        
        layout.addLayout(grid)
        
        return frame
    
    def _create_metric_card(self, key, label, icon, color):
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setSpacing(4)
        
        # Icon and trend
        header = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI", 18))
        header.addWidget(icon_label)
        header.addStretch()
        
        trend_label = QLabel("")
        trend_label.setObjectName("trend")
        header.addWidget(trend_label)
        layout.addLayout(header)
        
        # Value
        value_label = QLabel("0")
        value_label.setObjectName("value")
        value_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        layout.addWidget(value_label)
        
        # Label
        label_widget = QLabel(label)
        label_widget.setStyleSheet("color: #8b949e; font-size: 12px;")
        layout.addWidget(label_widget)
        
        return card
    
    def _create_alerts_panel(self):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        # Header
        header = QHBoxLayout()
        title = QLabel("🚨 Active Alerts")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #c9d1d9;")
        header.addWidget(title)
        header.addStretch()
        
        # Alert counts
        self.alert_count_labels = {}
        for severity, color in [("critical", "#f85149"), ("high", "#db6d28"), 
                                 ("medium", "#d29922"), ("low", "#8b949e")]:
            count = QLabel("0")
            count.setStyleSheet(f"color: {color}; font-weight: bold; padding: 2px 8px; background: #21262d; border-radius: 10px;")
            self.alert_count_labels[severity] = count
            header.addWidget(count)
        
        layout.addLayout(header)
        
        # Alerts list
        self.alerts_list = QListWidget()
        self.alerts_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #c9d1d9;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
            }
            QListWidget::item:hover {
                background: #161b22;
            }
        """)
        self.alerts_list.setMinimumHeight(200)
        layout.addWidget(self.alerts_list)
        
        return frame
    
    def _create_timeline_panel(self):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        header = QLabel("📅 Security Timeline (24h)")
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setStyleSheet("color: #c9d1d9;")
        layout.addWidget(header)
        
        self.timeline_list = QListWidget()
        self.timeline_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #c9d1d9;
            }
            QListWidget::item {
                padding: 10px;
                border-left: 3px solid #30363d;
                margin-left: 10px;
            }
        """)
        self.timeline_list.setMinimumHeight(200)
        layout.addWidget(self.timeline_list)
        
        return frame
    
    def _create_vulnerability_panel(self):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        header = QLabel("🐛 Vulnerabilities")
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setStyleSheet("color: #c9d1d9;")
        layout.addWidget(header)
        
        # Severity bars
        self.vuln_bars = {}
        severities = [
            ("critical", "Critical", "#f85149"),
            ("high", "High", "#db6d28"),
            ("medium", "Medium", "#d29922"),
            ("low", "Low", "#8b949e")
        ]
        
        for key, label, color in severities:
            row = QHBoxLayout()
            
            name = QLabel(label)
            name.setStyleSheet(f"color: {color}; font-weight: 600;")
            name.setMinimumWidth(60)
            row.addWidget(name)
            
            bar = QProgressBar()
            bar.setMaximum(200)
            bar.setValue(0)
            bar.setFormat("%v")
            bar.setMaximumHeight(20)
            bar.setStyleSheet(f"""
                QProgressBar {{
                    background: #21262d;
                    border: none;
                    border-radius: 4px;
                    text-align: center;
                    color: white;
                }}
                QProgressBar::chunk {{
                    background: {color};
                    border-radius: 4px;
                }}
            """)
            self.vuln_bars[key] = bar
            row.addWidget(bar)
            
            layout.addLayout(row)
        
        # Total
        total_layout = QHBoxLayout()
        total_label = QLabel("Total:")
        total_label.setStyleSheet("color: #c9d1d9; font-weight: 600;")
        total_layout.addWidget(total_label)
        
        self.vuln_total = QLabel("0")
        self.vuln_total.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        self.vuln_total.setStyleSheet("color: #58a6ff;")
        total_layout.addWidget(self.vuln_total)
        total_layout.addStretch()
        
        layout.addLayout(total_layout)
        
        return frame
    
    def _create_compliance_panel(self):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        header = QLabel("📋 Compliance")
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setStyleSheet("color: #c9d1d9;")
        layout.addWidget(header)
        
        # Overall compliance score
        score_layout = QHBoxLayout()
        score_label = QLabel("Overall Score:")
        score_label.setStyleSheet("color: #8b949e;")
        score_layout.addWidget(score_label)
        
        self.compliance_score = QLabel("0%")
        self.compliance_score.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        self.compliance_score.setStyleSheet("color: #3fb950;")
        score_layout.addWidget(self.compliance_score)
        score_layout.addStretch()
        layout.addLayout(score_layout)
        
        # Compliance metrics
        self.compliance_metrics = {}
        metrics = [
            ("patch_compliance", "Patch Compliance"),
            ("endpoint_coverage", "Endpoint Coverage")
        ]
        
        for key, label in metrics:
            row = QHBoxLayout()
            
            name = QLabel(label)
            name.setStyleSheet("color: #8b949e;")
            row.addWidget(name)
            
            value = QLabel("0%")
            value.setObjectName(key)
            value.setStyleSheet("color: #c9d1d9; font-weight: 600;")
            self.compliance_metrics[key] = value
            row.addWidget(value)
            
            layout.addLayout(row)
        
        return frame
    
    def _create_performance_panel(self):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        header = QLabel("⏱️ Performance")
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setStyleSheet("color: #c9d1d9;")
        layout.addWidget(header)
        
        # Performance metrics
        self.perf_metrics = {}
        metrics = [
            ("mean_time_detect", "Mean Time to Detect", "min"),
            ("mean_time_respond", "Mean Time to Respond", "min")
        ]
        
        for key, label, unit in metrics:
            metric_frame = QFrame()
            metric_frame.setStyleSheet("""
                QFrame {
                    background: #0d1117;
                    border: 1px solid #21262d;
                    border-radius: 6px;
                    padding: 12px;
                    margin: 4px 0;
                }
            """)
            metric_layout = QVBoxLayout(metric_frame)
            metric_layout.setSpacing(4)
            
            name = QLabel(label)
            name.setStyleSheet("color: #8b949e; font-size: 11px;")
            metric_layout.addWidget(name)
            
            value_layout = QHBoxLayout()
            value = QLabel("0")
            value.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
            value.setStyleSheet("color: #58a6ff;")
            self.perf_metrics[key] = value
            value_layout.addWidget(value)
            
            unit_label = QLabel(unit)
            unit_label.setStyleSheet("color: #8b949e;")
            value_layout.addWidget(unit_label)
            value_layout.addStretch()
            
            metric_layout.addLayout(value_layout)
            layout.addWidget(metric_frame)
        
        return frame
    
    def _start_updates(self):
        """Start periodic dashboard updates"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._refresh_dashboard)
        self.update_timer.start(30000)  # Update every 30 seconds
        
        # Initial refresh
        self._refresh_dashboard()
    
    def _refresh_dashboard(self):
        """Refresh all dashboard data"""
        if not self.engine:
            return
        
        # Get summary
        summary = self.engine.get_dashboard_summary()
        
        # Update risk score
        if summary.get("risk_score"):
            score = summary["risk_score"]
            self.risk_score_label.setText(f"{score.score:.1f}")
            self.risk_grade_label.setText(f"Grade: {score.grade}")
            
            # Color based on score
            if score.score <= 3:
                color = "#3fb950"
            elif score.score <= 6:
                color = "#d29922"
            else:
                color = "#f85149"
            
            self.risk_score_label.setStyleSheet(f"color: {color};")
            self.risk_grade_label.setStyleSheet(f"color: {color};")
            
            # Update breakdown bars
            for key, bar in self.breakdown_bars.items():
                if key in score.breakdown:
                    value = int(score.breakdown[key] * 10)  # Scale to 0-100
                    bar.setValue(value)
                    
                    # Color based on value
                    if value <= 30:
                        bar_color = "#3fb950"
                    elif value <= 60:
                        bar_color = "#d29922"
                    else:
                        bar_color = "#f85149"
                    
                    bar.setStyleSheet(f"""
                        QProgressBar {{
                            background: #21262d;
                            border: none;
                            border-radius: 4px;
                        }}
                        QProgressBar::chunk {{
                            background: {bar_color};
                            border-radius: 4px;
                        }}
                    """)
        
        # Update metrics
        metrics = summary.get("metrics", {})
        for key, card in self.metric_cards.items():
            if key in metrics:
                value_label = card.findChild(QLabel, "value")
                if value_label:
                    value_label.setText(str(int(metrics[key]["value"])))
                
                trend_label = card.findChild(QLabel, "trend")
                if trend_label:
                    trend = metrics[key].get("trend", "stable")
                    change = metrics[key].get("change", 0)
                    if trend == "up":
                        trend_label.setText(f"↑ {abs(change):.0f}%")
                        trend_label.setStyleSheet("color: #f85149;")
                    elif trend == "down":
                        trend_label.setText(f"↓ {abs(change):.0f}%")
                        trend_label.setStyleSheet("color: #3fb950;")
                    else:
                        trend_label.setText("→")
                        trend_label.setStyleSheet("color: #8b949e;")
        
        # Update alert counts
        alert_counts = summary.get("alert_counts", {})
        for severity, label in self.alert_count_labels.items():
            count = alert_counts.get(severity, 0)
            label.setText(str(count))
        
        # Update alerts list
        self.alerts_list.clear()
        for alert in self.engine.get_alerts(limit=10):
            severity_icons = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "info": "🔵"
            }
            icon = severity_icons.get(alert.severity.value, "⚪")
            
            text = f"{icon} {alert.title}\n"
            text += f"   {alert.source} • {alert.created_at.strftime('%H:%M')}"
            
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, alert.id)
            self.alerts_list.addItem(item)
        
        # Update timeline
        self.timeline_list.clear()
        for event in self.engine.get_events(hours=24)[:15]:
            severity_colors = {
                "critical": "#f85149",
                "high": "#db6d28",
                "medium": "#d29922",
                "low": "#8b949e",
                "info": "#58a6ff"
            }
            color = severity_colors.get(event.severity.value, "#8b949e")
            
            text = f"[{event.timestamp.strftime('%H:%M')}] {event.title}\n"
            text += f"   {event.description[:60]}..."
            
            item = QListWidgetItem(text)
            item.setForeground(QColor(color))
            self.timeline_list.addItem(item)
        
        # Update vulnerability bars
        vuln_total = 0
        for key in ["critical", "high", "medium", "low"]:
            metric_key = f"vuln_{key}"
            if metric_key in metrics:
                value = int(metrics[metric_key]["value"])
                vuln_total += value
                self.vuln_bars[key].setValue(value)
        self.vuln_total.setText(str(vuln_total))
        
        # Update compliance
        if "compliance_score" in metrics:
            score = int(metrics["compliance_score"]["value"])
            self.compliance_score.setText(f"{score}%")
            
            if score >= 90:
                self.compliance_score.setStyleSheet("color: #3fb950;")
            elif score >= 70:
                self.compliance_score.setStyleSheet("color: #d29922;")
            else:
                self.compliance_score.setStyleSheet("color: #f85149;")
        
        for key, label in self.compliance_metrics.items():
            if key in metrics:
                value = int(metrics[key]["value"])
                label.setText(f"{value}%")
        
        # Update performance metrics
        for key, label in self.perf_metrics.items():
            if key in metrics:
                value = int(metrics[key]["value"])
                label.setText(str(value))
        
        # Update timestamp
        self.last_updated_label.setText(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")
    
    def closeEvent(self, event):
        """Handle page close"""
        if hasattr(self, 'update_timer'):
            self.update_timer.stop()
        super().closeEvent(event)
