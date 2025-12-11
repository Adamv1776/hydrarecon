#!/usr/bin/env python3
"""
HydraRecon Security Metrics Page
Enterprise security KPIs, metrics tracking, and performance analytics dashboard.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QTableWidget, QTableWidgetItem,
    QTabWidget, QLineEdit, QComboBox, QTextEdit, QProgressBar,
    QHeaderView, QGridLayout, QSpinBox, QCheckBox, QSplitter,
    QGroupBox, QListWidget, QListWidgetItem, QDialog, QDialogButtonBox,
    QFormLayout, QStackedWidget, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush
from PyQt6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis, QPieSeries, QBarSeries, QBarSet, QBarCategoryAxis

from datetime import datetime, timedelta


class SecurityMetricsPage(QWidget):
    """Security Metrics and KPIs interface"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.engine = None
        self._init_engine()
        self._setup_ui()
        self._load_data()
    
    def _init_engine(self):
        """Initialize security metrics engine"""
        try:
            from core.security_metrics import SecurityMetricsEngine
            self.engine = SecurityMetricsEngine()
        except ImportError:
            self.engine = None
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # KPI Cards
        kpi_section = self._create_kpi_section()
        layout.addWidget(kpi_section)
        
        # Main tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                border-radius: 8px;
                background-color: #0d1117;
            }
            QTabBar::tab {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px 20px;
                border: 1px solid #30363d;
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 4px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #f0f6fc;
            }
            QTabBar::tab:hover:!selected {
                background-color: #21262d;
            }
        """)
        
        # Dashboard tab
        dashboard_tab = self._create_dashboard_tab()
        self.tabs.addTab(dashboard_tab, "📊 Dashboard")
        
        # Metrics tab
        metrics_tab = self._create_metrics_tab()
        self.tabs.addTab(metrics_tab, "📈 All Metrics")
        
        # Trends tab
        trends_tab = self._create_trends_tab()
        self.tabs.addTab(trends_tab, "📉 Trends")
        
        # Benchmarks tab
        benchmarks_tab = self._create_benchmarks_tab()
        self.tabs.addTab(benchmarks_tab, "🎯 Benchmarks")
        
        # Reports tab
        reports_tab = self._create_reports_tab()
        self.tabs.addTab(reports_tab, "📋 Reports")
        
        layout.addWidget(self.tabs)
    
    def _create_header(self) -> QFrame:
        """Create page header"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #8957e5, stop:1 #6e40c9);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_section = QVBoxLayout()
        
        title = QLabel("📊 Security Metrics & KPIs")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: white; background: transparent;")
        title_section.addWidget(title)
        
        subtitle = QLabel("Track, measure, and improve your security posture")
        subtitle.setStyleSheet("color: rgba(255,255,255,0.8); background: transparent;")
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        
        refresh_btn = QPushButton("🔄 Refresh Data")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255,255,255,0.2);
                color: white;
                border: 1px solid rgba(255,255,255,0.3);
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255,255,255,0.3);
            }
        """)
        refresh_btn.clicked.connect(self._refresh_data)
        btn_layout.addWidget(refresh_btn)
        
        report_btn = QPushButton("📥 Export Report")
        report_btn.setStyleSheet("""
            QPushButton {
                background-color: white;
                color: #8957e5;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #f0f0f0;
            }
        """)
        report_btn.clicked.connect(self._export_report)
        btn_layout.addWidget(report_btn)
        
        layout.addLayout(btn_layout)
        
        return header
    
    def _create_kpi_section(self) -> QFrame:
        """Create KPI cards section"""
        container = QFrame()
        layout = QHBoxLayout(container)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.kpi_cards = {}
        
        kpis = [
            ("security_posture", "Security Posture", "78.5", "90", "📊", "#238636"),
            ("incident_response", "Incident Response", "82.3", "95", "🚨", "#1f6feb"),
            ("compliance", "Compliance Score", "91.2", "98", "✅", "#a371f7"),
            ("vuln_mgmt", "Vulnerability Mgmt", "75.8", "90", "🐛", "#d29922"),
            ("threat_detection", "Threat Detection", "85.4", "95", "🎯", "#f85149")
        ]
        
        for key, name, score, target, icon, color in kpis:
            card = self._create_kpi_card(key, name, score, target, icon, color)
            layout.addWidget(card)
        
        return container
    
    def _create_kpi_card(self, key, name, score, target, icon, color) -> QFrame:
        """Create individual KPI card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                border-top: 4px solid {color};
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        
        # Icon and name
        header = QHBoxLayout()
        
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI", 20))
        header.addWidget(icon_label)
        
        name_label = QLabel(name)
        name_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        header.addWidget(name_label)
        header.addStretch()
        
        layout.addLayout(header)
        
        # Score
        score_layout = QHBoxLayout()
        
        score_label = QLabel(score)
        score_label.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        score_label.setStyleSheet(f"color: {color};")
        score_layout.addWidget(score_label)
        
        target_label = QLabel(f"/ {target}")
        target_label.setStyleSheet("color: #8b949e; font-size: 16px;")
        target_label.setAlignment(Qt.AlignmentFlag.AlignBottom)
        score_layout.addWidget(target_label)
        score_layout.addStretch()
        
        layout.addLayout(score_layout)
        
        # Progress bar
        progress = QProgressBar()
        progress.setMaximum(100)
        progress.setValue(int(float(score)))
        progress.setTextVisible(False)
        progress.setMaximumHeight(6)
        progress.setStyleSheet(f"""
            QProgressBar {{
                background-color: #21262d;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 3px;
            }}
        """)
        layout.addWidget(progress)
        
        # Trend indicator
        trend = QLabel("▲ +2.5% from last month")
        trend.setStyleSheet("color: #238636; font-size: 11px;")
        layout.addWidget(trend)
        
        self.kpi_cards[key] = {
            "card": card,
            "score_label": score_label,
            "progress": progress,
            "trend": trend
        }
        
        return card
    
    def _create_dashboard_tab(self) -> QWidget:
        """Create main dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Charts row
        charts_layout = QHBoxLayout()
        
        # Category breakdown chart
        category_frame = QFrame()
        category_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        category_layout = QVBoxLayout(category_frame)
        
        category_title = QLabel("Metrics by Category")
        category_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        category_title.setStyleSheet("color: #f0f6fc;")
        category_layout.addWidget(category_title)
        
        # Create pie chart
        self.category_chart = self._create_category_chart()
        category_layout.addWidget(self.category_chart)
        
        charts_layout.addWidget(category_frame)
        
        # Status breakdown
        status_frame = QFrame()
        status_frame.setStyleSheet(category_frame.styleSheet())
        status_layout = QVBoxLayout(status_frame)
        
        status_title = QLabel("Target Status")
        status_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        status_title.setStyleSheet("color: #f0f6fc;")
        status_layout.addWidget(status_title)
        
        self.status_chart = self._create_status_chart()
        status_layout.addWidget(self.status_chart)
        
        charts_layout.addWidget(status_frame)
        
        # Trend chart
        trend_frame = QFrame()
        trend_frame.setStyleSheet(category_frame.styleSheet())
        trend_layout = QVBoxLayout(trend_frame)
        
        trend_title = QLabel("Overall Score Trend")
        trend_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        trend_title.setStyleSheet("color: #f0f6fc;")
        trend_layout.addWidget(trend_title)
        
        self.trend_chart = self._create_trend_chart()
        trend_layout.addWidget(self.trend_chart)
        
        charts_layout.addWidget(trend_frame)
        
        layout.addLayout(charts_layout)
        
        # Top concerns table
        concerns_frame = QFrame()
        concerns_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        concerns_layout = QVBoxLayout(concerns_frame)
        
        concerns_header = QHBoxLayout()
        concerns_title = QLabel("⚠️ Top Concerns (Missed Targets)")
        concerns_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        concerns_title.setStyleSheet("color: #f0f6fc;")
        concerns_header.addWidget(concerns_title)
        concerns_header.addStretch()
        
        view_all_btn = QPushButton("View All →")
        view_all_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #58a6ff;
                border: none;
            }
            QPushButton:hover {
                text-decoration: underline;
            }
        """)
        concerns_header.addWidget(view_all_btn)
        concerns_layout.addLayout(concerns_header)
        
        self.concerns_table = QTableWidget()
        self.concerns_table.setColumnCount(5)
        self.concerns_table.setHorizontalHeaderLabels([
            "Metric", "Category", "Current", "Target", "Variance"
        ])
        self.concerns_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
            QTableWidget::item {
                padding: 10px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        self.concerns_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.concerns_table.setMaximumHeight(200)
        concerns_layout.addWidget(self.concerns_table)
        
        layout.addWidget(concerns_frame)
        
        return widget
    
    def _create_metrics_tab(self) -> QWidget:
        """Create all metrics tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Filters
        filter_frame = QFrame()
        filter_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        filter_layout = QHBoxLayout(filter_frame)
        filter_layout.setContentsMargins(16, 12, 16, 12)
        
        # Search
        self.metric_search = QLineEdit()
        self.metric_search.setPlaceholderText("🔍 Search metrics...")
        self.metric_search.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
                min-width: 250px;
            }
            QLineEdit:focus {
                border-color: #58a6ff;
            }
        """)
        self.metric_search.textChanged.connect(self._filter_metrics)
        filter_layout.addWidget(self.metric_search)
        
        # Category filter
        filter_layout.addWidget(QLabel("Category:"))
        self.category_filter = QComboBox()
        self.category_filter.addItems([
            "All Categories", "Vulnerability", "Threat", "Compliance",
            "Incident", "Patching", "Access", "Data", "Network", 
            "Endpoint", "Awareness"
        ])
        self.category_filter.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c9d1d9;
                min-width: 150px;
            }
        """)
        self.category_filter.currentTextChanged.connect(self._filter_metrics)
        filter_layout.addWidget(self.category_filter)
        
        # Status filter
        filter_layout.addWidget(QLabel("Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Status", "Met", "At Risk", "Missed"])
        self.status_filter.setStyleSheet(self.category_filter.styleSheet())
        self.status_filter.currentTextChanged.connect(self._filter_metrics)
        filter_layout.addWidget(self.status_filter)
        
        filter_layout.addStretch()
        
        layout.addWidget(filter_frame)
        
        # Metrics table
        self.metrics_table = QTableWidget()
        self.metrics_table.setColumnCount(8)
        self.metrics_table.setHorizontalHeaderLabels([
            "Metric", "Category", "Current", "Target", "Unit", "Trend", "Status", "Owner"
        ])
        self.metrics_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
                color: #c9d1d9;
            }
            QTableWidget::item:selected {
                background-color: #1f6feb;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 12px;
                border: none;
                border-bottom: 1px solid #30363d;
                font-weight: bold;
            }
        """)
        self.metrics_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.metrics_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.metrics_table)
        
        return widget
    
    def _create_trends_tab(self) -> QWidget:
        """Create trends analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Splitter for trend lists and chart
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Improving metrics
        improving_frame = QFrame()
        improving_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        improving_layout = QVBoxLayout(improving_frame)
        
        improving_title = QLabel("📈 Improving Metrics")
        improving_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        improving_title.setStyleSheet("color: #238636;")
        improving_layout.addWidget(improving_title)
        
        self.improving_list = QListWidget()
        self.improving_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
                color: #c9d1d9;
            }
            QListWidget::item:selected {
                background-color: #238636;
            }
        """)
        improving_layout.addWidget(self.improving_list)
        
        splitter.addWidget(improving_frame)
        
        # Declining metrics
        declining_frame = QFrame()
        declining_frame.setStyleSheet(improving_frame.styleSheet())
        declining_layout = QVBoxLayout(declining_frame)
        
        declining_title = QLabel("📉 Declining Metrics")
        declining_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        declining_title.setStyleSheet("color: #f85149;")
        declining_layout.addWidget(declining_title)
        
        self.declining_list = QListWidget()
        self.declining_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #21262d;
                color: #c9d1d9;
            }
            QListWidget::item:selected {
                background-color: #f85149;
            }
        """)
        declining_layout.addWidget(self.declining_list)
        
        splitter.addWidget(declining_frame)
        
        # Trend chart
        chart_frame = QFrame()
        chart_frame.setStyleSheet(improving_frame.styleSheet())
        chart_layout = QVBoxLayout(chart_frame)
        
        chart_title = QLabel("📊 Selected Metric Trend")
        chart_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        chart_title.setStyleSheet("color: #f0f6fc;")
        chart_layout.addWidget(chart_title)
        
        self.detail_trend_chart = self._create_detail_trend_chart()
        chart_layout.addWidget(self.detail_trend_chart)
        
        splitter.addWidget(chart_frame)
        splitter.setSizes([250, 250, 400])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_benchmarks_tab(self) -> QWidget:
        """Create benchmarks comparison tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Industry selector
        industry_frame = QFrame()
        industry_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        industry_layout = QHBoxLayout(industry_frame)
        industry_layout.setContentsMargins(16, 12, 16, 12)
        
        industry_layout.addWidget(QLabel("Compare to Industry:"))
        self.industry_combo = QComboBox()
        self.industry_combo.addItems([
            "All Industries", "Financial Services", "Healthcare",
            "Technology", "Manufacturing", "Retail", "Government"
        ])
        self.industry_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c9d1d9;
                min-width: 200px;
            }
        """)
        industry_layout.addWidget(self.industry_combo)
        industry_layout.addStretch()
        
        layout.addWidget(industry_frame)
        
        # Benchmark comparison table
        self.benchmark_table = QTableWidget()
        self.benchmark_table.setColumnCount(7)
        self.benchmark_table.setHorizontalHeaderLabels([
            "Metric", "Your Value", "25th %ile", "Median", "75th %ile", "90th %ile", "Your Percentile"
        ])
        self.benchmark_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 12px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 12px;
                border: none;
            }
        """)
        self.benchmark_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.benchmark_table)
        
        return widget
    
    def _create_reports_tab(self) -> QWidget:
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Report types
        reports_frame = QFrame()
        reports_frame.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        reports_layout = QVBoxLayout(reports_frame)
        reports_layout.setContentsMargins(20, 20, 20, 20)
        
        reports_title = QLabel("Generate Reports")
        reports_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        reports_title.setStyleSheet("color: #f0f6fc;")
        reports_layout.addWidget(reports_title)
        
        # Report buttons
        report_types = [
            ("📊 Executive Summary", "High-level overview for leadership", "#8957e5"),
            ("📈 Detailed Metrics Report", "Full breakdown of all metrics", "#1f6feb"),
            ("📉 Trend Analysis", "Month-over-month trend analysis", "#238636"),
            ("🎯 Benchmark Comparison", "Compare against industry peers", "#d29922"),
            ("⚠️ Risk Assessment", "Metrics-based risk assessment", "#f85149")
        ]
        
        reports_grid = QGridLayout()
        for i, (title, desc, color) in enumerate(report_types):
            row, col = i // 2, i % 2
            
            btn = QPushButton()
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: #21262d;
                    border: 1px solid #30363d;
                    border-radius: 8px;
                    border-left: 4px solid {color};
                    padding: 20px;
                    text-align: left;
                }}
                QPushButton:hover {{
                    background-color: #30363d;
                }}
            """)
            
            btn_layout = QVBoxLayout(btn)
            
            title_label = QLabel(title)
            title_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
            title_label.setStyleSheet(f"color: {color};")
            btn_layout.addWidget(title_label)
            
            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color: #8b949e;")
            btn_layout.addWidget(desc_label)
            
            reports_grid.addWidget(btn, row, col)
        
        reports_layout.addLayout(reports_grid)
        
        layout.addWidget(reports_frame)
        
        # Scheduled reports
        scheduled_frame = QFrame()
        scheduled_frame.setStyleSheet(reports_frame.styleSheet())
        scheduled_layout = QVBoxLayout(scheduled_frame)
        scheduled_layout.setContentsMargins(20, 20, 20, 20)
        
        scheduled_header = QHBoxLayout()
        scheduled_title = QLabel("📅 Scheduled Reports")
        scheduled_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        scheduled_title.setStyleSheet("color: #f0f6fc;")
        scheduled_header.addWidget(scheduled_title)
        
        new_schedule_btn = QPushButton("+ New Schedule")
        new_schedule_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
            }
        """)
        scheduled_header.addWidget(new_schedule_btn)
        scheduled_header.addStretch()
        
        scheduled_layout.addLayout(scheduled_header)
        
        self.scheduled_table = QTableWidget()
        self.scheduled_table.setColumnCount(5)
        self.scheduled_table.setHorizontalHeaderLabels([
            "Report", "Frequency", "Recipients", "Next Run", "Actions"
        ])
        self.scheduled_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
            QTableWidget::item {
                padding: 10px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        self.scheduled_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.scheduled_table.setMaximumHeight(200)
        scheduled_layout.addWidget(self.scheduled_table)
        
        layout.addWidget(scheduled_frame)
        
        return widget
    
    def _create_category_chart(self) -> QChartView:
        """Create category breakdown pie chart"""
        chart = QChart()
        chart.setBackgroundBrush(QBrush(QColor("#161b22")))
        chart.setTitleBrush(QBrush(QColor("#f0f6fc")))
        chart.legend().setLabelColor(QColor("#8b949e"))
        
        series = QPieSeries()
        
        categories = [
            ("Vulnerability", 4, "#f85149"),
            ("Incident", 5, "#d29922"),
            ("Compliance", 3, "#238636"),
            ("Threat", 2, "#1f6feb"),
            ("Other", 6, "#8957e5")
        ]
        
        for name, value, color in categories:
            slice = series.append(name, value)
            slice.setColor(QColor(color))
            slice.setLabelVisible(False)
        
        chart.addSeries(series)
        chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)
        
        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        chart_view.setMinimumHeight(200)
        
        return chart_view
    
    def _create_status_chart(self) -> QChartView:
        """Create status breakdown chart"""
        chart = QChart()
        chart.setBackgroundBrush(QBrush(QColor("#161b22")))
        chart.legend().setLabelColor(QColor("#8b949e"))
        
        series = QPieSeries()
        
        statuses = [
            ("Met", 12, "#238636"),
            ("At Risk", 5, "#d29922"),
            ("Missed", 3, "#f85149")
        ]
        
        for name, value, color in statuses:
            slice = series.append(name, value)
            slice.setColor(QColor(color))
            slice.setLabelVisible(True)
            slice.setLabelColor(QColor("#f0f6fc"))
        
        chart.addSeries(series)
        
        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        chart_view.setMinimumHeight(200)
        
        return chart_view
    
    def _create_trend_chart(self) -> QChartView:
        """Create overall trend line chart"""
        chart = QChart()
        chart.setBackgroundBrush(QBrush(QColor("#161b22")))
        chart.legend().hide()
        
        series = QLineSeries()
        series.setColor(QColor("#8957e5"))
        
        # Sample trend data
        data = [72, 74, 73, 76, 78, 77, 79, 80, 78, 81, 82, 85]
        for i, value in enumerate(data):
            series.append(i, value)
        
        chart.addSeries(series)
        
        # Axes
        axis_x = QValueAxis()
        axis_x.setRange(0, 11)
        axis_x.setLabelsColor(QColor("#8b949e"))
        axis_x.setGridLineVisible(False)
        chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axis_x)
        
        axis_y = QValueAxis()
        axis_y.setRange(60, 100)
        axis_y.setLabelsColor(QColor("#8b949e"))
        axis_y.setGridLineColor(QColor("#21262d"))
        chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)
        
        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        chart_view.setMinimumHeight(200)
        
        return chart_view
    
    def _create_detail_trend_chart(self) -> QChartView:
        """Create detailed trend chart"""
        chart = QChart()
        chart.setBackgroundBrush(QBrush(QColor("#0d1117")))
        chart.legend().hide()
        
        series = QLineSeries()
        series.setColor(QColor("#58a6ff"))
        
        chart.addSeries(series)
        
        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        return chart_view
    
    def _load_data(self):
        """Load all data"""
        self._load_metrics()
        self._load_concerns()
        self._load_trends()
        self._load_benchmarks()
    
    def _load_metrics(self):
        """Load metrics into table"""
        if not self.engine:
            return
        
        metrics = list(self.engine.metrics.values())
        self.metrics_table.setRowCount(len(metrics))
        
        for row, metric in enumerate(metrics):
            status = self.engine.evaluate_metric_status(metric.id)
            trend = self.engine.get_metric_trend(metric.id)
            
            # Name
            self.metrics_table.setItem(row, 0, QTableWidgetItem(metric.name))
            
            # Category
            self.metrics_table.setItem(row, 1, QTableWidgetItem(metric.category.value.title()))
            
            # Current value
            current = status.get("current_value", "-")
            if current is not None:
                current = f"{current:.1f}" if isinstance(current, float) else str(current)
            self.metrics_table.setItem(row, 2, QTableWidgetItem(str(current)))
            
            # Target
            self.metrics_table.setItem(row, 3, QTableWidgetItem(str(metric.target_value)))
            
            # Unit
            self.metrics_table.setItem(row, 4, QTableWidgetItem(metric.unit))
            
            # Trend
            trend_text = f"{trend['percentage']:+.1f}%" if trend['percentage'] != 0 else "→ 0%"
            trend_item = QTableWidgetItem(trend_text)
            if trend['trend'].value == "improving":
                trend_item.setForeground(QColor("#238636"))
            elif trend['trend'].value == "declining":
                trend_item.setForeground(QColor("#f85149"))
            else:
                trend_item.setForeground(QColor("#8b949e"))
            self.metrics_table.setItem(row, 5, trend_item)
            
            # Status
            status_text = status.get("status", "unknown").replace("_", " ").title()
            status_item = QTableWidgetItem(status_text)
            status_colors = {
                "met": "#238636",
                "at_risk": "#d29922",
                "missed": "#f85149"
            }
            status_item.setForeground(QColor(status_colors.get(status.get("status", ""), "#8b949e")))
            self.metrics_table.setItem(row, 6, status_item)
            
            # Owner
            self.metrics_table.setItem(row, 7, QTableWidgetItem(metric.owner))
    
    def _load_concerns(self):
        """Load top concerns"""
        if not self.engine:
            return
        
        summary = self.engine.get_executive_summary()
        concerns = summary.get("top_concerns", [])
        
        self.concerns_table.setRowCount(len(concerns))
        
        for row, concern in enumerate(concerns):
            metric = concern.get("metric")
            if not metric:
                continue
            
            self.concerns_table.setItem(row, 0, QTableWidgetItem(metric.name))
            self.concerns_table.setItem(row, 1, QTableWidgetItem(metric.category.value.title()))
            
            current = concern.get("current_value", 0)
            self.concerns_table.setItem(row, 2, QTableWidgetItem(f"{current:.1f}"))
            
            self.concerns_table.setItem(row, 3, QTableWidgetItem(str(metric.target_value)))
            
            variance = concern.get("variance_percentage", 0)
            variance_item = QTableWidgetItem(f"{variance:+.1f}%")
            variance_item.setForeground(QColor("#f85149"))
            self.concerns_table.setItem(row, 4, variance_item)
    
    def _load_trends(self):
        """Load trend lists"""
        if not self.engine:
            return
        
        trend_report = self.engine._generate_trend_report(None)
        
        # Improving
        self.improving_list.clear()
        for metric in trend_report.get("improving_metrics", []):
            item = QListWidgetItem(f"▲ {metric['metric_name']} ({metric['percentage']:+.1f}%)")
            self.improving_list.addItem(item)
        
        # Declining
        self.declining_list.clear()
        for metric in trend_report.get("declining_metrics", []):
            item = QListWidgetItem(f"▼ {metric['metric_name']} ({metric['percentage']:+.1f}%)")
            self.declining_list.addItem(item)
    
    def _load_benchmarks(self):
        """Load benchmark comparisons"""
        if not self.engine:
            return
        
        metrics = list(self.engine.metrics.values())[:10]
        self.benchmark_table.setRowCount(len(metrics))
        
        for row, metric in enumerate(metrics):
            benchmark = self.engine.compare_to_benchmark(metric.id)
            
            self.benchmark_table.setItem(row, 0, QTableWidgetItem(metric.name))
            
            current = benchmark.get("current_value", "-")
            if current != "-":
                current = f"{current:.1f}"
            self.benchmark_table.setItem(row, 1, QTableWidgetItem(str(current)))
            
            benchmarks = benchmark.get("benchmarks", {})
            self.benchmark_table.setItem(row, 2, QTableWidgetItem(f"{benchmarks.get('percentile_25', '-'):.1f}"))
            self.benchmark_table.setItem(row, 3, QTableWidgetItem(f"{benchmarks.get('percentile_50', '-'):.1f}"))
            self.benchmark_table.setItem(row, 4, QTableWidgetItem(f"{benchmarks.get('percentile_75', '-'):.1f}"))
            self.benchmark_table.setItem(row, 5, QTableWidgetItem(f"{benchmarks.get('percentile_90', '-'):.1f}"))
            
            percentile = benchmark.get("percentile", 50)
            perc_item = QTableWidgetItem(f"{percentile}th")
            if percentile >= 75:
                perc_item.setForeground(QColor("#238636"))
            elif percentile >= 50:
                perc_item.setForeground(QColor("#d29922"))
            else:
                perc_item.setForeground(QColor("#f85149"))
            self.benchmark_table.setItem(row, 6, perc_item)
    
    def _filter_metrics(self):
        """Filter metrics table"""
        search_text = self.metric_search.text().lower()
        category = self.category_filter.currentText().lower()
        status = self.status_filter.currentText().lower()
        
        for row in range(self.metrics_table.rowCount()):
            show = True
            
            if search_text:
                name = self.metrics_table.item(row, 0).text().lower()
                if search_text not in name:
                    show = False
            
            if category != "all categories" and show:
                row_cat = self.metrics_table.item(row, 1).text().lower()
                if category != row_cat:
                    show = False
            
            if status != "all status" and show:
                row_status = self.metrics_table.item(row, 6).text().lower()
                if status not in row_status:
                    show = False
            
            self.metrics_table.setRowHidden(row, not show)
    
    def _refresh_data(self):
        """Refresh all data"""
        self._load_data()
    
    def _export_report(self):
        """Export metrics report"""
        if not self.engine:
            return
        
        report = self.engine.generate_report("executive")
        # Would save to file or show preview
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.information(
            self,
            "Report Generated",
            f"Executive Summary Report\n\n"
            f"Overall Score: {report['overall_score']:.1f}%\n"
            f"Targets Met: {report['targets_met']}\n"
            f"At Risk: {report['at_risk']}\n"
            f"Missed: {report['targets_missed']}"
        )
