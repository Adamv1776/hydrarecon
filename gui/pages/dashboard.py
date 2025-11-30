#!/usr/bin/env python3
"""
HydraRecon Dashboard Page
████████████████████████████████████████████████████████████████████████████████
█  COMMAND CENTER - Real-time security metrics and system overview             █
████████████████████████████████████████████████████████████████████████████████
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QGridLayout, QScrollArea, QSizePolicy, QPushButton, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor
import random

from ..widgets import (
    StatsCard, CircularProgress, AnimatedCard, ConsoleOutput,
    GlowingButton, StatusIndicator, LoadingSpinner
)


class DashboardPage(QWidget):
    """Dashboard page with statistics and overview"""
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self._setup_ui()
        self._start_updates()
    
    def _setup_ui(self):
        """Setup the dashboard UI"""
        # Main scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        # Content widget
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(24)
        
        # Header
        header = self._create_header()
        layout.addLayout(header)
        
        # Stats cards row
        stats_layout = self._create_stats_row()
        layout.addLayout(stats_layout)
        
        # Main content area
        main_content = QHBoxLayout()
        main_content.setSpacing(24)
        
        # Left column - Activity & Quick Actions
        left_column = self._create_left_column()
        main_content.addLayout(left_column, stretch=2)
        
        # Right column - Charts & Recent
        right_column = self._create_right_column()
        main_content.addLayout(right_column, stretch=1)
        
        layout.addLayout(main_content)
        layout.addStretch()
        
        scroll.setWidget(content)
        
        # Page layout
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)
    
    def _create_header(self) -> QHBoxLayout:
        """Create the header section"""
        layout = QHBoxLayout()
        
        # Title section
        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)
        
        # Title with glow effect
        title = QLabel("Dashboard")
        title.setFont(QFont("SF Pro Display", 32, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e6e6;")
        
        title_glow = QGraphicsDropShadowEffect()
        title_glow.setColor(QColor("#00ff88"))
        title_glow.setBlurRadius(20)
        title_glow.setOffset(0, 0)
        title.setGraphicsEffect(title_glow)
        
        subtitle = QLabel("🛡️ Security Command Center")
        subtitle.setStyleSheet("""
            color: #8b949e; 
            font-size: 15px;
            font-family: 'SF Pro Text', 'Segoe UI', -apple-system, sans-serif;
        """)
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        # Status indicator
        status_layout = QHBoxLayout()
        status_layout.setSpacing(8)
        
        self.system_status = StatusIndicator(status='online')
        status_label = QLabel("System Online")
        status_label.setStyleSheet("color: #00ff88; font-weight: 600;")
        
        status_layout.addWidget(self.system_status)
        status_layout.addWidget(status_label)
        title_layout.addLayout(status_layout)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Quick action buttons
        new_scan_btn = GlowingButton("+ New Scan", accent_color="#238636")
        layout.addWidget(new_scan_btn)
        
        return layout
    
    def _create_stats_row(self) -> QHBoxLayout:
        """Create the statistics cards row"""
        layout = QHBoxLayout()
        layout.setSpacing(20)
        
        # Stats cards
        self.stats_cards = {}
        
        stats_data = [
            ("hosts", "Hosts Discovered", "0", "#00ff88"),
            ("ports", "Open Ports", "0", "#0088ff"),
            ("credentials", "Credentials Found", "0", "#a855f7"),
            ("vulnerabilities", "Vulnerabilities", "0", "#f85149"),
        ]
        
        for key, title, value, color in stats_data:
            card = StatsCard(title, value, accent_color=color)
            self.stats_cards[key] = card
            layout.addWidget(card)
        
        return layout
    
    def _create_left_column(self) -> QVBoxLayout:
        """Create the left column"""
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # Recent Activity Section
        activity_frame = QFrame()
        activity_frame.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        activity_layout = QVBoxLayout(activity_frame)
        activity_layout.setContentsMargins(20, 20, 20, 20)
        activity_layout.setSpacing(16)
        
        activity_header = QLabel("Recent Activity")
        activity_header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        activity_header.setStyleSheet("color: #e6e6e6;")
        activity_layout.addWidget(activity_header)
        
        # Console output for activity
        self.activity_console = ConsoleOutput()
        self.activity_console.setMinimumHeight(300)
        self.activity_console.append_info("HydraRecon initialized")
        self.activity_console.append_success("System ready for scanning")
        activity_layout.addWidget(self.activity_console)
        
        layout.addWidget(activity_frame)
        
        # Quick Actions Section
        actions_frame = QFrame()
        actions_frame.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        actions_layout = QVBoxLayout(actions_frame)
        actions_layout.setContentsMargins(20, 20, 20, 20)
        actions_layout.setSpacing(12)
        
        actions_header = QLabel("Quick Actions")
        actions_header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        actions_header.setStyleSheet("color: #e6e6e6;")
        actions_layout.addWidget(actions_header)
        
        # Action buttons grid
        actions_grid = QGridLayout()
        actions_grid.setSpacing(12)
        
        action_items = [
            ("🔍 Network Scan", "#21262d"),
            ("🔓 Brute Force", "#21262d"),
            ("🌐 OSINT Recon", "#21262d"),
            ("📊 Generate Report", "#21262d"),
        ]
        
        for i, (text, color) in enumerate(action_items):
            btn = QPushButton(text)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    border: 1px solid #30363d;
                    border-radius: 8px;
                    padding: 16px;
                    color: #e6e6e6;
                    font-size: 14px;
                    font-weight: 500;
                }}
                QPushButton:hover {{
                    background-color: #30363d;
                    border-color: #484f58;
                }}
            """)
            actions_grid.addWidget(btn, i // 2, i % 2)
        
        actions_layout.addLayout(actions_grid)
        layout.addWidget(actions_frame)
        
        return layout
    
    def _create_right_column(self) -> QVBoxLayout:
        """Create the right column"""
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # Scan Status Section
        status_frame = QFrame()
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        status_layout = QVBoxLayout(status_frame)
        status_layout.setContentsMargins(20, 20, 20, 20)
        status_layout.setSpacing(16)
        
        status_header = QLabel("Scan Status")
        status_header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        status_header.setStyleSheet("color: #e6e6e6;")
        status_layout.addWidget(status_header)
        
        # Circular progress
        progress_container = QHBoxLayout()
        progress_container.addStretch()
        
        self.scan_progress = CircularProgress(size=120, thickness=10)
        self.scan_progress.setValue(0)
        progress_container.addWidget(self.scan_progress)
        
        progress_container.addStretch()
        status_layout.addLayout(progress_container)
        
        # Status text
        self.status_text = QLabel("No active scan")
        self.status_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_text.setStyleSheet("color: #8b949e; font-size: 14px;")
        status_layout.addWidget(self.status_text)
        
        layout.addWidget(status_frame)
        
        # Recent Findings Section
        findings_frame = QFrame()
        findings_frame.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        findings_layout = QVBoxLayout(findings_frame)
        findings_layout.setContentsMargins(20, 20, 20, 20)
        findings_layout.setSpacing(12)
        
        findings_header = QLabel("Recent Findings")
        findings_header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        findings_header.setStyleSheet("color: #e6e6e6;")
        findings_layout.addWidget(findings_header)
        
        # Placeholder findings
        no_findings = QLabel("No recent findings")
        no_findings.setStyleSheet("color: #8b949e; padding: 20px;")
        no_findings.setAlignment(Qt.AlignmentFlag.AlignCenter)
        findings_layout.addWidget(no_findings)
        
        layout.addWidget(findings_frame)
        
        # Severity Distribution
        severity_frame = QFrame()
        severity_frame.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 12px;
            }
        """)
        severity_layout = QVBoxLayout(severity_frame)
        severity_layout.setContentsMargins(20, 20, 20, 20)
        severity_layout.setSpacing(12)
        
        severity_header = QLabel("Severity Distribution")
        severity_header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        severity_header.setStyleSheet("color: #e6e6e6;")
        severity_layout.addWidget(severity_header)
        
        # Severity bars
        severities = [
            ("Critical", 0, "#ff4444"),
            ("High", 0, "#f85149"),
            ("Medium", 0, "#d29922"),
            ("Low", 0, "#238636"),
            ("Info", 0, "#0088ff"),
        ]
        
        for name, count, color in severities:
            row = QHBoxLayout()
            
            label = QLabel(name)
            label.setStyleSheet("color: #8b949e; min-width: 60px;")
            
            bar = QFrame()
            bar.setFixedHeight(8)
            bar.setStyleSheet(f"""
                background-color: {color};
                border-radius: 4px;
            """)
            bar.setFixedWidth(10)  # Placeholder width
            
            count_label = QLabel(str(count))
            count_label.setStyleSheet("color: #e6e6e6; min-width: 30px;")
            count_label.setAlignment(Qt.AlignmentFlag.AlignRight)
            
            row.addWidget(label)
            row.addWidget(bar, stretch=1)
            row.addWidget(count_label)
            
            severity_layout.addLayout(row)
        
        layout.addWidget(severity_frame)
        layout.addStretch()
        
        return layout
    
    def _start_updates(self):
        """Start periodic UI updates"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._update_stats)
        self.update_timer.start(5000)  # Update every 5 seconds
    
    def _update_stats(self):
        """Update statistics from database"""
        # This would fetch real data from the database
        pass
    
    def update_activity(self, message: str, level: str = "info"):
        """Add activity log message"""
        if level == "success":
            self.activity_console.append_success(message)
        elif level == "error":
            self.activity_console.append_error(message)
        elif level == "warning":
            self.activity_console.append_warning(message)
        else:
            self.activity_console.append_info(message)
    
    def simulate_scan_progress(self):
        """Demo: Simulate a scan for visual effect"""
        self.system_status.setStatus('scanning')
        self.scan_progress.setValue(0)
        self.status_text.setText("Scanning in progress...")
        self.status_text.setStyleSheet("color: #00ff88; font-size: 14px;")
        
        self._scan_value = 0
        self._scan_timer = QTimer()
        self._scan_timer.timeout.connect(self._increment_scan)
        self._scan_timer.start(100)
    
    def _increment_scan(self):
        self._scan_value += random.randint(1, 3)
        if self._scan_value >= 100:
            self._scan_value = 100
            self._scan_timer.stop()
            self.system_status.setStatus('online')
            self.status_text.setText("Scan Complete!")
            self.activity_console.append_success("Network scan completed")
        self.scan_progress.setValue(self._scan_value)
