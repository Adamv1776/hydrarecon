"""
HydraRecon Attack Replay Page
Record, replay, and analyze pentest sessions like a DVR
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QSlider, QListWidget, QListWidgetItem, QSplitter,
    QGroupBox, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QComboBox, QCheckBox, QScrollArea
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QPen, QBrush, QFont

from datetime import datetime, timedelta
from typing import Dict, List, Optional


class TimelineWidget(QWidget):
    """Widget for visualizing session timeline"""
    
    position_changed = pyqtSignal(float)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.duration = 3600  # 1 hour in seconds
        self.position = 0
        self.events = []
        self.setMinimumHeight(80)
        self.setMouseTracking(True)
    
    def set_events(self, events: List[Dict]):
        self.events = events
        self.update()
    
    def set_position(self, pos: float):
        self.position = pos
        self.update()
    
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            pos = event.position().x() / self.width()
            self.position = pos * self.duration
            self.position_changed.emit(self.position)
            self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Background
        painter.fillRect(self.rect(), QColor(15, 15, 20))
        
        # Timeline bar
        bar_height = 30
        bar_y = (self.height() - bar_height) // 2
        
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(40, 40, 45)))
        painter.drawRoundedRect(10, bar_y, self.width() - 20, bar_height, 5, 5)
        
        # Events on timeline
        event_colors = {
            'scan': QColor(0, 136, 255),
            'exploit': QColor(255, 136, 0),
            'finding': QColor(255, 0, 0),
            'note': QColor(0, 255, 0),
            'command': QColor(136, 136, 136)
        }
        
        for evt in self.events:
            evt_time = evt.get('time', 0)
            evt_type = evt.get('type', 'command')
            
            x = 10 + int((evt_time / self.duration) * (self.width() - 20))
            color = event_colors.get(evt_type, QColor(100, 100, 100))
            
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(x - 4, bar_y + bar_height // 2 - 4, 8, 8)
        
        # Position indicator
        pos_x = 10 + int((self.position / self.duration) * (self.width() - 20))
        painter.setPen(QPen(QColor(0, 255, 0), 2))
        painter.drawLine(pos_x, bar_y - 10, pos_x, bar_y + bar_height + 10)
        
        # Playhead
        painter.setBrush(QBrush(QColor(0, 255, 0)))
        from PyQt6.QtGui import QPolygon
        from PyQt6.QtCore import QPoint
        triangle = QPolygon([
            QPoint(pos_x - 6, bar_y - 10),
            QPoint(pos_x + 6, bar_y - 10),
            QPoint(pos_x, bar_y - 2)
        ])
        painter.drawPolygon(triangle)
        
        # Time labels
        painter.setPen(QPen(QColor(100, 100, 100)))
        painter.setFont(QFont('Consolas', 9))
        
        for i in range(0, self.duration + 1, 600):  # Every 10 minutes
            x = 10 + int((i / self.duration) * (self.width() - 20))
            time_str = str(timedelta(seconds=i))[:-3]  # Remove seconds
            painter.drawText(x - 15, self.height() - 5, time_str)
        
        painter.end()


class EventWidget(QFrame):
    """Widget for displaying a single replay event"""
    
    def __init__(self, event: Dict, parent=None):
        super().__init__(parent)
        self.event = event
        self.setup_ui()
    
    def setup_ui(self):
        event_type = self.event.get('type', 'command')
        
        type_colors = {
            'scan': '#0088ff',
            'exploit': '#ff8800',
            'finding': '#ff0000',
            'note': '#00ff00',
            'command': '#888888'
        }
        
        color = type_colors.get(event_type, '#888')
        
        self.setStyleSheet(f"""
            QFrame {{
                background: #1a1a1a;
                border-left: 3px solid {color};
                padding: 8px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        
        # Header
        header = QHBoxLayout()
        
        icons = {
            'scan': '🔍',
            'exploit': '💥',
            'finding': '🚨',
            'note': '📝',
            'command': '⌨️'
        }
        
        icon = QLabel(icons.get(event_type, '📌'))
        header.addWidget(icon)
        
        title = QLabel(self.event.get('title', 'Event'))
        title.setStyleSheet(f"color: {color}; font-weight: bold;")
        header.addWidget(title, 1)
        
        time = str(timedelta(seconds=int(self.event.get('time', 0))))
        time_label = QLabel(time)
        time_label.setStyleSheet("color: #666; font-size: 10px;")
        header.addWidget(time_label)
        
        layout.addLayout(header)
        
        # Details
        details = self.event.get('details', '')
        if details:
            detail_label = QLabel(details)
            detail_label.setStyleSheet("color: #888; font-size: 11px;")
            detail_label.setWordWrap(True)
            layout.addWidget(detail_label)


class AttackReplayPage(QWidget):
    """Attack Replay page for session recording and playback"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.is_playing = False
        self.is_recording = False
        self.playback_speed = 1.0
        self.current_time = 0
        self.setup_ui()
        self.load_demo_session()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        header = QFrame()
        header.setStyleSheet("background: #111; border-bottom: 1px solid #00ff00;")
        header_layout = QHBoxLayout(header)
        
        title = QLabel("🎬 Attack Replay System")
        title.setStyleSheet("color: #00ff00; font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Record button
        self.record_btn = QPushButton("⏺️ Record")
        self.record_btn.setStyleSheet("""
            QPushButton {
                background: #330000;
                color: #ff0000;
                border: 1px solid #ff0000;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #440000; }
        """)
        self.record_btn.clicked.connect(self.toggle_recording)
        header_layout.addWidget(self.record_btn)
        
        # Session selector
        session_label = QLabel("Session:")
        session_label.setStyleSheet("color: #888;")
        header_layout.addWidget(session_label)
        
        self.session_combo = QComboBox()
        self.session_combo.addItems([
            "🔴 Live Session",
            "📁 webapp_pentest_2024-01-15",
            "📁 network_assessment_2024-01-10",
            "📁 red_team_exercise_2024-01-05"
        ])
        self.session_combo.setStyleSheet("""
            QComboBox {
                background: #1a1a1a;
                color: #00ff00;
                border: 1px solid #333;
                padding: 5px;
                min-width: 200px;
            }
        """)
        header_layout.addWidget(self.session_combo)
        
        layout.addWidget(header)
        
        # Main content
        content = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Events list
        left_panel = QFrame()
        left_panel.setStyleSheet("background: #0a0a0a;")
        left_layout = QVBoxLayout(left_panel)
        
        events_title = QLabel("📋 Session Events")
        events_title.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 14px;")
        left_layout.addWidget(events_title)
        
        # Filter bar
        filter_layout = QHBoxLayout()
        
        self.filter_scans = QCheckBox("Scans")
        self.filter_scans.setChecked(True)
        self.filter_scans.setStyleSheet("color: #0088ff;")
        filter_layout.addWidget(self.filter_scans)
        
        self.filter_exploits = QCheckBox("Exploits")
        self.filter_exploits.setChecked(True)
        self.filter_exploits.setStyleSheet("color: #ff8800;")
        filter_layout.addWidget(self.filter_exploits)
        
        self.filter_findings = QCheckBox("Findings")
        self.filter_findings.setChecked(True)
        self.filter_findings.setStyleSheet("color: #ff0000;")
        filter_layout.addWidget(self.filter_findings)
        
        left_layout.addLayout(filter_layout)
        
        # Events list
        self.events_layout = QVBoxLayout()
        self.events_layout.setSpacing(4)
        
        events_container = QWidget()
        events_container.setLayout(self.events_layout)
        
        events_scroll = QScrollArea()
        events_scroll.setWidget(events_container)
        events_scroll.setWidgetResizable(True)
        events_scroll.setStyleSheet("""
            QScrollArea { border: none; background: transparent; }
            QScrollBar:vertical { background: #111; width: 8px; }
            QScrollBar::handle:vertical { background: #333; border-radius: 4px; }
        """)
        left_layout.addWidget(events_scroll, 1)
        
        content.addWidget(left_panel)
        
        # Center - Replay view
        center_panel = QFrame()
        center_panel.setStyleSheet("background: #0a0a0a;")
        center_layout = QVBoxLayout(center_panel)
        
        # Terminal output
        terminal_group = QGroupBox("🖥️ Terminal Replay")
        terminal_group.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #333;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        terminal_layout = QVBoxLayout(terminal_group)
        
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setStyleSheet("""
            QTextEdit {
                background: #0a0a0a;
                color: #00ff00;
                font-family: Consolas;
                font-size: 12px;
                border: 1px solid #333;
            }
        """)
        terminal_layout.addWidget(self.terminal_output)
        
        center_layout.addWidget(terminal_group, 1)
        
        # Timeline
        timeline_group = QGroupBox("⏱️ Timeline")
        timeline_group.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #333;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        timeline_layout = QVBoxLayout(timeline_group)
        
        self.timeline = TimelineWidget()
        self.timeline.position_changed.connect(self.on_timeline_click)
        timeline_layout.addWidget(self.timeline)
        
        # Playback controls
        controls = QHBoxLayout()
        
        self.time_label = QLabel("00:00:00")
        self.time_label.setStyleSheet("color: #00ff00; font-family: Consolas; font-size: 14px;")
        controls.addWidget(self.time_label)
        
        controls.addStretch()
        
        # Control buttons
        rewind_btn = QPushButton("⏮️")
        rewind_btn.setStyleSheet(self.control_btn_style())
        rewind_btn.clicked.connect(lambda: self.seek(-60))
        controls.addWidget(rewind_btn)
        
        back_btn = QPushButton("⏪")
        back_btn.setStyleSheet(self.control_btn_style())
        back_btn.clicked.connect(lambda: self.seek(-10))
        controls.addWidget(back_btn)
        
        self.play_btn = QPushButton("▶️")
        self.play_btn.setStyleSheet("""
            QPushButton {
                background: #003300;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 10px 20px;
                font-size: 16px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #004400; }
        """)
        self.play_btn.clicked.connect(self.toggle_playback)
        controls.addWidget(self.play_btn)
        
        forward_btn = QPushButton("⏩")
        forward_btn.setStyleSheet(self.control_btn_style())
        forward_btn.clicked.connect(lambda: self.seek(10))
        controls.addWidget(forward_btn)
        
        end_btn = QPushButton("⏭️")
        end_btn.setStyleSheet(self.control_btn_style())
        end_btn.clicked.connect(lambda: self.seek(60))
        controls.addWidget(end_btn)
        
        controls.addStretch()
        
        # Speed control
        speed_label = QLabel("Speed:")
        speed_label.setStyleSheet("color: #888;")
        controls.addWidget(speed_label)
        
        self.speed_combo = QComboBox()
        self.speed_combo.addItems(['0.5x', '1x', '2x', '4x', '8x'])
        self.speed_combo.setCurrentText('1x')
        self.speed_combo.setStyleSheet("""
            QComboBox {
                background: #1a1a1a;
                color: #00ff00;
                border: 1px solid #333;
                padding: 5px;
            }
        """)
        self.speed_combo.currentTextChanged.connect(self.update_speed)
        controls.addWidget(self.speed_combo)
        
        self.duration_label = QLabel("/ 01:00:00")
        self.duration_label.setStyleSheet("color: #888; font-family: Consolas;")
        controls.addWidget(self.duration_label)
        
        timeline_layout.addLayout(controls)
        
        center_layout.addWidget(timeline_group)
        
        content.addWidget(center_panel)
        
        # Right - Details panel
        right_panel = QFrame()
        right_panel.setStyleSheet("background: #0a0a0a;")
        right_layout = QVBoxLayout(right_panel)
        
        details_title = QLabel("📊 Event Details")
        details_title.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 14px;")
        right_layout.addWidget(details_title)
        
        # Event details
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setStyleSheet("""
            QTextEdit {
                background: #1a1a1a;
                color: #00ff00;
                border: 1px solid #333;
                font-family: Consolas;
            }
        """)
        self.details_text.setPlaceholderText("Select an event to view details...")
        right_layout.addWidget(self.details_text)
        
        # Annotations
        annot_group = QGroupBox("📝 Annotations")
        annot_group.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #333;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        annot_layout = QVBoxLayout(annot_group)
        
        self.annotation_input = QTextEdit()
        self.annotation_input.setMaximumHeight(80)
        self.annotation_input.setPlaceholderText("Add notes about this moment...")
        self.annotation_input.setStyleSheet("""
            QTextEdit {
                background: #1a1a1a;
                color: #00ff00;
                border: 1px solid #333;
            }
        """)
        annot_layout.addWidget(self.annotation_input)
        
        add_note_btn = QPushButton("📌 Add Note")
        add_note_btn.setStyleSheet("""
            QPushButton {
                background: #003300;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #004400; }
        """)
        annot_layout.addWidget(add_note_btn)
        
        right_layout.addWidget(annot_group)
        
        # Export options
        export_group = QGroupBox("📤 Export")
        export_group.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #333;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        export_layout = QVBoxLayout(export_group)
        
        export_btns = [
            ("📄 Export Report", "report"),
            ("🎬 Export Video", "video"),
            ("📊 Export Timeline", "timeline")
        ]
        
        for text, export_type in export_btns:
            btn = QPushButton(text)
            btn.setStyleSheet("""
                QPushButton {
                    background: #1a1a1a;
                    color: #888;
                    border: 1px solid #333;
                    padding: 8px;
                    text-align: left;
                    border-radius: 4px;
                }
                QPushButton:hover { background: #252525; color: #00ff00; }
            """)
            export_layout.addWidget(btn)
        
        right_layout.addWidget(export_group)
        
        content.addWidget(right_panel)
        content.setSizes([250, 550, 200])
        
        layout.addWidget(content, 1)
        
        # Playback timer
        self.playback_timer = QTimer()
        self.playback_timer.timeout.connect(self.advance_playback)
    
    def control_btn_style(self):
        return """
            QPushButton {
                background: #1a1a1a;
                color: #888;
                border: 1px solid #333;
                padding: 8px 12px;
                font-size: 14px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #252525; color: #00ff00; }
        """
    
    def load_demo_session(self):
        """Load demo session data"""
        events = [
            {'time': 0, 'type': 'command', 'title': 'Session Started', 'details': 'New pentest session initialized'},
            {'time': 60, 'type': 'scan', 'title': 'Port Scan', 'details': 'nmap -sV -sC 192.168.1.0/24'},
            {'time': 180, 'type': 'finding', 'title': 'Open Port 22', 'details': 'SSH service running OpenSSH 7.6'},
            {'time': 300, 'type': 'finding', 'title': 'Open Port 80', 'details': 'Apache 2.4.29 detected'},
            {'time': 450, 'type': 'scan', 'title': 'Vuln Scan', 'details': 'Running vulnerability assessment'},
            {'time': 600, 'type': 'finding', 'title': 'CVE-2021-41773', 'details': 'Apache path traversal vulnerability found'},
            {'time': 750, 'type': 'exploit', 'title': 'Exploit Attempt', 'details': 'Attempting CVE-2021-41773 exploitation'},
            {'time': 900, 'type': 'finding', 'title': 'Shell Access', 'details': 'Gained www-data shell access'},
            {'time': 1200, 'type': 'note', 'title': 'User Note', 'details': 'Proceeding with privilege escalation'},
            {'time': 1500, 'type': 'exploit', 'title': 'Priv Esc', 'details': 'Attempting kernel exploit'},
            {'time': 1800, 'type': 'finding', 'title': 'Root Access', 'details': 'Successfully obtained root access!'}
        ]
        
        self.timeline.set_events(events)
        
        for evt in events:
            widget = EventWidget(evt)
            self.events_layout.addWidget(widget)
        
        # Demo terminal output
        self.terminal_output.setHtml("""
<span style="color: #00ff00;">$ nmap -sV -sC 192.168.1.100</span><br>
<span style="color: #888;">Starting Nmap 7.94 ( https://nmap.org )</span><br>
<span style="color: #888;">Nmap scan report for 192.168.1.100</span><br>
<span style="color: #888;">PORT   STATE SERVICE VERSION</span><br>
<span style="color: #ff8800;">22/tcp open  ssh     OpenSSH 7.6p1</span><br>
<span style="color: #ff8800;">80/tcp open  http    Apache httpd 2.4.29</span><br>
<br>
<span style="color: #00ff00;">$ curl -s --path-as-is http://192.168.1.100/cgi-bin/.%2e/.%2e/.%2e/etc/passwd</span><br>
<span style="color: #ff0000;">root:x:0:0:root:/root:/bin/bash</span><br>
<span style="color: #ff0000;">www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin</span><br>
        """)
    
    def toggle_playback(self):
        if self.is_playing:
            self.is_playing = False
            self.play_btn.setText("▶️")
            self.playback_timer.stop()
        else:
            self.is_playing = True
            self.play_btn.setText("⏸️")
            self.playback_timer.start(100)
    
    def toggle_recording(self):
        if self.is_recording:
            self.is_recording = False
            self.record_btn.setText("⏺️ Record")
            self.record_btn.setStyleSheet("""
                QPushButton {
                    background: #330000;
                    color: #ff0000;
                    border: 1px solid #ff0000;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
                QPushButton:hover { background: #440000; }
            """)
        else:
            self.is_recording = True
            self.record_btn.setText("⏹️ Stop")
            self.record_btn.setStyleSheet("""
                QPushButton {
                    background: #ff0000;
                    color: #fff;
                    border: 1px solid #ff0000;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
            """)
    
    def advance_playback(self):
        self.current_time += 0.1 * self.playback_speed
        if self.current_time >= self.timeline.duration:
            self.current_time = self.timeline.duration
            self.toggle_playback()
        
        self.timeline.set_position(self.current_time)
        self.update_time_display()
    
    def seek(self, delta: int):
        self.current_time = max(0, min(self.timeline.duration, self.current_time + delta))
        self.timeline.set_position(self.current_time)
        self.update_time_display()
    
    def on_timeline_click(self, position: float):
        self.current_time = position
        self.update_time_display()
    
    def update_time_display(self):
        time_str = str(timedelta(seconds=int(self.current_time)))
        self.time_label.setText(time_str)
    
    def update_speed(self, speed_text: str):
        speed_map = {'0.5x': 0.5, '1x': 1.0, '2x': 2.0, '4x': 4.0, '8x': 8.0}
        self.playback_speed = speed_map.get(speed_text, 1.0)
