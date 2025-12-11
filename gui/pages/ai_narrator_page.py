"""
HydraRecon AI Threat Narrator Page
Voice-powered AI security explanations and threat analysis
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QComboBox, QSlider, QTextEdit, QListWidget,
    QListWidgetItem, QGroupBox, QGridLayout, QProgressBar,
    QSplitter, QScrollArea, QCheckBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QIcon

from datetime import datetime
from typing import Dict, List, Optional


class NarrationWidget(QFrame):
    """Widget for a single narration entry"""
    
    def __init__(self, narration: Dict, parent=None):
        super().__init__(parent)
        self.narration = narration
        self.setup_ui()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            QFrame {
                background: #1a1a1a;
                border: 1px solid #333;
                border-radius: 6px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(self)
        
        # Header
        header = QHBoxLayout()
        
        icon = QLabel("🔊")
        icon.setStyleSheet("font-size: 20px;")
        header.addWidget(icon)
        
        title = QLabel(self.narration.get('title', 'Threat Analysis'))
        title.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 14px;")
        header.addWidget(title, 1)
        
        severity = self.narration.get('severity', 'medium')
        severity_colors = {
            'info': '#0088ff',
            'low': '#00ff00',
            'medium': '#ffff00',
            'high': '#ff8800',
            'critical': '#ff0000'
        }
        
        sev_label = QLabel(severity.upper())
        sev_label.setStyleSheet(f"""
            color: {severity_colors.get(severity, '#888')};
            font-size: 11px;
            font-weight: bold;
            padding: 2px 6px;
            background: {severity_colors.get(severity, '#888')}22;
            border-radius: 3px;
        """)
        header.addWidget(sev_label)
        
        layout.addLayout(header)
        
        # Content
        content = QLabel(self.narration.get('content', ''))
        content.setWordWrap(True)
        content.setStyleSheet("color: #ccc; line-height: 1.4;")
        layout.addWidget(content)
        
        # Actions
        actions = QHBoxLayout()
        
        play_btn = QPushButton("▶ Play")
        play_btn.setStyleSheet("""
            QPushButton {
                background: #003300;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 4px 12px;
                border-radius: 3px;
            }
            QPushButton:hover { background: #004400; }
        """)
        actions.addWidget(play_btn)
        
        copy_btn = QPushButton("📋 Copy")
        copy_btn.setStyleSheet("""
            QPushButton {
                background: #1a1a1a;
                color: #888;
                border: 1px solid #333;
                padding: 4px 12px;
                border-radius: 3px;
            }
            QPushButton:hover { background: #252525; }
        """)
        actions.addWidget(copy_btn)
        
        actions.addStretch()
        
        timestamp = QLabel(self.narration.get('timestamp', ''))
        timestamp.setStyleSheet("color: #666; font-size: 10px;")
        actions.addWidget(timestamp)
        
        layout.addLayout(actions)


class VoiceWaveform(QWidget):
    """Voice waveform visualization"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.is_speaking = False
        self.bars = [0] * 30
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.animate)
        self.timer.start(50)
        
        self.setMinimumHeight(60)
    
    def set_speaking(self, speaking: bool):
        self.is_speaking = speaking
    
    def animate(self):
        import random
        if self.is_speaking:
            self.bars = [random.randint(10, 50) for _ in range(30)]
        else:
            self.bars = [max(0, b - 5) for b in self.bars]
        self.update()
    
    def paintEvent(self, event):
        from PyQt6.QtGui import QPainter, QColor, QPen, QBrush
        
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Background
        painter.fillRect(self.rect(), QColor(15, 15, 15))
        
        # Draw bars
        bar_width = self.width() // (len(self.bars) + 5)
        center_y = self.height() // 2
        
        for i, height in enumerate(self.bars):
            x = 10 + i * (bar_width + 2)
            color = QColor(0, 255, 0)
            color.setAlpha(150 + int(height * 2))
            
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(color))
            
            painter.drawRect(x, center_y - height // 2, bar_width, height)
        
        painter.end()


class AIThreatNarratorPage(QWidget):
    """AI Threat Narrator page with voice-powered explanations"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.is_speaking = False
        self.narrations = []
        self.setup_ui()
        self.load_demo_narrations()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        header = QFrame()
        header.setStyleSheet("background: #111; border-bottom: 1px solid #00ff00;")
        header_layout = QHBoxLayout(header)
        
        title = QLabel("🎙️ AI Threat Narrator")
        title.setStyleSheet("color: #00ff00; font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Voice selector
        voice_label = QLabel("Voice:")
        voice_label.setStyleSheet("color: #888;")
        header_layout.addWidget(voice_label)
        
        self.voice_combo = QComboBox()
        self.voice_combo.addItems([
            "🤖 CyberAnalyst",
            "👤 Commander",
            "👩 Oracle",
            "🎭 Shadow"
        ])
        self.voice_combo.setStyleSheet("""
            QComboBox {
                background: #1a1a1a;
                color: #00ff00;
                border: 1px solid #333;
                padding: 5px;
            }
        """)
        header_layout.addWidget(self.voice_combo)
        
        # Volume
        vol_label = QLabel("Vol:")
        vol_label.setStyleSheet("color: #888;")
        header_layout.addWidget(vol_label)
        
        self.volume_slider = QSlider(Qt.Orientation.Horizontal)
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(75)
        self.volume_slider.setFixedWidth(80)
        header_layout.addWidget(self.volume_slider)
        
        layout.addWidget(header)
        
        # Main content
        content = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Controls & Queue
        left_panel = QFrame()
        left_panel.setStyleSheet("background: #0a0a0a;")
        left_layout = QVBoxLayout(left_panel)
        
        # Voice visualizer
        viz_group = QGroupBox("🔊 Voice Output")
        viz_group.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #333;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        viz_layout = QVBoxLayout(viz_group)
        
        self.waveform = VoiceWaveform()
        viz_layout.addWidget(self.waveform)
        
        # Status
        self.status_label = QLabel("Ready to narrate")
        self.status_label.setStyleSheet("color: #888; text-align: center;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        viz_layout.addWidget(self.status_label)
        
        left_layout.addWidget(viz_group)
        
        # Narration controls
        controls = QGroupBox("🎮 Controls")
        controls.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #333;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        controls_layout = QVBoxLayout(controls)
        
        self.speak_btn = QPushButton("🔊 Start Narration")
        self.speak_btn.setStyleSheet("""
            QPushButton {
                background: #003300;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 12px;
                font-size: 14px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #004400; }
        """)
        self.speak_btn.clicked.connect(self.toggle_narration)
        controls_layout.addWidget(self.speak_btn)
        
        btn_row = QHBoxLayout()
        
        prev_btn = QPushButton("⏮ Previous")
        prev_btn.setStyleSheet("""
            QPushButton {
                background: #1a1a1a;
                color: #888;
                border: 1px solid #333;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #252525; }
        """)
        btn_row.addWidget(prev_btn)
        
        next_btn = QPushButton("Next ⏭")
        next_btn.setStyleSheet("""
            QPushButton {
                background: #1a1a1a;
                color: #888;
                border: 1px solid #333;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #252525; }
        """)
        btn_row.addWidget(next_btn)
        
        controls_layout.addLayout(btn_row)
        
        left_layout.addWidget(controls)
        
        # Options
        options = QGroupBox("⚙️ Options")
        options.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #333;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        options_layout = QVBoxLayout(options)
        
        self.auto_narrate = QCheckBox("Auto-narrate new threats")
        self.auto_narrate.setChecked(True)
        self.auto_narrate.setStyleSheet("color: #00ff00;")
        options_layout.addWidget(self.auto_narrate)
        
        self.detailed_mode = QCheckBox("Detailed explanations")
        self.detailed_mode.setChecked(True)
        self.detailed_mode.setStyleSheet("color: #00ff00;")
        options_layout.addWidget(self.detailed_mode)
        
        self.recommendations = QCheckBox("Include recommendations")
        self.recommendations.setChecked(True)
        self.recommendations.setStyleSheet("color: #00ff00;")
        options_layout.addWidget(self.recommendations)
        
        left_layout.addWidget(options)
        
        # Speed control
        speed_group = QGroupBox("⏩ Speech Speed")
        speed_group.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #333;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        speed_layout = QHBoxLayout(speed_group)
        
        speed_layout.addWidget(QLabel("🐢"))
        
        self.speed_slider = QSlider(Qt.Orientation.Horizontal)
        self.speed_slider.setRange(50, 200)
        self.speed_slider.setValue(100)
        speed_layout.addWidget(self.speed_slider)
        
        speed_layout.addWidget(QLabel("🐰"))
        
        self.speed_label = QLabel("1.0x")
        self.speed_label.setStyleSheet("color: #00ff00;")
        speed_layout.addWidget(self.speed_label)
        
        self.speed_slider.valueChanged.connect(
            lambda v: self.speed_label.setText(f"{v/100:.1f}x")
        )
        
        left_layout.addWidget(speed_group)
        
        left_layout.addStretch()
        
        content.addWidget(left_panel)
        
        # Right - Narration feed
        right_panel = QFrame()
        right_panel.setStyleSheet("background: #0a0a0a;")
        right_layout = QVBoxLayout(right_panel)
        
        feed_header = QHBoxLayout()
        feed_title = QLabel("📝 Narration History")
        feed_title.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 14px;")
        feed_header.addWidget(feed_title)
        
        feed_header.addStretch()
        
        clear_btn = QPushButton("🗑️ Clear")
        clear_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #888;
                border: none;
                padding: 4px 8px;
            }
            QPushButton:hover { color: #ff0000; }
        """)
        clear_btn.clicked.connect(self.clear_narrations)
        feed_header.addWidget(clear_btn)
        
        right_layout.addLayout(feed_header)
        
        # Narration list
        self.narration_list = QVBoxLayout()
        self.narration_list.setSpacing(8)
        
        narration_container = QWidget()
        narration_container.setLayout(self.narration_list)
        
        scroll = QScrollArea()
        scroll.setWidget(narration_container)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea { border: none; background: transparent; }
            QScrollBar:vertical { background: #111; width: 8px; }
            QScrollBar::handle:vertical { background: #333; border-radius: 4px; }
        """)
        right_layout.addWidget(scroll, 1)
        
        # Quick analyze
        analyze_group = QGroupBox("🔍 Quick Analyze")
        analyze_group.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #333;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        analyze_layout = QVBoxLayout(analyze_group)
        
        self.analyze_input = QTextEdit()
        self.analyze_input.setPlaceholderText("Paste threat data, logs, or describe a security event...")
        self.analyze_input.setMaximumHeight(80)
        self.analyze_input.setStyleSheet("""
            QTextEdit {
                background: #1a1a1a;
                color: #00ff00;
                border: 1px solid #333;
            }
        """)
        analyze_layout.addWidget(self.analyze_input)
        
        analyze_btn = QPushButton("🎙️ Analyze & Narrate")
        analyze_btn.setStyleSheet("""
            QPushButton {
                background: #003300;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #004400; }
        """)
        analyze_btn.clicked.connect(self.analyze_input_text)
        analyze_layout.addWidget(analyze_btn)
        
        right_layout.addWidget(analyze_group)
        
        content.addWidget(right_panel)
        content.setSizes([350, 650])
        
        layout.addWidget(content, 1)
    
    def toggle_narration(self):
        self.is_speaking = not self.is_speaking
        self.waveform.set_speaking(self.is_speaking)
        
        if self.is_speaking:
            self.speak_btn.setText("⏹️ Stop Narration")
            self.speak_btn.setStyleSheet("""
                QPushButton {
                    background: #330000;
                    color: #ff0000;
                    border: 1px solid #ff0000;
                    padding: 12px;
                    font-size: 14px;
                    border-radius: 4px;
                }
                QPushButton:hover { background: #440000; }
            """)
            self.status_label.setText("Narrating threat analysis...")
        else:
            self.speak_btn.setText("🔊 Start Narration")
            self.speak_btn.setStyleSheet("""
                QPushButton {
                    background: #003300;
                    color: #00ff00;
                    border: 1px solid #00ff00;
                    padding: 12px;
                    font-size: 14px;
                    border-radius: 4px;
                }
                QPushButton:hover { background: #004400; }
            """)
            self.status_label.setText("Ready to narrate")
    
    def load_demo_narrations(self):
        demo_data = [
            {
                'title': 'SQL Injection Attempt Detected',
                'content': 'A SQL injection attack has been detected from IP 192.168.1.105. The attacker is attempting to extract user credentials from the database using a UNION-based injection technique. Immediate action recommended: Block the source IP and review database access logs.',
                'severity': 'high',
                'timestamp': datetime.now().strftime('%H:%M:%S')
            },
            {
                'title': 'Suspicious Port Scan Activity',
                'content': 'Multiple port scan attempts detected from a foreign IP address. The scanner is targeting common service ports including SSH, HTTP, HTTPS, and database ports. This could be reconnaissance for a larger attack.',
                'severity': 'medium',
                'timestamp': datetime.now().strftime('%H:%M:%S')
            },
            {
                'title': 'Critical: Ransomware Signature Match',
                'content': 'A file matching known ransomware signatures has been identified on endpoint WORKSTATION-42. The malware appears to be a variant of LockBit 3.0. Immediate isolation of the affected system is strongly recommended.',
                'severity': 'critical',
                'timestamp': datetime.now().strftime('%H:%M:%S')
            }
        ]
        
        for data in demo_data:
            widget = NarrationWidget(data)
            self.narration_list.addWidget(widget)
    
    def clear_narrations(self):
        while self.narration_list.count():
            item = self.narration_list.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
    
    def analyze_input_text(self):
        text = self.analyze_input.toPlainText()
        if text.strip():
            narration = {
                'title': 'Custom Analysis',
                'content': f"Analysis of input: {text[:200]}...",
                'severity': 'info',
                'timestamp': datetime.now().strftime('%H:%M:%S')
            }
            widget = NarrationWidget(narration)
            self.narration_list.insertWidget(0, widget)
            self.analyze_input.clear()
