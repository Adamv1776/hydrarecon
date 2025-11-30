#!/usr/bin/env python3
"""
HydraRecon Splash Screen
████████████████████████████████████████████████████████████████████████████████
█  CYBERPUNK ANIMATED SPLASH SCREEN                                            █
█  Matrix rain, glowing logo, and loading progress                             █
████████████████████████████████████████████████████████████████████████████████
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar,
    QGraphicsDropShadowEffect, QApplication
)
from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve, 
    pyqtProperty, QRectF, QPointF
)
from PyQt6.QtGui import (
    QPainter, QColor, QFont, QLinearGradient, QRadialGradient,
    QPen, QBrush, QPainterPath, QFontDatabase
)
import random
import math


class MatrixRainWidget(QWidget):
    """Matrix-style falling code background"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._streams = []
        self._chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン<>{}[]/*-+="
        self._timer = QTimer()
        self._timer.timeout.connect(self._update)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        
    def start(self):
        self._init_streams()
        self._timer.start(50)
    
    def stop(self):
        self._timer.stop()
    
    def _init_streams(self):
        self._streams = []
        col_width = 20
        num_cols = self.width() // col_width + 1
        
        for i in range(num_cols):
            self._streams.append({
                'x': i * col_width,
                'y': random.randint(-500, 0),
                'speed': random.uniform(4, 12),
                'chars': [random.choice(self._chars) for _ in range(random.randint(10, 30))],
                'opacity': random.uniform(0.3, 0.8)
            })
    
    def _update(self):
        for stream in self._streams:
            stream['y'] += stream['speed']
            if stream['y'] > self.height() + 200:
                stream['y'] = random.randint(-300, -50)
                stream['x'] = random.randint(0, self.width())
                stream['chars'] = [random.choice(self._chars) for _ in range(random.randint(10, 30))]
                stream['opacity'] = random.uniform(0.3, 0.8)
            # Randomly change a character
            if random.random() < 0.1 and stream['chars']:
                idx = random.randint(0, len(stream['chars']) - 1)
                stream['chars'][idx] = random.choice(self._chars)
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        
        font = QFont("JetBrains Mono", 14)
        painter.setFont(font)
        
        for stream in self._streams:
            for i, char in enumerate(stream['chars']):
                y = stream['y'] + i * 20
                if 0 <= y <= self.height():
                    # Head character is brightest
                    if i == 0:
                        color = QColor("#ffffff")
                        color.setAlphaF(stream['opacity'])
                    else:
                        # Fade from green to dark
                        alpha = max(0, stream['opacity'] - (i * 0.03))
                        intensity = max(0, 255 - i * 15)
                        color = QColor(0, intensity, int(intensity * 0.5))
                        color.setAlphaF(alpha)
                    
                    painter.setPen(color)
                    painter.drawText(int(stream['x']), int(y), char)


class GlowingLogo(QWidget):
    """Animated glowing logo widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._glow_intensity = 0
        self._glow_direction = 1
        self._rotation = 0
        self._timer = QTimer()
        self._timer.timeout.connect(self._animate)
        self.setFixedSize(200, 200)
    
    def start(self):
        self._timer.start(30)
    
    def stop(self):
        self._timer.stop()
    
    def _animate(self):
        # Glow pulsing
        self._glow_intensity += self._glow_direction * 2
        if self._glow_intensity >= 60:
            self._glow_direction = -1
        elif self._glow_intensity <= 20:
            self._glow_direction = 1
        
        # Slow rotation
        self._rotation = (self._rotation + 0.5) % 360
        
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        cx = self.width() // 2
        cy = self.height() // 2
        radius = 70
        
        # Draw outer glow rings
        for i in range(5):
            glow_radius = radius + 20 + i * 8
            alpha = max(0, self._glow_intensity - i * 10)
            color = QColor("#00ff88")
            color.setAlpha(alpha)
            painter.setPen(QPen(color, 2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QPointF(cx, cy), glow_radius, glow_radius)
        
        # Draw hexagon shield
        path = QPainterPath()
        for i in range(6):
            angle = math.radians(60 * i - 30 + self._rotation)
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        path.closeSubpath()
        
        # Fill with gradient
        gradient = QRadialGradient(cx, cy, radius)
        gradient.setColorAt(0, QColor(0, 255, 136, 100))
        gradient.setColorAt(0.7, QColor(0, 136, 255, 50))
        gradient.setColorAt(1, QColor(0, 0, 0, 0))
        
        painter.setBrush(QBrush(gradient))
        painter.setPen(QPen(QColor("#00ff88"), 3))
        painter.drawPath(path)
        
        # Draw inner hexagon
        inner_path = QPainterPath()
        inner_radius = radius * 0.6
        for i in range(6):
            angle = math.radians(60 * i - 30 - self._rotation * 0.5)
            x = cx + inner_radius * math.cos(angle)
            y = cy + inner_radius * math.sin(angle)
            if i == 0:
                inner_path.moveTo(x, y)
            else:
                inner_path.lineTo(x, y)
        inner_path.closeSubpath()
        
        painter.setBrush(QBrush(QColor(0, 136, 255, 80)))
        painter.setPen(QPen(QColor("#0088ff"), 2))
        painter.drawPath(inner_path)
        
        # Draw hydra icon (stylized H)
        painter.setPen(QPen(QColor("#00ff88"), 4))
        font = QFont("SF Pro Display", 48, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "⚡")


class CyberProgressBar(QWidget):
    """Cyberpunk-styled progress bar"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = 0
        self._segments = 30
        self._animation_offset = 0
        self._timer = QTimer()
        self._timer.timeout.connect(self._animate)
        self.setFixedHeight(20)
        self.setMinimumWidth(400)
    
    def start(self):
        self._timer.start(50)
    
    def stop(self):
        self._timer.stop()
    
    def setValue(self, value: int):
        self._value = min(100, max(0, value))
        self.update()
    
    def _animate(self):
        self._animation_offset = (self._animation_offset + 1) % 10
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        width = self.width()
        height = self.height()
        segment_width = width // self._segments
        filled_segments = int(self._segments * (self._value / 100))
        
        # Draw background segments
        for i in range(self._segments):
            x = i * segment_width + 2
            rect_width = segment_width - 4
            
            if i < filled_segments:
                # Filled segment with gradient
                gradient = QLinearGradient(x, 0, x + rect_width, 0)
                gradient.setColorAt(0, QColor("#00ff88"))
                gradient.setColorAt(0.5, QColor("#00ffff"))
                gradient.setColorAt(1, QColor("#0088ff"))
                painter.setBrush(QBrush(gradient))
                
                # Glow effect on recent segments
                if i >= filled_segments - 3:
                    glow_alpha = 150 - (filled_segments - 1 - i) * 40
                    glow = QColor("#00ff88")
                    glow.setAlpha(glow_alpha)
                    painter.setPen(QPen(glow, 2))
                else:
                    painter.setPen(Qt.PenStyle.NoPen)
            else:
                # Empty segment
                painter.setBrush(QBrush(QColor("#21262d")))
                painter.setPen(Qt.PenStyle.NoPen)
            
            painter.drawRoundedRect(x, 2, rect_width, height - 4, 3, 3)
        
        # Draw scanning line effect
        if self._value < 100:
            scan_x = (filled_segments * segment_width) + self._animation_offset
            gradient = QLinearGradient(scan_x - 20, 0, scan_x + 20, 0)
            gradient.setColorAt(0, QColor(0, 255, 136, 0))
            gradient.setColorAt(0.5, QColor(0, 255, 136, 200))
            gradient.setColorAt(1, QColor(0, 255, 136, 0))
            painter.setBrush(QBrush(gradient))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRect(scan_x - 20, 0, 40, height)


class SplashScreen(QWidget):
    """Main splash screen widget"""
    
    def __init__(self):
        super().__init__()
        self._loading_step = 0
        self._loading_messages = [
            "Initializing neural network...",
            "Loading vulnerability databases...",
            "Calibrating scanner modules...",
            "Connecting to threat intelligence...",
            "Activating security protocols...",
            "Preparing reconnaissance tools...",
            "Loading OSINT modules...",
            "Initializing Hydra engine...",
            "Configuring Nmap profiles...",
            "System ready!"
        ]
        self._setup_ui()
    
    def _setup_ui(self):
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(700, 500)
        
        # Center on screen
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Container with background
        container = QWidget()
        container.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(10, 14, 20, 0.98),
                    stop:0.5 rgba(5, 8, 12, 0.98),
                    stop:1 rgba(10, 14, 20, 0.98));
                border: 2px solid #00ff8844;
                border-radius: 20px;
            }
        """)
        
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(40, 30, 40, 30)
        container_layout.setSpacing(20)
        
        # Matrix rain background
        self.matrix_rain = MatrixRainWidget(container)
        self.matrix_rain.setGeometry(0, 0, 700, 500)
        
        # Logo
        logo_layout = QHBoxLayout()
        logo_layout.addStretch()
        self.logo = GlowingLogo()
        logo_layout.addWidget(self.logo)
        logo_layout.addStretch()
        container_layout.addLayout(logo_layout)
        
        # Title
        title = QLabel("HYDRARECON")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            font-family: 'SF Pro Display', 'Segoe UI', -apple-system, sans-serif;
            font-size: 42px;
            font-weight: 800;
            color: #00ff88;
            letter-spacing: 8px;
        """)
        title_glow = QGraphicsDropShadowEffect()
        title_glow.setColor(QColor("#00ff88"))
        title_glow.setBlurRadius(30)
        title_glow.setOffset(0, 0)
        title.setGraphicsEffect(title_glow)
        container_layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Enterprise Security Assessment Suite")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("""
            font-family: 'SF Pro Text', 'Segoe UI', -apple-system, sans-serif;
            font-size: 14px;
            color: #8b949e;
            letter-spacing: 3px;
        """)
        container_layout.addWidget(subtitle)
        
        container_layout.addSpacing(30)
        
        # Progress bar
        progress_layout = QHBoxLayout()
        progress_layout.addStretch()
        self.progress_bar = CyberProgressBar()
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addStretch()
        container_layout.addLayout(progress_layout)
        
        # Loading message
        self.loading_label = QLabel(self._loading_messages[0])
        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.loading_label.setStyleSheet("""
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 12px;
            color: #0088ff;
        """)
        container_layout.addWidget(self.loading_label)
        
        # Version
        version = QLabel("v1.0.0 | Nmap • Hydra • OSINT")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version.setStyleSheet("""
            font-size: 11px;
            color: #484f58;
        """)
        container_layout.addWidget(version)
        
        layout.addWidget(container)
        
        # Loading timer
        self._load_timer = QTimer()
        self._load_timer.timeout.connect(self._update_loading)
    
    def start_loading(self):
        """Start the loading animation"""
        self.matrix_rain.start()
        self.logo.start()
        self.progress_bar.start()
        self._load_timer.start(300)
    
    def _update_loading(self):
        """Update loading progress"""
        self._loading_step += 1
        progress = min(100, self._loading_step * 10)
        self.progress_bar.setValue(progress)
        
        if self._loading_step < len(self._loading_messages):
            self.loading_label.setText(self._loading_messages[self._loading_step])
        
        if progress >= 100:
            self._load_timer.stop()
            self.loading_label.setText("✓ System ready!")
            self.loading_label.setStyleSheet("""
                font-family: 'JetBrains Mono', 'Fira Code', monospace;
                font-size: 12px;
                color: #00ff88;
            """)
    
    def finish(self):
        """Stop animations and close"""
        self.matrix_rain.stop()
        self.logo.stop()
        self.progress_bar.stop()
        self._load_timer.stop()
        self.close()


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    splash = SplashScreen()
    splash.show()
    splash.start_loading()
    
    # Demo - close after 5 seconds
    QTimer.singleShot(5000, splash.finish)
    
    sys.exit(app.exec())
