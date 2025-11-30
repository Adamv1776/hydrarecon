#!/usr/bin/env python3
"""
HydraRecon Custom Widgets
████████████████████████████████████████████████████████████████████████████████
█  ENTERPRISE-GRADE VISUAL COMPONENTS                                          █
█  Advanced UI with Glassmorphism, Animations, and Cyberpunk Aesthetics        █
████████████████████████████████████████████████████████████████████████████████
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QLineEdit, QTextEdit, QProgressBar, QGraphicsDropShadowEffect,
    QSizePolicy, QSpacerItem, QApplication, QScrollArea, QGridLayout,
    QGraphicsOpacityEffect, QStackedWidget, QComboBox, QTableWidget,
    QHeaderView, QTableWidgetItem, QAbstractItemView
)
from PyQt6.QtCore import (
    Qt, QPropertyAnimation, QEasingCurve, QSize, pyqtSignal, pyqtProperty,
    QPoint, QTimer, QParallelAnimationGroup, QSequentialAnimationGroup,
    QRect, QRectF, QPointF, QVariantAnimation, QAbstractAnimation
)
from PyQt6.QtGui import (
    QColor, QPainter, QPainterPath, QLinearGradient, QBrush, QPen,
    QFont, QFontMetrics, QIcon, QPixmap, QRadialGradient, QConicalGradient,
    QPalette, QGradient, QTransform, QImage
)
import math
import random
from datetime import datetime


# ═══════════════════════════════════════════════════════════════════════════════
#  COLOR PALETTE - CYBERPUNK NEON
# ═══════════════════════════════════════════════════════════════════════════════
NEON_GREEN = "#00ff88"
NEON_BLUE = "#0088ff"
NEON_CYAN = "#00ffff"
NEON_PURPLE = "#8800ff"
NEON_PINK = "#ff0088"
NEON_ORANGE = "#ff8800"
NEON_RED = "#ff4444"
NEON_YELLOW = "#ffff00"

GLASS_BG = "rgba(13, 17, 23, 0.7)"
GLASS_BORDER = "rgba(255, 255, 255, 0.1)"
DARK_BG = "#0a0e14"
CARD_BG = "#161b22"


class PulsingGlowEffect(QGraphicsDropShadowEffect):
    """Animated pulsing glow effect for widgets"""
    
    def __init__(self, parent=None, color="#00ff88", min_blur=5, max_blur=25):
        super().__init__(parent)
        self._color = QColor(color)
        self._min_blur = min_blur
        self._max_blur = max_blur
        self._direction = 1
        self._current_blur = min_blur
        
        self.setColor(self._color)
        self.setBlurRadius(min_blur)
        self.setOffset(0, 0)
        
        self._timer = QTimer()
        self._timer.timeout.connect(self._animate)
    
    def start(self, interval=30):
        self._timer.start(interval)
    
    def stop(self):
        self._timer.stop()
    
    def _animate(self):
        self._current_blur += self._direction * 0.5
        if self._current_blur >= self._max_blur:
            self._direction = -1
        elif self._current_blur <= self._min_blur:
            self._direction = 1
        self.setBlurRadius(self._current_blur)


class GlowingButton(QPushButton):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  NEON GLOW BUTTON                                                        ║
    ║  Animated button with pulsing glow, gradient background, and ripple      ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, text: str = "", parent=None, accent_color: str = "#00ff88"):
        super().__init__(text, parent)
        self.accent_color = accent_color
        self._glow_effect = None
        self._ripple_pos = QPointF()
        self._ripple_radius = 0
        self._ripple_opacity = 0
        self._ripple_timer = QTimer()
        self._ripple_timer.timeout.connect(self._animate_ripple)
        self.setup_glow()
        self._apply_gradient_style()
    
    def _apply_gradient_style(self):
        self.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {self.accent_color}cc, 
                    stop:0.5 {self.accent_color}88,
                    stop:1 {self.accent_color}cc);
                border: 2px solid {self.accent_color};
                border-radius: 10px;
                padding: 12px 28px;
                color: #0a0e14;
                font-weight: 700;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {self.accent_color}, 
                    stop:0.5 {self.accent_color}cc,
                    stop:1 {self.accent_color});
            }}
            QPushButton:pressed {{
                background: {self.accent_color}88;
            }}
            QPushButton:disabled {{
                background: #21262d;
                border-color: #30363d;
                color: #484f58;
            }}
        """)
    
    def setup_glow(self):
        """Setup glow effect"""
        self._glow_effect = QGraphicsDropShadowEffect(self)
        self._glow_effect.setColor(QColor(self.accent_color))
        self._glow_effect.setBlurRadius(0)
        self._glow_effect.setOffset(0, 0)
        self.setGraphicsEffect(self._glow_effect)
    
    def enterEvent(self, event):
        """Animate glow on hover"""
        super().enterEvent(event)
        self._animate_glow(30)
    
    def leaveEvent(self, event):
        """Remove glow on leave"""
        super().leaveEvent(event)
        self._animate_glow(0)
    
    def mousePressEvent(self, event):
        """Start ripple effect on click"""
        super().mousePressEvent(event)
        self._ripple_pos = event.position()
        self._ripple_radius = 0
        self._ripple_opacity = 150
        self._ripple_timer.start(16)
    
    def _animate_ripple(self):
        self._ripple_radius += 8
        self._ripple_opacity -= 5
        if self._ripple_opacity <= 0:
            self._ripple_timer.stop()
            self._ripple_opacity = 0
        self.update()
    
    def paintEvent(self, event):
        super().paintEvent(event)
        if self._ripple_opacity > 0:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            color = QColor(self.accent_color)
            color.setAlpha(int(self._ripple_opacity))
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(self._ripple_pos, self._ripple_radius, self._ripple_radius)
    
    def _animate_glow(self, target_radius: int):
        """Animate glow effect"""
        if self._glow_effect:
            animation = QPropertyAnimation(self._glow_effect, b"blurRadius")
            animation.setDuration(200)
            animation.setEndValue(target_radius)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            animation.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)


class AnimatedCard(QFrame):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  GLASSMORPHISM ANIMATED CARD                                             ║
    ║  Frosted glass effect with hover animations and gradient borders         ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    clicked = pyqtSignal()
    
    def __init__(self, parent=None, accent_color: str = "#00ff88"):
        super().__init__(parent)
        self.accent_color = accent_color
        self.setObjectName("animatedCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._hover_progress = 0
        self._setup_style()
        self._setup_shadow()
        self._animation = None
    
    def _setup_shadow(self):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setBlurRadius(20)
        shadow.setOffset(0, 4)
        self.setGraphicsEffect(shadow)
    
    def _setup_style(self):
        self.setStyleSheet(f"""
            QFrame#animatedCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(22, 27, 34, 0.95),
                    stop:1 rgba(13, 17, 23, 0.95));
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 16px;
            }}
            QFrame#animatedCard:hover {{
                border: 1px solid {self.accent_color}44;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(28, 33, 40, 0.98),
                    stop:1 rgba(22, 27, 34, 0.98));
            }}
        """)
    
    def enterEvent(self, event):
        super().enterEvent(event)
        effect = self.graphicsEffect()
        if isinstance(effect, QGraphicsDropShadowEffect):
            effect.setColor(QColor(self.accent_color).darker(150))
            effect.setBlurRadius(30)
    
    def leaveEvent(self, event):
        super().leaveEvent(event)
        effect = self.graphicsEffect()
        if isinstance(effect, QGraphicsDropShadowEffect):
            effect.setColor(QColor(0, 0, 0, 80))
            effect.setBlurRadius(20)
    
    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.clicked.emit()


class StatsCard(QFrame):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  HOLOGRAPHIC STATS CARD                                                  ║
    ║  Animated statistics display with gradient values and glow effects       ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, title: str, value: str = "0", icon: str = None,
                 accent_color: str = "#00ff88", parent=None):
        super().__init__(parent)
        self.accent_color = accent_color
        self._target_value = 0
        self._current_value = 0
        self._counter_timer = QTimer()
        self._counter_timer.timeout.connect(self._update_counter)
        self._setup_ui(title, value, icon)
        self._setup_effects()
    
    def _setup_effects(self):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setColor(QColor(self.accent_color).darker(200))
        shadow.setBlurRadius(25)
        shadow.setOffset(0, 5)
        self.setGraphicsEffect(shadow)
    
    def _setup_ui(self, title: str, value: str, icon: str):
        self.setObjectName("statsCard")
        self.setMinimumSize(200, 120)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(8)
        
        # Header with icon placeholder
        header_layout = QHBoxLayout()
        
        # Title
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet(f"""
            font-size: 13px;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 2px;
            font-weight: 600;
        """)
        
        # Accent dot indicator
        self.dot = QLabel("●")
        self.dot.setStyleSheet(f"color: {self.accent_color}; font-size: 10px;")
        
        header_layout.addWidget(self.title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.dot)
        
        # Value - Large glowing text
        self.value_label = QLabel(value)
        self.value_label.setObjectName("statsValue")
        self.value_label.setStyleSheet(f"""
            font-size: 42px;
            font-weight: 800;
            color: {self.accent_color};
            font-family: 'SF Pro Display', 'Segoe UI', -apple-system, sans-serif;
        """)
        
        # Value glow effect
        value_glow = QGraphicsDropShadowEffect()
        value_glow.setColor(QColor(self.accent_color))
        value_glow.setBlurRadius(15)
        value_glow.setOffset(0, 0)
        self.value_label.setGraphicsEffect(value_glow)
        
        # Trend indicator (placeholder)
        self.trend_label = QLabel("▲ Active")
        self.trend_label.setStyleSheet(f"""
            font-size: 11px;
            color: {self.accent_color};
            font-weight: 500;
        """)
        
        layout.addLayout(header_layout)
        layout.addWidget(self.value_label)
        layout.addWidget(self.trend_label)
        layout.addStretch()
        
        # Card style with gradient border effect
        self.setStyleSheet(f"""
            QFrame#statsCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(22, 27, 34, 0.98),
                    stop:0.5 rgba(16, 21, 28, 0.98),
                    stop:1 rgba(22, 27, 34, 0.98));
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-left: 3px solid {self.accent_color};
                border-radius: 16px;
            }}
            QFrame#statsCard:hover {{
                border: 1px solid {self.accent_color}44;
                border-left: 3px solid {self.accent_color};
            }}
        """)
    
    def setValue(self, value: str):
        """Update the displayed value with counting animation"""
        try:
            self._target_value = int(value)
            self._current_value = 0
            self._counter_timer.start(20)
        except ValueError:
            self.value_label.setText(value)
    
    def _update_counter(self):
        diff = self._target_value - self._current_value
        step = max(1, diff // 10)
        self._current_value += step
        
        if self._current_value >= self._target_value:
            self._current_value = self._target_value
            self._counter_timer.stop()
        
        self.value_label.setText(str(self._current_value))
    
    def setAccentColor(self, color: str):
        """Change accent color"""
        self.accent_color = color
        self.value_label.setStyleSheet(f"""
            font-size: 42px;
            font-weight: 800;
            color: {color};
            font-family: 'SF Pro Display', 'Segoe UI', -apple-system, sans-serif;
        """)


class CircularProgress(QWidget):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  NEON CIRCULAR PROGRESS                                                  ║
    ║  Animated ring progress with gradient glow and percentage display        ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, parent=None, size: int = 120, thickness: int = 10,
                 color: str = "#00ff88", bg_color: str = "#21262d"):
        super().__init__(parent)
        self._size = size
        self._thickness = thickness
        self._color = QColor(color)
        self._bg_color = QColor(bg_color)
        self._value = 0
        self._max_value = 100
        self._rotation_angle = 0
        self._glow_intensity = 0
        
        # Animation timer for glow pulsing
        self._glow_timer = QTimer()
        self._glow_timer.timeout.connect(self._animate_glow)
        self._glow_direction = 1
        
        self.setFixedSize(size, size)
    
    def setValue(self, value: int):
        self._value = min(max(0, value), self._max_value)
        self.update()
        
        # Start glow animation when progress updates
        if not self._glow_timer.isActive() and self._value > 0:
            self._glow_timer.start(30)
    
    def setMaxValue(self, value: int):
        self._max_value = value
        self.update()
    
    def _animate_glow(self):
        self._glow_intensity += self._glow_direction * 2
        if self._glow_intensity >= 30:
            self._glow_direction = -1
        elif self._glow_intensity <= 0:
            self._glow_direction = 1
            if self._value >= self._max_value:
                self._glow_timer.stop()
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Calculate dimensions
        size = min(self.width(), self.height())
        rect = self.rect().adjusted(
            self._thickness + 5, self._thickness + 5,
            -(self._thickness + 5), -(self._thickness + 5)
        )
        
        # Draw outer glow ring
        if self._glow_intensity > 0:
            glow_pen = QPen(self._color)
            glow_pen.setWidth(self._thickness + self._glow_intensity // 2)
            glow_color = QColor(self._color)
            glow_color.setAlpha(self._glow_intensity * 3)
            glow_pen.setColor(glow_color)
            glow_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(glow_pen)
            span_angle = int(-360 * 16 * (self._value / self._max_value))
            painter.drawArc(rect, 90 * 16, span_angle)
        
        # Draw background arc
        pen = QPen(self._bg_color)
        pen.setWidth(self._thickness)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, 0, 360 * 16)
        
        # Draw progress arc with gradient
        gradient = QConicalGradient(rect.center(), 90)
        gradient.setColorAt(0, self._color)
        gradient.setColorAt(0.5, QColor(self._color).lighter(130))
        gradient.setColorAt(1, self._color)
        
        pen = QPen(QBrush(gradient), self._thickness)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        span_angle = int(-360 * 16 * (self._value / self._max_value))
        painter.drawArc(rect, 90 * 16, span_angle)
        
        # Draw percentage text
        painter.setPen(QPen(QColor("#ffffff")))
        font = QFont("SF Pro Display", size // 5, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, 
                        f"{int(self._value)}%")
        
        # Draw label
        font.setPointSize(size // 10)
        font.setWeight(QFont.Weight.Normal)
        painter.setFont(font)
        painter.setPen(QPen(QColor("#8b949e")))
        label_rect = QRect(rect.x(), rect.y() + size // 4, rect.width(), rect.height())
        painter.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, "COMPLETE")


class ModernLineEdit(QLineEdit):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  CYBERPUNK TEXT INPUT                                                    ║
    ║  Glowing border on focus with smooth animations                          ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, placeholder: str = "", parent=None, accent_color: str = "#00ff88"):
        super().__init__(parent)
        self.accent_color = accent_color
        self.setPlaceholderText(placeholder)
        self._setup_style()
        self._setup_effects()
    
    def _setup_effects(self):
        self._glow = QGraphicsDropShadowEffect()
        self._glow.setColor(QColor(self.accent_color))
        self._glow.setBlurRadius(0)
        self._glow.setOffset(0, 0)
        self.setGraphicsEffect(self._glow)
    
    def _setup_style(self):
        self.setStyleSheet(f"""
            QLineEdit {{
                background-color: rgba(13, 17, 23, 0.9);
                border: 2px solid #30363d;
                border-radius: 12px;
                padding: 14px 18px;
                color: #e6e6e6;
                font-size: 14px;
                font-family: 'SF Pro Text', 'Segoe UI', -apple-system, sans-serif;
                selection-background-color: {self.accent_color}44;
            }}
            QLineEdit:focus {{
                border-color: {self.accent_color};
                background-color: rgba(13, 17, 23, 0.95);
            }}
            QLineEdit:hover:!focus {{
                border-color: #484f58;
                background-color: rgba(22, 27, 34, 0.9);
            }}
            QLineEdit::placeholder {{
                color: #484f58;
            }}
        """)
    
    def focusInEvent(self, event):
        super().focusInEvent(event)
        animation = QPropertyAnimation(self._glow, b"blurRadius")
        animation.setDuration(200)
        animation.setEndValue(15)
        animation.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
    
    def focusOutEvent(self, event):
        super().focusOutEvent(event)
        animation = QPropertyAnimation(self._glow, b"blurRadius")
        animation.setDuration(200)
        animation.setEndValue(0)
        animation.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)


class ConsoleOutput(QTextEdit):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  MATRIX-STYLE CONSOLE OUTPUT                                             ║
    ║  Terminal emulation with syntax highlighting and typing effects          ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self._typing_queue = []
        self._typing_timer = QTimer()
        self._typing_timer.timeout.connect(self._type_next_char)
        self._current_text = ""
        self._setup_style()
    
    def _setup_style(self):
        self.setStyleSheet("""
            QTextEdit {
                background-color: rgba(5, 8, 12, 0.98);
                border: 1px solid #21262d;
                border-radius: 12px;
                padding: 16px;
                font-family: "JetBrains Mono", "Fira Code", "SF Mono", "Consolas", monospace;
                font-size: 13px;
                color: #00ff88;
                line-height: 1.5;
            }
            QTextEdit QScrollBar:vertical {
                background: #0a0e14;
                width: 8px;
                border-radius: 4px;
            }
            QTextEdit QScrollBar::handle:vertical {
                background: #21262d;
                border-radius: 4px;
                min-height: 40px;
            }
            QTextEdit QScrollBar::handle:vertical:hover {
                background: #30363d;
            }
        """)
    
    def append_with_typing(self, text: str, delay: int = 10):
        """Append text with typewriter effect"""
        self._typing_queue.extend(list(text + "\n"))
        if not self._typing_timer.isActive():
            self._typing_timer.start(delay)
    
    def _type_next_char(self):
        if self._typing_queue:
            char = self._typing_queue.pop(0)
            cursor = self.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            cursor.insertText(char)
            self.setTextCursor(cursor)
            self.ensureCursorVisible()
        else:
            self._typing_timer.stop()
    
    def append_command(self, command: str):
        """Append a command (shown in cyan)"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.append(f'<span style="color: #484f58;">[{timestamp}]</span> '
                   f'<span style="color: #0088ff;">❯</span> '
                   f'<span style="color: #00ffff;">{command}</span>')
    
    def append_output(self, output: str):
        """Append regular output"""
        self.append(f'<span style="color: #c9d1d9;">{output}</span>')
    
    def append_success(self, message: str):
        """Append success message (green)"""
        self.append(f'<span style="color: #00ff88;">✓ {message}</span>')
    
    def append_error(self, message: str):
        """Append error message (red)"""
        self.append(f'<span style="color: #ff4444;">✗ {message}</span>')
    
    def append_warning(self, message: str):
        """Append warning message (yellow)"""
        self.append(f'<span style="color: #ffaa00;">⚠ {message}</span>')
    
    def append_info(self, message: str):
        """Append info message (blue)"""
        self.append(f'<span style="color: #0088ff;">ℹ {message}</span>')
    
    def append_scan_result(self, result_type: str, data: str):
        """Append formatted scan result"""
        colors = {
            'port': '#00ff88',
            'vuln': '#ff4444',
            'credential': '#ffaa00',
            'host': '#0088ff',
            'service': '#8b5cf6'
        }
        color = colors.get(result_type, '#c9d1d9')
        icon = {'port': '🔓', 'vuln': '🔴', 'credential': '🔑', 'host': '💻', 'service': '⚙️'}.get(result_type, '•')
        self.append(f'<span style="color: {color};">{icon} {data}</span>')


class SeverityBadge(QLabel):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  GLOWING SEVERITY BADGE                                                  ║
    ║  Color-coded severity indicator with glow effect                         ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    COLORS = {
        'critical': ('#ff0040', '💀'),
        'high': ('#ff4444', '🔴'),
        'medium': ('#ff8800', '🟠'),
        'low': ('#00ff88', '🟢'),
        'info': ('#0088ff', 'ℹ️')
    }
    
    def __init__(self, severity: str = "info", parent=None):
        super().__init__(parent)
        self._setup_glow()
        self.setSeverity(severity)
    
    def _setup_glow(self):
        self._glow = QGraphicsDropShadowEffect()
        self._glow.setBlurRadius(10)
        self._glow.setOffset(0, 0)
        self.setGraphicsEffect(self._glow)
    
    def setSeverity(self, severity: str):
        severity = severity.lower()
        color, icon = self.COLORS.get(severity, self.COLORS['info'])
        
        self._glow.setColor(QColor(color))
        
        self.setText(f"{icon} {severity.upper()}")
        self.setStyleSheet(f"""
            QLabel {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {color}cc, stop:1 {color}88);
                color: white;
                padding: 6px 14px;
                border-radius: 14px;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 1px;
            }}
        """)


class NavButton(QPushButton):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  SIDEBAR NAVIGATION BUTTON                                               ║
    ║  Animated navigation with sliding indicator and glow effects             ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, text: str, icon_char: str = "◆", parent=None, accent_color: str = "#00ff88"):
        super().__init__(text, parent)
        self.accent_color = accent_color
        self.icon_char = icon_char
        self.setCheckable(True)
        self._setup_style()
        self._setup_effects()
    
    def _setup_effects(self):
        self._glow = QGraphicsDropShadowEffect()
        self._glow.setColor(QColor(self.accent_color))
        self._glow.setBlurRadius(0)
        self._glow.setOffset(0, 0)
        self.setGraphicsEffect(self._glow)
    
    def _setup_style(self):
        self.setText(f"  {self.icon_char}  {self.text()}")
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                border: none;
                border-radius: 10px;
                padding: 16px 20px;
                text-align: left;
                color: #6e7681;
                font-size: 14px;
                font-weight: 500;
                font-family: 'SF Pro Text', 'Segoe UI', -apple-system, sans-serif;
            }}
            QPushButton:hover {{
                background-color: rgba(255, 255, 255, 0.05);
                color: #e6e6e6;
            }}
            QPushButton:checked {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {self.accent_color}22, 
                    stop:1 transparent);
                color: {self.accent_color};
                border-left: 3px solid {self.accent_color};
                border-radius: 0 10px 10px 0;
            }}
        """)
    
    def enterEvent(self, event):
        super().enterEvent(event)
        if not self.isChecked():
            animation = QPropertyAnimation(self._glow, b"blurRadius")
            animation.setDuration(150)
            animation.setEndValue(8)
            animation.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
    
    def leaveEvent(self, event):
        super().leaveEvent(event)
        if not self.isChecked():
            animation = QPropertyAnimation(self._glow, b"blurRadius")
            animation.setDuration(150)
            animation.setEndValue(0)
            animation.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)


class ScanProgressWidget(QWidget):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  ANIMATED SCAN PROGRESS BAR                                              ║
    ║  Gradient progress with pulse animation and status indicators            ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._pulse_pos = 0
        self._pulse_timer = QTimer()
        self._pulse_timer.timeout.connect(self._animate_pulse)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        # Header row with status and percentage
        header = QHBoxLayout()
        
        # Status label with icon
        self.status_label = QLabel("⚡ Ready")
        self.status_label.setStyleSheet("""
            font-size: 15px;
            font-weight: 600;
            color: #e6e6e6;
            font-family: 'SF Pro Display', 'Segoe UI', -apple-system, sans-serif;
        """)
        
        # Percentage label
        self.percent_label = QLabel("0%")
        self.percent_label.setStyleSheet("""
            font-size: 15px;
            font-weight: 700;
            color: #00ff88;
        """)
        
        header.addWidget(self.status_label)
        header.addStretch()
        header.addWidget(self.percent_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(10)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #21262d;
                border: none;
                border-radius: 5px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, 
                    stop:0.3 #00ffff,
                    stop:0.6 #0088ff,
                    stop:1 #8800ff);
                border-radius: 5px;
            }
        """)
        
        # Detail label
        self.detail_label = QLabel("")
        self.detail_label.setStyleSheet("""
            font-size: 12px;
            color: #6e7681;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
        """)
        
        layout.addLayout(header)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.detail_label)
    
    def _animate_pulse(self):
        # This would animate a pulsing effect (implemented via stylesheet updates)
        self._pulse_pos = (self._pulse_pos + 2) % 100
    
    def setProgress(self, value: int, status: str = "", detail: str = ""):
        self.progress_bar.setValue(value)
        self.percent_label.setText(f"{value}%")
        if status:
            self.status_label.setText(f"⚡ {status}")
        if detail:
            self.detail_label.setText(detail)
    
    def setRunning(self):
        """Set to running state"""
        self._pulse_timer.start(50)
        self.status_label.setText("🔄 Scanning...")
        self.status_label.setStyleSheet("""
            font-size: 15px;
            font-weight: 600;
            color: #00ff88;
        """)
    
    def setCompleted(self):
        """Set to completed state"""
        self._pulse_timer.stop()
        self.progress_bar.setValue(100)
        self.percent_label.setText("100%")
        self.status_label.setText("✅ Completed")
        self.status_label.setStyleSheet("""
            font-size: 15px;
            font-weight: 600;
            color: #238636;
        """)
    
    def setError(self, message: str = "Error"):
        """Set to error state"""
        self._pulse_timer.stop()
        self.status_label.setText(f"❌ {message}")
        self.status_label.setStyleSheet("""
            font-size: 15px;
            font-weight: 600;
            color: #f85149;
        """)


class TargetInputWidget(QWidget):
    """Target input with validation"""
    
    targetAdded = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        self.input = ModernLineEdit("Enter target (IP, hostname, or CIDR)")
        self.input.returnPressed.connect(self._on_add)
        
        self.add_btn = GlowingButton("Add Target")
        self.add_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                color: white;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
        """)
        self.add_btn.clicked.connect(self._on_add)
        
        layout.addWidget(self.input, stretch=1)
        layout.addWidget(self.add_btn)
    
    def _on_add(self):
        target = self.input.text().strip()
        if target:
            self.targetAdded.emit(target)
            self.input.clear()


class ExpandableSection(QWidget):
    """Collapsible/expandable section widget"""
    
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self._expanded = True
        self._content_widget = None
        self._setup_ui(title)
    
    def _setup_ui(self, title: str):
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        
        # Header
        self._header = QPushButton(f"▼ {title}")
        self._header.setStyleSheet("""
            QPushButton {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
                padding: 12px 16px;
                text-align: left;
                color: #e6e6e6;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #1c2128;
            }
        """)
        self._header.clicked.connect(self._toggle)
        
        # Content area
        self._content_area = QFrame()
        self._content_area.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-top: none;
                border-radius: 0 0 8px 8px;
            }
        """)
        self._content_layout = QVBoxLayout(self._content_area)
        self._content_layout.setContentsMargins(16, 16, 16, 16)
        
        self._layout.addWidget(self._header)
        self._layout.addWidget(self._content_area)
    
    def setContent(self, widget: QWidget):
        """Set the content widget"""
        if self._content_widget:
            self._content_layout.removeWidget(self._content_widget)
        self._content_widget = widget
        self._content_layout.addWidget(widget)
    
    def _toggle(self):
        """Toggle expanded/collapsed state"""
        self._expanded = not self._expanded
        self._content_area.setVisible(self._expanded)
        
        title = self._header.text()[2:]  # Remove arrow
        arrow = "▼" if self._expanded else "▶"
        self._header.setText(f"{arrow} {title}")


class LoadingSpinner(QWidget):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  CYBERPUNK LOADING SPINNER                                               ║
    ║  Multi-ring animated spinner with glowing trails                         ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, parent=None, size: int = 60, color: str = "#00ff88"):
        super().__init__(parent)
        self._size = size
        self._color = QColor(color)
        self._angle = 0
        self._angle2 = 180
        self._trail_angles = [0] * 8
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._rotate)
        
        self.setFixedSize(size, size)
    
    def start(self):
        """Start spinning animation"""
        self._timer.start(16)  # ~60fps
    
    def stop(self):
        """Stop spinning animation"""
        self._timer.stop()
    
    def _rotate(self):
        self._angle = (self._angle + 8) % 360
        self._angle2 = (self._angle2 - 6) % 360
        # Update trail positions
        for i in range(len(self._trail_angles) - 1, 0, -1):
            self._trail_angles[i] = self._trail_angles[i - 1]
        self._trail_angles[0] = self._angle
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        cx = self.width() // 2
        cy = self.height() // 2
        
        # Outer ring
        outer_radius = min(cx, cy) - 4
        inner_radius = outer_radius - 12
        
        # Draw glow background
        glow_color = QColor(self._color)
        glow_color.setAlpha(30)
        painter.setBrush(QBrush(glow_color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPointF(cx, cy), outer_radius + 2, outer_radius + 2)
        
        # Draw outer spinning arc
        pen = QPen(self._color)
        pen.setWidth(3)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        rect = self.rect().adjusted(6, 6, -6, -6)
        painter.drawArc(rect, int(self._angle * 16), 120 * 16)
        
        # Draw inner spinning arc (opposite direction)
        inner_rect = self.rect().adjusted(14, 14, -14, -14)
        color2 = QColor("#0088ff")
        pen.setColor(color2)
        pen.setWidth(2)
        painter.setPen(pen)
        painter.drawArc(inner_rect, int(self._angle2 * 16), 90 * 16)
        
        # Draw center dot
        painter.setBrush(QBrush(self._color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPointF(cx, cy), 4, 4)
        
        # Draw trailing dots
        for i, trail_angle in enumerate(self._trail_angles):
            alpha = 150 - (i * 15)
            if alpha > 0:
                dot_color = QColor(self._color)
                dot_color.setAlpha(alpha)
                painter.setBrush(QBrush(dot_color))
                
                rad = math.radians(trail_angle)
                x = cx + (outer_radius - 6) * math.cos(rad)
                y = cy - (outer_radius - 6) * math.sin(rad)
                painter.drawEllipse(QPointF(x, y), 3 - i * 0.2, 3 - i * 0.2)


# ═══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL SPECTACULAR WIDGETS
# ═══════════════════════════════════════════════════════════════════════════════

class NeonFrame(QFrame):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  NEON BORDERED FRAME                                                     ║
    ║  Glassmorphism container with animated neon border                       ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, parent=None, accent_color: str = "#00ff88"):
        super().__init__(parent)
        self.accent_color = accent_color
        self._border_animation_pos = 0
        self._animate_border = False
        self._border_timer = QTimer()
        self._border_timer.timeout.connect(self._update_border)
        self._setup_style()
        self._setup_shadow()
    
    def _setup_shadow(self):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setColor(QColor(self.accent_color).darker(200))
        shadow.setBlurRadius(30)
        shadow.setOffset(0, 5)
        self.setGraphicsEffect(shadow)
    
    def _setup_style(self):
        self.setStyleSheet(f"""
            NeonFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(13, 17, 23, 0.95),
                    stop:0.5 rgba(22, 27, 34, 0.90),
                    stop:1 rgba(13, 17, 23, 0.95));
                border: 2px solid {self.accent_color}44;
                border-radius: 16px;
            }}
        """)
    
    def startBorderAnimation(self):
        self._animate_border = True
        self._border_timer.start(50)
    
    def stopBorderAnimation(self):
        self._animate_border = False
        self._border_timer.stop()
    
    def _update_border(self):
        self._border_animation_pos = (self._border_animation_pos + 5) % 360
        self.update()


class HexagonWidget(QWidget):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  HEXAGONAL STATUS INDICATOR                                              ║
    ║  Sci-fi styled hexagon with pulsing glow                                 ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    clicked = pyqtSignal()
    
    def __init__(self, parent=None, size: int = 80, color: str = "#00ff88", label: str = ""):
        super().__init__(parent)
        self._size = size
        self._color = QColor(color)
        self._label = label
        self._pulse_intensity = 0
        self._pulse_direction = 1
        self._timer = QTimer()
        self._timer.timeout.connect(self._pulse)
        self._active = False
        
        self.setFixedSize(size + 20, size + 20)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
    
    def setActive(self, active: bool):
        self._active = active
        if active:
            self._timer.start(30)
        else:
            self._timer.stop()
            self._pulse_intensity = 0
        self.update()
    
    def _pulse(self):
        self._pulse_intensity += self._pulse_direction * 2
        if self._pulse_intensity >= 40:
            self._pulse_direction = -1
        elif self._pulse_intensity <= 0:
            self._pulse_direction = 1
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        cx = self.width() // 2
        cy = self.height() // 2
        
        # Create hexagon path
        path = QPainterPath()
        for i in range(6):
            angle = math.radians(60 * i - 30)
            x = cx + (self._size // 2) * math.cos(angle)
            y = cy + (self._size // 2) * math.sin(angle)
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        path.closeSubpath()
        
        # Draw glow
        if self._pulse_intensity > 0:
            glow_color = QColor(self._color)
            glow_color.setAlpha(self._pulse_intensity * 2)
            painter.setBrush(QBrush(glow_color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawPath(path)
        
        # Draw fill
        fill_color = QColor(self._color)
        fill_color.setAlpha(50 if self._active else 20)
        painter.setBrush(QBrush(fill_color))
        painter.setPen(QPen(self._color, 2))
        painter.drawPath(path)
        
        # Draw label
        if self._label:
            painter.setPen(QPen(self._color))
            font = QFont("SF Pro Display", 10, QFont.Weight.Bold)
            painter.setFont(font)
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self._label)
    
    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.clicked.emit()


class DataStreamWidget(QWidget):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  MATRIX DATA STREAM                                                      ║
    ║  Animated falling data visualization like the Matrix                     ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, parent=None, color: str = "#00ff88"):
        super().__init__(parent)
        self._color = QColor(color)
        self._streams = []
        self._chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"
        self._timer = QTimer()
        self._timer.timeout.connect(self._update_streams)
        
        self.setMinimumSize(200, 150)
        self._init_streams()
    
    def _init_streams(self):
        self._streams = []
        for i in range(20):
            self._streams.append({
                'x': random.randint(0, self.width() if self.width() > 0 else 200),
                'y': random.randint(-100, 0),
                'speed': random.uniform(2, 8),
                'chars': [random.choice(self._chars) for _ in range(random.randint(5, 15))]
            })
    
    def start(self):
        self._timer.start(50)
    
    def stop(self):
        self._timer.stop()
    
    def _update_streams(self):
        for stream in self._streams:
            stream['y'] += stream['speed']
            if stream['y'] > self.height() + 100:
                stream['y'] = random.randint(-100, -20)
                stream['x'] = random.randint(0, self.width())
                stream['chars'] = [random.choice(self._chars) for _ in range(random.randint(5, 15))]
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        
        font = QFont("JetBrains Mono", 12)
        painter.setFont(font)
        
        for stream in self._streams:
            for i, char in enumerate(stream['chars']):
                y = stream['y'] + i * 18
                if 0 <= y <= self.height():
                    alpha = max(0, 255 - i * 25)
                    color = QColor(self._color)
                    color.setAlpha(alpha)
                    painter.setPen(color)
                    painter.drawText(int(stream['x']), int(y), char)


class ModernTable(QTableWidget):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  CYBERPUNK DATA TABLE                                                    ║
    ║  Styled table with hover effects and alternating row colors              ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_style()
    
    def _setup_style(self):
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.setShowGrid(False)
        
        self.setStyleSheet("""
            QTableWidget {
                background-color: rgba(13, 17, 23, 0.95);
                alternate-background-color: rgba(22, 27, 34, 0.95);
                border: 1px solid #21262d;
                border-radius: 12px;
                gridline-color: transparent;
                font-family: 'SF Pro Text', 'Segoe UI', -apple-system, sans-serif;
                font-size: 13px;
                color: #c9d1d9;
            }
            QTableWidget::item {
                padding: 12px 16px;
                border-bottom: 1px solid #21262d;
            }
            QTableWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff8833, stop:1 #0088ff33);
                color: #00ff88;
            }
            QTableWidget::item:hover {
                background-color: rgba(255, 255, 255, 0.05);
            }
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #21262d, stop:1 #161b22);
                color: #8b949e;
                padding: 14px 16px;
                border: none;
                border-bottom: 2px solid #00ff88;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1px;
                font-size: 11px;
            }
            QScrollBar:vertical {
                background: #0a0e14;
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #30363d;
                border-radius: 4px;
                min-height: 40px;
            }
            QScrollBar::handle:vertical:hover {
                background: #00ff88;
            }
        """)


class GlassPanel(QFrame):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  FROSTED GLASS PANEL                                                     ║
    ║  Translucent panel with blur effect backdrop                             ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, parent=None, opacity: float = 0.8):
        super().__init__(parent)
        self._opacity = opacity
        self._setup_style()
        self._setup_shadow()
    
    def _setup_shadow(self):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 10)
        self.setGraphicsEffect(shadow)
    
    def _setup_style(self):
        alpha = int(self._opacity * 255)
        self.setStyleSheet(f"""
            GlassPanel {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(255, 255, 255, 0.1),
                    stop:0.5 rgba(255, 255, 255, 0.05),
                    stop:1 rgba(255, 255, 255, 0.1));
                border: 1px solid rgba(255, 255, 255, 0.18);
                border-radius: 20px;
            }}
        """)


class AnimatedCounter(QLabel):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  ANIMATED NUMBER COUNTER                                                 ║
    ║  Smooth counting animation for statistics                                ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, parent=None, start_value: int = 0, color: str = "#00ff88"):
        super().__init__(parent)
        self._value = start_value
        self._target = start_value
        self._color = color
        self._timer = QTimer()
        self._timer.timeout.connect(self._animate)
        self._setup_style()
        self.setText(str(start_value))
    
    def _setup_style(self):
        self.setStyleSheet(f"""
            QLabel {{
                font-size: 48px;
                font-weight: 800;
                color: {self._color};
                font-family: 'SF Pro Display', 'Segoe UI', -apple-system, sans-serif;
            }}
        """)
        
        glow = QGraphicsDropShadowEffect()
        glow.setColor(QColor(self._color))
        glow.setBlurRadius(20)
        glow.setOffset(0, 0)
        self.setGraphicsEffect(glow)
    
    def setTarget(self, value: int, duration: int = 1000):
        """Animate to target value"""
        self._target = value
        if not self._timer.isActive():
            self._timer.start(16)
    
    def _animate(self):
        diff = self._target - self._value
        if abs(diff) < 1:
            self._value = self._target
            self._timer.stop()
        else:
            self._value += diff * 0.1
        self.setText(f"{int(self._value):,}")


class StatusIndicator(QWidget):
    """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  PULSING STATUS INDICATOR                                                ║
    ║  Animated dot showing system status                                      ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    
    STATUS_COLORS = {
        'online': '#00ff88',
        'offline': '#ff4444',
        'warning': '#ffaa00',
        'scanning': '#0088ff',
        'idle': '#6e7681'
    }
    
    def __init__(self, parent=None, status: str = 'idle', size: int = 12):
        super().__init__(parent)
        self._status = status
        self._size = size
        self._pulse_radius = 0
        self._pulse_opacity = 255
        self._timer = QTimer()
        self._timer.timeout.connect(self._pulse)
        
        self.setFixedSize(size * 3, size * 3)
    
    def setStatus(self, status: str):
        self._status = status
        if status in ['online', 'scanning']:
            self._timer.start(30)
        else:
            self._timer.stop()
            self._pulse_radius = 0
        self.update()
    
    def _pulse(self):
        self._pulse_radius += 0.5
        self._pulse_opacity = max(0, 255 - self._pulse_radius * 15)
        if self._pulse_radius > 15:
            self._pulse_radius = 0
            self._pulse_opacity = 255
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        cx = self.width() // 2
        cy = self.height() // 2
        color = QColor(self.STATUS_COLORS.get(self._status, '#6e7681'))
        
        # Draw pulse ring
        if self._pulse_radius > 0:
            pulse_color = QColor(color)
            pulse_color.setAlpha(int(self._pulse_opacity * 0.5))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(pulse_color, 2))
            painter.drawEllipse(QPointF(cx, cy), 
                              self._size // 2 + self._pulse_radius,
                              self._size // 2 + self._pulse_radius)
        
        # Draw main dot
        painter.setBrush(QBrush(color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPointF(cx, cy), self._size // 2, self._size // 2)
        
        # Draw inner highlight
        highlight = QColor(255, 255, 255, 100)
        painter.setBrush(QBrush(highlight))
        painter.drawEllipse(QPointF(cx - 1, cy - 1), self._size // 4, self._size // 4)
