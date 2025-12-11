"""
Holographic Display System for HydraRecon

Advanced holographic UI elements:
- 3D floating interfaces
- Holographic data displays
- Sci-fi inspired visualizations
- Depth-based rendering
- Looking glass support
- Light field display integration
"""

import math
import time
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable
from enum import Enum

try:
    from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QPropertyAnimation, QEasingCurve
    from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QFrame
    from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QFont, QLinearGradient, QRadialGradient
    from PyQt6.QtOpenGLWidgets import QOpenGLWidget
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    QWidget = object
    QObject = object

try:
    from OpenGL.GL import *
    OPENGL_AVAILABLE = True
except ImportError:
    OPENGL_AVAILABLE = False


class HoloStyle(Enum):
    """Holographic visual styles"""
    CYAN = "cyan"
    ORANGE = "orange"
    GREEN = "green"
    PURPLE = "purple"
    RED = "red"
    WHITE = "white"
    RAINBOW = "rainbow"


class HoloElementType(Enum):
    """Holographic element types"""
    PANEL = "panel"
    CHART = "chart"
    GLOBE = "globe"
    RING = "ring"
    GRID = "grid"
    TEXT = "text"
    METER = "meter"
    GRAPH = "graph"


@dataclass
class HoloColor:
    """Holographic color with glow"""
    primary: Tuple[int, int, int]
    glow: Tuple[int, int, int]
    intensity: float = 1.0
    
    @staticmethod
    def from_style(style: HoloStyle) -> 'HoloColor':
        """Create color from style"""
        styles = {
            HoloStyle.CYAN: HoloColor((0, 200, 255), (0, 100, 200)),
            HoloStyle.ORANGE: HoloColor((255, 150, 50), (200, 100, 20)),
            HoloStyle.GREEN: HoloColor((50, 255, 100), (20, 200, 50)),
            HoloStyle.PURPLE: HoloColor((180, 100, 255), (120, 50, 200)),
            HoloStyle.RED: HoloColor((255, 50, 50), (200, 20, 20)),
            HoloStyle.WHITE: HoloColor((255, 255, 255), (180, 180, 200)),
        }
        return styles.get(style, styles[HoloStyle.CYAN])


class HoloEffect:
    """Base class for holographic effects"""
    
    def __init__(self):
        self.time = 0.0
        self.enabled = True
    
    def update(self, dt: float):
        """Update effect"""
        self.time += dt
    
    def apply(self, painter: 'QPainter', rect: 'QRect'):
        """Apply effect to painter"""
        pass


class ScanlineEffect(HoloEffect):
    """Horizontal scanline effect"""
    
    def __init__(self, speed: float = 50.0, gap: int = 4, alpha: int = 30):
        super().__init__()
        self.speed = speed
        self.gap = gap
        self.alpha = alpha
    
    def apply(self, painter, rect):
        if not PYQT_AVAILABLE or not self.enabled:
            return
        
        offset = int(self.time * self.speed) % self.gap
        
        pen = QPen(QColor(255, 255, 255, self.alpha))
        painter.setPen(pen)
        
        for y in range(offset, rect.height(), self.gap):
            painter.drawLine(rect.x(), rect.y() + y, 
                           rect.x() + rect.width(), rect.y() + y)


class FlickerEffect(HoloEffect):
    """Random flicker effect"""
    
    def __init__(self, frequency: float = 8.0, intensity: float = 0.1):
        super().__init__()
        self.frequency = frequency
        self.intensity = intensity
        self.current_flicker = 1.0
    
    def update(self, dt: float):
        super().update(dt)
        
        import random
        if random.random() < self.frequency * dt:
            self.current_flicker = 1.0 - random.random() * self.intensity
        else:
            self.current_flicker = min(1.0, self.current_flicker + dt * 2)


class PulseEffect(HoloEffect):
    """Pulsing glow effect"""
    
    def __init__(self, frequency: float = 1.0, min_intensity: float = 0.7):
        super().__init__()
        self.frequency = frequency
        self.min_intensity = min_intensity
    
    def get_intensity(self) -> float:
        """Get current pulse intensity"""
        pulse = (math.sin(self.time * self.frequency * 2 * math.pi) + 1) / 2
        return self.min_intensity + pulse * (1 - self.min_intensity)


class GlitchEffect(HoloEffect):
    """Digital glitch effect"""
    
    def __init__(self, probability: float = 0.02):
        super().__init__()
        self.probability = probability
        self.glitch_offset = (0, 0)
        self.glitch_active = False
        self.glitch_duration = 0.0
    
    def update(self, dt: float):
        super().update(dt)
        
        import random
        
        if self.glitch_active:
            self.glitch_duration -= dt
            if self.glitch_duration <= 0:
                self.glitch_active = False
                self.glitch_offset = (0, 0)
        else:
            if random.random() < self.probability:
                self.glitch_active = True
                self.glitch_duration = random.uniform(0.05, 0.15)
                self.glitch_offset = (
                    random.randint(-10, 10),
                    random.randint(-3, 3)
                )


if PYQT_AVAILABLE:
    class HoloPanel(QFrame):
        """
        Holographic panel widget
        
        A floating panel with sci-fi holographic styling.
        """
        
        def __init__(self, parent=None, style: HoloStyle = HoloStyle.CYAN):
            super().__init__(parent)
            
            self.holo_style = style
            self.holo_color = HoloColor.from_style(style)
            
            # Effects
            self.scanlines = ScanlineEffect()
            self.flicker = FlickerEffect()
            self.pulse = PulseEffect()
            self.glitch = GlitchEffect()
            
            self.effects = [self.scanlines, self.flicker, self.pulse, self.glitch]
            
            # Animation
            self.boot_progress = 0.0
            self.is_booting = True
            
            # Setup
            self.setStyleSheet("background: transparent;")
            self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            
            # Update timer
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self._update)
            self.update_timer.start(16)  # ~60 FPS
        
        def _update(self):
            """Update effects"""
            dt = 0.016
            
            for effect in self.effects:
                effect.update(dt)
            
            if self.is_booting:
                self.boot_progress = min(1.0, self.boot_progress + dt * 2)
                if self.boot_progress >= 1.0:
                    self.is_booting = False
            
            self.update()
        
        def paintEvent(self, event):
            """Custom paint for holographic effect"""
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            rect = self.rect()
            
            # Apply glitch offset
            if self.glitch.glitch_active:
                painter.translate(*self.glitch.glitch_offset)
            
            # Calculate intensity
            intensity = self.pulse.get_intensity() * self.flicker.current_flicker
            
            if self.is_booting:
                intensity *= self.boot_progress
            
            r, g, b = self.holo_color.primary
            gr, gg, gb = self.holo_color.glow
            
            # Background glow
            glow_gradient = QRadialGradient(
                rect.center().x(), rect.center().y(),
                max(rect.width(), rect.height()) * 0.7
            )
            glow_gradient.setColorAt(0, QColor(gr, gg, gb, int(40 * intensity)))
            glow_gradient.setColorAt(1, QColor(gr, gg, gb, 0))
            
            painter.fillRect(rect, glow_gradient)
            
            # Border
            border_pen = QPen(QColor(r, g, b, int(200 * intensity)))
            border_pen.setWidth(2)
            painter.setPen(border_pen)
            
            # Draw frame with cut corners
            corner_size = 15
            points = [
                (corner_size, 0),
                (rect.width() - corner_size, 0),
                (rect.width(), corner_size),
                (rect.width(), rect.height() - corner_size),
                (rect.width() - corner_size, rect.height()),
                (corner_size, rect.height()),
                (0, rect.height() - corner_size),
                (0, corner_size),
            ]
            
            from PyQt6.QtGui import QPolygon
            from PyQt6.QtCore import QPoint
            
            polygon = QPolygon([QPoint(int(x), int(y)) for x, y in points])
            
            # Fill
            fill_gradient = QLinearGradient(0, 0, 0, rect.height())
            fill_gradient.setColorAt(0, QColor(gr, gg, gb, int(30 * intensity)))
            fill_gradient.setColorAt(0.5, QColor(gr, gg, gb, int(15 * intensity)))
            fill_gradient.setColorAt(1, QColor(gr, gg, gb, int(25 * intensity)))
            
            painter.setBrush(QBrush(fill_gradient))
            painter.drawPolygon(polygon)
            
            # Apply scanlines
            self.scanlines.apply(painter, rect)
            
            # Corner decorations
            self._draw_corner_decorations(painter, rect, intensity)
            
            painter.end()
        
        def _draw_corner_decorations(self, painter, rect, intensity: float):
            """Draw corner decorations"""
            r, g, b = self.holo_color.primary
            color = QColor(r, g, b, int(255 * intensity))
            
            pen = QPen(color)
            pen.setWidth(1)
            painter.setPen(pen)
            
            dec_size = 8
            
            # Top left
            painter.drawLine(0, dec_size + 15, 0, 25)
            painter.drawLine(dec_size + 15, 0, 25, 0)
            
            # Top right
            painter.drawLine(rect.width(), dec_size + 15, rect.width(), 25)
            painter.drawLine(rect.width() - dec_size - 15, 0, rect.width() - 25, 0)
            
            # Bottom left
            painter.drawLine(0, rect.height() - dec_size - 15, 0, rect.height() - 25)
            painter.drawLine(dec_size + 15, rect.height(), 25, rect.height())
            
            # Bottom right
            painter.drawLine(rect.width(), rect.height() - dec_size - 15, 
                           rect.width(), rect.height() - 25)
            painter.drawLine(rect.width() - dec_size - 15, rect.height(), 
                           rect.width() - 25, rect.height())


    class HoloMeter(QWidget):
        """
        Holographic meter/gauge widget
        """
        
        valueChanged = pyqtSignal(float)
        
        def __init__(self, parent=None, style: HoloStyle = HoloStyle.CYAN):
            super().__init__(parent)
            
            self.holo_style = style
            self.holo_color = HoloColor.from_style(style)
            
            self._value = 0.0
            self._min_value = 0.0
            self._max_value = 100.0
            self._label = "METER"
            self._unit = "%"
            
            # Effects
            self.pulse = PulseEffect(frequency=0.5)
            
            self.setMinimumSize(150, 150)
            
            # Animation
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self._update)
            self.update_timer.start(16)
        
        def _update(self):
            self.pulse.update(0.016)
            self.update()
        
        def setValue(self, value: float):
            """Set meter value"""
            self._value = max(self._min_value, min(self._max_value, value))
            self.valueChanged.emit(self._value)
            self.update()
        
        def value(self) -> float:
            return self._value
        
        def setRange(self, min_val: float, max_val: float):
            """Set value range"""
            self._min_value = min_val
            self._max_value = max_val
        
        def setLabel(self, label: str):
            """Set meter label"""
            self._label = label
        
        def setUnit(self, unit: str):
            """Set unit string"""
            self._unit = unit
        
        def paintEvent(self, event):
            """Paint holographic meter"""
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            rect = self.rect()
            center_x = rect.width() / 2
            center_y = rect.height() / 2
            radius = min(rect.width(), rect.height()) / 2 - 20
            
            intensity = self.pulse.get_intensity()
            
            r, g, b = self.holo_color.primary
            gr, gg, gb = self.holo_color.glow
            
            # Background arc
            pen = QPen(QColor(gr, gg, gb, int(50 * intensity)))
            pen.setWidth(8)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            
            arc_rect = rect.adjusted(20, 20, -20, -20)
            painter.drawArc(arc_rect, 225 * 16, -270 * 16)
            
            # Value arc
            normalized = (self._value - self._min_value) / (self._max_value - self._min_value)
            arc_angle = int(270 * normalized)
            
            pen = QPen(QColor(r, g, b, int(255 * intensity)))
            pen.setWidth(8)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            
            painter.drawArc(arc_rect, 225 * 16, -arc_angle * 16)
            
            # Glow effect
            pen = QPen(QColor(r, g, b, int(100 * intensity)))
            pen.setWidth(12)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.drawArc(arc_rect, 225 * 16, -arc_angle * 16)
            
            # Value text
            font = QFont("Consolas", 24, QFont.Weight.Bold)
            painter.setFont(font)
            painter.setPen(QColor(r, g, b, int(255 * intensity)))
            
            value_text = f"{self._value:.0f}"
            text_rect = painter.fontMetrics().boundingRect(value_text)
            painter.drawText(
                int(center_x - text_rect.width() / 2),
                int(center_y + text_rect.height() / 4),
                value_text
            )
            
            # Unit
            font = QFont("Consolas", 12)
            painter.setFont(font)
            painter.drawText(
                int(center_x - painter.fontMetrics().horizontalAdvance(self._unit) / 2),
                int(center_y + 25),
                self._unit
            )
            
            # Label
            font = QFont("Consolas", 10)
            painter.setFont(font)
            painter.setPen(QColor(r, g, b, int(180 * intensity)))
            painter.drawText(
                int(center_x - painter.fontMetrics().horizontalAdvance(self._label) / 2),
                int(rect.height() - 10),
                self._label
            )
            
            painter.end()


    class HoloRing(QWidget):
        """
        Holographic rotating ring indicator
        """
        
        def __init__(self, parent=None, style: HoloStyle = HoloStyle.CYAN):
            super().__init__(parent)
            
            self.holo_style = style
            self.holo_color = HoloColor.from_style(style)
            
            self.rotation = 0.0
            self.rotation_speed = 30.0  # degrees per second
            self.segments = 8
            self.active_segments = [True] * self.segments
            
            self.setMinimumSize(100, 100)
            
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self._update)
            self.update_timer.start(16)
        
        def _update(self):
            self.rotation += self.rotation_speed * 0.016
            self.rotation %= 360
            self.update()
        
        def setActiveSegments(self, segments: List[bool]):
            """Set which segments are active"""
            self.active_segments = segments
        
        def paintEvent(self, event):
            """Paint holographic ring"""
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            rect = self.rect()
            center_x = rect.width() / 2
            center_y = rect.height() / 2
            radius = min(rect.width(), rect.height()) / 2 - 10
            
            r, g, b = self.holo_color.primary
            gr, gg, gb = self.holo_color.glow
            
            painter.translate(center_x, center_y)
            painter.rotate(self.rotation)
            
            segment_angle = 360 / self.segments
            gap = 5  # degrees
            
            for i in range(self.segments):
                if i < len(self.active_segments) and self.active_segments[i]:
                    alpha = 255
                    emission = 1.0
                else:
                    alpha = 80
                    emission = 0.3
                
                start_angle = i * segment_angle + gap / 2
                span_angle = segment_angle - gap
                
                # Draw segment
                pen = QPen(QColor(r, g, b, alpha))
                pen.setWidth(4)
                pen.setCapStyle(Qt.PenCapStyle.RoundCap)
                painter.setPen(pen)
                
                arc_rect = self.rect().adjusted(
                    int(-center_x + 10), int(-center_y + 10),
                    int(-center_x - 10), int(-center_y - 10)
                )
                
                painter.drawArc(arc_rect, int(start_angle * 16), int(span_angle * 16))
                
                # Glow
                if emission > 0.5:
                    pen = QPen(QColor(r, g, b, int(60 * emission)))
                    pen.setWidth(8)
                    painter.setPen(pen)
                    painter.drawArc(arc_rect, int(start_angle * 16), int(span_angle * 16))
            
            painter.end()


    class HoloGraph(QWidget):
        """
        Holographic line graph widget
        """
        
        def __init__(self, parent=None, style: HoloStyle = HoloStyle.CYAN):
            super().__init__(parent)
            
            self.holo_style = style
            self.holo_color = HoloColor.from_style(style)
            
            self.data: List[float] = []
            self.max_points = 100
            self._label = "GRAPH"
            self._auto_range = True
            self._min_val = 0.0
            self._max_val = 100.0
            
            self.scanlines = ScanlineEffect(gap=3, alpha=15)
            
            self.setMinimumSize(200, 100)
            
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self._update)
            self.update_timer.start(16)
        
        def _update(self):
            self.scanlines.update(0.016)
            self.update()
        
        def addPoint(self, value: float):
            """Add a data point"""
            self.data.append(value)
            if len(self.data) > self.max_points:
                self.data.pop(0)
        
        def setData(self, data: List[float]):
            """Set all data"""
            self.data = data[-self.max_points:]
        
        def setLabel(self, label: str):
            """Set graph label"""
            self._label = label
        
        def setRange(self, min_val: float, max_val: float):
            """Set Y-axis range"""
            self._auto_range = False
            self._min_val = min_val
            self._max_val = max_val
        
        def paintEvent(self, event):
            """Paint holographic graph"""
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            rect = self.rect()
            margin = 10
            graph_rect = rect.adjusted(margin, margin + 20, -margin, -margin - 20)
            
            r, g, b = self.holo_color.primary
            gr, gg, gb = self.holo_color.glow
            
            # Background
            painter.fillRect(graph_rect, QColor(gr, gg, gb, 20))
            
            # Border
            pen = QPen(QColor(r, g, b, 100))
            pen.setWidth(1)
            painter.setPen(pen)
            painter.drawRect(graph_rect)
            
            # Grid lines
            pen = QPen(QColor(r, g, b, 30))
            painter.setPen(pen)
            
            for i in range(1, 4):
                y = graph_rect.y() + (graph_rect.height() * i / 4)
                painter.drawLine(graph_rect.x(), int(y), 
                               graph_rect.x() + graph_rect.width(), int(y))
            
            for i in range(1, 5):
                x = graph_rect.x() + (graph_rect.width() * i / 5)
                painter.drawLine(int(x), graph_rect.y(), 
                               int(x), graph_rect.y() + graph_rect.height())
            
            # Scanlines
            self.scanlines.apply(painter, graph_rect)
            
            # Draw data
            if len(self.data) > 1:
                # Auto range
                if self._auto_range:
                    min_val = min(self.data)
                    max_val = max(self.data)
                    if max_val == min_val:
                        max_val = min_val + 1
                else:
                    min_val = self._min_val
                    max_val = self._max_val
                
                # Create path
                from PyQt6.QtGui import QPainterPath
                
                path = QPainterPath()
                fill_path = QPainterPath()
                
                for i, value in enumerate(self.data):
                    x = graph_rect.x() + (i / (len(self.data) - 1)) * graph_rect.width()
                    normalized = (value - min_val) / (max_val - min_val)
                    y = graph_rect.y() + graph_rect.height() * (1 - normalized)
                    
                    if i == 0:
                        path.moveTo(x, y)
                        fill_path.moveTo(x, graph_rect.y() + graph_rect.height())
                        fill_path.lineTo(x, y)
                    else:
                        path.lineTo(x, y)
                        fill_path.lineTo(x, y)
                
                # Close fill path
                fill_path.lineTo(graph_rect.x() + graph_rect.width(), 
                               graph_rect.y() + graph_rect.height())
                fill_path.closeSubpath()
                
                # Fill gradient
                fill_gradient = QLinearGradient(0, graph_rect.y(), 
                                               0, graph_rect.y() + graph_rect.height())
                fill_gradient.setColorAt(0, QColor(r, g, b, 80))
                fill_gradient.setColorAt(1, QColor(r, g, b, 10))
                
                painter.fillPath(fill_path, fill_gradient)
                
                # Draw line
                pen = QPen(QColor(r, g, b, 255))
                pen.setWidth(2)
                painter.setPen(pen)
                painter.drawPath(path)
                
                # Glow
                pen = QPen(QColor(r, g, b, 80))
                pen.setWidth(4)
                painter.setPen(pen)
                painter.drawPath(path)
            
            # Label
            font = QFont("Consolas", 10)
            painter.setFont(font)
            painter.setPen(QColor(r, g, b, 200))
            painter.drawText(margin, margin + 15, self._label)
            
            # Current value
            if self.data:
                value_text = f"{self.data[-1]:.1f}"
                painter.drawText(
                    rect.width() - margin - painter.fontMetrics().horizontalAdvance(value_text),
                    margin + 15,
                    value_text
                )
            
            painter.end()


    class HoloDataGrid(QWidget):
        """
        Holographic data grid/table widget
        """
        
        def __init__(self, parent=None, style: HoloStyle = HoloStyle.CYAN):
            super().__init__(parent)
            
            self.holo_style = style
            self.holo_color = HoloColor.from_style(style)
            
            self.headers: List[str] = []
            self.data: List[List[str]] = []
            self.selected_row = -1
            
            self.row_height = 25
            self.header_height = 30
            
            self.scanlines = ScanlineEffect(gap=3, alpha=10)
            
            self.setMinimumSize(300, 150)
            
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self._update)
            self.update_timer.start(16)
        
        def _update(self):
            self.scanlines.update(0.016)
            self.update()
        
        def setHeaders(self, headers: List[str]):
            """Set column headers"""
            self.headers = headers
        
        def setData(self, data: List[List[str]]):
            """Set table data"""
            self.data = data
        
        def addRow(self, row: List[str]):
            """Add a row of data"""
            self.data.append(row)
        
        def paintEvent(self, event):
            """Paint holographic data grid"""
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            rect = self.rect()
            margin = 5
            
            r, g, b = self.holo_color.primary
            gr, gg, gb = self.holo_color.glow
            
            # Background
            painter.fillRect(rect, QColor(gr, gg, gb, 15))
            
            # Border
            pen = QPen(QColor(r, g, b, 100))
            pen.setWidth(1)
            painter.setPen(pen)
            painter.drawRect(rect.adjusted(0, 0, -1, -1))
            
            # Calculate column widths
            num_cols = max(len(self.headers), max(len(row) for row in self.data) if self.data else 1)
            col_width = (rect.width() - margin * 2) / num_cols
            
            # Draw headers
            font = QFont("Consolas", 10, QFont.Weight.Bold)
            painter.setFont(font)
            painter.setPen(QColor(r, g, b, 255))
            
            for i, header in enumerate(self.headers):
                x = margin + i * col_width
                painter.drawText(int(x), int(margin + 18), header[:int(col_width / 8)])
            
            # Header line
            painter.drawLine(margin, self.header_height, 
                           rect.width() - margin, self.header_height)
            
            # Draw data rows
            font = QFont("Consolas", 9)
            painter.setFont(font)
            
            for row_idx, row in enumerate(self.data):
                y = self.header_height + (row_idx + 1) * self.row_height
                
                if y > rect.height():
                    break
                
                # Selection highlight
                if row_idx == self.selected_row:
                    painter.fillRect(
                        margin, int(y - self.row_height + 5),
                        rect.width() - margin * 2, self.row_height,
                        QColor(r, g, b, 40)
                    )
                
                # Alternating row colors
                if row_idx % 2 == 1:
                    painter.fillRect(
                        margin, int(y - self.row_height + 5),
                        rect.width() - margin * 2, self.row_height,
                        QColor(gr, gg, gb, 10)
                    )
                
                painter.setPen(QColor(r, g, b, 200))
                
                for col_idx, cell in enumerate(row):
                    x = margin + col_idx * col_width
                    text = str(cell)[:int(col_width / 7)]
                    painter.drawText(int(x), int(y), text)
            
            # Scanlines
            self.scanlines.apply(painter, rect)
            
            painter.end()


    class HolographicDisplay(QWidget):
        """
        Complete holographic display container
        
        Provides a container for multiple holographic widgets
        with overall visual effects.
        """
        
        def __init__(self, parent=None, style: HoloStyle = HoloStyle.CYAN):
            super().__init__(parent)
            
            self.holo_style = style
            self.holo_color = HoloColor.from_style(style)
            
            self.setStyleSheet("background: transparent;")
            self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            
            self.layout = QVBoxLayout(self)
            self.layout.setContentsMargins(10, 10, 10, 10)
            self.layout.setSpacing(10)
            
            # Global effects
            self.glitch = GlitchEffect(probability=0.01)
            self.flicker = FlickerEffect(frequency=5.0, intensity=0.05)
            
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self._update)
            self.update_timer.start(16)
        
        def _update(self):
            self.glitch.update(0.016)
            self.flicker.update(0.016)
        
        def addPanel(self, title: str = "") -> HoloPanel:
            """Add a holographic panel"""
            panel = HoloPanel(self, self.holo_style)
            self.layout.addWidget(panel)
            return panel
        
        def addMeter(self, label: str = "METER") -> HoloMeter:
            """Add a holographic meter"""
            meter = HoloMeter(self, self.holo_style)
            meter.setLabel(label)
            self.layout.addWidget(meter)
            return meter
        
        def addGraph(self, label: str = "GRAPH") -> HoloGraph:
            """Add a holographic graph"""
            graph = HoloGraph(self, self.holo_style)
            graph.setLabel(label)
            self.layout.addWidget(graph)
            return graph
        
        def addDataGrid(self) -> HoloDataGrid:
            """Add a holographic data grid"""
            grid = HoloDataGrid(self, self.holo_style)
            self.layout.addWidget(grid)
            return grid


# Export all classes
__all__ = [
    'HoloStyle',
    'HoloElementType',
    'HoloColor',
    'HoloEffect',
    'ScanlineEffect',
    'FlickerEffect',
    'PulseEffect',
    'GlitchEffect',
]

if PYQT_AVAILABLE:
    __all__.extend([
        'HoloPanel',
        'HoloMeter',
        'HoloRing',
        'HoloGraph',
        'HoloDataGrid',
        'HolographicDisplay'
    ])
