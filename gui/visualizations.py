#!/usr/bin/env python3
"""
HydraRecon Advanced Visualizations
Real-time network topology and threat visualization components.
"""

import math
import random
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsLineItem, QGraphicsTextItem, QGraphicsRectItem,
    QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, QTimer, QRectF, QPointF, pyqtSignal, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import (
    QPainter, QColor, QPen, QBrush, QFont, QRadialGradient,
    QLinearGradient, QPainterPath
)


@dataclass
class NetworkNode:
    """Represents a network node"""
    id: str
    ip: str
    hostname: str
    node_type: str  # 'host', 'router', 'server', 'attacker'
    x: float = 0
    y: float = 0
    ports: List[int] = None
    services: List[str] = None
    risk_level: str = 'unknown'  # 'critical', 'high', 'medium', 'low', 'unknown'
    
    def __post_init__(self):
        if self.ports is None:
            self.ports = []
        if self.services is None:
            self.services = []


class NetworkTopologyView(QGraphicsView):
    """
    Real-time network topology visualization with animated connections
    and threat indicators.
    """
    
    node_clicked = pyqtSignal(str)  # Emits node ID
    
    # Color scheme
    COLORS = {
        'background': QColor('#0a0e14'),
        'grid': QColor('#1a1f26'),
        'node_default': QColor('#21262d'),
        'node_border': QColor('#30363d'),
        'node_active': QColor('#00ff88'),
        'node_danger': QColor('#ff4444'),
        'node_warning': QColor('#ffaa00'),
        'connection': QColor('#30363d'),
        'connection_active': QColor('#00ff88'),
        'text': QColor('#e6e6e6'),
        'text_dim': QColor('#8b949e'),
    }
    
    RISK_COLORS = {
        'critical': QColor('#ff4444'),
        'high': QColor('#ff6b35'),
        'medium': QColor('#ffaa00'),
        'low': QColor('#00ff88'),
        'unknown': QColor('#8b949e'),
    }
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        
        self.nodes: Dict[str, NetworkNode] = {}
        self.node_items: Dict[str, QGraphicsEllipseItem] = {}
        self.connections: List[Tuple[str, str]] = []
        self.connection_items: List[QGraphicsLineItem] = []
        
        self._setup_view()
        self._setup_animations()
    
    def _setup_view(self):
        """Configure view settings"""
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setBackgroundBrush(QBrush(self.COLORS['background']))
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        
        # Set scene rect
        self.scene.setSceneRect(-500, -500, 1000, 1000)
        
        # Draw grid
        self._draw_grid()
    
    def _draw_grid(self):
        """Draw background grid"""
        pen = QPen(self.COLORS['grid'])
        pen.setWidth(1)
        
        # Draw grid lines
        for i in range(-500, 501, 50):
            # Vertical lines
            line = self.scene.addLine(i, -500, i, 500, pen)
            line.setZValue(-100)
            # Horizontal lines
            line = self.scene.addLine(-500, i, 500, i, pen)
            line.setZValue(-100)
    
    def _setup_animations(self):
        """Setup animation timers"""
        self.pulse_timer = QTimer()
        self.pulse_timer.timeout.connect(self._animate_pulse)
        self.pulse_timer.start(50)
        
        self.pulse_phase = 0
        self.data_flow_phase = 0
    
    def _animate_pulse(self):
        """Animate node pulses and data flow"""
        self.pulse_phase = (self.pulse_phase + 5) % 360
        self.data_flow_phase = (self.data_flow_phase + 2) % 100
        
        # Update node glows
        for node_id, item in self.node_items.items():
            node = self.nodes.get(node_id)
            if node and node.risk_level in ['critical', 'high']:
                # Pulsing glow for high-risk nodes
                opacity = 0.5 + 0.5 * math.sin(math.radians(self.pulse_phase))
                effect = item.graphicsEffect()
                if effect:
                    effect.setColor(self.RISK_COLORS[node.risk_level])
        
        self.scene.update()
    
    def add_node(self, node: NetworkNode):
        """Add a node to the topology"""
        self.nodes[node.id] = node
        
        # Create node visual
        size = 40
        if node.node_type == 'router':
            size = 50
        elif node.node_type == 'server':
            size = 45
        
        # Position node if not set
        if node.x == 0 and node.y == 0:
            angle = random.uniform(0, 2 * math.pi)
            radius = random.uniform(100, 300)
            node.x = radius * math.cos(angle)
            node.y = radius * math.sin(angle)
        
        # Create gradient for node
        gradient = QRadialGradient(size/2, size/2, size/2)
        base_color = self.RISK_COLORS.get(node.risk_level, self.COLORS['node_default'])
        gradient.setColorAt(0, base_color.lighter(150))
        gradient.setColorAt(0.5, base_color)
        gradient.setColorAt(1, base_color.darker(150))
        
        # Create ellipse
        item = self.scene.addEllipse(
            node.x - size/2, node.y - size/2,
            size, size,
            QPen(self.COLORS['node_border'], 2),
            QBrush(gradient)
        )
        item.setZValue(10)
        
        # Add glow effect
        glow = QGraphicsDropShadowEffect()
        glow.setColor(base_color)
        glow.setBlurRadius(20)
        glow.setOffset(0, 0)
        item.setGraphicsEffect(glow)
        
        self.node_items[node.id] = item
        
        # Add label
        label = self.scene.addText(node.ip, QFont("SF Mono", 8))
        label.setDefaultTextColor(self.COLORS['text'])
        label.setPos(node.x - 30, node.y + size/2 + 5)
        label.setZValue(11)
        
        # Add hostname if available
        if node.hostname:
            hostname_label = self.scene.addText(node.hostname, QFont("SF Mono", 7))
            hostname_label.setDefaultTextColor(self.COLORS['text_dim'])
            hostname_label.setPos(node.x - 30, node.y + size/2 + 18)
            hostname_label.setZValue(11)
    
    def add_connection(self, source_id: str, target_id: str, 
                       connection_type: str = 'normal'):
        """Add a connection between nodes"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return
        
        source = self.nodes[source_id]
        target = self.nodes[target_id]
        
        # Create line
        pen = QPen(self.COLORS['connection'])
        pen.setWidth(2)
        
        if connection_type == 'active':
            pen.setColor(self.COLORS['connection_active'])
            pen.setWidth(3)
        elif connection_type == 'attack':
            pen.setColor(self.COLORS['node_danger'])
            pen.setWidth(3)
            pen.setStyle(Qt.PenStyle.DashLine)
        
        line = self.scene.addLine(source.x, source.y, target.x, target.y, pen)
        line.setZValue(5)
        
        self.connections.append((source_id, target_id))
        self.connection_items.append(line)
    
    def clear_topology(self):
        """Clear all nodes and connections"""
        self.scene.clear()
        self.nodes.clear()
        self.node_items.clear()
        self.connections.clear()
        self.connection_items.clear()
        self._draw_grid()
    
    def highlight_node(self, node_id: str, highlight: bool = True):
        """Highlight a specific node"""
        if node_id in self.node_items:
            item = self.node_items[node_id]
            if highlight:
                item.setPen(QPen(self.COLORS['node_active'], 3))
            else:
                item.setPen(QPen(self.COLORS['node_border'], 2))
    
    def center_on_node(self, node_id: str):
        """Center view on a specific node"""
        if node_id in self.nodes:
            node = self.nodes[node_id]
            self.centerOn(node.x, node.y)


class ThreatRadar(QWidget):
    """
    Animated radar-style threat visualization widget.
    Shows real-time threat detection with sweeping radar effect.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(200, 200)
        
        self.threats: List[Dict] = []
        self.sweep_angle = 0
        self.detected_threats: List[Tuple[float, float, str]] = []  # (angle, distance, severity)
        
        # Animation timer
        self.timer = QTimer()
        self.timer.timeout.connect(self._update_radar)
        self.timer.start(30)
    
    def _update_radar(self):
        """Update radar sweep"""
        self.sweep_angle = (self.sweep_angle + 2) % 360
        self.update()
    
    def add_threat(self, severity: str, angle: float = None, distance: float = None):
        """Add a threat blip to the radar"""
        if angle is None:
            angle = random.uniform(0, 360)
        if distance is None:
            distance = random.uniform(0.3, 0.9)
        
        self.detected_threats.append((angle, distance, severity))
    
    def clear_threats(self):
        """Clear all threats"""
        self.detected_threats.clear()
    
    def paintEvent(self, event):
        """Paint the radar"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Get dimensions
        w = self.width()
        h = self.height()
        center_x = w // 2
        center_y = h // 2
        radius = min(w, h) // 2 - 20
        
        # Draw background
        painter.fillRect(self.rect(), QColor('#0a0e14'))
        
        # Draw concentric circles
        pen = QPen(QColor('#1a2332'))
        pen.setWidth(1)
        painter.setPen(pen)
        
        for i in range(1, 5):
            r = radius * i // 4
            painter.drawEllipse(center_x - r, center_y - r, r * 2, r * 2)
        
        # Draw crosshairs
        painter.drawLine(center_x - radius, center_y, center_x + radius, center_y)
        painter.drawLine(center_x, center_y - radius, center_x, center_y + radius)
        
        # Draw sweep
        sweep_gradient = QRadialGradient(center_x, center_y, radius)
        sweep_gradient.setColorAt(0, QColor(0, 255, 136, 100))
        sweep_gradient.setColorAt(1, QColor(0, 255, 136, 0))
        
        painter.setBrush(QBrush(sweep_gradient))
        painter.setPen(Qt.PenStyle.NoPen)
        
        # Draw sweep cone
        path = QPainterPath()
        path.moveTo(center_x, center_y)
        path.arcTo(
            center_x - radius, center_y - radius,
            radius * 2, radius * 2,
            self.sweep_angle, 30
        )
        path.lineTo(center_x, center_y)
        painter.drawPath(path)
        
        # Draw sweep line
        angle_rad = math.radians(self.sweep_angle)
        end_x = center_x + radius * math.cos(angle_rad)
        end_y = center_y - radius * math.sin(angle_rad)
        
        pen = QPen(QColor('#00ff88'))
        pen.setWidth(2)
        painter.setPen(pen)
        painter.drawLine(int(center_x), int(center_y), int(end_x), int(end_y))
        
        # Draw threat blips
        for threat_angle, distance, severity in self.detected_threats:
            angle_diff = (self.sweep_angle - threat_angle) % 360
            
            # Blips fade after sweep passes
            if angle_diff < 90:
                alpha = int(255 * (1 - angle_diff / 90))
            else:
                alpha = 50
            
            # Color based on severity
            if severity == 'critical':
                color = QColor(255, 68, 68, alpha)
            elif severity == 'high':
                color = QColor(255, 107, 53, alpha)
            elif severity == 'medium':
                color = QColor(255, 170, 0, alpha)
            else:
                color = QColor(0, 255, 136, alpha)
            
            # Calculate position
            t_rad = math.radians(threat_angle)
            t_x = center_x + radius * distance * math.cos(t_rad)
            t_y = center_y - radius * distance * math.sin(t_rad)
            
            # Draw blip
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(int(t_x) - 5, int(t_y) - 5, 10, 10)
        
        # Draw center point
        painter.setBrush(QBrush(QColor('#00ff88')))
        painter.drawEllipse(center_x - 4, center_y - 4, 8, 8)
        
        # Draw outer ring
        pen = QPen(QColor('#00ff88'))
        pen.setWidth(2)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(center_x - radius, center_y - radius, radius * 2, radius * 2)


class SeverityGauge(QWidget):
    """
    Animated gauge showing overall security severity level.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(150, 150)
        
        self._value = 0  # 0-100
        self._target_value = 0
        self._label = "SECURE"
        
        # Animation
        self.timer = QTimer()
        self.timer.timeout.connect(self._animate)
        self.timer.start(16)
    
    def setValue(self, value: int, label: str = None):
        """Set the gauge value (0-100)"""
        self._target_value = max(0, min(100, value))
        if label:
            self._label = label
    
    def _animate(self):
        """Animate value changes"""
        if abs(self._value - self._target_value) > 0.5:
            self._value += (self._target_value - self._value) * 0.1
            self.update()
    
    def paintEvent(self, event):
        """Paint the gauge"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w = self.width()
        h = self.height()
        center_x = w // 2
        center_y = h // 2
        radius = min(w, h) // 2 - 15
        
        # Draw background
        painter.fillRect(self.rect(), QColor('#0d1117'))
        
        # Draw arc background
        pen = QPen(QColor('#21262d'))
        pen.setWidth(12)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        
        rect = QRectF(center_x - radius, center_y - radius, radius * 2, radius * 2)
        painter.drawArc(rect, 225 * 16, -270 * 16)
        
        # Draw value arc with gradient color
        if self._value < 30:
            color = QColor('#00ff88')  # Green - Safe
        elif self._value < 60:
            color = QColor('#ffaa00')  # Yellow - Warning
        elif self._value < 80:
            color = QColor('#ff6b35')  # Orange - High
        else:
            color = QColor('#ff4444')  # Red - Critical
        
        pen = QPen(color)
        pen.setWidth(12)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        
        span = int(-270 * 16 * (self._value / 100))
        painter.drawArc(rect, 225 * 16, span)
        
        # Draw center text
        painter.setPen(QPen(QColor('#e6e6e6')))
        font = QFont("SF Pro Display", radius // 3, QFont.Weight.Bold)
        painter.setFont(font)
        
        value_text = f"{int(self._value)}"
        text_rect = QRectF(center_x - radius, center_y - radius // 2, radius * 2, radius)
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, value_text)
        
        # Draw label
        font.setPointSize(radius // 6)
        font.setWeight(QFont.Weight.Normal)
        painter.setFont(font)
        painter.setPen(QPen(color))
        
        label_rect = QRectF(center_x - radius, center_y + radius // 6, radius * 2, radius // 2)
        painter.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, self._label)


class LiveActivityFeed(QWidget):
    """
    Real-time scrolling activity feed showing scan events.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.activities: List[Dict] = []
        self.max_activities = 50
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header
        header = QLabel("⚡ LIVE ACTIVITY")
        header.setStyleSheet("""
            QLabel {
                background-color: #161b22;
                color: #00ff88;
                font-size: 12px;
                font-weight: bold;
                padding: 10px;
                border-bottom: 1px solid #21262d;
            }
        """)
        layout.addWidget(header)
        
        # Activity container
        self.container = QWidget()
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setContentsMargins(8, 8, 8, 8)
        self.container_layout.setSpacing(4)
        self.container_layout.addStretch()
        
        self.container.setStyleSheet("""
            QWidget {
                background-color: #0d1117;
            }
        """)
        
        layout.addWidget(self.container)
    
    def add_activity(self, activity_type: str, message: str, 
                     severity: str = 'info'):
        """Add an activity to the feed"""
        # Create activity widget
        activity = QFrame()
        activity.setStyleSheet(f"""
            QFrame {{
                background-color: #161b22;
                border-radius: 6px;
                border-left: 3px solid {self._get_severity_color(severity)};
            }}
        """)
        
        layout = QHBoxLayout(activity)
        layout.setContentsMargins(10, 8, 10, 8)
        
        # Icon
        icon_map = {
            'scan': '🔍',
            'found': '✓',
            'warning': '⚠️',
            'error': '✗',
            'credential': '🔑',
            'vulnerability': '🛡️',
        }
        icon = QLabel(icon_map.get(activity_type, '•'))
        icon.setStyleSheet("font-size: 14px;")
        layout.addWidget(icon)
        
        # Message
        msg = QLabel(message)
        msg.setStyleSheet(f"""
            color: #e6e6e6;
            font-size: 12px;
        """)
        msg.setWordWrap(True)
        layout.addWidget(msg, stretch=1)
        
        # Add to container
        self.container_layout.insertWidget(0, activity)
        
        # Remove old activities
        while self.container_layout.count() > self.max_activities + 1:  # +1 for stretch
            item = self.container_layout.takeAt(self.max_activities)
            if item.widget():
                item.widget().deleteLater()
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            'critical': '#ff4444',
            'high': '#ff6b35',
            'medium': '#ffaa00',
            'low': '#00ff88',
            'info': '#0088ff',
        }
        return colors.get(severity, '#8b949e')
    
    def clear(self):
        """Clear all activities"""
        while self.container_layout.count() > 1:  # Keep stretch
            item = self.container_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
