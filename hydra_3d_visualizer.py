#!/usr/bin/env python3
"""
HydraSense 3D Environment Reconstructor
========================================
Immersive 3D visualization using WiFi signal triangulation
to detect and visualize objects, people, and room layout.
"""

import sys
import json
import math
import time
import threading
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
import random

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QStatusBar, QSplitter, QPushButton
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QPointF
from PyQt6.QtGui import (
    QPainter, QColor, QPen, QBrush, QFont, QLinearGradient,
    QRadialGradient, QPainterPath, QPolygonF, QTransform
)


# ============== Configuration ==============

ESP32_HOST = "192.168.0.139"
ESP32_PORT = 80
ROOM_WIDTH = 6.0  # meters
ROOM_DEPTH = 5.0  # meters
ROOM_HEIGHT = 2.7  # meters
PRIMARY_POS = (0.5, 0.5)  # Primary sensor position
REMOTE_POS = (5.0, 0.5)   # Remote sensor position (15ft / 4.5m away)


# ============== Data Structures ==============

@dataclass
class DetectedEntity:
    """A detected entity in the environment."""
    mac: str
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    rssi_primary: int = -100
    rssi_remote: int = -100
    velocity: Tuple[float, float, float] = (0, 0, 0)
    last_seen: float = 0
    signal_strength: float = 0
    is_moving: bool = False
    entity_type: str = "unknown"  # person, device, object
    confidence: float = 0.0
    trail: List[Tuple[float, float, float]] = field(default_factory=list)


@dataclass
class WallSegment:
    """Detected wall segment from signal reflections."""
    start: Tuple[float, float]
    end: Tuple[float, float]
    confidence: float = 0.0
    

@dataclass
class SignalHeatPoint:
    """Signal strength heat map point."""
    x: float
    y: float
    strength: float
    timestamp: float


# ============== Triangulation & Environment Reconstruction ==============

class EnvironmentReconstructor:
    """Reconstructs 3D environment from WiFi signals."""
    
    RSSI_REF = -35  # RSSI at 1 meter
    PATH_LOSS = 2.5  # Path loss exponent
    
    def __init__(self):
        self.entities: Dict[str, DetectedEntity] = {}
        self.walls: List[WallSegment] = []
        self.heat_map: List[SignalHeatPoint] = []
        self.position_history: Dict[str, List[Tuple[float, float, float]]] = defaultdict(list)
        
        # Initialize default room walls
        self._init_room_walls()
        
    def _init_room_walls(self):
        """Initialize room boundary walls."""
        self.walls = [
            WallSegment((0, 0), (ROOM_WIDTH, 0), 1.0),  # Front
            WallSegment((ROOM_WIDTH, 0), (ROOM_WIDTH, ROOM_DEPTH), 1.0),  # Right
            WallSegment((ROOM_WIDTH, ROOM_DEPTH), (0, ROOM_DEPTH), 1.0),  # Back
            WallSegment((0, ROOM_DEPTH), (0, 0), 1.0),  # Left
        ]
        
    def rssi_to_distance(self, rssi: int) -> float:
        """Convert RSSI to estimated distance."""
        if rssi >= 0 or rssi < -100:
            return 10.0
        distance = 10 ** ((self.RSSI_REF - rssi) / (10 * self.PATH_LOSS))
        return min(max(distance, 0.1), 15.0)
    
    def triangulate(self, rssi1: int, rssi2: int) -> Tuple[float, float]:
        """Triangulate position from two RSSI measurements."""
        d1 = self.rssi_to_distance(rssi1)
        d2 = self.rssi_to_distance(rssi2)
        
        # Distance between sensors
        dx = REMOTE_POS[0] - PRIMARY_POS[0]
        dy = REMOTE_POS[1] - PRIMARY_POS[1]
        d = math.sqrt(dx*dx + dy*dy)
        
        if d < 0.1:
            return (ROOM_WIDTH/2, ROOM_DEPTH/2)
        
        # Trilateration
        a = (d1*d1 - d2*d2 + d*d) / (2*d)
        h_sq = d1*d1 - a*a
        
        if h_sq < 0:
            # Weighted average fallback
            w1, w2 = 1/(d1+0.1), 1/(d2+0.1)
            total = w1 + w2
            x = (PRIMARY_POS[0]*w1 + REMOTE_POS[0]*w2) / total
            y = (PRIMARY_POS[1]*w1 + REMOTE_POS[1]*w2) / total
        else:
            h = math.sqrt(h_sq)
            x = PRIMARY_POS[0] + a * dx / d
            y = PRIMARY_POS[1] + a * dy / d + h
        
        # Clamp to room bounds with margin
        x = max(0.2, min(ROOM_WIDTH-0.2, x))
        y = max(0.2, min(ROOM_DEPTH-0.2, y))
        
        return (x, y)
    
    def process_detection(self, mac: str, rssi: int, is_remote: bool, frame_type: int = 0):
        """Process a WiFi detection."""
        now = time.time()
        
        if mac not in self.entities:
            self.entities[mac] = DetectedEntity(mac=mac)
        
        entity = self.entities[mac]
        entity.last_seen = now
        
        if is_remote:
            entity.rssi_remote = rssi
        else:
            entity.rssi_primary = rssi
        
        # Calculate signal strength (0-1)
        avg_rssi = (entity.rssi_primary + entity.rssi_remote) / 2
        entity.signal_strength = max(0, min(1, (avg_rssi + 100) / 60))
        
        # Triangulate if we have both measurements
        if entity.rssi_primary > -95 and entity.rssi_remote > -95:
            x, y = self.triangulate(entity.rssi_primary, entity.rssi_remote)
            
            # Smooth with history
            history = self.position_history[mac]
            history.append((x, y, now))
            if len(history) > 15:
                history.pop(0)
            
            # Exponential moving average
            if len(history) > 1:
                smooth_x, smooth_y = 0, 0
                total_w = 0
                for i, (hx, hy, ht) in enumerate(history):
                    age = now - ht
                    w = math.exp(-age * 2) * (i + 1)
                    smooth_x += hx * w
                    smooth_y += hy * w
                    total_w += w
                if total_w > 0:
                    x = smooth_x / total_w
                    y = smooth_y / total_w
            
            # Detect movement
            if len(history) >= 3:
                old_x, old_y, old_t = history[-3]
                dt = now - old_t
                if dt > 0:
                    vx = (x - old_x) / dt
                    vy = (y - old_y) / dt
                    speed = math.sqrt(vx*vx + vy*vy)
                    entity.is_moving = speed > 0.15
                    entity.velocity = (vx, vy, 0)
            
            entity.x = x
            entity.y = y
            entity.z = 0.9  # Assume typical height
            
            # Add to trail
            entity.trail.append((x, y, now))
            if len(entity.trail) > 50:
                entity.trail.pop(0)
            
            # Classify entity type
            if entity.is_moving and entity.signal_strength > 0.4:
                entity.entity_type = "person"
                entity.confidence = 0.8
            elif entity.signal_strength > 0.6:
                entity.entity_type = "device"
                entity.confidence = 0.7
            else:
                entity.entity_type = "object"
                entity.confidence = 0.5
            
            # Add heat map point
            self.heat_map.append(SignalHeatPoint(x, y, entity.signal_strength, now))
            if len(self.heat_map) > 500:
                self.heat_map.pop(0)
        
        return entity
    
    def get_active_entities(self, max_age: float = 8.0) -> List[DetectedEntity]:
        """Get entities seen recently."""
        now = time.time()
        return [e for e in self.entities.values() if now - e.last_seen < max_age]


# ============== Data Fetcher ==============

class ESP32Fetcher(QThread):
    """Fetches data from ESP32."""
    
    data_received = pyqtSignal(dict)
    status_changed = pyqtSignal(bool, str)
    
    def __init__(self, host: str, port: int):
        super().__init__()
        self.host = host
        self.port = port
        self.running = True
        self.connected = False
        
    def run(self):
        while self.running:
            try:
                # Fetch all endpoints
                status = self._get(f"http://{self.host}:{self.port}/status")
                scan = self._get(f"http://{self.host}:{self.port}/scan")
                remotes = self._get(f"http://{self.host}:{self.port}/remotes")
                
                if status:
                    self.connected = True
                    self.data_received.emit({
                        'status': status,
                        'scan': scan or {},
                        'remotes': remotes or {}
                    })
                    self.status_changed.emit(True, f"{self.host}")
                else:
                    self.connected = False
                    self.status_changed.emit(False, "No response")
                    
            except Exception as e:
                self.connected = False
                self.status_changed.emit(False, str(e)[:30])
            
            time.sleep(0.08)  # ~12 Hz
    
    def _get(self, url: str) -> Optional[dict]:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'HydraSense/2.0'})
            with urllib.request.urlopen(req, timeout=1.5) as r:
                return json.loads(r.read())
        except Exception:
            return None
    
    def stop(self):
        self.running = False


# ============== 3D Visualization Widget ==============

class Environment3DWidget(QWidget):
    """Immersive 3D-style environment visualization."""
    
    def __init__(self):
        super().__init__()
        self.setMinimumSize(800, 600)
        
        self.reconstructor = EnvironmentReconstructor()
        
        # View settings
        self.camera_angle = 35  # degrees tilt
        self.camera_rotation = 0  # degrees rotation
        self.zoom = 1.0
        
        # Animation
        self.pulse_phase = 0
        self.scan_angle = 0
        
        # Start animation timer
        self.anim_timer = QTimer()
        self.anim_timer.timeout.connect(self._animate)
        self.anim_timer.start(33)  # 30 FPS
        
    def _animate(self):
        self.pulse_phase = (self.pulse_phase + 0.1) % (2 * math.pi)
        self.scan_angle = (self.scan_angle + 2) % 360
        self.update()
        
    def process_data(self, data: dict):
        """Process incoming ESP32 data."""
        scan = data.get('scan', {})
        detections = scan.get('detections', [])
        
        for det in detections:
            mac = det.get('mac', '')
            if not mac or mac == '00:00:00:00:00:00':
                continue
            
            rssi = det.get('rssi', -100)
            antenna = det.get('antenna', 0)
            frame_type = det.get('frame_type', 0)
            
            is_remote = antenna >= 100
            self.reconstructor.process_detection(mac, rssi, is_remote, frame_type)
    
    def world_to_screen(self, x: float, y: float, z: float = 0) -> Tuple[int, int]:
        """Convert 3D world coordinates to 2D screen with perspective."""
        w, h = self.width(), self.height()
        
        # Center of screen
        cx, cy = w // 2, h // 2 + 50
        
        # Scale
        scale = min(w, h) / 8 * self.zoom
        
        # Isometric projection with tilt
        tilt = math.radians(self.camera_angle)
        rot = math.radians(self.camera_rotation)
        
        # Rotate around center of room
        rx = x - ROOM_WIDTH/2
        ry = y - ROOM_DEPTH/2
        
        # Apply rotation
        rx2 = rx * math.cos(rot) - ry * math.sin(rot)
        ry2 = rx * math.sin(rot) + ry * math.cos(rot)
        
        # Project
        sx = cx + rx2 * scale
        sy = cy + ry2 * scale * math.cos(tilt) - z * scale * math.sin(tilt) * 0.8
        
        return (int(sx), int(sy))
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w, h = self.width(), self.height()
        
        # Dark space background with gradient
        grad = QRadialGradient(w/2, h/2, max(w, h))
        grad.setColorAt(0, QColor("#0f1929"))
        grad.setColorAt(0.5, QColor("#0a1020"))
        grad.setColorAt(1, QColor("#050810"))
        painter.fillRect(0, 0, w, h, grad)
        
        # Draw star field effect
        painter.setPen(QColor(255, 255, 255, 30))
        random.seed(42)
        for _ in range(100):
            sx = random.randint(0, w)
            sy = random.randint(0, h)
            painter.drawPoint(sx, sy)
        
        # Draw floor grid
        self._draw_floor_grid(painter)
        
        # Draw walls
        self._draw_walls(painter)
        
        # Draw sensor sweep effect
        self._draw_sensor_sweep(painter)
        
        # Draw heat map
        self._draw_heat_map(painter)
        
        # Draw sensors
        self._draw_sensors(painter)
        
        # Draw detected entities
        self._draw_entities(painter)
        
        # Draw HUD overlay
        self._draw_hud(painter)
    
    def _draw_floor_grid(self, painter: QPainter):
        """Draw 3D floor grid."""
        # Grid lines
        grid_color = QColor("#1a3050")
        grid_color.setAlpha(100)
        painter.setPen(QPen(grid_color, 1))
        
        # Horizontal lines
        for y in range(int(ROOM_DEPTH) + 1):
            p1 = self.world_to_screen(0, y, 0)
            p2 = self.world_to_screen(ROOM_WIDTH, y, 0)
            painter.drawLine(p1[0], p1[1], p2[0], p2[1])
        
        # Vertical lines
        for x in range(int(ROOM_WIDTH) + 1):
            p1 = self.world_to_screen(x, 0, 0)
            p2 = self.world_to_screen(x, ROOM_DEPTH, 0)
            painter.drawLine(p1[0], p1[1], p2[0], p2[1])
        
        # Floor surface (semi-transparent)
        floor_color = QColor("#0a1525")
        floor_color.setAlpha(150)
        
        corners = [
            self.world_to_screen(0, 0, 0),
            self.world_to_screen(ROOM_WIDTH, 0, 0),
            self.world_to_screen(ROOM_WIDTH, ROOM_DEPTH, 0),
            self.world_to_screen(0, ROOM_DEPTH, 0)
        ]
        
        polygon = QPolygonF([QPointF(c[0], c[1]) for c in corners])
        painter.setBrush(QBrush(floor_color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPolygon(polygon)
    
    def _draw_walls(self, painter: QPainter):
        """Draw 3D walls."""
        wall_height = 2.5
        
        # Wall definitions: (x1, y1, x2, y2)
        wall_defs = [
            (0, 0, ROOM_WIDTH, 0),  # Front
            (ROOM_WIDTH, 0, ROOM_WIDTH, ROOM_DEPTH),  # Right
            (ROOM_WIDTH, ROOM_DEPTH, 0, ROOM_DEPTH),  # Back
            (0, ROOM_DEPTH, 0, 0),  # Left
        ]
        
        for x1, y1, x2, y2 in wall_defs:
            # Draw wall surface
            p1_bottom = self.world_to_screen(x1, y1, 0)
            p2_bottom = self.world_to_screen(x2, y2, 0)
            p1_top = self.world_to_screen(x1, y1, wall_height)
            p2_top = self.world_to_screen(x2, y2, wall_height)
            
            # Wall gradient (darker at bottom)
            wall_grad = QLinearGradient(p1_bottom[0], p1_bottom[1], p1_top[0], p1_top[1])
            wall_grad.setColorAt(0, QColor(20, 40, 70, 180))
            wall_grad.setColorAt(1, QColor(30, 60, 100, 120))
            
            polygon = QPolygonF([
                QPointF(*p1_bottom), QPointF(*p2_bottom),
                QPointF(*p2_top), QPointF(*p1_top)
            ])
            
            painter.setBrush(QBrush(wall_grad))
            painter.setPen(QPen(QColor("#2a5a8a"), 2))
            painter.drawPolygon(polygon)
    
    def _draw_sensor_sweep(self, painter: QPainter):
        """Draw radar sweep effect from sensors."""
        for pos, color in [(PRIMARY_POS, QColor("#00ff88")), (REMOTE_POS, QColor("#00d4ff"))]:
            sx, sy = self.world_to_screen(pos[0], pos[1], 0.3)
            
            # Sweep arc
            sweep_radius = 150
            color.setAlpha(30)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(color))
            
            path = QPainterPath()
            path.moveTo(sx, sy)
            path.arcTo(sx - sweep_radius, sy - sweep_radius, 
                      sweep_radius * 2, sweep_radius * 2,
                      self.scan_angle, 30)
            path.lineTo(sx, sy)
            painter.drawPath(path)
            
            # Pulse rings
            for i in range(3):
                radius = (self.pulse_phase + i * 2.1) % 6.3 * 40
                alpha = max(0, 100 - radius * 1.5)
                ring_color = QColor(color)
                ring_color.setAlpha(int(alpha))
                painter.setPen(QPen(ring_color, 2))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawEllipse(sx - int(radius), sy - int(radius//1.5), 
                                   int(radius*2), int(radius*1.3))
    
    def _draw_heat_map(self, painter: QPainter):
        """Draw signal strength heat map."""
        now = time.time()
        
        for point in self.reconstructor.heat_map:
            age = now - point.timestamp
            if age > 5:
                continue
            
            sx, sy = self.world_to_screen(point.x, point.y, 0.05)
            
            # Heat color based on strength
            alpha = int(max(0, (1 - age/5) * point.strength * 100))
            
            if point.strength > 0.7:
                color = QColor(255, 100, 100, alpha)
            elif point.strength > 0.4:
                color = QColor(255, 200, 50, alpha)
            else:
                color = QColor(100, 200, 100, alpha)
            
            grad = QRadialGradient(sx, sy, 25)
            grad.setColorAt(0, color)
            color.setAlpha(0)
            grad.setColorAt(1, color)
            
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(grad))
            painter.drawEllipse(sx - 25, sy - 15, 50, 30)
    
    def _draw_sensors(self, painter: QPainter):
        """Draw sensor nodes."""
        # Primary sensor
        px, py = self.world_to_screen(PRIMARY_POS[0], PRIMARY_POS[1], 0.5)
        
        # Glow effect
        glow = QRadialGradient(px, py, 30)
        glow.setColorAt(0, QColor(0, 255, 136, 100))
        glow.setColorAt(1, QColor(0, 255, 136, 0))
        painter.setBrush(QBrush(glow))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(px - 30, py - 20, 60, 40)
        
        # Sensor body
        painter.setBrush(QBrush(QColor("#00ff88")))
        painter.setPen(QPen(QColor("#00cc66"), 2))
        painter.drawEllipse(px - 10, py - 7, 20, 14)
        
        # Label
        painter.setPen(QColor("#00ff88"))
        painter.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        painter.drawText(px - 35, py + 25, "PRIMARY")
        
        # Remote sensor
        rx, ry = self.world_to_screen(REMOTE_POS[0], REMOTE_POS[1], 0.5)
        
        glow = QRadialGradient(rx, ry, 30)
        glow.setColorAt(0, QColor(0, 212, 255, 100))
        glow.setColorAt(1, QColor(0, 212, 255, 0))
        painter.setBrush(QBrush(glow))
        painter.drawEllipse(rx - 30, ry - 20, 60, 40)
        
        painter.setBrush(QBrush(QColor("#00d4ff")))
        painter.setPen(QPen(QColor("#00a0cc"), 2))
        painter.drawEllipse(rx - 10, ry - 7, 20, 14)
        
        painter.setPen(QColor("#00d4ff"))
        painter.drawText(rx - 30, ry + 25, "REMOTE")
        
        # Connection line
        painter.setPen(QPen(QColor(0, 200, 255, 80), 1, Qt.PenStyle.DashLine))
        painter.drawLine(px, py, rx, ry)
    
    def _draw_entities(self, painter: QPainter):
        """Draw detected entities with 3D representation."""
        now = time.time()
        entities = self.reconstructor.get_active_entities()
        
        for entity in entities:
            age = now - entity.last_seen
            if age > 8:
                continue
            
            x, y, z = entity.x, entity.y, entity.z
            sx, sy = self.world_to_screen(x, y, z)
            
            # Fade based on age
            alpha = max(50, int(255 * (1 - age/8)))
            
            # Draw trail
            if len(entity.trail) > 2:
                painter.setPen(QPen(QColor(255, 150, 100, alpha//3), 2))
                for i in range(1, len(entity.trail)):
                    t1 = entity.trail[i-1]
                    t2 = entity.trail[i]
                    p1 = self.world_to_screen(t1[0], t1[1], 0.1)
                    p2 = self.world_to_screen(t2[0], t2[1], 0.1)
                    painter.drawLine(p1[0], p1[1], p2[0], p2[1])
            
            # Ground shadow
            shadow_sx, shadow_sy = self.world_to_screen(x, y, 0)
            shadow_color = QColor(0, 0, 0, alpha//3)
            painter.setBrush(QBrush(shadow_color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(shadow_sx - 15, shadow_sy - 8, 30, 16)
            
            # Entity visualization based on type
            if entity.entity_type == "person" and entity.is_moving:
                # Moving person - red pulsing figure
                size = 18 + int(math.sin(self.pulse_phase * 3) * 3)
                color = QColor(255, 100, 100, alpha)
                
                # Humanoid shape
                head_y = sy - 25
                body_y = sy - 10
                
                # Glow
                glow = QRadialGradient(sx, body_y, 40)
                glow.setColorAt(0, QColor(255, 100, 100, alpha//2))
                glow.setColorAt(1, QColor(255, 100, 100, 0))
                painter.setBrush(QBrush(glow))
                painter.drawEllipse(sx - 40, body_y - 25, 80, 50)
                
                # Body
                painter.setBrush(QBrush(color))
                painter.setPen(QPen(color.darker(120), 2))
                painter.drawEllipse(sx - 12, body_y - 15, 24, 30)
                
                # Head
                painter.drawEllipse(sx - 8, head_y - 8, 16, 16)
                
                # Movement indicator
                vx, vy, _ = entity.velocity
                vlen = math.sqrt(vx*vx + vy*vy)
                if vlen > 0.1:
                    arrow_len = min(vlen * 30, 50)
                    arrow_x = sx + vx / vlen * arrow_len
                    arrow_y = sy - vy / vlen * arrow_len * 0.6
                    painter.setPen(QPen(QColor(255, 100, 100, alpha), 3))
                    painter.drawLine(sx, sy - 20, int(arrow_x), int(arrow_y - 20))
                    
            elif entity.entity_type == "device":
                # Stationary device - cyan cube
                size = 14
                color = QColor(0, 200, 255, alpha)
                
                # Draw as cube
                painter.setBrush(QBrush(color))
                painter.setPen(QPen(color.lighter(120), 2))
                
                # Front face
                painter.drawRect(sx - size//2, sy - size//2, size, size)
                
                # Top face (parallelogram)
                top_offset = size // 3
                points = [
                    QPointF(sx - size//2, sy - size//2),
                    QPointF(sx - size//2 + top_offset, sy - size//2 - top_offset),
                    QPointF(sx + size//2 + top_offset, sy - size//2 - top_offset),
                    QPointF(sx + size//2, sy - size//2),
                ]
                painter.drawPolygon(QPolygonF(points))
                
            else:
                # Unknown/object - green sphere
                size = 12
                color = QColor(100, 200, 100, alpha)
                
                grad = QRadialGradient(sx - 3, sy - 3, size)
                grad.setColorAt(0, color.lighter(150))
                grad.setColorAt(1, color.darker(150))
                
                painter.setBrush(QBrush(grad))
                painter.setPen(QPen(color.darker(120), 1))
                painter.drawEllipse(sx - size//2, sy - size//2, size, size)
            
            # MAC label
            painter.setPen(QColor(200, 220, 255, alpha))
            painter.setFont(QFont("Consolas", 8))
            painter.drawText(sx - 25, sy + 30, entity.mac[-8:])
            
            # Signal strength bar
            bar_width = int(entity.signal_strength * 40)
            painter.setBrush(QBrush(QColor(0, 255, 136, alpha)))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRect(sx - 20, sy + 35, bar_width, 3)
    
    def _draw_hud(self, painter: QPainter):
        """Draw heads-up display overlay."""
        w, h = self.width(), self.height()
        
        # Corner brackets
        bracket_color = QColor("#00d4ff")
        bracket_color.setAlpha(150)
        painter.setPen(QPen(bracket_color, 2))
        
        bsize = 30
        # Top-left
        painter.drawLine(10, 10, 10, 10 + bsize)
        painter.drawLine(10, 10, 10 + bsize, 10)
        # Top-right
        painter.drawLine(w - 10, 10, w - 10, 10 + bsize)
        painter.drawLine(w - 10, 10, w - 10 - bsize, 10)
        # Bottom-left
        painter.drawLine(10, h - 10, 10, h - 10 - bsize)
        painter.drawLine(10, h - 10, 10 + bsize, h - 10)
        # Bottom-right
        painter.drawLine(w - 10, h - 10, w - 10, h - 10 - bsize)
        painter.drawLine(w - 10, h - 10, w - 10 - bsize, h - 10)
        
        # Title
        painter.setPen(QColor("#00d4ff"))
        painter.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        painter.drawText(20, 35, "🛰️ HYDRASENSE ENVIRONMENT SCANNER")
        
        # Stats
        entities = self.reconstructor.get_active_entities()
        moving = sum(1 for e in entities if e.is_moving)
        
        painter.setFont(QFont("Consolas", 11))
        painter.setPen(QColor("#8fb3ff"))
        painter.drawText(20, h - 60, f"ENTITIES: {len(entities)}")
        painter.drawText(20, h - 40, f"MOVING: {moving}")
        painter.drawText(20, h - 20, f"TIME: {time.strftime('%H:%M:%S')}")
        
        # Compass
        cx, cy = w - 60, 70
        painter.setPen(QPen(QColor("#2a5a8a"), 1))
        painter.drawEllipse(cx - 30, cy - 30, 60, 60)
        painter.setPen(QColor("#00d4ff"))
        painter.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        painter.drawText(cx - 5, cy - 35, "N")
        painter.drawText(cx - 5, cy + 45, "S")
        painter.drawText(cx - 45, cy + 5, "W")
        painter.drawText(cx + 35, cy + 5, "E")


# ============== Main Window ==============

class HydraSenseMainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛰️ HydraSense 3D Environment Scanner")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        
        self.setStyleSheet("""
            QMainWindow { background: #050810; }
            QStatusBar { background: #0a1020; color: #8fb3ff; border-top: 1px solid #1a3050; }
            QLabel { color: #d7e7ff; }
            QPushButton {
                background: #1a3050;
                border: 1px solid #2a5080;
                border-radius: 5px;
                color: #00d4ff;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover { background: #2a4070; }
        """)
        
        # Create main widget
        self.env_view = Environment3DWidget()
        self.setCentralWidget(self.env_view)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.conn_label = QLabel("⏳ Connecting to ESP32...")
        self.pps_label = QLabel("PPS: --")
        self.remote_label = QLabel("Remote: --")
        
        self.status_bar.addWidget(self.conn_label)
        self.status_bar.addWidget(QLabel(" | "))
        self.status_bar.addWidget(self.pps_label)
        self.status_bar.addWidget(QLabel(" | "))
        self.status_bar.addWidget(self.remote_label)
        
        # Data fetcher
        self.fetcher = ESP32Fetcher(ESP32_HOST, ESP32_PORT)
        self.fetcher.data_received.connect(self._on_data)
        self.fetcher.status_changed.connect(self._on_status)
        self.fetcher.start()
        
    def _on_data(self, data: dict):
        """Handle incoming data."""
        self.env_view.process_data(data)
        
        status = data.get('status', {})
        remotes = data.get('remotes', {})
        
        self.pps_label.setText(f"📡 PPS: {status.get('pps', 0)} | Total: {status.get('total', 0):,}")
        
        remote_list = remotes.get('remotes', [])
        if remote_list:
            r = remote_list[0]
            self.remote_label.setText(f"🔗 Remote: {r.get('node_id', 'N/A')} ({r.get('rssi', 0)} dBm)")
            self.remote_label.setStyleSheet("color: #00ff88;")
        else:
            self.remote_label.setText("🔗 Remote: Disconnected")
            self.remote_label.setStyleSheet("color: #ff6b6b;")
    
    def _on_status(self, connected: bool, info: str):
        if connected:
            self.conn_label.setText(f"🟢 Connected: {info}")
            self.conn_label.setStyleSheet("color: #00ff88;")
        else:
            self.conn_label.setText(f"🔴 Disconnected: {info}")
            self.conn_label.setStyleSheet("color: #ff6b6b;")
    
    def closeEvent(self, event):
        self.fetcher.stop()
        self.fetcher.wait()
        super().closeEvent(event)


# ============== Main ==============

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("HydraSense 3D Scanner")
    
    window = HydraSenseMainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
