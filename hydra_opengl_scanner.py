#!/usr/bin/env python3
"""
HydraSense Advanced OpenGL 3D Environment Scanner
==================================================
High-fidelity real OpenGL 3D visualization with:
- True 3D perspective and depth rendering
- Dynamic lighting and shadows
- Volumetric signal effects
- Real-time triangulation visualization
- Interactive camera controls (drag/zoom)
"""

import sys
import json
import math
import time
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
import numpy as np

from PyQt6.QtWidgets import QApplication, QMainWindow, QStatusBar, QLabel
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QSurfaceFormat
from PyQt6.QtOpenGLWidgets import QOpenGLWidget

from OpenGL.GL import *
from OpenGL.GLU import *


# ==================== Configuration ====================

ESP32_HOST = "192.168.0.139"
ESP32_PORT = 80

# Room dimensions in meters
ROOM_WIDTH = 6.0
ROOM_DEPTH = 5.0
ROOM_HEIGHT = 2.8

# Sensor positions (x, y, z) in meters
PRIMARY_POS = (0.5, 0.5, 0.3)
REMOTE_POS = (5.5, 0.5, 0.3)


# ==================== Data Classes ====================

@dataclass
class Entity:
    """Represents a detected entity in the environment."""
    mac: str
    x: float = 0.0
    y: float = 0.0
    z: float = 1.0
    rssi_primary: int = -100
    rssi_remote: int = -100
    velocity: Tuple[float, float, float] = (0, 0, 0)
    last_seen: float = 0
    signal_strength: float = 0
    is_moving: bool = False
    entity_type: str = "unknown"
    trail: List[Tuple[float, float, float, float]] = field(default_factory=list)  # x, y, z, time
    size: float = 0.3
    color: Tuple[float, float, float] = (0.5, 0.5, 0.5)
    detection_count: int = 0


@dataclass
class SignalPulse:
    """Expanding signal pulse visualization."""
    origin: Tuple[float, float, float]
    radius: float = 0.0
    max_radius: float = 4.0
    color: Tuple[float, float, float] = (0, 1, 0.5)
    birth_time: float = 0
    speed: float = 3.0


# ==================== Environment Engine ====================

class EnvironmentEngine:
    """Handles WiFi triangulation and entity tracking."""
    
    RSSI_REF = -35  # Reference RSSI at 1 meter
    PATH_LOSS = 2.5  # Path loss exponent
    
    def __init__(self):
        self.entities: Dict[str, Entity] = {}
        self.pulses: List[SignalPulse] = []
        self.position_history: Dict[str, List[Tuple[float, float, float, float]]] = defaultdict(list)
        self.total_detections = 0
        
    def rssi_to_distance(self, rssi: int) -> float:
        """Convert RSSI to estimated distance in meters."""
        if rssi >= 0 or rssi < -100:
            return 10.0
        distance = 10 ** ((self.RSSI_REF - rssi) / (10 * self.PATH_LOSS))
        return min(max(distance, 0.1), 15.0)
    
    def triangulate(self, rssi1: int, rssi2: int) -> Tuple[float, float, float]:
        """Triangulate position from two RSSI readings."""
        d1 = self.rssi_to_distance(rssi1)
        d2 = self.rssi_to_distance(rssi2)
        
        # Vector between sensors
        dx = REMOTE_POS[0] - PRIMARY_POS[0]
        dy = REMOTE_POS[1] - PRIMARY_POS[1]
        d_sensors = math.sqrt(dx*dx + dy*dy)
        
        if d_sensors < 0.1:
            return (ROOM_WIDTH/2, ROOM_DEPTH/2, 1.0)
        
        # Trilateration math
        a = (d1*d1 - d2*d2 + d_sensors*d_sensors) / (2 * d_sensors)
        h_sq = d1*d1 - a*a
        
        if h_sq < 0:
            # Circles don't intersect, use weighted average
            w1 = 1 / (d1 + 0.1)
            w2 = 1 / (d2 + 0.1)
            total = w1 + w2
            x = (PRIMARY_POS[0] * w1 + REMOTE_POS[0] * w2) / total
            y = (PRIMARY_POS[1] * w1 + REMOTE_POS[1] * w2) / total
        else:
            h = math.sqrt(h_sq)
            # Point along the line between sensors
            px = PRIMARY_POS[0] + a * dx / d_sensors
            py = PRIMARY_POS[1] + a * dy / d_sensors
            # Offset perpendicular to get intersection
            x = px - h * dy / d_sensors
            y = py + h * dx / d_sensors
        
        # Clamp to room bounds
        x = max(0.3, min(ROOM_WIDTH - 0.3, x))
        y = max(0.3, min(ROOM_DEPTH - 0.3, y))
        
        # Estimate height from signal strength
        avg_rssi = (rssi1 + rssi2) / 2
        z = 0.8 + (avg_rssi + 70) * 0.015
        z = max(0.3, min(ROOM_HEIGHT - 0.3, z))
        
        return (x, y, z)
    
    def process_detection(self, mac: str, rssi: int, is_remote: bool) -> Entity:
        """Process a detection and update entity state."""
        now = time.time()
        self.total_detections += 1
        
        # Create or get entity
        if mac not in self.entities:
            self.entities[mac] = Entity(mac=mac)
        
        entity = self.entities[mac]
        entity.last_seen = now
        entity.detection_count += 1
        
        # Update RSSI
        if is_remote:
            entity.rssi_remote = rssi
        else:
            entity.rssi_primary = rssi
        
        # Calculate signal strength (0-1)
        avg_rssi = (entity.rssi_primary + entity.rssi_remote) / 2
        entity.signal_strength = max(0, min(1, (avg_rssi + 100) / 60))
        
        # Only triangulate if we have readings from both sensors
        if entity.rssi_primary > -95 and entity.rssi_remote > -95:
            x, y, z = self.triangulate(entity.rssi_primary, entity.rssi_remote)
            
            # Store history for smoothing
            history = self.position_history[mac]
            history.append((x, y, z, now))
            if len(history) > 30:
                history.pop(0)
            
            # Apply exponential smoothing
            if len(history) >= 3:
                smooth_x, smooth_y, smooth_z = 0, 0, 0
                total_w = 0
                for i, (hx, hy, hz, ht) in enumerate(history):
                    age = now - ht
                    w = math.exp(-age * 0.8) * (i + 1) / len(history)
                    smooth_x += hx * w
                    smooth_y += hy * w
                    smooth_z += hz * w
                    total_w += w
                if total_w > 0:
                    x = smooth_x / total_w
                    y = smooth_y / total_w
                    z = smooth_z / total_w
            
            # Calculate velocity for movement detection
            if len(history) >= 5:
                old = history[-5]
                dt = now - old[3]
                if dt > 0.1:
                    vx = (x - old[0]) / dt
                    vy = (y - old[1]) / dt
                    vz = (z - old[2]) / dt
                    speed = math.sqrt(vx*vx + vy*vy + vz*vz)
                    entity.is_moving = speed > 0.15
                    entity.velocity = (vx, vy, vz)
            
            # Update position
            entity.x, entity.y, entity.z = x, y, z
            
            # Add to trail
            entity.trail.append((x, y, z, now))
            if len(entity.trail) > 80:
                entity.trail.pop(0)
            
            # Classify entity
            self._classify_entity(entity)
        
        return entity
    
    def _classify_entity(self, entity: Entity):
        """Classify entity based on behavior."""
        if entity.is_moving and entity.signal_strength > 0.3:
            entity.entity_type = "person"
            entity.color = (1.0, 0.35, 0.35)
            entity.size = 0.4
        elif entity.signal_strength > 0.5 and entity.detection_count > 20:
            entity.entity_type = "device"
            entity.color = (0.35, 0.8, 1.0)
            entity.size = 0.25
        elif entity.signal_strength > 0.2:
            entity.entity_type = "object"
            entity.color = (0.4, 0.95, 0.5)
            entity.size = 0.2
        else:
            entity.entity_type = "weak"
            entity.color = (0.6, 0.6, 0.6)
            entity.size = 0.15
    
    def add_pulse(self, origin: Tuple[float, float, float], color: Tuple[float, float, float]):
        """Add a signal pulse effect."""
        self.pulses.append(SignalPulse(origin=origin, color=color, birth_time=time.time()))
        if len(self.pulses) > 40:
            self.pulses.pop(0)
    
    def update_pulses(self, dt: float):
        """Update pulse animations."""
        now = time.time()
        for pulse in self.pulses[:]:
            age = now - pulse.birth_time
            pulse.radius = age * pulse.speed
            if pulse.radius > pulse.max_radius:
                self.pulses.remove(pulse)
    
    def get_active_entities(self, max_age: float = 12.0) -> List[Entity]:
        """Get entities seen recently."""
        now = time.time()
        return [e for e in self.entities.values() if now - e.last_seen < max_age]


# ==================== Data Fetcher ====================

class DataFetcher(QThread):
    """Background thread to fetch data from ESP32."""
    data_received = pyqtSignal(dict)
    status_changed = pyqtSignal(bool, str)
    
    def __init__(self, host: str, port: int):
        super().__init__()
        self.host = host
        self.port = port
        self.running = True
        self.scan_counter = 0
        self.last_scan = {}
        
    def run(self):
        while self.running:
            try:
                # Fast endpoints - fetch every cycle
                status = self._fetch(f"http://{self.host}:{self.port}/status", timeout=1.5)
                remotes = self._fetch(f"http://{self.host}:{self.port}/remotes", timeout=1.5)
                
                # Slow endpoint - fetch less frequently with longer timeout
                self.scan_counter += 1
                if self.scan_counter >= 3:  # Every 3rd cycle
                    scan = self._fetch(f"http://{self.host}:{self.port}/scan", timeout=8.0)
                    if scan:
                        self.last_scan = scan
                    self.scan_counter = 0
                
                if status:
                    self.data_received.emit({
                        'status': status,
                        'scan': self.last_scan,
                        'remotes': remotes or {}
                    })
                    self.status_changed.emit(True, f"{self.host}")
                else:
                    self.status_changed.emit(False, "No response")
            except Exception as e:
                self.status_changed.emit(False, str(e)[:25])
            
            time.sleep(0.1)  # ~10 Hz for fast endpoints
    
    def _fetch(self, url: str, timeout: float = 2.0) -> Optional[dict]:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'HydraSense/3.0'})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.loads(response.read())
        except Exception:
            return None
    
    def stop(self):
        self.running = False


# ==================== OpenGL 3D Renderer ====================

class OpenGL3DRenderer(QOpenGLWidget):
    """Advanced OpenGL 3D environment renderer."""
    
    def __init__(self):
        super().__init__()
        
        self.engine = EnvironmentEngine()
        
        # Camera parameters
        self.cam_distance = 14.0
        self.cam_azimuth = 45.0  # Horizontal angle
        self.cam_elevation = 35.0  # Vertical angle
        self.cam_target = [ROOM_WIDTH/2, ROOM_DEPTH/2, 1.0]
        
        # Animation
        self.time = 0
        self.scan_angle = 0
        self.last_pulse_time = 0
        
        # Mouse tracking
        self.last_mouse = None
        self.setMouseTracking(True)
        
        # Stats
        self.fps = 0
        self.frame_count = 0
        self.fps_time = time.time()
        
        # Animation timer
        self.anim_timer = QTimer()
        self.anim_timer.timeout.connect(self._tick)
        self.anim_timer.start(16)  # ~60 FPS
        
    def _tick(self):
        """Animation tick."""
        self.time += 0.016
        self.scan_angle = (self.scan_angle + 2) % 360
        self.engine.update_pulses(0.016)
        
        # FPS calculation
        self.frame_count += 1
        now = time.time()
        if now - self.fps_time >= 1.0:
            self.fps = self.frame_count / (now - self.fps_time)
            self.frame_count = 0
            self.fps_time = now
        
        self.update()
    
    def initializeGL(self):
        """Initialize OpenGL state."""
        glClearColor(0.015, 0.03, 0.08, 1.0)
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_BLEND)
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA)
        glEnable(GL_LINE_SMOOTH)
        glEnable(GL_POINT_SMOOTH)
        glHint(GL_LINE_SMOOTH_HINT, GL_NICEST)
        glHint(GL_POINT_SMOOTH_HINT, GL_NICEST)
        
        # Enable lighting
        glEnable(GL_LIGHTING)
        glEnable(GL_LIGHT0)
        glEnable(GL_LIGHT1)
        glEnable(GL_COLOR_MATERIAL)
        glColorMaterial(GL_FRONT_AND_BACK, GL_AMBIENT_AND_DIFFUSE)
        
        # Main overhead light
        glLightfv(GL_LIGHT0, GL_POSITION, [ROOM_WIDTH/2, ROOM_DEPTH/2, 6.0, 1.0])
        glLightfv(GL_LIGHT0, GL_DIFFUSE, [0.8, 0.85, 0.95, 1.0])
        glLightfv(GL_LIGHT0, GL_AMBIENT, [0.12, 0.14, 0.2, 1.0])
        glLightfv(GL_LIGHT0, GL_SPECULAR, [0.5, 0.5, 0.6, 1.0])
        
        # Secondary fill light
        glLightfv(GL_LIGHT1, GL_POSITION, [0, 0, 4.0, 1.0])
        glLightfv(GL_LIGHT1, GL_DIFFUSE, [0.25, 0.4, 0.5, 1.0])
        glLightfv(GL_LIGHT1, GL_AMBIENT, [0.05, 0.08, 0.1, 1.0])
        
        # Material properties
        glMaterialfv(GL_FRONT_AND_BACK, GL_SPECULAR, [0.3, 0.3, 0.3, 1.0])
        glMaterialf(GL_FRONT_AND_BACK, GL_SHININESS, 32.0)
        
    def resizeGL(self, w, h):
        """Handle resize."""
        glViewport(0, 0, w, h)
        glMatrixMode(GL_PROJECTION)
        glLoadIdentity()
        gluPerspective(50, w / max(h, 1), 0.1, 100.0)
        glMatrixMode(GL_MODELVIEW)
        
    def paintGL(self):
        """Main render function."""
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
        glLoadIdentity()
        
        # Calculate camera position
        az_rad = math.radians(self.cam_azimuth)
        el_rad = math.radians(self.cam_elevation)
        
        cam_x = self.cam_target[0] + self.cam_distance * math.cos(el_rad) * math.sin(az_rad)
        cam_y = self.cam_target[1] + self.cam_distance * math.cos(el_rad) * math.cos(az_rad)
        cam_z = self.cam_target[2] + self.cam_distance * math.sin(el_rad)
        
        gluLookAt(
            cam_x, cam_y, cam_z,
            self.cam_target[0], self.cam_target[1], self.cam_target[2],
            0, 0, 1
        )
        
        # Render scene layers
        self._render_environment()
        self._render_floor_effects()
        self._render_sensors()
        self._render_signal_pulses()
        self._render_connection_beams()
        self._render_entities()
        self._render_hud()
        
    def _render_environment(self):
        """Render the room environment."""
        # Floor with subtle gradient effect
        glEnable(GL_LIGHTING)
        glColor4f(0.04, 0.08, 0.15, 1.0)
        glBegin(GL_QUADS)
        glNormal3f(0, 0, 1)
        glVertex3f(0, 0, 0)
        glVertex3f(ROOM_WIDTH, 0, 0)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, 0)
        glVertex3f(0, ROOM_DEPTH, 0)
        glEnd()
        
        # Semi-transparent walls
        wall_alpha = 0.25
        
        # Back wall
        glColor4f(0.08, 0.12, 0.2, wall_alpha)
        glBegin(GL_QUADS)
        glNormal3f(0, -1, 0)
        glVertex3f(0, ROOM_DEPTH, 0)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, 0)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, ROOM_HEIGHT)
        glVertex3f(0, ROOM_DEPTH, ROOM_HEIGHT)
        glEnd()
        
        # Left wall
        glColor4f(0.06, 0.1, 0.18, wall_alpha)
        glBegin(GL_QUADS)
        glNormal3f(1, 0, 0)
        glVertex3f(0, 0, 0)
        glVertex3f(0, ROOM_DEPTH, 0)
        glVertex3f(0, ROOM_DEPTH, ROOM_HEIGHT)
        glVertex3f(0, 0, ROOM_HEIGHT)
        glEnd()
        
        # Right wall
        glBegin(GL_QUADS)
        glNormal3f(-1, 0, 0)
        glVertex3f(ROOM_WIDTH, 0, 0)
        glVertex3f(ROOM_WIDTH, 0, ROOM_HEIGHT)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, ROOM_HEIGHT)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, 0)
        glEnd()
        
        # Glowing edges
        glDisable(GL_LIGHTING)
        glLineWidth(2.0)
        glColor4f(0.1, 0.4, 0.7, 0.7)
        
        # Floor edges
        glBegin(GL_LINE_LOOP)
        glVertex3f(0, 0, 0)
        glVertex3f(ROOM_WIDTH, 0, 0)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, 0)
        glVertex3f(0, ROOM_DEPTH, 0)
        glEnd()
        
        # Vertical edges
        glColor4f(0.08, 0.3, 0.5, 0.5)
        glBegin(GL_LINES)
        for x, y in [(0, 0), (ROOM_WIDTH, 0), (ROOM_WIDTH, ROOM_DEPTH), (0, ROOM_DEPTH)]:
            glVertex3f(x, y, 0)
            glVertex3f(x, y, ROOM_HEIGHT)
        glEnd()
        
        # Ceiling edges
        glColor4f(0.06, 0.2, 0.4, 0.4)
        glBegin(GL_LINE_LOOP)
        glVertex3f(0, 0, ROOM_HEIGHT)
        glVertex3f(ROOM_WIDTH, 0, ROOM_HEIGHT)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, ROOM_HEIGHT)
        glVertex3f(0, ROOM_DEPTH, ROOM_HEIGHT)
        glEnd()
        
        glEnable(GL_LIGHTING)
        
    def _render_floor_effects(self):
        """Render floor grid and scanning effects."""
        glDisable(GL_LIGHTING)
        
        # Main grid lines
        glLineWidth(1.0)
        glColor4f(0.08, 0.2, 0.35, 0.4)
        glBegin(GL_LINES)
        for i in range(int(ROOM_WIDTH) + 1):
            glVertex3f(i, 0, 0.005)
            glVertex3f(i, ROOM_DEPTH, 0.005)
        for i in range(int(ROOM_DEPTH) + 1):
            glVertex3f(0, i, 0.005)
            glVertex3f(ROOM_WIDTH, i, 0.005)
        glEnd()
        
        # Sub-grid
        glColor4f(0.05, 0.12, 0.22, 0.2)
        glBegin(GL_LINES)
        for i in range(int(ROOM_WIDTH * 4) + 1):
            x = i * 0.25
            glVertex3f(x, 0, 0.003)
            glVertex3f(x, ROOM_DEPTH, 0.003)
        for i in range(int(ROOM_DEPTH * 4) + 1):
            y = i * 0.25
            glVertex3f(0, y, 0.003)
            glVertex3f(ROOM_WIDTH, y, 0.003)
        glEnd()
        
        # Scanning sweep from primary sensor
        sweep_angle = math.radians(self.scan_angle)
        sweep_length = 5.0
        
        glBegin(GL_TRIANGLES)
        for i in range(12):
            a1 = sweep_angle + i * 0.02
            a2 = sweep_angle + (i + 1) * 0.02
            alpha = 0.25 * (1 - i / 12)
            
            glColor4f(0.0, 0.8, 0.5, 0)
            glVertex3f(PRIMARY_POS[0], PRIMARY_POS[1], 0.01)
            glColor4f(0.0, 0.8, 0.5, alpha)
            glVertex3f(PRIMARY_POS[0] + math.cos(a1) * sweep_length,
                      PRIMARY_POS[1] + math.sin(a1) * sweep_length, 0.01)
            glVertex3f(PRIMARY_POS[0] + math.cos(a2) * sweep_length,
                      PRIMARY_POS[1] + math.sin(a2) * sweep_length, 0.01)
        glEnd()
        
        # Secondary sweep from remote sensor
        sweep_angle2 = math.radians(self.scan_angle + 180)
        glBegin(GL_TRIANGLES)
        for i in range(12):
            a1 = sweep_angle2 + i * 0.02
            a2 = sweep_angle2 + (i + 1) * 0.02
            alpha = 0.2 * (1 - i / 12)
            
            glColor4f(0.0, 0.6, 1.0, 0)
            glVertex3f(REMOTE_POS[0], REMOTE_POS[1], 0.01)
            glColor4f(0.0, 0.6, 1.0, alpha)
            glVertex3f(REMOTE_POS[0] + math.cos(a1) * sweep_length,
                      REMOTE_POS[1] + math.sin(a1) * sweep_length, 0.01)
            glVertex3f(REMOTE_POS[0] + math.cos(a2) * sweep_length,
                      REMOTE_POS[1] + math.sin(a2) * sweep_length, 0.01)
        glEnd()
        
        glEnable(GL_LIGHTING)
        
    def _render_sensors(self):
        """Render sensor nodes with effects."""
        sensors = [
            (PRIMARY_POS, (0, 1, 0.5), "PRIMARY"),
            (REMOTE_POS, (0, 0.7, 1), "REMOTE")
        ]
        
        for pos, color, name in sensors:
            x, y, z = pos
            
            # Base platform
            glEnable(GL_LIGHTING)
            glColor4f(*color, 1.0)
            
            glPushMatrix()
            glTranslatef(x, y, 0)
            
            # Cylinder base
            quadric = gluNewQuadric()
            gluCylinder(quadric, 0.18, 0.14, z, 20, 4)
            
            # Top dome
            glTranslatef(0, 0, z)
            gluSphere(quadric, 0.14, 20, 20)
            gluDeleteQuadric(quadric)
            
            glPopMatrix()
            
            # Emission rings
            glDisable(GL_LIGHTING)
            for i in range(5):
                phase = (self.time * 1.5 + i * 0.8) % 4
                radius = 0.3 + phase * 0.7
                alpha = max(0, 0.5 - phase * 0.12)
                
                glColor4f(*color, alpha)
                glLineWidth(2.0)
                glBegin(GL_LINE_LOOP)
                for a in range(40):
                    angle = a * math.pi * 2 / 40
                    glVertex3f(x + math.cos(angle) * radius,
                              y + math.sin(angle) * radius, z)
                glEnd()
            
            # Vertical beam
            glColor4f(*color, 0.15)
            glBegin(GL_LINES)
            glVertex3f(x, y, z)
            glVertex3f(x, y, z + 2.0)
            glEnd()
            
            glEnable(GL_LIGHTING)
            
    def _render_signal_pulses(self):
        """Render expanding signal pulses."""
        glDisable(GL_LIGHTING)
        
        for pulse in self.engine.pulses:
            alpha = max(0, 0.6 * (1 - pulse.radius / pulse.max_radius))
            
            glColor4f(*pulse.color, alpha)
            glLineWidth(2.5)
            
            # Draw pulse ring
            glBegin(GL_LINE_LOOP)
            for i in range(50):
                angle = i * math.pi * 2 / 50
                glVertex3f(
                    pulse.origin[0] + math.cos(angle) * pulse.radius,
                    pulse.origin[1] + math.sin(angle) * pulse.radius,
                    pulse.origin[2]
                )
            glEnd()
            
            # Inner glow
            if pulse.radius < 1.0:
                inner_alpha = alpha * 0.3
                glColor4f(*pulse.color, inner_alpha)
                glBegin(GL_TRIANGLE_FAN)
                glVertex3f(*pulse.origin)
                for i in range(51):
                    angle = i * math.pi * 2 / 50
                    glVertex3f(
                        pulse.origin[0] + math.cos(angle) * pulse.radius,
                        pulse.origin[1] + math.sin(angle) * pulse.radius,
                        pulse.origin[2]
                    )
                glEnd()
        
        glEnable(GL_LIGHTING)
        
    def _render_connection_beams(self):
        """Render beams between sensors and entities."""
        glDisable(GL_LIGHTING)
        now = time.time()
        
        entities = self.engine.get_active_entities()
        
        for entity in entities:
            age = now - entity.last_seen
            if age > 5:
                continue
            
            base_alpha = 0.2 * entity.signal_strength * max(0, 1 - age / 5)
            
            # Beam to primary
            if entity.rssi_primary > -90:
                glColor4f(0, 1, 0.5, base_alpha)
                glLineWidth(1.5)
                glBegin(GL_LINES)
                glVertex3f(*PRIMARY_POS)
                glVertex3f(entity.x, entity.y, entity.z)
                glEnd()
                
                # Animated dots along beam
                for i in range(5):
                    t = ((self.time * 2 + i * 0.2) % 1)
                    px = PRIMARY_POS[0] + (entity.x - PRIMARY_POS[0]) * t
                    py = PRIMARY_POS[1] + (entity.y - PRIMARY_POS[1]) * t
                    pz = PRIMARY_POS[2] + (entity.z - PRIMARY_POS[2]) * t
                    
                    glPointSize(4.0)
                    glColor4f(0, 1, 0.5, base_alpha * 2)
                    glBegin(GL_POINTS)
                    glVertex3f(px, py, pz)
                    glEnd()
            
            # Beam to remote
            if entity.rssi_remote > -90:
                glColor4f(0, 0.7, 1, base_alpha)
                glLineWidth(1.5)
                glBegin(GL_LINES)
                glVertex3f(*REMOTE_POS)
                glVertex3f(entity.x, entity.y, entity.z)
                glEnd()
        
        glEnable(GL_LIGHTING)
        
    def _render_entities(self):
        """Render detected entities."""
        now = time.time()
        entities = self.engine.get_active_entities()
        
        for entity in entities:
            age = now - entity.last_seen
            if age > 12:
                continue
            
            alpha = max(0.25, 1.0 - age / 12)
            x, y, z = entity.x, entity.y, entity.z
            
            # Draw trail
            if len(entity.trail) > 2:
                glDisable(GL_LIGHTING)
                glLineWidth(2.0)
                glBegin(GL_LINE_STRIP)
                for i, (tx, ty, tz, tt) in enumerate(entity.trail):
                    trail_age = now - tt
                    trail_alpha = max(0, alpha * 0.5 * (1 - trail_age / 8))
                    glColor4f(*entity.color, trail_alpha)
                    glVertex3f(tx, ty, 0.02)
                glEnd()
                glEnable(GL_LIGHTING)
            
            # Ground shadow
            glDisable(GL_LIGHTING)
            glColor4f(0, 0, 0, 0.25 * alpha)
            glBegin(GL_POLYGON)
            for i in range(20):
                angle = i * math.pi * 2 / 20
                glVertex3f(x + math.cos(angle) * entity.size * 0.9,
                          y + math.sin(angle) * entity.size * 0.9, 0.005)
            glEnd()
            
            # Vertical indicator line
            glColor4f(*entity.color, alpha * 0.4)
            glLineWidth(1.0)
            glBegin(GL_LINES)
            glVertex3f(x, y, 0.01)
            glVertex3f(x, y, z)
            glEnd()
            glEnable(GL_LIGHTING)
            
            # Entity body
            glPushMatrix()
            glTranslatef(x, y, z)
            
            if entity.entity_type == "person":
                self._draw_person_model(entity, alpha)
            elif entity.entity_type == "device":
                self._draw_device_model(entity, alpha)
            else:
                self._draw_generic_model(entity, alpha)
            
            glPopMatrix()
            
            # Signal strength indicator
            self._draw_signal_bar(x, y, z + entity.size + 0.4, entity.signal_strength, alpha)
            
    def _draw_person_model(self, entity: Entity, alpha: float):
        """Draw humanoid entity."""
        r, g, b = entity.color
        pulse = 1.0 + (math.sin(self.time * 6) * 0.12 if entity.is_moving else 0)
        
        glColor4f(r, g, b, alpha)
        
        quadric = gluNewQuadric()
        
        # Body (elongated sphere)
        glPushMatrix()
        glScalef(1, 1, 1.4)
        gluSphere(quadric, entity.size * 0.45 * pulse, 20, 20)
        glPopMatrix()
        
        # Head
        glPushMatrix()
        glTranslatef(0, 0, entity.size * 0.85)
        gluSphere(quadric, entity.size * 0.22 * pulse, 16, 16)
        glPopMatrix()
        
        gluDeleteQuadric(quadric)
        
        # Movement direction arrow
        if entity.is_moving:
            vx, vy, _ = entity.velocity
            speed = math.sqrt(vx*vx + vy*vy)
            if speed > 0.1:
                glDisable(GL_LIGHTING)
                glColor4f(1, 0.4, 0.4, alpha * 0.9)
                glLineWidth(3.0)
                glBegin(GL_LINES)
                glVertex3f(0, 0, entity.size * 0.5)
                glVertex3f(vx / speed * 0.9, vy / speed * 0.9, entity.size * 0.5)
                glEnd()
                glEnable(GL_LIGHTING)
                
    def _draw_device_model(self, entity: Entity, alpha: float):
        """Draw device as cube with glow."""
        r, g, b = entity.color
        s = entity.size * 0.4
        
        glColor4f(r, g, b, alpha)
        
        # Cube faces
        glBegin(GL_QUADS)
        # Top
        glNormal3f(0, 0, 1)
        glVertex3f(-s, -s, s*2)
        glVertex3f(s, -s, s*2)
        glVertex3f(s, s, s*2)
        glVertex3f(-s, s, s*2)
        # Front
        glNormal3f(0, -1, 0)
        glVertex3f(-s, -s, 0)
        glVertex3f(s, -s, 0)
        glVertex3f(s, -s, s*2)
        glVertex3f(-s, -s, s*2)
        # Back
        glNormal3f(0, 1, 0)
        glVertex3f(-s, s, 0)
        glVertex3f(-s, s, s*2)
        glVertex3f(s, s, s*2)
        glVertex3f(s, s, 0)
        # Left
        glNormal3f(-1, 0, 0)
        glVertex3f(-s, -s, 0)
        glVertex3f(-s, -s, s*2)
        glVertex3f(-s, s, s*2)
        glVertex3f(-s, s, 0)
        # Right
        glNormal3f(1, 0, 0)
        glVertex3f(s, -s, 0)
        glVertex3f(s, s, 0)
        glVertex3f(s, s, s*2)
        glVertex3f(s, -s, s*2)
        # Bottom
        glNormal3f(0, 0, -1)
        glVertex3f(-s, -s, 0)
        glVertex3f(-s, s, 0)
        glVertex3f(s, s, 0)
        glVertex3f(s, -s, 0)
        glEnd()
        
        # Edge glow
        glDisable(GL_LIGHTING)
        glColor4f(r, g, b, alpha * 0.7)
        glLineWidth(1.5)
        glBegin(GL_LINE_LOOP)
        glVertex3f(-s, -s, s*2)
        glVertex3f(s, -s, s*2)
        glVertex3f(s, s, s*2)
        glVertex3f(-s, s, s*2)
        glEnd()
        glEnable(GL_LIGHTING)
        
    def _draw_generic_model(self, entity: Entity, alpha: float):
        """Draw generic object as sphere."""
        r, g, b = entity.color
        glColor4f(r, g, b, alpha)
        
        quadric = gluNewQuadric()
        gluSphere(quadric, entity.size * 0.35, 16, 16)
        gluDeleteQuadric(quadric)
        
    def _draw_signal_bar(self, x: float, y: float, z: float, strength: float, alpha: float):
        """Draw floating signal strength indicator."""
        glDisable(GL_LIGHTING)
        
        bar_w = 0.35
        bar_h = 0.06
        
        glPushMatrix()
        glTranslatef(x - bar_w/2, y, z)
        
        # Background
        glColor4f(0.15, 0.15, 0.15, alpha * 0.6)
        glBegin(GL_QUADS)
        glVertex3f(0, 0, 0)
        glVertex3f(bar_w, 0, 0)
        glVertex3f(bar_w, 0, bar_h)
        glVertex3f(0, 0, bar_h)
        glEnd()
        
        # Fill color based on strength
        if strength > 0.65:
            glColor4f(0.2, 1.0, 0.4, alpha * 0.9)
        elif strength > 0.35:
            glColor4f(1.0, 0.85, 0.2, alpha * 0.9)
        else:
            glColor4f(1.0, 0.3, 0.3, alpha * 0.9)
        
        glBegin(GL_QUADS)
        glVertex3f(0, 0, 0)
        glVertex3f(bar_w * strength, 0, 0)
        glVertex3f(bar_w * strength, 0, bar_h)
        glVertex3f(0, 0, bar_h)
        glEnd()
        
        # Border
        glColor4f(1, 1, 1, alpha * 0.3)
        glLineWidth(1.0)
        glBegin(GL_LINE_LOOP)
        glVertex3f(0, 0, 0)
        glVertex3f(bar_w, 0, 0)
        glVertex3f(bar_w, 0, bar_h)
        glVertex3f(0, 0, bar_h)
        glEnd()
        
        glPopMatrix()
        glEnable(GL_LIGHTING)
        
    def _render_hud(self):
        """Render 2D HUD overlay."""
        # Not implementing complex 2D overlay in fixed-pipeline OpenGL
        # Status is shown in Qt status bar instead
        pass
        
    def process_data(self, data: dict):
        """Process incoming ESP32 data."""
        scan = data.get('scan', {})
        now = time.time()
        
        for det in scan.get('detections', []):
            mac = det.get('mac', '')
            if not mac or mac == '00:00:00:00:00:00':
                continue
            
            rssi = det.get('rssi', -100)
            antenna = det.get('antenna', 0)
            is_remote = antenna >= 100
            
            entity = self.engine.process_detection(mac, rssi, is_remote)
            
            # Add signal pulse effect occasionally
            if entity.signal_strength > 0.25 and np.random.random() < 0.03:
                color = (0, 1, 0.5) if not is_remote else (0, 0.7, 1)
                origin = PRIMARY_POS if not is_remote else REMOTE_POS
                self.engine.add_pulse(origin, color)
                
    def mousePressEvent(self, event):
        """Handle mouse press."""
        self.last_mouse = event.pos()
        
    def mouseMoveEvent(self, event):
        """Handle mouse drag for camera rotation."""
        if self.last_mouse and event.buttons() & Qt.MouseButton.LeftButton:
            dx = event.pos().x() - self.last_mouse.x()
            dy = event.pos().y() - self.last_mouse.y()
            
            self.cam_azimuth = (self.cam_azimuth + dx * 0.4) % 360
            self.cam_elevation = max(5, min(85, self.cam_elevation + dy * 0.25))
            
            self.last_mouse = event.pos()
            self.update()
            
    def mouseReleaseEvent(self, event):
        """Handle mouse release."""
        self.last_mouse = None
        
    def wheelEvent(self, event):
        """Handle mouse wheel for zoom."""
        delta = event.angleDelta().y() / 120
        self.cam_distance = max(4, min(30, self.cam_distance - delta * 0.8))
        self.update()


# ==================== Main Window ====================

class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛰️ HydraSense OpenGL 3D Scanner")
        self.setMinimumSize(1280, 800)
        self.resize(1600, 1000)
        
        self.setStyleSheet("""
            QMainWindow { background: #020510; }
            QStatusBar { 
                background: #0a1222; 
                color: #9ec5ff; 
                border-top: 1px solid #1a3050;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                padding: 3px;
            }
            QLabel { color: #d0e5ff; }
        """)
        
        # Configure OpenGL format
        fmt = QSurfaceFormat()
        fmt.setSamples(8)  # Antialiasing
        fmt.setDepthBufferSize(24)
        fmt.setStencilBufferSize(8)
        QSurfaceFormat.setDefaultFormat(fmt)
        
        # Create OpenGL renderer
        self.renderer = OpenGL3DRenderer()
        self.setCentralWidget(self.renderer)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.conn_label = QLabel("⏳ Connecting...")
        self.pps_label = QLabel("📡 -- pps")
        self.entities_label = QLabel("👥 0 entities")
        self.remote_label = QLabel("🔗 Remote: --")
        self.fps_label = QLabel("🎮 -- FPS")
        
        self.status_bar.addWidget(self.conn_label)
        self.status_bar.addWidget(self._separator())
        self.status_bar.addWidget(self.pps_label)
        self.status_bar.addWidget(self._separator())
        self.status_bar.addWidget(self.entities_label)
        self.status_bar.addWidget(self._separator())
        self.status_bar.addWidget(self.remote_label)
        self.status_bar.addWidget(self._separator())
        self.status_bar.addWidget(self.fps_label)
        self.status_bar.addPermanentWidget(QLabel("🖱️ Drag to rotate  │  Scroll to zoom"))
        
        # FPS update timer
        self.fps_timer = QTimer()
        self.fps_timer.timeout.connect(self._update_fps)
        self.fps_timer.start(500)
        
        # Start data fetcher
        self.fetcher = DataFetcher(ESP32_HOST, ESP32_PORT)
        self.fetcher.data_received.connect(self._on_data)
        self.fetcher.status_changed.connect(self._on_status)
        self.fetcher.start()
        
    def _separator(self) -> QLabel:
        """Create a separator label."""
        sep = QLabel(" │ ")
        sep.setStyleSheet("color: #3a5a80;")
        return sep
        
    def _update_fps(self):
        """Update FPS display."""
        self.fps_label.setText(f"🎮 {self.renderer.fps:.0f} FPS")
        
    def _on_data(self, data: dict):
        """Handle incoming data."""
        self.renderer.process_data(data)
        
        status = data.get('status', {})
        remotes = data.get('remotes', {})
        
        pps = status.get('pps', 0)
        self.pps_label.setText(f"📡 {pps} pps")
        
        entities = self.renderer.engine.get_active_entities()
        moving = sum(1 for e in entities if e.is_moving)
        self.entities_label.setText(f"👥 {len(entities)} entities ({moving} moving)")
        
        remote_list = remotes.get('remotes', [])
        if remote_list:
            r = remote_list[0]
            node_id = r.get('node_id', 'N/A')
            rssi = r.get('rssi', 0)
            self.remote_label.setText(f"🔗 {node_id} ({rssi} dBm)")
            self.remote_label.setStyleSheet("color: #00ff88;")
        else:
            self.remote_label.setText("🔗 Remote: Offline")
            self.remote_label.setStyleSheet("color: #ff6b6b;")
            
    def _on_status(self, connected: bool, info: str):
        """Handle connection status change."""
        if connected:
            self.conn_label.setText(f"🟢 {info}")
            self.conn_label.setStyleSheet("color: #00ff88;")
        else:
            self.conn_label.setText(f"🔴 {info}")
            self.conn_label.setStyleSheet("color: #ff6b6b;")
            
    def closeEvent(self, event):
        """Clean up on close."""
        self.fetcher.stop()
        self.fetcher.wait()
        super().closeEvent(event)


# ==================== Entry Point ====================

def main():
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
