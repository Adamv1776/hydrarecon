#!/usr/bin/env python3
"""
HydraSense Environment Reconstruction Scanner
==============================================
Full 3D environment reconstruction using WiFi signal analysis:
- Voxel-based structure detection from signal attenuation
- Kalman-filtered entity tracking with movement detection  
- Dual-sensor triangulation for position estimation
- Real-time OpenGL visualization
"""

import sys
import json
import math
import time
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set
import numpy as np

from PyQt6.QtWidgets import (QApplication, QMainWindow, QStatusBar, QLabel, 
                              QDockWidget, QWidget, QVBoxLayout, QProgressBar)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QSurfaceFormat, QFont
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

# Sensor positions (x, y, z) in meters - ~15 feet apart
PRIMARY_POS = np.array([0.5, 0.5, 0.3])
REMOTE_POS = np.array([5.0, 0.5, 0.3])

# Voxel grid resolution
VOXEL_RES = 0.25  # 25cm voxels
GRID_X = int(ROOM_WIDTH / VOXEL_RES)
GRID_Y = int(ROOM_DEPTH / VOXEL_RES)
GRID_Z = int(ROOM_HEIGHT / VOXEL_RES)


# ==================== Kalman Filter for Tracking ====================

class KalmanTracker:
    """Simple 2D Kalman filter for position tracking."""
    
    def __init__(self, x: float, y: float, z: float):
        # State: [x, y, z, vx, vy, vz]
        self.state = np.array([x, y, z, 0.0, 0.0, 0.0])
        
        # State covariance
        self.P = np.eye(6) * 1.0
        
        # Process noise
        self.Q = np.eye(6) * 0.1
        self.Q[3:, 3:] *= 0.5  # Lower noise for velocity
        
        # Measurement noise
        self.R = np.eye(3) * 0.5
        
        # State transition matrix
        self.dt = 0.1
        self.F = np.eye(6)
        self.F[0, 3] = self.dt
        self.F[1, 4] = self.dt
        self.F[2, 5] = self.dt
        
        # Measurement matrix (we only measure position)
        self.H = np.zeros((3, 6))
        self.H[0, 0] = 1
        self.H[1, 1] = 1
        self.H[2, 2] = 1
        
    def predict(self, dt: float = None):
        """Predict next state."""
        if dt:
            self.F[0, 3] = dt
            self.F[1, 4] = dt
            self.F[2, 5] = dt
        
        self.state = self.F @ self.state
        self.P = self.F @ self.P @ self.F.T + self.Q
        
    def update(self, x: float, y: float, z: float):
        """Update with measurement."""
        z_meas = np.array([x, y, z])
        
        # Innovation
        y_innov = z_meas - self.H @ self.state
        S = self.H @ self.P @ self.H.T + self.R
        
        # Kalman gain
        K = self.P @ self.H.T @ np.linalg.inv(S)
        
        # Update state
        self.state = self.state + K @ y_innov
        self.P = (np.eye(6) - K @ self.H) @ self.P
        
    @property
    def position(self) -> Tuple[float, float, float]:
        return (self.state[0], self.state[1], self.state[2])
    
    @property
    def velocity(self) -> Tuple[float, float, float]:
        return (self.state[3], self.state[4], self.state[5])
    
    @property
    def speed(self) -> float:
        return np.linalg.norm(self.state[3:6])


# ==================== Entity Tracking ====================

@dataclass
class TrackedEntity:
    """A tracked entity in the environment."""
    mac: str
    tracker: KalmanTracker = None
    rssi_primary: int = -100
    rssi_remote: int = -100
    last_seen_primary: float = 0
    last_seen_remote: float = 0
    detection_count: int = 0
    trail: List[Tuple[float, float, float, float]] = field(default_factory=list)
    is_stationary: bool = True
    entity_class: str = "unknown"  # person, device, object
    color: Tuple[float, float, float] = (0.5, 0.5, 0.5)
    
    @property
    def x(self) -> float:
        return self.tracker.position[0] if self.tracker else 0
    
    @property
    def y(self) -> float:
        return self.tracker.position[1] if self.tracker else 0
    
    @property
    def z(self) -> float:
        return self.tracker.position[2] if self.tracker else 1.0
    
    @property
    def velocity(self) -> Tuple[float, float, float]:
        return self.tracker.velocity if self.tracker else (0, 0, 0)
    
    @property
    def speed(self) -> float:
        return self.tracker.speed if self.tracker else 0
    
    @property
    def signal_strength(self) -> float:
        avg = (self.rssi_primary + self.rssi_remote) / 2
        return max(0, min(1, (avg + 100) / 60))
    
    @property
    def last_seen(self) -> float:
        return max(self.last_seen_primary, self.last_seen_remote)


# ==================== Environment Reconstruction Engine ====================

class ReconstructionEngine:
    """
    Handles structure detection and entity tracking using WiFi signals.
    
    Structure Detection:
    - Builds occupancy grid from signal attenuation patterns
    - Strong attenuation along paths indicates obstacles/walls
    
    Entity Tracking:
    - Triangulates positions using dual-sensor RSSI
    - Kalman filters for smooth tracking
    - Movement classification
    """
    
    RSSI_REF = -35  # Reference RSSI at 1 meter
    PATH_LOSS_FREE = 2.0  # Free space path loss exponent
    PATH_LOSS_INDOOR = 3.0  # Indoor path loss exponent
    
    def __init__(self):
        # Entity tracking
        self.entities: Dict[str, TrackedEntity] = {}
        self.mac_rssi_buffer: Dict[str, Dict[str, List[Tuple[int, float]]]] = defaultdict(lambda: {'primary': [], 'remote': []})
        
        # Structure reconstruction - occupancy probability grid
        self.occupancy_grid = np.zeros((GRID_X, GRID_Y, GRID_Z), dtype=np.float32)
        self.occupancy_hits = np.zeros((GRID_X, GRID_Y, GRID_Z), dtype=np.int32)
        
        # Signal strength field (for visualization)
        self.signal_field = np.zeros((GRID_X, GRID_Y), dtype=np.float32)
        
        # Statistics
        self.total_detections = 0
        self.structure_updates = 0
        
        # Known infrastructure MACs (routers, APs - don't track as people)
        self.infrastructure_macs: Set[str] = set()
        
    def rssi_to_distance(self, rssi: int, path_loss: float = None) -> float:
        """Convert RSSI to estimated distance."""
        if rssi >= 0 or rssi < -100:
            return 10.0
        pl = path_loss or self.PATH_LOSS_INDOOR
        distance = 10 ** ((self.RSSI_REF - rssi) / (10 * pl))
        return min(max(distance, 0.1), 15.0)
    
    def triangulate(self, rssi_primary: int, rssi_remote: int) -> Tuple[float, float, float]:
        """Triangulate position from dual RSSI readings."""
        d1 = self.rssi_to_distance(rssi_primary)
        d2 = self.rssi_to_distance(rssi_remote)
        
        # Sensor separation
        sensor_vec = REMOTE_POS - PRIMARY_POS
        d_sensors = np.linalg.norm(sensor_vec[:2])
        
        if d_sensors < 0.1:
            return (ROOM_WIDTH/2, ROOM_DEPTH/2, 1.0)
        
        # Trilateration
        a = (d1*d1 - d2*d2 + d_sensors*d_sensors) / (2 * d_sensors)
        h_sq = d1*d1 - a*a
        
        if h_sq < 0:
            # Circles don't intersect - weighted average
            w1 = 1 / (d1 + 0.1)
            w2 = 1 / (d2 + 0.1)
            total = w1 + w2
            x = (PRIMARY_POS[0] * w1 + REMOTE_POS[0] * w2) / total
            y = (PRIMARY_POS[1] * w1 + REMOTE_POS[1] * w2) / total
        else:
            h = math.sqrt(h_sq)
            # Point along sensor axis
            unit_vec = sensor_vec[:2] / d_sensors
            px = PRIMARY_POS[0] + a * unit_vec[0]
            py = PRIMARY_POS[1] + a * unit_vec[1]
            # Perpendicular offset (pick the point inside the room)
            perp = np.array([-unit_vec[1], unit_vec[0]])
            x = px + h * perp[0]
            y = py + h * perp[1]
            
            # If outside room, try the other intersection
            if not (0 < x < ROOM_WIDTH and 0 < y < ROOM_DEPTH):
                x = px - h * perp[0]
                y = py - h * perp[1]
        
        # Clamp to room
        x = max(0.2, min(ROOM_WIDTH - 0.2, x))
        y = max(0.2, min(ROOM_DEPTH - 0.2, y))
        
        # Estimate Z from average signal strength
        avg_rssi = (rssi_primary + rssi_remote) / 2
        z = 0.8 + (avg_rssi + 70) * 0.02
        z = max(0.3, min(ROOM_HEIGHT - 0.3, z))
        
        return (x, y, z)
    
    def update_structure(self, entity: TrackedEntity):
        """
        Update occupancy grid based on signal paths.
        
        The idea: if signal between sensors is weaker than expected
        for a given distance, there's likely an obstacle in the path.
        """
        if entity.rssi_primary < -90 or entity.rssi_remote < -90:
            return
        
        x, y, z = entity.x, entity.y, entity.z
        
        # Expected RSSI based on free-space distance
        d1 = np.linalg.norm(np.array([x, y, z]) - PRIMARY_POS)
        d2 = np.linalg.norm(np.array([x, y, z]) - REMOTE_POS)
        
        expected_rssi_1 = self.RSSI_REF - 10 * self.PATH_LOSS_FREE * math.log10(max(d1, 0.1))
        expected_rssi_2 = self.RSSI_REF - 10 * self.PATH_LOSS_FREE * math.log10(max(d2, 0.1))
        
        # Attenuation = expected - actual (positive = obstacle absorbing signal)
        atten_1 = expected_rssi_1 - entity.rssi_primary
        atten_2 = expected_rssi_2 - entity.rssi_remote
        
        # If significant attenuation, mark path as potentially blocked
        if atten_1 > 5 or atten_2 > 5:
            self._mark_path_attenuation(PRIMARY_POS, np.array([x, y, z]), atten_1)
            self._mark_path_attenuation(REMOTE_POS, np.array([x, y, z]), atten_2)
            self.structure_updates += 1
        
        # Update signal strength field for floor visualization
        gx = int(x / VOXEL_RES)
        gy = int(y / VOXEL_RES)
        if 0 <= gx < GRID_X and 0 <= gy < GRID_Y:
            strength = entity.signal_strength
            self.signal_field[gx, gy] = max(self.signal_field[gx, gy], strength)
            # Decay neighbors slightly
            for dx in [-1, 0, 1]:
                for dy in [-1, 0, 1]:
                    nx, ny = gx + dx, gy + dy
                    if 0 <= nx < GRID_X and 0 <= ny < GRID_Y:
                        self.signal_field[nx, ny] = max(
                            self.signal_field[nx, ny] * 0.95,
                            strength * 0.3
                        )
    
    def _mark_path_attenuation(self, start: np.ndarray, end: np.ndarray, attenuation: float):
        """Mark voxels along a path as potentially containing obstacles."""
        if attenuation <= 0:
            return
        
        # Bresenham-like 3D line through voxels
        direction = end - start
        length = np.linalg.norm(direction)
        if length < 0.1:
            return
        
        direction = direction / length
        steps = int(length / (VOXEL_RES * 0.5))
        
        prob_increment = min(0.1, attenuation / 100)
        
        for i in range(steps):
            t = i / max(steps, 1)
            point = start + direction * length * t
            
            gx = int(point[0] / VOXEL_RES)
            gy = int(point[1] / VOXEL_RES)
            gz = int(point[2] / VOXEL_RES)
            
            if 0 <= gx < GRID_X and 0 <= gy < GRID_Y and 0 <= gz < GRID_Z:
                # Higher probability in middle of path (more likely obstacle location)
                weight = math.sin(t * math.pi)  # Peak in middle
                self.occupancy_grid[gx, gy, gz] += prob_increment * weight
                self.occupancy_hits[gx, gy, gz] += 1
    
    def process_detection(self, mac: str, rssi: int, source: str, timestamp: float = None):
        """Process a single detection from primary or remote sensor."""
        now = timestamp or time.time()
        self.total_detections += 1
        
        is_remote = source == "remote"
        
        # Buffer RSSI readings
        buffer = self.mac_rssi_buffer[mac]
        key = 'remote' if is_remote else 'primary'
        buffer[key].append((rssi, now))
        
        # Keep only recent readings (last 2 seconds)
        buffer[key] = [(r, t) for r, t in buffer[key] if now - t < 2.0]
        
        # Create or update entity
        if mac not in self.entities:
            self.entities[mac] = TrackedEntity(mac=mac)
        
        entity = self.entities[mac]
        entity.detection_count += 1
        
        # Update RSSI (use median of recent readings for stability)
        if buffer['primary']:
            readings = [r for r, t in buffer['primary']]
            entity.rssi_primary = int(np.median(readings))
            entity.last_seen_primary = now
        
        if buffer['remote']:
            readings = [r for r, t in buffer['remote']]
            entity.rssi_remote = int(np.median(readings))
            entity.last_seen_remote = now
        
        # Only triangulate if we have recent readings from BOTH sensors
        have_primary = now - entity.last_seen_primary < 1.5
        have_remote = now - entity.last_seen_remote < 1.5
        
        if have_primary and have_remote and entity.rssi_primary > -95 and entity.rssi_remote > -95:
            x, y, z = self.triangulate(entity.rssi_primary, entity.rssi_remote)
            
            # Initialize or update Kalman tracker
            if entity.tracker is None:
                entity.tracker = KalmanTracker(x, y, z)
            else:
                dt = now - entity.last_seen
                entity.tracker.predict(dt)
                entity.tracker.update(x, y, z)
            
            # Update trail
            pos = entity.tracker.position
            entity.trail.append((pos[0], pos[1], pos[2], now))
            if len(entity.trail) > 100:
                entity.trail.pop(0)
            
            # Classify entity based on behavior
            self._classify_entity(entity)
            
            # Update structure grid
            self.update_structure(entity)
        
        return entity
    
    def _classify_entity(self, entity: TrackedEntity):
        """Classify entity as person, device, or object."""
        speed = entity.speed
        signal = entity.signal_strength
        detections = entity.detection_count
        
        # Check movement history
        if len(entity.trail) >= 10:
            positions = np.array([(t[0], t[1]) for t in entity.trail[-10:]])
            movement_range = np.max(positions, axis=0) - np.min(positions, axis=0)
            total_movement = np.sum(np.linalg.norm(movement_range))
            entity.is_stationary = total_movement < 0.3
        else:
            entity.is_stationary = speed < 0.1
        
        # Classification logic
        if not entity.is_stationary and speed > 0.15:
            entity.entity_class = "person"
            entity.color = (1.0, 0.3, 0.3)  # Red for people
        elif entity.is_stationary and signal > 0.5 and detections > 50:
            entity.entity_class = "device"
            entity.color = (0.3, 0.7, 1.0)  # Blue for devices
        elif signal > 0.3:
            entity.entity_class = "object"
            entity.color = (0.3, 1.0, 0.5)  # Green for objects
        else:
            entity.entity_class = "weak"
            entity.color = (0.5, 0.5, 0.5)  # Gray for weak signals
    
    def get_active_entities(self, max_age: float = 8.0) -> List[TrackedEntity]:
        """Get recently seen entities with valid positions."""
        now = time.time()
        active = []
        for entity in self.entities.values():
            if entity.tracker and now - entity.last_seen < max_age:
                active.append(entity)
        return active
    
    def get_moving_entities(self) -> List[TrackedEntity]:
        """Get entities currently moving."""
        return [e for e in self.get_active_entities() if not e.is_stationary]
    
    def get_structure_voxels(self, threshold: float = 0.3) -> List[Tuple[int, int, int, float]]:
        """Get voxels with high occupancy probability (likely walls/obstacles)."""
        voxels = []
        # Normalize by hits
        for x in range(GRID_X):
            for y in range(GRID_Y):
                for z in range(GRID_Z):
                    hits = self.occupancy_hits[x, y, z]
                    if hits > 5:  # Need enough samples
                        prob = self.occupancy_grid[x, y, z] / hits
                        if prob > threshold:
                            voxels.append((x, y, z, prob))
        return voxels
    
    def decay_grids(self, factor: float = 0.995):
        """Slowly decay grids to allow structure to update over time."""
        self.signal_field *= factor
        # Don't decay occupancy too fast - structure is more permanent


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
                # Fast endpoints
                status = self._fetch(f"http://{self.host}:{self.port}/status", timeout=2.0)
                remotes = self._fetch(f"http://{self.host}:{self.port}/remotes", timeout=2.0)
                
                # Scan endpoint (slower, fetch every other cycle)
                self.scan_counter += 1
                if self.scan_counter >= 2:
                    scan = self._fetch(f"http://{self.host}:{self.port}/scan", timeout=10.0)
                    if scan:
                        self.last_scan = scan
                    self.scan_counter = 0
                
                if status:
                    self.data_received.emit({
                        'status': status,
                        'scan': self.last_scan,
                        'remotes': remotes or {}
                    })
                    self.status_changed.emit(True, self.host)
                else:
                    self.status_changed.emit(False, "No response")
                    
            except Exception as e:
                self.status_changed.emit(False, str(e)[:30])
            
            time.sleep(0.15)
    
    def _fetch(self, url: str, timeout: float = 3.0) -> Optional[dict]:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'HydraRecon/4.0'})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.loads(response.read())
        except Exception:
            return None
    
    def stop(self):
        self.running = False


# ==================== OpenGL 3D Renderer ====================

class ReconRenderer(QOpenGLWidget):
    """OpenGL renderer for environment reconstruction visualization."""
    
    def __init__(self):
        super().__init__()
        
        self.engine = ReconstructionEngine()
        
        # Camera
        self.cam_dist = 14.0
        self.cam_azimuth = 45.0
        self.cam_elevation = 40.0
        self.cam_target = [ROOM_WIDTH/2, ROOM_DEPTH/2, 1.0]
        
        # Animation
        self.time = 0
        self.scan_angle = 0
        
        # Mouse
        self.last_mouse = None
        self.setMouseTracking(True)
        
        # FPS tracking
        self.fps = 0
        self.frame_count = 0
        self.fps_time = time.time()
        
        # Animation timer
        self.timer = QTimer()
        self.timer.timeout.connect(self._tick)
        self.timer.start(16)
        
    def _tick(self):
        self.time += 0.016
        self.scan_angle = (self.scan_angle + 1.5) % 360
        self.engine.decay_grids()
        
        self.frame_count += 1
        now = time.time()
        if now - self.fps_time >= 1.0:
            self.fps = self.frame_count / (now - self.fps_time)
            self.frame_count = 0
            self.fps_time = now
        
        self.update()
    
    def initializeGL(self):
        glClearColor(0.02, 0.04, 0.1, 1.0)
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_BLEND)
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA)
        glEnable(GL_LINE_SMOOTH)
        glEnable(GL_POINT_SMOOTH)
        glHint(GL_LINE_SMOOTH_HINT, GL_NICEST)
        
        # Lighting
        glEnable(GL_LIGHTING)
        glEnable(GL_LIGHT0)
        glEnable(GL_COLOR_MATERIAL)
        glColorMaterial(GL_FRONT_AND_BACK, GL_AMBIENT_AND_DIFFUSE)
        
        glLightfv(GL_LIGHT0, GL_POSITION, [ROOM_WIDTH/2, ROOM_DEPTH/2, 8.0, 1.0])
        glLightfv(GL_LIGHT0, GL_DIFFUSE, [0.8, 0.85, 0.95, 1.0])
        glLightfv(GL_LIGHT0, GL_AMBIENT, [0.2, 0.22, 0.28, 1.0])
        
    def resizeGL(self, w, h):
        glViewport(0, 0, w, h)
        glMatrixMode(GL_PROJECTION)
        glLoadIdentity()
        gluPerspective(50, w / max(h, 1), 0.1, 100.0)
        glMatrixMode(GL_MODELVIEW)
        
    def paintGL(self):
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
        glLoadIdentity()
        
        # Camera
        az = math.radians(self.cam_azimuth)
        el = math.radians(self.cam_elevation)
        
        cx = self.cam_target[0] + self.cam_dist * math.cos(el) * math.sin(az)
        cy = self.cam_target[1] + self.cam_dist * math.cos(el) * math.cos(az)
        cz = self.cam_target[2] + self.cam_dist * math.sin(el)
        
        gluLookAt(cx, cy, cz, *self.cam_target, 0, 0, 1)
        
        # Render layers
        self._render_room()
        self._render_signal_heatmap()
        self._render_structure()
        self._render_sensors()
        self._render_entities()
        self._render_tracking_beams()
        
    def _render_room(self):
        """Render room boundaries."""
        # Floor
        glEnable(GL_LIGHTING)
        glColor4f(0.05, 0.08, 0.15, 1.0)
        glBegin(GL_QUADS)
        glNormal3f(0, 0, 1)
        glVertex3f(0, 0, 0)
        glVertex3f(ROOM_WIDTH, 0, 0)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, 0)
        glVertex3f(0, ROOM_DEPTH, 0)
        glEnd()
        
        # Walls (transparent)
        glColor4f(0.1, 0.15, 0.25, 0.2)
        
        # Back wall
        glBegin(GL_QUADS)
        glVertex3f(0, ROOM_DEPTH, 0)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, 0)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, ROOM_HEIGHT)
        glVertex3f(0, ROOM_DEPTH, ROOM_HEIGHT)
        glEnd()
        
        # Side walls
        glBegin(GL_QUADS)
        glVertex3f(0, 0, 0)
        glVertex3f(0, ROOM_DEPTH, 0)
        glVertex3f(0, ROOM_DEPTH, ROOM_HEIGHT)
        glVertex3f(0, 0, ROOM_HEIGHT)
        glEnd()
        
        glBegin(GL_QUADS)
        glVertex3f(ROOM_WIDTH, 0, 0)
        glVertex3f(ROOM_WIDTH, 0, ROOM_HEIGHT)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, ROOM_HEIGHT)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, 0)
        glEnd()
        
        # Edges
        glDisable(GL_LIGHTING)
        glLineWidth(2.0)
        glColor4f(0.15, 0.4, 0.7, 0.6)
        
        glBegin(GL_LINE_LOOP)
        glVertex3f(0, 0, 0)
        glVertex3f(ROOM_WIDTH, 0, 0)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, 0)
        glVertex3f(0, ROOM_DEPTH, 0)
        glEnd()
        
        glColor4f(0.1, 0.3, 0.5, 0.4)
        glBegin(GL_LINES)
        for x, y in [(0, 0), (ROOM_WIDTH, 0), (ROOM_WIDTH, ROOM_DEPTH), (0, ROOM_DEPTH)]:
            glVertex3f(x, y, 0)
            glVertex3f(x, y, ROOM_HEIGHT)
        glEnd()
        
        # Grid
        glLineWidth(1.0)
        glColor4f(0.1, 0.2, 0.35, 0.3)
        glBegin(GL_LINES)
        for i in range(int(ROOM_WIDTH) + 1):
            glVertex3f(i, 0, 0.01)
            glVertex3f(i, ROOM_DEPTH, 0.01)
        for i in range(int(ROOM_DEPTH) + 1):
            glVertex3f(0, i, 0.01)
            glVertex3f(ROOM_WIDTH, i, 0.01)
        glEnd()
        
        glEnable(GL_LIGHTING)
        
    def _render_signal_heatmap(self):
        """Render signal strength heatmap on floor."""
        glDisable(GL_LIGHTING)
        
        field = self.engine.signal_field
        
        glBegin(GL_QUADS)
        for gx in range(GRID_X):
            for gy in range(GRID_Y):
                strength = field[gx, gy]
                if strength > 0.05:
                    x = gx * VOXEL_RES
                    y = gy * VOXEL_RES
                    
                    # Color based on strength
                    r = strength
                    g = strength * 0.5
                    b = 0.2
                    alpha = strength * 0.4
                    
                    glColor4f(r, g, b, alpha)
                    glVertex3f(x, y, 0.02)
                    glVertex3f(x + VOXEL_RES, y, 0.02)
                    glVertex3f(x + VOXEL_RES, y + VOXEL_RES, 0.02)
                    glVertex3f(x, y + VOXEL_RES, 0.02)
        glEnd()
        
        glEnable(GL_LIGHTING)
        
    def _render_structure(self):
        """Render detected obstacles/walls from occupancy grid."""
        glEnable(GL_LIGHTING)
        
        voxels = self.engine.get_structure_voxels(threshold=0.25)
        
        for gx, gy, gz, prob in voxels:
            x = gx * VOXEL_RES
            y = gy * VOXEL_RES
            z = gz * VOXEL_RES
            s = VOXEL_RES * 0.9
            
            # Color based on probability (yellow/orange for obstacles)
            alpha = min(0.7, prob)
            glColor4f(1.0, 0.7, 0.2, alpha)
            
            self._draw_cube(x + s/2, y + s/2, z + s/2, s/2)
        
    def _draw_cube(self, x, y, z, size):
        """Draw a cube at position."""
        s = size
        
        glPushMatrix()
        glTranslatef(x, y, z)
        
        glBegin(GL_QUADS)
        # Top
        glNormal3f(0, 0, 1)
        glVertex3f(-s, -s, s)
        glVertex3f(s, -s, s)
        glVertex3f(s, s, s)
        glVertex3f(-s, s, s)
        # Bottom
        glNormal3f(0, 0, -1)
        glVertex3f(-s, -s, -s)
        glVertex3f(-s, s, -s)
        glVertex3f(s, s, -s)
        glVertex3f(s, -s, -s)
        # Front
        glNormal3f(0, -1, 0)
        glVertex3f(-s, -s, -s)
        glVertex3f(s, -s, -s)
        glVertex3f(s, -s, s)
        glVertex3f(-s, -s, s)
        # Back
        glNormal3f(0, 1, 0)
        glVertex3f(-s, s, -s)
        glVertex3f(-s, s, s)
        glVertex3f(s, s, s)
        glVertex3f(s, s, -s)
        # Left
        glNormal3f(-1, 0, 0)
        glVertex3f(-s, -s, -s)
        glVertex3f(-s, -s, s)
        glVertex3f(-s, s, s)
        glVertex3f(-s, s, -s)
        # Right
        glNormal3f(1, 0, 0)
        glVertex3f(s, -s, -s)
        glVertex3f(s, s, -s)
        glVertex3f(s, s, s)
        glVertex3f(s, -s, s)
        glEnd()
        
        glPopMatrix()
        
    def _render_sensors(self):
        """Render sensor nodes."""
        sensors = [
            (PRIMARY_POS, (0, 1, 0.5), "PRIMARY"),
            (REMOTE_POS, (0, 0.7, 1), "REMOTE")
        ]
        
        for pos, color, name in sensors:
            x, y, z = pos
            
            # Sensor body
            glEnable(GL_LIGHTING)
            glColor4f(*color, 1.0)
            
            glPushMatrix()
            glTranslatef(x, y, 0)
            q = gluNewQuadric()
            gluCylinder(q, 0.15, 0.12, z + 0.15, 16, 4)
            glTranslatef(0, 0, z + 0.15)
            gluSphere(q, 0.12, 16, 16)
            gluDeleteQuadric(q)
            glPopMatrix()
            
            # Scanning effect
            glDisable(GL_LIGHTING)
            
            # Pulse rings
            for i in range(4):
                phase = (self.time * 1.5 + i) % 4
                radius = 0.3 + phase * 0.6
                alpha = max(0, 0.4 - phase * 0.1)
                
                glColor4f(*color, alpha)
                glLineWidth(2.0)
                glBegin(GL_LINE_LOOP)
                for a in range(32):
                    angle = a * math.pi * 2 / 32
                    glVertex3f(x + math.cos(angle) * radius,
                              y + math.sin(angle) * radius, z)
                glEnd()
            
            # Scan beam
            beam_angle = math.radians(self.scan_angle + (180 if name == "REMOTE" else 0))
            beam_len = 4.5
            
            glBegin(GL_TRIANGLES)
            glColor4f(*color, 0.25)
            glVertex3f(x, y, z)
            glColor4f(*color, 0.0)
            glVertex3f(x + math.cos(beam_angle - 0.15) * beam_len,
                      y + math.sin(beam_angle - 0.15) * beam_len, z)
            glVertex3f(x + math.cos(beam_angle + 0.15) * beam_len,
                      y + math.sin(beam_angle + 0.15) * beam_len, z)
            glEnd()
            
            glEnable(GL_LIGHTING)
            
    def _render_entities(self):
        """Render tracked entities."""
        now = time.time()
        entities = self.engine.get_active_entities()
        
        for entity in entities:
            age = now - entity.last_seen
            alpha = max(0.3, 1.0 - age / 8)
            
            x, y, z = entity.x, entity.y, entity.z
            
            # Trail
            if len(entity.trail) > 2:
                glDisable(GL_LIGHTING)
                glLineWidth(2.5)
                glBegin(GL_LINE_STRIP)
                for i, (tx, ty, tz, tt) in enumerate(entity.trail):
                    trail_age = now - tt
                    trail_alpha = max(0, alpha * 0.6 * (1 - trail_age / 6))
                    glColor4f(*entity.color, trail_alpha)
                    glVertex3f(tx, ty, 0.03)
                glEnd()
                glEnable(GL_LIGHTING)
            
            # Shadow
            glDisable(GL_LIGHTING)
            glColor4f(0, 0, 0, 0.25 * alpha)
            glBegin(GL_POLYGON)
            for i in range(16):
                a = i * math.pi * 2 / 16
                glVertex3f(x + math.cos(a) * 0.25, y + math.sin(a) * 0.25, 0.01)
            glEnd()
            
            # Vertical line
            glColor4f(*entity.color, alpha * 0.5)
            glLineWidth(1.0)
            glBegin(GL_LINES)
            glVertex3f(x, y, 0.02)
            glVertex3f(x, y, z)
            glEnd()
            glEnable(GL_LIGHTING)
            
            # Entity body
            glPushMatrix()
            glTranslatef(x, y, z)
            glColor4f(*entity.color, alpha)
            
            q = gluNewQuadric()
            
            if entity.entity_class == "person":
                # Humanoid shape
                pulse = 1.0 + (0.1 * math.sin(self.time * 5) if not entity.is_stationary else 0)
                glPushMatrix()
                glScalef(1, 1, 1.3)
                gluSphere(q, 0.18 * pulse, 16, 16)
                glPopMatrix()
                # Head
                glPushMatrix()
                glTranslatef(0, 0, 0.35)
                gluSphere(q, 0.1 * pulse, 12, 12)
                glPopMatrix()
                
                # Movement arrow
                if not entity.is_stationary:
                    vx, vy, vz = entity.velocity
                    speed = entity.speed
                    if speed > 0.1:
                        glDisable(GL_LIGHTING)
                        glColor4f(1, 0.4, 0.2, alpha * 0.9)
                        glLineWidth(3.0)
                        glBegin(GL_LINES)
                        glVertex3f(0, 0, 0.2)
                        glVertex3f(vx / speed * 0.6, vy / speed * 0.6, 0.2)
                        glEnd()
                        glEnable(GL_LIGHTING)
                        
            elif entity.entity_class == "device":
                # Cube
                self._draw_cube(0, 0, 0.1, 0.1)
                
            else:
                # Sphere
                gluSphere(q, 0.12, 12, 12)
            
            gluDeleteQuadric(q)
            glPopMatrix()
            
            # Signal bar
            self._draw_signal_bar(x, y, z + 0.5, entity.signal_strength, alpha)
            
    def _draw_signal_bar(self, x, y, z, strength, alpha):
        """Draw signal strength bar."""
        glDisable(GL_LIGHTING)
        
        w, h = 0.35, 0.06
        
        glPushMatrix()
        glTranslatef(x - w/2, y, z)
        
        # Background
        glColor4f(0.2, 0.2, 0.2, alpha * 0.5)
        glBegin(GL_QUADS)
        glVertex3f(0, 0, 0)
        glVertex3f(w, 0, 0)
        glVertex3f(w, 0, h)
        glVertex3f(0, 0, h)
        glEnd()
        
        # Fill
        if strength > 0.6:
            glColor4f(0.2, 1.0, 0.4, alpha * 0.8)
        elif strength > 0.35:
            glColor4f(1.0, 0.8, 0.2, alpha * 0.8)
        else:
            glColor4f(1.0, 0.3, 0.3, alpha * 0.8)
        
        glBegin(GL_QUADS)
        glVertex3f(0, 0, 0)
        glVertex3f(w * strength, 0, 0)
        glVertex3f(w * strength, 0, h)
        glVertex3f(0, 0, h)
        glEnd()
        
        glPopMatrix()
        glEnable(GL_LIGHTING)
        
    def _render_tracking_beams(self):
        """Render beams from sensors to tracked entities."""
        glDisable(GL_LIGHTING)
        now = time.time()
        
        for entity in self.engine.get_active_entities():
            if now - entity.last_seen > 3:
                continue
            
            alpha = 0.15 * entity.signal_strength
            
            # Primary beam
            if entity.rssi_primary > -90:
                glColor4f(0, 1, 0.5, alpha)
                glLineWidth(1.0)
                glBegin(GL_LINES)
                glVertex3f(*PRIMARY_POS)
                glVertex3f(entity.x, entity.y, entity.z)
                glEnd()
            
            # Remote beam
            if entity.rssi_remote > -90:
                glColor4f(0, 0.7, 1, alpha)
                glBegin(GL_LINES)
                glVertex3f(*REMOTE_POS)
                glVertex3f(entity.x, entity.y, entity.z)
                glEnd()
        
        glEnable(GL_LIGHTING)
        
    def process_data(self, data: dict):
        """Process incoming detection data."""
        scan = data.get('scan', {})
        
        for det in scan.get('detections', []):
            mac = det.get('mac', '')
            if not mac or mac == '00:00:00:00:00:00':
                continue
            
            rssi = det.get('rssi', -100)
            source = det.get('source', 'local')
            
            self.engine.process_detection(mac, rssi, source)
            
    def mousePressEvent(self, event):
        self.last_mouse = event.pos()
        
    def mouseMoveEvent(self, event):
        if self.last_mouse and event.buttons() & Qt.MouseButton.LeftButton:
            dx = event.pos().x() - self.last_mouse.x()
            dy = event.pos().y() - self.last_mouse.y()
            
            self.cam_azimuth = (self.cam_azimuth + dx * 0.4) % 360
            self.cam_elevation = max(5, min(85, self.cam_elevation + dy * 0.25))
            
            self.last_mouse = event.pos()
            
    def mouseReleaseEvent(self, event):
        self.last_mouse = None
        
    def wheelEvent(self, event):
        delta = event.angleDelta().y() / 120
        self.cam_dist = max(5, min(30, self.cam_dist - delta * 0.8))


# ==================== Main Window ====================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛰️ HydraSense Environment Reconstruction")
        self.setMinimumSize(1280, 800)
        self.resize(1600, 1000)
        
        self.setStyleSheet("""
            QMainWindow { background: #0a0f1a; }
            QStatusBar { 
                background: #0d1525; 
                color: #a0c5ff; 
                border-top: 1px solid #1a3050;
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }
            QLabel { color: #d0e5ff; }
            QDockWidget { 
                color: #d0e5ff; 
                font-weight: bold;
            }
            QDockWidget::title {
                background: #0d1525;
                padding: 6px;
            }
        """)
        
        # OpenGL format
        fmt = QSurfaceFormat()
        fmt.setSamples(8)
        fmt.setDepthBufferSize(24)
        QSurfaceFormat.setDefaultFormat(fmt)
        
        # Renderer
        self.renderer = ReconRenderer()
        self.setCentralWidget(self.renderer)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.conn_label = QLabel("⏳ Connecting...")
        self.pps_label = QLabel("📡 -- pps")
        self.entities_label = QLabel("👥 0 entities")
        self.moving_label = QLabel("🚶 0 moving")
        self.structure_label = QLabel("🧱 0 voxels")
        self.remote_label = QLabel("🔗 Remote: --")
        self.fps_label = QLabel("🎮 -- FPS")
        
        for lbl in [self.conn_label, self.pps_label, self.entities_label, 
                    self.moving_label, self.structure_label, self.remote_label, self.fps_label]:
            self.status_bar.addWidget(lbl)
            self.status_bar.addWidget(QLabel(" │ "))
        
        self.status_bar.addPermanentWidget(QLabel("🖱️ Drag=Rotate  Scroll=Zoom"))
        
        # FPS timer
        self.fps_timer = QTimer()
        self.fps_timer.timeout.connect(self._update_stats)
        self.fps_timer.start(500)
        
        # Data fetcher
        self.fetcher = DataFetcher(ESP32_HOST, ESP32_PORT)
        self.fetcher.data_received.connect(self._on_data)
        self.fetcher.status_changed.connect(self._on_status)
        self.fetcher.start()
        
    def _update_stats(self):
        self.fps_label.setText(f"🎮 {self.renderer.fps:.0f} FPS")
        
        # Structure voxels
        voxels = len(self.renderer.engine.get_structure_voxels())
        self.structure_label.setText(f"🧱 {voxels} voxels")
        
    def _on_data(self, data: dict):
        self.renderer.process_data(data)
        
        status = data.get('status', {})
        remotes = data.get('remotes', {})
        
        self.pps_label.setText(f"📡 {status.get('pps', 0)} pps")
        
        entities = self.renderer.engine.get_active_entities()
        moving = self.renderer.engine.get_moving_entities()
        self.entities_label.setText(f"👥 {len(entities)} entities")
        self.moving_label.setText(f"🚶 {len(moving)} moving")
        
        remote_list = remotes.get('remotes', [])
        if remote_list:
            r = remote_list[0]
            self.remote_label.setText(f"🔗 {r.get('node_id', 'N/A')} ({r.get('rssi', 0)} dBm)")
            self.remote_label.setStyleSheet("color: #00ff88;")
        else:
            self.remote_label.setText("🔗 Remote: Offline")
            self.remote_label.setStyleSheet("color: #ff6b6b;")
            
    def _on_status(self, connected: bool, info: str):
        if connected:
            self.conn_label.setText(f"🟢 {info}")
            self.conn_label.setStyleSheet("color: #00ff88;")
        else:
            self.conn_label.setText(f"🔴 {info}")
            self.conn_label.setStyleSheet("color: #ff6b6b;")
            
    def closeEvent(self, event):
        self.fetcher.stop()
        self.fetcher.wait()
        super().closeEvent(event)


# ==================== Main ====================

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
