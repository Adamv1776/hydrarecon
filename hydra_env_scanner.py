#!/usr/bin/env python3
"""
HydraSense Environment Reconstruction Scanner
=============================================
WiFi-based 3D environment mapping with:
- Voxel grid structure reconstruction from signal attenuation
- Kalman-filtered moving object tracking
- Real-time triangulation from dual ESP32 sensors
- OpenGL 3D visualization
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
                             QDockWidget, QVBoxLayout, QWidget, QProgressBar)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QSurfaceFormat
from PyQt6.QtOpenGLWidgets import QOpenGLWidget

from OpenGL.GL import *
from OpenGL.GLU import *


# ==================== Configuration ====================

ESP32_HOST = "192.168.0.139"
ESP32_PORT = 80
FETCH_TIMEOUT = 4.0  # seconds - /scan can be large

# Room dimensions in meters
ROOM_WIDTH = 6.0
ROOM_DEPTH = 5.0
ROOM_HEIGHT = 2.8

# Voxel grid resolution for structure reconstruction
VOXEL_RES = 0.25  # meters per voxel
GRID_W = int(ROOM_WIDTH / VOXEL_RES)
GRID_D = int(ROOM_DEPTH / VOXEL_RES)
GRID_H = int(ROOM_HEIGHT / VOXEL_RES)

# Sensor positions (x, y, z) in meters
PRIMARY_POS = np.array([0.5, 0.5, 0.3])
REMOTE_POS = np.array([5.5, 0.5, 0.3])


# ==================== Structure Reconstruction ====================

class StructureGrid:
    """
    Voxel grid for environment structure reconstruction.
    Uses signal attenuation patterns to detect walls and obstacles.
    """
    
    def __init__(self):
        # Occupancy grid: probability that each voxel contains an obstacle
        self.occupancy = np.zeros((GRID_W, GRID_D, GRID_H), dtype=np.float32)
        # Confidence: how many observations contributed to each voxel
        self.confidence = np.zeros((GRID_W, GRID_D, GRID_H), dtype=np.float32)
        # Signal strength map (2D floor projection)
        self.signal_map = np.zeros((GRID_W, GRID_D), dtype=np.float32)
        self.signal_counts = np.zeros((GRID_W, GRID_D), dtype=np.int32)
        # Detected walls (list of line segments)
        self.walls: List[Tuple[np.ndarray, np.ndarray]] = []
        # Last update time
        self.last_wall_update = 0
        
    def world_to_grid(self, x: float, y: float, z: float = 0) -> Tuple[int, int, int]:
        """Convert world coordinates to grid indices."""
        gx = int(np.clip(x / VOXEL_RES, 0, GRID_W - 1))
        gy = int(np.clip(y / VOXEL_RES, 0, GRID_D - 1))
        gz = int(np.clip(z / VOXEL_RES, 0, GRID_H - 1))
        return gx, gy, gz
    
    def grid_to_world(self, gx: int, gy: int, gz: int = 0) -> Tuple[float, float, float]:
        """Convert grid indices to world coordinates (center of voxel)."""
        return (gx + 0.5) * VOXEL_RES, (gy + 0.5) * VOXEL_RES, (gz + 0.5) * VOXEL_RES
    
    def update_from_detection(self, pos: np.ndarray, rssi: int, sensor_pos: np.ndarray):
        """
        Update occupancy grid based on a detection.
        Strong signals = clear path, weak signals = possible obstruction.
        """
        if rssi >= 0 or rssi < -100:
            return
        
        # Normalized signal strength (0 = very weak, 1 = very strong)
        strength = (rssi + 100) / 70.0
        strength = np.clip(strength, 0, 1)
        
        # Update signal map at entity position
        gx, gy, _ = self.world_to_grid(pos[0], pos[1], 0)
        self.signal_map[gx, gy] = (self.signal_map[gx, gy] * self.signal_counts[gx, gy] + strength) / (self.signal_counts[gx, gy] + 1)
        self.signal_counts[gx, gy] += 1
        
        # Ray march from sensor to entity - clear path should be empty
        direction = pos - sensor_pos
        dist = np.linalg.norm(direction)
        if dist < 0.1:
            return
        direction = direction / dist
        
        # Expected RSSI based on distance (free space path loss)
        expected_rssi = -35 - 25 * np.log10(max(dist, 0.1))
        attenuation = expected_rssi - rssi  # positive = more loss than expected
        
        # If significant extra attenuation, mark potential obstacles along path
        steps = int(dist / (VOXEL_RES * 0.5))
        for i in range(steps):
            t = (i + 1) / (steps + 1)
            p = sensor_pos + direction * dist * t
            gx, gy, gz = self.world_to_grid(p[0], p[1], p[2])
            
            if 0 <= gx < GRID_W and 0 <= gy < GRID_D and 0 <= gz < GRID_H:
                if attenuation > 8:  # Significant obstruction
                    # More likely to be obstacle near middle of path
                    obstacle_prob = 0.1 * (1 - abs(t - 0.5) * 2) * min(attenuation / 20, 1)
                    self.occupancy[gx, gy, gz] += obstacle_prob
                else:
                    # Clear path - reduce occupancy probability
                    self.occupancy[gx, gy, gz] *= 0.98
                self.confidence[gx, gy, gz] += 0.1
    
    def detect_walls(self):
        """
        Analyze occupancy grid to detect wall segments.
        Uses edge detection on the 2D floor projection.
        """
        now = time.time()
        if now - self.last_wall_update < 2.0:  # Update every 2 seconds
            return
        self.last_wall_update = now
        
        # Project occupancy to 2D (max along z)
        floor_occ = np.max(self.occupancy, axis=2)
        
        # Threshold to binary
        threshold = np.percentile(floor_occ[floor_occ > 0], 75) if np.any(floor_occ > 0) else 0.5
        binary = (floor_occ > threshold).astype(np.float32)
        
        # Simple edge detection - find transitions
        self.walls = []
        
        # Horizontal edges
        for gy in range(GRID_D - 1):
            in_wall = False
            wall_start = 0
            for gx in range(GRID_W):
                is_edge = binary[gx, gy] != binary[gx, gy + 1]
                if is_edge and not in_wall:
                    in_wall = True
                    wall_start = gx
                elif not is_edge and in_wall:
                    in_wall = False
                    if gx - wall_start >= 2:  # Minimum wall length
                        p1 = np.array(self.grid_to_world(wall_start, gy + 1, 0))
                        p2 = np.array(self.grid_to_world(gx, gy + 1, 0))
                        self.walls.append((p1, p2))
        
        # Vertical edges
        for gx in range(GRID_W - 1):
            in_wall = False
            wall_start = 0
            for gy in range(GRID_D):
                is_edge = binary[gx, gy] != binary[gx + 1, gy]
                if is_edge and not in_wall:
                    in_wall = True
                    wall_start = gy
                elif not is_edge and in_wall:
                    in_wall = False
                    if gy - wall_start >= 2:
                        p1 = np.array(self.grid_to_world(gx + 1, wall_start, 0))
                        p2 = np.array(self.grid_to_world(gx + 1, gy, 0))
                        self.walls.append((p1, p2))
    
    def get_obstacle_voxels(self, threshold: float = 0.3) -> List[Tuple[float, float, float, float]]:
        """Get list of obstacle voxels above threshold: (x, y, z, intensity)."""
        obstacles = []
        mask = (self.occupancy > threshold) & (self.confidence > 0.5)
        indices = np.argwhere(mask)
        for gx, gy, gz in indices:
            x, y, z = self.grid_to_world(gx, gy, gz)
            intensity = min(self.occupancy[gx, gy, gz], 1.0)
            obstacles.append((x, y, z, intensity))
        return obstacles


# ==================== Moving Object Tracker ====================

@dataclass
class TrackedObject:
    """Kalman-filtered tracked object."""
    mac: str
    # State: [x, y, z, vx, vy, vz]
    state: np.ndarray = field(default_factory=lambda: np.zeros(6))
    # Covariance matrix
    P: np.ndarray = field(default_factory=lambda: np.eye(6) * 10)
    # Measurement history
    rssi_primary: int = -100
    rssi_remote: int = -100
    last_seen: float = 0
    last_primary: float = 0
    last_remote: float = 0
    detection_count: int = 0
    # Classification
    is_moving: bool = False
    speed: float = 0
    entity_type: str = "unknown"
    color: Tuple[float, float, float] = (0.5, 0.5, 0.5)
    size: float = 0.25
    # Trail for visualization
    trail: List[Tuple[float, float, float, float]] = field(default_factory=list)
    
    @property
    def x(self): return self.state[0]
    @property
    def y(self): return self.state[1]
    @property
    def z(self): return self.state[2]
    @property
    def vx(self): return self.state[3]
    @property
    def vy(self): return self.state[4]
    @property
    def vz(self): return self.state[5]
    @property
    def position(self): return self.state[:3]
    @property
    def velocity(self): return self.state[3:6]


class ObjectTracker:
    """
    Tracks multiple objects using Kalman filtering for smooth motion estimation.
    """
    
    # Kalman filter parameters
    PROCESS_NOISE = 0.5  # How much we expect velocity to change
    MEASUREMENT_NOISE = 0.8  # How noisy position measurements are
    
    # RSSI to distance conversion
    RSSI_REF = -35
    PATH_LOSS = 2.5
    
    def __init__(self, structure: StructureGrid):
        self.objects: Dict[str, TrackedObject] = {}
        self.structure = structure
        
    def rssi_to_distance(self, rssi: int) -> float:
        """Convert RSSI to estimated distance."""
        if rssi >= 0 or rssi < -100:
            return 10.0
        d = 10 ** ((self.RSSI_REF - rssi) / (10 * self.PATH_LOSS))
        return np.clip(d, 0.1, 15.0)
    
    def triangulate(self, rssi1: int, rssi2: int) -> np.ndarray:
        """Triangulate position from two RSSI readings."""
        d1 = self.rssi_to_distance(rssi1)
        d2 = self.rssi_to_distance(rssi2)
        
        # Vector between sensors
        sensor_vec = REMOTE_POS - PRIMARY_POS
        d_sensors = np.linalg.norm(sensor_vec)
        
        if d_sensors < 0.1:
            return np.array([ROOM_WIDTH/2, ROOM_DEPTH/2, 1.0])
        
        # Trilateration
        a = (d1*d1 - d2*d2 + d_sensors*d_sensors) / (2 * d_sensors)
        h_sq = d1*d1 - a*a
        
        if h_sq < 0:
            # Circles don't intersect - weighted average
            w1, w2 = 1/(d1+0.1), 1/(d2+0.1)
            pos = (PRIMARY_POS * w1 + REMOTE_POS * w2) / (w1 + w2)
        else:
            h = np.sqrt(h_sq)
            unit = sensor_vec / d_sensors
            perp = np.array([-unit[1], unit[0], 0])
            pos = PRIMARY_POS + unit * a + perp * h
        
        # Clamp to room
        pos[0] = np.clip(pos[0], 0.3, ROOM_WIDTH - 0.3)
        pos[1] = np.clip(pos[1], 0.3, ROOM_DEPTH - 0.3)
        
        # Estimate height from average RSSI
        avg_rssi = (rssi1 + rssi2) / 2
        pos[2] = np.clip(0.8 + (avg_rssi + 70) * 0.02, 0.3, 2.2)
        
        return pos
    
    def single_sensor_position(self, rssi: int, sensor_pos: np.ndarray) -> np.ndarray:
        """Estimate position with only one sensor (less accurate)."""
        d = self.rssi_to_distance(rssi)
        # Place at distance from sensor, biased toward room center
        center = np.array([ROOM_WIDTH/2, ROOM_DEPTH/2, 1.0])
        direction = center - sensor_pos
        direction = direction / (np.linalg.norm(direction) + 0.01)
        pos = sensor_pos + direction * min(d, 4.0)
        pos[0] = np.clip(pos[0], 0.3, ROOM_WIDTH - 0.3)
        pos[1] = np.clip(pos[1], 0.3, ROOM_DEPTH - 0.3)
        pos[2] = np.clip(0.8 + (rssi + 70) * 0.02, 0.3, 2.2)
        return pos
    
    def predict(self, obj: TrackedObject, dt: float):
        """Kalman predict step."""
        # State transition matrix
        F = np.eye(6)
        F[0, 3] = dt
        F[1, 4] = dt
        F[2, 5] = dt
        
        # Process noise
        Q = np.eye(6) * self.PROCESS_NOISE * dt
        Q[3:, 3:] *= 2  # More noise in velocity
        
        obj.state = F @ obj.state
        obj.P = F @ obj.P @ F.T + Q
        
        # Clamp position to room bounds
        obj.state[0] = np.clip(obj.state[0], 0.1, ROOM_WIDTH - 0.1)
        obj.state[1] = np.clip(obj.state[1], 0.1, ROOM_DEPTH - 0.1)
        obj.state[2] = np.clip(obj.state[2], 0.1, ROOM_HEIGHT - 0.1)
        
        # Dampen velocity
        obj.state[3:6] *= 0.95
    
    def update(self, obj: TrackedObject, measurement: np.ndarray):
        """Kalman update step with position measurement."""
        H = np.zeros((3, 6))
        H[0, 0] = H[1, 1] = H[2, 2] = 1
        
        R = np.eye(3) * self.MEASUREMENT_NOISE
        
        y = measurement - H @ obj.state  # Innovation
        S = H @ obj.P @ H.T + R
        K = obj.P @ H.T @ np.linalg.inv(S)  # Kalman gain
        
        obj.state = obj.state + K @ y
        obj.P = (np.eye(6) - K @ H) @ obj.P
    
    def process_detection(self, mac: str, rssi: int, is_remote: bool) -> Optional[TrackedObject]:
        """Process a detection and update tracking."""
        now = time.time()
        
        # Skip broadcast/invalid
        if mac in ('00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'):
            return None
        
        # Get or create object
        if mac not in self.objects:
            self.objects[mac] = TrackedObject(mac=mac)
        
        obj = self.objects[mac]
        obj.detection_count += 1
        
        # Time since last update
        dt = now - obj.last_seen if obj.last_seen > 0 else 0.1
        dt = min(dt, 2.0)  # Cap dt for stability
        
        # Predict step
        if obj.last_seen > 0:
            self.predict(obj, dt)
        
        # Update RSSI
        if is_remote:
            obj.rssi_remote = rssi
            obj.last_remote = now
        else:
            obj.rssi_primary = rssi
            obj.last_primary = now
        obj.last_seen = now
        
        # Get position measurement
        have_both = (now - obj.last_primary < 1.0) and (now - obj.last_remote < 1.0)
        
        if have_both:
            measurement = self.triangulate(obj.rssi_primary, obj.rssi_remote)
        else:
            # Single sensor - less accurate
            sensor_pos = REMOTE_POS if is_remote else PRIMARY_POS
            measurement = self.single_sensor_position(rssi, sensor_pos)
        
        # Update step
        self.update(obj, measurement)
        
        # Calculate speed and detect movement
        obj.speed = np.linalg.norm(obj.velocity)
        obj.is_moving = obj.speed > 0.12
        
        # Update structure grid
        sensor_pos = REMOTE_POS if is_remote else PRIMARY_POS
        self.structure.update_from_detection(obj.position, rssi, sensor_pos)
        
        # Classify
        self._classify(obj)
        
        # Update trail
        obj.trail.append((obj.x, obj.y, obj.z, now))
        if len(obj.trail) > 100:
            obj.trail.pop(0)
        
        return obj
    
    def _classify(self, obj: TrackedObject):
        """Classify object based on behavior."""
        signal_strength = (obj.rssi_primary + obj.rssi_remote + 200) / 140
        
        if obj.is_moving and obj.speed > 0.2:
            obj.entity_type = "person"
            obj.color = (1.0, 0.3, 0.3)
            obj.size = 0.4
        elif obj.is_moving:
            obj.entity_type = "moving"
            obj.color = (1.0, 0.7, 0.2)
            obj.size = 0.35
        elif signal_strength > 0.6 and obj.detection_count > 50:
            obj.entity_type = "device"
            obj.color = (0.3, 0.8, 1.0)
            obj.size = 0.25
        elif obj.detection_count > 20:
            obj.entity_type = "stationary"
            obj.color = (0.4, 0.95, 0.5)
            obj.size = 0.2
        else:
            obj.entity_type = "unknown"
            obj.color = (0.6, 0.6, 0.6)
            obj.size = 0.15
    
    def get_active_objects(self, max_age: float = 15.0) -> List[TrackedObject]:
        """Get recently seen objects."""
        now = time.time()
        return [o for o in self.objects.values() if now - o.last_seen < max_age]
    
    def get_moving_objects(self) -> List[TrackedObject]:
        """Get currently moving objects."""
        return [o for o in self.get_active_objects(5.0) if o.is_moving]


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
        self.consecutive_failures = 0
        
    def run(self):
        while self.running:
            try:
                # Fetch status first (small, fast)
                status = self._fetch(f"http://{self.host}:{self.port}/status", timeout=1.5)
                
                if status:
                    # Then fetch scan data (larger, needs more time)
                    scan = self._fetch(f"http://{self.host}:{self.port}/scan", timeout=FETCH_TIMEOUT)
                    remotes = self._fetch(f"http://{self.host}:{self.port}/remotes", timeout=1.5)
                    
                    self.data_received.emit({
                        'status': status,
                        'scan': scan or {'detections': []},
                        'remotes': remotes or {'remotes': []}
                    })
                    self.status_changed.emit(True, f"{self.host}")
                    self.consecutive_failures = 0
                else:
                    self.consecutive_failures += 1
                    self.status_changed.emit(False, f"No response ({self.consecutive_failures})")
                    
            except Exception as e:
                self.consecutive_failures += 1
                self.status_changed.emit(False, str(e)[:30])
            
            # Adaptive polling rate
            delay = 0.1 if self.consecutive_failures == 0 else min(1.0, 0.2 * self.consecutive_failures)
            time.sleep(delay)
    
    def _fetch(self, url: str, timeout: float = 2.0) -> Optional[dict]:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'HydraSense/4.0'})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = response.read()
                return json.loads(data)
        except Exception:
            return None
    
    def stop(self):
        self.running = False


# ==================== OpenGL 3D Renderer ====================

class EnvironmentRenderer(QOpenGLWidget):
    """OpenGL 3D environment renderer with structure and tracking visualization."""
    
    def __init__(self):
        super().__init__()
        
        self.structure = StructureGrid()
        self.tracker = ObjectTracker(self.structure)
        
        # Camera
        self.cam_distance = 14.0
        self.cam_azimuth = 45.0
        self.cam_elevation = 35.0
        self.cam_target = np.array([ROOM_WIDTH/2, ROOM_DEPTH/2, 1.0])
        
        # Animation
        self.anim_time = 0
        self.scan_angle = 0
        
        # Mouse
        self.last_mouse = None
        self.setMouseTracking(True)
        
        # Stats
        self.fps = 0
        self.frame_count = 0
        self.fps_time = time.time()
        
        # Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self._tick)
        self.timer.start(16)
        
    def _tick(self):
        self.anim_time += 0.016
        self.scan_angle = (self.scan_angle + 1.5) % 360
        
        # Update wall detection periodically
        self.structure.detect_walls()
        
        # FPS
        self.frame_count += 1
        now = time.time()
        if now - self.fps_time >= 1.0:
            self.fps = self.frame_count / (now - self.fps_time)
            self.frame_count = 0
            self.fps_time = now
        
        self.update()
    
    def initializeGL(self):
        glClearColor(0.01, 0.02, 0.05, 1.0)
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_BLEND)
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA)
        glEnable(GL_LINE_SMOOTH)
        glEnable(GL_POINT_SMOOTH)
        glHint(GL_LINE_SMOOTH_HINT, GL_NICEST)
        
        glEnable(GL_LIGHTING)
        glEnable(GL_LIGHT0)
        glEnable(GL_LIGHT1)
        glEnable(GL_COLOR_MATERIAL)
        glColorMaterial(GL_FRONT_AND_BACK, GL_AMBIENT_AND_DIFFUSE)
        
        glLightfv(GL_LIGHT0, GL_POSITION, [ROOM_WIDTH/2, ROOM_DEPTH/2, 6.0, 1.0])
        glLightfv(GL_LIGHT0, GL_DIFFUSE, [0.9, 0.9, 1.0, 1.0])
        glLightfv(GL_LIGHT0, GL_AMBIENT, [0.15, 0.15, 0.2, 1.0])
        
        glLightfv(GL_LIGHT1, GL_POSITION, [0, 0, 4.0, 1.0])
        glLightfv(GL_LIGHT1, GL_DIFFUSE, [0.3, 0.5, 0.6, 1.0])
        
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
        cx = self.cam_target[0] + self.cam_distance * math.cos(el) * math.sin(az)
        cy = self.cam_target[1] + self.cam_distance * math.cos(el) * math.cos(az)
        cz = self.cam_target[2] + self.cam_distance * math.sin(el)
        
        gluLookAt(cx, cy, cz, *self.cam_target, 0, 0, 1)
        
        self._render_room()
        self._render_floor_grid()
        self._render_signal_heatmap()
        self._render_structure()
        self._render_detected_walls()
        self._render_sensors()
        self._render_objects()
        self._render_movement_trails()
        
    def _render_room(self):
        """Render room boundaries."""
        glEnable(GL_LIGHTING)
        
        # Floor
        glColor4f(0.03, 0.06, 0.12, 1.0)
        glBegin(GL_QUADS)
        glNormal3f(0, 0, 1)
        glVertex3f(0, 0, 0)
        glVertex3f(ROOM_WIDTH, 0, 0)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, 0)
        glVertex3f(0, ROOM_DEPTH, 0)
        glEnd()
        
        # Walls (transparent)
        glColor4f(0.08, 0.12, 0.2, 0.2)
        for wall in [
            [(0, ROOM_DEPTH, 0), (ROOM_WIDTH, ROOM_DEPTH, 0), (ROOM_WIDTH, ROOM_DEPTH, ROOM_HEIGHT), (0, ROOM_DEPTH, ROOM_HEIGHT)],
            [(0, 0, 0), (0, ROOM_DEPTH, 0), (0, ROOM_DEPTH, ROOM_HEIGHT), (0, 0, ROOM_HEIGHT)],
            [(ROOM_WIDTH, 0, 0), (ROOM_WIDTH, 0, ROOM_HEIGHT), (ROOM_WIDTH, ROOM_DEPTH, ROOM_HEIGHT), (ROOM_WIDTH, ROOM_DEPTH, 0)],
        ]:
            glBegin(GL_QUADS)
            for v in wall:
                glVertex3f(*v)
            glEnd()
        
        # Edges
        glDisable(GL_LIGHTING)
        glLineWidth(1.5)
        glColor4f(0.1, 0.4, 0.7, 0.6)
        glBegin(GL_LINE_LOOP)
        for v in [(0,0,0), (ROOM_WIDTH,0,0), (ROOM_WIDTH,ROOM_DEPTH,0), (0,ROOM_DEPTH,0)]:
            glVertex3f(*v)
        glEnd()
        glBegin(GL_LINES)
        for x, y in [(0,0), (ROOM_WIDTH,0), (ROOM_WIDTH,ROOM_DEPTH), (0,ROOM_DEPTH)]:
            glVertex3f(x, y, 0)
            glVertex3f(x, y, ROOM_HEIGHT)
        glEnd()
        glEnable(GL_LIGHTING)
        
    def _render_floor_grid(self):
        """Render floor grid."""
        glDisable(GL_LIGHTING)
        glLineWidth(1.0)
        glColor4f(0.08, 0.2, 0.35, 0.3)
        glBegin(GL_LINES)
        for i in range(int(ROOM_WIDTH) + 1):
            glVertex3f(i, 0, 0.005)
            glVertex3f(i, ROOM_DEPTH, 0.005)
        for i in range(int(ROOM_DEPTH) + 1):
            glVertex3f(0, i, 0.005)
            glVertex3f(ROOM_WIDTH, i, 0.005)
        glEnd()
        glEnable(GL_LIGHTING)
        
    def _render_signal_heatmap(self):
        """Render signal strength heatmap on floor."""
        glDisable(GL_LIGHTING)
        
        for gx in range(GRID_W):
            for gy in range(GRID_D):
                if self.structure.signal_counts[gx, gy] > 0:
                    strength = self.structure.signal_map[gx, gy]
                    if strength > 0.1:
                        x, y, _ = self.structure.grid_to_world(gx, gy, 0)
                        
                        # Color: blue (weak) -> green -> yellow -> red (strong)
                        if strength < 0.4:
                            r, g, b = 0, strength * 2, 0.5
                        elif strength < 0.7:
                            r, g, b = (strength - 0.4) * 3, 0.8, 0
                        else:
                            r, g, b = 1.0, 1.0 - (strength - 0.7) * 3, 0
                        
                        alpha = 0.15 + strength * 0.2
                        glColor4f(r, g, b, alpha)
                        
                        s = VOXEL_RES * 0.45
                        glBegin(GL_QUADS)
                        glVertex3f(x - s, y - s, 0.01)
                        glVertex3f(x + s, y - s, 0.01)
                        glVertex3f(x + s, y + s, 0.01)
                        glVertex3f(x - s, y + s, 0.01)
                        glEnd()
        
        glEnable(GL_LIGHTING)
        
    def _render_structure(self):
        """Render detected structure (obstacles/walls) as voxels."""
        glEnable(GL_LIGHTING)
        
        obstacles = self.structure.get_obstacle_voxels(threshold=0.4)
        
        for x, y, z, intensity in obstacles:
            glPushMatrix()
            glTranslatef(x, y, z)
            
            # Purple/magenta for obstacles
            glColor4f(0.6 * intensity, 0.2, 0.8 * intensity, 0.4 + intensity * 0.4)
            
            s = VOXEL_RES * 0.4
            glBegin(GL_QUADS)
            # Top
            glNormal3f(0, 0, 1)
            glVertex3f(-s, -s, s); glVertex3f(s, -s, s)
            glVertex3f(s, s, s); glVertex3f(-s, s, s)
            # Front
            glNormal3f(0, -1, 0)
            glVertex3f(-s, -s, -s); glVertex3f(s, -s, -s)
            glVertex3f(s, -s, s); glVertex3f(-s, -s, s)
            # Back
            glNormal3f(0, 1, 0)
            glVertex3f(-s, s, -s); glVertex3f(-s, s, s)
            glVertex3f(s, s, s); glVertex3f(s, s, -s)
            # Left
            glNormal3f(-1, 0, 0)
            glVertex3f(-s, -s, -s); glVertex3f(-s, -s, s)
            glVertex3f(-s, s, s); glVertex3f(-s, s, -s)
            # Right
            glNormal3f(1, 0, 0)
            glVertex3f(s, -s, -s); glVertex3f(s, s, -s)
            glVertex3f(s, s, s); glVertex3f(s, -s, s)
            glEnd()
            
            glPopMatrix()
            
    def _render_detected_walls(self):
        """Render detected wall segments."""
        glDisable(GL_LIGHTING)
        glLineWidth(4.0)
        glColor4f(0.9, 0.4, 0.1, 0.8)
        
        for p1, p2 in self.structure.walls:
            glBegin(GL_LINES)
            glVertex3f(p1[0], p1[1], 0.05)
            glVertex3f(p2[0], p2[1], 0.05)
            # Vertical extent
            glVertex3f(p1[0], p1[1], 0.05)
            glVertex3f(p1[0], p1[1], ROOM_HEIGHT * 0.8)
            glVertex3f(p2[0], p2[1], 0.05)
            glVertex3f(p2[0], p2[1], ROOM_HEIGHT * 0.8)
            glEnd()
            
            # Wall plane (semi-transparent)
            glColor4f(0.9, 0.5, 0.2, 0.15)
            glBegin(GL_QUADS)
            glVertex3f(p1[0], p1[1], 0)
            glVertex3f(p2[0], p2[1], 0)
            glVertex3f(p2[0], p2[1], ROOM_HEIGHT * 0.8)
            glVertex3f(p1[0], p1[1], ROOM_HEIGHT * 0.8)
            glEnd()
            glColor4f(0.9, 0.4, 0.1, 0.8)
        
        glEnable(GL_LIGHTING)
        
    def _render_sensors(self):
        """Render sensor nodes."""
        sensors = [(PRIMARY_POS, (0, 1, 0.5), "P"), (REMOTE_POS, (0, 0.7, 1), "R")]
        
        for pos, color, _ in sensors:
            glEnable(GL_LIGHTING)
            glColor4f(*color, 1.0)
            
            glPushMatrix()
            glTranslatef(*pos)
            q = gluNewQuadric()
            gluCylinder(q, 0.15, 0.1, 0.25, 16, 4)
            glTranslatef(0, 0, 0.25)
            gluSphere(q, 0.12, 16, 16)
            gluDeleteQuadric(q)
            glPopMatrix()
            
            # Scan beam
            glDisable(GL_LIGHTING)
            angle = math.radians(self.scan_angle + (180 if color[1] < 0.9 else 0))
            glColor4f(*color, 0.2)
            glBegin(GL_TRIANGLES)
            glVertex3f(*pos)
            for da in [-0.15, 0.15]:
                a = angle + da
                glVertex3f(pos[0] + math.cos(a) * 4, pos[1] + math.sin(a) * 4, pos[2])
            glEnd()
            
            # Pulse rings
            for i in range(3):
                phase = (self.anim_time * 1.5 + i * 0.7) % 3
                radius = 0.3 + phase * 0.8
                alpha = max(0, 0.4 - phase * 0.13)
                glColor4f(*color, alpha)
                glLineWidth(1.5)
                glBegin(GL_LINE_LOOP)
                for a in range(32):
                    ang = a * math.pi * 2 / 32
                    glVertex3f(pos[0] + math.cos(ang) * radius,
                              pos[1] + math.sin(ang) * radius, pos[2])
                glEnd()
                
            glEnable(GL_LIGHTING)
            
    def _render_objects(self):
        """Render tracked objects."""
        now = time.time()
        
        for obj in self.tracker.get_active_objects(12.0):
            age = now - obj.last_seen
            alpha = max(0.3, 1.0 - age / 12)
            
            x, y, z = obj.x, obj.y, obj.z
            r, g, b = obj.color
            
            # Ground shadow
            glDisable(GL_LIGHTING)
            glColor4f(0, 0, 0, 0.25 * alpha)
            glBegin(GL_POLYGON)
            for i in range(16):
                a = i * math.pi * 2 / 16
                glVertex3f(x + math.cos(a) * obj.size * 0.8,
                          y + math.sin(a) * obj.size * 0.8, 0.005)
            glEnd()
            
            # Vertical line to floor
            glColor4f(r, g, b, alpha * 0.3)
            glLineWidth(1.0)
            glBegin(GL_LINES)
            glVertex3f(x, y, 0.01)
            glVertex3f(x, y, z)
            glEnd()
            glEnable(GL_LIGHTING)
            
            # Body
            glPushMatrix()
            glTranslatef(x, y, z)
            glColor4f(r, g, b, alpha)
            
            q = gluNewQuadric()
            if obj.entity_type == "person":
                # Humanoid
                glPushMatrix()
                glScalef(1, 1, 1.3)
                gluSphere(q, obj.size * 0.45, 16, 16)
                glPopMatrix()
                glTranslatef(0, 0, obj.size * 0.8)
                gluSphere(q, obj.size * 0.2, 12, 12)
            elif obj.entity_type in ("device", "stationary"):
                # Cube
                s = obj.size * 0.35
                glBegin(GL_QUADS)
                for nz in [-1, 1]:
                    glNormal3f(0, 0, nz)
                    zz = s * nz
                    glVertex3f(-s, -s, zz); glVertex3f(s, -s, zz)
                    glVertex3f(s, s, zz); glVertex3f(-s, s, zz)
                glEnd()
            else:
                # Sphere
                gluSphere(q, obj.size * 0.35, 12, 12)
            gluDeleteQuadric(q)
            
            glPopMatrix()
            
            # Velocity arrow for moving objects
            if obj.is_moving and obj.speed > 0.1:
                glDisable(GL_LIGHTING)
                glColor4f(1, 0.4, 0.4, alpha * 0.9)
                glLineWidth(3.0)
                vel_dir = obj.velocity / (obj.speed + 0.01)
                glBegin(GL_LINES)
                glVertex3f(x, y, z)
                glVertex3f(x + vel_dir[0] * 0.8, y + vel_dir[1] * 0.8, z)
                glEnd()
                glEnable(GL_LIGHTING)
                
            # Signal strength bar
            self._draw_signal_bar(x, y, z + obj.size + 0.35, 
                                  (obj.rssi_primary + obj.rssi_remote + 200) / 140, alpha)
    
    def _render_movement_trails(self):
        """Render movement trails for tracked objects."""
        glDisable(GL_LIGHTING)
        now = time.time()
        
        for obj in self.tracker.get_active_objects():
            if len(obj.trail) < 3:
                continue
            
            r, g, b = obj.color
            glLineWidth(2.0)
            glBegin(GL_LINE_STRIP)
            for i, (tx, ty, tz, tt) in enumerate(obj.trail):
                age = now - tt
                alpha = max(0, 0.5 * (1 - age / 8) * (i / len(obj.trail)))
                glColor4f(r, g, b, alpha)
                glVertex3f(tx, ty, 0.02)
            glEnd()
        
        glEnable(GL_LIGHTING)
        
    def _draw_signal_bar(self, x: float, y: float, z: float, strength: float, alpha: float):
        """Draw floating signal strength bar."""
        glDisable(GL_LIGHTING)
        strength = np.clip(strength, 0, 1)
        
        w, h = 0.35, 0.06
        glPushMatrix()
        glTranslatef(x - w/2, y, z)
        
        # Background
        glColor4f(0.15, 0.15, 0.15, alpha * 0.5)
        glBegin(GL_QUADS)
        glVertex3f(0, 0, 0); glVertex3f(w, 0, 0)
        glVertex3f(w, 0, h); glVertex3f(0, 0, h)
        glEnd()
        
        # Fill
        if strength > 0.6:
            glColor4f(0.2, 1.0, 0.4, alpha * 0.85)
        elif strength > 0.35:
            glColor4f(1.0, 0.85, 0.2, alpha * 0.85)
        else:
            glColor4f(1.0, 0.3, 0.3, alpha * 0.85)
        glBegin(GL_QUADS)
        glVertex3f(0, 0, 0); glVertex3f(w * strength, 0, 0)
        glVertex3f(w * strength, 0, h); glVertex3f(0, 0, h)
        glEnd()
        
        glPopMatrix()
        glEnable(GL_LIGHTING)
        
    def process_data(self, data: dict):
        """Process incoming ESP32 data."""
        scan = data.get('scan', {})
        
        for det in scan.get('detections', []):
            mac = det.get('mac', '')
            if not mac or mac == '00:00:00:00:00:00':
                continue
            
            rssi = det.get('rssi', -100)
            source = det.get('source', 'local')
            is_remote = source == 'remote'
            
            self.tracker.process_detection(mac, rssi, is_remote)
    
    # Mouse handlers
    def mousePressEvent(self, e):
        self.last_mouse = e.pos()
        
    def mouseMoveEvent(self, e):
        if self.last_mouse and e.buttons() & Qt.MouseButton.LeftButton:
            dx = e.pos().x() - self.last_mouse.x()
            dy = e.pos().y() - self.last_mouse.y()
            self.cam_azimuth = (self.cam_azimuth + dx * 0.4) % 360
            self.cam_elevation = np.clip(self.cam_elevation + dy * 0.25, 5, 85)
            self.last_mouse = e.pos()
            
    def mouseReleaseEvent(self, e):
        self.last_mouse = None
        
    def wheelEvent(self, e):
        d = e.angleDelta().y() / 120
        self.cam_distance = np.clip(self.cam_distance - d * 0.8, 4, 30)


# ==================== Main Window ====================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛰️ HydraSense Environment Scanner")
        self.setMinimumSize(1280, 800)
        self.resize(1600, 1000)
        
        self.setStyleSheet("""
            QMainWindow { background: #020408; }
            QStatusBar { background: #0a1220; color: #9ec5ff; border-top: 1px solid #1a3050;
                         font-family: 'Consolas', monospace; font-size: 12px; padding: 3px; }
            QLabel { color: #d0e5ff; }
            QDockWidget { color: #9ec5ff; font-weight: bold; }
            QDockWidget::title { background: #0a1525; padding: 6px; }
        """)
        
        # OpenGL format
        fmt = QSurfaceFormat()
        fmt.setSamples(8)
        fmt.setDepthBufferSize(24)
        QSurfaceFormat.setDefaultFormat(fmt)
        
        # Renderer
        self.renderer = EnvironmentRenderer()
        self.setCentralWidget(self.renderer)
        
        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        
        self.lbl_conn = QLabel("⏳ Connecting...")
        self.lbl_pps = QLabel("📡 -- pps")
        self.lbl_objects = QLabel("👥 0 tracked")
        self.lbl_moving = QLabel("🏃 0 moving")
        self.lbl_structure = QLabel("🧱 0 obstacles")
        self.lbl_remote = QLabel("🔗 Remote: --")
        self.lbl_fps = QLabel("🎮 -- FPS")
        
        for w in [self.lbl_conn, self.lbl_pps, self.lbl_objects, 
                  self.lbl_moving, self.lbl_structure, self.lbl_remote, self.lbl_fps]:
            self.status.addWidget(w)
            self.status.addWidget(QLabel(" │ "))
        self.status.addPermanentWidget(QLabel("🖱️ Drag=rotate  Scroll=zoom"))
        
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
        self.lbl_fps.setText(f"🎮 {self.renderer.fps:.0f} FPS")
        
        objects = self.renderer.tracker.get_active_objects()
        moving = [o for o in objects if o.is_moving]
        obstacles = self.renderer.structure.get_obstacle_voxels()
        walls = len(self.renderer.structure.walls)
        
        self.lbl_objects.setText(f"👥 {len(objects)} tracked")
        self.lbl_moving.setText(f"🏃 {len(moving)} moving")
        self.lbl_structure.setText(f"🧱 {len(obstacles)} voxels, {walls} walls")
        
    def _on_data(self, data: dict):
        self.renderer.process_data(data)
        
        status = data.get('status', {})
        remotes = data.get('remotes', {})
        
        self.lbl_pps.setText(f"📡 {status.get('pps', 0)} pps")
        
        remote_list = remotes.get('remotes', [])
        if remote_list:
            r = remote_list[0]
            self.lbl_remote.setText(f"🔗 {r.get('node_id', 'N/A')} ({r.get('rssi', 0)}dBm)")
            self.lbl_remote.setStyleSheet("color: #00ff88;")
        else:
            self.lbl_remote.setText("🔗 Remote: offline")
            self.lbl_remote.setStyleSheet("color: #ff6b6b;")
            
    def _on_status(self, connected: bool, info: str):
        if connected:
            self.lbl_conn.setText(f"🟢 {info}")
            self.lbl_conn.setStyleSheet("color: #00ff88;")
        else:
            self.lbl_conn.setText(f"🔴 {info}")
            self.lbl_conn.setStyleSheet("color: #ff6b6b;")
            
    def closeEvent(self, e):
        self.fetcher.stop()
        self.fetcher.wait()
        super().closeEvent(e)


# ==================== Entry Point ====================

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
