#!/usr/bin/env python3
"""
HYDRA TOMOGRAPHIC SCANNER - Advanced WiFi Environment Reconstruction
=====================================================================
High-fidelity 3D environment reconstruction using multi-sensor
WiFi signal analysis with:

- Tomographic reconstruction from signal attenuation
- Ray-tracing based wall detection  
- Fresnel zone analysis for obstacle mapping
- Temporal signal variance for movement detection
- Bayesian occupancy grid with confidence accumulation
- Multi-path reflection detection for surface mapping
- Object vs wall classification

Creates a persistent, accurate 3D model of the environment.
"""

import sys
import os
import json
import math
import time
import sqlite3
import threading
import urllib.request
import urllib.error
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set
import numpy as np

try:
    from scipy import ndimage  # type: ignore
except Exception:  # pragma: no cover
    ndimage = None

from PyQt6.QtWidgets import QApplication, QMainWindow, QStatusBar, QLabel, QWidget, QVBoxLayout
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QSurfaceFormat, QPainter, QColor, QFont, QPen
from PyQt6.QtOpenGLWidgets import QOpenGLWidget

from OpenGL.GL import *
from OpenGL.GLU import *
from OpenGL.GLUT import *

# Initialize GLUT for text rendering
try:
    glutInit()
except Exception:
    pass  # GLUT may not be available


# ==================== Persistence ====================

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DATA_DIR, "hydra_scanner.db")


# ==================== Configuration ====================

ESP32_HOSTS = [
    "192.168.0.139",  # primary on home WiFi
    "192.168.4.1",    # primary AP mode
    "hydrasense.local",
]
ESP32_PORT = 80

# Room dimensions (meters) - adjust to your actual room
ROOM_WIDTH = 8.0   # X axis
ROOM_DEPTH = 6.0   # Y axis  
ROOM_HEIGHT = 2.8  # Z axis

# Sensor positions (meters) - ~15 feet (4.5m) apart
PRIMARY_POS = np.array([0.5, 0.5, 0.4])
REMOTE_POS = np.array([5.0, 0.5, 0.4])

# Reconstruction grid
VOXEL_SIZE = 0.15  # 15cm resolution for fine detail
GRID_X = int(ROOM_WIDTH / VOXEL_SIZE)
GRID_Y = int(ROOM_DEPTH / VOXEL_SIZE)
GRID_Z = int(ROOM_HEIGHT / VOXEL_SIZE)

# Wall detection floor grid (2D overhead view)
FLOOR_RES = 0.1  # 10cm for floor plan
FLOOR_X = int(ROOM_WIDTH / FLOOR_RES)
FLOOR_Y = int(ROOM_DEPTH / FLOOR_RES)

# Shadow detection zones
SHADOW_THRESHOLD = 0.4  # Threshold for shadow zone detection


# ==================== Signal Processing ====================

class SignalProcessor:
    """Advanced signal processing for environment reconstruction."""
    
    # Calibration constants - tune these for your environment
    RSSI_REF_1M = -35      # RSSI at 1 meter (calibrate for your devices)
    PATH_LOSS_FREE = 2.0   # Free space path loss exponent
    PATH_LOSS_INDOOR = 3.0 # Indoor path loss with moderate obstructions
    PATH_LOSS_WALL = 3.8   # Path loss through walls
    WALL_ATTENUATION = 4   # dB loss per wall
    
    @staticmethod
    def rssi_to_distance(rssi: int, path_loss: float = 2.8) -> float:
        """Convert RSSI to distance estimate."""
        if rssi >= 0 or rssi < -100:
            return 10.0
        d = 10 ** ((SignalProcessor.RSSI_REF_1M - rssi) / (10 * path_loss))
        return max(0.1, min(15.0, d))
    
    @staticmethod
    def expected_rssi(distance: float, path_loss: float = 2.8) -> float:
        """Calculate expected RSSI at distance."""
        if distance < 0.1:
            distance = 0.1
        return SignalProcessor.RSSI_REF_1M - 10 * path_loss * math.log10(distance)
    
    @staticmethod
    def fresnel_radius(distance: float, freq_ghz: float = 2.4) -> float:
        """Calculate first Fresnel zone radius."""
        wavelength = 0.3 / freq_ghz  # meters
        return math.sqrt(wavelength * distance / 4)


def _box_blur_2d(arr: np.ndarray) -> np.ndarray:
    """Small, fast blur fallback when SciPy isn't available."""
    k = np.array([1, 2, 3, 2, 1], dtype=np.float32)
    k = k / float(k.sum())

    # Convolve in X then Y (separable)
    tmp = np.zeros_like(arr, dtype=np.float32)
    out = np.zeros_like(arr, dtype=np.float32)

    pad = len(k) // 2
    padded = np.pad(arr.astype(np.float32), ((pad, pad), (0, 0)), mode="edge")
    for i in range(arr.shape[0]):
        tmp[i, :] = (padded[i : i + len(k), :] * k[:, None]).sum(axis=0)

    padded2 = np.pad(tmp, ((0, 0), (pad, pad)), mode="edge")
    for j in range(arr.shape[1]):
        out[:, j] = (padded2[:, j : j + len(k)] * k[None, :]).sum(axis=1)

    return out


def _smooth_2d(arr: np.ndarray, sigma: float = 0.8) -> np.ndarray:
    if ndimage is not None:
        return ndimage.gaussian_filter(arr, sigma=sigma)
    # sigma isn't used in the fallback; keep signature consistent
    return _box_blur_2d(arr)


# ==================== Wall Line Extraction ====================

class WallLineExtractor:
    """
    Extract wall line segments from probability grid using
    a simplified Hough-like accumulator approach.
    """
    
    def __init__(self, grid_x: int, grid_y: int, res: float):
        self.grid_x = grid_x
        self.grid_y = grid_y
        self.res = res
        self.detected_lines: List[Tuple[np.ndarray, np.ndarray, float]] = []  # (start, end, confidence)
        
    def extract_lines(self, prob_grid: np.ndarray, threshold: float = 0.35) -> List[Tuple[np.ndarray, np.ndarray, float]]:
        """Extract wall line segments from probability grid."""
        lines = []
        
        # Find high-probability cells
        wall_mask = prob_grid > threshold
        
        # Get wall cell coordinates
        wall_coords = np.argwhere(wall_mask)
        if len(wall_coords) < 3:
            return lines
        
        # Group into connected components (simple 4-connected)
        visited = set()
        components = []
        
        for coord in wall_coords:
            coord_tuple = (coord[0], coord[1])
            if coord_tuple in visited:
                continue
            
            # BFS to find connected component
            component = []
            queue = [coord_tuple]
            while queue:
                curr = queue.pop(0)
                if curr in visited:
                    continue
                visited.add(curr)
                
                # Check if this cell is a wall
                if 0 <= curr[0] < self.grid_x and 0 <= curr[1] < self.grid_y:
                    if prob_grid[curr[0], curr[1]] > threshold:
                        component.append(curr)
                        # Add neighbors
                        for dx, dy in [(-1,0), (1,0), (0,-1), (0,1), (-1,-1), (1,1), (-1,1), (1,-1)]:
                            nx, ny = curr[0]+dx, curr[1]+dy
                            if (nx, ny) not in visited:
                                queue.append((nx, ny))
            
            if len(component) >= 3:
                components.append(component)
        
        # Fit lines to each component using PCA
        for component in components:
            if len(component) < 4:
                continue
            
            pts = np.array(component, dtype=np.float32)
            
            # PCA to find principal axis
            centroid = pts.mean(axis=0)
            centered = pts - centroid
            cov = np.cov(centered.T)
            
            if cov.shape == (2, 2):
                eigvals, eigvecs = np.linalg.eigh(cov)
                # Principal direction
                principal = eigvecs[:, np.argmax(eigvals)]
                
                # Project points onto principal axis
                projections = centered @ principal
                min_proj, max_proj = projections.min(), projections.max()
                
                # Line endpoints in grid coords
                start_grid = centroid + min_proj * principal
                end_grid = centroid + max_proj * principal
                
                # Convert to world coords
                start_world = np.array([start_grid[0] * self.res, start_grid[1] * self.res, 0])
                end_world = np.array([end_grid[0] * self.res, end_grid[1] * self.res, ROOM_HEIGHT])
                
                # Confidence from avg probability
                avg_prob = np.mean([prob_grid[c[0], c[1]] for c in component])
                
                # Only keep lines that are long enough
                length = np.linalg.norm(end_grid - start_grid) * self.res
                if length > 0.4:  # Min 40cm wall segment
                    lines.append((start_world, end_world, float(avg_prob)))
        
        self.detected_lines = lines
        return lines


# ==================== Kalman Tracker ====================

class KalmanTracker3D:
    """3D Kalman filter for smooth entity tracking."""
    
    def __init__(self, x: float, y: float, z: float):
        # State: [x, y, z, vx, vy, vz]
        self.state = np.array([x, y, z, 0.0, 0.0, 0.0], dtype=np.float64)
        self.P = np.eye(6) * 2.0  # Initial covariance
        self.Q = np.diag([0.05, 0.05, 0.02, 0.1, 0.1, 0.05])  # Process noise
        self.R = np.diag([0.3, 0.3, 0.2])  # Measurement noise
        self.last_update = time.time()
        
    def predict(self, dt: float = None):
        if dt is None:
            dt = time.time() - self.last_update
        dt = max(0.01, min(dt, 1.0))
        
        F = np.eye(6)
        F[0, 3] = dt
        F[1, 4] = dt
        F[2, 5] = dt
        
        self.state = F @ self.state
        self.P = F @ self.P @ F.T + self.Q * dt
        
    def update(self, x: float, y: float, z: float):
        self.predict()
        
        H = np.zeros((3, 6))
        H[0, 0] = H[1, 1] = H[2, 2] = 1
        
        z_meas = np.array([x, y, z])
        y_innov = z_meas - H @ self.state
        S = H @ self.P @ H.T + self.R
        K = self.P @ H.T @ np.linalg.inv(S)
        
        self.state = self.state + K @ y_innov
        self.P = (np.eye(6) - K @ H) @ self.P
        self.last_update = time.time()
        
    @property
    def position(self) -> np.ndarray:
        return self.state[:3]
    
    @property
    def velocity(self) -> np.ndarray:
        return self.state[3:6]
    
    @property
    def speed(self) -> float:
        return np.linalg.norm(self.state[3:6])


# ==================== Entity Tracking ====================

@dataclass
class TrackedEntity:
    mac: str
    tracker: KalmanTracker3D = None
    rssi_history: Dict[str, List[Tuple[int, float]]] = field(default_factory=lambda: {'primary': [], 'remote': []})
    last_seen: float = 0
    detection_count: int = 0
    trail: List[Tuple[float, float, float, float]] = field(default_factory=list)
    entity_type: str = "unknown"
    color: Tuple[float, float, float] = (0.5, 0.5, 0.5)
    is_infrastructure: bool = False
    variance_primary: float = 0
    variance_remote: float = 0
    paired_rssi: List[Tuple[int, int, float]] = field(default_factory=list)  # (p, r, t)
    
    # Enhanced tracking fields
    rssi_velocity: float = 0.0  # Rate of RSSI change (dB/s) - indicates movement
    approach_direction: str = "unknown"  # toward_primary, toward_remote, lateral
    confidence_score: float = 0.0  # Overall tracking confidence
    last_zone: int = 0  # Last known zone ID
    dwell_time: float = 0.0  # Time spent in current zone
    
    # Device classification from firmware
    device_type: int = 0  # 0=unknown, 1=smartphone, 2=laptop, 3=iot, 4=infra, 5=wearable
    device_type_name: str = "unknown"
    signal_quality: float = 0.0  # 0-1 consistency score
    presence_confidence: float = 0.0  # 0-1 presence likelihood
    micro_variance: float = 0.0  # Tiny RSSI fluctuations (breathing detection)
    rssi_gradient: int = 0  # Short-term RSSI slope
    
    # Breathing/vital detection
    breathing_detected: bool = False
    breathing_pattern: List[float] = field(default_factory=list)  # Micro-variance history
    
    # Environment context
    channel_diversity: int = 1
    peak_rssi: int = -100
    min_rssi: int = -100
    
    @property
    def rssi_primary(self) -> int:
        if not self.rssi_history['primary']:
            return -100
        recent = [r for r, t in self.rssi_history['primary'] if time.time() - t < 3]
        return int(np.median(recent)) if recent else -100
    
    @property
    def rssi_remote(self) -> int:
        if not self.rssi_history['remote']:
            return -100
        recent = [r for r, t in self.rssi_history['remote'] if time.time() - t < 3]
        return int(np.median(recent)) if recent else -100
    
    @property
    def position(self) -> np.ndarray:
        return self.tracker.position if self.tracker else np.array([0, 0, 1])
    
    @property
    def velocity(self) -> np.ndarray:
        return self.tracker.velocity if self.tracker else np.zeros(3)
    
    @property
    def speed(self) -> float:
        return self.tracker.speed if self.tracker else 0
    
    @property
    def is_moving(self) -> bool:
        return self.speed > 0.12 or abs(self.rssi_velocity) > 2.0
    
    @property
    def signal_strength(self) -> float:
        avg = max(self.rssi_primary, self.rssi_remote)
        return max(0, min(1, (avg + 100) / 60))


# ==================== Tomographic Reconstruction Engine ====================

class TomographicEngine:
    """
    Advanced environment reconstruction using WiFi tomography.
    
    Techniques:
    1. Signal attenuation tomography - walls absorb signal
    2. Fresnel zone analysis - obstacles in signal path
    3. Temporal variance mapping - static vs dynamic areas
    4. Bayesian occupancy accumulation - confidence over time
    5. Motion prediction with trajectory estimation
    6. Occupancy history heatmap
    7. Signal fingerprint database for location matching
    """
    
    def __init__(self):
        # Entity tracking
        self.entities: Dict[str, TrackedEntity] = {}
        
        # 2D occupancy grid (wall probability from top-down)
        self.wall_probability = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        self.wall_confidence = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        self.signal_strength_map = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)

        # Persistent wall evidence (log-odds)
        self.wall_log_odds = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        
        # Signal path attenuation map (accumulates evidence of obstacles)
        self.attenuation_map = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        self.path_count = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        
        # Free space map (areas confirmed to be empty)
        self.free_space = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        
        # Wall line extractor
        self.line_extractor = WallLineExtractor(FLOOR_X, FLOOR_Y, FLOOR_RES)
        self.wall_lines: List[Tuple[np.ndarray, np.ndarray, float]] = []
        
        # Occupancy history heatmap (where people have been)
        self.occupancy_history = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        self.motion_vectors = np.zeros((FLOOR_X, FLOOR_Y, 2), dtype=np.float32)  # Average motion direction
        
        # Signal fingerprint database {(gx, gy): {mac: avg_rssi}}
        self.fingerprint_db: Dict[Tuple[int, int], Dict[str, float]] = {}
        
        # Statistics
        self.total_detections = 0
        self.reconstruction_cycles = 0
        self.dual_sensor_count = 0
        self.persons_detected = 0
        self.max_simultaneous = 0

        # Adaptive path-loss (self-calibrates from static devices)
        self.path_loss_est = 2.8
        self._last_calibration = 0.0
        
        # Infrastructure MACs
        self.infrastructure_macs: Set[str] = set()
        
        # Known reference points (router positions for calibration)
        self.reference_points: Dict[str, np.ndarray] = {}
        
        # Shadow zones (areas blocked from both sensors)
        self.shadow_zones = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        
        # Coverage quality map
        self.coverage_quality = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        self._init_coverage_map()
        
        # Temporal signal anomaly detection
        self.prev_signal_map = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        self.signal_change_map = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        self.anomaly_events: List[Tuple[float, float, float, float]] = []  # (x, y, z, intensity)
        
        # Room segmentation / zone detection
        self.zone_map = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.int32)  # Zone IDs
        self.zone_labels: Dict[int, str] = {0: "Unknown"}  # Zone ID -> name
        self.zone_activity: Dict[int, float] = {}  # Zone ID -> activity level
        
        # Multi-person tracking
        self.person_tracks: Dict[str, List[Tuple[float, float, float, float]]] = {}  # MAC -> [(x,y,z,t), ...]
        self.max_track_length = 500  # Keep last 500 positions per person
        
        # Advanced signal propagation model
        self.ray_trace_cache: Dict[Tuple[int, int, int, int], float] = {}  # Cache ray traces
        self.fresnel_zones = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)  # Fresnel zone impacts
        self.multipath_signature = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)  # Multipath indicators
        self.propagation_model = "log_distance"  # "log_distance", "ray_trace", "hybrid"
        
        # Material inference
        self.material_map = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.int32)  # 0=unknown, 1=drywall, 2=concrete, 3=glass, 4=metal
        self.material_confidence = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        
        # Reflection point tracking
        self.reflection_points: List[Tuple[float, float, float, float]] = []  # (x, y, intensity, time)
        self.max_reflections = 200
        
        # Memory bounds for collections
        self.max_fingerprints = 10000
        self.max_entities = 100
        
        # Environmental baseline
        self.baseline_rssi_map = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.float32)
        self.baseline_samples = np.zeros((FLOOR_X, FLOOR_Y), dtype=np.int32)
        self.has_baseline = False
        
        # CSI processing state
        self.csi_movement_indicator = 0.0
        self._csi_history = []
        
        # Persistence
        self._db_lock = threading.Lock()
        self._init_database()
        self._load_persistent_data()
    
    def _init_database(self):
        """Initialize SQLite database for persistent storage."""
        os.makedirs(DATA_DIR, exist_ok=True)
        with self._db_lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS wall_data (
                id INTEGER PRIMARY KEY,
                wall_probability BLOB,
                wall_confidence BLOB,
                wall_log_odds BLOB,
                attenuation_map BLOB,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS fingerprints (
                id INTEGER PRIMARY KEY,
                gx INTEGER, gy INTEGER,
                mac TEXT,
                avg_rssi REAL,
                UNIQUE(gx, gy, mac)
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS wall_lines (
                id INTEGER PRIMARY KEY,
                start_x REAL, start_y REAL,
                end_x REAL, end_y REAL,
                confidence REAL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_fingerprints_grid ON fingerprints(gx, gy)''')
            conn.commit()
            conn.close()
            
    def _load_persistent_data(self):
        """Load wall maps and fingerprints from database."""
        with self._db_lock:
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                
                # Load wall data
                c.execute('SELECT wall_probability, wall_confidence, wall_log_odds, attenuation_map FROM wall_data ORDER BY updated_at DESC LIMIT 1')
                row = c.fetchone()
                if row:
                    self.wall_probability = np.frombuffer(row[0], dtype=np.float32).reshape((FLOOR_X, FLOOR_Y))
                    self.wall_confidence = np.frombuffer(row[1], dtype=np.float32).reshape((FLOOR_X, FLOOR_Y))
                    self.wall_log_odds = np.frombuffer(row[2], dtype=np.float32).reshape((FLOOR_X, FLOOR_Y))
                    self.attenuation_map = np.frombuffer(row[3], dtype=np.float32).reshape((FLOOR_X, FLOOR_Y))
                    print(f"[DB] Loaded wall map from database")
                
                # Load fingerprints
                c.execute('SELECT gx, gy, mac, avg_rssi FROM fingerprints')
                count = 0
                for gx, gy, mac, avg_rssi in c.fetchall():
                    key = (gx, gy)
                    if key not in self.fingerprint_db:
                        self.fingerprint_db[key] = {}
                    self.fingerprint_db[key][mac] = avg_rssi
                    count += 1
                if count > 0:
                    print(f"[DB] Loaded {count} fingerprints from database")
                
                # Load wall lines
                c.execute('SELECT start_x, start_y, end_x, end_y, confidence FROM wall_lines')
                for start_x, start_y, end_x, end_y, conf in c.fetchall():
                    self.wall_lines.append((np.array([start_x, start_y]), np.array([end_x, end_y]), conf))
                if self.wall_lines:
                    print(f"[DB] Loaded {len(self.wall_lines)} wall lines from database")
                
                conn.close()
            except Exception as e:
                print(f"[DB] Error loading persistent data: {e}")
    
    def save_persistent_data(self):
        """Save wall maps and fingerprints to database."""
        with self._db_lock:
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                
                # Save wall data (upsert)
                c.execute('DELETE FROM wall_data')
                c.execute('INSERT INTO wall_data (wall_probability, wall_confidence, wall_log_odds, attenuation_map) VALUES (?, ?, ?, ?)',
                    (self.wall_probability.tobytes(), self.wall_confidence.tobytes(), 
                     self.wall_log_odds.tobytes(), self.attenuation_map.tobytes()))
                
                # Save fingerprints (upsert with REPLACE)
                for (gx, gy), macs in list(self.fingerprint_db.items())[:self.max_fingerprints]:
                    for mac, avg_rssi in macs.items():
                        c.execute('INSERT OR REPLACE INTO fingerprints (gx, gy, mac, avg_rssi) VALUES (?, ?, ?, ?)',
                            (gx, gy, mac, avg_rssi))
                
                # Save wall lines
                c.execute('DELETE FROM wall_lines')
                for start, end, conf in self.wall_lines:
                    c.execute('INSERT INTO wall_lines (start_x, start_y, end_x, end_y, confidence) VALUES (?, ?, ?, ?, ?)',
                        (float(start[0]), float(start[1]), float(end[0]), float(end[1]), float(conf)))
                
                conn.commit()
                conn.close()
                print(f"[DB] Saved wall map and {len(self.fingerprint_db)} fingerprint locations")
            except Exception as e:
                print(f"[DB] Error saving persistent data: {e}")
    
    def enforce_memory_limits(self):
        """Enforce memory limits on collections to prevent unbounded growth."""
        # Limit fingerprint database
        if len(self.fingerprint_db) > self.max_fingerprints:
            # Keep only the most populated cells
            sorted_keys = sorted(self.fingerprint_db.keys(), 
                                key=lambda k: len(self.fingerprint_db[k]), reverse=True)
            new_db = {k: self.fingerprint_db[k] for k in sorted_keys[:self.max_fingerprints]}
            self.fingerprint_db = new_db
            
        # Limit entities
        if len(self.entities) > self.max_entities:
            # Remove oldest entities
            sorted_entities = sorted(self.entities.items(), 
                                    key=lambda x: x[1].last_seen, reverse=True)
            self.entities = dict(sorted_entities[:self.max_entities])
    
    def process_csi_data(self, csi_data: dict):
        """Process CSI data for enhanced movement detection.
        
        CSI (Channel State Information) contains amplitude and phase information
        for each WiFi subcarrier, enabling sub-meter movement detection.
        """
        if not csi_data or not csi_data.get('csi_enabled'):
            return
        
        raw_csi = csi_data.get('data', [])
        if not raw_csi or len(raw_csi) < 10:
            return
        
        # Convert CSI data to numpy array
        csi_array = np.array(raw_csi, dtype=np.float32)
        
        # Calculate amplitude (CSI is typically interleaved I/Q samples)
        if len(csi_array) >= 2:
            # Assuming I/Q interleaved format
            i_samples = csi_array[0::2]
            q_samples = csi_array[1::2]
            amplitudes = np.sqrt(i_samples**2 + q_samples**2)
            
            # Store CSI state for temporal analysis
            if not hasattr(self, '_csi_history'):
                self._csi_history = []
            
            self._csi_history.append({
                'amplitudes': amplitudes,
                'timestamp': csi_data.get('timestamp', time.time()),
                'mac': csi_data.get('mac', '')
            })
            
            # Keep only recent CSI samples
            self._csi_history = self._csi_history[-50:]
            
            # Analyze CSI variance for movement detection
            if len(self._csi_history) >= 5:
                recent_amps = [h['amplitudes'] for h in self._csi_history[-5:]]
                # Pad or truncate to same length
                min_len = min(len(a) for a in recent_amps)
                recent_amps = [a[:min_len] for a in recent_amps]
                amp_array = np.array(recent_amps)
                
                # Per-subcarrier variance
                subcarrier_variance = np.var(amp_array, axis=0)
                avg_variance = np.mean(subcarrier_variance)
                
                # High variance indicates movement
                self.csi_movement_indicator = min(1.0, avg_variance / 100.0)
                
                # Update global motion estimate
                if avg_variance > 50:
                    # Significant CSI change - likely human movement
                    for entity in self.entities.values():
                        if time.time() - entity.last_seen < 2:
                            entity.is_moving = True
    
    def _init_coverage_map(self):
        """Initialize theoretical coverage map based on sensor positions."""
        for gx in range(FLOOR_X):
            for gy in range(FLOOR_Y):
                x = (gx + 0.5) * FLOOR_RES
                y = (gy + 0.5) * FLOOR_RES
                
                # Distance to each sensor
                d1 = math.sqrt((x - PRIMARY_POS[0])**2 + (y - PRIMARY_POS[1])**2)
                d2 = math.sqrt((x - REMOTE_POS[0])**2 + (y - REMOTE_POS[1])**2)
                
                # Coverage quality (better when closer to sensors and in crossfire)
                q1 = math.exp(-d1 * 0.15)
                q2 = math.exp(-d2 * 0.15)
                
                # Bonus for dual-sensor coverage (crossfire zone)
                crossfire_bonus = min(q1, q2) * 0.5
                
                self.coverage_quality[gx, gy] = (q1 + q2) / 2 + crossfire_bonus
        
        # Normalize
        max_q = self.coverage_quality.max()
        if max_q > 0:
            self.coverage_quality /= max_q
        
    def triangulate(self, rssi_p: int, rssi_r: int) -> np.ndarray:
        """Triangulate position from dual RSSI using weighted trilateration."""
        d1 = SignalProcessor.rssi_to_distance(rssi_p, self.path_loss_est)
        d2 = SignalProcessor.rssi_to_distance(rssi_r, self.path_loss_est)
        
        sensor_vec = REMOTE_POS - PRIMARY_POS
        d_sensors = np.linalg.norm(sensor_vec[:2])
        
        if d_sensors < 0.1:
            return np.array([ROOM_WIDTH/2, ROOM_DEPTH/2, 1.0])
        
        # Trilateration using circles
        a = (d1*d1 - d2*d2 + d_sensors*d_sensors) / (2 * d_sensors)
        h_sq = d1*d1 - a*a
        
        unit_vec = sensor_vec[:2] / d_sensors
        
        if h_sq < 0:
            # No intersection - use weighted position
            w1, w2 = 1/(d1+0.1), 1/(d2+0.1)
            x = (PRIMARY_POS[0]*w1 + REMOTE_POS[0]*w2) / (w1+w2)
            y = (PRIMARY_POS[1]*w1 + REMOTE_POS[1]*w2) / (w1+w2)
        else:
            h = math.sqrt(h_sq)
            px = PRIMARY_POS[0] + a * unit_vec[0]
            py = PRIMARY_POS[1] + a * unit_vec[1]
            perp = np.array([-unit_vec[1], unit_vec[0]])
            
            # Pick intersection inside room (usually positive Y)
            x1, y1 = px + h * perp[0], py + h * perp[1]
            x2, y2 = px - h * perp[0], py - h * perp[1]
            
            # Choose based on room bounds
            if 0 < y1 < ROOM_DEPTH:
                x, y = x1, y1
            else:
                x, y = x2, y2
        
        # Clamp to room
        x = max(0.3, min(ROOM_WIDTH - 0.3, x))
        y = max(0.3, min(ROOM_DEPTH - 0.3, y))
        
        # Z from signal strength
        avg_rssi = (rssi_p + rssi_r) / 2
        z = 1.0 + (avg_rssi + 60) * 0.02
        z = max(0.3, min(2.0, z))
        
        return np.array([x, y, z])
    
    def process_detection(self, mac: str, rssi: int, source: str, motion_hint: int = None):
        """Process a detection and update reconstruction.
        
        Args:
            mac: Device MAC address
            rssi: Signal strength
            source: 'local' or 'remote'
            motion_hint: Optional motion hint from firmware (1=moving, 0=static)
        """
        now = time.time()
        self.total_detections += 1
        
        is_remote = source == "remote"
        
        # Get or create entity
        if mac not in self.entities:
            self.entities[mac] = TrackedEntity(mac=mac)
        
        entity = self.entities[mac]
        entity.last_seen = now
        entity.detection_count += 1
        
        # Use firmware motion hint if provided
        if motion_hint is not None:
            entity.is_moving = (motion_hint == 1)
        
        # Store RSSI history
        key = 'remote' if is_remote else 'primary'
        entity.rssi_history[key].append((rssi, now))
        
        # Keep only recent history
        for k in ['primary', 'remote']:
            entity.rssi_history[k] = [(r, t) for r, t in entity.rssi_history[k] if now - t < 4]
        
        # Calculate variance
        if len(entity.rssi_history[key]) >= 3:
            readings = [r for r, t in entity.rssi_history[key][-10:]]
            if key == 'primary':
                entity.variance_primary = np.var(readings)
            else:
                entity.variance_remote = np.var(readings)
        
        # Calculate RSSI velocity (rate of change) for Doppler-like motion detection
        self._update_rssi_velocity(entity, key, rssi, now)
        
        # Determine approach direction based on differential RSSI changes
        self._update_approach_direction(entity)
        
        # Build paired RSSI samples (time-aligned)
        other_key = 'primary' if is_remote else 'remote'
        other_hist = entity.rssi_history[other_key]
        if other_hist:
            # Find nearest-in-time sample in the other sensor
            t0 = now
            best_rssi, best_dt = None, None
            for r2, t2 in other_hist[-12:]:
                dt = abs(t2 - t0)
                if best_dt is None or dt < best_dt:
                    best_dt = dt
                    best_rssi = r2

            # Pair window: allow some latency between nodes
            if best_dt is not None and best_dt <= 1.6:
                if is_remote:
                    rp, rr = best_rssi, rssi
                else:
                    rp, rr = rssi, best_rssi
                entity.paired_rssi.append((int(rp), int(rr), now))

        # Keep only recent paired samples
        entity.paired_rssi = [(rp, rr, t) for (rp, rr, t) in entity.paired_rssi if now - t < 8]

        # Triangulate using paired samples when possible
        pairs = [(rp, rr) for (rp, rr, t) in entity.paired_rssi if now - t < 4]
        if len(pairs) >= 1:
            rssi_p = int(np.median([p[0] for p in pairs]))
            rssi_r = int(np.median([p[1] for p in pairs]))

            # Basic sanity gate
            if rssi_p > -90 and rssi_r > -90:
                self.dual_sensor_count += 1
                pos = self.triangulate(rssi_p, rssi_r)

                # Initialize or update tracker
                if entity.tracker is None:
                    entity.tracker = KalmanTracker3D(*pos)
                else:
                    entity.tracker.update(*pos)

                # Trail
                entity.trail.append((*entity.position, now))
                if len(entity.trail) > 150:
                    entity.trail.pop(0)

                # Classify
                self._classify_entity(entity)

                # Update reconstruction
                self._update_signal_map(entity)
                self._update_tomography(entity, rssi_p, rssi_r)
                
                # Advanced propagation analysis
                self._update_fresnel_zones(entity)
                self._build_baseline(entity)
                self._detect_occlusion(entity)
                
                # Update occupancy history for moving entities
                if entity.entity_type == "person" and entity.is_moving:
                    self._update_occupancy_history(entity)
                    self._update_motion_vectors(entity)
                    self._update_person_track(mac, entity)
                
                # Build signal fingerprint
                self._update_fingerprint(entity, rssi_p, rssi_r)

        # Periodic self-calibration of path-loss using stable (infrastructure) nodes
        if now - self._last_calibration > 6.0:
            self._maybe_calibrate_path_loss(now)
            
        return entity
    
    def _update_rssi_velocity(self, entity: TrackedEntity, key: str, rssi: int, now: float):
        """Calculate rate of RSSI change (pseudo-Doppler) for motion detection."""
        hist = entity.rssi_history[key]
        if len(hist) < 3:
            return
        
        # Get samples from last 2 seconds
        recent = [(r, t) for r, t in hist if now - t < 2.0]
        if len(recent) < 3:
            return
        
        # Linear regression to find slope (dB/s)
        times = np.array([t - recent[0][1] for r, t in recent])
        rssis = np.array([r for r, t in recent])
        
        if times[-1] - times[0] < 0.3:  # Need at least 300ms span
            return
        
        # Simple linear fit
        n = len(times)
        sum_t = np.sum(times)
        sum_r = np.sum(rssis)
        sum_tr = np.sum(times * rssis)
        sum_t2 = np.sum(times * times)
        
        denom = n * sum_t2 - sum_t * sum_t
        if abs(denom) > 0.001:
            slope = (n * sum_tr - sum_t * sum_r) / denom
            # Smooth with exponential moving average
            entity.rssi_velocity = entity.rssi_velocity * 0.7 + slope * 0.3
    
    def _update_approach_direction(self, entity: TrackedEntity):
        """Determine movement direction based on differential RSSI changes."""
        p_hist = entity.rssi_history['primary']
        r_hist = entity.rssi_history['remote']
        
        if len(p_hist) < 4 or len(r_hist) < 4:
            entity.approach_direction = "unknown"
            return
        
        # Get recent RSSI values
        now = time.time()
        p_recent = [r for r, t in p_hist if now - t < 2.0]
        r_recent = [r for r, t in r_hist if now - t < 2.0]
        
        if len(p_recent) < 2 or len(r_recent) < 2:
            return
        
        # Calculate trends
        p_trend = p_recent[-1] - p_recent[0]  # Primary RSSI change
        r_trend = r_recent[-1] - r_recent[0]  # Remote RSSI change
        
        # Determine direction
        threshold = 2.0  # dB change threshold
        
        if p_trend > threshold and r_trend < -threshold:
            entity.approach_direction = "toward_primary"
        elif p_trend < -threshold and r_trend > threshold:
            entity.approach_direction = "toward_remote"
        elif p_trend > threshold and r_trend > threshold:
            entity.approach_direction = "approaching_center"
        elif p_trend < -threshold and r_trend < -threshold:
            entity.approach_direction = "leaving_center"
        elif abs(p_trend) < threshold and abs(r_trend) < threshold:
            entity.approach_direction = "stationary"
        else:
            entity.approach_direction = "lateral"
        
        # Update confidence based on signal quality
        entity.confidence_score = min(1.0, entity.detection_count / 50.0) * \
                                  (1.0 - min(1.0, (entity.variance_primary + entity.variance_remote) / 50.0))
    
    def _classify_entity(self, entity: TrackedEntity):
        """Classify entity based on signal behavior."""
        total_variance = entity.variance_primary + entity.variance_remote
        
        # Infrastructure: stable, high detection count
        if entity.detection_count > 300 and total_variance < 4 and not entity.is_moving:
            entity.is_infrastructure = True
            entity.entity_type = "infrastructure"
            entity.color = (0.3, 0.3, 0.5)
            self.infrastructure_macs.add(entity.mac)
            return
        
        if entity.mac in self.infrastructure_macs:
            entity.is_infrastructure = True
            entity.entity_type = "infrastructure"
            entity.color = (0.3, 0.3, 0.5)
            return
        
        # Moving = person (use RSSI velocity as additional indicator)
        if entity.is_moving or total_variance > 10 or abs(entity.rssi_velocity) > 3.0:
            entity.entity_type = "person"
            entity.color = (1.0, 0.3, 0.3)
            self.persons_detected += 1
        elif entity.signal_strength > 0.5:
            entity.entity_type = "device"
            entity.color = (0.3, 0.7, 1.0)
        else:
            entity.entity_type = "object"
            entity.color = (0.4, 0.9, 0.5)
    
    def _update_occupancy_history(self, entity: TrackedEntity):
        """Update occupancy heatmap with person locations."""
        pos = entity.position
        gx = int(pos[0] / FLOOR_RES)
        gy = int(pos[1] / FLOOR_RES)
        
        # Gaussian splat for smooth heatmap
        for dx in range(-3, 4):
            for dy in range(-3, 4):
                nx, ny = gx + dx, gy + dy
                if 0 <= nx < FLOOR_X and 0 <= ny < FLOOR_Y:
                    dist = math.sqrt(dx*dx + dy*dy)
                    weight = math.exp(-dist * 0.5) * 0.15
                    self.occupancy_history[nx, ny] += weight
        
        # Clamp and slow decay
        self.occupancy_history = np.clip(self.occupancy_history, 0, 5.0)
    
    def _update_motion_vectors(self, entity: TrackedEntity):
        """Update average motion direction at each location."""
        if not entity.is_moving or entity.speed < 0.1:
            return
        
        pos = entity.position
        vel = entity.velocity
        gx = int(pos[0] / FLOOR_RES)
        gy = int(pos[1] / FLOOR_RES)
        
        if 0 <= gx < FLOOR_X and 0 <= gy < FLOOR_Y:
            # Exponential moving average of motion direction
            alpha = 0.2
            self.motion_vectors[gx, gy, 0] = (1 - alpha) * self.motion_vectors[gx, gy, 0] + alpha * vel[0]
            self.motion_vectors[gx, gy, 1] = (1 - alpha) * self.motion_vectors[gx, gy, 1] + alpha * vel[1]
    
    def _update_fingerprint(self, entity: TrackedEntity, rssi_p: int, rssi_r: int):
        """Build signal fingerprint database for location matching."""
        pos = entity.position
        gx = int(pos[0] / FLOOR_RES)
        gy = int(pos[1] / FLOOR_RES)
        
        key = (gx, gy)
        if key not in self.fingerprint_db:
            self.fingerprint_db[key] = {}
        
        # Store combined RSSI signature
        mac = entity.mac
        if mac not in self.fingerprint_db[key]:
            self.fingerprint_db[key][mac] = (rssi_p + rssi_r) / 2
        else:
            # Moving average
            self.fingerprint_db[key][mac] = 0.9 * self.fingerprint_db[key][mac] + 0.1 * ((rssi_p + rssi_r) / 2)
    
    def predict_position(self, mac: str, rssi_p: int, rssi_r: int) -> Optional[np.ndarray]:
        """Predict position using signal fingerprint matching."""
        if not self.fingerprint_db:
            return None
        
        target_rssi = (rssi_p + rssi_r) / 2
        best_match = None
        best_score = float('inf')
        
        for (gx, gy), fingerprints in self.fingerprint_db.items():
            if mac in fingerprints:
                diff = abs(fingerprints[mac] - target_rssi)
                if diff < best_score:
                    best_score = diff
                    best_match = (gx, gy)
        
        if best_match and best_score < 10:  # Within 10 dB
            return np.array([best_match[0] * FLOOR_RES, best_match[1] * FLOOR_RES, 1.0])
        return None
    
    def _detect_signal_anomalies(self):
        """Detect temporal signal anomalies indicating movement."""
        # Calculate change from previous frame
        change = np.abs(self.signal_strength_map - self.prev_signal_map)
        
        # Update change map with temporal smoothing
        self.signal_change_map = self.signal_change_map * 0.7 + change * 0.3
        
        # Find anomaly hotspots (areas with sudden signal changes)
        threshold = 0.15  # 15% signal change is significant
        anomaly_mask = self.signal_change_map > threshold
        
        # Extract anomaly locations
        self.anomaly_events = []
        indices = np.argwhere(anomaly_mask)
        
        # Cluster and select strongest anomalies
        if len(indices) > 0:
            # Sort by intensity
            intensities = [(gx, gy, self.signal_change_map[gx, gy]) 
                          for gx, gy in indices]
            intensities.sort(key=lambda x: x[2], reverse=True)
            
            # Take top anomalies, avoiding duplicates
            used_cells = set()
            for gx, gy, intensity in intensities[:20]:
                # Check if too close to existing anomaly
                too_close = False
                for ux, uy in used_cells:
                    if abs(gx - ux) + abs(gy - uy) < 4:
                        too_close = True
                        break
                
                if not too_close:
                    x = gx * FLOOR_RES
                    y = gy * FLOOR_RES
                    z = 1.0  # Assume person height
                    self.anomaly_events.append((x, y, z, intensity))
                    used_cells.add((gx, gy))
        
        # Store current map for next comparison
        self.prev_signal_map = self.signal_strength_map.copy()
    
    def _update_person_track(self, mac: str, entity: TrackedEntity):
        """Update position track for a person."""
        now = time.time()
        pos = entity.position
        
        if mac not in self.person_tracks:
            self.person_tracks[mac] = []
        
        self.person_tracks[mac].append((pos[0], pos[1], pos[2], now))
        
        # Limit track length
        if len(self.person_tracks[mac]) > self.max_track_length:
            self.person_tracks[mac] = self.person_tracks[mac][-self.max_track_length:]
        
        # Update zone activity
        gx, gy = int(pos[0] / FLOOR_RES), int(pos[1] / FLOOR_RES)
        if 0 <= gx < FLOOR_X and 0 <= gy < FLOOR_Y:
            zone_id = self.zone_map[gx, gy]
            if zone_id not in self.zone_activity:
                self.zone_activity[zone_id] = 0
            self.zone_activity[zone_id] += 0.1
    
    def segment_zones_from_walls(self):
        """Segment room into zones based on detected walls."""
        # Create binary wall mask
        wall_mask = self.wall_probability > 0.4
        
        # Use flood fill to find connected regions
        visited = np.zeros_like(wall_mask, dtype=bool)
        zone_id = 1
        
        for start_x in range(FLOOR_X):
            for start_y in range(FLOOR_Y):
                if not visited[start_x, start_y] and not wall_mask[start_x, start_y]:
                    # Flood fill from this point
                    self._flood_fill_zone(start_x, start_y, zone_id, wall_mask, visited)
                    
                    # Auto-label zone based on position
                    cx, cy = start_x * FLOOR_RES, start_y * FLOOR_RES
                    if cx < ROOM_WIDTH / 3:
                        if cy < ROOM_DEPTH / 2:
                            self.zone_labels[zone_id] = f"Zone-{zone_id}-Left-Front"
                        else:
                            self.zone_labels[zone_id] = f"Zone-{zone_id}-Left-Back"
                    elif cx > ROOM_WIDTH * 2/3:
                        if cy < ROOM_DEPTH / 2:
                            self.zone_labels[zone_id] = f"Zone-{zone_id}-Right-Front"
                        else:
                            self.zone_labels[zone_id] = f"Zone-{zone_id}-Right-Back"
                    else:
                        self.zone_labels[zone_id] = f"Zone-{zone_id}-Center"
                    
                    zone_id += 1
    
    def _flood_fill_zone(self, start_x: int, start_y: int, zone_id: int, 
                         wall_mask: np.ndarray, visited: np.ndarray):
        """Flood fill to mark connected zone."""
        stack = [(start_x, start_y)]
        
        while stack:
            x, y = stack.pop()
            
            if x < 0 or x >= FLOOR_X or y < 0 or y >= FLOOR_Y:
                continue
            if visited[x, y] or wall_mask[x, y]:
                continue
            
            visited[x, y] = True
            self.zone_map[x, y] = zone_id
            
            # Add neighbors
            stack.extend([(x+1, y), (x-1, y), (x, y+1), (x, y-1)])
    
    def _update_signal_map(self, entity: TrackedEntity):
        """Update 2D signal strength map."""
        pos = entity.position
        gx = int(pos[0] / FLOOR_RES)
        gy = int(pos[1] / FLOOR_RES)
        
        if 0 <= gx < FLOOR_X and 0 <= gy < FLOOR_Y:
            strength = entity.signal_strength
            
            # Gaussian splat
            for dx in range(-4, 5):
                for dy in range(-4, 5):
                    nx, ny = gx + dx, gy + dy
                    if 0 <= nx < FLOOR_X and 0 <= ny < FLOOR_Y:
                        dist = math.sqrt(dx*dx + dy*dy)
                        weight = math.exp(-dist * 0.4) * strength
                        self.signal_strength_map[nx, ny] = max(
                            self.signal_strength_map[nx, ny] * 0.97,
                            weight
                        )
    
    def _update_tomography(self, entity: TrackedEntity, rssi_p: int, rssi_r: int):
        """
        Tomographic reconstruction: analyze signal paths for obstacles.
        
        If actual RSSI << expected RSSI, there's an obstacle in the path.
        """
        pos = entity.position
        
        # Analyze path from primary sensor
        d_primary = np.linalg.norm(pos - PRIMARY_POS)
        expected_p = SignalProcessor.expected_rssi(d_primary, self.path_loss_est)
        atten_p = expected_p - rssi_p
        
        # Analyze path from remote sensor
        d_remote = np.linalg.norm(pos - REMOTE_POS)
        expected_r = SignalProcessor.expected_rssi(d_remote, self.path_loss_est)
        atten_r = expected_r - rssi_r
        
        # Strong attenuation suggests wall in path
        if atten_p > 4.5:
            self._trace_attenuation_path(PRIMARY_POS, pos, atten_p)
        else:
            # Low attenuation = clear path
            self._mark_free_path(PRIMARY_POS, pos)
            
        if atten_r > 4.5:
            self._trace_attenuation_path(REMOTE_POS, pos, atten_r)
        else:
            self._mark_free_path(REMOTE_POS, pos)
        
        # Check for multipath (signal stronger than expected)
        if atten_p < -3 or atten_r < -3:
            # Signal stronger than free-space - likely multipath reflection
            # This indicates reflective surface nearby
            self._mark_reflection_point(pos, entity)
    
    def _trace_attenuation_path(self, start: np.ndarray, end: np.ndarray, attenuation: float):
        """
        Mark potential wall locations along an attenuated path.
        Walls are more likely in the middle of the path.
        """
        direction = end[:2] - start[:2]
        length = np.linalg.norm(direction)
        if length < 0.3:
            return
        
        direction = direction / length
        steps = int(length / (FLOOR_RES * 0.4))
        
        # Evidence weight based on attenuation
        base_prob = min(0.12, max(0.0, (attenuation - 3.5) / 55.0))
        
        for i in range(steps):
            t = i / max(steps, 1)
            
            # Gaussian: walls most likely in middle
            position_weight = math.exp(-((t - 0.5) ** 2) * 10)
            
            point = start[:2] + direction * length * t
            gx = int(point[0] / FLOOR_RES)
            gy = int(point[1] / FLOOR_RES)
            
            if 0 <= gx < FLOOR_X and 0 <= gy < FLOOR_Y:
                prob_inc = base_prob * position_weight

                # Persistent log-odds update
                self.wall_log_odds[gx, gy] += prob_inc * 0.65
                self.wall_confidence[gx, gy] += prob_inc * 0.25

                # Keep legacy maps for debugging/visualization
                self.attenuation_map[gx, gy] += prob_inc * attenuation
                self.path_count[gx, gy] += 1
    
    def _mark_free_path(self, start: np.ndarray, end: np.ndarray):
        """Mark path as free space (no obstacles)."""
        direction = end[:2] - start[:2]
        length = np.linalg.norm(direction)
        if length < 0.2:
            return
        
        direction = direction / length
        steps = int(length / (FLOOR_RES * 0.5))
        
        for i in range(steps):
            t = i / max(steps, 1)
            point = start[:2] + direction * length * t
            gx = int(point[0] / FLOOR_RES)
            gy = int(point[1] / FLOOR_RES)
            
            if 0 <= gx < FLOOR_X and 0 <= gy < FLOOR_Y:
                # Increase free space confidence
                self.free_space[gx, gy] += 0.02
                # Negative evidence for walls
                self.wall_log_odds[gx, gy] -= 0.035
    
    def _mark_reflection_point(self, pos: np.ndarray, entity: TrackedEntity):
        """Mark potential reflection surface near entity."""
        gx = int(pos[0] / FLOOR_RES)
        gy = int(pos[1] / FLOOR_RES)
        
        # Multipath suggests reflective surfaces nearby
        # Mark surrounding area as potential wall
        for dx in range(-2, 3):
            for dy in range(-2, 3):
                nx, ny = gx + dx, gy + dy
                if 0 <= nx < FLOOR_X and 0 <= ny < FLOOR_Y:
                    dist = math.sqrt(dx*dx + dy*dy)
                    if dist > 1:  # Ring around entity
                        self.attenuation_map[nx, ny] += 0.3
                        self.path_count[nx, ny] += 0.1
                        self.wall_log_odds[nx, ny] += 0.03
        
        # Track reflection point for visualization
        now = time.time()
        self.reflection_points.append((pos[0], pos[1], 1.0, now))
        if len(self.reflection_points) > self.max_reflections:
            self.reflection_points.pop(0)
    
    def _ray_trace_attenuation(self, start: np.ndarray, end: np.ndarray) -> float:
        """Trace ray from start to end and calculate expected attenuation through walls."""
        # Bresenham-style line through grid
        sx, sy = int(start[0] / FLOOR_RES), int(start[1] / FLOOR_RES)
        ex, ey = int(end[0] / FLOOR_RES), int(end[1] / FLOOR_RES)
        
        cache_key = (sx, sy, ex, ey)
        if cache_key in self.ray_trace_cache:
            return self.ray_trace_cache[cache_key]
        
        total_atten = 0.0
        
        dx = abs(ex - sx)
        dy = abs(ey - sy)
        x, y = sx, sy
        step_x = 1 if sx < ex else -1
        step_y = 1 if sy < ey else -1
        
        if dx > dy:
            err = dx / 2
            while x != ex:
                if 0 <= x < FLOOR_X and 0 <= y < FLOOR_Y:
                    # Attenuation based on wall probability and inferred material
                    wp = self.wall_probability[x, y]
                    mat = self.material_map[x, y]
                    
                    # Material-dependent attenuation (dB per cell)
                    mat_atten = {0: 2.0, 1: 3.5, 2: 12.0, 3: 6.0, 4: 15.0}.get(mat, 2.0)
                    total_atten += wp * mat_atten * FLOOR_RES
                
                err -= dy
                if err < 0:
                    y += step_y
                    err += dx
                x += step_x
        else:
            err = dy / 2
            while y != ey:
                if 0 <= x < FLOOR_X and 0 <= y < FLOOR_Y:
                    wp = self.wall_probability[x, y]
                    mat = self.material_map[x, y]
                    mat_atten = {0: 2.0, 1: 3.5, 2: 12.0, 3: 6.0, 4: 15.0}.get(mat, 2.0)
                    total_atten += wp * mat_atten * FLOOR_RES
                
                err -= dx
                if err < 0:
                    x += step_x
                    err += dy
                y += step_y
        
        # Cache result (with size limit)
        if len(self.ray_trace_cache) < 10000:
            self.ray_trace_cache[cache_key] = total_atten
        
        return total_atten
    
    def _infer_material(self, gx: int, gy: int, rssi_actual: int, rssi_expected: int):
        """Infer wall material from signal attenuation pattern."""
        if not (0 <= gx < FLOOR_X and 0 <= gy < FLOOR_Y):
            return
        
        atten = rssi_expected - rssi_actual  # Positive = more attenuation than expected
        
        if self.wall_probability[gx, gy] < 0.3:
            return  # Only infer material for probable walls
        
        # Material inference based on attenuation
        if atten > 15:
            inferred_mat = 4  # Metal (very high attenuation)
            conf = 0.4
        elif atten > 10:
            inferred_mat = 2  # Concrete
            conf = 0.35
        elif atten > 5:
            inferred_mat = 3  # Glass
            conf = 0.3
        elif atten > 2:
            inferred_mat = 1  # Drywall
            conf = 0.25
        else:
            return  # Too little attenuation
        
        # Update material map with confidence weighting
        old_mat = self.material_map[gx, gy]
        old_conf = self.material_confidence[gx, gy]
        
        if conf > old_conf or old_mat == 0:
            self.material_map[gx, gy] = inferred_mat
            self.material_confidence[gx, gy] = min(1.0, old_conf + conf * 0.1)
    
    def _calculate_fresnel_zone(self, pos: np.ndarray, sensor_pos: np.ndarray, freq_mhz: float = 2437) -> float:
        """Calculate first Fresnel zone radius at midpoint."""
        # Fresnel zone radius: sqrt(wavelength * d1 * d2 / (d1 + d2))
        wavelength = 299.792458 / freq_mhz  # meters
        d = np.linalg.norm(pos[:2] - sensor_pos[:2])
        
        if d < 0.1:
            return 0.0
        
        # First Fresnel zone at midpoint
        d1 = d / 2
        d2 = d / 2
        radius = math.sqrt(wavelength * d1 * d2 / (d1 + d2))
        return radius
    
    def _update_fresnel_zones(self, entity: TrackedEntity):
        """Mark Fresnel zone obstruction areas."""
        if entity.position is None:
            return
            
        pos = entity.position
        
        # Calculate Fresnel zones for paths to both sensors
        for sensor_pos in [PRIMARY_POS, REMOTE_POS]:
            r = self._calculate_fresnel_zone(pos, sensor_pos)
            if r < 0.1:
                continue
            
            # Mark cells in the Fresnel zone ellipse
            mid_x = (pos[0] + sensor_pos[0]) / 2
            mid_y = (pos[1] + sensor_pos[1]) / 2
            
            # Direction vector
            dx = sensor_pos[0] - pos[0]
            dy = sensor_pos[1] - pos[1]
            d = math.sqrt(dx*dx + dy*dy)
            if d < 0.1:
                continue
            dx, dy = dx/d, dy/d
            
            # Mark zone
            gx, gy = int(mid_x / FLOOR_RES), int(mid_y / FLOOR_RES)
            r_cells = int(r / FLOOR_RES) + 1
            
            for ox in range(-r_cells, r_cells+1):
                for oy in range(-r_cells, r_cells+1):
                    nx, ny = gx + ox, gy + oy
                    if 0 <= nx < FLOOR_X and 0 <= ny < FLOOR_Y:
                        # Check if in Fresnel zone
                        cell_dist = math.sqrt(ox*ox + oy*oy) * FLOOR_RES
                        if cell_dist < r:
                            self.fresnel_zones[nx, ny] += 0.1 * (1 - cell_dist/r)
    
    def _build_baseline(self, entity: TrackedEntity):
        """Build baseline RSSI map from static infrastructure."""
        if not entity.is_infrastructure:
            return
        
        gx = int(entity.position[0] / FLOOR_RES)
        gy = int(entity.position[1] / FLOOR_RES)
        
        if not (0 <= gx < FLOOR_X and 0 <= gy < FLOOR_Y):
            return
        
        avg_rssi = (entity.rssi_primary + entity.rssi_remote) / 2
        
        # Running average
        old_count = self.baseline_samples[gx, gy]
        old_rssi = self.baseline_rssi_map[gx, gy]
        
        self.baseline_samples[gx, gy] = old_count + 1
        self.baseline_rssi_map[gx, gy] = (old_rssi * old_count + avg_rssi) / (old_count + 1)
        
        if np.sum(self.baseline_samples > 5) > 20:
            self.has_baseline = True
    
    def _detect_occlusion(self, entity: TrackedEntity):
        """Detect if entity is occluded (behind wall) based on expected vs actual RSSI."""
        if entity.position is None:
            return
        
        # Calculate expected RSSI based on distance only
        pos = entity.position
        d_primary = np.linalg.norm(pos[:2] - PRIMARY_POS[:2])
        d_remote = np.linalg.norm(pos[:2] - REMOTE_POS[:2])
        
        # Expected RSSI from free-space path loss
        expected_primary = -40 - 10 * self.path_loss_est * math.log10(max(0.1, d_primary))
        expected_remote = -40 - 10 * self.path_loss_est * math.log10(max(0.1, d_remote))
        
        # Ray trace to get wall attenuation
        atten_primary = self._ray_trace_attenuation(pos, PRIMARY_POS)
        atten_remote = self._ray_trace_attenuation(pos, REMOTE_POS)
        
        # Actual vs expected with wall attenuation
        actual_vs_expected_p = entity.rssi_primary - (expected_primary - atten_primary)
        actual_vs_expected_r = entity.rssi_remote - (expected_remote - atten_remote)
        
        # If actual is much lower than expected, there's additional obstruction
        if actual_vs_expected_p < -10:
            # Mark potential obstruction between entity and primary
            self._mark_path_obstruction(pos, PRIMARY_POS, abs(actual_vs_expected_p))
        
        if actual_vs_expected_r < -10:
            self._mark_path_obstruction(pos, REMOTE_POS, abs(actual_vs_expected_r))
        
        # Update material inference along path
        self._infer_material_along_path(pos, PRIMARY_POS, entity.rssi_primary, expected_primary)
    
    def _mark_path_obstruction(self, start: np.ndarray, end: np.ndarray, intensity: float):
        """Mark probable obstruction along signal path."""
        # Find midpoint (most likely obstruction location)
        mid_x = (start[0] + end[0]) / 2
        mid_y = (start[1] + end[1]) / 2
        
        gx, gy = int(mid_x / FLOOR_RES), int(mid_y / FLOOR_RES)
        
        # Spread around midpoint
        spread = min(5, int(intensity / 5))
        for dx in range(-spread, spread+1):
            for dy in range(-spread, spread+1):
                nx, ny = gx + dx, gy + dy
                if 0 <= nx < FLOOR_X and 0 <= ny < FLOOR_Y:
                    dist = math.sqrt(dx*dx + dy*dy) + 0.1
                    self.wall_log_odds[nx, ny] += (intensity * 0.02) / dist
    
    def _infer_material_along_path(self, entity_pos: np.ndarray, sensor_pos: np.ndarray, 
                                    actual_rssi: int, expected_rssi: float):
        """Infer materials along the signal path."""
        # Walk along path and check where walls are
        sx, sy = int(entity_pos[0] / FLOOR_RES), int(entity_pos[1] / FLOOR_RES)
        ex, ey = int(sensor_pos[0] / FLOOR_RES), int(sensor_pos[1] / FLOOR_RES)
        
        dx = abs(ex - sx)
        dy = abs(ey - sy)
        
        steps = max(dx, dy)
        if steps == 0:
            return
        
        step_x = (ex - sx) / steps
        step_y = (ey - sy) / steps
        
        x, y = float(sx), float(sy)
        
        for _ in range(int(steps)):
            gx, gy = int(x), int(y)
            if 0 <= gx < FLOOR_X and 0 <= gy < FLOOR_Y:
                if self.wall_probability[gx, gy] > 0.4:
                    self._infer_material(gx, gy, actual_rssi, int(expected_rssi))
            x += step_x
            y += step_y
    
    def run_reconstruction_cycle(self):
        """Process accumulated data to detect walls."""
        self.reconstruction_cycles += 1

        # Gentle decay: walls persist, but noise fades
        self.wall_log_odds *= 0.9995
        self.wall_log_odds = np.clip(self.wall_log_odds, -6.0, 6.0)

        # Convert to probability
        self.wall_probability = 1.0 / (1.0 + np.exp(-self.wall_log_odds))

        # Free space strongly reduces wall probability where repeatedly confirmed
        free_mask = self.free_space > 1.2
        self.wall_probability[free_mask] *= 0.55

        # Smooth periodically + de-speckle
        if self.reconstruction_cycles % 12 == 0:
            sm = _smooth_2d(self.wall_probability, sigma=0.8)
            sm = np.clip(sm, 0.0, 1.0)

            # Remove isolated speckles (cheap neighbor count)
            wall_mask = sm > 0.55
            neigh = (
                np.roll(wall_mask, 1, 0)
                + np.roll(wall_mask, -1, 0)
                + np.roll(wall_mask, 1, 1)
                + np.roll(wall_mask, -1, 1)
                + np.roll(np.roll(wall_mask, 1, 0), 1, 1)
                + np.roll(np.roll(wall_mask, 1, 0), -1, 1)
                + np.roll(np.roll(wall_mask, -1, 0), 1, 1)
                + np.roll(np.roll(wall_mask, -1, 0), -1, 1)
            )
            speckle = wall_mask & (neigh < 2)
            sm[speckle] *= 0.6
            self.wall_probability = sm
            
            # Extract wall line segments
            self.wall_lines = self.line_extractor.extract_lines(self.wall_probability, threshold=0.38)
            
            # Detect temporal signal anomalies (sudden changes indicate movement)
            self._detect_signal_anomalies()
        
        # Zone segmentation every 60 cycles
        if self.reconstruction_cycles % 60 == 0:
            self.segment_zones_from_walls()
            
            # Decay zone activity
            for zone_id in self.zone_activity:
                self.zone_activity[zone_id] *= 0.95
        
        # Slow decay
        self.signal_strength_map *= 0.995
        self.attenuation_map *= 0.999
        self.free_space *= 0.998
        
        # Decay Fresnel zone evidence and multipath signatures
        self.fresnel_zones *= 0.99
        self.multipath_signature *= 0.995
        
        # Slowly decay material confidence (allows re-learning)
        self.material_confidence *= 0.9995
        
        # Clear old reflection points
        now = time.time()
        self.reflection_points = [(x, y, i, t) for x, y, i, t in self.reflection_points if now - t < 30]
        
        # Periodically clear ray trace cache
        if self.reconstruction_cycles % 100 == 0:
            self.ray_trace_cache.clear()
        
        # Enforce memory limits every 50 cycles
        if self.reconstruction_cycles % 50 == 0:
            self.enforce_memory_limits()
        
        # Auto-save to database every 300 cycles (~5 minutes at 1Hz)
        if self.reconstruction_cycles % 300 == 0:
            self.save_persistent_data()

    def _maybe_calibrate_path_loss(self, now: float):
        """Estimate a good path-loss exponent by minimizing jitter for stable nodes."""
        self._last_calibration = now

        candidates = []
        for e in self.entities.values():
            if e.is_infrastructure and len(e.paired_rssi) >= 6:
                pairs = [(rp, rr) for (rp, rr, t) in e.paired_rssi if now - t < 8]
                if len(pairs) >= 6:
                    candidates.append(pairs)

        if not candidates:
            return

        exps = np.linspace(2.0, 3.8, 10)
        best_exp = None
        best_score = None
        
        for exp in exps:
            scores = []
            for pairs in candidates:
                pts = []
                for rp, rr in pairs[-18:]:
                    d1 = SignalProcessor.rssi_to_distance(rp, exp)
                    d2 = SignalProcessor.rssi_to_distance(rr, exp)

                    sensor_vec = REMOTE_POS - PRIMARY_POS
                    d_sensors = np.linalg.norm(sensor_vec[:2])
                    if d_sensors < 0.1:
                        continue

                    a = (d1*d1 - d2*d2 + d_sensors*d_sensors) / (2 * d_sensors)
                    h_sq = d1*d1 - a*a
                    unit_vec = sensor_vec[:2] / d_sensors
                    if h_sq < 0:
                        w1, w2 = 1/(d1+0.1), 1/(d2+0.1)
                        x = (PRIMARY_POS[0]*w1 + REMOTE_POS[0]*w2) / (w1+w2)
                        y = (PRIMARY_POS[1]*w1 + REMOTE_POS[1]*w2) / (w1+w2)
                    else:
                        h = math.sqrt(h_sq)
                        px = PRIMARY_POS[0] + a * unit_vec[0]
                        py = PRIMARY_POS[1] + a * unit_vec[1]
                        perp = np.array([-unit_vec[1], unit_vec[0]])
                        x1, y1 = px + h * perp[0], py + h * perp[1]
                        x2, y2 = px - h * perp[0], py - h * perp[1]
                        if 0 < y1 < ROOM_DEPTH:
                            x, y = x1, y1
                        else:
                            x, y = x2, y2

                    pts.append((x, y))

                if len(pts) >= 6:
                    pts = np.array(pts, dtype=np.float32)
                    scores.append(float(np.mean(np.var(pts, axis=0))))

            if scores:
                score = float(np.mean(scores))
                if best_score is None or score < best_score:
                    best_score = score
                    best_exp = exp

        if best_exp is None:
            return

        # Smooth update
        self.path_loss_est = float(0.85 * self.path_loss_est + 0.15 * best_exp)
    
    def get_active_entities(self, max_age: float = 10.0) -> List[TrackedEntity]:
        now = time.time()
        return [e for e in self.entities.values() 
                if e.tracker and now - e.last_seen < max_age 
                and not e.is_infrastructure]
    
    def get_active_persons(self) -> List[TrackedEntity]:
        """Get currently active persons."""
        return [e for e in self.get_active_entities() if e.entity_type == "person"]
    
    def get_person_in_zone(self, zone_id: int) -> List[TrackedEntity]:
        """Get persons currently in a specific zone."""
        persons = []
        for e in self.get_active_persons():
            gx = int(e.position[0] / FLOOR_RES)
            gy = int(e.position[1] / FLOOR_RES)
            if 0 <= gx < FLOOR_X and 0 <= gy < FLOOR_Y:
                if self.zone_map[gx, gy] == zone_id:
                    persons.append(e)
        return persons
    
    def predict_future_position(self, mac: str, seconds: float = 2.0) -> Optional[np.ndarray]:
        """Predict where a person will be in N seconds based on track history.
        
        Uses wall awareness to avoid predicting positions inside walls.
        """
        if mac not in self.person_tracks:
            return None
        
        track = self.person_tracks[mac]
        if len(track) < 3:
            return None
        
        # Get recent positions
        recent = track[-10:]  # Last 10 positions
        
        if len(recent) < 2:
            return None
        
        # Calculate weighted average velocity (recent positions weighted higher)
        total_vx, total_vy = 0, 0
        total_weight = 0
        
        for i in range(1, len(recent)):
            x1, y1, z1, t1 = recent[i-1]
            x2, y2, z2, t2 = recent[i]
            dt = t2 - t1
            if dt > 0.01:
                weight = 1.0 + (i / len(recent))  # Recent positions weighted higher
                total_vx += (x2 - x1) / dt * weight
                total_vy += (y2 - y1) / dt * weight
                total_weight += weight
        
        if total_weight < 0.1:
            return None
        
        avg_vx = total_vx / total_weight
        avg_vy = total_vy / total_weight
        
        # Predict future position
        last_x, last_y, last_z, last_t = recent[-1]
        
        pred_x = last_x + avg_vx * seconds
        pred_y = last_y + avg_vy * seconds
        
        # Wall collision avoidance - step along path and check for walls
        steps = int(seconds * 10)  # 10 steps per second
        step_vx = avg_vx / 10
        step_vy = avg_vy / 10
        
        cur_x, cur_y = last_x, last_y
        for _ in range(steps):
            next_x = cur_x + step_vx
            next_y = cur_y + step_vy
            
            # Check if next position is in a wall
            gx = int(next_x / FLOOR_RES)
            gy = int(next_y / FLOOR_RES)
            
            if 0 <= gx < FLOOR_X and 0 <= gy < FLOOR_Y:
                if self.wall_probability[gx, gy] > 0.5:
                    # Hit a wall - stop here
                    break
            
            cur_x, cur_y = next_x, next_y
        
        pred_x, pred_y = cur_x, cur_y
        
        # Clamp to room bounds
        pred_x = max(0.2, min(ROOM_WIDTH - 0.2, pred_x))
        pred_y = max(0.2, min(ROOM_DEPTH - 0.2, pred_y))
        
        return np.array([pred_x, pred_y, last_z])
    
    def predict_trajectory(self, mac: str, duration: float = 5.0, resolution: float = 0.5) -> List[np.ndarray]:
        """Predict full trajectory for the next N seconds.
        
        Returns list of predicted positions at regular intervals.
        """
        positions = []
        for t in np.arange(resolution, duration + resolution, resolution):
            pos = self.predict_future_position(mac, t)
            if pos is not None:
                positions.append(pos)
        return positions
    
    def estimate_arrival_time(self, mac: str, target_x: float, target_y: float) -> Optional[float]:
        """Estimate time to reach a target location based on current trajectory."""
        if mac not in self.entities:
            return None
        
        entity = self.entities[mac]
        if entity.position is None or not entity.is_moving:
            return None
        
        # Current position and velocity
        cur_x, cur_y = entity.position[0], entity.position[1]
        vx, vy = entity.velocity[0], entity.velocity[1]
        speed = entity.speed
        
        if speed < 0.1:
            return None
        
        # Distance to target
        dx = target_x - cur_x
        dy = target_y - cur_y
        dist = math.sqrt(dx*dx + dy*dy)
        
        # Check if moving toward target
        dot = dx * vx + dy * vy
        if dot < 0:
            return None  # Moving away from target
        
        # Simple ETA
        return dist / speed
    
    def detect_room_boundaries(self) -> dict:
        """Analyze accumulated data to detect actual room boundaries."""
        # Find edges of high-probability wall regions
        wall_mask = self.wall_probability > 0.4
        
        # Scan from each edge to find first significant wall
        bounds = {'min_x': 0, 'max_x': ROOM_WIDTH, 'min_y': 0, 'max_y': ROOM_DEPTH}
        
        # Scan from left
        for gx in range(FLOOR_X):
            col_sum = np.sum(wall_mask[gx, :])
            if col_sum > FLOOR_Y * 0.15:  # 15% threshold
                bounds['min_x'] = max(0, gx * FLOOR_RES - 0.2)
                break
        
        # Scan from right
        for gx in range(FLOOR_X - 1, -1, -1):
            col_sum = np.sum(wall_mask[gx, :])
            if col_sum > FLOOR_Y * 0.15:
                bounds['max_x'] = min(ROOM_WIDTH, (gx + 1) * FLOOR_RES + 0.2)
                break
        
        # Scan from bottom
        for gy in range(FLOOR_Y):
            row_sum = np.sum(wall_mask[:, gy])
            if row_sum > FLOOR_X * 0.15:
                bounds['min_y'] = max(0, gy * FLOOR_RES - 0.2)
                break
        
        # Scan from top
        for gy in range(FLOOR_Y - 1, -1, -1):
            row_sum = np.sum(wall_mask[:, gy])
            if row_sum > FLOOR_X * 0.15:
                bounds['max_y'] = min(ROOM_DEPTH, (gy + 1) * FLOOR_RES + 0.2)
                break
        
        return bounds
    
    def get_activity_summary(self) -> dict:
        """Get summary of room activity for analysis."""
        active = self.get_active_entities()
        persons = self.get_active_persons()
        
        # Zone activity
        zone_summary = {}
        for zone_id, activity in self.zone_activity.items():
            if zone_id > 0:
                label = self.zone_labels.get(zone_id, f"Zone-{zone_id}")
                zone_summary[label] = round(activity, 2)
        
        # Occupancy map stats
        max_occ = np.max(self.occupancy_history)
        occ_hotspots = []
        if max_occ > 0.1:
            norm_occ = self.occupancy_history / max_occ
            for gx in range(2, FLOOR_X-2, 4):
                for gy in range(2, FLOOR_Y-2, 4):
                    if norm_occ[gx, gy] > 0.6:
                        occ_hotspots.append({
                            'x': gx * FLOOR_RES,
                            'y': gy * FLOOR_RES,
                            'intensity': round(norm_occ[gx, gy], 2)
                        })
        
        # Material summary
        material_summary = {}
        mat_names = {1: "Drywall", 2: "Concrete", 3: "Glass", 4: "Metal"}
        for mat_id, name in mat_names.items():
            cnt = np.sum((self.material_map == mat_id) & (self.material_confidence > 0.2))
            if cnt > 0:
                material_summary[name] = int(cnt)
        
        return {
            'total_entities': len(active),
            'persons': len(persons),
            'moving': sum(1 for e in active if e.is_moving),
            'dual_sensor': self.dual_sensor_count,
            'fingerprints': len(self.fingerprint_db),
            'wall_segments': len(self.wall_lines),
            'zones': zone_summary,
            'hotspots': occ_hotspots[:5],  # Top 5
            'anomalies': len(self.anomaly_events),
            'materials': material_summary,
            'reflections': len(self.reflection_points),
            'has_baseline': self.has_baseline
        }
    
    def infer_room_layout(self) -> dict:
        """Infer room layout geometry from wall probability map."""
        # Find room boundaries
        boundaries = self.detect_room_boundaries()
        
        # Find wall segments
        wall_lines = self.wall_lines
        
        # Classify walls by orientation
        horizontal_walls = []
        vertical_walls = []
        diagonal_walls = []
        
        for start, end, conf in wall_lines:
            dx = end[0] - start[0]
            dy = end[1] - start[1]
            angle = math.degrees(math.atan2(dy, dx))
            
            # Normalize to 0-180
            angle = angle % 180
            
            if angle < 15 or angle > 165:
                horizontal_walls.append((start, end, conf))
            elif 75 < angle < 105:
                vertical_walls.append((start, end, conf))
            else:
                diagonal_walls.append((start, end, conf))
        
        # Find dominant wall directions (Hough-like analysis)
        angle_histogram = np.zeros(36)  # 5-degree bins
        for start, end, conf in wall_lines:
            dx = end[0] - start[0]
            dy = end[1] - start[1]
            angle = math.degrees(math.atan2(dy, dx)) % 180
            bin_idx = int(angle / 5) % 36
            length = math.sqrt(dx*dx + dy*dy)
            angle_histogram[bin_idx] += conf * length
        
        # Find peaks
        dominant_angles = []
        for i in range(36):
            if angle_histogram[i] > np.mean(angle_histogram) * 1.5:
                dominant_angles.append(i * 5)
        
        # Estimate room shape
        room_shape = "unknown"
        if len(horizontal_walls) >= 2 and len(vertical_walls) >= 2:
            room_shape = "rectangular"
        elif len(horizontal_walls) >= 1 or len(vertical_walls) >= 1:
            room_shape = "partial_rectangular"
        elif len(diagonal_walls) > len(horizontal_walls) + len(vertical_walls):
            room_shape = "irregular"
        
        # Find corners (intersections of walls)
        corners = []
        for i, (s1, e1, c1) in enumerate(wall_lines):
            for j, (s2, e2, c2) in enumerate(wall_lines[i+1:], i+1):
                # Check for intersection
                intersection = self._line_intersection(s1, e1, s2, e2)
                if intersection is not None:
                    x, y = intersection
                    if 0 < x < ROOM_WIDTH and 0 < y < ROOM_DEPTH:
                        corners.append((x, y, c1 * c2))
        
        # Merge nearby corners
        merged_corners = []
        used = set()
        for i, (x, y, c) in enumerate(corners):
            if i in used:
                continue
            cluster = [(x, y, c)]
            for j, (x2, y2, c2) in enumerate(corners[i+1:], i+1):
                if j not in used:
                    dist = math.sqrt((x-x2)**2 + (y-y2)**2)
                    if dist < 0.5:  # 50cm merge threshold
                        cluster.append((x2, y2, c2))
                        used.add(j)
            
            # Average corner position
            avg_x = sum(p[0] for p in cluster) / len(cluster)
            avg_y = sum(p[1] for p in cluster) / len(cluster)
            avg_c = max(p[2] for p in cluster)
            merged_corners.append({'x': round(avg_x, 2), 'y': round(avg_y, 2), 'confidence': round(avg_c, 2)})
        
        return {
            'shape': room_shape,
            'boundaries': boundaries,
            'horizontal_walls': len(horizontal_walls),
            'vertical_walls': len(vertical_walls),
            'diagonal_walls': len(diagonal_walls),
            'dominant_angles': dominant_angles,
            'corners': merged_corners[:20],  # Top 20 corners
            'wall_coverage': round(np.mean(self.wall_probability > 0.3) * 100, 1)
        }
    
    def _line_intersection(self, p1, p2, p3, p4):
        """Find intersection point of two line segments."""
        x1, y1 = p1[0], p1[1]
        x2, y2 = p2[0], p2[1]
        x3, y3 = p3[0], p3[1]
        x4, y4 = p4[0], p4[1]
        
        denom = (x1-x2)*(y3-y4) - (y1-y2)*(x3-x4)
        if abs(denom) < 0.001:
            return None
        
        t = ((x1-x3)*(y3-y4) - (y1-y3)*(x3-x4)) / denom
        u = -((x1-x2)*(y1-y3) - (y1-y2)*(x1-x3)) / denom
        
        if 0 <= t <= 1 and 0 <= u <= 1:
            x = x1 + t * (x2 - x1)
            y = y1 + t * (y2 - y1)
            return (x, y)
        return None
    
    def get_wall_voxels(self, threshold: float = 0.25) -> List[Tuple[int, int, float]]:
        """Get floor grid cells likely containing walls."""
        voxels = []
        for x in range(FLOOR_X):
            for y in range(FLOOR_Y):
                prob = self.wall_probability[x, y]
                if prob > threshold:
                    voxels.append((x, y, prob))
        return voxels
    
    def get_presence_status(self) -> dict:
        """Get comprehensive presence detection status for smart home integration."""
        now = time.time()
        active = self.get_active_entities()
        persons = self.get_active_persons()
        
        # Room occupied status
        is_occupied = len(persons) > 0
        
        # Activity level (0-1)
        activity_level = 0.0
        for entity in active:
            if entity.is_moving:
                activity_level += 0.3
            if entity.entity_type == "person":
                activity_level += 0.2
        activity_level = min(1.0, activity_level)
        
        # Person details
        person_details = []
        for p in persons:
            detail = {
                'mac': p.mac[-8:],  # Last 8 chars for privacy
                'position': {'x': round(p.position[0], 2), 'y': round(p.position[1], 2)},
                'moving': p.is_moving,
                'speed': round(p.speed, 2),
                'signal': round(p.signal_strength, 2),
            }
            
            # Add zone info
            if p.last_zone:
                detail['zone'] = p.last_zone
            
            # Add approach direction
            if p.approach_direction and p.approach_direction != "stationary":
                detail['approaching'] = p.approach_direction.replace('_', ' ')
            
            person_details.append(detail)
        
        # Zone occupancy
        zone_occupancy = {}
        for zone_id, label in self.zone_labels.items():
            if zone_id > 0:
                persons_in_zone = sum(1 for p in persons if p.last_zone == label)
                zone_occupancy[label] = {
                    'occupied': persons_in_zone > 0,
                    'count': persons_in_zone,
                    'activity': round(self.zone_activity.get(zone_id, 0), 2)
                }
        
        # Motion detection summary
        motion_detected = any(e.is_moving for e in active)
        recent_motion = any(
            now - e.last_seen < 30 and (e.is_moving or e.rssi_velocity and abs(e.rssi_velocity) > 2)
            for e in self.entities.values()
        )
        
        return {
            'timestamp': now,
            'occupied': is_occupied,
            'person_count': len(persons),
            'activity_level': round(activity_level, 2),
            'motion_detected': motion_detected,
            'recent_motion': recent_motion,
            'persons': person_details,
            'zones': zone_occupancy,
            'sensors': {
                'primary': {'ip': '192.168.0.139', 'status': 'ok'},
                'remote': {'ip': '192.168.4.2', 'status': 'ok' if len([e for e in active if e.rssi_remote > -90]) > 0 else 'no_signal'}
            }
        }
    
    def check_zone_entry(self, zone_name: str) -> List[str]:
        """Check which entities recently entered a specific zone."""
        entered = []
        now = time.time()
        
        for mac, entity in self.entities.items():
            if entity.last_zone == zone_name:
                # Check if entity was in a different zone recently
                if hasattr(entity, '_prev_zone') and entity._prev_zone != zone_name:
                    if now - entity.last_seen < 5:  # Within last 5 seconds
                        entered.append(mac)
            
            # Update previous zone tracking
            entity._prev_zone = entity.last_zone
        
        return entered
    
    def get_occupancy_forecast(self, hours: float = 1.0) -> dict:
        """Provide occupancy forecast based on historical patterns."""
        # This is a simplified forecast based on current state
        # A real implementation would use historical data
        
        persons = self.get_active_persons()
        current_occupancy = len(persons)
        
        # Simple forecast: if someone is moving toward exit, predict decrease
        forecast = []
        for t in [0.25, 0.5, 1.0]:
            predicted = current_occupancy
            for p in persons:
                if p.approach_direction == "away_from_primary":
                    predicted = max(0, predicted - 0.3)
                elif p.approach_direction == "toward_primary":
                    predicted = min(predicted + 0.2, current_occupancy + 1)
            forecast.append({
                'time_offset_hours': t,
                'predicted_occupancy': round(predicted, 1),
                'confidence': 0.5  # Low confidence for simple model
            })
        
        return {
            'current': current_occupancy,
            'forecast': forecast
        }


# ==================== Data Fetcher ====================

class DataFetcher(QThread):
    data_received = pyqtSignal(dict)
    status_changed = pyqtSignal(bool, str)
    
    def __init__(self, hosts: List[str], port: int):
        super().__init__()
        self.hosts = hosts
        self.host = hosts[0] if hosts else "127.0.0.1"
        self.port = port
        self.running = True
        self.cycle = 0
        self.last_scan = {}
        self.last_csi = {}
        self.fetch_csi = True  # Enable CSI fetching
        
    def run(self):
        while self.running:
            try:
                status, remotes, csi_data = None, None, None
                for h in self.hosts:
                    s = self._fetch(f"http://{h}:{self.port}/status", 2.0)
                    if s:
                        self.host = h
                        status = s
                        remotes = self._fetch(f"http://{h}:{self.port}/remotes", 2.0)
                        # Fetch CSI data if enabled
                        if self.fetch_csi:
                            csi_data = self._fetch(f"http://{h}:{self.port}/csi", 1.0)
                            if csi_data:
                                self.last_csi = csi_data
                        break
                
                self.cycle += 1
                # Fetch scan every other cycle with long timeout
                if self.cycle >= 2:
                    scan = self._fetch(f"http://{self.host}:{self.port}/scan", 12.0)
                    if scan:
                        self.last_scan = scan
                    self.cycle = 0
                
                if status:
                    self.data_received.emit({
                        'status': status,
                        'scan': self.last_scan,
                        'remotes': remotes or {},
                        'csi': self.last_csi
                    })
                    self.status_changed.emit(True, self.host)
                else:
                    self.status_changed.emit(False, "No response")
                    
            except Exception as e:
                self.status_changed.emit(False, str(e)[:30])
            
            time.sleep(0.12)
    
    def _fetch(self, url: str, timeout: float) -> Optional[dict]:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'HydraTomo/1.0'})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, ValueError):
            return None
    
    def stop(self):
        self.running = False


# ==================== OpenGL Renderer ====================

class TomoRenderer(QOpenGLWidget):
    """3D renderer for tomographic reconstruction."""
    
    def __init__(self):
        super().__init__()
        self.engine = TomographicEngine()
        
        # Camera
        self.cam_dist = 14.0
        self.cam_azimuth = 45.0
        self.cam_elevation = 55.0
        self.cam_target = [ROOM_WIDTH/2, ROOM_DEPTH/2, 1.0]
        
        # Animation
        self.time = 0
        self.scan_angle = 0
        
        # Mouse
        self.last_mouse = None
        self.setMouseTracking(True)
        
        # FPS tracking
        self.fps = 0
        self.frames = 0
        self.fps_time = time.time()
        
        # Visualization toggles
        self.show_heatmap = True
        self.show_walls = True
        self.show_coverage = True
        self.show_fresnel = True
        self.show_radar = True
        self.show_trails = True
        self.show_occupancy = False  # Occupancy history heatmap
        self.show_motion = False     # Motion vector field
        self.show_anomalies = True   # Signal anomaly indicators
        self.show_zones = False      # Zone boundaries
        self.show_person_trails = True  # Individual person tracks
        self.auto_rotate = False
        
        # Remote environment sensing data
        self.remote_environment = {
            'occupancy': 0,
            'breathing_detected': False,
            'activity_level': 0,
            'signal_density': 0,
            'moving': 0,
            'approaching': 0,
            'receding': 0
        }
        
        # Set focus policy for keyboard events
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        
        # Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self._tick)
        self.timer.start(16)
        
    def _tick(self):
        self.time += 0.016
        self.scan_angle = (self.scan_angle + 1.5) % 360
        
        # Auto-rotate camera
        if self.auto_rotate:
            self.cam_azimuth = (self.cam_azimuth + 0.15) % 360
        
        self.engine.run_reconstruction_cycle()
        
        self.frames += 1
        now = time.time()
        if now - self.fps_time >= 1:
            self.fps = self.frames / (now - self.fps_time)
            self.frames = 0
            self.fps_time = now
        
        self.update()
    
    def keyPressEvent(self, event):
        """Handle keyboard shortcuts."""
        key = event.key()
        
        # Toggle visualization layers
        if key == Qt.Key.Key_H:
            self.show_heatmap = not self.show_heatmap
        elif key == Qt.Key.Key_W:
            self.show_walls = not self.show_walls
        elif key == Qt.Key.Key_C:
            self.show_coverage = not self.show_coverage
        elif key == Qt.Key.Key_F:
            self.show_fresnel = not self.show_fresnel
        elif key == Qt.Key.Key_R:
            self.show_radar = not self.show_radar
        elif key == Qt.Key.Key_T:
            self.show_trails = not self.show_trails
        elif key == Qt.Key.Key_A:
            self.auto_rotate = not self.auto_rotate
        elif key == Qt.Key.Key_O:
            self.show_occupancy = not self.show_occupancy
        elif key == Qt.Key.Key_M:
            self.show_motion = not self.show_motion
        elif key == Qt.Key.Key_X:
            self.show_anomalies = not self.show_anomalies
        elif key == Qt.Key.Key_Z:
            self.show_zones = not self.show_zones
        elif key == Qt.Key.Key_P:
            self.show_person_trails = not self.show_person_trails
        # Camera presets
        elif key == Qt.Key.Key_1:  # Top-down view
            self.cam_azimuth = 0
            self.cam_elevation = 89
            self.cam_dist = 10
        elif key == Qt.Key.Key_2:  # Front view
            self.cam_azimuth = 0
            self.cam_elevation = 15
            self.cam_dist = 14
        elif key == Qt.Key.Key_3:  # Side view
            self.cam_azimuth = 90
            self.cam_elevation = 25
            self.cam_dist = 14
        elif key == Qt.Key.Key_4:  # Isometric
            self.cam_azimuth = 45
            self.cam_elevation = 55
            self.cam_dist = 14
        # Zoom
        elif key == Qt.Key.Key_Plus or key == Qt.Key.Key_Equal:
            self.cam_dist = max(3, self.cam_dist - 1)
        elif key == Qt.Key.Key_Minus:
            self.cam_dist = min(30, self.cam_dist + 1)
        # Reset
        elif key == Qt.Key.Key_0:
            self.cam_azimuth = 45
            self.cam_elevation = 55
            self.cam_dist = 14
            self.cam_target = [ROOM_WIDTH/2, ROOM_DEPTH/2, 1.0]
        
        self.update()
        super().keyPressEvent(event)
    
    def initializeGL(self):
        glClearColor(0.02, 0.03, 0.08, 1.0)
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
        
        glLightfv(GL_LIGHT0, GL_POSITION, [ROOM_WIDTH/2, ROOM_DEPTH/2, 10, 1])
        glLightfv(GL_LIGHT0, GL_DIFFUSE, [0.9, 0.92, 1.0, 1])
        glLightfv(GL_LIGHT0, GL_AMBIENT, [0.3, 0.32, 0.4, 1])
        
        glLightfv(GL_LIGHT1, GL_POSITION, [0, 0, 5, 1])
        glLightfv(GL_LIGHT1, GL_DIFFUSE, [0.4, 0.5, 0.6, 1])
        
    def resizeGL(self, w, h):
        glViewport(0, 0, w, h)
        glMatrixMode(GL_PROJECTION)
        glLoadIdentity()
        gluPerspective(50, w / max(h, 1), 0.1, 100)
        glMatrixMode(GL_MODELVIEW)
    
    def paintGL(self):
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
        glLoadIdentity()
        
        # Camera
        az, el = math.radians(self.cam_azimuth), math.radians(self.cam_elevation)
        cx = self.cam_target[0] + self.cam_dist * math.cos(el) * math.sin(az)
        cy = self.cam_target[1] + self.cam_dist * math.cos(el) * math.cos(az)
        cz = self.cam_target[2] + self.cam_dist * math.sin(el)
        gluLookAt(cx, cy, cz, *self.cam_target, 0, 0, 1)
        
        self._render_room()
        
        if self.show_zones:
            self._render_zones()
        
        if self.show_heatmap or self.show_coverage:
            self._render_signal_heatmap()
        
        if self.show_occupancy:
            self._render_occupancy_heatmap()
        
        if self.show_motion:
            self._render_motion_vectors()
        
        if self.show_walls:
            self._render_walls()
        
        if self.show_anomalies:
            self._render_anomalies()
        
        if self.show_person_trails:
            self._render_person_trails()
        
        self._render_sensors()
        self._render_entities()
        self._render_connections()
        self._render_hud()
    
    def _render_hud(self):
        """Render heads-up display with statistics."""
        # Switch to 2D orthographic projection for HUD
        glMatrixMode(GL_PROJECTION)
        glPushMatrix()
        glLoadIdentity()
        w, h = self.width(), self.height()
        glOrtho(0, w, h, 0, -1, 1)
        glMatrixMode(GL_MODELVIEW)
        glPushMatrix()
        glLoadIdentity()
        
        glDisable(GL_LIGHTING)
        glDisable(GL_DEPTH_TEST)
        
        # Semi-transparent background for HUD (top-left stats)
        margin = 10
        hud_w, hud_h = 260, 340  # Expanded for breathing/device info
        
        glColor4f(0.02, 0.04, 0.08, 0.75)
        glBegin(GL_QUADS)
        glVertex2f(margin, margin)
        glVertex2f(margin + hud_w, margin)
        glVertex2f(margin + hud_w, margin + hud_h)
        glVertex2f(margin, margin + hud_h)
        glEnd()
        
        # Border
        glColor4f(0.2, 0.5, 0.8, 0.8)
        glLineWidth(2)
        glBegin(GL_LINE_LOOP)
        glVertex2f(margin, margin)
        glVertex2f(margin + hud_w, margin)
        glVertex2f(margin + hud_w, margin + hud_h)
        glVertex2f(margin, margin + hud_h)
        glEnd()
        
        # Signal quality bars in HUD
        self._render_signal_quality_bars(margin + 10, margin + 20)
        
        # Legend panel (top-right)
        self._render_legend(w - 160, margin)
        
        # Mini radar in bottom-right
        self._render_mini_radar(w - 150, h - 150, 120)
        
        # Scale indicator (bottom-left)
        self._render_scale_indicator(margin + 20, h - 40)
        
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_LIGHTING)
        
        # Restore 3D projection
        glMatrixMode(GL_PROJECTION)
        glPopMatrix()
        glMatrixMode(GL_MODELVIEW)
        glPopMatrix()
    
    def _render_signal_quality_bars(self, x, y):
        """Render signal quality indicator bars."""
        # Primary sensor
        glColor4f(0.6, 0.8, 0.4, 0.8)
        glBegin(GL_QUADS)
        glVertex2f(x, y)
        glVertex2f(x + 8, y)
        glVertex2f(x + 8, y + 12)
        glVertex2f(x, y + 12)
        glEnd()
        
        glColor4f(0.4, 0.8, 0.3, 0.9)
        
        # Bar levels
        active = self.engine.get_active_entities()
        quality = min(1.0, len(active) / 5) if active else 0
        
        bar_w, bar_h = 85, 8
        for i in range(5):
            bx = x + 15 + i * 18
            by = y + 2
            
            if i / 5 <= quality:
                glColor4f(0.3, 0.9, 0.4, 0.9)
            else:
                glColor4f(0.2, 0.3, 0.2, 0.4)
            
            glBegin(GL_QUADS)
            glVertex2f(bx, by)
            glVertex2f(bx + 14, by)
            glVertex2f(bx + 14, by + bar_h)
            glVertex2f(bx, by + bar_h)
            glEnd()
        
        # Remote sensor status
        remote_ok = len([e for e in self.engine.entities.values() 
                        if e.rssi_remote > -95]) > 0
        
        if remote_ok:
            glColor4f(0.3, 0.7, 1.0, 0.9)
        else:
            glColor4f(0.6, 0.3, 0.3, 0.6)
        
        glBegin(GL_QUADS)
        glVertex2f(x, y + 20)
        glVertex2f(x + 8, y + 20)
        glVertex2f(x + 8, y + 32)
        glVertex2f(x, y + 32)
        glEnd()
        
        # Stats counters
        y_offset = y + 50
        
        # Count materials
        material_counts = {}
        for mat in range(5):
            cnt = np.sum((self.engine.material_map == mat) & (self.engine.material_confidence > 0.2))
            if cnt > 0:
                material_counts[mat] = cnt
        
        # Count approach directions
        approach_counts = {}
        for e in active:
            if e.approach_direction and e.approach_direction != "stationary":
                approach_counts[e.approach_direction] = approach_counts.get(e.approach_direction, 0) + 1
        
        stats = [
            (f"Entities: {len(active)}", (0.7, 0.9, 0.7)),
            (f"Persons: {self.engine.persons_detected}", (1.0, 0.5, 0.5)),
            (f"Walls: {len(self.engine.get_wall_voxels())}", (0.5, 0.8, 0.9)),
            (f"Dual: {self.engine.dual_sensor_count}", (0.9, 0.7, 0.4)),
            (f"Fingerprints: {len(self.engine.fingerprint_db)}", (0.7, 0.5, 0.9)),
            (f"Reflections: {len(self.engine.reflection_points)}", (1.0, 0.6, 0.2)),
            (f"FPS: {self.fps:.0f}", (0.5, 0.7, 0.5)),
        ]
        
        # Add breathing/presence detection stats
        breathing_count = sum(1 for e in active if e.breathing_detected)
        high_conf_count = sum(1 for e in active if e.presence_confidence > 0.7)
        
        stats.append((f"Breathing: {breathing_count}", (1.0, 0.3, 0.8) if breathing_count > 0 else (0.4, 0.2, 0.3)))
        stats.append((f"High-Conf: {high_conf_count}", (0.9, 0.8, 0.3)))
        
        # Device type breakdown
        dev_types = {'smartphone': 0, 'laptop': 0, 'iot': 0, 'infrastructure': 0, 'wearable': 0}
        for e in active:
            if e.device_type_name in dev_types:
                dev_types[e.device_type_name] += 1
        
        for dtype, cnt in dev_types.items():
            if cnt > 0:
                color_map = {
                    'smartphone': (0.2, 0.8, 0.3),
                    'laptop': (0.5, 0.5, 0.9),
                    'iot': (0.8, 0.5, 0.2),
                    'infrastructure': (0.3, 0.3, 0.8),
                    'wearable': (0.8, 0.3, 0.8)
                }
                stats.append((f"{dtype.title()}: {cnt}", color_map.get(dtype, (0.5, 0.5, 0.5))))
        
        # Add material info
        mat_names = {0: "Unknown", 1: "Drywall", 2: "Concrete", 3: "Glass", 4: "Metal"}
        for mat, cnt in material_counts.items():
            if mat > 0:  # Skip unknown
                stats.append((f"{mat_names[mat]}: {cnt}", (0.6, 0.7, 0.8)))
        
        for i, (text, color) in enumerate(stats):
            glColor4f(*color, 0.8)
            # Draw stat indicator bars
            bar_val = 0.5
            if "Entities" in text:
                bar_val = min(1.0, len(active) / 10)
            elif "Persons" in text:
                bar_val = min(1.0, self.engine.persons_detected / 5)
            elif "Walls" in text:
                bar_val = min(1.0, len(self.engine.get_wall_voxels()) / 500)
            elif "Dual" in text:
                bar_val = min(1.0, self.engine.dual_sensor_count / 100)
            elif "Fingerprints" in text:
                bar_val = min(1.0, len(self.engine.fingerprint_db) / 50)
            elif "FPS" in text:
                bar_val = min(1.0, self.fps / 60)
            
            glBegin(GL_QUADS)
            glVertex2f(x + 5, y_offset + i * 20)
            glVertex2f(x + 5 + bar_val * 100, y_offset + i * 20)
            glVertex2f(x + 5 + bar_val * 100, y_offset + i * 20 + 13)
            glVertex2f(x + 5, y_offset + i * 20 + 13)
            glEnd()
    
    def _render_legend(self, x, y):
        """Render entity type legend and keyboard shortcuts."""
        glColor4f(0.02, 0.04, 0.08, 0.7)
        legend_w, legend_h = 145, 190
        
        glBegin(GL_QUADS)
        glVertex2f(x, y)
        glVertex2f(x + legend_w, y)
        glVertex2f(x + legend_w, y + legend_h)
        glVertex2f(x, y + legend_h)
        glEnd()
        
        glColor4f(0.2, 0.5, 0.8, 0.6)
        glLineWidth(1)
        glBegin(GL_LINE_LOOP)
        glVertex2f(x, y)
        glVertex2f(x + legend_w, y)
        glVertex2f(x + legend_w, y + legend_h)
        glVertex2f(x, y + legend_h)
        glEnd()
        
        # Legend items
        items = [
            ((1.0, 0.3, 0.3), "Person"),
            ((0.3, 0.7, 1.0), "Device"),
            ((0.4, 0.9, 0.5), "Object"),
            ((0.2, 0.75, 0.85), "Wall"),
            ((0, 1, 0.5), "Primary"),
            ((0, 0.7, 1), "Remote"),
        ]
        
        for i, (color, label) in enumerate(items):
            iy = y + 12 + i * 18
            
            # Color box
            glColor4f(*color, 0.9)
            glBegin(GL_QUADS)
            glVertex2f(x + 10, iy)
            glVertex2f(x + 24, iy)
            glVertex2f(x + 24, iy + 12)
            glVertex2f(x + 10, iy + 12)
            glEnd()
        
        # Keyboard toggle indicators
        toggles = [
            ('H', self.show_heatmap, (1.0, 0.8, 0.3)),
            ('W', self.show_walls, (0.2, 0.75, 0.85)),
            ('C', self.show_coverage, (0.3, 0.5, 0.9)),
            ('X', self.show_anomalies, (1.0, 0.6, 0.1)),
            ('O', self.show_occupancy, (0.8, 0.3, 0.8)),
            ('M', self.show_motion, (0.9, 0.4, 0.4)),
            ('T', self.show_trails, (0.5, 0.9, 0.5)),
            ('Z', self.show_zones, (0.4, 0.6, 0.9)),
            ('P', self.show_person_trails, (1.0, 0.4, 0.4)),
            ('A', self.auto_rotate, (0.6, 0.6, 0.9)),
        ]
        
        ty_base = y + 128
        for i, (key, active, color) in enumerate(toggles):
            tx = x + 8 + (i % 5) * 28
            ty = ty_base + (i // 5) * 24
            
            # Key box
            if active:
                glColor4f(*color, 0.9)
            else:
                glColor4f(0.25, 0.25, 0.3, 0.5)
            
            glBegin(GL_QUADS)
            glVertex2f(tx, ty)
            glVertex2f(tx + 24, ty)
            glVertex2f(tx + 24, ty + 18)
            glVertex2f(tx, ty + 18)
            glEnd()
            
            # Border
            glColor4f(0.5, 0.6, 0.7, 0.7)
            glLineWidth(1)
            glBegin(GL_LINE_LOOP)
            glVertex2f(tx, ty)
            glVertex2f(tx + 24, ty)
            glVertex2f(tx + 24, ty + 18)
            glVertex2f(tx, ty + 18)
            glEnd()
    
    def _render_scale_indicator(self, x, y):
        """Render a scale bar."""
        glColor4f(0.5, 0.7, 0.9, 0.7)
        glLineWidth(2)
        
        scale_len = 80  # pixels
        
        glBegin(GL_LINES)
        # Main line
        glVertex2f(x, y)
        glVertex2f(x + scale_len, y)
        # End ticks
        glVertex2f(x, y - 5)
        glVertex2f(x, y + 5)
        glVertex2f(x + scale_len, y - 5)
        glVertex2f(x + scale_len, y + 5)
        glEnd()
    
    def _render_mini_radar(self, cx, cy, size):
        """Render a mini radar view in corner."""
        glDisable(GL_LIGHTING)
        
        # Background circle
        glColor4f(0.02, 0.05, 0.1, 0.8)
        glBegin(GL_POLYGON)
        for i in range(32):
            a = i * math.pi * 2 / 32
            glVertex2f(cx + math.cos(a) * size/2, cy + math.sin(a) * size/2)
        glEnd()
        
        # Border
        glColor4f(0.2, 0.6, 0.9, 0.8)
        glLineWidth(2)
        glBegin(GL_LINE_LOOP)
        for i in range(32):
            a = i * math.pi * 2 / 32
            glVertex2f(cx + math.cos(a) * size/2, cy + math.sin(a) * size/2)
        glEnd()
        
        # Grid lines
        glColor4f(0.15, 0.3, 0.5, 0.4)
        glLineWidth(1)
        glBegin(GL_LINES)
        glVertex2f(cx - size/2, cy)
        glVertex2f(cx + size/2, cy)
        glVertex2f(cx, cy - size/2)
        glVertex2f(cx, cy + size/2)
        glEnd()
        
        # Range rings
        for r in [0.33, 0.66]:
            glBegin(GL_LINE_LOOP)
            for i in range(24):
                a = i * math.pi * 2 / 24
                glVertex2f(cx + math.cos(a) * size/2 * r, cy + math.sin(a) * size/2 * r)
            glEnd()
        
        # Scale: radar maps room to circle
        scale_x = (size * 0.9) / ROOM_WIDTH
        scale_y = (size * 0.9) / ROOM_DEPTH
        scale = min(scale_x, scale_y)
        offset_x = cx - ROOM_WIDTH/2 * scale
        offset_y = cy - ROOM_DEPTH/2 * scale
        
        # Sensors
        for pos, color in [(PRIMARY_POS, (0, 1, 0.5)), (REMOTE_POS, (0, 0.7, 1))]:
            rx = offset_x + pos[0] * scale
            ry = offset_y + pos[1] * scale
            glColor4f(*color, 0.9)
            glPointSize(6)
            glBegin(GL_POINTS)
            glVertex2f(rx, ry)
            glEnd()
        
        # Entities
        for entity in self.engine.get_active_entities():
            pos = entity.position
            rx = offset_x + pos[0] * scale
            ry = offset_y + pos[1] * scale
            
            # Check if in radar circle
            dist = math.sqrt((rx-cx)**2 + (ry-cy)**2)
            if dist > size/2:
                continue
            
            glColor4f(*entity.color, 0.9)
            
            if entity.entity_type == "person":
                # Larger dot for people
                glPointSize(8)
            else:
                glPointSize(5)
            
            glBegin(GL_POINTS)
            glVertex2f(rx, ry)
            glEnd()
            
            # Movement vector
            if entity.is_moving:
                vel = entity.velocity
                vx = rx + vel[0] * scale * 1.5
                vy = ry + vel[1] * scale * 1.5
                glColor4f(1, 0.5, 0.2, 0.7)
                glLineWidth(2)
                glBegin(GL_LINES)
                glVertex2f(rx, ry)
                glVertex2f(vx, vy)
                glEnd()
        
        # Sweep line
        sweep_ang = math.radians(self.scan_angle)
        glColor4f(0.3, 0.8, 1.0, 0.6)
        glLineWidth(2)
        glBegin(GL_LINES)
        glVertex2f(cx, cy)
        glVertex2f(cx + math.cos(sweep_ang) * size/2, cy + math.sin(sweep_ang) * size/2)
        glEnd()
    
    def _render_room(self):
        """Render room boundaries with measurements."""
        glEnable(GL_LIGHTING)
        
        # Floor
        glColor4f(0.04, 0.06, 0.12, 1)
        glBegin(GL_QUADS)
        glNormal3f(0, 0, 1)
        glVertex3f(0, 0, 0)
        glVertex3f(ROOM_WIDTH, 0, 0)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, 0)
        glVertex3f(0, ROOM_DEPTH, 0)
        glEnd()
        
        # Boundary walls
        glColor4f(0.08, 0.12, 0.2, 0.12)
        for wall in [
            [(0, ROOM_DEPTH, 0), (ROOM_WIDTH, ROOM_DEPTH, 0), (ROOM_WIDTH, ROOM_DEPTH, ROOM_HEIGHT), (0, ROOM_DEPTH, ROOM_HEIGHT)],
            [(0, 0, 0), (0, ROOM_DEPTH, 0), (0, ROOM_DEPTH, ROOM_HEIGHT), (0, 0, ROOM_HEIGHT)],
            [(ROOM_WIDTH, 0, 0), (ROOM_WIDTH, 0, ROOM_HEIGHT), (ROOM_WIDTH, ROOM_DEPTH, ROOM_HEIGHT), (ROOM_WIDTH, ROOM_DEPTH, 0)],
        ]:
            glBegin(GL_QUADS)
            for v in wall:
                glVertex3f(*v)
            glEnd()
        
        # Grid
        glDisable(GL_LIGHTING)
        glLineWidth(1)
        glColor4f(0.1, 0.2, 0.3, 0.25)
        glBegin(GL_LINES)
        for i in range(int(ROOM_WIDTH) + 1):
            glVertex3f(i, 0, 0.01)
            glVertex3f(i, ROOM_DEPTH, 0.01)
        for i in range(int(ROOM_DEPTH) + 1):
            glVertex3f(0, i, 0.01)
            glVertex3f(ROOM_WIDTH, i, 0.01)
        glEnd()
        
        # Room outline
        glLineWidth(2)
        glColor4f(0.2, 0.5, 0.8, 0.6)
        glBegin(GL_LINE_LOOP)
        glVertex3f(0, 0, 0)
        glVertex3f(ROOM_WIDTH, 0, 0)
        glVertex3f(ROOM_WIDTH, ROOM_DEPTH, 0)
        glVertex3f(0, ROOM_DEPTH, 0)
        glEnd()
        
        # Measurement markers (tick marks)
        glColor4f(0.4, 0.7, 1.0, 0.5)
        glLineWidth(1)
        glBegin(GL_LINES)
        # X axis markers
        for i in range(int(ROOM_WIDTH) + 1):
            glVertex3f(i, -0.2, 0.01)
            glVertex3f(i, 0, 0.01)
        # Y axis markers  
        for i in range(int(ROOM_DEPTH) + 1):
            glVertex3f(-0.2, i, 0.01)
            glVertex3f(0, i, 0.01)
        glEnd()
        
        # Compass rose at origin
        self._render_compass(0.3, 0.3, 0.02)
        
        glEnable(GL_LIGHTING)
    
    def _render_compass(self, x, y, z):
        """Render a compass indicator."""
        glDisable(GL_LIGHTING)
        size = 0.35
        
        # Circle
        glColor4f(0.3, 0.5, 0.7, 0.5)
        glLineWidth(1)
        glBegin(GL_LINE_LOOP)
        for i in range(16):
            a = i * math.pi * 2 / 16
            glVertex3f(x + math.cos(a)*size, y + math.sin(a)*size, z)
        glEnd()
        
        # N arrow (Y+)
        glColor4f(1.0, 0.3, 0.3, 0.8)
        glBegin(GL_TRIANGLES)
        glVertex3f(x, y + size*0.85, z)
        glVertex3f(x - size*0.15, y + size*0.4, z)
        glVertex3f(x + size*0.15, y + size*0.4, z)
        glEnd()
        
        # S arrow (Y-)
        glColor4f(0.5, 0.5, 0.5, 0.6)
        glBegin(GL_TRIANGLES)
        glVertex3f(x, y - size*0.65, z)
        glVertex3f(x - size*0.1, y - size*0.3, z)
        glVertex3f(x + size*0.1, y - size*0.3, z)
        glEnd()
        
        # E-W line
        glColor4f(0.5, 0.5, 0.5, 0.4)
        glBegin(GL_LINES)
        glVertex3f(x - size*0.5, y, z)
        glVertex3f(x + size*0.5, y, z)
        glEnd()
        
        glEnable(GL_LIGHTING)
    
    def _render_signal_heatmap(self):
        """Render signal strength heatmap with coverage overlay."""
        glDisable(GL_LIGHTING)
        
        sig_map = self.engine.signal_strength_map
        cov_map = self.engine.coverage_quality
        
        # Coverage quality underlay (shows sensor reach)
        glBegin(GL_QUADS)
        for gx in range(0, FLOOR_X, 3):
            for gy in range(0, FLOOR_Y, 3):
                cov = cov_map[gx, gy]
                if cov > 0.1:
                    x, y = gx * FLOOR_RES, gy * FLOOR_RES
                    s = FLOOR_RES * 3
                    
                    # Blue tint for coverage
                    glColor4f(0.1, 0.2, 0.5 * cov, 0.08 * cov)
                    glVertex3f(x, y, 0.008)
                    glVertex3f(x+s, y, 0.008)
                    glVertex3f(x+s, y+s, 0.008)
                    glVertex3f(x, y+s, 0.008)
        glEnd()
        
        # Signal strength layer
        glBegin(GL_QUADS)
        for gx in range(0, FLOOR_X, 2):
            for gy in range(0, FLOOR_Y, 2):
                val = sig_map[gx, gy]
                if val > 0.03:
                    x, y = gx * FLOOR_RES, gy * FLOOR_RES
                    s = FLOOR_RES * 2
                    
                    r = min(1, val * 1.8)
                    g = min(1, val * 1.0)
                    b = 0.2
                    a = val * 0.45
                    
                    glColor4f(r, g, b, a)
                    glVertex3f(x, y, 0.012)
                    glVertex3f(x+s, y, 0.012)
                    glVertex3f(x+s, y+s, 0.012)
                    glVertex3f(x, y+s, 0.012)
        glEnd()
        
        # Shadow zone indicators (areas with poor coverage)
        self._render_shadow_indicators()
        
        glEnable(GL_LIGHTING)
    
    def _render_shadow_indicators(self):
        """Render areas that may be in RF shadow."""
        cov_map = self.engine.coverage_quality
        wall_prob = self.engine.wall_probability
        
        glColor4f(0.3, 0.1, 0.1, 0.15)
        glBegin(GL_QUADS)
        for gx in range(0, FLOOR_X, 4):
            for gy in range(0, FLOOR_Y, 4):
                # Low coverage + near wall = potential shadow
                cov = cov_map[gx, gy]
                wall = wall_prob[gx, gy] if gx < FLOOR_X and gy < FLOOR_Y else 0
                
                if cov < 0.3 and wall < 0.3:  # Low coverage, not a wall itself
                    x, y = gx * FLOOR_RES, gy * FLOOR_RES
                    s = FLOOR_RES * 4
                    
                    glVertex3f(x, y, 0.006)
                    glVertex3f(x+s, y, 0.006)
                    glVertex3f(x+s, y+s, 0.006)
                    glVertex3f(x, y+s, 0.006)
        glEnd()
    
    def _render_occupancy_heatmap(self):
        """Render historical occupancy heatmap showing where people have been."""
        glDisable(GL_LIGHTING)
        
        occ_map = self.engine.occupancy_history
        max_occ = np.max(occ_map)
        if max_occ < 0.001:
            glEnable(GL_LIGHTING)
            return
        
        # Normalize occupancy
        occ_norm = occ_map / max_occ
        
        glBegin(GL_QUADS)
        for gx in range(0, FLOOR_X, 2):
            for gy in range(0, FLOOR_Y, 2):
                val = occ_norm[gx, gy]
                if val > 0.02:
                    x, y = gx * FLOOR_RES, gy * FLOOR_RES
                    s = FLOOR_RES * 2
                    
                    # Purple/magenta color scheme for occupancy history
                    # More visited = brighter and more saturated
                    r = 0.6 * val + 0.2
                    g = 0.1 * val
                    b = 0.8 * val + 0.2
                    a = val * 0.5
                    
                    glColor4f(r, g, b, a)
                    glVertex3f(x, y, 0.014)
                    glVertex3f(x+s, y, 0.014)
                    glVertex3f(x+s, y+s, 0.014)
                    glVertex3f(x, y+s, 0.014)
        glEnd()
        
        # Hotspot markers for highest occupancy areas
        hotspots = []
        for gx in range(2, FLOOR_X-2, 4):
            for gy in range(2, FLOOR_Y-2, 4):
                val = occ_norm[gx, gy]
                if val > 0.6:
                    hotspots.append((gx * FLOOR_RES, gy * FLOOR_RES, val))
        
        # Render hotspot indicators
        glPointSize(8)
        glBegin(GL_POINTS)
        for hx, hy, intensity in hotspots:
            glColor4f(1.0, 0.3, 0.8, intensity * 0.8)
            glVertex3f(hx, hy, 0.02)
        glEnd()
        
        glEnable(GL_LIGHTING)
    
    def _render_motion_vectors(self):
        """Render motion vector field showing average movement directions."""
        glDisable(GL_LIGHTING)
        
        motion_map = self.engine.motion_vectors
        
        # Draw motion arrows
        glLineWidth(2)
        glBegin(GL_LINES)
        
        for gx in range(2, FLOOR_X-2, 6):
            for gy in range(2, FLOOR_Y-2, 6):
                vx, vy = motion_map[gx, gy]
                speed = math.sqrt(vx*vx + vy*vy)
                
                if speed > 0.01:
                    x, y = gx * FLOOR_RES, gy * FLOOR_RES
                    
                    # Normalize and scale for visualization
                    scale = min(0.5, speed * 2)
                    nx, ny = vx / speed * scale, vy / speed * scale
                    
                    # Color by speed: blue (slow) to red (fast)
                    r = min(1, speed * 3)
                    g = 0.3
                    b = max(0, 1 - speed * 2)
                    
                    glColor4f(r, g, b, 0.7)
                    glVertex3f(x, y, 0.025)
                    glVertex3f(x + nx, y + ny, 0.025)
                    
                    # Arrowhead
                    # Perpendicular direction
                    px, py = -ny * 0.15, nx * 0.15
                    tip_x, tip_y = x + nx, y + ny
                    
                    glVertex3f(tip_x, tip_y, 0.025)
                    glVertex3f(tip_x - nx*0.3 + px, tip_y - ny*0.3 + py, 0.025)
                    glVertex3f(tip_x, tip_y, 0.025)
                    glVertex3f(tip_x - nx*0.3 - px, tip_y - ny*0.3 - py, 0.025)
        
        glEnd()
        glEnable(GL_LIGHTING)
    
    def _render_anomalies(self):
        """Render signal anomaly indicators (sudden changes = movement)."""
        glDisable(GL_LIGHTING)
        
        anomalies = self.engine.anomaly_events
        if not anomalies:
            return
        
        # Render pulsing anomaly markers
        t = time.time()
        pulse = 0.5 + 0.5 * math.sin(t * 6)
        
        for x, y, z, intensity in anomalies:
            # Anomaly glow effect - expanding rings
            size = 0.2 + intensity * 0.4 + pulse * 0.1
            
            # Yellow-orange warning color
            r = 1.0
            g = 0.6 - intensity * 0.3
            b = 0.1
            a = intensity * 0.7 * (0.6 + pulse * 0.4)
            
            # Inner marker
            glColor4f(r, g, b, a)
            glBegin(GL_TRIANGLE_FAN)
            glVertex3f(x, y, z)
            for i in range(17):
                angle = i * math.pi * 2 / 16
                glVertex3f(x + math.cos(angle) * size, 
                          y + math.sin(angle) * size, z)
            glEnd()
            
            # Outer ring
            glLineWidth(2)
            glColor4f(r, g * 0.8, b, a * 0.5)
            glBegin(GL_LINE_LOOP)
            for i in range(24):
                angle = i * math.pi * 2 / 24
                ring_size = size * 1.5 + pulse * 0.15
                glVertex3f(x + math.cos(angle) * ring_size, 
                          y + math.sin(angle) * ring_size, z)
            glEnd()
            
            # Vertical line to floor
            glColor4f(r, g, b, a * 0.3)
            glBegin(GL_LINES)
            glVertex3f(x, y, z)
            glVertex3f(x, y, 0.01)
            glEnd()
        
        glEnable(GL_LIGHTING)
    
    def _render_zones(self):
        """Render zone boundaries and labels."""
        glDisable(GL_LIGHTING)
        
        zone_map = self.engine.zone_map
        max_zone = np.max(zone_map)
        if max_zone == 0:
            glEnable(GL_LIGHTING)
            return
        
        # Color each zone differently
        zone_colors = [
            (0.2, 0.4, 0.8),   # Blue
            (0.8, 0.4, 0.2),   # Orange
            (0.3, 0.7, 0.3),   # Green
            (0.7, 0.3, 0.7),   # Purple
            (0.7, 0.7, 0.2),   # Yellow
            (0.2, 0.7, 0.7),   # Cyan
            (0.8, 0.2, 0.4),   # Pink
            (0.5, 0.5, 0.5),   # Gray
        ]
        
        glBegin(GL_QUADS)
        for gx in range(0, FLOOR_X, 3):
            for gy in range(0, FLOOR_Y, 3):
                zone_id = zone_map[gx, gy]
                if zone_id > 0:
                    color = zone_colors[(zone_id - 1) % len(zone_colors)]
                    
                    # Activity level affects brightness
                    activity = self.engine.zone_activity.get(zone_id, 0)
                    brightness = 0.5 + min(0.5, activity * 0.1)
                    
                    x, y = gx * FLOOR_RES, gy * FLOOR_RES
                    s = FLOOR_RES * 3
                    
                    glColor4f(color[0] * brightness, color[1] * brightness, 
                             color[2] * brightness, 0.1)
                    glVertex3f(x, y, 0.003)
                    glVertex3f(x+s, y, 0.003)
                    glVertex3f(x+s, y+s, 0.003)
                    glVertex3f(x, y+s, 0.003)
        glEnd()
        
        # Draw zone boundaries
        glLineWidth(2)
        for gx in range(1, FLOOR_X):
            for gy in range(1, FLOOR_Y):
                curr = zone_map[gx, gy]
                left = zone_map[gx-1, gy]
                below = zone_map[gx, gy-1]
                
                # Draw boundary line if adjacent zones differ
                if curr != left and curr > 0 and left > 0:
                    x, y = gx * FLOOR_RES, gy * FLOOR_RES
                    glColor4f(1, 1, 1, 0.4)
                    glBegin(GL_LINES)
                    glVertex3f(x, y, 0.01)
                    glVertex3f(x, y + FLOOR_RES, 0.01)
                    glEnd()
                
                if curr != below and curr > 0 and below > 0:
                    x, y = gx * FLOOR_RES, gy * FLOOR_RES
                    glColor4f(1, 1, 1, 0.4)
                    glBegin(GL_LINES)
                    glVertex3f(x, y, 0.01)
                    glVertex3f(x + FLOOR_RES, y, 0.01)
                    glEnd()
        
        glEnable(GL_LIGHTING)
    
    def _render_person_trails(self):
        """Render trails for tracked persons."""
        glDisable(GL_LIGHTING)
        
        now = time.time()
        
        # Person colors (cycle through for different persons)
        trail_colors = [
            (1.0, 0.3, 0.3),  # Red
            (0.3, 1.0, 0.3),  # Green
            (0.3, 0.3, 1.0),  # Blue
            (1.0, 1.0, 0.3),  # Yellow
            (1.0, 0.3, 1.0),  # Magenta
            (0.3, 1.0, 1.0),  # Cyan
        ]
        
        for i, (mac, track) in enumerate(self.engine.person_tracks.items()):
            if len(track) < 2:
                continue
            
            color = trail_colors[i % len(trail_colors)]
            
            # Draw trail as line strip with fading
            glLineWidth(3)
            glBegin(GL_LINE_STRIP)
            
            for j, (x, y, z, t) in enumerate(track):
                # Older points are more transparent
                age = now - t
                if age > 60:  # Skip points older than 60 seconds
                    continue
                
                # Fade from full alpha to 0.1 over 30 seconds
                alpha = max(0.1, 1.0 - age / 30.0)
                
                # Also fade along track length
                pos_fade = j / len(track)
                alpha *= pos_fade * 0.8 + 0.2
                
                glColor4f(color[0], color[1], color[2], alpha)
                glVertex3f(x, y, z * 0.5)  # Slightly lower than entity height
            
            glEnd()
            
            # Draw dot at most recent position
            if track:
                x, y, z, t = track[-1]
                if now - t < 5:  # Recent position
                    glPointSize(10)
                    glColor4f(color[0], color[1], color[2], 0.9)
                    glBegin(GL_POINTS)
                    glVertex3f(x, y, z * 0.5)
                    glEnd()
                    
                    # Draw predicted future position
                    pred = self.engine.predict_future_position(mac, 2.0)
                    if pred is not None:
                        # Dashed line to prediction
                        glLineWidth(2)
                        glColor4f(color[0], color[1], color[2], 0.4)
                        
                        # Draw dashed line
                        steps = 8
                        for s in range(0, steps, 2):
                            t0, t1 = s / steps, (s + 1) / steps
                            px0 = x + (pred[0] - x) * t0
                            py0 = y + (pred[1] - y) * t0
                            px1 = x + (pred[0] - x) * t1
                            py1 = y + (pred[1] - y) * t1
                            
                            glBegin(GL_LINES)
                            glVertex3f(px0, py0, z * 0.5)
                            glVertex3f(px1, py1, z * 0.5)
                            glEnd()
                        
                        # Ghost marker at prediction
                        glColor4f(color[0], color[1], color[2], 0.25)
                        glBegin(GL_TRIANGLE_FAN)
                        glVertex3f(pred[0], pred[1], pred[2] * 0.5)
                        for a in range(17):
                            angle = a * math.pi * 2 / 16
                            glVertex3f(pred[0] + math.cos(angle) * 0.15,
                                      pred[1] + math.sin(angle) * 0.15,
                                      pred[2] * 0.5)
                        glEnd()
        
        glEnable(GL_LIGHTING)
    
    def _render_walls(self):
        """Render detected walls as 3D structures with material indicators."""
        glEnable(GL_LIGHTING)

        # Material color palette
        # 0=unknown, 1=drywall, 2=concrete, 3=glass, 4=metal
        material_colors = {
            0: (0.12, 0.55, 0.65),   # Cyan - unknown
            1: (0.8, 0.75, 0.65),    # Beige - drywall
            2: (0.5, 0.5, 0.55),     # Gray - concrete
            3: (0.4, 0.7, 0.9),      # Light blue - glass
            4: (0.6, 0.6, 0.7),      # Silver - metal
        }

        # Render wall voxels (probability grid)
        wall_voxels = self.engine.get_wall_voxels(threshold=0.28)
        if len(wall_voxels) > 3500:
            wall_voxels.sort(key=lambda v: v[2], reverse=True)
            wall_voxels = wall_voxels[:3500]
        
        for gx, gy, prob in wall_voxels:
            x, y = gx * FLOOR_RES, gy * FLOOR_RES
            
            alpha = min(0.75, prob * 1.2)
            height = ROOM_HEIGHT * min(1.0, prob * 1.2 + 0.25)
            
            # Get material at this cell
            mat = self.engine.material_map[gx, gy] if hasattr(self.engine, 'material_map') else 0
            mat_conf = self.engine.material_confidence[gx, gy] if hasattr(self.engine, 'material_confidence') else 0
            
            # Blend between unknown and inferred material color
            base_color = material_colors.get(0)
            mat_color = material_colors.get(mat, base_color)
            blend = mat_conf
            r = base_color[0] * (1 - blend) + mat_color[0] * blend
            g = base_color[1] * (1 - blend) + mat_color[1] * blend
            b = base_color[2] * (1 - blend) + mat_color[2] * blend
            
            glColor4f(r, g, b, alpha)
            
            s = FLOOR_RES
            self._draw_wall_box(x, y, 0, s, s, height)
        
        # Render reflection points
        self._render_reflection_points()
        
        # Render extracted wall line segments (cleaner walls)
        self._render_wall_lines()
    
    def _render_reflection_points(self):
        """Render detected reflection/multipath points."""
        glDisable(GL_LIGHTING)
        
        now = time.time()
        for rx, ry, intensity, t in self.engine.reflection_points:
            age = now - t
            if age > 30:
                continue
            
            # Fade with age
            alpha = intensity * (1 - age / 30) * 0.6
            
            # Pulsing effect
            pulse = 1.0 + 0.2 * math.sin(self.time * 8 - age)
            
            glColor4f(1.0, 0.6, 0.2, alpha)
            
            # Draw as expanding ring
            ring_r = 0.1 + age * 0.02
            glLineWidth(2)
            glBegin(GL_LINE_LOOP)
            for i in range(16):
                ang = i * math.pi * 2 / 16
                glVertex3f(rx + ring_r * math.cos(ang) * pulse, 
                          ry + ring_r * math.sin(ang) * pulse, 
                          0.05)
            glEnd()
            
            # Inner dot
            glPointSize(4)
            glBegin(GL_POINTS)
            glVertex3f(rx, ry, 0.05)
            glEnd()
        
        glEnable(GL_LIGHTING)
    
    def _render_wall_lines(self):
        """Render clean wall line segments extracted from probability grid."""
        glEnable(GL_LIGHTING)
        
        for start, end, confidence in self.engine.wall_lines:
            if confidence < 0.3:
                continue
            
            # Wall thickness based on confidence
            thickness = 0.08 + confidence * 0.06
            
            # Direction vector (2D)
            dx = end[0] - start[0]
            dy = end[1] - start[1]
            length = math.sqrt(dx*dx + dy*dy)
            if length < 0.1:
                continue
            
            # Perpendicular for wall thickness
            px, py = -dy/length * thickness, dx/length * thickness
            
            # Wall color - brighter for confident walls
            alpha = min(0.95, confidence * 1.4)
            glColor4f(0.2, 0.75, 0.85, alpha)
            
            # Draw wall as a thick quad
            h = ROOM_HEIGHT * min(1.0, confidence + 0.4)
            
            glBegin(GL_QUADS)
            # Front face
            glNormal3f(px, py, 0)
            glVertex3f(start[0] + px, start[1] + py, 0)
            glVertex3f(end[0] + px, end[1] + py, 0)
            glVertex3f(end[0] + px, end[1] + py, h)
            glVertex3f(start[0] + px, start[1] + py, h)
            
            # Back face
            glNormal3f(-px, -py, 0)
            glVertex3f(start[0] - px, start[1] - py, 0)
            glVertex3f(start[0] - px, start[1] - py, h)
            glVertex3f(end[0] - px, end[1] - py, h)
            glVertex3f(end[0] - px, end[1] - py, 0)
            
            # Top face
            glNormal3f(0, 0, 1)
            glVertex3f(start[0] - px, start[1] - py, h)
            glVertex3f(start[0] + px, start[1] + py, h)
            glVertex3f(end[0] + px, end[1] + py, h)
            glVertex3f(end[0] - px, end[1] - py, h)
            
            # End caps
            glNormal3f(-dx/length, -dy/length, 0)
            glVertex3f(start[0] - px, start[1] - py, 0)
            glVertex3f(start[0] + px, start[1] + py, 0)
            glVertex3f(start[0] + px, start[1] + py, h)
            glVertex3f(start[0] - px, start[1] - py, h)
            
            glNormal3f(dx/length, dy/length, 0)
            glVertex3f(end[0] - px, end[1] - py, 0)
            glVertex3f(end[0] - px, end[1] - py, h)
            glVertex3f(end[0] + px, end[1] + py, h)
            glVertex3f(end[0] + px, end[1] + py, 0)
            glEnd()
            
            # Top edge glow
            glDisable(GL_LIGHTING)
            glColor4f(0.4, 1.0, 1.0, alpha * 0.8)
            glLineWidth(2)
            glBegin(GL_LINES)
            glVertex3f(start[0], start[1], h)
            glVertex3f(end[0], end[1], h)
            glEnd()
            glEnable(GL_LIGHTING)
        
    def _draw_wall_box(self, x, y, z, sx, sy, sz):
        """Draw a wall box with proper normals."""
        glBegin(GL_QUADS)
        
        # Front (Y-)
        glNormal3f(0, -1, 0)
        glVertex3f(x, y, z)
        glVertex3f(x+sx, y, z)
        glVertex3f(x+sx, y, z+sz)
        glVertex3f(x, y, z+sz)
        
        # Back (Y+)
        glNormal3f(0, 1, 0)
        glVertex3f(x, y+sy, z)
        glVertex3f(x, y+sy, z+sz)
        glVertex3f(x+sx, y+sy, z+sz)
        glVertex3f(x+sx, y+sy, z)
        
        # Left (X-)
        glNormal3f(-1, 0, 0)
        glVertex3f(x, y, z)
        glVertex3f(x, y, z+sz)
        glVertex3f(x, y+sy, z+sz)
        glVertex3f(x, y+sy, z)
        
        # Right (X+)
        glNormal3f(1, 0, 0)
        glVertex3f(x+sx, y, z)
        glVertex3f(x+sx, y+sy, z)
        glVertex3f(x+sx, y+sy, z+sz)
        glVertex3f(x+sx, y, z+sz)
        
        # Top (Z+)
        glNormal3f(0, 0, 1)
        glVertex3f(x, y, z+sz)
        glVertex3f(x+sx, y, z+sz)
        glVertex3f(x+sx, y+sy, z+sz)
        glVertex3f(x, y+sy, z+sz)
        
        glEnd()
        
        # Edge highlight
        glDisable(GL_LIGHTING)
        glColor4f(0.3, 0.9, 1.0, 0.6)
        glLineWidth(1)
        glBegin(GL_LINE_LOOP)
        glVertex3f(x, y, z+sz)
        glVertex3f(x+sx, y, z+sz)
        glVertex3f(x+sx, y+sy, z+sz)
        glVertex3f(x, y+sy, z+sz)
        glEnd()
        glEnable(GL_LIGHTING)
    
    def _render_sensors(self):
        """Render sensor nodes with effects and Fresnel zone."""
        sensors = [
            (PRIMARY_POS, (0, 1, 0.5), "P"),
            (REMOTE_POS, (0, 0.7, 1), "R")
        ]
        
        # Fresnel zone between sensors (RF sensing region)
        self._render_fresnel_zone()
        
        for pos, color, name in sensors:
            x, y, z = pos
            
            glEnable(GL_LIGHTING)
            glColor4f(*color, 1)
            
            glPushMatrix()
            glTranslatef(x, y, 0)
            q = gluNewQuadric()
            gluCylinder(q, 0.14, 0.12, z+0.12, 16, 4)
            glTranslatef(0, 0, z+0.12)
            gluSphere(q, 0.12, 16, 16)
            gluDeleteQuadric(q)
            glPopMatrix()
            
            # Signal coverage visualization
            self._render_coverage_cone(x, y, z, color, name)
            
            # Scan pulses
            glDisable(GL_LIGHTING)
            for i in range(6):
                phase = (self.time * 1.5 + i * 0.7) % 4
                radius = 0.4 + phase * 1.0
                alpha = max(0, 0.35 - phase * 0.09)
                
                glColor4f(*color, alpha)
                glLineWidth(2)
                glBegin(GL_LINE_LOOP)
                for a in range(40):
                    ang = a * math.pi * 2 / 40
                    glVertex3f(x + math.cos(ang)*radius, y + math.sin(ang)*radius, z)
                glEnd()
            
            # Scanning beam
            beam_ang = math.radians(self.scan_angle + (180 if name == "R" else 0))
            beam_len = 7
            
            glBegin(GL_TRIANGLES)
            glColor4f(*color, 0.18)
            glVertex3f(x, y, z)
            glColor4f(*color, 0)
            glVertex3f(x + math.cos(beam_ang-0.15)*beam_len, y + math.sin(beam_ang-0.15)*beam_len, z)
            glVertex3f(x + math.cos(beam_ang+0.15)*beam_len, y + math.sin(beam_ang+0.15)*beam_len, z)
            glEnd()
            
            glEnable(GL_LIGHTING)
    
    def _render_fresnel_zone(self):
        """Render Fresnel zone between the two sensors."""
        p1 = PRIMARY_POS
        p2 = REMOTE_POS
        
        # Distance between sensors
        dx = p2[0] - p1[0]
        dy = p2[1] - p1[1]
        dist = math.sqrt(dx*dx + dy*dy)
        
        if dist < 0.5:
            return
        
        # Fresnel radius at wavelength 12.5cm (2.4GHz)
        wavelength = 0.125  # 2.4 GHz wavelength in meters
        fresnel_r = math.sqrt(wavelength * dist / 2) * 0.6  # First Fresnel zone
        
        glDisable(GL_LIGHTING)
        
        # Draw elliptical Fresnel zone on floor
        segments = 40
        center_x = (p1[0] + p2[0]) / 2
        center_y = (p1[1] + p2[1]) / 2
        z_height = max(p1[2], p2[2])
        
        # Animate
        pulse = (math.sin(self.time * 2) + 1) * 0.5 * 0.15
        
        # Draw filled zone
        glColor4f(0.2, 0.7, 0.9, 0.05 + pulse * 0.03)
        glBegin(GL_POLYGON)
        for i in range(segments):
            angle = i * 2 * math.pi / segments
            # Ellipse aligned with sensor axis
            local_x = math.cos(angle) * dist / 2 * 1.1
            local_y = math.sin(angle) * fresnel_r * 1.5
            
            # Rotate to sensor axis
            axis_ang = math.atan2(dy, dx)
            rx = local_x * math.cos(axis_ang) - local_y * math.sin(axis_ang)
            ry = local_x * math.sin(axis_ang) + local_y * math.cos(axis_ang)
            
            glVertex3f(center_x + rx, center_y + ry, 0.015)
        glEnd()
        
        # Outline
        glColor4f(0.3, 0.8, 1.0, 0.25 + pulse * 0.1)
        glLineWidth(2)
        glBegin(GL_LINE_LOOP)
        for i in range(segments):
            angle = i * 2 * math.pi / segments
            local_x = math.cos(angle) * dist / 2 * 1.1
            local_y = math.sin(angle) * fresnel_r * 1.5
            axis_ang = math.atan2(dy, dx)
            rx = local_x * math.cos(axis_ang) - local_y * math.sin(axis_ang)
            ry = local_x * math.sin(axis_ang) + local_y * math.cos(axis_ang)
            glVertex3f(center_x + rx, center_y + ry, 0.015)
        glEnd()
        
        # Cross-link line between sensors
        glColor4f(0.4, 0.9, 1.0, 0.3)
        glLineWidth(1)
        glEnable(GL_LINE_STIPPLE)
        glLineStipple(1, 0x00FF)
        glBegin(GL_LINES)
        glVertex3f(p1[0], p1[1], p1[2])
        glVertex3f(p2[0], p2[1], p2[2])
        glEnd()
        glDisable(GL_LINE_STIPPLE)
        
        glEnable(GL_LIGHTING)
    
    def _render_coverage_cone(self, x, y, z, color, name):
        """Render signal coverage pattern for sensor."""
        glDisable(GL_LIGHTING)
        
        # Coverage visualization - gradient from sensor outward
        max_range = 6.0
        
        for ring in range(5):
            r = (ring + 1) * max_range / 5
            alpha = 0.08 * (1 - ring / 5)
            
            glColor4f(*color, alpha)
            glBegin(GL_LINE_LOOP)
            for a in range(32):
                ang = a * math.pi * 2 / 32
                glVertex3f(x + math.cos(ang)*r, y + math.sin(ang)*r, 0.01)
            glEnd()
        
        glEnable(GL_LIGHTING)
    
    def _render_entities(self):
        """Render tracked entities with predictive paths."""
        now = time.time()
        
        for entity in self.engine.get_active_entities():
            age = now - entity.last_seen
            alpha = max(0.3, 1 - age/10)
            pos = entity.position
            x, y, z = pos
            
            # Trail (past movement)
            if len(entity.trail) > 2:
                glDisable(GL_LIGHTING)
                glLineWidth(3)
                glBegin(GL_LINE_STRIP)
                for tx, ty, tz, tt in entity.trail:
                    ta = max(0, alpha * 0.55 * (1 - (now-tt)/7))
                    glColor4f(*entity.color, ta)
                    glVertex3f(tx, ty, 0.02)
                glEnd()
                glEnable(GL_LIGHTING)
            
            # Predictive path (future movement estimate)
            if entity.is_moving and entity.speed > 0.15:
                vel = entity.velocity
                glDisable(GL_LIGHTING)
                glLineWidth(2)
                glEnable(GL_LINE_STIPPLE)
                glLineStipple(2, 0xAAAA)
                glBegin(GL_LINE_STRIP)
                for t in range(8):
                    future_t = t * 0.3
                    fx = x + vel[0] * future_t
                    fy = y + vel[1] * future_t
                    # Clamp to room
                    fx = max(0.2, min(ROOM_WIDTH-0.2, fx))
                    fy = max(0.2, min(ROOM_DEPTH-0.2, fy))
                    pa = alpha * 0.5 * (1 - t/8)
                    glColor4f(1.0, 0.6, 0.2, pa)
                    glVertex3f(fx, fy, 0.03)
                glEnd()
                glDisable(GL_LINE_STIPPLE)
                glEnable(GL_LIGHTING)
            
            # Shadow
            glDisable(GL_LIGHTING)
            glColor4f(0, 0, 0, 0.2*alpha)
            glBegin(GL_POLYGON)
            for i in range(20):
                a = i*math.pi*2/20
                glVertex3f(x+math.cos(a)*0.3, y+math.sin(a)*0.3, 0.01)
            glEnd()
            
            # Vertical line
            glColor4f(*entity.color, alpha*0.35)
            glLineWidth(1)
            glBegin(GL_LINES)
            glVertex3f(x, y, 0.02)
            glVertex3f(x, y, z)
            glEnd()
            
            # Distance rings (radar style)
            if entity.entity_type == "person":
                ring_alpha = 0.15 * alpha * (0.5 + 0.5 * math.sin(self.time * 3))
                glColor4f(*entity.color, ring_alpha)
                glLineWidth(1)
                for r in [0.5, 1.0]:
                    glBegin(GL_LINE_LOOP)
                    for i in range(24):
                        a = i * math.pi * 2 / 24
                        glVertex3f(x + math.cos(a)*r, y + math.sin(a)*r, 0.015)
                    glEnd()
            
            glEnable(GL_LIGHTING)
            
            # Entity body
            glPushMatrix()
            glTranslatef(x, y, z)
            glColor4f(*entity.color, alpha)
            
            q = gluNewQuadric()
            
            if entity.entity_type == "person":
                pulse = 1 + 0.1*math.sin(self.time*7) if entity.is_moving else 1
                
                # Heat signature gradient effect
                conf = entity.confidence_score if entity.confidence_score else 0.5
                heat_intensity = 0.7 + conf * 0.3
                
                # Core body heat (brighter center)
                core_color = (
                    min(1.0, entity.color[0] + 0.3 * heat_intensity),
                    entity.color[1] * 0.8,
                    entity.color[2] * 0.5
                )
                glColor4f(*core_color, alpha * heat_intensity)
                
                # Body
                glPushMatrix()
                glScalef(1, 1, 1.5)
                gluSphere(q, 0.2*pulse, 16, 16)
                glPopMatrix()
                
                # Heat glow around body (outer layer)
                glColor4f(entity.color[0], entity.color[1]*0.5, entity.color[2]*0.3, alpha * 0.25)
                glPushMatrix()
                glScalef(1, 1, 1.5)
                gluSphere(q, 0.28*pulse, 12, 12)
                glPopMatrix()
                
                # Head with heat signature
                glColor4f(*core_color, alpha * heat_intensity)
                glPushMatrix()
                glTranslatef(0, 0, 0.42)
                gluSphere(q, 0.12*pulse, 12, 12)
                glPopMatrix()
                
                # Head glow
                glColor4f(entity.color[0], entity.color[1]*0.5, 0.2, alpha * 0.2)
                glPushMatrix()
                glTranslatef(0, 0, 0.42)
                gluSphere(q, 0.16*pulse, 10, 10)
                glPopMatrix()
                glPushMatrix()
                glTranslatef(0, 0, 0.42)
                gluSphere(q, 0.12*pulse, 12, 12)
                glPopMatrix()
                
                # Movement arrow
                if entity.is_moving:
                    vel = entity.velocity
                    spd = entity.speed
                    if spd > 0.1:
                        glDisable(GL_LIGHTING)
                        glColor4f(1, 0.3, 0.2, alpha*0.9)
                        glLineWidth(3)
                        glBegin(GL_LINES)
                        glVertex3f(0, 0, 0.2)
                        glVertex3f(vel[0]/spd*0.8, vel[1]/spd*0.8, 0.2)
                        glEnd()
                        glEnable(GL_LIGHTING)
                
                # Approach direction indicator (RSSI-based Doppler)
                if entity.approach_direction and entity.approach_direction != "stationary":
                    glDisable(GL_LIGHTING)
                    
                    # Color by approach direction
                    dir_colors = {
                        "toward_primary": (0.2, 1.0, 0.4),    # Green - approaching primary
                        "away_from_primary": (1.0, 0.4, 0.2), # Orange - moving away
                        "toward_remote": (0.2, 0.6, 1.0),     # Blue - approaching remote
                        "away_from_remote": (1.0, 0.2, 0.6),  # Magenta - away from remote
                        "lateral": (1.0, 1.0, 0.3),           # Yellow - sideways motion
                        "unknown": (0.6, 0.6, 0.6),           # Gray
                    }
                    dc = dir_colors.get(entity.approach_direction, (0.6, 0.6, 0.6))
                    
                    # Draw approach direction ring
                    rssi_v = abs(entity.rssi_velocity) if entity.rssi_velocity else 0
                    ring_intensity = min(1.0, rssi_v / 5.0)  # Scale by velocity
                    
                    glColor4f(dc[0], dc[1], dc[2], alpha * 0.6 * ring_intensity)
                    glLineWidth(2)
                    
                    # Draw pulsing ring at feet
                    ring_phase = (self.time * 3) % 1.0
                    ring_r = 0.2 + ring_phase * 0.3
                    
                    glBegin(GL_LINE_LOOP)
                    for i in range(24):
                        ang = i * 3.14159 * 2 / 24
                        glVertex3f(ring_r * np.cos(ang), ring_r * np.sin(ang), 0.02)
                    glEnd()
                    
                    # Draw directional arrow from center toward sensor
                    arrow_len = 0.4
                    if "primary" in entity.approach_direction:
                        # Arrow toward/away from primary sensor
                        dx = PRIMARY_POS[0] - entity.position[0]
                        dy = PRIMARY_POS[1] - entity.position[1]
                    elif "remote" in entity.approach_direction:
                        # Arrow toward/away from remote sensor
                        dx = REMOTE_POS[0] - entity.position[0]
                        dy = REMOTE_POS[1] - entity.position[1]
                    else:
                        dx, dy = 1, 0  # Default lateral
                    
                    dist = np.sqrt(dx*dx + dy*dy) + 0.001
                    dx, dy = dx/dist, dy/dist
                    
                    if "away" in entity.approach_direction:
                        dx, dy = -dx, -dy  # Reverse for away
                    
                    glColor4f(dc[0], dc[1], dc[2], alpha * 0.85)
                    glLineWidth(3)
                    glBegin(GL_LINES)
                    glVertex3f(0, 0, 0.15)
                    glVertex3f(dx * arrow_len, dy * arrow_len, 0.15)
                    glEnd()
                    
                    # Arrowhead
                    glBegin(GL_TRIANGLES)
                    head_x, head_y = dx * arrow_len, dy * arrow_len
                    perp_x, perp_y = -dy * 0.08, dx * 0.08
                    glVertex3f(head_x + dx*0.1, head_y + dy*0.1, 0.15)
                    glVertex3f(head_x - perp_x, head_y - perp_y, 0.15)
                    glVertex3f(head_x + perp_x, head_y + perp_y, 0.15)
                    glEnd()
                    
                    glEnable(GL_LIGHTING)
                
                # Breathing indicator (gentle pulsing ring when breathing detected)
                if entity.breathing_detected:
                    glDisable(GL_LIGHTING)
                    
                    # Breathing creates a slow pulsing cyan ring
                    breath_phase = (self.time * 1.2) % (2 * math.pi)  # ~18 breaths/min
                    breath_intensity = 0.5 + 0.5 * math.sin(breath_phase)
                    
                    # Ring color - soft cyan/blue for life detection
                    glColor4f(0.3, 0.9, 1.0, alpha * 0.4 * breath_intensity)
                    glLineWidth(2)
                    
                    ring_r = 0.35 + 0.05 * math.sin(breath_phase)
                    glBegin(GL_LINE_LOOP)
                    for i in range(32):
                        ang = i * math.pi * 2 / 32
                        glVertex3f(ring_r * np.cos(ang), ring_r * np.sin(ang), 0.25)
                    glEnd()
                    
                    # Inner glow
                    glColor4f(0.2, 0.8, 0.9, alpha * 0.15 * breath_intensity)
                    glBegin(GL_POLYGON)
                    for i in range(32):
                        ang = i * math.pi * 2 / 32
                        glVertex3f(ring_r * 0.9 * np.cos(ang), ring_r * 0.9 * np.sin(ang), 0.24)
                    glEnd()
                    
                    # "BREATHING" text indicator above entity
                    # Small vertical bar pulsing
                    glColor4f(0.3, 1.0, 0.9, alpha * 0.6 * breath_intensity)
                    bar_h = 0.08 + 0.04 * math.sin(breath_phase)
                    glBegin(GL_QUADS)
                    glVertex3f(-0.02, 0, 0.7)
                    glVertex3f(0.02, 0, 0.7)
                    glVertex3f(0.02, 0, 0.7 + bar_h)
                    glVertex3f(-0.02, 0, 0.7 + bar_h)
                    glEnd()
                    
                    glEnable(GL_LIGHTING)
                        
            elif entity.entity_type == "device":
                # Cube with rotation
                rot = self.time * 20
                glRotatef(rot, 0, 0, 1)
                s = 0.12
                glBegin(GL_QUADS)
                for face in [
                    [(s,s,s), (-s,s,s), (-s,-s,s), (s,-s,s)],
                    [(s,s,-s), (s,-s,-s), (-s,-s,-s), (-s,s,-s)],
                    [(s,s,s), (s,-s,s), (s,-s,-s), (s,s,-s)],
                    [(-s,s,s), (-s,s,-s), (-s,-s,-s), (-s,-s,s)],
                    [(s,s,s), (s,s,-s), (-s,s,-s), (-s,s,s)],
                    [(s,-s,s), (-s,-s,s), (-s,-s,-s), (s,-s,-s)],
                ]:
                    for v in face:
                        glVertex3f(*v)
                glEnd()
            else:
                gluSphere(q, 0.14, 12, 12)
            
            gluDeleteQuadric(q)
            glPopMatrix()
            
            # Signal bar
            self._draw_signal_bar(x, y, z+0.6, entity.signal_strength, alpha)
            
            # Entity label
            self._draw_entity_label(x, y, z+0.75, entity, alpha)
    
    def _draw_signal_bar(self, x, y, z, strength, alpha):
        glDisable(GL_LIGHTING)
        w, h = 0.4, 0.06
        
        glPushMatrix()
        glTranslatef(x-w/2, y, z)
        
        glColor4f(0.15, 0.15, 0.15, alpha*0.6)
        glBegin(GL_QUADS)
        glVertex3f(0, 0, 0)
        glVertex3f(w, 0, 0)
        glVertex3f(w, 0, h)
        glVertex3f(0, 0, h)
        glEnd()
        
        c = (0.2, 1, 0.4) if strength > 0.6 else (1, 0.8, 0.2) if strength > 0.35 else (1, 0.3, 0.3)
        glColor4f(*c, alpha*0.85)
        glBegin(GL_QUADS)
        glVertex3f(0, 0, 0)
        glVertex3f(w*strength, 0, 0)
        glVertex3f(w*strength, 0, h)
        glVertex3f(0, 0, h)
        glEnd()
        
        glPopMatrix()
        glEnable(GL_LIGHTING)
    
    def _draw_entity_label(self, x, y, z, entity, alpha):
        """Draw entity type label above the entity."""
        glDisable(GL_LIGHTING)
        glDisable(GL_DEPTH_TEST)
        
        # Small indicator based on type
        label_size = 0.08
        if entity.entity_type == "person":
            # Triangle pointing up (person)
            glColor4f(1, 0.4, 0.4, alpha * 0.8)
            glBegin(GL_TRIANGLES)
            glVertex3f(x, y, z + label_size)
            glVertex3f(x - label_size*0.6, y, z - label_size*0.3)
            glVertex3f(x + label_size*0.6, y, z - label_size*0.3)
            glEnd()
        elif entity.entity_type == "device":
            # Diamond (device)
            glColor4f(0.4, 0.8, 1, alpha * 0.8)
            glBegin(GL_QUADS)
            glVertex3f(x, y, z + label_size)
            glVertex3f(x - label_size*0.5, y, z)
            glVertex3f(x, y, z - label_size)
            glVertex3f(x + label_size*0.5, y, z)
            glEnd()
        elif entity.entity_type == "infrastructure":
            # Square (infrastructure/AP)
            glColor4f(0.3, 0.3, 0.9, alpha * 0.8)
            glBegin(GL_QUADS)
            glVertex3f(x - label_size*0.5, y, z - label_size*0.5)
            glVertex3f(x + label_size*0.5, y, z - label_size*0.5)
            glVertex3f(x + label_size*0.5, y, z + label_size*0.5)
            glVertex3f(x - label_size*0.5, y, z + label_size*0.5)
            glEnd()
        
        # Device type badge (small indicator)
        if entity.device_type > 0:
            badge_x = x + 0.2
            badge_z = z + 0.05
            badge_r = 0.04
            
            # Color by device type
            dev_colors = {
                1: (0.2, 0.9, 0.3),   # smartphone - green
                2: (0.4, 0.4, 0.9),   # laptop - blue
                3: (0.9, 0.6, 0.2),   # iot - orange
                4: (0.2, 0.3, 0.8),   # infrastructure - dark blue
                5: (0.9, 0.3, 0.9),   # wearable - magenta
            }
            dc = dev_colors.get(entity.device_type, (0.5, 0.5, 0.5))
            
            glColor4f(*dc, alpha * 0.9)
            glBegin(GL_POLYGON)
            for i in range(12):
                ang = i * math.pi * 2 / 12
                glVertex3f(badge_x + badge_r * math.cos(ang), y, badge_z + badge_r * math.sin(ang))
            glEnd()
        
        # Speed indicator for moving entities
        if entity.is_moving:
            spd = entity.speed
            spd_str = f"{spd:.1f}m/s"
            # Draw speed as small bar
            bar_w = min(0.4, spd * 0.3)
            glColor4f(1, 0.6, 0.2, alpha * 0.7)
            glBegin(GL_QUADS)
            glVertex3f(x - 0.2, y, z + 0.12)
            glVertex3f(x - 0.2 + bar_w, y, z + 0.12)
            glVertex3f(x - 0.2 + bar_w, y, z + 0.15)
            glVertex3f(x - 0.2, y, z + 0.15)
            glEnd()
        
        # Confidence score indicator (ring fill)
        conf = entity.confidence_score if entity.confidence_score else 0.5
        ring_segs = int(conf * 12)  # 0-12 segments based on confidence
        if ring_segs > 0:
            glColor4f(0.3, 1.0, 0.5, alpha * 0.5)
            glLineWidth(2)
            glBegin(GL_LINE_STRIP)
            for i in range(ring_segs + 1):
                ang = -1.57 + i * 3.14159 / 6  # Arc from top
                rx = x + 0.25 * np.cos(ang)
                rz = z + 0.25 * np.sin(ang)
                glVertex3f(rx, y, rz)
            glEnd()
        
        # Dwell time indicator (for stationary entities)
        dwell = entity.dwell_time if entity.dwell_time else 0
        if dwell > 5 and not entity.is_moving:  # Show if dwelling > 5 seconds
            # Draw clock-like indicator
            dwell_fill = min(1.0, dwell / 60.0)  # Fill up over 60 seconds
            glColor4f(0.8, 0.5, 1.0, alpha * 0.6)
            glBegin(GL_TRIANGLE_FAN)
            glVertex3f(x + 0.35, y, z)
            for i in range(int(dwell_fill * 12) + 1):
                ang = -1.57 + i * 3.14159 * 2 / 12
                glVertex3f(x + 0.35 + 0.06 * np.cos(ang), y, z + 0.06 * np.sin(ang))
            glEnd()
            
            # Dwell ring outline
            glColor4f(0.6, 0.3, 0.8, alpha * 0.4)
            glLineWidth(1)
            glBegin(GL_LINE_LOOP)
            for i in range(12):
                ang = i * 3.14159 * 2 / 12
                glVertex3f(x + 0.35 + 0.07 * np.cos(ang), y, z + 0.07 * np.sin(ang))
            glEnd()
        
        # Zone indicator
        if entity.last_zone:
            zone_colors = {
                "entrance": (0.2, 1.0, 0.4),
                "living": (0.4, 0.8, 1.0),
                "kitchen": (1.0, 0.8, 0.3),
                "hallway": (0.8, 0.4, 1.0),
                "bedroom": (0.3, 0.5, 1.0),
                "bathroom": (0.3, 1.0, 0.8),
            }
            zc = zone_colors.get(entity.last_zone, (0.5, 0.5, 0.5))
            
            # Small zone dot
            glColor4f(*zc, alpha * 0.7)
            glPointSize(6)
            glBegin(GL_POINTS)
            glVertex3f(x - 0.35, y, z)
            glEnd()
        
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_LIGHTING)
    
    def _render_connections(self):
        """Render connection lines to entities."""
        glDisable(GL_LIGHTING)
        
        for entity in self.engine.get_active_entities():
            if time.time() - entity.last_seen > 2:
                continue
            
            alpha = 0.1 * entity.signal_strength
            pos = entity.position
            
            if entity.rssi_primary > -85:
                glColor4f(0, 1, 0.5, alpha)
                glLineWidth(1)
                glBegin(GL_LINES)
                glVertex3f(*PRIMARY_POS)
                glVertex3f(*pos)
                glEnd()
            
            if entity.rssi_remote > -85:
                glColor4f(0, 0.7, 1, alpha)
                glBegin(GL_LINES)
                glVertex3f(*REMOTE_POS)
                glVertex3f(*pos)
                glEnd()
        
        glEnable(GL_LIGHTING)
    
    def process_data(self, data: dict):
        scan = data.get('scan', {})
        
        # Process primary sensor's tracked MAC summary (new firmware)
        for tr in scan.get('tracked_macs', []):
            mac = tr.get('mac', '')
            if mac and mac in self.engine.entities:
                entity = self.engine.entities[mac]
                
                # Use primary's motion detection
                if tr.get('mv', 0) == 1:
                    entity.is_moving = True
                
                # Use primary's direction hint
                direction = tr.get('dir', 0)
                primary_vel = tr.get('vel', 0)
                
                if direction < 0:
                    entity.approach_direction = "toward_primary"
                elif direction > 0:
                    entity.approach_direction = "away_from_primary"
                
                # Use primary's RSSI velocity
                if primary_vel:
                    entity.rssi_velocity = float(primary_vel)
                
                # Process device classification from primary
                dev_type = tr.get('dev_type', 0)
                if dev_type > 0 and entity.device_type == 0:
                    entity.device_type = dev_type
                    entity.device_type_name = {
                        1: "smartphone",
                        2: "laptop",
                        3: "iot",
                        4: "infrastructure",
                        5: "wearable"
                    }.get(dev_type, "unknown")
                    
                    # Update entity type
                    if dev_type == 1 or dev_type == 5:
                        entity.entity_type = "person"
                        entity.color = (0.2, 0.8, 0.3)
                    elif dev_type == 4:
                        entity.is_infrastructure = True
                        entity.entity_type = "infrastructure"
                        entity.color = (0.3, 0.3, 0.8)
                    elif dev_type == 3:
                        entity.entity_type = "device"
                        entity.color = (0.8, 0.5, 0.2)
                
                # Quality and confidence from primary
                quality = tr.get('quality', 0) / 100.0
                conf = tr.get('conf', 0) / 100.0
                if quality > 0:
                    entity.signal_quality = max(entity.signal_quality, quality)
                if conf > 0:
                    entity.presence_confidence = max(entity.presence_confidence, conf)
                
                # Micro-variance from primary
                micro_var = tr.get('micro_var', 0)
                if micro_var > 0:
                    entity.micro_variance = micro_var
                    # Check for breathing
                    if 0.3 < micro_var < 5.0 and not entity.is_moving:
                        entity.breathing_pattern.append(micro_var)
                        if len(entity.breathing_pattern) > 30:
                            entity.breathing_pattern = entity.breathing_pattern[-30:]
                        if len(entity.breathing_pattern) >= 10:
                            var_of_var = np.var(entity.breathing_pattern)
                            if 0.1 < var_of_var < 2.0:
                                entity.breathing_detected = True
                
                # RSSI gradient
                entity.rssi_gradient = tr.get('gradient', entity.rssi_gradient)
                
                # Peak/min from primary
                entity.peak_rssi = max(entity.peak_rssi, tr.get('peak', -100))
                entity.min_rssi = min(entity.min_rssi, tr.get('min', -100)) if entity.min_rssi < 0 else tr.get('min', -100)
        
        for det in scan.get('detections', []):
            mac = det.get('mac', '')
            if not mac or mac == '00:00:00:00:00:00':
                continue
            rssi = det.get('rssi', -100)
            source = det.get('source', 'local')
            
            # Check for firmware-provided motion hint
            motion_hint = det.get('mv', None)  # 1 = moving, 0 = static
            
            # Also extract direction hint from per-detection data
            direction_hint = det.get('dir', None)
            velocity = det.get('vel', None)
            
            self.engine.process_detection(mac, rssi, source, motion_hint=motion_hint)
            
            # Apply direction from detection if entity exists
            if direction_hint is not None and mac in self.engine.entities:
                entity = self.engine.entities[mac]
                if source == 'local':
                    if direction_hint < 0:
                        entity.approach_direction = "toward_primary"
                    elif direction_hint > 0:
                        entity.approach_direction = "away_from_primary"
                else:
                    if direction_hint < 0:
                        entity.approach_direction = "toward_remote"
                    elif direction_hint > 0:
                        entity.approach_direction = "away_from_remote"
                
                if velocity is not None:
                    entity.rssi_velocity = float(velocity)
        
        # Process tracked MAC summary from remote nodes (enhanced firmware)
        for remote_data in scan.get('remotes', []):
            tracked_macs = remote_data.get('tracked', [])
            remote_moving = remote_data.get('moving_entities', 0)
            remote_approaching = remote_data.get('approaching', 0)
            remote_receding = remote_data.get('receding', 0)
            remote_strongest = remote_data.get('strongest', -100)
            channel_activity = remote_data.get('ch_activity', [])
            
            # New environment sensing from remote
            remote_occupancy = remote_data.get('occupancy', 0)
            remote_breathing = remote_data.get('breathing', 0) == 1
            remote_activity = remote_data.get('activity', 0)
            remote_density = remote_data.get('density', 0)
            
            # Store environment metrics for visualization
            if hasattr(self, 'remote_environment'):
                self.remote_environment = {
                    'occupancy': remote_occupancy,
                    'breathing_detected': remote_breathing,
                    'activity_level': remote_activity,
                    'signal_density': remote_density,
                    'moving': remote_moving,
                    'approaching': remote_approaching,
                    'receding': remote_receding,
                    'motion_threshold': remote_data.get('motion_thresh', 12),
                    'baseline_variance': remote_data.get('baseline_var', 2),
                    'env_noise': remote_data.get('env_noise', 0)
                }
            
            # Process multipath reflections for wall detection
            reflections = remote_data.get('reflections', [])
            for ref in reflections:
                ref_mac = ref.get('mac', '')
                direct_rssi = ref.get('direct', -100)
                reflected_rssi = ref.get('reflected', -100)
                diff_db = ref.get('diff', 0)
                
                # Large RSSI difference indicates reflection off wall
                if diff_db > 8 and ref_mac in self.engine.entities:
                    entity = self.engine.entities[ref_mac]
                    pos = entity.position
                    
                    # Use the RSSI difference to estimate distance to reflector
                    # Higher diff = closer reflection surface
                    reflection_dist = 2.0 - (diff_db - 8) * 0.1  # 0.5-2m range
                    reflection_dist = max(0.3, min(2.5, reflection_dist))
                    
                    # Mark potential reflection surfaces in multiple directions
                    for angle in np.linspace(0, 2*np.pi, 8):
                        rx = pos[0] + reflection_dist * np.cos(angle)
                        ry = pos[1] + reflection_dist * np.sin(angle)
                        
                        # Clamp to room bounds
                        rx = max(0, min(ROOM_WIDTH, rx))
                        ry = max(0, min(ROOM_DEPTH, ry))
                        
                        # Add to reflection points
                        self.engine.reflection_points.append((rx, ry, diff_db / 20.0, time.time()))
                        if len(self.engine.reflection_points) > self.engine.max_reflections:
                            self.engine.reflection_points.pop(0)
                        
                        # Boost wall probability at reflection points
                        gx = int(rx * 10)
                        gy = int(ry * 10)
                        if 0 <= gx < FLOOR_X and 0 <= gy < FLOOR_Y:
                            self.engine.wall_probability[gx, gy] = min(1.0, 
                                self.engine.wall_probability[gx, gy] + 0.05 * diff_db / 10)
            
            for tr in tracked_macs:
                mac = tr.get('mac', '')
                if mac and mac in self.engine.entities:
                    entity = self.engine.entities[mac]
                    
                    # Use remote's motion detection
                    if tr.get('mv', 0) == 1:
                        entity.is_moving = True
                    
                    # Use remote's direction hint (-1=approaching, 0=static, 1=receding)
                    direction = tr.get('dir', 0)
                    remote_vel = tr.get('vel', 0)
                    
                    # Map remote direction to approach_direction
                    if direction < 0:
                        # Approaching remote sensor
                        entity.approach_direction = "toward_remote"
                    elif direction > 0:
                        # Receding from remote sensor
                        entity.approach_direction = "away_from_remote"
                    
                    # Use remote's RSSI velocity if we don't have primary data
                    if remote_vel and (entity.rssi_velocity is None or abs(remote_vel) > abs(entity.rssi_velocity)):
                        entity.rssi_velocity = float(remote_vel)
                    
                    # Peak/min RSSI for signal range
                    peak = tr.get('peak', -100)
                    min_rssi = tr.get('min', -100)
                    entity.peak_rssi = max(entity.peak_rssi, peak)
                    entity.min_rssi = min(entity.min_rssi, min_rssi) if entity.min_rssi < 0 else min_rssi
                    
                    # Channel diversity indicates mobility
                    ch_div = tr.get('ch_div', 0)
                    entity.channel_diversity = max(entity.channel_diversity, ch_div)
                    if ch_div > 2:
                        entity.is_moving = True  # Seen on multiple channels = moving
                    
                    # Device classification from firmware
                    dev_type = tr.get('dev_type', 0)
                    if dev_type > 0:
                        entity.device_type = dev_type
                        entity.device_type_name = {
                            1: "smartphone",
                            2: "laptop",
                            3: "iot",
                            4: "infrastructure",
                            5: "wearable"
                        }.get(dev_type, "unknown")
                        
                        # Update entity type based on firmware classification
                        if dev_type == 1 or dev_type == 5:  # smartphone or wearable
                            entity.entity_type = "person"
                            entity.color = (0.2, 0.8, 0.3)  # Green for people
                        elif dev_type == 4:  # infrastructure
                            entity.is_infrastructure = True
                            entity.entity_type = "infrastructure"
                            entity.color = (0.3, 0.3, 0.8)  # Blue for infra
                        elif dev_type == 3:  # iot
                            entity.entity_type = "device"
                            entity.color = (0.8, 0.5, 0.2)  # Orange for IoT
                    
                    # Signal quality and presence confidence
                    quality = tr.get('quality', 0) / 100.0  # Comes as 0-100
                    conf = tr.get('conf', 0) / 100.0
                    entity.signal_quality = quality
                    entity.presence_confidence = conf
                    
                    # Micro-variance for breathing detection
                    micro_var = tr.get('micro_var', 0)
                    entity.micro_variance = micro_var
                    
                    # Track breathing pattern
                    if 0.3 < micro_var < 5.0 and not entity.is_moving:
                        entity.breathing_pattern.append(micro_var)
                        if len(entity.breathing_pattern) > 30:
                            entity.breathing_pattern = entity.breathing_pattern[-30:]
                        # Detect breathing if consistent pattern
                        if len(entity.breathing_pattern) >= 10:
                            var_of_var = np.var(entity.breathing_pattern)
                            if 0.1 < var_of_var < 2.0:
                                entity.breathing_detected = True
                    else:
                        entity.breathing_detected = False
                    
                    # RSSI gradient
                    entity.rssi_gradient = tr.get('gradient', 0)
                    
                    # Boost confidence for classified devices
                    entity.confidence_score = (quality + conf + (0.3 if dev_type > 0 else 0)) / 2.3
        
        # Process CSI data for enhanced movement detection
        csi_data = data.get('csi', {})
        if csi_data:
            self.engine.process_csi_data(csi_data)
    
    def mousePressEvent(self, e):
        self.last_mouse = e.pos()
    
    def mouseMoveEvent(self, e):
        if self.last_mouse and e.buttons() & Qt.MouseButton.LeftButton:
            dx = e.pos().x() - self.last_mouse.x()
            dy = e.pos().y() - self.last_mouse.y()
            self.cam_azimuth = (self.cam_azimuth + dx*0.4) % 360
            self.cam_elevation = max(5, min(85, self.cam_elevation + dy*0.25))
            self.last_mouse = e.pos()
    
    def mouseReleaseEvent(self, e):
        self.last_mouse = None
    
    def wheelEvent(self, e):
        d = e.angleDelta().y() / 120
        self.cam_dist = max(4, min(35, self.cam_dist - d*0.9))


# ==================== Main Window ====================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🌐 HYDRA TOMOGRAPHIC SCANNER - WiFi Environment Reconstruction")
        self.setMinimumSize(1300, 850)
        self.resize(1700, 1050)
        
        self.setStyleSheet("""
            QMainWindow { background: #080c18; }
            QStatusBar { background: #0a1025; color: #a0c5ff; border-top: 1px solid #1a3050; font-family: Consolas; font-size: 12px; }
            QLabel { color: #d0e5ff; }
        """)
        
        fmt = QSurfaceFormat()
        fmt.setSamples(8)
        fmt.setDepthBufferSize(24)
        QSurfaceFormat.setDefaultFormat(fmt)
        
        self.renderer = TomoRenderer()
        self.setCentralWidget(self.renderer)
        
        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        
        self.lbl_conn = QLabel("⏳ Connecting...")
        self.lbl_pps = QLabel("📡 --")
        self.lbl_entities = QLabel("👥 0")
        self.lbl_moving = QLabel("🚶 0")
        self.lbl_dual = QLabel("🎯 0")
        self.lbl_walls = QLabel("🧱 0")
        self.lbl_remote = QLabel("🔗 --")
        self.lbl_csi = QLabel("📶 --")
        self.lbl_fps = QLabel("🎮 --")
        
        for l in [self.lbl_conn, self.lbl_pps, self.lbl_entities, self.lbl_moving, self.lbl_dual, self.lbl_walls, self.lbl_remote, self.lbl_csi, self.lbl_fps]:
            self.status.addWidget(l)
            self.status.addWidget(QLabel(" │ "))
        
        self.status.addPermanentWidget(QLabel("🖱️ Drag=Rotate  Scroll=Zoom  [H]eat [W]alls [C]overage [F]resnel [R]adar [A]uto  [1-4] Views"))
        
        # Stats update timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self._update_stats)
        self.stats_timer.start(500)
        
        # Data fetcher
        self.fetcher = DataFetcher(ESP32_HOSTS, ESP32_PORT)
        self.fetcher.data_received.connect(self._on_data)
        self.fetcher.status_changed.connect(self._on_status)
        self.fetcher.start()
    
    def _update_stats(self):
        self.lbl_fps.setText(f"🎮 {self.renderer.fps:.0f}")
        engine = self.renderer.engine
        self.lbl_walls.setText(f"🧱 {len(engine.get_wall_voxels())}")
        self.lbl_dual.setText(f"🎯 {engine.dual_sensor_count}")
    
    def _on_data(self, data):
        self.renderer.process_data(data)
        
        status = data.get('status', {})
        remotes = data.get('remotes', {})
        csi = data.get('csi', {})
        
        self.lbl_pps.setText(f"📡 {status.get('pps', 0)}")
        
        active = self.renderer.engine.get_active_entities()
        moving = [e for e in active if e.is_moving]
        self.lbl_entities.setText(f"👥 {len(active)}")
        self.lbl_moving.setText(f"🚶 {len(moving)}")
        
        rlist = remotes.get('remotes', [])
        if rlist:
            r = rlist[0]
            self.lbl_remote.setText(f"🔗 {r.get('node_id', '?')} ({r.get('rssi', 0)})")
            self.lbl_remote.setStyleSheet("color: #00ff88;")
        else:
            self.lbl_remote.setText("🔗 Offline")
            self.lbl_remote.setStyleSheet("color: #ff6b6b;")
        
        # Update CSI status
        if csi.get('csi_enabled'):
            csi_len = csi.get('len', 0)
            csi_motion = self.renderer.engine.csi_movement_indicator
            if csi_motion > 0.5:
                self.lbl_csi.setText(f"📶 CSI ({csi_len}) 🔴")
                self.lbl_csi.setStyleSheet("color: #ff6b6b;")
            elif csi_motion > 0.2:
                self.lbl_csi.setText(f"📶 CSI ({csi_len}) 🟡")
                self.lbl_csi.setStyleSheet("color: #ffcc00;")
            else:
                self.lbl_csi.setText(f"📶 CSI ({csi_len}) 🟢")
                self.lbl_csi.setStyleSheet("color: #00ff88;")
        else:
            self.lbl_csi.setText("📶 No CSI")
            self.lbl_csi.setStyleSheet("color: #888888;")
    
    def _on_status(self, ok, info):
        if ok:
            self.lbl_conn.setText(f"🟢 {info}")
            self.lbl_conn.setStyleSheet("color: #00ff88;")
        else:
            self.lbl_conn.setText(f"🔴 {info}")
            self.lbl_conn.setStyleSheet("color: #ff6b6b;")
    
    def closeEvent(self, e):
        # Save persistent data before exit
        print("[HYDRA] Saving persistent data before exit...")
        self.renderer.engine.save_persistent_data()
        
        self.fetcher.stop()
        self.fetcher.wait()
        super().closeEvent(e)


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
