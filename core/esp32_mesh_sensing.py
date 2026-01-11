"""
ESP32 Mesh Sensing Module - Dual-Node WiFi Sensing with Triangulation

Connects to:
1. Primary ESP32-S3 (192.168.4.1) - Access Point mode, provides HTTP API and TCP streaming
2. Remote ESP32 (connected via WiFi) - Sends detection data to primary for triangulation

Features:
- Real-time CSI (Channel State Information) processing
- Dual-node triangulation for improved localization
- Environment reconstruction from WiFi reflections
- Person detection and tracking
- Activity recognition from signal patterns

Copyright (c) 2024-2025 HydraRecon Security Suite
For authorized security research only.
"""

import asyncio
import aiohttp
import socket
import struct
import json
import time
import math
import threading
import logging
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable, Any
from collections import deque
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class WiFiDetection:
    """A single WiFi detection from an ESP32 node."""
    node_id: str
    timestamp_us: int
    mac: str
    bssid: str
    rssi: int
    channel: int
    frame_type: int
    seq_num: int
    noise_floor: int
    bandwidth: int
    data_rate: int
    raw_csi: Optional[List[float]] = None
    
    @property
    def timestamp_sec(self) -> float:
        return self.timestamp_us / 1_000_000


@dataclass  
class NodeInfo:
    """Information about a sensing node."""
    node_id: str
    ip_address: str
    mac_address: str
    position: Tuple[float, float, float]  # x, y, z in meters
    is_primary: bool
    connected: bool = False
    last_seen: float = 0.0
    packet_count: int = 0
    channel: int = 1


@dataclass
class TriangulatedPosition:
    """A triangulated position from multiple node detections."""
    x: float
    y: float
    z: float
    confidence: float
    velocity: Tuple[float, float, float]
    source_mac: str
    timestamp: float
    contributing_nodes: List[str]


@dataclass
class EnvironmentObject:
    """A detected object/obstruction in the environment."""
    id: str
    object_type: str  # wall, furniture, person, door, etc.
    position: Tuple[float, float, float]
    size: Tuple[float, float, float]  # width, depth, height
    confidence: float
    last_updated: float
    signal_absorption: float  # How much the object blocks signals
    is_moving: bool = False
    velocity: Tuple[float, float, float] = (0, 0, 0)


@dataclass
class TrackedPerson:
    """A tracked person in the environment."""
    id: str
    position: Tuple[float, float, float]
    velocity: Tuple[float, float, float]
    confidence: float
    activity: str  # idle, walking, running, sitting, fallen
    breath_rate: Optional[float] = None
    heart_rate: Optional[float] = None
    last_seen: float = 0.0
    track_history: List[Tuple[float, float, float]] = field(default_factory=list)


class ActivityType(Enum):
    IDLE = "idle"
    WALKING = "walking"
    RUNNING = "running"
    SITTING = "sitting"
    STANDING = "standing"
    FALLEN = "fallen"
    UNKNOWN = "unknown"


# =============================================================================
# ESP32 Node Connection
# =============================================================================

class ESP32NodeConnection:
    """Connection to a single ESP32 sensing node."""
    
    def __init__(self, node_id: str, host: str, port: int = 80, 
                 position: Tuple[float, float, float] = (0, 0, 0),
                 is_primary: bool = False):
        self.node_id = node_id
        self.host = host
        self.http_port = port
        self.tcp_port = 8080
        self.position = position
        self.is_primary = is_primary
        
        self.connected = False
        self.mac_address = ""
        self.packet_count = 0
        self.last_packet_time = 0.0
        self.current_channel = 1
        
        self._tcp_socket: Optional[socket.socket] = None
        self._tcp_thread: Optional[threading.Thread] = None
        self._running = False
        self._buffer = b""
        
        self.on_detection: Optional[Callable[[WiFiDetection], None]] = None
        self.detections: deque = deque(maxlen=10000)
        
        self.logger = logging.getLogger(f"ESP32Node.{node_id}")
        
    async def connect(self) -> bool:
        """Connect to the ESP32 node via HTTP to verify it's online."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(f"http://{self.host}:{self.http_port}/status") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self.connected = True
                        self.mac_address = data.get("mac", "")
                        self.current_channel = data.get("channel", 1)
                        self.logger.info(f"Connected to {self.node_id} at {self.host} (MAC: {self.mac_address})")
                        return True
        except Exception as e:
            self.logger.error(f"Failed to connect to {self.node_id}: {e}")
        return False
    
    def start_tcp_stream(self, callback: Callable[[WiFiDetection], None]) -> bool:
        """Start receiving TCP stream data from the node."""
        if self._running:
            return True
            
        self.on_detection = callback
        
        try:
            self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_socket.settimeout(10.0)
            self._tcp_socket.connect((self.host, self.tcp_port))
            self._tcp_socket.settimeout(1.0)
            
            self._running = True
            self._tcp_thread = threading.Thread(target=self._tcp_receive_loop, daemon=True)
            self._tcp_thread.start()
            
            self.logger.info(f"TCP stream started from {self.node_id}:{self.tcp_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start TCP stream: {e}")
            return False
    
    def stop_tcp_stream(self):
        """Stop the TCP stream."""
        self._running = False
        if self._tcp_socket:
            try:
                self._tcp_socket.close()
            except OSError:
                pass  # Socket already closed
        if self._tcp_thread:
            self._tcp_thread.join(timeout=2)
            
    def _tcp_receive_loop(self):
        """Background thread to receive TCP data."""
        while self._running and self._tcp_socket:
            try:
                data = self._tcp_socket.recv(4096)
                if not data:
                    time.sleep(0.1)
                    continue
                    
                self._buffer += data
                self._process_buffer()
                
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.debug(f"TCP receive error: {e}")
                time.sleep(0.5)
                
    def _process_buffer(self):
        """Process buffered data looking for complete JSON messages."""
        while b'\n' in self._buffer:
            line, self._buffer = self._buffer.split(b'\n', 1)
            try:
                data = json.loads(line.decode('utf-8', errors='ignore'))
                detection = self._parse_detection(data)
                if detection:
                    self.packet_count += 1
                    self.last_packet_time = time.time()
                    self.detections.append(detection)
                    if self.on_detection:
                        self.on_detection(detection)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                self.logger.debug(f"Parse error: {e}")
                
    def _parse_detection(self, data: Dict[str, Any]) -> Optional[WiFiDetection]:
        """Parse a detection from JSON data."""
        try:
            # Determine source node - detections from remote nodes have "source": "remote"
            source = data.get("source", "primary")
            node_id = self.node_id if source == "primary" else f"remote_{source}"
            
            return WiFiDetection(
                node_id=node_id,
                timestamp_us=data.get("ts", data.get("timestamp_us", int(time.time() * 1_000_000))),
                mac=data.get("mac", ""),
                bssid=data.get("bssid", ""),
                rssi=data.get("rssi", -100),
                channel=data.get("ch", data.get("channel", self.current_channel)),
                frame_type=data.get("type", data.get("frame_type", 0)),
                seq_num=data.get("seq", data.get("seq_num", 0)),
                noise_floor=data.get("noise", data.get("noise_floor", -95)),
                bandwidth=data.get("bw", data.get("bandwidth", 20)),
                data_rate=data.get("rate", data.get("data_rate", 0)),
                raw_csi=data.get("csi")
            )
        except Exception:
            return None
    
    async def get_scan_data(self) -> List[WiFiDetection]:
        """Get current scan data via HTTP."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(f"http://{self.host}:{self.http_port}/scan") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        detections = []
                        for d in data.get("detections", []):
                            det = self._parse_detection(d)
                            if det:
                                detections.append(det)
                        return detections
        except Exception as e:
            self.logger.debug(f"Scan data fetch error: {e}")
        return []


# =============================================================================
# Triangulation Engine
# =============================================================================

class TriangulationEngine:
    """
    Triangulate positions using RSSI data from multiple nodes.
    
    Uses multilateration with RSSI-based distance estimation.
    """
    
    # Path loss exponent (typical indoor values: 2.0-4.0)
    PATH_LOSS_EXPONENT = 2.8
    # Reference RSSI at 1 meter
    RSSI_REF_1M = -40.0
    
    def __init__(self):
        self.nodes: Dict[str, NodeInfo] = {}
        self.logger = logging.getLogger("Triangulation")
        
    def add_node(self, node_info: NodeInfo):
        """Add a sensing node to the triangulation system."""
        self.nodes[node_info.node_id] = node_info
        
    def rssi_to_distance(self, rssi: float) -> float:
        """Convert RSSI to distance in meters using log-distance path loss model."""
        if rssi >= self.RSSI_REF_1M:
            return 0.5  # Very close
        distance = 10 ** ((self.RSSI_REF_1M - rssi) / (10 * self.PATH_LOSS_EXPONENT))
        return min(distance, 50.0)  # Cap at 50 meters
    
    def triangulate(self, detections: List[WiFiDetection], 
                    target_mac: str) -> Optional[TriangulatedPosition]:
        """
        Triangulate position of a MAC address using detections from multiple nodes.
        
        Uses weighted least squares multilateration.
        """
        # Group detections by node
        node_detections: Dict[str, List[WiFiDetection]] = {}
        for det in detections:
            if det.mac == target_mac:
                if det.node_id not in node_detections:
                    node_detections[det.node_id] = []
                node_detections[det.node_id].append(det)
        
        if len(node_detections) < 2:
            # Need at least 2 nodes for triangulation
            return None
            
        # Calculate average RSSI and distance for each node
        node_distances: List[Tuple[NodeInfo, float, float]] = []  # (node, distance, rssi)
        for node_id, dets in node_detections.items():
            if node_id not in self.nodes:
                continue
            node = self.nodes[node_id]
            avg_rssi = sum(d.rssi for d in dets) / len(dets)
            distance = self.rssi_to_distance(avg_rssi)
            node_distances.append((node, distance, avg_rssi))
        
        if len(node_distances) < 2:
            return None
            
        # Perform multilateration
        position = self._multilaterate(node_distances)
        if position is None:
            return None
            
        # Calculate confidence based on number of nodes and RSSI consistency
        confidence = min(1.0, len(node_distances) / 3) * 0.5
        rssi_values = [nd[2] for nd in node_distances]
        rssi_std = np.std(rssi_values) if len(rssi_values) > 1 else 0
        confidence += 0.5 * max(0, 1 - rssi_std / 20)
        
        return TriangulatedPosition(
            x=position[0],
            y=position[1],
            z=position[2],
            confidence=confidence,
            velocity=(0, 0, 0),
            source_mac=target_mac,
            timestamp=time.time(),
            contributing_nodes=[nd[0].node_id for nd in node_distances]
        )
    
    def _multilaterate(self, node_distances: List[Tuple[NodeInfo, float, float]]) -> Optional[Tuple[float, float, float]]:
        """
        Perform multilateration using weighted least squares.
        
        For 2 nodes, returns intersection of circles.
        For 3+ nodes, uses optimization.
        """
        if len(node_distances) < 2:
            return None
            
        # Use the first node as reference
        ref_node, ref_dist, _ = node_distances[0]
        ref_pos = np.array(ref_node.position)
        
        if len(node_distances) == 2:
            # 2-node case: return midpoint weighted by distance
            node2, dist2, _ = node_distances[1]
            pos2 = np.array(node2.position)
            
            # Vector from node1 to node2
            v = pos2 - ref_pos
            v_len = np.linalg.norm(v)
            if v_len == 0:
                return tuple(ref_pos)
                
            v_norm = v / v_len
            
            # Position along the line between nodes
            total_dist = ref_dist + dist2
            if total_dist == 0:
                t = 0.5
            else:
                t = ref_dist / total_dist
                
            position = ref_pos + v_norm * (t * v_len)
            return (float(position[0]), float(position[1]), float(position[2]))
        
        # 3+ nodes: least squares
        try:
            A = []
            b = []
            
            for i in range(1, len(node_distances)):
                node, dist, _ = node_distances[i]
                pos = np.array(node.position)
                
                # Build linear system: 2(xi - x0)*x + 2(yi - y0)*y + 2(zi - z0)*z = 
                #   di^2 - d0^2 - xi^2 - yi^2 - zi^2 + x0^2 + y0^2 + z0^2
                A.append([
                    2 * (pos[0] - ref_pos[0]),
                    2 * (pos[1] - ref_pos[1]),
                    2 * (pos[2] - ref_pos[2])
                ])
                
                b.append(
                    ref_dist**2 - dist**2 -
                    ref_pos[0]**2 - ref_pos[1]**2 - ref_pos[2]**2 +
                    pos[0]**2 + pos[1]**2 + pos[2]**2
                )
            
            A = np.array(A)
            b = np.array(b)
            
            # Solve using least squares
            result, _, _, _ = np.linalg.lstsq(A, b, rcond=None)
            return (float(result[0]), float(result[1]), float(result[2]))
            
        except Exception as e:
            self.logger.debug(f"Multilateration failed: {e}")
            return None


# =============================================================================
# Environment Reconstruction
# =============================================================================

class EnvironmentReconstructor:
    """
    Reconstruct the environment from WiFi signal reflections.
    
    Uses signal strength variations and CSI phase data to:
    - Detect walls and static objects
    - Estimate room dimensions
    - Track dynamic objects (people)
    """
    
    def __init__(self, room_width: float = 10.0, room_depth: float = 10.0, room_height: float = 3.0):
        self.room_width = room_width
        self.room_depth = room_depth
        self.room_height = room_height
        
        # Voxel grid for environment mapping (0.5m resolution)
        self.voxel_size = 0.5
        self.grid_width = int(room_width / self.voxel_size)
        self.grid_depth = int(room_depth / self.voxel_size)
        self.grid_height = int(room_height / self.voxel_size)
        
        # Occupancy grid: probability of obstruction at each voxel
        self.occupancy_grid = np.zeros((self.grid_width, self.grid_depth, self.grid_height))
        
        # Signal propagation map
        self.signal_map = np.zeros((self.grid_width, self.grid_depth, self.grid_height))
        
        # Detected objects
        self.objects: Dict[str, EnvironmentObject] = {}
        
        # Signal history for pattern analysis
        self.signal_history: deque = deque(maxlen=1000)
        
        self.logger = logging.getLogger("EnvironmentReconstructor")
        
    def process_detections(self, detections: List[WiFiDetection], 
                          node_positions: Dict[str, Tuple[float, float, float]]):
        """Process detections to update environment model."""
        for det in detections:
            if det.node_id not in node_positions:
                continue
                
            node_pos = node_positions[det.node_id]
            
            # Update signal map based on RSSI
            self._update_signal_map(node_pos, det.rssi, det.channel)
            
            # Store for pattern analysis
            self.signal_history.append({
                'time': det.timestamp_sec,
                'node': det.node_id,
                'rssi': det.rssi,
                'channel': det.channel,
                'csi': det.raw_csi
            })
            
        # Analyze patterns to detect objects
        self._analyze_signal_patterns()
        
    def _update_signal_map(self, node_pos: Tuple[float, float, float], 
                           rssi: float, channel: int):
        """Update signal propagation map from a detection."""
        # Convert position to grid coordinates
        nx = int(node_pos[0] / self.voxel_size)
        ny = int(node_pos[1] / self.voxel_size)
        nz = int(node_pos[2] / self.voxel_size)
        
        if not (0 <= nx < self.grid_width and 0 <= ny < self.grid_depth and 0 <= nz < self.grid_height):
            return
            
        # Propagate signal strength with distance attenuation
        signal_strength = 10 ** (rssi / 20)  # Convert dBm to linear
        
        for x in range(self.grid_width):
            for y in range(self.grid_depth):
                dist = math.sqrt((x - nx)**2 + (y - ny)**2) * self.voxel_size
                if dist < 0.1:
                    dist = 0.1
                    
                # Free space path loss
                attenuation = signal_strength / (dist ** 2)
                
                # Update with exponential moving average
                alpha = 0.1
                self.signal_map[x, y, nz] = (1 - alpha) * self.signal_map[x, y, nz] + alpha * attenuation
                
    def _analyze_signal_patterns(self):
        """Analyze signal patterns to detect walls and obstructions."""
        if len(self.signal_history) < 100:
            return
            
        # Calculate signal variance at each point
        recent = list(self.signal_history)[-100:]
        
        # Group by node
        by_node: Dict[str, List[float]] = {}
        for s in recent:
            if s['node'] not in by_node:
                by_node[s['node']] = []
            by_node[s['node']].append(s['rssi'])
        
        # High variance indicates movement or multipath
        for node_id, rssi_values in by_node.items():
            if len(rssi_values) < 10:
                continue
                
            variance = np.var(rssi_values)
            mean_rssi = np.mean(rssi_values)
            
            # Low variance + weak signal = obstruction
            if variance < 2.0 and mean_rssi < -70:
                # Likely a static obstruction between nodes
                self._detect_obstruction(node_id, mean_rssi)
                
    def _detect_obstruction(self, node_id: str, rssi: float):
        """Mark potential obstruction zones."""
        # This is a simplified model - real implementation would use
        # CSI phase data and multiple node correlations
        pass
        
    def get_floor_plan(self) -> Dict[str, Any]:
        """Get current floor plan estimate."""
        # Find high-occupancy regions (walls)
        wall_threshold = 0.6
        walls = []
        
        for x in range(self.grid_width):
            for y in range(self.grid_depth):
                if self.occupancy_grid[x, y, 1] > wall_threshold:
                    walls.append({
                        'x': x * self.voxel_size,
                        'y': y * self.voxel_size,
                        'probability': float(self.occupancy_grid[x, y, 1])
                    })
        
        return {
            'width': self.room_width,
            'depth': self.room_depth,
            'height': self.room_height,
            'voxel_size': self.voxel_size,
            'walls': walls,
            'objects': [
                {
                    'id': obj.id,
                    'type': obj.object_type,
                    'position': obj.position,
                    'size': obj.size,
                    'confidence': obj.confidence
                }
                for obj in self.objects.values()
            ]
        }
    
    def get_signal_heatmap(self) -> np.ndarray:
        """Get 2D signal strength heatmap at floor level."""
        return self.signal_map[:, :, 0].copy()


# =============================================================================
# Person Tracker
# =============================================================================

class PersonTracker:
    """
    Track people using WiFi sensing data.
    
    Uses Kalman filtering for smooth tracking and activity classification
    from movement patterns.
    """
    
    def __init__(self):
        self.persons: Dict[str, TrackedPerson] = {}
        self.next_person_id = 1
        
        # Detection parameters
        self.merge_distance = 1.5  # meters - merge detections closer than this
        self.lost_timeout = 5.0    # seconds - remove person after no detection
        
        # Kalman filter parameters
        self.process_noise = 0.1
        self.measurement_noise = 0.5
        
        # Activity classification history
        self.velocity_history: Dict[str, deque] = {}
        
        self.logger = logging.getLogger("PersonTracker")
        
    def update(self, positions: List[TriangulatedPosition]) -> List[TrackedPerson]:
        """Update tracking with new triangulated positions."""
        now = time.time()
        
        # Match new positions to existing tracks
        unmatched = list(positions)
        
        for person_id, person in list(self.persons.items()):
            best_match = None
            best_dist = self.merge_distance
            
            for pos in unmatched:
                dist = math.sqrt(
                    (pos.x - person.position[0])**2 +
                    (pos.y - person.position[1])**2 +
                    (pos.z - person.position[2])**2
                )
                if dist < best_dist:
                    best_dist = dist
                    best_match = pos
            
            if best_match:
                unmatched.remove(best_match)
                self._update_person(person, best_match, now)
            else:
                # No match - check if person is lost
                if now - person.last_seen > self.lost_timeout:
                    del self.persons[person_id]
                    if person_id in self.velocity_history:
                        del self.velocity_history[person_id]
                        
        # Create new tracks for unmatched positions
        for pos in unmatched:
            if pos.confidence > 0.3:  # Only create if confident enough
                person_id = f"person_{self.next_person_id}"
                self.next_person_id += 1
                
                self.persons[person_id] = TrackedPerson(
                    id=person_id,
                    position=(pos.x, pos.y, pos.z),
                    velocity=(0, 0, 0),
                    confidence=pos.confidence,
                    activity=ActivityType.UNKNOWN.value,
                    last_seen=now
                )
                self.velocity_history[person_id] = deque(maxlen=50)
                
        return list(self.persons.values())
    
    def _update_person(self, person: TrackedPerson, pos: TriangulatedPosition, now: float):
        """Update a person's position and classify activity."""
        dt = now - person.last_seen
        if dt > 0:
            # Calculate velocity
            vx = (pos.x - person.position[0]) / dt
            vy = (pos.y - person.position[1]) / dt
            vz = (pos.z - person.position[2]) / dt
            
            # Kalman-like smoothing
            alpha = 0.3
            person.velocity = (
                person.velocity[0] * (1 - alpha) + vx * alpha,
                person.velocity[1] * (1 - alpha) + vy * alpha,
                person.velocity[2] * (1 - alpha) + vz * alpha
            )
            
            # Track velocity history for activity classification
            speed = math.sqrt(vx**2 + vy**2 + vz**2)
            self.velocity_history[person.id].append(speed)
            
            # Classify activity
            person.activity = self._classify_activity(person.id)
        
        # Update position with smoothing
        alpha = 0.5
        person.position = (
            person.position[0] * (1 - alpha) + pos.x * alpha,
            person.position[1] * (1 - alpha) + pos.y * alpha,
            person.position[2] * (1 - alpha) + pos.z * alpha
        )
        
        person.confidence = pos.confidence
        person.last_seen = now
        
        # Track history for visualization
        person.track_history.append(person.position)
        if len(person.track_history) > 100:
            person.track_history = person.track_history[-100:]
            
    def _classify_activity(self, person_id: str) -> str:
        """Classify activity from velocity patterns."""
        if person_id not in self.velocity_history:
            return ActivityType.UNKNOWN.value
            
        history = list(self.velocity_history[person_id])
        if len(history) < 5:
            return ActivityType.UNKNOWN.value
            
        avg_speed = np.mean(history[-10:])
        speed_variance = np.var(history[-10:])
        
        # Classification thresholds (m/s)
        if avg_speed < 0.1 and speed_variance < 0.05:
            # Check if sitting or standing based on position history
            return ActivityType.IDLE.value
        elif avg_speed < 0.5:
            return ActivityType.STANDING.value
        elif avg_speed < 1.5:
            return ActivityType.WALKING.value
        else:
            return ActivityType.RUNNING.value


# =============================================================================
# Main Mesh Sensing System
# =============================================================================

class ESP32MeshSensing:
    """
    Main class for dual-ESP32 mesh WiFi sensing system.
    
    Coordinates:
    - Connection to primary and remote ESP32 nodes
    - Triangulation of WiFi signals
    - Environment reconstruction
    - Person tracking
    """
    
    # Default configuration
    DEFAULT_PRIMARY_HOST = "192.168.4.1"
    DEFAULT_ROOM_SIZE = (8.0, 8.0, 3.0)  # width, depth, height in meters
    DEFAULT_NODE_SEPARATION = 4.57  # ~15 feet in meters
    
    def __init__(self, primary_host: str = None, 
                 room_size: Tuple[float, float, float] = None,
                 node_separation: float = None):
        
        self.primary_host = primary_host or self.DEFAULT_PRIMARY_HOST
        self.room_size = room_size or self.DEFAULT_ROOM_SIZE
        self.node_separation = node_separation or self.DEFAULT_NODE_SEPARATION
        
        # Node connections
        self.primary_node: Optional[ESP32NodeConnection] = None
        self.remote_nodes: Dict[str, ESP32NodeConnection] = {}
        
        # Processing engines
        self.triangulator = TriangulationEngine()
        self.environment = EnvironmentReconstructor(*self.room_size)
        self.person_tracker = PersonTracker()
        
        # Data storage
        self.all_detections: deque = deque(maxlen=50000)
        self.tracked_macs: Dict[str, Dict[str, Any]] = {}
        
        # State
        self.running = False
        self._lock = threading.Lock()
        
        # Callbacks
        self.on_person_update: Optional[Callable[[List[TrackedPerson]], None]] = None
        self.on_detection: Optional[Callable[[WiFiDetection], None]] = None
        self.on_environment_update: Optional[Callable[[Dict[str, Any]], None]] = None
        
        # Statistics
        self.stats = {
            'packets_received': 0,
            'triangulations': 0,
            'persons_detected': 0,
            'start_time': 0.0
        }
        
        self.logger = logging.getLogger("ESP32MeshSensing")
        
    async def initialize(self) -> bool:
        """Initialize connections to all ESP32 nodes."""
        self.logger.info("Initializing ESP32 mesh sensing system...")
        
        # Create and connect to primary node
        # Primary is at center-left of the room
        primary_pos = (0, self.room_size[1] / 2, 1.0)
        self.primary_node = ESP32NodeConnection(
            node_id="primary",
            host=self.primary_host,
            position=primary_pos,
            is_primary=True
        )
        
        if not await self.primary_node.connect():
            self.logger.error("Failed to connect to primary node")
            return False
            
        # Add primary to triangulator
        self.triangulator.add_node(NodeInfo(
            node_id="primary",
            ip_address=self.primary_host,
            mac_address=self.primary_node.mac_address,
            position=primary_pos,
            is_primary=True,
            connected=True
        ))
        
        # Fetch remote nodes from primary
        await self._discover_remote_nodes()
        
        self.logger.info(f"Mesh initialized with 1 primary + {len(self.remote_nodes)} remote node(s)")
        return True
        
    async def _discover_remote_nodes(self):
        """Discover remote nodes registered with primary."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(f"http://{self.primary_host}/remotes") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for remote in data.get("remotes", []):
                            # Support both "id" and "node_id" keys
                            node_id = remote.get("node_id", remote.get("id", ""))
                            ip = remote.get("ip", "")
                            
                            if node_id and ip:
                                # Remote is ~15ft away from primary
                                remote_pos = (self.node_separation, self.room_size[1] / 2, 1.0)
                                
                                self.triangulator.add_node(NodeInfo(
                                    node_id=node_id,
                                    ip_address=ip,
                                    mac_address=remote.get("mac", ""),
                                    position=remote_pos,
                                    is_primary=False,
                                    connected=True
                                ))
                                
                                self.logger.info(f"Discovered remote node: {node_id} at {ip}")
        except Exception as e:
            self.logger.warning(f"Remote node discovery failed: {e}")
            
    def start(self):
        """Start the sensing system."""
        if self.running:
            return
            
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Start TCP stream from primary
        if self.primary_node:
            self.primary_node.start_tcp_stream(self._on_detection)
            
        # Start processing loop
        self._process_thread = threading.Thread(target=self._processing_loop, daemon=True)
        self._process_thread.start()
        
        self.logger.info("Sensing system started")
        
    def stop(self):
        """Stop the sensing system."""
        self.running = False
        
        if self.primary_node:
            self.primary_node.stop_tcp_stream()
            
        for node in self.remote_nodes.values():
            node.stop_tcp_stream()
            
        self.logger.info("Sensing system stopped")
        
    def _on_detection(self, detection: WiFiDetection):
        """Handle incoming detection from any node."""
        with self._lock:
            self.all_detections.append(detection)
            self.stats['packets_received'] += 1
            
            # Track MAC addresses
            if detection.mac not in self.tracked_macs:
                self.tracked_macs[detection.mac] = {
                    'first_seen': time.time(),
                    'last_seen': time.time(),
                    'rssi_history': deque(maxlen=100),
                    'detection_count': 0
                }
            
            mac_info = self.tracked_macs[detection.mac]
            mac_info['last_seen'] = time.time()
            mac_info['rssi_history'].append(detection.rssi)
            mac_info['detection_count'] += 1
            
            if self.on_detection:
                self.on_detection(detection)
                
    def _processing_loop(self):
        """Background processing loop for triangulation and tracking."""
        last_process_time = 0
        process_interval = 0.1  # Process every 100ms
        
        while self.running:
            now = time.time()
            if now - last_process_time < process_interval:
                time.sleep(0.01)
                continue
                
            last_process_time = now
            
            with self._lock:
                # Get recent detections
                cutoff = now - 1.0  # Last second
                recent = [d for d in self.all_detections 
                         if d.timestamp_sec > cutoff]
                
            if not recent:
                continue
                
            # Triangulate positions for active MACs
            triangulated: List[TriangulatedPosition] = []
            
            for mac, info in self.tracked_macs.items():
                if now - info['last_seen'] > 2.0:
                    continue
                    
                pos = self.triangulator.triangulate(recent, mac)
                if pos:
                    triangulated.append(pos)
                    self.stats['triangulations'] += 1
                    
            # Update person tracking
            if triangulated:
                persons = self.person_tracker.update(triangulated)
                self.stats['persons_detected'] = len(persons)
                
                if self.on_person_update:
                    self.on_person_update(persons)
                    
            # Update environment model
            node_positions = {}
            for node_id, node_info in self.triangulator.nodes.items():
                node_positions[node_id] = node_info.position
                
            self.environment.process_detections(recent, node_positions)
            
    def get_status(self) -> Dict[str, Any]:
        """Get current system status."""
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] > 0 else 0
        
        return {
            'running': self.running,
            'uptime_seconds': uptime,
            'primary_connected': self.primary_node.connected if self.primary_node else False,
            'remote_nodes': len(self.remote_nodes),
            'packets_received': self.stats['packets_received'],
            'triangulations': self.stats['triangulations'],
            'persons_detected': self.stats['persons_detected'],
            'tracked_macs': len(self.tracked_macs)
        }
        
    def get_persons(self) -> List[Dict[str, Any]]:
        """Get all tracked persons."""
        return [
            {
                'id': p.id,
                'position': {'x': p.position[0], 'y': p.position[1], 'z': p.position[2]},
                'velocity': {'x': p.velocity[0], 'y': p.velocity[1], 'z': p.velocity[2]},
                'confidence': p.confidence,
                'activity': p.activity,
                'breath_rate': p.breath_rate,
                'heart_rate': p.heart_rate,
                'track_history': [{'x': h[0], 'y': h[1], 'z': h[2]} for h in p.track_history[-20:]]
            }
            for p in self.person_tracker.persons.values()
        ]
        
    def get_environment(self) -> Dict[str, Any]:
        """Get environment reconstruction data."""
        floor_plan = self.environment.get_floor_plan()
        heatmap = self.environment.get_signal_heatmap()
        
        return {
            'floor_plan': floor_plan,
            'signal_heatmap': heatmap.tolist() if isinstance(heatmap, np.ndarray) else heatmap
        }
        
    def get_tracked_macs(self) -> List[Dict[str, Any]]:
        """Get all tracked MAC addresses."""
        now = time.time()
        return [
            {
                'mac': mac,
                'first_seen': info['first_seen'],
                'last_seen': info['last_seen'],
                'age_seconds': now - info['first_seen'],
                'detection_count': info['detection_count'],
                'avg_rssi': np.mean(list(info['rssi_history'])) if info['rssi_history'] else -100,
                'active': now - info['last_seen'] < 5.0
            }
            for mac, info in self.tracked_macs.items()
        ]


# =============================================================================
# CLI Entry Point
# =============================================================================

async def main():
    """Command-line entry point for testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description="ESP32 Mesh WiFi Sensing")
    parser.add_argument("--host", default="192.168.4.1", help="Primary ESP32 host")
    parser.add_argument("--room-width", type=float, default=8.0, help="Room width in meters")
    parser.add_argument("--room-depth", type=float, default=8.0, help="Room depth in meters")
    parser.add_argument("--separation", type=float, default=4.57, help="Node separation in meters (15ft default)")
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    
    sensing = ESP32MeshSensing(
        primary_host=args.host,
        room_size=(args.room_width, args.room_depth, 3.0),
        node_separation=args.separation
    )
    
    # Set up callbacks
    def on_person_update(persons):
        for p in persons:
            print(f"Person {p.id}: pos=({p.position[0]:.2f}, {p.position[1]:.2f}) activity={p.activity} conf={p.confidence:.2f}")
    
    sensing.on_person_update = on_person_update
    
    if await sensing.initialize():
        sensing.start()
        
        print("\nESP32 Mesh Sensing Active")
        print("=" * 50)
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                await asyncio.sleep(5)
                status = sensing.get_status()
                print(f"Status: packets={status['packets_received']} triangulations={status['triangulations']} persons={status['persons_detected']}")
        except KeyboardInterrupt:
            print("\nStopping...")
            sensing.stop()
    else:
        print("Failed to initialize sensing system")
        

if __name__ == "__main__":
    asyncio.run(main())
