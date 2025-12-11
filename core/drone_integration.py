"""
HydraRecon Autonomous Drone Integration
=========================================

Advanced drone/UAV security operations:
- Autonomous reconnaissance flights
- WiFi network scanning from air
- RF spectrum analysis
- Physical security perimeter mapping
- Thermal imaging integration
- Visual inspection and photography
- GPS-denied navigation
- Swarm coordination
- Obstacle avoidance
- Mission planning and execution
"""

import os
import time
import math
import threading
import queue
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable
from datetime import datetime
from enum import Enum, auto
from abc import ABC, abstractmethod
import numpy as np
import json

# Optional imports
try:
    from dronekit import connect, VehicleMode
    DRONEKIT_AVAILABLE = True
except ImportError:
    DRONEKIT_AVAILABLE = False


class DroneStatus(Enum):
    """Drone operational status"""
    OFFLINE = auto()
    INITIALIZING = auto()
    READY = auto()
    ARMED = auto()
    TAKING_OFF = auto()
    FLYING = auto()
    HOVERING = auto()
    LANDING = auto()
    RETURNING = auto()
    EMERGENCY = auto()


class MissionType(Enum):
    """Types of reconnaissance missions"""
    PERIMETER_SCAN = auto()
    WIFI_SURVEY = auto()
    RF_ANALYSIS = auto()
    VISUAL_INSPECTION = auto()
    THERMAL_SCAN = auto()
    WAYPOINT_PATROL = auto()
    FOLLOW_TARGET = auto()
    SWARM_FORMATION = auto()


@dataclass
class GPSCoordinate:
    """GPS coordinate"""
    latitude: float
    longitude: float
    altitude: float = 0.0
    
    def distance_to(self, other: 'GPSCoordinate') -> float:
        """Calculate distance in meters using Haversine formula"""
        R = 6371000  # Earth radius in meters
        
        lat1 = math.radians(self.latitude)
        lat2 = math.radians(other.latitude)
        dlat = math.radians(other.latitude - self.latitude)
        dlon = math.radians(other.longitude - self.longitude)
        
        a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        horizontal = R * c
        vertical = abs(other.altitude - self.altitude)
        
        return math.sqrt(horizontal ** 2 + vertical ** 2)
    
    def bearing_to(self, other: 'GPSCoordinate') -> float:
        """Calculate bearing in degrees"""
        lat1 = math.radians(self.latitude)
        lat2 = math.radians(other.latitude)
        dlon = math.radians(other.longitude - self.longitude)
        
        x = math.sin(dlon) * math.cos(lat2)
        y = math.cos(lat1) * math.sin(lat2) - math.sin(lat1) * math.cos(lat2) * math.cos(dlon)
        
        bearing = math.atan2(x, y)
        return (math.degrees(bearing) + 360) % 360


@dataclass
class DroneState:
    """Current drone state"""
    position: GPSCoordinate
    heading: float  # Degrees
    ground_speed: float  # m/s
    vertical_speed: float  # m/s
    battery_percent: float
    gps_fix: int
    satellites: int
    armed: bool
    mode: str
    status: DroneStatus
    timestamp: float = field(default_factory=time.time)


@dataclass
class Waypoint:
    """Mission waypoint"""
    position: GPSCoordinate
    hold_time: float = 0.0  # Seconds to hover
    action: Optional[str] = None  # Action to perform at waypoint
    action_params: Dict[str, Any] = field(default_factory=dict)
    completed: bool = False


@dataclass
class ScanResult:
    """Scan result from drone sensors"""
    timestamp: float
    position: GPSCoordinate
    scan_type: str
    data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Drone Controller
# =============================================================================

class DroneController:
    """Base drone controller"""
    
    def __init__(self, drone_id: str = None):
        self.drone_id = drone_id or f"drone_{int(time.time())}"
        self.state: Optional[DroneState] = None
        self.status = DroneStatus.OFFLINE
        self.connected = False
        
        # Home position
        self.home_position: Optional[GPSCoordinate] = None
        
        # Geofence
        self.geofence_radius = 500.0  # meters
        self.geofence_enabled = True
        
        # Safety limits
        self.max_altitude = 120.0  # meters (FAA limit)
        self.min_altitude = 2.0
        self.max_speed = 15.0  # m/s
        self.return_to_home_battery = 20.0  # percent
        
        # Callbacks
        self._on_state_change: List[Callable] = []
        self._on_telemetry: List[Callable] = []
        
        # Telemetry thread
        self._telemetry_thread: Optional[threading.Thread] = None
        self._running = False
    
    def connect(self, connection_string: str = None) -> bool:
        """Connect to drone"""
        if DRONEKIT_AVAILABLE and connection_string:
            try:
                self.vehicle = connect(connection_string, wait_ready=True)
                self.connected = True
                self.status = DroneStatus.READY
                self._update_home_position()
                self._start_telemetry()
                return True
            except Exception:
                return False
        
        # Simulation mode
        self.connected = True
        self.status = DroneStatus.READY
        self.home_position = GPSCoordinate(37.7749, -122.4194, 0)
        self.state = DroneState(
            position=self.home_position,
            heading=0,
            ground_speed=0,
            vertical_speed=0,
            battery_percent=100,
            gps_fix=3,
            satellites=12,
            armed=False,
            mode="STABILIZE",
            status=DroneStatus.READY
        )
        self._start_telemetry()
        return True
    
    def disconnect(self):
        """Disconnect from drone"""
        self._running = False
        if self._telemetry_thread:
            self._telemetry_thread.join(timeout=2.0)
        self.connected = False
        self.status = DroneStatus.OFFLINE
    
    def _start_telemetry(self):
        """Start telemetry monitoring"""
        self._running = True
        self._telemetry_thread = threading.Thread(target=self._telemetry_loop, daemon=True)
        self._telemetry_thread.start()
    
    def _telemetry_loop(self):
        """Telemetry monitoring loop"""
        while self._running:
            self._update_state()
            self._check_safety()
            
            for callback in self._on_telemetry:
                try:
                    callback(self.state)
                except Exception:
                    pass
            
            time.sleep(0.1)
    
    def _update_state(self):
        """Update drone state"""
        if self.state:
            # Simulate battery drain
            self.state.battery_percent = max(0, self.state.battery_percent - 0.001)
            self.state.timestamp = time.time()
    
    def _update_home_position(self):
        """Update home position from GPS"""
        if self.state:
            self.home_position = self.state.position
    
    def _check_safety(self):
        """Check safety conditions"""
        if not self.state:
            return
        
        # Low battery - return to home
        if self.state.battery_percent < self.return_to_home_battery and self.status == DroneStatus.FLYING:
            self.return_to_home()
        
        # Geofence check
        if self.geofence_enabled and self.home_position:
            distance = self.state.position.distance_to(self.home_position)
            if distance > self.geofence_radius:
                self.return_to_home()
        
        # Altitude check
        if self.state.position.altitude > self.max_altitude:
            self.set_altitude(self.max_altitude)
    
    def arm(self) -> bool:
        """Arm the drone"""
        if not self.connected:
            return False
        
        self.status = DroneStatus.ARMED
        if self.state:
            self.state.armed = True
        self._notify_state_change()
        return True
    
    def disarm(self) -> bool:
        """Disarm the drone"""
        if self.status == DroneStatus.FLYING:
            return False  # Can't disarm while flying
        
        self.status = DroneStatus.READY
        if self.state:
            self.state.armed = False
        self._notify_state_change()
        return True
    
    def takeoff(self, altitude: float = 10.0) -> bool:
        """Take off to specified altitude"""
        if self.status != DroneStatus.ARMED:
            return False
        
        altitude = min(altitude, self.max_altitude)
        altitude = max(altitude, self.min_altitude)
        
        self.status = DroneStatus.TAKING_OFF
        self._notify_state_change()
        
        # Simulate takeoff
        if self.state:
            self.state.position = GPSCoordinate(
                self.state.position.latitude,
                self.state.position.longitude,
                altitude
            )
        
        self.status = DroneStatus.HOVERING
        self._notify_state_change()
        return True
    
    def land(self) -> bool:
        """Land the drone"""
        self.status = DroneStatus.LANDING
        self._notify_state_change()
        
        # Simulate landing
        if self.state:
            self.state.position = GPSCoordinate(
                self.state.position.latitude,
                self.state.position.longitude,
                0
            )
        
        self.status = DroneStatus.READY
        if self.state:
            self.state.armed = False
        self._notify_state_change()
        return True
    
    def return_to_home(self) -> bool:
        """Return to home position"""
        if not self.home_position:
            return False
        
        self.status = DroneStatus.RETURNING
        self._notify_state_change()
        
        # Would navigate to home
        self.goto(self.home_position)
        self.land()
        return True
    
    def goto(self, position: GPSCoordinate, speed: float = None) -> bool:
        """Go to GPS position"""
        if self.status not in [DroneStatus.FLYING, DroneStatus.HOVERING, DroneStatus.TAKING_OFF]:
            return False
        
        speed = min(speed or self.max_speed, self.max_speed)
        
        self.status = DroneStatus.FLYING
        
        # Simulate movement
        if self.state:
            self.state.position = position
            self.state.ground_speed = speed
        
        self.status = DroneStatus.HOVERING
        return True
    
    def set_altitude(self, altitude: float) -> bool:
        """Change altitude"""
        altitude = min(altitude, self.max_altitude)
        altitude = max(altitude, self.min_altitude)
        
        if self.state:
            self.state.position = GPSCoordinate(
                self.state.position.latitude,
                self.state.position.longitude,
                altitude
            )
        return True
    
    def set_heading(self, heading: float) -> bool:
        """Set drone heading"""
        heading = heading % 360
        if self.state:
            self.state.heading = heading
        return True
    
    def on_state_change(self, callback: Callable):
        """Register state change callback"""
        self._on_state_change.append(callback)
    
    def on_telemetry(self, callback: Callable):
        """Register telemetry callback"""
        self._on_telemetry.append(callback)
    
    def _notify_state_change(self):
        """Notify state change callbacks"""
        for callback in self._on_state_change:
            try:
                callback(self.status)
            except Exception:
                pass


# =============================================================================
# Mission Planner
# =============================================================================

class MissionPlanner:
    """Plan and execute drone missions"""
    
    def __init__(self, controller: DroneController):
        self.controller = controller
        self.waypoints: List[Waypoint] = []
        self.current_waypoint_index = 0
        self.mission_type: Optional[MissionType] = None
        self.mission_active = False
        self.results: List[ScanResult] = []
        
        self._mission_thread: Optional[threading.Thread] = None
    
    def create_perimeter_scan(
        self,
        center: GPSCoordinate,
        radius: float,
        altitude: float,
        num_points: int = 8
    ) -> List[Waypoint]:
        """Create perimeter scan mission"""
        self.waypoints.clear()
        self.mission_type = MissionType.PERIMETER_SCAN
        
        for i in range(num_points):
            angle = 2 * math.pi * i / num_points
            
            # Calculate point on circle
            lat = center.latitude + (radius / 111000) * math.cos(angle)
            lon = center.longitude + (radius / (111000 * math.cos(math.radians(center.latitude)))) * math.sin(angle)
            
            waypoint = Waypoint(
                position=GPSCoordinate(lat, lon, altitude),
                hold_time=5.0,
                action="scan",
                action_params={'type': 'perimeter'}
            )
            self.waypoints.append(waypoint)
        
        # Return to start
        self.waypoints.append(Waypoint(
            position=self.waypoints[0].position,
            hold_time=0
        ))
        
        return self.waypoints
    
    def create_grid_survey(
        self,
        corner1: GPSCoordinate,
        corner2: GPSCoordinate,
        altitude: float,
        overlap: float = 0.3
    ) -> List[Waypoint]:
        """Create grid survey mission for WiFi mapping"""
        self.waypoints.clear()
        self.mission_type = MissionType.WIFI_SURVEY
        
        # Calculate grid spacing based on coverage
        # Assume 50m WiFi effective scan radius
        spacing = 50 * (1 - overlap)
        
        lat_diff = corner2.latitude - corner1.latitude
        lon_diff = corner2.longitude - corner1.longitude
        
        num_lat = max(2, int(abs(lat_diff * 111000) / spacing))
        num_lon = max(2, int(abs(lon_diff * 111000 * math.cos(math.radians(corner1.latitude))) / spacing))
        
        # Generate lawnmower pattern
        for i in range(num_lat):
            lat = corner1.latitude + lat_diff * i / (num_lat - 1)
            
            lon_range = range(num_lon) if i % 2 == 0 else range(num_lon - 1, -1, -1)
            
            for j in lon_range:
                lon = corner1.longitude + lon_diff * j / (num_lon - 1)
                
                waypoint = Waypoint(
                    position=GPSCoordinate(lat, lon, altitude),
                    hold_time=3.0,
                    action="wifi_scan",
                    action_params={'type': 'grid_point'}
                )
                self.waypoints.append(waypoint)
        
        return self.waypoints
    
    def create_rf_spectrum_sweep(
        self,
        path: List[GPSCoordinate],
        altitude: float,
        freq_range: Tuple[float, float] = (2.4e9, 5.8e9)
    ) -> List[Waypoint]:
        """Create RF spectrum analysis mission"""
        self.waypoints.clear()
        self.mission_type = MissionType.RF_ANALYSIS
        
        for pos in path:
            waypoint = Waypoint(
                position=GPSCoordinate(pos.latitude, pos.longitude, altitude),
                hold_time=10.0,
                action="rf_scan",
                action_params={
                    'freq_start': freq_range[0],
                    'freq_end': freq_range[1]
                }
            )
            self.waypoints.append(waypoint)
        
        return self.waypoints
    
    def start_mission(self) -> bool:
        """Start mission execution"""
        if not self.waypoints:
            return False
        
        if not self.controller.connected:
            return False
        
        self.mission_active = True
        self.current_waypoint_index = 0
        self.results.clear()
        
        self._mission_thread = threading.Thread(target=self._execute_mission, daemon=True)
        self._mission_thread.start()
        
        return True
    
    def stop_mission(self):
        """Stop mission execution"""
        self.mission_active = False
        if self._mission_thread:
            self._mission_thread.join(timeout=5.0)
    
    def pause_mission(self):
        """Pause mission execution"""
        self.mission_active = False
    
    def resume_mission(self):
        """Resume mission execution"""
        if self.waypoints and not self.mission_active:
            self.mission_active = True
            self._mission_thread = threading.Thread(target=self._execute_mission, daemon=True)
            self._mission_thread.start()
    
    def _execute_mission(self):
        """Execute mission waypoints"""
        # Takeoff if needed
        if self.controller.status == DroneStatus.READY:
            self.controller.arm()
            self.controller.takeoff(self.waypoints[0].position.altitude)
        
        while self.mission_active and self.current_waypoint_index < len(self.waypoints):
            waypoint = self.waypoints[self.current_waypoint_index]
            
            # Navigate to waypoint
            self.controller.goto(waypoint.position)
            
            # Hold and perform action
            if waypoint.hold_time > 0:
                time.sleep(waypoint.hold_time)
            
            if waypoint.action:
                result = self._perform_action(waypoint)
                if result:
                    self.results.append(result)
            
            waypoint.completed = True
            self.current_waypoint_index += 1
        
        # Mission complete
        self.mission_active = False
    
    def _perform_action(self, waypoint: Waypoint) -> Optional[ScanResult]:
        """Perform action at waypoint"""
        action = waypoint.action
        params = waypoint.action_params
        
        if action == "wifi_scan":
            return self._simulate_wifi_scan(waypoint.position)
        elif action == "rf_scan":
            return self._simulate_rf_scan(waypoint.position, params)
        elif action == "photo":
            return self._simulate_photo(waypoint.position)
        elif action == "scan":
            return self._simulate_general_scan(waypoint.position)
        
        return None
    
    def _simulate_wifi_scan(self, position: GPSCoordinate) -> ScanResult:
        """Simulate WiFi scan"""
        networks = []
        for i in range(np.random.randint(3, 15)):
            networks.append({
                'ssid': f"Network_{np.random.randint(1000, 9999)}",
                'bssid': ':'.join([f'{np.random.randint(0, 256):02X}' for _ in range(6)]),
                'signal': -np.random.randint(40, 90),
                'channel': np.random.randint(1, 14),
                'security': np.random.choice(['WPA2', 'WPA3', 'WEP', 'Open'])
            })
        
        return ScanResult(
            timestamp=time.time(),
            position=position,
            scan_type='wifi',
            data={'networks': networks}
        )
    
    def _simulate_rf_scan(self, position: GPSCoordinate, params: Dict) -> ScanResult:
        """Simulate RF spectrum scan"""
        freq_start = params.get('freq_start', 2.4e9)
        freq_end = params.get('freq_end', 5.8e9)
        num_points = 100
        
        frequencies = np.linspace(freq_start, freq_end, num_points)
        powers = -100 + 20 * np.random.randn(num_points)
        
        # Add some signals
        signal_freqs = [2.4e9, 2.45e9, 5.2e9, 5.8e9]
        for sf in signal_freqs:
            if freq_start <= sf <= freq_end:
                idx = int((sf - freq_start) / (freq_end - freq_start) * num_points)
                if 0 <= idx < num_points:
                    powers[max(0, idx - 2):min(num_points, idx + 3)] += 40 + 10 * np.random.rand()
        
        return ScanResult(
            timestamp=time.time(),
            position=position,
            scan_type='rf_spectrum',
            data={
                'frequencies': frequencies.tolist(),
                'power_dbm': powers.tolist()
            }
        )
    
    def _simulate_photo(self, position: GPSCoordinate) -> ScanResult:
        """Simulate photo capture"""
        return ScanResult(
            timestamp=time.time(),
            position=position,
            scan_type='photo',
            data={
                'filename': f"photo_{int(time.time())}.jpg",
                'resolution': '4096x3072',
                'heading': self.controller.state.heading if self.controller.state else 0
            }
        )
    
    def _simulate_general_scan(self, position: GPSCoordinate) -> ScanResult:
        """Simulate general area scan"""
        return ScanResult(
            timestamp=time.time(),
            position=position,
            scan_type='general',
            data={
                'altitude': position.altitude,
                'visibility': 'clear',
                'observations': []
            }
        )
    
    def get_progress(self) -> Dict[str, Any]:
        """Get mission progress"""
        completed = sum(1 for wp in self.waypoints if wp.completed)
        
        return {
            'total_waypoints': len(self.waypoints),
            'completed_waypoints': completed,
            'current_waypoint': self.current_waypoint_index,
            'progress_percent': (completed / len(self.waypoints) * 100) if self.waypoints else 0,
            'active': self.mission_active,
            'results_count': len(self.results)
        }
    
    def export_results(self, filepath: str):
        """Export scan results"""
        data = {
            'mission_type': self.mission_type.name if self.mission_type else None,
            'drone_id': self.controller.drone_id,
            'waypoints': [
                {
                    'lat': wp.position.latitude,
                    'lon': wp.position.longitude,
                    'alt': wp.position.altitude,
                    'completed': wp.completed
                }
                for wp in self.waypoints
            ],
            'results': [
                {
                    'timestamp': r.timestamp,
                    'position': {
                        'lat': r.position.latitude,
                        'lon': r.position.longitude,
                        'alt': r.position.altitude
                    },
                    'scan_type': r.scan_type,
                    'data': r.data
                }
                for r in self.results
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


# =============================================================================
# Swarm Controller
# =============================================================================

class DroneSwarm:
    """Control multiple drones in formation"""
    
    def __init__(self):
        self.drones: Dict[str, DroneController] = {}
        self.formation: str = "line"  # line, triangle, grid, circle
        self.spacing: float = 20.0  # meters
        self.leader_id: Optional[str] = None
    
    def add_drone(self, drone: DroneController):
        """Add drone to swarm"""
        self.drones[drone.drone_id] = drone
        
        if self.leader_id is None:
            self.leader_id = drone.drone_id
    
    def remove_drone(self, drone_id: str):
        """Remove drone from swarm"""
        if drone_id in self.drones:
            del self.drones[drone_id]
        
        if self.leader_id == drone_id and self.drones:
            self.leader_id = list(self.drones.keys())[0]
    
    def set_formation(self, formation: str, spacing: float = None):
        """Set swarm formation"""
        self.formation = formation
        if spacing:
            self.spacing = spacing
    
    def calculate_positions(self, leader_pos: GPSCoordinate, heading: float) -> Dict[str, GPSCoordinate]:
        """Calculate positions for all drones in formation"""
        positions = {}
        drone_ids = list(self.drones.keys())
        
        if not drone_ids:
            return positions
        
        # Leader position
        positions[self.leader_id] = leader_pos
        
        followers = [d for d in drone_ids if d != self.leader_id]
        
        if self.formation == "line":
            for i, drone_id in enumerate(followers):
                # Behind leader
                offset = self.spacing * (i + 1)
                rad = math.radians(heading + 180)
                
                lat = leader_pos.latitude + (offset / 111000) * math.cos(rad)
                lon = leader_pos.longitude + (offset / (111000 * math.cos(math.radians(leader_pos.latitude)))) * math.sin(rad)
                
                positions[drone_id] = GPSCoordinate(lat, lon, leader_pos.altitude)
        
        elif self.formation == "triangle":
            for i, drone_id in enumerate(followers):
                # V formation
                side = 1 if i % 2 == 0 else -1
                row = (i // 2) + 1
                
                # Behind and to the side
                behind = self.spacing * row
                beside = self.spacing * row * side
                
                rad = math.radians(heading + 180)
                lat_offset = (behind * math.cos(rad) - beside * math.sin(rad)) / 111000
                lon_offset = (behind * math.sin(rad) + beside * math.cos(rad)) / (111000 * math.cos(math.radians(leader_pos.latitude)))
                
                positions[drone_id] = GPSCoordinate(
                    leader_pos.latitude + lat_offset,
                    leader_pos.longitude + lon_offset,
                    leader_pos.altitude
                )
        
        elif self.formation == "grid":
            grid_size = int(math.ceil(math.sqrt(len(followers))))
            for i, drone_id in enumerate(followers):
                row = i // grid_size
                col = i % grid_size
                
                lat_offset = -self.spacing * (row + 1) / 111000
                lon_offset = self.spacing * (col - grid_size // 2) / (111000 * math.cos(math.radians(leader_pos.latitude)))
                
                positions[drone_id] = GPSCoordinate(
                    leader_pos.latitude + lat_offset,
                    leader_pos.longitude + lon_offset,
                    leader_pos.altitude
                )
        
        elif self.formation == "circle":
            radius = self.spacing
            for i, drone_id in enumerate(followers):
                angle = 2 * math.pi * i / len(followers)
                
                lat = leader_pos.latitude + (radius / 111000) * math.cos(angle)
                lon = leader_pos.longitude + (radius / (111000 * math.cos(math.radians(leader_pos.latitude)))) * math.sin(angle)
                
                positions[drone_id] = GPSCoordinate(lat, lon, leader_pos.altitude)
        
        return positions
    
    def move_formation(self, target: GPSCoordinate, heading: float):
        """Move entire swarm in formation"""
        positions = self.calculate_positions(target, heading)
        
        for drone_id, position in positions.items():
            if drone_id in self.drones:
                self.drones[drone_id].goto(position)
    
    def takeoff_all(self, altitude: float = 10.0):
        """Takeoff all drones"""
        for drone in self.drones.values():
            drone.arm()
            drone.takeoff(altitude)
    
    def land_all(self):
        """Land all drones"""
        for drone in self.drones.values():
            drone.land()
    
    def return_all_home(self):
        """Return all drones to home"""
        for drone in self.drones.values():
            drone.return_to_home()


# =============================================================================
# Drone Security Manager
# =============================================================================

class DroneSecurityManager:
    """Main manager for drone security operations"""
    
    def __init__(self):
        self.controller: Optional[DroneController] = None
        self.planner: Optional[MissionPlanner] = None
        self.swarm: Optional[DroneSwarm] = None
        
        self.scan_results: List[ScanResult] = []
        self.wifi_heatmap: Dict[Tuple[float, float], List[Dict]] = {}
        self.rf_data: List[Dict] = []
    
    def initialize_drone(self, connection_string: str = None) -> bool:
        """Initialize drone connection"""
        self.controller = DroneController()
        
        if self.controller.connect(connection_string):
            self.planner = MissionPlanner(self.controller)
            return True
        
        return False
    
    def initialize_swarm(self, num_drones: int = 3) -> bool:
        """Initialize drone swarm"""
        self.swarm = DroneSwarm()
        
        for i in range(num_drones):
            drone = DroneController(f"drone_{i}")
            drone.connect()
            self.swarm.add_drone(drone)
        
        return True
    
    def start_perimeter_scan(
        self,
        center_lat: float,
        center_lon: float,
        radius: float,
        altitude: float = 30.0
    ) -> bool:
        """Start perimeter security scan"""
        if not self.planner:
            return False
        
        center = GPSCoordinate(center_lat, center_lon, altitude)
        self.planner.create_perimeter_scan(center, radius, altitude)
        return self.planner.start_mission()
    
    def start_wifi_survey(
        self,
        corner1_lat: float,
        corner1_lon: float,
        corner2_lat: float,
        corner2_lon: float,
        altitude: float = 30.0
    ) -> bool:
        """Start WiFi coverage survey"""
        if not self.planner:
            return False
        
        corner1 = GPSCoordinate(corner1_lat, corner1_lon, altitude)
        corner2 = GPSCoordinate(corner2_lat, corner2_lon, altitude)
        
        self.planner.create_grid_survey(corner1, corner2, altitude)
        return self.planner.start_mission()
    
    def start_rf_sweep(
        self,
        waypoints: List[Tuple[float, float]],
        altitude: float = 30.0,
        freq_range: Tuple[float, float] = (2.4e9, 5.8e9)
    ) -> bool:
        """Start RF spectrum sweep"""
        if not self.planner:
            return False
        
        path = [GPSCoordinate(lat, lon, altitude) for lat, lon in waypoints]
        self.planner.create_rf_spectrum_sweep(path, altitude, freq_range)
        return self.planner.start_mission()
    
    def build_wifi_heatmap(self) -> Dict[str, Any]:
        """Build WiFi signal heatmap from scan results"""
        for result in self.planner.results if self.planner else []:
            if result.scan_type == 'wifi':
                key = (
                    round(result.position.latitude, 5),
                    round(result.position.longitude, 5)
                )
                
                if key not in self.wifi_heatmap:
                    self.wifi_heatmap[key] = []
                
                self.wifi_heatmap[key].extend(result.data.get('networks', []))
        
        return {
            'points': [
                {
                    'lat': lat,
                    'lon': lon,
                    'networks': len(networks),
                    'strongest_signal': max((n['signal'] for n in networks), default=-100)
                }
                for (lat, lon), networks in self.wifi_heatmap.items()
            ]
        }
    
    def get_mission_status(self) -> Dict[str, Any]:
        """Get current mission status"""
        if not self.planner:
            return {'active': False}
        
        progress = self.planner.get_progress()
        
        return {
            **progress,
            'drone_status': self.controller.status.name if self.controller else 'OFFLINE',
            'battery': self.controller.state.battery_percent if self.controller and self.controller.state else 0,
            'position': {
                'lat': self.controller.state.position.latitude,
                'lon': self.controller.state.position.longitude,
                'alt': self.controller.state.position.altitude
            } if self.controller and self.controller.state else None
        }
    
    def emergency_stop(self):
        """Emergency stop all operations"""
        if self.planner:
            self.planner.stop_mission()
        
        if self.controller:
            self.controller.return_to_home()
        
        if self.swarm:
            self.swarm.return_all_home()
    
    def export_all_results(self, filepath: str):
        """Export all scan results"""
        if self.planner:
            self.planner.export_results(filepath)


# Global instance
drone_manager = DroneSecurityManager()


def get_drone_manager() -> DroneSecurityManager:
    """Get global drone manager"""
    return drone_manager
