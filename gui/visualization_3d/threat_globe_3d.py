"""
3D Threat Globe Visualization

Interactive 3D globe showing:
- Real-time attack origins and targets
- Threat feeds visualization
- Geographic IP mapping
- Attack flow arcs
- Heatmaps of threat activity
"""

import math
import time
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum

from PyQt6.QtCore import Qt, QTimer, pyqtSignal

from .engine_3d import (
    Visualization3DEngine, Scene3D, Object3D, Mesh3D, Material3D,
    Light3D, Camera3D, LightType
)


class ThreatSeverity(Enum):
    """Threat severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Types of threats"""
    MALWARE = "malware"
    PHISHING = "phishing"
    DDOS = "ddos"
    INTRUSION = "intrusion"
    RANSOMWARE = "ransomware"
    APT = "apt"
    BOTNET = "botnet"
    EXPLOIT = "exploit"
    SCAN = "scan"
    BRUTEFORCE = "bruteforce"


@dataclass
class GeoLocation:
    """Geographic location"""
    latitude: float
    longitude: float
    country: str = ""
    country_code: str = ""
    city: str = ""
    region: str = ""
    
    def to_3d(self, radius: float = 10.0) -> Tuple[float, float, float]:
        """Convert lat/lon to 3D coordinates on sphere"""
        lat_rad = math.radians(self.latitude)
        lon_rad = math.radians(self.longitude)
        
        x = radius * math.cos(lat_rad) * math.cos(lon_rad)
        y = radius * math.sin(lat_rad)
        z = radius * math.cos(lat_rad) * math.sin(lon_rad)
        
        return (x, y, z)


@dataclass
class ThreatEvent:
    """Single threat event"""
    id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    
    source: GeoLocation
    target: GeoLocation
    
    timestamp: float = 0.0
    description: str = ""
    
    # Metadata
    source_ip: str = ""
    target_ip: str = ""
    port: int = 0
    protocol: str = ""
    
    # Visualization
    object_3d: Optional[Object3D] = None
    arc_object: Optional[Object3D] = None
    
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatCluster:
    """Cluster of threats in a region"""
    location: GeoLocation
    events: List[ThreatEvent] = field(default_factory=list)
    total_count: int = 0
    severity_distribution: Dict[ThreatSeverity, int] = field(default_factory=dict)
    
    object_3d: Optional[Object3D] = None


class ThreatGlobe3D(Visualization3DEngine):
    """3D Threat Globe Visualization"""
    
    eventClicked = pyqtSignal(object)
    countryClicked = pyqtSignal(str)
    statsUpdated = pyqtSignal(dict)
    
    # Severity colors
    SEVERITY_COLORS = {
        ThreatSeverity.INFO: (0.3, 0.5, 0.8),
        ThreatSeverity.LOW: (0.2, 0.7, 0.3),
        ThreatSeverity.MEDIUM: (0.9, 0.7, 0.1),
        ThreatSeverity.HIGH: (0.9, 0.4, 0.1),
        ThreatSeverity.CRITICAL: (0.9, 0.1, 0.1),
    }
    
    # Threat type colors
    THREAT_COLORS = {
        ThreatType.MALWARE: (0.8, 0.2, 0.2),
        ThreatType.PHISHING: (0.9, 0.6, 0.1),
        ThreatType.DDOS: (0.2, 0.2, 0.8),
        ThreatType.INTRUSION: (0.8, 0.3, 0.5),
        ThreatType.RANSOMWARE: (0.9, 0.1, 0.3),
        ThreatType.APT: (0.5, 0.1, 0.5),
        ThreatType.BOTNET: (0.3, 0.3, 0.3),
        ThreatType.EXPLOIT: (0.7, 0.3, 0.1),
        ThreatType.SCAN: (0.4, 0.6, 0.8),
        ThreatType.BRUTEFORCE: (0.6, 0.4, 0.2),
    }
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.events: Dict[str, ThreatEvent] = {}
        self.clusters: Dict[str, ThreatCluster] = {}
        
        # Globe settings
        self.globe_radius = 10.0
        self.atmosphere_radius = 10.5
        
        # Animation
        self.auto_rotate = True
        self.rotation_speed = 5.0
        
        # Event queue for animation
        self.event_queue: List[ThreatEvent] = []
        self.max_visible_arcs = 100
        
        # Stats
        self.stats = {
            "total_events": 0,
            "events_by_severity": {},
            "events_by_type": {},
            "top_sources": [],
            "top_targets": []
        }
        
        # Setup
        self._setup_scene()
    
    def _setup_scene(self):
        """Setup the 3D scene"""
        self.scene.background_color = (0.0, 0.0, 0.02)
        self.scene.ambient_color = (0.05, 0.05, 0.1)
        
        # Add globe
        self._create_globe()
        
        # Add atmosphere glow
        self._create_atmosphere()
        
        # Add lighting
        self._setup_lighting()
        
        # Set camera
        self.scene.camera.position = (25, 10, 25)
        self.scene.camera.target = (0, 0, 0)
    
    def _create_globe(self):
        """Create the Earth globe"""
        # Main globe
        globe_mesh = Mesh3D.create_sphere(self.globe_radius, 64, 32)
        
        globe_material = Material3D(
            name="globe",
            albedo=(0.1, 0.2, 0.4),
            metallic=0.2,
            roughness=0.8,
            emission=(0.0, 0.05, 0.1),
            emission_strength=0.3
        )
        
        globe = Object3D(
            name="globe",
            mesh=globe_mesh,
            material=globe_material,
            data={"type": "globe"}
        )
        
        # Auto-rotation animation
        def animate_globe(obj: Object3D, dt: float):
            if self.auto_rotate:
                obj.rotation = (
                    obj.rotation[0],
                    obj.rotation[1] + self.rotation_speed * dt,
                    obj.rotation[2]
                )
        
        globe.animation_callback = animate_globe
        
        self.scene.add_object(globe)
        
        # Add latitude/longitude grid
        self._create_globe_grid()
    
    def _create_globe_grid(self):
        """Create latitude/longitude grid lines"""
        grid_vertices = []
        
        # Latitude lines
        for lat in range(-60, 90, 30):
            lat_rad = math.radians(lat)
            r = self.globe_radius * math.cos(lat_rad) * 1.01
            y = self.globe_radius * math.sin(lat_rad) * 1.01
            
            for i in range(73):
                lon = i * 5
                lon_rad = math.radians(lon)
                x = r * math.cos(lon_rad)
                z = r * math.sin(lon_rad)
                grid_vertices.extend([x, y, z])
        
        # Longitude lines
        for lon in range(0, 360, 30):
            lon_rad = math.radians(lon)
            
            for i in range(37):
                lat = -90 + i * 5
                lat_rad = math.radians(lat)
                
                r = self.globe_radius * 1.01
                x = r * math.cos(lat_rad) * math.cos(lon_rad)
                y = r * math.sin(lat_rad)
                z = r * math.cos(lat_rad) * math.sin(lon_rad)
                grid_vertices.extend([x, y, z])
        
        # Create indices for line segments
        indices = []
        idx = 0
        
        # Latitude indices
        for _ in range(5):  # 5 latitude lines
            for i in range(72):
                indices.extend([idx + i, idx + i + 1])
            idx += 73
        
        # Longitude indices
        for _ in range(12):  # 12 longitude lines
            for i in range(36):
                indices.extend([idx + i, idx + i + 1])
            idx += 37
        
        grid_mesh = Mesh3D(
            vertices=np.array(grid_vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        grid_material = Material3D(
            name="globe_grid",
            albedo=(0.2, 0.4, 0.6),
            emission=(0.1, 0.2, 0.3),
            emission_strength=0.5,
            opacity=0.3,
            wireframe=True
        )
        
        grid = Object3D(
            name="globe_grid",
            mesh=grid_mesh,
            material=grid_material
        )
        
        self.scene.add_object(grid)
    
    def _create_atmosphere(self):
        """Create atmospheric glow effect"""
        atmo_mesh = Mesh3D.create_sphere(self.atmosphere_radius, 32, 16)
        
        atmo_material = Material3D(
            name="atmosphere",
            albedo=(0.3, 0.5, 0.8),
            emission=(0.2, 0.4, 0.7),
            emission_strength=0.3,
            opacity=0.15,
            double_sided=True
        )
        
        atmosphere = Object3D(
            name="atmosphere",
            mesh=atmo_mesh,
            material=atmo_material
        )
        
        self.scene.add_object(atmosphere)
    
    def _setup_lighting(self):
        """Setup scene lighting"""
        # Sun light (directional)
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(50, 30, 50),
            color=(1.0, 0.95, 0.9),
            intensity=200.0
        ))
        
        # Ambient fill
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(-30, -20, -30),
            color=(0.3, 0.4, 0.5),
            intensity=50.0
        ))
    
    def add_event(self, event: ThreatEvent, animate: bool = True):
        """Add a threat event"""
        self.events[event.id] = event
        
        # Update stats
        self.stats["total_events"] += 1
        self.stats["events_by_severity"][event.severity.value] = \
            self.stats["events_by_severity"].get(event.severity.value, 0) + 1
        self.stats["events_by_type"][event.threat_type.value] = \
            self.stats["events_by_type"].get(event.threat_type.value, 0) + 1
        
        # Create source marker
        source_pos = event.source.to_3d(self.globe_radius + 0.1)
        source_marker = self._create_marker(event, source_pos, is_source=True)
        event.object_3d = source_marker
        self.scene.add_object(source_marker)
        
        # Create attack arc
        if animate:
            self._create_attack_arc(event)
        
        # Emit stats update
        self.statsUpdated.emit(self.stats)
    
    def _create_marker(self, event: ThreatEvent, position: Tuple[float, float, float],
                       is_source: bool = True) -> Object3D:
        """Create a marker for threat source/target"""
        # Size based on severity
        size_map = {
            ThreatSeverity.INFO: 0.1,
            ThreatSeverity.LOW: 0.15,
            ThreatSeverity.MEDIUM: 0.2,
            ThreatSeverity.HIGH: 0.25,
            ThreatSeverity.CRITICAL: 0.3,
        }
        size = size_map.get(event.severity, 0.15)
        
        mesh = Mesh3D.create_sphere(size, 8, 4)
        
        color = self.SEVERITY_COLORS.get(event.severity, (0.5, 0.5, 0.5))
        
        material = Material3D(
            name=f"marker_{event.id}",
            albedo=color,
            emission=color,
            emission_strength=1.5,
            metallic=0.0,
            roughness=1.0
        )
        
        marker = Object3D(
            name=f"marker_{event.id}",
            mesh=mesh,
            material=material,
            position=position,
            data={"event_id": event.id, "type": "marker"}
        )
        
        # Pulsing animation
        def animate_marker(obj: Object3D, dt: float):
            pulse = math.sin(time.time() * 4) * 0.3 + 1.0
            obj.scale = (pulse, pulse, pulse)
        
        marker.animation_callback = animate_marker
        
        return marker
    
    def _create_attack_arc(self, event: ThreatEvent):
        """Create animated attack arc between source and target"""
        source_pos = event.source.to_3d(self.globe_radius)
        target_pos = event.target.to_3d(self.globe_radius)
        
        # Calculate arc
        arc_vertices = self._calculate_arc(source_pos, target_pos)
        
        if len(arc_vertices) < 6:
            return
        
        # Create mesh
        indices = []
        for i in range(len(arc_vertices) // 3 - 1):
            indices.extend([i, i + 1])
        
        mesh = Mesh3D(
            vertices=np.array(arc_vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        color = self.THREAT_COLORS.get(event.threat_type, self.SEVERITY_COLORS.get(event.severity, (0.5, 0.5, 0.5)))
        
        material = Material3D(
            name=f"arc_{event.id}",
            albedo=color,
            emission=color,
            emission_strength=1.0,
            opacity=0.8,
            wireframe=True
        )
        
        arc = Object3D(
            name=f"arc_{event.id}",
            mesh=mesh,
            material=material,
            data={"event_id": event.id, "type": "arc"}
        )
        
        # Animation - fade out over time
        start_time = time.time()
        
        def animate_arc(obj: Object3D, dt: float):
            elapsed = time.time() - start_time
            # Fade out after 5 seconds
            if elapsed > 3:
                fade = max(0, 1 - (elapsed - 3) / 2)
                obj.material.opacity = 0.8 * fade
                obj.material.emission_strength = fade
                
                if fade <= 0:
                    self.scene.remove_object(obj)
        
        arc.animation_callback = animate_arc
        
        event.arc_object = arc
        self.scene.add_object(arc)
    
    def _calculate_arc(self, start: Tuple[float, float, float],
                       end: Tuple[float, float, float],
                       segments: int = 50) -> List[float]:
        """Calculate arc points between two positions"""
        vertices = []
        
        start_vec = np.array(start)
        end_vec = np.array(end)
        
        # Calculate arc height based on distance
        distance = np.linalg.norm(end_vec - start_vec)
        arc_height = min(5.0, distance * 0.3)
        
        for i in range(segments + 1):
            t = i / segments
            
            # Spherical interpolation
            omega = math.acos(np.clip(np.dot(start_vec, end_vec) / 
                                      (np.linalg.norm(start_vec) * np.linalg.norm(end_vec)), -1, 1))
            
            if omega < 0.001:
                point = start_vec * (1 - t) + end_vec * t
            else:
                point = (math.sin((1 - t) * omega) * start_vec + 
                        math.sin(t * omega) * end_vec) / math.sin(omega)
            
            # Add height (arc above globe)
            height = arc_height * math.sin(t * math.pi)
            point = point * (1 + height / self.globe_radius)
            
            vertices.extend(point.tolist())
        
        return vertices
    
    def add_cluster(self, cluster: ThreatCluster):
        """Add a threat cluster (aggregated events)"""
        self.clusters[f"{cluster.location.latitude}_{cluster.location.longitude}"] = cluster
        
        # Create cluster visualization
        pos = cluster.location.to_3d(self.globe_radius + 0.2)
        
        # Size based on event count
        size = min(1.0, 0.2 + cluster.total_count * 0.02)
        
        mesh = Mesh3D.create_sphere(size, 16, 8)
        
        # Color based on highest severity
        max_severity = ThreatSeverity.INFO
        for sev in ThreatSeverity:
            if cluster.severity_distribution.get(sev, 0) > 0:
                max_severity = sev
        
        color = self.SEVERITY_COLORS.get(max_severity, (0.5, 0.5, 0.5))
        
        material = Material3D(
            name=f"cluster_{cluster.location.city}",
            albedo=color,
            emission=color,
            emission_strength=1.0 + cluster.total_count * 0.1,
            opacity=0.8
        )
        
        cluster_obj = Object3D(
            name=f"cluster_{cluster.location.city}",
            mesh=mesh,
            material=material,
            position=pos,
            data={"type": "cluster", "location": cluster.location}
        )
        
        # Pulsing animation
        def animate_cluster(obj: Object3D, dt: float):
            pulse = math.sin(time.time() * 2) * 0.2 + 1.0
            obj.scale = (pulse, pulse, pulse)
        
        cluster_obj.animation_callback = animate_cluster
        
        cluster.object_3d = cluster_obj
        self.scene.add_object(cluster_obj)
    
    def set_auto_rotate(self, enabled: bool):
        """Enable/disable auto rotation"""
        self.auto_rotate = enabled
    
    def set_rotation_speed(self, speed: float):
        """Set rotation speed"""
        self.rotation_speed = speed
    
    def focus_on_location(self, location: GeoLocation):
        """Focus camera on a geographic location"""
        pos = location.to_3d(self.globe_radius)
        
        # Calculate camera position
        direction = np.array(pos) / np.linalg.norm(pos)
        camera_pos = direction * 25
        
        self.scene.camera.position = tuple(camera_pos)
        self.scene.camera.target = (0, 0, 0)
        
        # Temporarily stop rotation
        self.auto_rotate = False
    
    def focus_on_country(self, country_code: str):
        """Focus on a country"""
        # Common country coordinates (simplified)
        country_coords = {
            "US": (38.0, -97.0),
            "CN": (35.0, 105.0),
            "RU": (60.0, 100.0),
            "DE": (51.0, 9.0),
            "GB": (54.0, -2.0),
            "FR": (46.0, 2.0),
            "JP": (36.0, 138.0),
            "AU": (-25.0, 135.0),
            "BR": (-10.0, -55.0),
            "IN": (20.0, 77.0),
        }
        
        coords = country_coords.get(country_code.upper())
        if coords:
            location = GeoLocation(latitude=coords[0], longitude=coords[1], country_code=country_code)
            self.focus_on_location(location)
    
    def get_events_by_country(self, country_code: str) -> List[ThreatEvent]:
        """Get all events for a country"""
        return [e for e in self.events.values() 
                if e.source.country_code == country_code or 
                   e.target.country_code == country_code]
    
    def clear_events(self, older_than: float = None):
        """Clear events, optionally older than a timestamp"""
        to_remove = []
        
        for event_id, event in self.events.items():
            if older_than is None or event.timestamp < older_than:
                to_remove.append(event_id)
                
                if event.object_3d:
                    self.scene.remove_object(event.object_3d)
                if event.arc_object:
                    self.scene.remove_object(event.arc_object)
        
        for event_id in to_remove:
            del self.events[event_id]
    
    def simulate_live_feed(self, events_per_second: float = 2.0):
        """Simulate a live threat feed"""
        import random
        
        countries = [
            ("US", 38.0, -97.0),
            ("CN", 35.0, 105.0),
            ("RU", 60.0, 100.0),
            ("DE", 51.0, 9.0),
            ("GB", 54.0, -2.0),
            ("FR", 46.0, 2.0),
            ("JP", 36.0, 138.0),
            ("BR", -10.0, -55.0),
            ("IN", 20.0, 77.0),
            ("AU", -25.0, 135.0),
            ("KR", 36.0, 128.0),
            ("IR", 32.0, 53.0),
            ("NL", 52.0, 5.0),
            ("UA", 49.0, 32.0),
        ]
        
        def generate_event():
            source_country = random.choice(countries)
            target_country = random.choice([c for c in countries if c[0] != source_country[0]])
            
            # Add some randomness to coordinates
            source = GeoLocation(
                latitude=source_country[1] + random.uniform(-5, 5),
                longitude=source_country[2] + random.uniform(-5, 5),
                country_code=source_country[0]
            )
            target = GeoLocation(
                latitude=target_country[1] + random.uniform(-5, 5),
                longitude=target_country[2] + random.uniform(-5, 5),
                country_code=target_country[0]
            )
            
            event = ThreatEvent(
                id=f"event_{int(time.time() * 1000)}_{random.randint(0, 9999)}",
                threat_type=random.choice(list(ThreatType)),
                severity=random.choice(list(ThreatSeverity)),
                source=source,
                target=target,
                timestamp=time.time()
            )
            
            self.add_event(event)
        
        # Create timer
        interval = int(1000 / events_per_second)
        
        self.feed_timer = QTimer()
        self.feed_timer.timeout.connect(generate_event)
        self.feed_timer.start(interval)
    
    def stop_live_feed(self):
        """Stop the simulated live feed"""
        if hasattr(self, 'feed_timer'):
            self.feed_timer.stop()
