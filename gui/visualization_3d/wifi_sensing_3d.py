"""
3D WiFi Sensing Visualization

Interactive 3D visualization of:
- Indoor localization
- WiFi signal propagation
- Human presence detection
- Breathing/movement patterns
- CSI data visualization
- Environment reconstruction
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


class SensorType(Enum):
    """WiFi sensor types"""
    ACCESS_POINT = "ap"
    ROUTER = "router"
    IOT_DEVICE = "iot"
    MOBILE = "mobile"
    LAPTOP = "laptop"
    STATION = "station"


class DetectionType(Enum):
    """Detection types"""
    PRESENCE = "presence"
    MOVEMENT = "movement"
    BREATHING = "breathing"
    GESTURE = "gesture"
    ACTIVITY = "activity"


@dataclass
class WifiSensor:
    """WiFi sensor/device"""
    id: str
    sensor_type: SensorType
    position: Tuple[float, float, float]
    name: str = ""
    
    # Signal properties
    signal_strength: float = -50.0  # dBm
    frequency: float = 2.4  # GHz
    channel: int = 1
    
    # CSI data
    csi_data: Optional[np.ndarray] = None
    
    # Visualization
    object_3d: Optional[Object3D] = None
    signal_object: Optional[Object3D] = None
    
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectedEntity:
    """Detected entity (person, object)"""
    id: str
    detection_type: DetectionType
    position: Tuple[float, float, float]
    
    # Confidence
    confidence: float = 0.0
    
    # Movement
    velocity: Tuple[float, float, float] = (0, 0, 0)
    
    # Biometrics
    breathing_rate: float = 0.0
    heart_rate: float = 0.0
    
    # Tracking
    track_history: List[Tuple[float, float, float]] = field(default_factory=list)
    
    object_3d: Optional[Object3D] = None
    track_object: Optional[Object3D] = None


@dataclass
class Room:
    """Room definition for indoor space"""
    id: str
    name: str
    
    # Bounds (min_x, min_y, min_z, max_x, max_y, max_z)
    bounds: Tuple[float, float, float, float, float, float]
    
    # Properties
    floor_level: float = 0.0
    ceiling_height: float = 3.0
    
    object_3d: Optional[Object3D] = None
    
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Zone3D:
    """Spatial zone for presence detection visualization."""
    id: str
    name: str
    bounds: Tuple[float, float, float, float, float, float]
    color: Tuple[float, float, float] = (0.2, 0.6, 0.9)
    object_3d: Optional[Object3D] = None


class WifiSensing3D(Visualization3DEngine):
    """3D WiFi Sensing Visualization"""
    
    sensorClicked = pyqtSignal(object)
    entityDetected = pyqtSignal(object)
    positionEstimated = pyqtSignal(tuple)
    
    # Colors
    SENSOR_COLORS = {
        SensorType.ACCESS_POINT: (0.0, 0.8, 0.4),
        SensorType.ROUTER: (0.2, 0.6, 0.9),
        SensorType.IOT_DEVICE: (0.9, 0.6, 0.2),
        SensorType.MOBILE: (0.8, 0.3, 0.6),
        SensorType.LAPTOP: (0.5, 0.5, 0.8),
        SensorType.STATION: (0.6, 0.8, 0.3),
    }
    
    DETECTION_COLORS = {
        DetectionType.PRESENCE: (0.3, 0.9, 0.5),
        DetectionType.MOVEMENT: (0.9, 0.6, 0.1),
        DetectionType.BREATHING: (0.5, 0.8, 0.9),
        DetectionType.GESTURE: (0.9, 0.4, 0.7),
        DetectionType.ACTIVITY: (0.7, 0.5, 0.9),
    }
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.sensors: Dict[str, WifiSensor] = {}
        self.entities: Dict[str, DetectedEntity] = {}
        self.rooms: Dict[str, Room] = {}
        self.zones: Dict[str, Zone3D] = {}
        
        # Visualization settings
        self.show_signals = True
        self.show_csi = True
        self.show_heatmap = True
        self.show_tracks = True
        self.show_fog = True
        self.show_breathing_halo = True
        self.show_zones = True
        self.show_gesture_indicator = True
        self.show_heart_rate = True
        
        # Signal visualization
        self.signal_objects: List[Object3D] = []
        
        # Heatmap
        self.heatmap_resolution = 50
        self.heatmap_data: Optional[np.ndarray] = None
        self.heatmap_object: Optional[Object3D] = None
        
        self._setup_scene()
    
    def _setup_scene(self):
        """Setup the 3D scene"""
        self.scene.background_color = (0.02, 0.02, 0.05)
        self.scene.ambient_color = (0.1, 0.1, 0.15)
        
        # Setup lighting
        self._setup_lighting()
        
        # Set camera for room view
        self.scene.camera.position = (15, 20, 15)
        self.scene.camera.target = (0, 1, 0)
        
        # Add floor grid
        self._create_floor_grid()
    
    def _setup_lighting(self):
        """Setup scene lighting"""
        # Main overhead light
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(0, 10, 0),
            color=(1.0, 0.98, 0.95),
            intensity=150.0
        ))
        
        # Fill lights
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(10, 5, 10),
            color=(0.7, 0.8, 1.0),
            intensity=50.0
        ))
        
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(-10, 5, -10),
            color=(0.7, 0.8, 1.0),
            intensity=50.0
        ))
    
    def _create_floor_grid(self):
        """Create floor grid"""
        vertices = []
        indices = []
        
        grid_size = 20
        cell_size = 1.0
        
        idx = 0
        for i in range(-grid_size, grid_size + 1):
            # X lines
            vertices.extend([i * cell_size, 0, -grid_size * cell_size])
            vertices.extend([i * cell_size, 0, grid_size * cell_size])
            indices.extend([idx, idx + 1])
            idx += 2
            
            # Z lines
            vertices.extend([-grid_size * cell_size, 0, i * cell_size])
            vertices.extend([grid_size * cell_size, 0, i * cell_size])
            indices.extend([idx, idx + 1])
            idx += 2
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name="floor_grid",
            albedo=(0.2, 0.3, 0.4),
            emission=(0.1, 0.15, 0.2),
            emission_strength=0.3,
            opacity=0.4,
            wireframe=True
        )
        
        grid = Object3D(
            name="floor_grid",
            mesh=mesh,
            material=material
        )
        
        self.scene.add_object(grid)
    
    def add_room(self, room: Room):
        """Add a room to the visualization"""
        self.rooms[room.id] = room
        
        # Create room wireframe
        min_x, min_y, min_z, max_x, max_y, max_z = room.bounds
        
        # Wall vertices
        vertices = [
            # Floor corners
            min_x, min_y, min_z,
            max_x, min_y, min_z,
            max_x, min_y, max_z,
            min_x, min_y, max_z,
            # Ceiling corners
            min_x, max_y, min_z,
            max_x, max_y, min_z,
            max_x, max_y, max_z,
            min_x, max_y, max_z,
        ]
        
        # Edges
        indices = [
            # Floor
            0, 1, 1, 2, 2, 3, 3, 0,
            # Ceiling
            4, 5, 5, 6, 6, 7, 7, 4,
            # Walls
            0, 4, 1, 5, 2, 6, 3, 7,
        ]
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=f"room_{room.id}",
            albedo=(0.3, 0.4, 0.5),
            emission=(0.1, 0.2, 0.3),
            emission_strength=0.3,
            opacity=0.6,
            wireframe=True
        )
        
        room_obj = Object3D(
            name=f"room_{room.id}",
            mesh=mesh,
            material=material,
            data={"type": "room", "room_id": room.id}
        )
        
        room.object_3d = room_obj
        self.scene.add_object(room_obj)
        
        # Create floor
        self._create_room_floor(room)
    
    def _create_room_floor(self, room: Room):
        """Create semi-transparent floor for room"""
        min_x, min_y, min_z, max_x, max_y, max_z = room.bounds
        
        mesh = Mesh3D.create_plane(max_x - min_x, max_z - min_z)
        
        material = Material3D(
            name=f"floor_{room.id}",
            albedo=(0.15, 0.2, 0.25),
            metallic=0.1,
            roughness=0.9,
            opacity=0.3
        )
        
        center_x = (min_x + max_x) / 2
        center_z = (min_z + max_z) / 2
        
        floor = Object3D(
            name=f"floor_{room.id}",
            mesh=mesh,
            material=material,
            position=(center_x, min_y + 0.01, center_z),
            rotation=(-90, 0, 0)
        )
        
        self.scene.add_object(floor)
    
    def add_sensor(self, sensor: WifiSensor):
        """Add a WiFi sensor"""
        self.sensors[sensor.id] = sensor
        
        # Create sensor visualization
        sensor_obj = self._create_sensor_object(sensor)
        sensor.object_3d = sensor_obj
        self.scene.add_object(sensor_obj)
        
        # Create signal visualization
        if self.show_signals:
            self._create_signal_visualization(sensor)
    
    def _create_sensor_object(self, sensor: WifiSensor) -> Object3D:
        """Create 3D object for sensor"""
        # Size based on type
        size_map = {
            SensorType.ACCESS_POINT: 0.4,
            SensorType.ROUTER: 0.5,
            SensorType.IOT_DEVICE: 0.2,
            SensorType.MOBILE: 0.15,
            SensorType.LAPTOP: 0.3,
            SensorType.STATION: 0.35,
        }
        size = size_map.get(sensor.sensor_type, 0.3)
        
        # Shape based on type
        if sensor.sensor_type in [SensorType.ACCESS_POINT, SensorType.ROUTER]:
            mesh = Mesh3D.create_box(size, size * 0.5, size)
        else:
            mesh = Mesh3D.create_sphere(size, 16, 8)
        
        color = self.SENSOR_COLORS.get(sensor.sensor_type, (0.5, 0.5, 0.5))
        
        material = Material3D(
            name=f"sensor_{sensor.id}",
            albedo=color,
            emission=color,
            emission_strength=0.8,
            metallic=0.3,
            roughness=0.5
        )
        
        sensor_obj = Object3D(
            name=f"sensor_{sensor.id}",
            mesh=mesh,
            material=material,
            position=sensor.position,
            data={"type": "sensor", "sensor_id": sensor.id}
        )
        
        # Pulsing animation for active sensors
        def animate_sensor(obj: Object3D, dt: float):
            pulse = math.sin(time.time() * 3) * 0.1 + 1.0
            strength = 0.5 + pulse * 0.3
            obj.material.emission_strength = strength
        
        sensor_obj.animation_callback = animate_sensor
        
        return sensor_obj
    
    def _create_signal_visualization(self, sensor: WifiSensor):
        """Create signal propagation visualization"""
        # Calculate signal range based on strength
        # Approximate: stronger signal = smaller visual radius (closer)
        max_range = 10.0  # meters
        range_factor = min(1.0, (-sensor.signal_strength + 30) / 60)
        signal_range = max_range * range_factor
        
        # Create expanding rings
        for i in range(3):
            ring_radius = signal_range * (0.3 + i * 0.35)
            
            vertices = []
            indices = []
            
            segments = 32
            for j in range(segments):
                angle = (j / segments) * 2 * math.pi
                x = sensor.position[0] + ring_radius * math.cos(angle)
                z = sensor.position[2] + ring_radius * math.sin(angle)
                vertices.extend([x, sensor.position[1], z])
            
            for j in range(segments):
                indices.extend([j, (j + 1) % segments])
            
            mesh = Mesh3D(
                vertices=np.array(vertices, dtype=np.float32),
                indices=np.array(indices, dtype=np.uint32)
            )
            
            color = self.SENSOR_COLORS.get(sensor.sensor_type, (0.5, 0.5, 0.5))
            alpha = 0.6 - i * 0.15
            
            material = Material3D(
                name=f"signal_{sensor.id}_{i}",
                albedo=color,
                emission=color,
                emission_strength=0.5 - i * 0.1,
                opacity=alpha,
                wireframe=True
            )
            
            ring = Object3D(
                name=f"signal_{sensor.id}_{i}",
                mesh=mesh,
                material=material,
                data={"type": "signal"}
            )
            
            # Expanding animation
            base_scale = 1.0
            ring_idx = i
            
            def animate_ring(obj: Object3D, dt: float, idx=ring_idx):
                t = (time.time() + idx * 0.3) % 2.0
                scale = 1.0 + t * 0.2
                obj.scale = (scale, 1, scale)
                obj.material.opacity = max(0, 0.6 - idx * 0.15 - t * 0.2)
            
            ring.animation_callback = animate_ring
            
            self.signal_objects.append(ring)
            self.scene.add_object(ring)
    
    def add_entity(self, entity: DetectedEntity):
        """Add a detected entity"""
        self.entities[entity.id] = entity
        
        # Create entity visualization
        entity_obj = self._create_entity_object(entity)
        entity.object_3d = entity_obj
        self.scene.add_object(entity_obj)
        
        # Create track visualization
        if self.show_tracks and entity.track_history:
            self._create_track_visualization(entity)
        
        self.entityDetected.emit(entity)
    
    def remove_entity(self, entity_id: str):
        """Remove a tracked entity from the scene."""
        if entity_id not in self.entities:
            return
        
        entity = self.entities[entity_id]
        
        # Remove 3D object from scene
        if entity.object_3d:
            try:
                self.scene.remove_object(entity.object_3d)
            except:
                pass
        
        # Remove track object if exists
        if hasattr(entity, 'track_object') and entity.track_object:
            try:
                self.scene.remove_object(entity.track_object)
            except:
                pass
        
        # Remove from entities dict
        del self.entities[entity_id]
    
    def _create_entity_object(self, entity: DetectedEntity) -> Object3D:
        """Create 3D object for detected entity"""
        # Human silhouette
        mesh = self._create_human_mesh()
        
        color = self.DETECTION_COLORS.get(entity.detection_type, (0.5, 0.8, 0.5))
        
        # Opacity based on confidence
        opacity = 0.3 + entity.confidence * 0.6
        
        material = Material3D(
            name=f"entity_{entity.id}",
            albedo=color,
            emission=color,
            emission_strength=0.5 + entity.confidence * 0.5,
            opacity=opacity
        )
        
        entity_obj = Object3D(
            name=f"entity_{entity.id}",
            mesh=mesh,
            material=material,
            position=entity.position,
            data={"type": "entity", "entity_id": entity.id}
        )
        
        # Breathing animation if detected
        if entity.detection_type == DetectionType.BREATHING and entity.breathing_rate > 0:
            breath_rate = entity.breathing_rate / 60.0  # breaths per second
            
            def animate_breathing(obj: Object3D, dt: float, rate=breath_rate):
                breath = math.sin(time.time() * rate * 2 * math.pi) * 0.05 + 1.0
                obj.scale = (1, breath, 1)
            
            entity_obj.animation_callback = animate_breathing

            # Add subtle breathing halo if enabled
            if self.show_breathing_halo:
                halo = self._create_breathing_indicator(entity, color)
                if halo:
                    self.scene.add_object(halo)
                    entity.track_object = halo
        
        return entity_obj

    def _create_breathing_indicator(self, entity: DetectedEntity, color: Tuple[float, float, float]) -> Optional[Object3D]:
        """Create a thin halo that pulses with breathing rate."""
        rate = max(0.1, entity.breathing_rate / 60.0)

        ring_vertices = []
        ring_indices = []
        segments = 48
        radius = 0.6
        for i in range(segments):
            angle = (i / segments) * 2 * math.pi
            x = entity.position[0] + radius * math.cos(angle)
            z = entity.position[2] + radius * math.sin(angle)
            ring_vertices.extend([x, entity.position[1] + 0.05, z])
        for i in range(segments):
            ring_indices.extend([i, (i + 1) % segments])

        mesh = Mesh3D(
            vertices=np.array(ring_vertices, dtype=np.float32),
            indices=np.array(ring_indices, dtype=np.uint32)
        )
        mat = Material3D(
            name=f"breathing_{entity.id}",
            albedo=color,
            emission=color,
            emission_strength=0.8,
            opacity=0.5,
            wireframe=True,
        )
        halo = Object3D(
            name=f"breathing_{entity.id}",
            mesh=mesh,
            material=mat,
            data={"type": "breathing_halo", "entity_id": entity.id}
        )

        def animate_halo(obj: Object3D, dt: float):
            t = time.time() * rate * 2 * math.pi
            scale = 1.0 + math.sin(t) * 0.08
            obj.scale = (scale, 1, scale)
            obj.material.opacity = 0.3 + 0.2 * (1 + math.sin(t))

        halo.animation_callback = animate_halo
        return halo
    
    def _create_human_mesh(self) -> Mesh3D:
        """Create simplified human silhouette mesh"""
        # Capsule-like shape for human
        vertices = []
        indices = []
        
        # Body (cylinder)
        segments = 12
        height = 1.7
        radius = 0.25
        
        for i in range(segments):
            angle = (i / segments) * 2 * math.pi
            x = radius * math.cos(angle)
            z = radius * math.sin(angle)
            
            # Bottom
            vertices.extend([x, 0.3, z])
            # Middle
            vertices.extend([x, height * 0.6, z])
            # Top (narrower)
            vertices.extend([x * 0.8, height * 0.85, z * 0.8])
        
        # Head (sphere-ish)
        head_y = height * 0.9
        head_radius = 0.15
        
        for i in range(segments):
            angle = (i / segments) * 2 * math.pi
            x = head_radius * math.cos(angle)
            z = head_radius * math.sin(angle)
            vertices.extend([x, head_y, z])
        
        # Top of head
        vertices.extend([0, height, 0])
        
        # Create indices for body
        for i in range(segments):
            next_i = (i + 1) % segments
            
            # Bottom to middle quad
            base = i * 3
            next_base = next_i * 3
            indices.extend([
                base, next_base, base + 1,
                next_base, next_base + 1, base + 1
            ])
            
            # Middle to top quad
            indices.extend([
                base + 1, next_base + 1, base + 2,
                next_base + 1, next_base + 2, base + 2
            ])
        
        # Head indices
        head_base = segments * 3
        head_top = head_base + segments
        
        for i in range(segments):
            next_i = (i + 1) % segments
            indices.extend([head_base + i, head_base + next_i, head_top])
        
        return Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
    
    def _create_track_visualization(self, entity: DetectedEntity):
        """Create movement track visualization"""
        if len(entity.track_history) < 2:
            return
        
        vertices = []
        indices = []
        
        for i, pos in enumerate(entity.track_history):
            vertices.extend(pos)
        
        for i in range(len(entity.track_history) - 1):
            indices.extend([i, i + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        color = self.DETECTION_COLORS.get(entity.detection_type, (0.5, 0.8, 0.5))
        
        material = Material3D(
            name=f"track_{entity.id}",
            albedo=color,
            emission=color,
            emission_strength=0.3,
            opacity=0.5,
            wireframe=True
        )
        
        track = Object3D(
            name=f"track_{entity.id}",
            mesh=mesh,
            material=material
        )
        
        entity.track_object = track
        self.scene.add_object(track)
    
    def update_entity_position(self, entity_id: str, position: Tuple[float, float, float]):
        """Update entity position"""
        if entity_id not in self.entities:
            return
        
        entity = self.entities[entity_id]
        
        # Store old position in history
        entity.track_history.append(entity.position)
        
        # Keep only last 50 positions
        if len(entity.track_history) > 50:
            entity.track_history = entity.track_history[-50:]
        
        # Update position
        entity.position = position
        
        if entity.object_3d:
            entity.object_3d.position = position
        
        # Update track
        if self.show_tracks:
            if entity.track_object:
                self.scene.remove_object(entity.track_object)
            self._create_track_visualization(entity)
        
        self.positionEstimated.emit(position)
    
    def create_heatmap(self, bounds: Tuple[float, float, float, float],
                       height: float = 0.1):
        """Create signal strength heatmap"""
        min_x, min_z, max_x, max_z = bounds
        
        # Create heatmap grid
        width = max_x - min_x
        depth = max_z - min_z
        
        self.heatmap_data = np.zeros((self.heatmap_resolution, self.heatmap_resolution))
        
        # Calculate signal strength at each point
        for i in range(self.heatmap_resolution):
            for j in range(self.heatmap_resolution):
                x = min_x + (i / self.heatmap_resolution) * width
                z = min_z + (j / self.heatmap_resolution) * depth
                
                # Sum signal contributions from all sensors
                total_signal = 0
                for sensor in self.sensors.values():
                    dist = math.sqrt(
                        (x - sensor.position[0]) ** 2 +
                        (z - sensor.position[2]) ** 2
                    )
                    # Signal strength decreases with distance
                    signal = max(0, 1 - dist / 10)
                    total_signal += signal
                
                self.heatmap_data[i, j] = min(1, total_signal)
        
        # Create mesh
        vertices = []
        colors = []
        indices = []
        
        for i in range(self.heatmap_resolution):
            for j in range(self.heatmap_resolution):
                x = min_x + (i / self.heatmap_resolution) * width
                z = min_z + (j / self.heatmap_resolution) * depth
                y = height
                
                vertices.extend([x, y, z])
                
                # Color based on signal strength
                val = self.heatmap_data[i, j]
                # Blue to red gradient
                r = val
                g = 0.2 + val * 0.3
                b = 1 - val
                colors.extend([r, g, b])
        
        # Create triangles
        for i in range(self.heatmap_resolution - 1):
            for j in range(self.heatmap_resolution - 1):
                idx = i * self.heatmap_resolution + j
                
                indices.extend([
                    idx, idx + 1, idx + self.heatmap_resolution,
                    idx + 1, idx + self.heatmap_resolution + 1, idx + self.heatmap_resolution
                ])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32),
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            name="heatmap",
            albedo=(1, 1, 1),
            emission=(0.5, 0.5, 0.5),
            emission_strength=0.5,
            opacity=0.6
        )
        
        if self.heatmap_object:
            self.scene.remove_object(self.heatmap_object)
        
        self.heatmap_object = Object3D(
            name="heatmap",
            mesh=mesh,
            material=material
        )
        
        self.scene.add_object(self.heatmap_object)

        # Optional volumetric fog to indicate signal density
        if self.show_fog:
            self._create_signal_fog(bounds, height)
    
    def visualize_csi(self, sensor: WifiSensor):
        """Visualize CSI data as 3D waveform"""
        if sensor.csi_data is None:
            return
        
        # Create 3D representation of CSI amplitude
        vertices = []
        indices = []
        
        csi = sensor.csi_data
        if len(csi.shape) == 1:
            csi = csi.reshape(1, -1)
        
        rows, cols = csi.shape
        scale = 0.05  # Scale factor for amplitude
        
        for i in range(rows):
            for j in range(cols):
                x = sensor.position[0] + (j - cols/2) * 0.1
                z = sensor.position[2] + (i - rows/2) * 0.1
                y = sensor.position[1] + abs(csi[i, j]) * scale
                
                vertices.extend([x, y, z])
        
        # Create mesh connectivity
        for i in range(rows - 1):
            for j in range(cols - 1):
                idx = i * cols + j
                indices.extend([
                    idx, idx + 1, idx + cols,
                    idx + 1, idx + cols + 1, idx + cols
                ])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        color = self.SENSOR_COLORS.get(sensor.sensor_type, (0.5, 0.8, 0.5))
        
        material = Material3D(
            name=f"csi_{sensor.id}",
            albedo=color,
            emission=color,
            emission_strength=0.5,
            opacity=0.7
        )
        
        csi_obj = Object3D(
            name=f"csi_{sensor.id}",
            mesh=mesh,
            material=material
        )
        
        # Animate CSI visualization
        def animate_csi(obj: Object3D, dt: float):
            # Wave effect
            if hasattr(obj, '_csi_time'):
                obj._csi_time += dt
            else:
                obj._csi_time = 0
            
            # Update vertices (simplified)
            t = obj._csi_time
            offset = math.sin(t * 2) * 0.02
            obj.position = (obj.position[0], obj.position[1] + offset, obj.position[2])
        
        csi_obj.animation_callback = animate_csi
        
        self.scene.add_object(csi_obj)

    def _create_signal_fog(self, bounds: Tuple[float, float, float, float], height: float):
        """Create low-poly volumetric fog blocks based on heatmap intensity."""
        if self.heatmap_data is None:
            return

        min_x, min_z, max_x, max_z = bounds
        width = max_x - min_x
        depth = max_z - min_z

        # Sample coarse grid to reduce object count
        step = max(1, int(self.heatmap_resolution / 8))
        for i in range(0, self.heatmap_resolution, step):
            for j in range(0, self.heatmap_resolution, step):
                val = float(self.heatmap_data[i, j])
                if val < 0.15:
                    continue

                x = min_x + (i / self.heatmap_resolution) * width
                z = min_z + (j / self.heatmap_resolution) * depth
                y = height + val * 0.3

                size = 0.4 + val * 0.8
                mesh = Mesh3D.create_box(size, size * 0.4, size)
                color = (val, 0.3 + val * 0.4, 1 - val * 0.6)
                mat = Material3D(
                    name=f"fog_{i}_{j}",
                    albedo=color,
                    emission=color,
                    emission_strength=0.2 + val * 0.4,
                    opacity=0.2 + val * 0.25,
                )
                fog = Object3D(
                    name=f"fog_{i}_{j}",
                    mesh=mesh,
                    material=mat,
                    position=(x, y, z),
                    data={"type": "signal_fog"}
                )

                def animate_fog(obj: Object3D, dt: float, phase=(i + j) * 0.1):
                    t = time.time() * 0.5 + phase
                    obj.position = (obj.position[0], y + math.sin(t) * 0.05, obj.position[2])
                    obj.material.opacity = max(0.05, obj.material.opacity + math.sin(t) * 0.03)

                fog.animation_callback = animate_fog
                self.scene.add_object(fog)
    
    def set_show_signals(self, show: bool):
        """Toggle signal visualization"""
        self.show_signals = show
        
        for obj in self.signal_objects:
            obj.visible = show
    
    def set_show_heatmap(self, show: bool):
        """Toggle heatmap visibility"""
        self.show_heatmap = show
        
        if self.heatmap_object:
            self.heatmap_object.visible = show

    def set_show_fog(self, show: bool):
        """Toggle volumetric signal fog"""
        self.show_fog = show
        # Rebuild heatmap to refresh fog state
        if self.heatmap_object and self.heatmap_data is not None:
            self.scene.remove_object(self.heatmap_object)
            self.heatmap_object = None
            self.create_heatmap((-10, -10, 10, 10))

    def set_show_breathing_halo(self, show: bool):
        """Toggle breathing halo visualization"""
        self.show_breathing_halo = show
    
    def estimate_position_trilateration(self, rssi_readings: Dict[str, float]) -> Optional[Tuple[float, float, float]]:
        """Estimate position using trilateration from RSSI readings"""
        if len(rssi_readings) < 3:
            return None
        
        # Simple trilateration implementation
        sensors_with_readings = [
            (self.sensors[sid], rssi)
            for sid, rssi in rssi_readings.items()
            if sid in self.sensors
        ]
        
        if len(sensors_with_readings) < 3:
            return None
        
        # Convert RSSI to distance (simplified)
        def rssi_to_distance(rssi: float, n: float = 2.0, tx_power: float = -40) -> float:
            return 10 ** ((tx_power - rssi) / (10 * n))
        
        # Get positions and distances
        positions = []
        distances = []
        
        for sensor, rssi in sensors_with_readings[:3]:
            positions.append(sensor.position)
            distances.append(rssi_to_distance(rssi))
        
        # Trilateration (2D for simplicity)
        p1, p2, p3 = positions
        r1, r2, r3 = distances
        
        # Solve system of equations
        try:
            A = 2 * np.array([
                [p2[0] - p1[0], p2[2] - p1[2]],
                [p3[0] - p1[0], p3[2] - p1[2]]
            ])
            
            b = np.array([
                r1**2 - r2**2 - p1[0]**2 + p2[0]**2 - p1[2]**2 + p2[2]**2,
                r1**2 - r3**2 - p1[0]**2 + p3[0]**2 - p1[2]**2 + p3[2]**2
            ])
            
            result = np.linalg.solve(A, b)
            
            estimated_pos = (result[0], 1.0, result[1])  # Assume person height
            
            self.positionEstimated.emit(estimated_pos)
            return estimated_pos
            
        except np.linalg.LinAlgError:
            return None
    
    def simulate_sensing(self, num_sensors: int = 4, room_size: float = 10):
        """Create a simulated sensing environment"""
        # Create room
        room = Room(
            id="main",
            name="Main Room",
            bounds=(-room_size/2, 0, -room_size/2, room_size/2, 3, room_size/2)
        )
        self.add_room(room)
        
        # Add sensors at corners
        positions = [
            (-room_size/2 + 0.5, 2.5, -room_size/2 + 0.5),
            (room_size/2 - 0.5, 2.5, -room_size/2 + 0.5),
            (-room_size/2 + 0.5, 2.5, room_size/2 - 0.5),
            (room_size/2 - 0.5, 2.5, room_size/2 - 0.5),
        ]
        
        for i, pos in enumerate(positions[:num_sensors]):
            sensor = WifiSensor(
                id=f"sensor_{i}",
                sensor_type=SensorType.ACCESS_POINT,
                position=pos,
                name=f"AP-{i+1}",
                signal_strength=-40 - i * 5
            )
            self.add_sensor(sensor)
        
        # Create heatmap
        self.create_heatmap(
            (-room_size/2, -room_size/2, room_size/2, room_size/2)
        )
        
        # Add simulated person
        entity = DetectedEntity(
            id="person_1",
            detection_type=DetectionType.PRESENCE,
            position=(0, 0, 0),
            confidence=0.85,
            breathing_rate=15
        )
        self.add_entity(entity)
        
        # Animate person movement
        self._simulate_movement("person_1", room_size * 0.4)
    
    def _simulate_movement(self, entity_id: str, radius: float):
        """Simulate entity movement"""
        import random
        
        def move_entity():
            if entity_id not in self.entities:
                return
            
            # Random walk with boundaries
            entity = self.entities[entity_id]
            
            dx = random.uniform(-0.3, 0.3)
            dz = random.uniform(-0.3, 0.3)
            
            new_x = max(-radius, min(radius, entity.position[0] + dx))
            new_z = max(-radius, min(radius, entity.position[2] + dz))
            
            self.update_entity_position(entity_id, (new_x, 0, new_z))
        
        self.movement_timer = QTimer()
        self.movement_timer.timeout.connect(move_entity)
        self.movement_timer.start(500)  # Update every 500ms

    # ─────────────────────────────────────────────────────────────────────────
    # Zone visualization
    # ─────────────────────────────────────────────────────────────────────────

    def add_zone(self, zone: Zone3D):
        """Add a spatial zone to the visualization."""
        self.zones[zone.id] = zone
        if self.show_zones:
            self._create_zone_object(zone)

    def _create_zone_object(self, zone: Zone3D):
        min_x, min_y, min_z, max_x, max_y, max_z = zone.bounds
        vertices = [
            min_x, min_y, min_z,
            max_x, min_y, min_z,
            max_x, min_y, max_z,
            min_x, min_y, max_z,
            min_x, max_y, min_z,
            max_x, max_y, min_z,
            max_x, max_y, max_z,
            min_x, max_y, max_z,
        ]
        indices = [
            0, 1, 1, 2, 2, 3, 3, 0,
            4, 5, 5, 6, 6, 7, 7, 4,
            0, 4, 1, 5, 2, 6, 3, 7,
        ]
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        mat = Material3D(
            name=f"zone_{zone.id}",
            albedo=zone.color,
            emission=zone.color,
            emission_strength=0.4,
            opacity=0.25,
            wireframe=True,
        )
        obj = Object3D(
            name=f"zone_{zone.id}",
            mesh=mesh,
            material=mat,
            data={"type": "zone", "zone_id": zone.id},
        )
        zone.object_3d = obj
        self.scene.add_object(obj)

    def set_show_zones(self, show: bool):
        """Toggle zone visualization."""
        self.show_zones = show
        for zone in self.zones.values():
            if zone.object_3d:
                zone.object_3d.visible = show

    # ─────────────────────────────────────────────────────────────────────────
    # Gesture indicator
    # ─────────────────────────────────────────────────────────────────────────

    def show_gesture(self, entity_id: str, gesture: str):
        """Display a gesture indicator above an entity."""
        if entity_id not in self.entities or not self.show_gesture_indicator:
            return
        entity = self.entities[entity_id]
        pos = entity.position

        # Create a small floating icon (sphere) above head
        mesh = Mesh3D.create_sphere(0.15, 12, 6)
        color = (0.9, 0.4, 0.7)
        mat = Material3D(
            name=f"gesture_{entity_id}",
            albedo=color,
            emission=color,
            emission_strength=1.2,
            opacity=0.9,
        )
        indicator = Object3D(
            name=f"gesture_{entity_id}",
            mesh=mesh,
            material=mat,
            position=(pos[0], pos[1] + 2.2, pos[2]),
            data={"type": "gesture", "gesture": gesture},
        )

        # Animate pop-in then fade
        start_time = time.time()
        def animate_gesture(obj: Object3D, dt: float):
            elapsed = time.time() - start_time
            if elapsed > 2.0:
                self.scene.remove_object(obj)
                return
            scale = 1.0 + math.sin(elapsed * 6) * 0.1
            obj.scale = (scale, scale, scale)
            obj.material.opacity = max(0, 0.9 - elapsed * 0.4)

        indicator.animation_callback = animate_gesture
        self.scene.add_object(indicator)

    # ─────────────────────────────────────────────────────────────────────────
    # Heart rate overlay
    # ─────────────────────────────────────────────────────────────────────────

    def update_heart_rate(self, entity_id: str, bpm: float):
        """Update heart rate value for an entity (for overlay display)."""
        if entity_id in self.entities:
            self.entities[entity_id].heart_rate = bpm

    def _create_heart_rate_indicator(self, entity: DetectedEntity) -> Optional[Object3D]:
        if not self.show_heart_rate or entity.heart_rate <= 0:
            return None

        pos = entity.position
        mesh = Mesh3D.create_sphere(0.08, 8, 4)
        # Color from green (low) to red (high)
        ratio = min(1.0, max(0, (entity.heart_rate - 60) / 60))
        color = (0.2 + 0.7 * ratio, 0.8 - 0.6 * ratio, 0.2)
        mat = Material3D(
            name=f"hr_{entity.id}",
            albedo=color,
            emission=color,
            emission_strength=0.8,
            opacity=0.85,
        )
        hr_obj = Object3D(
            name=f"hr_{entity.id}",
            mesh=mesh,
            material=mat,
            position=(pos[0] + 0.3, pos[1] + 1.8, pos[2]),
            data={"type": "heart_rate", "entity_id": entity.id},
        )

        bpm = entity.heart_rate
        def animate_hr(obj: Object3D, dt: float):
            pulse = 1.0 + math.sin(time.time() * (bpm / 60) * 2 * math.pi) * 0.15
            obj.scale = (pulse, pulse, pulse)

        hr_obj.animation_callback = animate_hr
        return hr_obj

    def set_show_heart_rate(self, show: bool):
        """Toggle heart rate indicator visibility."""
        self.show_heart_rate = show

    def set_show_gesture_indicator(self, show: bool):
        """Toggle gesture indicator visibility."""
        self.show_gesture_indicator = show

    # ─────────────────────────────────────────────────────────────────────────
    # ADVANCED SENSING VISUALIZATION
    # ─────────────────────────────────────────────────────────────────────────

    def update_through_wall_image(self, image_data: List[List[int]], position: Tuple[float, float, float] = (0, 2, -10)):
        """
        Display through-wall radar image as a floating 3D panel.
        
        Args:
            image_data: 2D array of pixel values (0-255)
            position: Where to place the image panel in 3D space
        """
        if not image_data:
            return
        
        # Remove existing panel if present
        existing = self.scene.find_object("through_wall_panel")
        if existing:
            self.scene.remove_object(existing)
        
        height = len(image_data)
        width = len(image_data[0]) if height > 0 else 0
        if width == 0 or height == 0:
            return
        
        # Create a textured quad for the image
        scale = 5.0 / max(width, height)
        w, h = width * scale, height * scale
        
        vertices = np.array([
            -w/2, -h/2, 0,  0, 0,
            w/2, -h/2, 0,   1, 0,
            w/2, h/2, 0,    1, 1,
            -w/2, h/2, 0,   0, 1,
        ], dtype=np.float32)
        indices = np.array([0, 1, 2, 0, 2, 3], dtype=np.uint32)
        
        mesh = Mesh3D(vertices=vertices, indices=indices)
        
        # Convert image to color based on intensity
        avg_intensity = np.mean(image_data) / 255.0
        color = (0.2 + 0.6 * avg_intensity, 0.8 - 0.3 * avg_intensity, 0.9)
        
        mat = Material3D(
            name="through_wall",
            albedo=color,
            emission=color,
            emission_strength=0.5 + avg_intensity * 0.5,
            opacity=0.8,
        )
        
        panel = Object3D(
            name="through_wall_panel",
            mesh=mesh,
            material=mat,
            position=position,
            data={"type": "through_wall", "resolution": (width, height)},
        )
        self.scene.add_object(panel)

    def update_people_count_display(self, count: int, confidence: float, position: Tuple[float, float, float] = (8, 5, 0)):
        """
        Display people count as floating 3D indicator.
        
        Args:
            count: Number of people detected
            confidence: Detection confidence (0-1)
            position: Position in 3D space
        """
        existing = self.scene.find_object("people_count")
        if existing:
            self.scene.remove_object(existing)
        
        # Create spheres for each person counted
        for i in range(min(count, 10)):
            angle = (i / max(count, 1)) * 2 * math.pi
            x = position[0] + math.cos(angle) * 0.5
            z = position[2] + math.sin(angle) * 0.5
            
            mesh = Mesh3D.create_sphere(0.2, 12, 8)
            color = (0.3, 0.9 * confidence, 0.5)
            mat = Material3D(
                name=f"person_count_{i}",
                albedo=color,
                emission=color,
                emission_strength=0.6,
                opacity=0.85,
            )
            obj = Object3D(
                name=f"person_count_{i}",
                mesh=mesh,
                material=mat,
                position=(x, position[1], z),
                data={"type": "people_count", "index": i},
            )
            self.scene.add_object(obj)

    def update_activity_display(self, activity: str, confidence: float, entity_id: str = "primary"):
        """
        Display current activity classification above an entity.
        
        Args:
            activity: Activity name (walking, sitting, etc.)
            confidence: Detection confidence
            entity_id: Entity to attach display to
        """
        if entity_id not in self.entities:
            return
        
        entity = self.entities[entity_id]
        pos = entity.position
        
        # Remove existing activity indicator
        existing = self.scene.find_object(f"activity_{entity_id}")
        if existing:
            self.scene.remove_object(existing)
        
        if activity == "idle" or confidence < 0.5:
            return
        
        # Activity-specific colors
        activity_colors = {
            "walking": (0.3, 0.9, 0.4),
            "running": (0.9, 0.5, 0.2),
            "sitting_down": (0.4, 0.6, 0.9),
            "standing_up": (0.5, 0.8, 0.4),
            "arm_movement": (0.8, 0.4, 0.7),
            "typing": (0.6, 0.6, 0.8),
            "lying_down": (0.5, 0.5, 0.9),
        }
        color = activity_colors.get(activity, (0.7, 0.7, 0.7))
        
        # Create animated ring around entity
        mesh = Mesh3D.create_torus(0.8, 0.05, 24, 8)
        mat = Material3D(
            name=f"activity_{entity_id}",
            albedo=color,
            emission=color,
            emission_strength=0.8 * confidence,
            opacity=0.7,
        )
        
        indicator = Object3D(
            name=f"activity_{entity_id}",
            mesh=mesh,
            material=mat,
            position=(pos[0], 0.1, pos[2]),
            rotation=(90, 0, 0),  # Lay flat on ground
            data={"type": "activity", "activity": activity},
        )
        
        # Rotate animation
        def animate_activity(obj: Object3D, dt: float):
            obj.rotation = (90, (obj.rotation[1] + dt * 30) % 360, 0)
        
        indicator.animation_callback = animate_activity
        self.scene.add_object(indicator)

    def update_doppler_velocity_display(self, velocity: float, direction: str, entity_id: str = "primary"):
        """
        Display Doppler velocity as directional arrow.
        
        Args:
            velocity: Velocity in m/s
            direction: "approaching" or "receding"
            entity_id: Entity to attach display to
        """
        if entity_id not in self.entities:
            return
        
        entity = self.entities[entity_id]
        pos = entity.position
        
        existing = self.scene.find_object(f"doppler_{entity_id}")
        if existing:
            self.scene.remove_object(existing)
        
        if abs(velocity) < 0.1:
            return
        
        # Arrow color: green for approaching, red for receding
        color = (0.2, 0.9, 0.3) if direction == "approaching" else (0.9, 0.3, 0.2)
        
        # Create arrow mesh (cone + cylinder)
        arrow_length = min(2.0, abs(velocity) * 2)
        mesh = Mesh3D.create_cone(0.15, arrow_length, 12)
        
        mat = Material3D(
            name=f"doppler_{entity_id}",
            albedo=color,
            emission=color,
            emission_strength=0.7,
            opacity=0.85,
        )
        
        # Point towards/away from camera
        rotation_y = 0 if direction == "approaching" else 180
        
        indicator = Object3D(
            name=f"doppler_{entity_id}",
            mesh=mesh,
            material=mat,
            position=(pos[0], pos[1] + 2.5, pos[2]),
            rotation=(0, rotation_y, 90),
            data={"type": "doppler", "velocity": velocity},
        )
        self.scene.add_object(indicator)

    def update_sleep_stage_display(self, stage: str, breathing_rate: float, position: Tuple[float, float, float] = (-8, 3, 0)):
        """
        Display sleep stage monitoring panel.
        
        Args:
            stage: Sleep stage (awake, light_sleep, deep_sleep, rem)
            breathing_rate: Breaths per minute
            position: Panel position
        """
        existing = self.scene.find_object("sleep_panel")
        if existing:
            self.scene.remove_object(existing)
        
        stage_colors = {
            "awake": (0.9, 0.9, 0.3),
            "light_sleep": (0.4, 0.7, 0.9),
            "deep_sleep": (0.2, 0.3, 0.8),
            "rem": (0.7, 0.4, 0.9),
        }
        color = stage_colors.get(stage, (0.5, 0.5, 0.5))
        
        # Create floating panel
        mesh = Mesh3D.create_box(2.0, 1.0, 0.1)
        mat = Material3D(
            name="sleep_panel",
            albedo=color,
            emission=color,
            emission_strength=0.4,
            opacity=0.7,
        )
        
        panel = Object3D(
            name="sleep_panel",
            mesh=mesh,
            material=mat,
            position=position,
            data={"type": "sleep", "stage": stage, "breathing_rate": breathing_rate},
        )
        
        # Gentle breathing animation
        def animate_sleep(obj: Object3D, dt: float):
            breath_cycle = math.sin(time.time() * (breathing_rate / 60) * 2 * math.pi)
            scale = 1.0 + breath_cycle * 0.05
            obj.scale = (scale, 1.0, 1.0)
        
        panel.animation_callback = animate_sleep
        self.scene.add_object(panel)

    def update_slam_map_display(self, occupancy_grid: List[List[float]], position: Tuple[float, float, float] = (0, 0.01, 0)):
        """
        Display WiFi SLAM occupancy map on the floor.
        
        Args:
            occupancy_grid: 2D array of occupancy probabilities (0-1)
            position: Map center position
        """
        existing = self.scene.find_object("slam_map")
        if existing:
            self.scene.remove_object(existing)
        
        if not occupancy_grid:
            return
        
        grid = np.array(occupancy_grid)
        height, width = grid.shape
        
        cell_size = 0.5
        
        # Create grid of cubes for occupied cells
        for i in range(height):
            for j in range(width):
                if grid[i, j] > 0.6:  # Threshold for obstacle
                    x = position[0] + (j - width/2) * cell_size
                    z = position[2] + (i - height/2) * cell_size
                    
                    mesh = Mesh3D.create_box(cell_size * 0.9, grid[i, j] * 2, cell_size * 0.9)
                    intensity = grid[i, j]
                    color = (0.6 * intensity, 0.3, 0.2)
                    mat = Material3D(
                        name=f"slam_{i}_{j}",
                        albedo=color,
                        emission=(0.3, 0.1, 0.1),
                        emission_strength=0.2,
                        opacity=0.7,
                    )
                    obj = Object3D(
                        name=f"slam_cell_{i}_{j}",
                        mesh=mesh,
                        material=mat,
                        position=(x, grid[i, j], z),
                        data={"type": "slam_cell"},
                    )
                    self.scene.add_object(obj)

    def update_material_detection_display(self, material: str, confidence: float, position: Tuple[float, float, float]):
        """
        Display detected material type at a position.
        
        Args:
            material: Material name (drywall, concrete, metal, etc.)
            confidence: Detection confidence
            position: Position where material was detected
        """
        existing = self.scene.find_object(f"material_{position}")
        if existing:
            self.scene.remove_object(existing)
        
        material_colors = {
            "air": (0.9, 0.95, 1.0),
            "drywall": (0.9, 0.85, 0.8),
            "wood": (0.6, 0.4, 0.2),
            "glass": (0.7, 0.9, 1.0),
            "brick": (0.7, 0.3, 0.2),
            "concrete": (0.5, 0.5, 0.5),
            "metal": (0.7, 0.75, 0.8),
            "water": (0.3, 0.5, 0.9),
            "human_body": (0.9, 0.7, 0.6),
        }
        color = material_colors.get(material, (0.5, 0.5, 0.5))
        
        mesh = Mesh3D.create_box(0.3, 0.3, 0.3)
        mat = Material3D(
            name=f"material_indicator",
            albedo=color,
            emission=color,
            emission_strength=0.3 * confidence,
            opacity=0.6,
        )
        
        obj = Object3D(
            name=f"material_{hash(position)}",
            mesh=mesh,
            material=mat,
            position=position,
            data={"type": "material", "material": material},
        )
        self.scene.add_object(obj)

    def update_comprehensive_status(self, status: Dict[str, Any]):
        """
        Update all advanced visualization elements from comprehensive status.
        
        Args:
            status: Dictionary from WifiSensingEngine.get_comprehensive_status()
        """
        if "doppler" in status:
            d = status["doppler"]
            self.update_doppler_velocity_display(d.get("velocity", 0), d.get("direction", "receding"))
        
        if "activity" in status:
            a = status["activity"]
            self.update_activity_display(a.get("activity", "idle"), a.get("confidence", 0))
        
        if "people_count" in status:
            pc = status["people_count"]
            self.update_people_count_display(pc.get("count", 0), pc.get("confidence", 0))
        
        if "sleep" in status:
            s = status["sleep"]
            self.update_sleep_stage_display(s.get("stage", "awake"), s.get("breathing_rate", 15))
        
        if "through_wall" in status:
            tw = status["through_wall"]
            if "image" in tw:
                self.update_through_wall_image(tw["image"])
        
        # Update SLAM map if available
        if "slam_position" in status:
            self._slam_position = status["slam_position"]

    # =========================================================================
    # ENVIRONMENT RECONSTRUCTION SYSTEM
    # =========================================================================
    
    def init_environment_reconstruction(self, bounds: Tuple[float, float, float, float] = (-5, -5, 5, 5),
                                         resolution: float = 0.25):
        """
        Initialize environment reconstruction grid.
        
        Args:
            bounds: (min_x, min_z, max_x, max_z) room bounds
            resolution: Grid cell size in meters
        """
        self._env_bounds = bounds
        self._env_resolution = resolution
        min_x, min_z, max_x, max_z = bounds
        
        self._env_grid_x = int((max_x - min_x) / resolution)
        self._env_grid_z = int((max_z - min_z) / resolution)
        
        # Occupancy grid: probability of obstacle at each cell
        self._occupancy_grid = np.ones((self._env_grid_x, self._env_grid_z)) * 0.5
        
        # Signal strength grid
        self._signal_grid = np.zeros((self._env_grid_x, self._env_grid_z))
        
        # Material grid (0=air, 1=wall, 2=furniture, 3=human)
        self._material_grid = np.zeros((self._env_grid_x, self._env_grid_z), dtype=np.int8)
        
        # Motion history grid (accumulated motion detection)
        self._motion_grid = np.zeros((self._env_grid_x, self._env_grid_z))
        
        # 3D objects for grid visualization
        self._env_objects: List[Object3D] = []
        self._signal_ray_objects: List[Object3D] = []
        self._obstacle_objects: List[Object3D] = []
        
        # Create ground plane for environment
        self._create_env_ground_plane()
        
        print(f"Environment reconstruction initialized: {self._env_grid_x}x{self._env_grid_z} grid")
    
    def _create_env_ground_plane(self):
        """Create textured ground plane for environment."""
        min_x, min_z, max_x, max_z = self._env_bounds
        width = max_x - min_x
        depth = max_z - min_z
        
        mesh = Mesh3D.create_plane(width, depth)
        material = Material3D(
            name="env_ground",
            albedo=(0.08, 0.1, 0.15),
            metallic=0.0,
            roughness=0.9,
            opacity=0.8
        )
        
        center_x = (min_x + max_x) / 2
        center_z = (min_z + max_z) / 2
        
        ground = Object3D(
            name="env_ground",
            mesh=mesh,
            material=material,
            position=(center_x, 0.01, center_z),
            rotation=(-90, 0, 0)
        )
        self.scene.add_object(ground)
    
    def update_signal_propagation(self, tx_position: Tuple[float, float, float],
                                   rx_position: Tuple[float, float, float],
                                   csi_amplitude: List[float],
                                   rssi: float):
        """
        Visualize signal propagation from transmitter to receiver.
        
        Args:
            tx_position: Transmitter (AP) position
            rx_position: Receiver (ESP32) position
            csi_amplitude: CSI amplitude data per subcarrier
            rssi: Received signal strength
        """
        # Clear old ray visualizations
        for obj in self._signal_ray_objects:
            try:
                self.scene.remove_object(obj)
            except:
                pass
        self._signal_ray_objects.clear()
        
        # Main line of sight ray
        self._create_signal_ray(tx_position, rx_position, rssi, is_los=True)
        
        # Create multipath rays based on CSI amplitude variance
        if len(csi_amplitude) > 0:
            amp_array = np.array(csi_amplitude)
            variance = np.var(amp_array)
            mean_amp = np.mean(amp_array)
            
            # High variance indicates multipath - create reflection rays
            if variance > 0.1:
                # Estimate reflection points based on CSI subcarrier groups
                n_reflections = min(5, int(variance * 20))
                
                for i in range(n_reflections):
                    # Calculate reflection point estimate
                    angle = (i / n_reflections) * 2 * math.pi
                    radius = 2.0 + (variance * 3)
                    
                    reflect_x = (tx_position[0] + rx_position[0]) / 2 + math.cos(angle) * radius
                    reflect_z = (tx_position[2] + rx_position[2]) / 2 + math.sin(angle) * radius
                    reflect_y = 1.0 + math.sin(angle * 2) * 0.5
                    
                    reflect_pos = (reflect_x, reflect_y, reflect_z)
                    
                    # Create multipath visualization
                    path_strength = mean_amp * (1 - i * 0.15)
                    self._create_signal_ray(tx_position, reflect_pos, rssi - 10 - i * 3, is_los=False)
                    self._create_signal_ray(reflect_pos, rx_position, rssi - 10 - i * 3, is_los=False)
                    
                    # Mark reflection point as potential obstacle
                    self._mark_obstacle_point(reflect_pos, confidence=0.3 + variance * 0.3)
    
    def _create_signal_ray(self, start: Tuple[float, float, float], 
                           end: Tuple[float, float, float],
                           rssi: float, is_los: bool = True):
        """Create a signal ray visualization between two points."""
        # Calculate ray properties
        dx = end[0] - start[0]
        dy = end[1] - start[1]
        dz = end[2] - start[2]
        length = math.sqrt(dx*dx + dy*dy + dz*dz)
        
        if length < 0.1:
            return
        
        # Normalize signal strength to color
        strength = min(1.0, max(0.0, (rssi + 100) / 60))
        
        if is_los:
            # Line of sight - bright blue-white
            color = (0.3 + strength * 0.7, 0.6 + strength * 0.4, 1.0)
            opacity = 0.6 + strength * 0.3
            emission_strength = 0.8
        else:
            # Multipath - dimmer orange-yellow
            color = (1.0, 0.6 + strength * 0.3, 0.2)
            opacity = 0.3 + strength * 0.2
            emission_strength = 0.4
        
        # Create line vertices
        vertices = np.array([
            start[0], start[1], start[2],
            end[0], end[1], end[2]
        ], dtype=np.float32)
        
        indices = np.array([0, 1], dtype=np.uint32)
        
        mesh = Mesh3D(vertices=vertices, indices=indices)
        
        material = Material3D(
            name="signal_ray",
            albedo=color,
            emission=color,
            emission_strength=emission_strength,
            opacity=opacity,
            wireframe=True
        )
        
        ray = Object3D(
            name=f"signal_ray_{len(self._signal_ray_objects)}",
            mesh=mesh,
            material=material,
            data={"type": "signal_ray", "is_los": is_los}
        )
        
        self._signal_ray_objects.append(ray)
        self.scene.add_object(ray)
    
    def _mark_obstacle_point(self, position: Tuple[float, float, float], confidence: float = 0.5):
        """Mark a potential obstacle at position."""
        if not hasattr(self, '_env_bounds'):
            return
        
        min_x, min_z, max_x, max_z = self._env_bounds
        
        # Convert to grid coordinates
        gx = int((position[0] - min_x) / self._env_resolution)
        gz = int((position[2] - min_z) / self._env_resolution)
        
        if 0 <= gx < self._env_grid_x and 0 <= gz < self._env_grid_z:
            # Bayesian update of occupancy probability
            prior = self._occupancy_grid[gx, gz]
            likelihood = 0.5 + confidence * 0.4
            posterior = (prior * likelihood) / (prior * likelihood + (1 - prior) * (1 - likelihood))
            self._occupancy_grid[gx, gz] = posterior
    
    def update_obstacle_map_from_csi(self, csi_amplitude: List[float], 
                                      csi_phase: List[float],
                                      sensor_position: Tuple[float, float, float]):
        """
        Update obstacle map based on CSI data analysis.
        
        Uses amplitude and phase patterns to detect obstacles and walls.
        """
        if not hasattr(self, '_occupancy_grid'):
            self.init_environment_reconstruction()
        
        amp = np.array(csi_amplitude)
        phase = np.array(csi_phase) if csi_phase else np.zeros_like(amp)
        
        # Analyze CSI for obstacle signatures
        amp_variance = np.var(amp)
        amp_mean = np.mean(amp)
        
        # Phase unwrapping for distance estimation
        if len(phase) > 1:
            phase_diff = np.diff(phase)
            phase_variance = np.var(phase_diff)
        else:
            phase_variance = 0
        
        # High amplitude variance + phase discontinuity = obstacle
        obstacle_likelihood = min(1.0, amp_variance * 5 + phase_variance * 2)
        
        if obstacle_likelihood > 0.3:
            # Estimate obstacle positions using simplified beamforming
            n_subcarriers = len(amp)
            
            for i in range(min(8, n_subcarriers // 8)):
                # Group subcarriers and analyze
                start_idx = i * (n_subcarriers // 8)
                end_idx = start_idx + (n_subcarriers // 8)
                group_amp = amp[start_idx:end_idx]
                
                # Angle estimation from subcarrier group
                angle = (i / 8) * 2 * math.pi - math.pi
                
                # Distance estimation from amplitude attenuation
                group_mean = np.mean(group_amp)
                distance = max(0.5, 5.0 * (1 - group_mean / (amp_mean + 0.01)))
                
                # Calculate obstacle position
                obs_x = sensor_position[0] + math.cos(angle) * distance
                obs_z = sensor_position[2] + math.sin(angle) * distance
                
                confidence = min(1.0, np.var(group_amp) * 10)
                if confidence > 0.2:
                    self._mark_obstacle_point((obs_x, 1.0, obs_z), confidence)
    
    def update_motion_detection(self, position: Tuple[float, float, float],
                                 velocity: float, confidence: float):
        """
        Update motion detection visualization at a position.
        
        Args:
            position: Detected motion position
            velocity: Motion velocity (m/s)
            confidence: Detection confidence
        """
        if not hasattr(self, '_motion_grid'):
            return
        
        min_x, min_z, max_x, max_z = self._env_bounds
        
        gx = int((position[0] - min_x) / self._env_resolution)
        gz = int((position[2] - min_z) / self._env_resolution)
        
        if 0 <= gx < self._env_grid_x and 0 <= gz < self._env_grid_z:
            # Accumulate motion energy
            self._motion_grid[gx, gz] += velocity * confidence
            
            # Decay over time
            self._motion_grid *= 0.95
    
    def render_environment_reconstruction(self, show_obstacles: bool = True,
                                           show_signals: bool = True,
                                           show_motion: bool = True):
        """
        Render the reconstructed environment to 3D.
        
        Args:
            show_obstacles: Show detected obstacles
            show_signals: Show signal strength map
            show_motion: Show motion detection heatmap
        """
        if not hasattr(self, '_occupancy_grid'):
            return
        
        # Clear old environment objects
        for obj in self._obstacle_objects:
            try:
                self.scene.remove_object(obj)
            except:
                pass
        self._obstacle_objects.clear()
        
        min_x, min_z, max_x, max_z = self._env_bounds
        
        # Render obstacles (high occupancy probability)
        if show_obstacles:
            for i in range(self._env_grid_x):
                for j in range(self._env_grid_z):
                    occupancy = self._occupancy_grid[i, j]
                    
                    if occupancy > 0.6:  # Likely obstacle
                        x = min_x + i * self._env_resolution + self._env_resolution / 2
                        z = min_z + j * self._env_resolution + self._env_resolution / 2
                        
                        # Height based on occupancy probability
                        height = (occupancy - 0.5) * 4  # 0 to 2 meters
                        
                        self._create_obstacle_block((x, height / 2, z), 
                                                    self._env_resolution * 0.9,
                                                    height,
                                                    occupancy)
        
        # Render motion heatmap
        if show_motion and hasattr(self, '_motion_grid'):
            self._render_motion_heatmap()
    
    def _create_obstacle_block(self, position: Tuple[float, float, float],
                                width: float, height: float, confidence: float):
        """Create a 3D block for detected obstacle."""
        mesh = Mesh3D.create_box(width, height, width)
        
        # Color based on material guess
        if confidence > 0.8:
            # High confidence = wall (gray)
            color = (0.4, 0.42, 0.45)
        elif confidence > 0.7:
            # Medium = furniture (brown)
            color = (0.5, 0.35, 0.2)
        else:
            # Lower = uncertain (semi-transparent blue)
            color = (0.3, 0.4, 0.6)
        
        material = Material3D(
            name="obstacle",
            albedo=color,
            emission=(color[0] * 0.2, color[1] * 0.2, color[2] * 0.2),
            emission_strength=0.1,
            opacity=0.3 + confidence * 0.5,
            metallic=0.1,
            roughness=0.8
        )
        
        obj = Object3D(
            name=f"obstacle_{len(self._obstacle_objects)}",
            mesh=mesh,
            material=material,
            position=position,
            data={"type": "obstacle", "confidence": confidence}
        )
        
        self._obstacle_objects.append(obj)
        self.scene.add_object(obj)
    
    def _render_motion_heatmap(self):
        """Render motion detection as a heatmap overlay."""
        if not hasattr(self, '_motion_grid'):
            return
        
        min_x, min_z, max_x, max_z = self._env_bounds
        max_motion = np.max(self._motion_grid) + 0.01
        
        # Only render cells with significant motion
        for i in range(self._env_grid_x):
            for j in range(self._env_grid_z):
                motion = self._motion_grid[i, j]
                
                if motion > max_motion * 0.1:
                    x = min_x + i * self._env_resolution + self._env_resolution / 2
                    z = min_z + j * self._env_resolution + self._env_resolution / 2
                    
                    intensity = motion / max_motion
                    
                    # Create motion indicator
                    mesh = Mesh3D.create_sphere(self._env_resolution * 0.4 * intensity, 8, 4)
                    
                    # Color: blue (slow) to red (fast)
                    r = min(1.0, intensity * 2)
                    g = max(0, 1 - intensity * 2)
                    b = 0.3
                    
                    material = Material3D(
                        name="motion",
                        albedo=(r, g, b),
                        emission=(r, g * 0.5, b),
                        emission_strength=0.5 + intensity * 0.5,
                        opacity=0.4 + intensity * 0.4
                    )
                    
                    obj = Object3D(
                        name=f"motion_{i}_{j}",
                        mesh=mesh,
                        material=material,
                        position=(x, 0.1 + intensity * 0.5, z),
                        data={"type": "motion"}
                    )
                    
                    self._obstacle_objects.append(obj)
                    self.scene.add_object(obj)
    
    def update_tracked_person(self, person_id: str, 
                               position: Tuple[float, float, float],
                               velocity: Tuple[float, float, float],
                               confidence: float,
                               activity: str = "walking"):
        """
        Update tracked person visualization with accurate positioning.
        
        Args:
            person_id: Unique person identifier
            position: 3D position (x, y, z)
            velocity: Movement velocity vector
            confidence: Tracking confidence
            activity: Current activity (walking, sitting, standing, etc.)
        """
        if person_id not in self.entities:
            # Create new entity
            entity = DetectedEntity(
                id=person_id,
                detection_type=DetectionType.MOVEMENT,
                position=position,
                confidence=confidence,
                velocity=velocity
            )
            self.add_entity(entity)
        
        entity = self.entities[person_id]
        entity.confidence = confidence
        entity.velocity = velocity
        
        # Update position
        self.update_entity_position(person_id, position)
        
        # Update visual based on activity
        if entity.object_3d:
            # Adjust appearance based on activity
            if activity == "walking":
                entity.object_3d.material.emission_strength = 0.6
            elif activity == "running":
                entity.object_3d.material.emission_strength = 0.9
            elif activity == "sitting":
                entity.object_3d.material.emission_strength = 0.3
            elif activity == "lying":
                entity.object_3d.material.emission_strength = 0.2
            else:
                entity.object_3d.material.emission_strength = 0.4
            
            # Opacity based on confidence
            entity.object_3d.material.opacity = 0.3 + confidence * 0.6
        
        # Update motion grid
        if hasattr(self, '_motion_grid'):
            speed = math.sqrt(velocity[0]**2 + velocity[1]**2 + velocity[2]**2)
            self.update_motion_detection(position, speed, confidence)

    # ==========================================
    # ENHANCED VISUALIZATION EFFECTS
    # ==========================================
    
    def create_tracking_lock_indicator(self, entity_id: str, lock_strength: float,
                                        color: Tuple[float, float, float] = (0.0, 1.0, 0.5)):
        """
        Create an animated tracking lock indicator around a tracked person.
        Shows a rotating targeting reticle when locked.
        """
        entity = self.entities.get(entity_id)
        if not entity:
            return
        
        # Remove existing lock indicator
        lock_name = f"lock_{entity_id}"
        existing = self.scene.find_object(lock_name)
        if existing:
            self.scene.remove_object(existing)
        
        if lock_strength < 0.3:
            return  # No indicator for weak locks
        
        pos = entity.position
        
        # Create targeting reticle with multiple rings
        vertices = []
        indices = []
        
        # Outer ring
        segments = 32
        outer_radius = 0.8
        inner_radius = 0.6
        
        idx = 0
        for ring_idx, (radius, offset) in enumerate([(outer_radius, 0), (inner_radius, 0.1)]):
            for i in range(segments):
                # Skip some segments for broken ring effect
                if ring_idx == 0 and i % 8 < 2:
                    continue
                    
                angle1 = (i / segments) * 2 * math.pi
                angle2 = ((i + 1) / segments) * 2 * math.pi
                
                x1, z1 = radius * math.cos(angle1), radius * math.sin(angle1)
                x2, z2 = radius * math.cos(angle2), radius * math.sin(angle2)
                
                vertices.extend([x1, offset, z1])
                vertices.extend([x2, offset, z2])
                indices.extend([idx, idx + 1])
                idx += 2
        
        # Crosshairs
        cross_size = 0.4
        for dx, dz in [(1, 0), (-1, 0), (0, 1), (0, -1)]:
            vertices.extend([dx * inner_radius * 0.7, 0.05, dz * inner_radius * 0.7])
            vertices.extend([dx * cross_size, 0.05, dz * cross_size])
            indices.extend([idx, idx + 1])
            idx += 2
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        # Color intensity based on lock strength
        glow = 0.5 + lock_strength * 0.5
        material = Material3D(
            name=lock_name,
            albedo=color,
            emission=color,
            emission_strength=glow,
            opacity=0.7 + lock_strength * 0.3,
            wireframe=True
        )
        
        indicator = Object3D(
            name=lock_name,
            mesh=mesh,
            material=material,
            position=pos,
            data={"type": "lock_indicator", "entity_id": entity_id}
        )
        
        # Animation: rotate and pulse
        def animate_lock(obj: Object3D, dt: float):
            t = time.time()
            # Slow rotation
            obj.rotation = (0, t * 30 % 360, 0)
            # Pulse glow
            pulse = 0.8 + 0.2 * math.sin(t * 4)
            obj.material.emission_strength = glow * pulse
            # Follow entity
            if entity_id in self.entities:
                obj.position = self.entities[entity_id].position
        
        indicator.animation_callback = animate_lock
        self.scene.add_object(indicator)
    
    def create_signal_pulse_wave(self, origin: Tuple[float, float, float],
                                  max_radius: float = 8.0,
                                  color: Tuple[float, float, float] = (0.0, 0.8, 1.0),
                                  duration: float = 2.0):
        """
        Create an expanding pulse wave effect to visualize signal propagation.
        """
        wave_id = f"pulse_{time.time()}"
        
        # Create ring mesh
        segments = 48
        vertices = []
        indices = []
        
        for i in range(segments):
            angle = (i / segments) * 2 * math.pi
            x = math.cos(angle)
            z = math.sin(angle)
            vertices.extend([x, 0, z])
        
        for i in range(segments):
            indices.extend([i, (i + 1) % segments])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=wave_id,
            albedo=color,
            emission=color,
            emission_strength=1.0,
            opacity=0.8,
            wireframe=True
        )
        
        wave = Object3D(
            name=wave_id,
            mesh=mesh,
            material=material,
            position=origin,
            scale=(0.1, 1, 0.1),
            data={"type": "pulse_wave", "start_time": time.time(), 
                  "duration": duration, "max_radius": max_radius}
        )
        
        def animate_pulse(obj: Object3D, dt: float):
            elapsed = time.time() - obj.data["start_time"]
            progress = elapsed / obj.data["duration"]
            
            if progress >= 1.0:
                # Remove after animation completes
                try:
                    self.scene.remove_object(obj)
                except:
                    pass
                return
            
            # Expand
            radius = progress * obj.data["max_radius"]
            obj.scale = (radius, 1, radius)
            
            # Fade out
            obj.material.opacity = 0.8 * (1 - progress)
            obj.material.emission_strength = 1.0 * (1 - progress * 0.5)
        
        wave.animation_callback = animate_pulse
        self.scene.add_object(wave)
    
    def create_biometric_display(self, entity_id: str, 
                                  heart_rate: float = 0.0,
                                  breathing_rate: float = 0.0,
                                  confidence: float = 0.8):
        """
        Create floating biometric indicators above an entity.
        Shows heart rate and breathing as animated icons.
        """
        entity = self.entities.get(entity_id)
        if not entity:
            return
        
        pos = entity.position
        display_y = pos[1] + 2.2
        
        # Heart rate indicator
        if heart_rate > 0:
            hr_name = f"hr_{entity_id}"
            existing = self.scene.find_object(hr_name)
            if existing:
                self.scene.remove_object(existing)
            
            # Create heart shape (simplified)
            heart_verts = []
            heart_idx = []
            
            # Simple heart from two circles and a triangle
            size = 0.1
            segments = 16
            
            # Left lobe
            for i in range(segments // 2):
                angle = math.pi + (i / (segments // 2)) * math.pi
                x = -size * 0.5 + size * 0.5 * math.cos(angle)
                y = size * 0.5 * math.sin(angle)
                heart_verts.extend([x, y, 0])
            
            # Right lobe
            for i in range(segments // 2):
                angle = (i / (segments // 2)) * math.pi
                x = size * 0.5 + size * 0.5 * math.cos(angle)
                y = size * 0.5 * math.sin(angle)
                heart_verts.extend([x, y, 0])
            
            # Bottom point
            heart_verts.extend([0, -size * 1.2, 0])
            
            # Connect with lines
            n = len(heart_verts) // 3
            for i in range(n - 1):
                heart_idx.extend([i, i + 1])
            heart_idx.extend([n - 1, 0])
            
            mesh = Mesh3D(
                vertices=np.array(heart_verts, dtype=np.float32),
                indices=np.array(heart_idx, dtype=np.uint32)
            )
            
            # Color based on heart rate (blue=low, red=high)
            hr_norm = min(1.0, max(0.0, (heart_rate - 40) / 120))
            color = (0.8 + hr_norm * 0.2, 0.3 * (1 - hr_norm), 0.3 * (1 - hr_norm))
            
            material = Material3D(
                name=hr_name,
                albedo=color,
                emission=color,
                emission_strength=0.8,
                opacity=0.9,
                wireframe=True
            )
            
            heart_obj = Object3D(
                name=hr_name,
                mesh=mesh,
                material=material,
                position=(pos[0] - 0.3, display_y, pos[2]),
                rotation=(0, 0, 0),
                data={"type": "heart_rate", "entity_id": entity_id, "rate": heart_rate}
            )
            
            # Beating animation
            beat_interval = 60.0 / max(40, heart_rate)
            
            def animate_heart(obj: Object3D, dt: float):
                t = time.time()
                beat_phase = (t % beat_interval) / beat_interval
                
                # Quick expand, slow contract
                if beat_phase < 0.1:
                    scale = 1.0 + 0.3 * (beat_phase / 0.1)
                elif beat_phase < 0.3:
                    scale = 1.3 - 0.3 * ((beat_phase - 0.1) / 0.2)
                else:
                    scale = 1.0
                
                obj.scale = (scale, scale, scale)
                obj.material.emission_strength = 0.6 + 0.4 * (1 - beat_phase)
                
                # Follow entity
                if entity_id in self.entities:
                    ent = self.entities[entity_id]
                    obj.position = (ent.position[0] - 0.3, ent.position[1] + 2.2, ent.position[2])
            
            heart_obj.animation_callback = animate_heart
            self.scene.add_object(heart_obj)
        
        # Breathing indicator
        if breathing_rate > 0:
            br_name = f"br_{entity_id}"
            existing = self.scene.find_object(br_name)
            if existing:
                self.scene.remove_object(existing)
            
            # Create wave pattern for breathing
            wave_verts = []
            wave_idx = []
            
            points = 20
            wave_width = 0.4
            for i in range(points):
                x = (i / (points - 1) - 0.5) * wave_width
                y = 0.05 * math.sin(i / (points - 1) * 2 * math.pi)
                wave_verts.extend([x, y, 0])
            
            for i in range(points - 1):
                wave_idx.extend([i, i + 1])
            
            mesh = Mesh3D(
                vertices=np.array(wave_verts, dtype=np.float32),
                indices=np.array(wave_idx, dtype=np.uint32)
            )
            
            material = Material3D(
                name=br_name,
                albedo=(0.3, 0.8, 1.0),
                emission=(0.3, 0.8, 1.0),
                emission_strength=0.7,
                opacity=0.8,
                wireframe=True
            )
            
            breath_obj = Object3D(
                name=br_name,
                mesh=mesh,
                material=material,
                position=(pos[0] + 0.3, display_y, pos[2]),
                data={"type": "breathing", "entity_id": entity_id, "rate": breathing_rate}
            )
            
            breath_interval = 60.0 / max(5, breathing_rate)
            
            def animate_breath(obj: Object3D, dt: float):
                t = time.time()
                phase = (t % breath_interval) / breath_interval
                
                # Smooth breathing wave
                scale_y = 0.7 + 0.6 * math.sin(phase * 2 * math.pi)
                obj.scale = (1, scale_y, 1)
                
                # Follow entity
                if entity_id in self.entities:
                    ent = self.entities[entity_id]
                    obj.position = (ent.position[0] + 0.3, ent.position[1] + 2.2, ent.position[2])
            
            breath_obj.animation_callback = animate_breath
            self.scene.add_object(breath_obj)
    
    def create_velocity_trail(self, entity_id: str, 
                               trail_length: int = 20,
                               fade: bool = True):
        """
        Create a fading trail behind a moving entity to show movement history.
        """
        entity = self.entities.get(entity_id)
        if not entity or len(entity.track_history) < 2:
            return
        
        trail_name = f"trail_{entity_id}"
        existing = self.scene.find_object(trail_name)
        if existing:
            self.scene.remove_object(existing)
        
        # Get last N positions
        history = entity.track_history[-trail_length:] + [entity.position]
        if len(history) < 2:
            return
        
        vertices = []
        colors = []
        indices = []
        
        for i, pos in enumerate(history):
            vertices.extend([pos[0], pos[1], pos[2]])
            
            # Fade from transparent to solid
            alpha = i / len(history) if fade else 1.0
            colors.extend([0.0, 0.8, 1.0, alpha])
            
            if i > 0:
                indices.extend([i - 1, i])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=trail_name,
            albedo=(0.0, 0.8, 1.0),
            emission=(0.0, 0.8, 1.0),
            emission_strength=0.5,
            opacity=0.6,
            wireframe=True
        )
        
        trail = Object3D(
            name=trail_name,
            mesh=mesh,
            material=material,
            data={"type": "velocity_trail", "entity_id": entity_id}
        )
        
        self.scene.add_object(trail)
    
    def create_detection_zone_glow(self, bounds: Tuple[float, float, float, float],
                                    detection_count: int = 0,
                                    max_detections: int = 5):
        """
        Create a glowing floor effect in detection zones that intensifies
        with more detected individuals.
        """
        zone_name = "detection_zone_glow"
        existing = self.scene.find_object(zone_name)
        if existing:
            self.scene.remove_object(existing)
        
        if detection_count == 0:
            return
        
        min_x, min_z, max_x, max_z = bounds
        
        # Create grid of glow points
        resolution = 10
        vertices = []
        colors = []
        indices = []
        
        intensity = min(1.0, detection_count / max_detections)
        
        idx = 0
        for i in range(resolution + 1):
            for j in range(resolution + 1):
                x = min_x + (i / resolution) * (max_x - min_x)
                z = min_z + (j / resolution) * (max_z - min_z)
                
                # Height varies with position for wave effect
                y = 0.02 + 0.03 * math.sin(i * 0.5) * math.sin(j * 0.5)
                
                vertices.extend([x, y, z])
                
                # Color gradient from blue to orange based on intensity
                r = intensity * 1.0
                g = 0.3 + intensity * 0.4
                b = 1.0 - intensity * 0.5
                colors.extend([r, g, b, 0.3 + intensity * 0.4])
        
        # Connect points into grid
        for i in range(resolution):
            for j in range(resolution):
                current = i * (resolution + 1) + j
                right = current + 1
                down = current + (resolution + 1)
                
                indices.extend([current, right])
                indices.extend([current, down])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=zone_name,
            albedo=(0.0, 0.5, 1.0),
            emission=(intensity, 0.3 + intensity * 0.4, 1.0 - intensity * 0.5),
            emission_strength=0.5 + intensity * 0.5,
            opacity=0.4,
            wireframe=True
        )
        
        zone = Object3D(
            name=zone_name,
            mesh=mesh,
            material=material,
            data={"type": "detection_zone", "count": detection_count}
        )
        
        # Pulsing animation
        def animate_zone(obj: Object3D, dt: float):
            t = time.time()
            pulse = 0.8 + 0.2 * math.sin(t * 2)
            obj.material.emission_strength = (0.5 + intensity * 0.5) * pulse
        
        zone.animation_callback = animate_zone
        self.scene.add_object(zone)

    def create_scanning_beam(self, origin: Tuple[float, float, float],
                              direction: float, range_m: float = 8.0,
                              beam_width: float = 30.0):
        """
        Create an animated scanning beam effect from a sensor,
        useful for visualizing active sensing sweeps.
        """
        beam_name = "scanning_beam"
        existing = self.scene.find_object(beam_name)
        if existing:
            self.scene.remove_object(existing)
        
        # Create wedge/cone shape for beam
        segments = 32
        vertices = [origin[0], origin[1], origin[2]]  # Origin point
        colors = [0.0, 0.8, 1.0, 0.8]  # Bright at origin
        indices = []
        
        half_angle = math.radians(beam_width / 2)
        
        for i in range(segments + 1):
            t = i / segments
            angle = direction + half_angle * (2 * t - 1)
            
            x = origin[0] + math.cos(angle) * range_m
            z = origin[2] + math.sin(angle) * range_m
            y = origin[1]
            
            vertices.extend([x, y, z])
            # Fade out at edges
            alpha = 0.3 * (1 - abs(2 * t - 1))
            colors.extend([0.0, 0.6, 1.0, alpha])
        
        # Connect to origin
        for i in range(segments):
            indices.extend([0, i + 1, i + 2])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=beam_name,
            albedo=(0.0, 0.6, 1.0),
            emission=(0.0, 0.8, 1.0),
            emission_strength=0.6,
            opacity=0.3
        )
        
        beam = Object3D(
            name=beam_name,
            mesh=mesh,
            material=material,
            data={"type": "scanning_beam", "direction": direction}
        )
        
        # Rotation animation
        def animate_beam(obj: Object3D, dt: float):
            t = time.time()
            sweep_angle = math.sin(t * 0.5) * math.pi
            obj.rotation = (0, sweep_angle, 0)
            # Pulsing opacity
            obj.material.opacity = 0.2 + 0.15 * math.sin(t * 3)
        
        beam.animation_callback = animate_beam
        self.scene.add_object(beam)
        return beam

    def create_gesture_indicator(self, position: Tuple[float, float, float],
                                   gesture_type: str, confidence: float = 0.8):
        """
        Create a visual indicator for detected gestures.
        Shows the gesture type as an animated icon above the person.
        """
        indicator_name = f"gesture_{gesture_type}"
        existing = self.scene.find_object(indicator_name)
        if existing:
            self.scene.remove_object(existing)
        
        # Gesture icons and colors
        gesture_colors = {
            "wave": (0.2, 0.8, 0.4),       # Green
            "swipe_up": (0.2, 0.6, 1.0),   # Blue
            "swipe_down": (1.0, 0.4, 0.2), # Orange
            "push": (0.8, 0.2, 0.8),       # Purple
            "circle": (1.0, 0.8, 0.2),     # Yellow
        }
        
        color = gesture_colors.get(gesture_type.lower(), (0.5, 0.5, 0.5))
        
        # Create floating icon above position
        icon_pos = (position[0], position[1] + 0.8, position[2])
        
        mesh = Mesh3D.create_sphere(radius=0.15, segments=12)
        
        material = Material3D(
            name=indicator_name,
            albedo=color,
            emission=color,
            emission_strength=1.0 + confidence,
            opacity=0.7
        )
        
        indicator = Object3D(
            name=indicator_name,
            mesh=mesh,
            material=material,
            position=icon_pos,
            data={"type": "gesture", "gesture": gesture_type, "confidence": confidence}
        )
        
        # Bounce and glow animation
        start_time = time.time()
        
        def animate_gesture(obj: Object3D, dt: float, t0=start_time):
            t = time.time() - t0
            # Fade out after 2 seconds
            if t > 2.0:
                obj.material.opacity = max(0, 0.7 - (t - 2.0) * 0.7)
            # Bounce up
            bounce = math.sin(t * 4) * 0.1 * max(0, 1 - t * 0.3)
            obj.position = (icon_pos[0], icon_pos[1] + bounce, icon_pos[2])
            # Pulse glow
            obj.material.emission_strength = 1.0 + 0.5 * math.sin(t * 6)
        
        indicator.animation_callback = animate_gesture
        self.scene.add_object(indicator)
        return indicator

    def create_room_scan_effect(self, bounds: Tuple[float, float, float, float],
                                 scan_progress: float = 0.0):
        """
        Create a scanning line effect across the room,
        visualizing room mapping progress.
        """
        scan_name = "room_scan_line"
        existing = self.scene.find_object(scan_name)
        if existing:
            self.scene.remove_object(existing)
        
        min_x, min_z, max_x, max_z = bounds
        
        # Scan line position based on progress
        scan_x = min_x + scan_progress * (max_x - min_x)
        
        # Create vertical scan line
        vertices = [
            scan_x, 0.0, min_z,
            scan_x, 3.0, min_z,
            scan_x, 3.0, max_z,
            scan_x, 0.0, max_z,
        ]
        
        colors = [
            0.0, 1.0, 0.5, 0.8,
            0.0, 1.0, 0.8, 0.4,
            0.0, 1.0, 0.8, 0.4,
            0.0, 1.0, 0.5, 0.8,
        ]
        
        indices = [0, 1, 1, 2, 2, 3, 3, 0, 0, 2, 1, 3]
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=scan_name,
            albedo=(0.0, 1.0, 0.5),
            emission=(0.0, 1.0, 0.8),
            emission_strength=1.5,
            opacity=0.6,
            wireframe=True
        )
        
        scan_line = Object3D(
            name=scan_name,
            mesh=mesh,
            material=material,
            data={"type": "room_scan", "progress": scan_progress}
        )
        
        # Moving scan animation
        def animate_scan(obj: Object3D, dt: float, min_x=min_x, max_x=max_x):
            t = time.time()
            progress = (t * 0.3) % 1.0
            new_x = min_x + progress * (max_x - min_x)
            # Update vertices would be complex, so just move the whole object
            offset = new_x - scan_x
            obj.position = (offset, 0, 0)
            # Intensity pulse
            obj.material.emission_strength = 1.0 + 0.5 * math.sin(t * 5)
        
        scan_line.animation_callback = animate_scan
        self.scene.add_object(scan_line)
        return scan_line

    def create_activity_aura(self, entity_id: str, activity: str,
                              position: Tuple[float, float, float]):
        """
        Create an aura effect around a person based on their detected activity.
        """
        aura_name = f"activity_aura_{entity_id}"
        existing = self.scene.find_object(aura_name)
        if existing:
            self.scene.remove_object(existing)
        
        # Activity colors
        activity_colors = {
            "walking": (0.2, 0.8, 0.3, 0.4),      # Green
            "running": (1.0, 0.6, 0.0, 0.5),      # Orange
            "sitting": (0.3, 0.5, 0.8, 0.3),      # Blue
            "standing": (0.5, 0.5, 0.5, 0.3),     # Gray
            "sleeping": (0.4, 0.3, 0.8, 0.4),     # Purple
            "idle": (0.4, 0.4, 0.4, 0.2),         # Dark gray
            "exercising": (1.0, 0.3, 0.3, 0.5),   # Red
        }
        
        rgba = activity_colors.get(activity.lower(), (0.5, 0.5, 0.5, 0.3))
        
        # Create torus aura around entity
        try:
            mesh = Mesh3D.create_torus(
                major_radius=0.6,
                minor_radius=0.08,
                major_segments=24,
                minor_segments=8
            )
        except:
            # Fallback to circle
            mesh = Mesh3D.create_sphere(radius=0.6, segments=16)
        
        material = Material3D(
            name=aura_name,
            albedo=(rgba[0], rgba[1], rgba[2]),
            emission=(rgba[0], rgba[1], rgba[2]),
            emission_strength=0.8,
            opacity=rgba[3]
        )
        
        aura = Object3D(
            name=aura_name,
            mesh=mesh,
            material=material,
            position=(position[0], 0.1, position[2]),
            rotation=(math.pi / 2, 0, 0),
            data={"type": "activity_aura", "activity": activity}
        )
        
        # Rotation animation
        def animate_aura(obj: Object3D, dt: float):
            t = time.time()
            obj.rotation = (math.pi / 2, t * 0.5, 0)
            # Breathing pulse
            scale = 1.0 + 0.1 * math.sin(t * 2)
            obj.scale = (scale, scale, 1)
        
        aura.animation_callback = animate_aura
        self.scene.add_object(aura)
        return aura

    def create_signal_heatmap(self, bounds: Tuple[float, float, float, float],
                               signal_values: np.ndarray = None,
                               resolution: int = 16):
        """
        Create a floor-level heat map showing signal strength distribution.
        """
        heatmap_name = "signal_heatmap"
        existing = self.scene.find_object(heatmap_name)
        if existing:
            self.scene.remove_object(existing)
        
        min_x, min_z, max_x, max_z = bounds
        
        # Generate or use provided signal values
        if signal_values is None:
            # Create simulated signal map based on sensor positions
            signal_values = np.zeros((resolution, resolution))
            for sensor_id, sensor in self.sensors.items():
                sx, sy, sz = sensor.position
                for i in range(resolution):
                    for j in range(resolution):
                        x = min_x + (i / (resolution - 1)) * (max_x - min_x)
                        z = min_z + (j / (resolution - 1)) * (max_z - min_z)
                        dist = math.sqrt((x - sx)**2 + (z - sz)**2)
                        # Signal falls off with distance
                        strength = max(0, 1 - dist / 6)
                        signal_values[i, j] += strength
            
            # Normalize
            if signal_values.max() > 0:
                signal_values = signal_values / signal_values.max()
        
        # Create mesh with colored vertices
        vertices = []
        colors = []
        indices = []
        
        for i in range(resolution):
            for j in range(resolution):
                x = min_x + (i / (resolution - 1)) * (max_x - min_x)
                z = min_z + (j / (resolution - 1)) * (max_z - min_z)
                y = 0.01  # Just above floor
                
                vertices.extend([x, y, z])
                
                # Color map: blue (weak) -> green -> yellow -> red (strong)
                v = signal_values[i, j]
                if v < 0.25:
                    r, g, b = 0, v * 4, 1 - v * 2
                elif v < 0.5:
                    r, g, b = 0, 1, 1 - (v - 0.25) * 4
                elif v < 0.75:
                    r, g, b = (v - 0.5) * 4, 1, 0
                else:
                    r, g, b = 1, 1 - (v - 0.75) * 4, 0
                
                colors.extend([r, g, b, 0.5])
        
        # Create triangles
        for i in range(resolution - 1):
            for j in range(resolution - 1):
                idx = i * resolution + j
                # Two triangles per cell
                indices.extend([idx, idx + 1, idx + resolution])
                indices.extend([idx + 1, idx + resolution + 1, idx + resolution])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=heatmap_name,
            albedo=(0.5, 0.5, 0.5),
            emission=(0.3, 0.3, 0.3),
            emission_strength=0.4,
            opacity=0.6
        )
        
        heatmap = Object3D(
            name=heatmap_name,
            mesh=mesh,
            material=material,
            data={"type": "signal_heatmap"}
        )
        
        self.scene.add_object(heatmap)
        return heatmap

    def create_multipath_visualization(self, tx_pos: Tuple[float, float, float],
                                         rx_pos: Tuple[float, float, float],
                                         reflection_points: List[Tuple[float, float, float]] = None):
        """
        Visualize multipath signal propagation with reflections.
        """
        vis_name = "multipath_vis"
        
        # Remove existing
        for i in range(10):
            existing = self.scene.find_object(f"{vis_name}_{i}")
            if existing:
                self.scene.remove_object(existing)
        
        # Direct path
        direct_vertices = [
            tx_pos[0], tx_pos[1], tx_pos[2],
            rx_pos[0], rx_pos[1], rx_pos[2]
        ]
        
        direct_mesh = Mesh3D(
            vertices=np.array(direct_vertices, dtype=np.float32),
            colors=np.array([0, 1, 0, 1, 0, 1, 0, 0.5], dtype=np.float32),
            indices=np.array([0, 1], dtype=np.uint32)
        )
        
        direct_line = Object3D(
            name=f"{vis_name}_direct",
            mesh=direct_mesh,
            material=Material3D(
                name=f"{vis_name}_direct",
                albedo=(0, 1, 0),
                emission=(0, 1, 0),
                emission_strength=0.8,
                opacity=0.7,
                wireframe=True
            ),
            data={"type": "multipath", "path": "direct"}
        )
        self.scene.add_object(direct_line)
        
        # Reflection paths
        if reflection_points is None:
            # Generate some default reflection points based on room walls
            reflection_points = [
                (-4, 1.5, 0),   # Left wall
                (4, 1.5, 0),    # Right wall
                (0, 1.5, -4),   # Back wall
            ]
        
        path_colors = [
            (1, 0.6, 0),   # Orange
            (0.6, 0, 1),   # Purple
            (1, 0.2, 0.6), # Pink
        ]
        
        for i, (reflect_pt, color) in enumerate(zip(reflection_points, path_colors)):
            # Path: tx -> reflection -> rx
            path_verts = [
                tx_pos[0], tx_pos[1], tx_pos[2],
                reflect_pt[0], reflect_pt[1], reflect_pt[2],
                rx_pos[0], rx_pos[1], rx_pos[2]
            ]
            
            path_colors_arr = [
                color[0], color[1], color[2], 0.8,
                color[0], color[1], color[2], 0.6,
                color[0], color[1], color[2], 0.3
            ]
            
            path_mesh = Mesh3D(
                vertices=np.array(path_verts, dtype=np.float32),
                colors=np.array(path_colors_arr, dtype=np.float32),
                indices=np.array([0, 1, 1, 2], dtype=np.uint32)
            )
            
            path_obj = Object3D(
                name=f"{vis_name}_{i}",
                mesh=path_mesh,
                material=Material3D(
                    name=f"{vis_name}_{i}",
                    albedo=color,
                    emission=color,
                    emission_strength=0.5,
                    opacity=0.5,
                    wireframe=True
                ),
                data={"type": "multipath", "path": f"reflection_{i}"}
            )
            
            # Animate with pulsing
            def animate_path(obj: Object3D, dt: float, idx=i):
                t = time.time()
                obj.material.opacity = 0.3 + 0.2 * math.sin(t * 2 + idx * 0.5)
            
            path_obj.animation_callback = animate_path
            self.scene.add_object(path_obj)

    def create_motion_trail_3d(self, entity_id: str, 
                                positions: List[Tuple[float, float, float]],
                                max_points: int = 50):
        """
        Create a 3D motion trail showing movement history.
        """
        trail_name = f"motion_trail_{entity_id}"
        existing = self.scene.find_object(trail_name)
        if existing:
            self.scene.remove_object(existing)
        
        if not positions or len(positions) < 2:
            return
        
        # Limit points
        positions = positions[-max_points:]
        
        vertices = []
        colors = []
        indices = []
        
        for i, pos in enumerate(positions):
            vertices.extend([pos[0], pos[1], pos[2]])
            
            # Fade from bright to dim
            alpha = (i + 1) / len(positions)
            colors.extend([0, alpha, 1, alpha * 0.8])
        
        # Connect consecutive points
        for i in range(len(positions) - 1):
            indices.extend([i, i + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=trail_name,
            albedo=(0, 0.5, 1),
            emission=(0, 0.7, 1),
            emission_strength=0.6,
            opacity=0.7,
            wireframe=True
        )
        
        trail = Object3D(
            name=trail_name,
            mesh=mesh,
            material=material,
            data={"type": "motion_trail", "entity_id": entity_id}
        )
        
        self.scene.add_object(trail)
        return trail

    def create_radar_sweep(self, center: Tuple[float, float, float],
                            radius: float = 6.0,
                            angle: float = 0.0,
                            sweep_width: float = 45.0):
        """
        Create a radar-style sweep visualization emanating from a sensor.
        """
        sweep_name = "radar_sweep"
        existing = self.scene.find_object(sweep_name)
        if existing:
            self.scene.remove_object(existing)
        
        segments = 20
        vertices = [center[0], center[1], center[2]]  # Center point
        colors = [0.0, 1.0, 0.5, 0.9]  # Bright at center
        indices = []
        
        half_width = math.radians(sweep_width / 2)
        
        for i in range(segments + 1):
            t = i / segments
            current_angle = angle - half_width + t * 2 * half_width
            
            x = center[0] + math.cos(current_angle) * radius
            z = center[2] + math.sin(current_angle) * radius
            y = center[1] - 0.5  # Slightly below center
            
            vertices.extend([x, y, z])
            
            # Fade toward edges
            edge_fade = 1 - abs(2 * t - 1)
            colors.extend([0.0, 1.0, 0.5, 0.4 * edge_fade])
        
        # Connect to center
        for i in range(segments):
            indices.extend([0, i + 1, i + 2])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=sweep_name,
            albedo=(0.0, 1.0, 0.5),
            emission=(0.0, 1.0, 0.5),
            emission_strength=0.8,
            opacity=0.4
        )
        
        sweep = Object3D(
            name=sweep_name,
            mesh=mesh,
            material=material,
            data={"type": "radar_sweep", "angle": angle}
        )
        
        # Rotation animation
        def animate_sweep(obj: Object3D, dt: float, ctr=center, rad=radius):
            t = time.time()
            angle = t * 1.5  # Rotation speed
            # Recreate vertices for new angle - simplified by rotating object
            obj.rotation = (0, angle, 0)
            # Pulsing opacity
            obj.material.opacity = 0.3 + 0.15 * math.sin(t * 3)
        
        sweep.animation_callback = animate_sweep
        self.scene.add_object(sweep)
        return sweep

    def create_occupancy_zones(self, zones: List[Dict] = None):
        """
        Create visual zones showing room occupancy regions.
        Each zone can have different occupancy levels.
        """
        # Default zones if not provided
        if zones is None:
            zones = [
                {"id": "zone_nw", "bounds": (-4, -4, -1, -1), "name": "NW", "occupancy": 0},
                {"id": "zone_ne", "bounds": (1, -4, 4, -1), "name": "NE", "occupancy": 0},
                {"id": "zone_sw", "bounds": (-4, 1, -1, 4), "name": "SW", "occupancy": 0},
                {"id": "zone_se", "bounds": (1, 1, 4, 4), "name": "SE", "occupancy": 0},
                {"id": "zone_center", "bounds": (-1, -1, 1, 1), "name": "Center", "occupancy": 0},
            ]
        
        for zone in zones:
            zone_name = f"occupancy_{zone['id']}"
            existing = self.scene.find_object(zone_name)
            if existing:
                self.scene.remove_object(existing)
            
            min_x, min_z, max_x, max_z = zone['bounds']
            occupancy = zone.get('occupancy', 0)
            
            # Color based on occupancy (green=empty, yellow=low, orange=medium, red=high)
            if occupancy == 0:
                color = (0.2, 0.5, 0.2)
                alpha = 0.15
            elif occupancy == 1:
                color = (0.8, 0.8, 0.2)
                alpha = 0.25
            elif occupancy == 2:
                color = (0.9, 0.5, 0.1)
                alpha = 0.35
            else:
                color = (0.9, 0.2, 0.2)
                alpha = 0.45
            
            # Create zone quad
            vertices = [
                min_x, 0.02, min_z,
                max_x, 0.02, min_z,
                max_x, 0.02, max_z,
                min_x, 0.02, max_z,
            ]
            
            zone_colors = [
                color[0], color[1], color[2], alpha,
                color[0], color[1], color[2], alpha,
                color[0], color[1], color[2], alpha,
                color[0], color[1], color[2], alpha,
            ]
            
            indices = [0, 1, 2, 0, 2, 3]
            
            mesh = Mesh3D(
                vertices=np.array(vertices, dtype=np.float32),
                colors=np.array(zone_colors, dtype=np.float32),
                indices=np.array(indices, dtype=np.uint32)
            )
            
            material = Material3D(
                name=zone_name,
                albedo=color,
                emission=color,
                emission_strength=0.3 + occupancy * 0.2,
                opacity=alpha
            )
            
            zone_obj = Object3D(
                name=zone_name,
                mesh=mesh,
                material=material,
                data={"type": "occupancy_zone", "zone_id": zone['id'], "occupancy": occupancy}
            )
            
            self.scene.add_object(zone_obj)

    def create_breathing_wave(self, position: Tuple[float, float, float],
                               breathing_rate: float = 12.0,
                               amplitude: float = 0.3):
        """
        Create an animated breathing wave visualization around a person.
        """
        wave_name = "breathing_wave"
        existing = self.scene.find_object(wave_name)
        if existing:
            self.scene.remove_object(existing)
        
        segments = 48
        vertices = []
        colors = []
        indices = []
        
        t = time.time()
        breath_phase = t * (breathing_rate / 60.0) * 2 * math.pi
        
        for i in range(segments):
            angle = (i / segments) * 2 * math.pi
            
            # Breathing modulation
            r = 0.6 + amplitude * math.sin(breath_phase)
            
            x = position[0] + math.cos(angle) * r
            z = position[2] + math.sin(angle) * r
            y = position[1] + 0.1
            
            vertices.extend([x, y, z])
            
            # Color varies with breathing
            intensity = 0.5 + 0.5 * math.sin(breath_phase)
            colors.extend([0.2, 0.6 + 0.4 * intensity, 0.8, 0.5])
        
        # Close the ring
        for i in range(segments):
            indices.extend([i, (i + 1) % segments])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=wave_name,
            albedo=(0.2, 0.7, 0.9),
            emission=(0.2, 0.8, 1.0),
            emission_strength=0.8,
            opacity=0.5,
            wireframe=True
        )
        
        wave = Object3D(
            name=wave_name,
            mesh=mesh,
            material=material,
            position=(0, 0, 0),
            data={"type": "breathing_wave", "rate": breathing_rate}
        )
        
        # Animation to update the wave
        def animate_breathing_wave(obj: Object3D, dt: float, pos=position, rate=breathing_rate, amp=amplitude):
            t = time.time()
            phase = t * (rate / 60.0) * 2 * math.pi
            r = 0.6 + amp * math.sin(phase)
            
            # Update scale to simulate breathing
            scale_factor = 1.0 + 0.15 * math.sin(phase)
            obj.scale = (scale_factor, 1, scale_factor)
            
            # Pulse emission
            obj.material.emission_strength = 0.6 + 0.3 * math.sin(phase)
        
        wave.animation_callback = animate_breathing_wave
        self.scene.add_object(wave)
        return wave

    def create_signal_ray_trace(self, tx_pos: Tuple[float, float, float],
                                  rx_pos: Tuple[float, float, float],
                                  obstacles: List[Tuple[float, float, float]] = None):
        """
        Visualize signal ray tracing with obstacles showing signal blockage/reflection.
        """
        ray_name = "signal_ray_trace"
        
        # Remove existing rays
        for i in range(20):
            existing = self.scene.find_object(f"{ray_name}_{i}")
            if existing:
                self.scene.remove_object(existing)
        
        # Direct ray
        direct_verts = [
            tx_pos[0], tx_pos[1], tx_pos[2],
            rx_pos[0], rx_pos[1], rx_pos[2]
        ]
        
        direct_mesh = Mesh3D(
            vertices=np.array(direct_verts, dtype=np.float32),
            colors=np.array([0, 1, 0, 1, 0, 1, 0, 0.5], dtype=np.float32),
            indices=np.array([0, 1], dtype=np.uint32)
        )
        
        direct_obj = Object3D(
            name=f"{ray_name}_direct",
            mesh=direct_mesh,
            material=Material3D(
                name=f"{ray_name}_direct",
                albedo=(0, 1, 0),
                emission=(0, 1, 0),
                emission_strength=1.0,
                opacity=0.8,
                wireframe=True
            ),
            data={"type": "ray_trace", "ray": "direct"}
        )
        self.scene.add_object(direct_obj)
        
        # Add obstacle reflection rays
        if obstacles:
            for i, obs in enumerate(obstacles[:5]):  # Limit to 5 obstacles
                # Ray from tx to obstacle
                ray1_verts = [
                    tx_pos[0], tx_pos[1], tx_pos[2],
                    obs[0], obs[1], obs[2]
                ]
                # Ray from obstacle to rx
                ray2_verts = [
                    obs[0], obs[1], obs[2],
                    rx_pos[0], rx_pos[1], rx_pos[2]
                ]
                
                # Combined path
                path_verts = ray1_verts + ray2_verts[3:]  # Avoid duplicate point
                
                path_colors = [
                    1, 0.5, 0, 0.8,  # Orange at start
                    1, 0.3, 0, 0.6,  # Dim at obstacle
                    1, 0.5, 0, 0.3   # Faint at end
                ]
                
                path_mesh = Mesh3D(
                    vertices=np.array(path_verts, dtype=np.float32),
                    colors=np.array(path_colors, dtype=np.float32),
                    indices=np.array([0, 1, 1, 2], dtype=np.uint32)
                )
                
                path_obj = Object3D(
                    name=f"{ray_name}_{i}",
                    mesh=path_mesh,
                    material=Material3D(
                        name=f"{ray_name}_{i}",
                        albedo=(1, 0.5, 0),
                        emission=(1, 0.4, 0),
                        emission_strength=0.5,
                        opacity=0.5,
                        wireframe=True
                    ),
                    data={"type": "ray_trace", "ray": f"reflected_{i}"}
                )
                self.scene.add_object(path_obj)

    def create_ml_prediction_display(self, position: Tuple[float, float, float],
                                       predictions: Dict[str, float] = None):
        """
        Create a visual display for ML-based activity predictions.
        Shows confidence bars floating above a detected person.
        """
        display_name = "ml_prediction"
        existing = self.scene.find_object(display_name)
        if existing:
            self.scene.remove_object(existing)
        
        if predictions is None:
            predictions = {
                "walking": 0.7,
                "sitting": 0.15,
                "standing": 0.1,
                "other": 0.05
            }
        
        # Create floating bars above position
        bar_height = 0.08
        bar_spacing = 0.12
        start_y = position[1] + 0.8
        
        all_vertices = []
        all_colors = []
        all_indices = []
        
        activity_colors = {
            "walking": (0.2, 0.8, 0.3),
            "running": (1.0, 0.6, 0.0),
            "sitting": (0.3, 0.5, 0.9),
            "standing": (0.6, 0.6, 0.6),
            "sleeping": (0.5, 0.3, 0.8),
            "other": (0.4, 0.4, 0.4),
        }
        
        idx_offset = 0
        sorted_preds = sorted(predictions.items(), key=lambda x: -x[1])[:4]
        
        for i, (activity, confidence) in enumerate(sorted_preds):
            y = start_y + i * bar_spacing
            bar_width = confidence * 0.8  # Max width 0.8
            
            color = activity_colors.get(activity, (0.5, 0.5, 0.5))
            
            # Bar vertices (quad)
            bar_verts = [
                position[0] - 0.4, y, position[2],
                position[0] - 0.4 + bar_width, y, position[2],
                position[0] - 0.4 + bar_width, y + bar_height, position[2],
                position[0] - 0.4, y + bar_height, position[2],
            ]
            all_vertices.extend(bar_verts)
            
            # Colors with alpha based on confidence
            alpha = 0.4 + confidence * 0.4
            for _ in range(4):
                all_colors.extend([color[0], color[1], color[2], alpha])
            
            # Indices
            base = idx_offset
            all_indices.extend([base, base+1, base+2, base, base+2, base+3])
            idx_offset += 4
        
        if not all_vertices:
            return
        
        mesh = Mesh3D(
            vertices=np.array(all_vertices, dtype=np.float32),
            colors=np.array(all_colors, dtype=np.float32),
            indices=np.array(all_indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=display_name,
            albedo=(0.5, 0.5, 0.5),
            emission=(0.3, 0.5, 0.3),
            emission_strength=0.5,
            opacity=0.7
        )
        
        display = Object3D(
            name=display_name,
            mesh=mesh,
            material=material,
            data={"type": "ml_prediction", "predictions": predictions}
        )
        
        # Gentle bobbing animation
        def animate_display(obj: Object3D, dt: float):
            t = time.time()
            obj.position = (0, 0.05 * math.sin(t * 2), 0)
        
        display.animation_callback = animate_display
        self.scene.add_object(display)
        return display

    def create_doppler_field(self, center: Tuple[float, float, float],
                              doppler_values: np.ndarray = None,
                              resolution: int = 8):
        """
        Visualize Doppler velocity field across the room as arrows.
        """
        field_name = "doppler_field"
        
        # Remove existing
        for i in range(resolution * resolution):
            existing = self.scene.find_object(f"{field_name}_{i}")
            if existing:
                self.scene.remove_object(existing)
        
        if doppler_values is None:
            # Generate simulated Doppler field
            doppler_values = np.random.randn(resolution, resolution) * 0.5
        
        bounds = 6.0
        step = bounds * 2 / resolution
        
        for i in range(resolution):
            for j in range(resolution):
                x = -bounds + i * step + step / 2
                z = -bounds + j * step + step / 2
                y = 0.5
                
                doppler = doppler_values[i, j] if i < doppler_values.shape[0] and j < doppler_values.shape[1] else 0
                
                if abs(doppler) < 0.05:
                    continue  # Skip near-zero values
                
                # Arrow direction and length based on doppler
                arrow_length = min(0.5, abs(doppler) * 0.5)
                arrow_dir = 1 if doppler > 0 else -1
                
                # Color: green for approaching, red for receding
                if doppler > 0:
                    color = (0.2, 0.9, 0.3)
                else:
                    color = (0.9, 0.3, 0.2)
                
                # Create simple arrow (line with head)
                arrow_verts = [
                    x, y, z,
                    x + arrow_dir * arrow_length, y, z
                ]
                
                arrow_mesh = Mesh3D(
                    vertices=np.array(arrow_verts, dtype=np.float32),
                    colors=np.array([color[0], color[1], color[2], 0.7,
                                     color[0], color[1], color[2], 0.3], dtype=np.float32),
                    indices=np.array([0, 1], dtype=np.uint32)
                )
                
                arrow_obj = Object3D(
                    name=f"{field_name}_{i * resolution + j}",
                    mesh=arrow_mesh,
                    material=Material3D(
                        name=f"{field_name}_{i * resolution + j}",
                        albedo=color,
                        emission=color,
                        emission_strength=0.6,
                        opacity=0.6,
                        wireframe=True
                    ),
                    data={"type": "doppler_field", "value": doppler}
                )
                self.scene.add_object(arrow_obj)

    def create_radar_sweep(self, origin: Tuple[float, float, float],
                            range_m: float = 6.0, sweep_speed: float = 1.0):
        """
        Create an animated radar sweep effect emanating from a sensor position.
        The sweep rotates 360 degrees showing detected objects.
        """
        sweep_name = "radar_sweep"
        existing = self.scene.find_object(sweep_name)
        if existing:
            self.scene.remove_object(existing)
        
        # Create sweep arc (pie slice)
        segments = 24
        arc_angle = math.radians(45)  # 45-degree sweep arc
        vertices = [origin[0], origin[1], origin[2]]  # Center
        colors = [0.0, 1.0, 0.5, 0.9]  # Bright at center
        indices = []
        
        for i in range(segments + 1):
            t = i / segments
            angle = -arc_angle / 2 + t * arc_angle
            
            x = origin[0] + math.cos(angle) * range_m
            z = origin[2] + math.sin(angle) * range_m
            y = origin[1]
            
            vertices.extend([x, y, z])
            # Fade out at edges and distance
            fade = 1 - abs(t - 0.5) * 2
            alpha = 0.6 * fade
            colors.extend([0.0, 0.8, 0.4, alpha])
        
        # Connect triangles to center
        for i in range(segments):
            indices.extend([0, i + 1, i + 2])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=sweep_name,
            albedo=(0.0, 0.8, 0.4),
            emission=(0.0, 1.0, 0.5),
            emission_strength=0.8,
            opacity=0.4
        )
        
        sweep = Object3D(
            name=sweep_name,
            mesh=mesh,
            material=material,
            position=(0, 0, 0),
            data={"type": "radar_sweep"}
        )
        
        # Continuous rotation animation
        def animate_sweep(obj: Object3D, dt: float, speed=sweep_speed):
            t = time.time()
            angle = (t * speed) % (2 * math.pi)
            obj.rotation = (0, angle, 0)
            # Pulse the intensity
            obj.material.emission_strength = 0.6 + 0.3 * math.sin(t * 5)
        
        sweep.animation_callback = animate_sweep
        self.scene.add_object(sweep)
        return sweep

    def create_presence_zones(self, zones: List[Tuple[float, float, float, float, float]] = None):
        """
        Create presence detection zones with occupancy visualization.
        Each zone can show current occupancy intensity.
        
        zones: List of (min_x, min_z, max_x, max_z, intensity) tuples
        """
        zone_base_name = "presence_zone"
        
        # Remove existing zones
        for i in range(20):
            existing = self.scene.find_object(f"{zone_base_name}_{i}")
            if existing:
                self.scene.remove_object(existing)
        
        if zones is None:
            # Create default 3x3 grid of zones
            zones = []
            for i in range(3):
                for j in range(3):
                    min_x = -4 + i * 2.5
                    min_z = -4 + j * 2.5
                    max_x = min_x + 2.3
                    max_z = min_z + 2.3
                    # Random intensity for demo
                    intensity = 0.1 + 0.9 * math.sin(time.time() + i + j * 0.5) ** 2
                    zones.append((min_x, min_z, max_x, max_z, intensity))
        
        for idx, (min_x, min_z, max_x, max_z, intensity) in enumerate(zones):
            # Create zone rectangle on floor
            vertices = [
                min_x, 0.02, min_z,
                max_x, 0.02, min_z,
                max_x, 0.02, max_z,
                min_x, 0.02, max_z,
            ]
            
            # Color based on intensity: blue -> green -> yellow -> red
            if intensity < 0.33:
                r, g, b = 0, intensity * 3, 1 - intensity * 2
            elif intensity < 0.66:
                r, g, b = (intensity - 0.33) * 3, 1, 0
            else:
                r, g, b = 1, 1 - (intensity - 0.66) * 3, 0
            
            alpha = 0.3 + intensity * 0.4
            
            colors = [
                r, g, b, alpha,
                r, g, b, alpha,
                r, g, b, alpha,
                r, g, b, alpha,
            ]
            
            indices = [0, 1, 2, 0, 2, 3]
            
            mesh = Mesh3D(
                vertices=np.array(vertices, dtype=np.float32),
                colors=np.array(colors, dtype=np.float32),
                indices=np.array(indices, dtype=np.uint32)
            )
            
            material = Material3D(
                name=f"{zone_base_name}_{idx}",
                albedo=(r, g, b),
                emission=(r, g, b),
                emission_strength=0.3 + intensity * 0.5,
                opacity=alpha
            )
            
            zone = Object3D(
                name=f"{zone_base_name}_{idx}",
                mesh=mesh,
                material=material,
                data={"type": "presence_zone", "intensity": intensity, "index": idx}
            )
            
            # Subtle pulse animation
            def animate_zone(obj: Object3D, dt: float, base_intensity=intensity):
                t = time.time()
                pulse = 0.9 + 0.1 * math.sin(t * 2)
                obj.material.emission_strength = (0.3 + base_intensity * 0.5) * pulse
            
            zone.animation_callback = animate_zone
            self.scene.add_object(zone)

    def create_interference_indicator(self, position: Tuple[float, float, float],
                                        interference_level: float = 0.5):
        """
        Visualize signal interference at a location.
        Shows as jagged, unstable energy pattern.
        """
        indicator_name = f"interference_{hash(position) % 1000}"
        existing = self.scene.find_object(indicator_name)
        if existing:
            self.scene.remove_object(existing)
        
        # Create spiky interference pattern
        segments = 16
        vertices = []
        colors = []
        indices = []
        
        base_radius = 0.3 + interference_level * 0.3
        
        for i in range(segments):
            angle = (i / segments) * 2 * math.pi
            # Jagged radius variation
            spike = 1.0 + 0.3 * math.sin(i * 5) * interference_level
            r = base_radius * spike
            
            x = position[0] + r * math.cos(angle)
            z = position[2] + r * math.sin(angle)
            y = position[1]
            
            vertices.extend([x, y, z])
            
            # Red/orange color for interference
            colors.extend([1.0, 0.3 + 0.4 * (1 - interference_level), 0.1, 0.7])
        
        # Center vertex
        vertices.extend([position[0], position[1], position[2]])
        colors.extend([1.0, 0.5, 0.2, 0.9])
        center_idx = segments
        
        # Connect to center
        for i in range(segments):
            indices.extend([center_idx, i, (i + 1) % segments])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=indicator_name,
            albedo=(1.0, 0.4, 0.1),
            emission=(1.0, 0.3, 0.0),
            emission_strength=0.8 + interference_level * 0.5,
            opacity=0.6
        )
        
        indicator = Object3D(
            name=indicator_name,
            mesh=mesh,
            material=material,
            data={"type": "interference", "level": interference_level}
        )
        
        # Jitter animation
        def animate_interference(obj: Object3D, dt: float, level=interference_level):
            t = time.time()
            # Random-ish jitter
            jitter = 0.02 * level * math.sin(t * 20 + level * 100)
            obj.position = (position[0] + jitter, position[1], position[2] + jitter * 0.7)
            # Flicker
            obj.material.emission_strength = 0.6 + 0.4 * abs(math.sin(t * 15))
        
        indicator.animation_callback = animate_interference
        self.scene.add_object(indicator)
        return indicator

    def create_signal_strength_rings(self, center: Tuple[float, float, float],
                                       rssi: float = -50, max_rings: int = 5):
        """
        Create concentric rings showing signal strength propagation.
        Stronger signals have more/brighter rings.
        """
        rings_name = "signal_rings"
        
        # Remove existing rings
        for i in range(max_rings):
            existing = self.scene.find_object(f"{rings_name}_{i}")
            if existing:
                self.scene.remove_object(existing)
        
        # Convert RSSI to normalized strength (0-1)
        # Typical range: -30 (excellent) to -90 (weak)
        strength = max(0, min(1, (rssi + 90) / 60))
        num_rings = int(1 + strength * (max_rings - 1))
        
        for ring_idx in range(num_rings):
            radius = 0.5 + ring_idx * 1.0
            
            # Fade based on distance from center
            ring_strength = strength * (1 - ring_idx / max_rings)
            
            segments = 32
            vertices = []
            colors = []
            indices = []
            
            for i in range(segments):
                angle = (i / segments) * 2 * math.pi
                x = center[0] + radius * math.cos(angle)
                z = center[2] + radius * math.sin(angle)
                y = center[1]
                
                vertices.extend([x, y, z])
                
                # Blue to cyan gradient
                colors.extend([0.0, 0.5 + 0.5 * ring_strength, 1.0, ring_strength * 0.8])
            
            # Line loop
            for i in range(segments):
                indices.extend([i, (i + 1) % segments])
            
            mesh = Mesh3D(
                vertices=np.array(vertices, dtype=np.float32),
                colors=np.array(colors, dtype=np.float32),
                indices=np.array(indices, dtype=np.uint32)
            )
            
            material = Material3D(
                name=f"{rings_name}_{ring_idx}",
                albedo=(0.0, 0.7, 1.0),
                emission=(0.0, 0.8, 1.0),
                emission_strength=0.5 * ring_strength,
                opacity=ring_strength * 0.7,
                wireframe=True
            )
            
            ring = Object3D(
                name=f"{rings_name}_{ring_idx}",
                mesh=mesh,
                material=material,
                data={"type": "signal_ring", "rssi": rssi, "ring": ring_idx}
            )
            
            # Expand animation
            start_time = time.time()
            
            def animate_ring(obj: Object3D, dt: float, idx=ring_idx, t0=start_time):
                t = time.time()
                # Pulse outward
                phase = (t * 0.5 + idx * 0.3) % 1.0
                scale = 1.0 + 0.1 * math.sin(phase * 2 * math.pi)
                obj.scale = (scale, 1, scale)
                # Fade pulse
                obj.material.opacity = max(0.1, ring_strength * 0.7 * (0.7 + 0.3 * math.sin(t * 2 + idx)))
            
            ring.animation_callback = animate_ring
            self.scene.add_object(ring)

    def create_person_skeleton(self, entity_id: str, position: Tuple[float, float, float],
                                pose: str = "standing", activity: str = "idle"):
        """
        Create a more detailed person representation with skeletal visualization.
        """
        skeleton_name = f"skeleton_{entity_id}"
        existing = self.scene.find_object(skeleton_name)
        if existing:
            self.scene.remove_object(existing)
        
        x, y, z = position
        
        # Joint positions based on pose
        if pose == "sitting":
            height_scale = 0.7
            leg_angle = math.pi / 4
        elif pose == "walking":
            height_scale = 1.0
            leg_angle = math.pi / 12
        else:  # standing
            height_scale = 1.0
            leg_angle = 0
        
        # Define joints
        joints = {
            'head': (x, y + 1.7 * height_scale, z),
            'neck': (x, y + 1.5 * height_scale, z),
            'chest': (x, y + 1.2 * height_scale, z),
            'hip': (x, y + 0.9 * height_scale, z),
            'left_shoulder': (x - 0.2, y + 1.4 * height_scale, z),
            'right_shoulder': (x + 0.2, y + 1.4 * height_scale, z),
            'left_elbow': (x - 0.35, y + 1.1 * height_scale, z),
            'right_elbow': (x + 0.35, y + 1.1 * height_scale, z),
            'left_hand': (x - 0.4, y + 0.85 * height_scale, z),
            'right_hand': (x + 0.4, y + 0.85 * height_scale, z),
            'left_knee': (x - 0.1, y + 0.5 * height_scale, z + math.sin(leg_angle) * 0.3),
            'right_knee': (x + 0.1, y + 0.5 * height_scale, z - math.sin(leg_angle) * 0.3),
            'left_foot': (x - 0.1, y + 0.05, z + math.sin(leg_angle) * 0.1),
            'right_foot': (x + 0.1, y + 0.05, z - math.sin(leg_angle) * 0.1),
        }
        
        # Define bones (connections between joints)
        bones = [
            ('head', 'neck'),
            ('neck', 'chest'),
            ('chest', 'hip'),
            ('neck', 'left_shoulder'),
            ('neck', 'right_shoulder'),
            ('left_shoulder', 'left_elbow'),
            ('right_shoulder', 'right_elbow'),
            ('left_elbow', 'left_hand'),
            ('right_elbow', 'right_hand'),
            ('hip', 'left_knee'),
            ('hip', 'right_knee'),
            ('left_knee', 'left_foot'),
            ('right_knee', 'right_foot'),
        ]
        
        vertices = []
        colors = []
        indices = []
        
        # Activity color
        activity_colors = {
            'walking': (0.2, 0.9, 0.3),
            'running': (1.0, 0.6, 0.1),
            'sitting': (0.3, 0.5, 0.9),
            'idle': (0.5, 0.5, 0.5),
        }
        color = activity_colors.get(activity.lower(), (0.5, 0.8, 0.5))
        
        idx = 0
        for joint1, joint2 in bones:
            p1 = joints[joint1]
            p2 = joints[joint2]
            
            vertices.extend([p1[0], p1[1], p1[2]])
            vertices.extend([p2[0], p2[1], p2[2]])
            colors.extend([color[0], color[1], color[2], 0.9])
            colors.extend([color[0], color[1], color[2], 0.9])
            indices.extend([idx, idx + 1])
            idx += 2
        
        # Add joint spheres (as additional vertices at joint positions)
        for joint_name, joint_pos in joints.items():
            vertices.extend([joint_pos[0], joint_pos[1], joint_pos[2]])
            # Brighter color for joints
            colors.extend([min(1, color[0] + 0.3), min(1, color[1] + 0.3), min(1, color[2] + 0.3), 1.0])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=skeleton_name,
            albedo=color,
            emission=color,
            emission_strength=0.6,
            opacity=0.9,
            wireframe=True
        )
        
        skeleton = Object3D(
            name=skeleton_name,
            mesh=mesh,
            material=material,
            data={"type": "skeleton", "entity_id": entity_id, "pose": pose, "activity": activity}
        )
        
        # Walking animation
        if activity.lower() == "walking":
            def animate_walking(obj: Object3D, dt: float):
                t = time.time()
                # Subtle bob
                obj.position = (0, 0.02 * math.sin(t * 6), 0)
            skeleton.animation_callback = animate_walking
        
        self.scene.add_object(skeleton)
        return skeleton

    # =========================================================================
    # ROOM LEARNING & FURNITURE DETECTION
    # =========================================================================
    
    def create_learned_room_layout(self, walls: List[Tuple[Tuple[float, float, float], Tuple[float, float, float]]],
                                    furniture: List[dict] = None):
        """
        Visualize learned room layout from CSI analysis.
        walls: List of (start_pos, end_pos) tuples
        furniture: List of {'type': str, 'position': (x,y,z), 'size': (w,h,d), 'confidence': float}
        """
        layout_name = "room_layout"
        
        # Remove existing layout
        for obj in list(self.scene.objects):
            if obj.name.startswith(layout_name):
                self.scene.remove_object(obj)
        
        # Draw detected walls
        for i, (start, end) in enumerate(walls):
            wall_vertices = []
            wall_colors = []
            wall_indices = []
            
            # Create wall as a vertical plane
            wall_height = 2.8
            
            # Bottom edge
            wall_vertices.extend([start[0], 0.01, start[2]])
            wall_vertices.extend([end[0], 0.01, end[2]])
            # Top edge
            wall_vertices.extend([start[0], wall_height, start[2]])
            wall_vertices.extend([end[0], wall_height, end[2]])
            
            # Wall color (detected = green, uncertain = yellow)
            for _ in range(4):
                wall_colors.extend([0.2, 0.8, 0.4, 0.3])
            
            # Two triangles for quad
            wall_indices.extend([0, 1, 2, 1, 3, 2])
            
            mesh = Mesh3D(
                vertices=np.array(wall_vertices, dtype=np.float32),
                colors=np.array(wall_colors, dtype=np.float32),
                indices=np.array(wall_indices, dtype=np.uint32)
            )
            
            material = Material3D(
                name=f"{layout_name}_wall_{i}",
                albedo=(0.2, 0.8, 0.4),
                emission=(0.1, 0.5, 0.2),
                emission_strength=0.3,
                opacity=0.3
            )
            
            wall_obj = Object3D(
                name=f"{layout_name}_wall_{i}",
                mesh=mesh,
                material=material,
                data={"type": "learned_wall"}
            )
            self.scene.add_object(wall_obj)
        
        # Draw detected furniture
        if furniture:
            for j, item in enumerate(furniture):
                self._create_furniture_item(f"{layout_name}_furniture_{j}", item)
    
    def _create_furniture_item(self, name: str, item: dict):
        """Create a 3D representation of detected furniture."""
        existing = self.scene.find_object(name)
        if existing:
            self.scene.remove_object(existing)
        
        ftype = item.get('type', 'box')
        pos = item.get('position', (0, 0, 0))
        size = item.get('size', (0.5, 0.5, 0.5))
        conf = item.get('confidence', 0.5)
        
        # Color based on furniture type
        type_colors = {
            'chair': (0.6, 0.4, 0.2),
            'table': (0.5, 0.3, 0.1),
            'couch': (0.3, 0.3, 0.7),
            'bed': (0.8, 0.6, 0.5),
            'desk': (0.4, 0.4, 0.4),
            'cabinet': (0.5, 0.5, 0.3),
            'box': (0.5, 0.5, 0.5),
        }
        color = type_colors.get(ftype.lower(), (0.5, 0.5, 0.5))
        
        # Create box mesh
        mesh = self._create_box_mesh(size, alpha=conf * 0.6)
        
        material = Material3D(
            name=name,
            albedo=color,
            emission=color,
            emission_strength=0.2 * conf,
            opacity=conf * 0.5
        )
        
        furniture_obj = Object3D(
            name=name,
            mesh=mesh,
            material=material,
            position=pos,
            data={"type": "furniture", "furniture_type": ftype, "confidence": conf}
        )
        
        self.scene.add_object(furniture_obj)
        return furniture_obj
    
    def _create_box_mesh(self, size: Tuple[float, float, float], alpha: float = 0.5):
        """Create a box mesh with given dimensions."""
        w, h, d = size[0] / 2, size[1] / 2, size[2] / 2
        
        vertices = [
            # Front face
            -w, -h, d,   w, -h, d,   w, h, d,   -w, h, d,
            # Back face
            -w, -h, -d,  -w, h, -d,  w, h, -d,   w, -h, -d,
            # Top face
            -w, h, -d,   -w, h, d,   w, h, d,    w, h, -d,
            # Bottom face
            -w, -h, -d,  w, -h, -d,  w, -h, d,  -w, -h, d,
            # Right face
            w, -h, -d,   w, h, -d,   w, h, d,    w, -h, d,
            # Left face
            -w, -h, -d,  -w, -h, d,  -w, h, d,  -w, h, -d,
        ]
        
        colors = [0.5, 0.5, 0.5, alpha] * 24  # 24 vertices, same color
        
        indices = [
            0, 1, 2, 0, 2, 3,    # Front
            4, 5, 6, 4, 6, 7,    # Back
            8, 9, 10, 8, 10, 11,  # Top
            12, 13, 14, 12, 14, 15,  # Bottom
            16, 17, 18, 16, 18, 19,  # Right
            20, 21, 22, 20, 22, 23,  # Left
        ]
        
        return Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
    
    def create_gesture_indicator(self, entity_id: str, position: Tuple[float, float, float],
                                  gesture: str, confidence: float = 0.8):
        """
        Display detected gesture as floating icon/text above entity.
        """
        gesture_name = f"gesture_{entity_id}"
        existing = self.scene.find_object(gesture_name)
        if existing:
            self.scene.remove_object(existing)
        
        # Gesture icons (simple shapes to represent different gestures)
        gesture_shapes = {
            'wave': {'color': (0.2, 0.9, 0.4), 'icon': '👋'},
            'point': {'color': (0.9, 0.6, 0.1), 'icon': '👆'},
            'swipe_left': {'color': (0.3, 0.6, 0.9), 'icon': '⬅️'},
            'swipe_right': {'color': (0.3, 0.6, 0.9), 'icon': '➡️'},
            'push': {'color': (0.9, 0.3, 0.3), 'icon': '✋'},
            'circle': {'color': (0.7, 0.4, 0.9), 'icon': '⭕'},
            'tap': {'color': (0.9, 0.9, 0.3), 'icon': '☝️'},
        }
        
        gesture_info = gesture_shapes.get(gesture.lower(), {'color': (0.5, 0.5, 0.5), 'icon': '?'})
        color = gesture_info['color']
        
        # Position above entity head
        icon_pos = (position[0], position[1] + 2.2, position[2])
        
        # Create a floating indicator (simple quad with gesture visualization)
        size = 0.4 * confidence
        
        vertices = [
            icon_pos[0] - size, icon_pos[1] - size, icon_pos[2],
            icon_pos[0] + size, icon_pos[1] - size, icon_pos[2],
            icon_pos[0] + size, icon_pos[1] + size, icon_pos[2],
            icon_pos[0] - size, icon_pos[1] + size, icon_pos[2],
        ]
        
        colors = []
        for _ in range(4):
            colors.extend([color[0], color[1], color[2], confidence])
        
        indices = [0, 1, 2, 0, 2, 3]
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=gesture_name,
            albedo=color,
            emission=color,
            emission_strength=0.8,
            opacity=confidence * 0.9
        )
        
        gesture_obj = Object3D(
            name=gesture_name,
            mesh=mesh,
            material=material,
            data={"type": "gesture", "gesture": gesture, "confidence": confidence}
        )
        
        # Float/bob animation
        def animate_gesture(obj: Object3D, dt: float):
            t = time.time()
            base_y = icon_pos[1]
            obj.position = (0, 0.1 * math.sin(t * 3), 0)
            # Fade out over time
            age = t % 3.0
            if age < 2.0:
                obj.material.opacity = confidence * 0.9
            else:
                obj.material.opacity = confidence * 0.9 * (3.0 - age)
        
        gesture_obj.animation_callback = animate_gesture
        self.scene.add_object(gesture_obj)
        return gesture_obj
    
    def create_multi_room_view(self, rooms: List[dict]):
        """
        Create a multi-room view showing multiple tracked spaces.
        rooms: List of {'name': str, 'position': (x,y,z), 'size': (w,h,d), 
                       'occupancy': int, 'activity': str}
        """
        # Remove existing multi-room objects
        for obj in list(self.scene.objects):
            if obj.name.startswith("multiroom_"):
                self.scene.remove_object(obj)
        
        for i, room in enumerate(rooms):
            name = room.get('name', f'Room {i+1}')
            pos = room.get('position', (i * 6, 0, 0))
            size = room.get('size', (4, 2.8, 4))
            occupancy = room.get('occupancy', 0)
            activity = room.get('activity', 'empty')
            
            # Room box outline
            mesh = self._create_box_mesh(size, alpha=0.15)
            
            # Color based on occupancy/activity
            if occupancy > 0:
                color = (0.2, 0.8, 0.4) if activity != 'alert' else (0.9, 0.3, 0.3)
            else:
                color = (0.3, 0.3, 0.5)
            
            material = Material3D(
                name=f"multiroom_{i}",
                albedo=color,
                emission=color,
                emission_strength=0.2 + 0.3 * min(occupancy, 3) / 3,
                opacity=0.2 + 0.1 * min(occupancy, 3),
                wireframe=False
            )
            
            room_obj = Object3D(
                name=f"multiroom_{i}",
                mesh=mesh,
                material=material,
                position=pos,
                data={"type": "room", "room_name": name, "occupancy": occupancy}
            )
            
            # Pulse if occupied
            if occupancy > 0:
                def animate_room(obj: Object3D, dt: float, occ=occupancy):
                    t = time.time()
                    pulse = 0.2 + 0.1 * math.sin(t * 2) * occ / 3
                    obj.material.emission_strength = pulse
                room_obj.animation_callback = animate_room
            
            self.scene.add_object(room_obj)
    
    def create_tracking_history(self, entity_id: str, 
                                 history: List[Tuple[float, float, float]],
                                 max_points: int = 100):
        """
        Visualize historical movement path of an entity.
        """
        history_name = f"history_{entity_id}"
        existing = self.scene.find_object(history_name)
        if existing:
            self.scene.remove_object(existing)
        
        if len(history) < 2:
            return
        
        # Limit to max points
        points = history[-max_points:]
        
        vertices = []
        colors = []
        indices = []
        
        for i, pos in enumerate(points):
            vertices.extend([pos[0], pos[1], pos[2]])
            
            # Fade older points
            age_factor = i / len(points)
            colors.extend([0.3, 0.8 * age_factor, 1.0, age_factor * 0.7])
            
            if i > 0:
                indices.extend([i - 1, i])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=history_name,
            albedo=(0.3, 0.8, 1.0),
            emission=(0.2, 0.6, 0.9),
            emission_strength=0.4,
            opacity=0.6,
            wireframe=True
        )
        
        history_obj = Object3D(
            name=history_name,
            mesh=mesh,
            material=material,
            data={"type": "history", "entity_id": entity_id, "point_count": len(points)}
        )
        
        self.scene.add_object(history_obj)
        return history_obj
    
    def create_zone_alert(self, zone_name: str, zone_bounds: Tuple[float, float, float, float],
                          alert_type: str = "intrusion", severity: float = 0.8):
        """
        Create visual alert for zone-based events.
        zone_bounds: (min_x, min_z, max_x, max_z)
        """
        alert_name = f"zone_alert_{zone_name}"
        existing = self.scene.find_object(alert_name)
        if existing:
            self.scene.remove_object(existing)
        
        min_x, min_z, max_x, max_z = zone_bounds
        center_x, center_z = (min_x + max_x) / 2, (min_z + max_z) / 2
        
        # Alert colors
        alert_colors = {
            'intrusion': (1.0, 0.1, 0.1),
            'loitering': (1.0, 0.6, 0.1),
            'tailgating': (0.9, 0.4, 0.7),
            'fall': (0.9, 0.2, 0.2),
            'normal': (0.2, 0.8, 0.3),
        }
        color = alert_colors.get(alert_type.lower(), (1.0, 0.5, 0.0))
        
        # Create zone outline with alert visualization
        segments = 20
        vertices = []
        colors = []
        indices = []
        
        # Rectangle outline
        corners = [
            (min_x, 0.02, min_z),
            (max_x, 0.02, min_z),
            (max_x, 0.02, max_z),
            (min_x, 0.02, max_z),
        ]
        
        for i, corner in enumerate(corners):
            vertices.extend(corner)
            colors.extend([color[0], color[1], color[2], severity])
            if i > 0:
                indices.extend([i - 1, i])
        indices.extend([3, 0])  # Close the rectangle
        
        # Add pulsing center point
        vertices.extend([center_x, 0.5, center_z])
        colors.extend([color[0], color[1], color[2], severity])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=alert_name,
            albedo=color,
            emission=color,
            emission_strength=0.8 * severity,
            opacity=severity * 0.7
        )
        
        alert_obj = Object3D(
            name=alert_name,
            mesh=mesh,
            material=material,
            data={"type": "zone_alert", "zone": zone_name, "alert_type": alert_type}
        )
        
        # Pulsing/flashing animation for alerts
        def animate_alert(obj: Object3D, dt: float, sev=severity):
            t = time.time()
            flash = 0.5 + 0.5 * math.sin(t * 8)  # Fast flash
            obj.material.emission_strength = 0.4 + 0.6 * flash * sev
            obj.material.opacity = 0.5 + 0.3 * flash * sev
        
        alert_obj.animation_callback = animate_alert
        self.scene.add_object(alert_obj)
        return alert_obj

    # ================================================================
    # ADVANCED VISUALIZATION METHODS - MAXIMUM CAPABILITY
    # ================================================================

    def create_holographic_person(self, entity_id: str, position: Tuple[float, float, float],
                                   confidence: float = 0.8, biometrics: dict = None):
        """
        Create a holographic 3D person representation with biometric overlays.
        Most advanced human visualization possible.
        """
        holo_name = f"hologram_{entity_id}"
        existing = self.scene.find_object(holo_name)
        if existing:
            self.scene.remove_object(existing)
        
        # Build detailed human mesh with multiple body parts
        vertices = []
        colors = []
        indices = []
        
        # Head (sphere approximation)
        head_y = position[1] + 1.6
        head_segments = 16
        for i in range(head_segments):
            theta = 2 * math.pi * i / head_segments
            for j in range(head_segments // 2):
                phi = math.pi * j / (head_segments // 2)
                
                x = position[0] + 0.12 * math.sin(phi) * math.cos(theta)
                y = head_y + 0.12 * math.cos(phi)
                z = position[2] + 0.12 * math.sin(phi) * math.sin(theta)
                
                vertices.extend([x, y, z])
                # Holographic blue-cyan color with confidence-based alpha
                colors.extend([0.0, 0.8, 1.0, confidence * 0.8])
        
        # Torso (cylinder)
        torso_top = position[1] + 1.45
        torso_bottom = position[1] + 0.9
        for i in range(16):
            theta = 2 * math.pi * i / 16
            
            x = position[0] + 0.18 * math.cos(theta)
            z = position[2] + 0.1 * math.sin(theta)
            
            vertices.extend([x, torso_top, z])
            colors.extend([0.0, 0.7, 0.9, confidence * 0.7])
            vertices.extend([x, torso_bottom, z])
            colors.extend([0.0, 0.6, 0.8, confidence * 0.6])
        
        # Legs
        for leg_offset in [-0.08, 0.08]:
            leg_x = position[0] + leg_offset
            for i in range(8):
                theta = 2 * math.pi * i / 8
                x = leg_x + 0.06 * math.cos(theta)
                z = position[2] + 0.06 * math.sin(theta)
                
                vertices.extend([x, position[1] + 0.9, z])
                colors.extend([0.0, 0.5, 0.7, confidence * 0.5])
                vertices.extend([x, position[1] + 0.05, z])
                colors.extend([0.0, 0.4, 0.6, confidence * 0.4])
        
        # Create wireframe indices
        num_verts = len(vertices) // 3
        for i in range(0, num_verts - 1, 2):
            indices.extend([i, i + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=holo_name,
            albedo=(0.0, 0.8, 1.0),
            emission=(0.0, 1.0, 1.0),
            emission_strength=1.2,
            opacity=confidence * 0.7,
            wireframe=True
        )
        
        hologram = Object3D(
            name=holo_name,
            mesh=mesh,
            material=material,
            data={"type": "hologram", "entity_id": entity_id, "biometrics": biometrics or {}}
        )
        
        # Holographic shimmer animation
        def animate_hologram(obj: Object3D, dt: float):
            t = time.time()
            # Vertical scan line effect
            scan = (t * 2) % 3.0
            obj.material.emission_strength = 0.8 + 0.4 * math.sin(t * 3)
            # Subtle position jitter for hologram effect
            jitter = 0.002 * math.sin(t * 20)
            obj.position = (position[0] + jitter, position[1], position[2] + jitter)
        
        hologram.animation_callback = animate_hologram
        self.scene.add_object(hologram)
        
        # Add biometric overlay if data provided
        if biometrics:
            self._add_biometric_overlay(entity_id, position, biometrics)
        
        return hologram

    def _add_biometric_overlay(self, entity_id: str, position: Tuple[float, float, float], 
                                biometrics: dict):
        """Add floating biometric data display near person."""
        overlay_name = f"bio_overlay_{entity_id}"
        existing = self.scene.find_object(overlay_name)
        if existing:
            self.scene.remove_object(existing)
        
        # Create small floating panel
        panel_pos = (position[0] + 0.5, position[1] + 1.8, position[2])
        
        mesh = Mesh3D.create_sphere(radius=0.1, segments=8)
        
        # Color based on health metrics
        hr = biometrics.get('heart_rate', 70)
        if hr < 60:
            color = (0.3, 0.3, 0.9)  # Blue - low
        elif hr > 100:
            color = (0.9, 0.3, 0.3)  # Red - high
        else:
            color = (0.3, 0.9, 0.3)  # Green - normal
        
        material = Material3D(
            name=overlay_name,
            albedo=color,
            emission=color,
            emission_strength=0.8,
            opacity=0.6
        )
        
        overlay = Object3D(
            name=overlay_name,
            mesh=mesh,
            material=material,
            position=panel_pos,
            data={"type": "biometric_overlay", "biometrics": biometrics}
        )
        
        # Pulsing animation synced to heart rate
        def animate_bio(obj: Object3D, dt: float, heart_rate=hr):
            t = time.time()
            beats_per_sec = heart_rate / 60.0
            pulse = 1.0 + 0.2 * abs(math.sin(t * math.pi * beats_per_sec))
            obj.scale = (pulse, pulse, pulse)
        
        overlay.animation_callback = animate_bio
        self.scene.add_object(overlay)

    def create_volumetric_csi_field(self, bounds: Tuple[float, float, float, float],
                                     csi_data: np.ndarray = None, resolution: int = 8):
        """
        Create a 3D volumetric visualization of CSI field strength.
        Shows signal propagation in 3D space.
        """
        field_name = "volumetric_csi_field"
        
        # Remove existing field objects
        for i in range(resolution ** 3):
            existing = self.scene.find_object(f"{field_name}_{i}")
            if existing:
                self.scene.remove_object(existing)
        
        min_x, min_z, max_x, max_z = bounds
        
        # Generate 3D field data if not provided
        if csi_data is None:
            # Simulate CSI field based on sensor positions
            field = np.zeros((resolution, resolution, resolution))
            for sensor_id, sensor in self.sensors.items():
                sx, sy, sz = sensor.position
                for i in range(resolution):
                    for j in range(resolution):
                        for k in range(resolution):
                            x = min_x + (i / (resolution - 1)) * (max_x - min_x)
                            y = (k / (resolution - 1)) * 2.5  # 0 to 2.5m height
                            z = min_z + (j / (resolution - 1)) * (max_z - min_z)
                            
                            dist = math.sqrt((x - sx)**2 + (y - sy)**2 + (z - sz)**2)
                            field[i, j, k] += max(0, 1 - dist / 5)
            
            if field.max() > 0:
                field = field / field.max()
        else:
            field = csi_data
        
        # Create voxels for high-intensity regions
        voxel_count = 0
        threshold = 0.3
        
        for i in range(resolution):
            for j in range(resolution):
                for k in range(resolution):
                    if field[i, j, k] > threshold:
                        x = min_x + (i / (resolution - 1)) * (max_x - min_x)
                        y = (k / (resolution - 1)) * 2.5
                        z = min_z + (j / (resolution - 1)) * (max_z - min_z)
                        
                        intensity = field[i, j, k]
                        
                        # Create small cube voxel
                        voxel_size = 0.3
                        mesh = Mesh3D.create_box(voxel_size, voxel_size, voxel_size)
                        
                        # Color gradient based on intensity
                        r = intensity
                        g = 0.5 * (1 - intensity)
                        b = 1 - intensity
                        
                        material = Material3D(
                            name=f"{field_name}_{voxel_count}",
                            albedo=(r, g, b),
                            emission=(r, g, b),
                            emission_strength=intensity * 0.5,
                            opacity=intensity * 0.4
                        )
                        
                        voxel = Object3D(
                            name=f"{field_name}_{voxel_count}",
                            mesh=mesh,
                            material=material,
                            position=(x, y, z),
                            data={"type": "csi_voxel", "intensity": intensity}
                        )
                        
                        self.scene.add_object(voxel)
                        voxel_count += 1

    def create_mimo_beam_pattern(self, sensor_id: str, num_antennas: int = 4,
                                   beam_direction: float = 0.0):
        """
        Visualize MIMO antenna beam pattern from a sensor.
        Shows directional signal strength pattern.
        """
        beam_name = f"mimo_beam_{sensor_id}"
        existing = self.scene.find_object(beam_name)
        if existing:
            self.scene.remove_object(existing)
        
        sensor = self.sensors.get(sensor_id)
        if not sensor:
            return
        
        origin = sensor.position
        
        vertices = [origin[0], origin[1], origin[2]]
        colors = [0.0, 1.0, 0.5, 1.0]
        indices = []
        
        # Create beam pattern with lobes
        segments = 64
        main_lobe_width = math.pi / 6  # 30 degrees
        
        for i in range(segments + 1):
            angle = beam_direction + (i / segments) * 2 * math.pi
            
            # Calculate antenna array pattern (simplified)
            # Main lobe in beam_direction, side lobes elsewhere
            angle_diff = abs(((angle - beam_direction + math.pi) % (2 * math.pi)) - math.pi)
            
            if angle_diff < main_lobe_width:
                # Main lobe
                gain = 1.0 * math.cos(angle_diff / main_lobe_width * math.pi / 2) ** 2
            else:
                # Side lobes
                gain = 0.2 * abs(math.sin(num_antennas * angle_diff))
            
            radius = 3.0 * gain + 0.5  # Min radius of 0.5
            
            x = origin[0] + radius * math.cos(angle)
            z = origin[2] + radius * math.sin(angle)
            y = origin[1]
            
            vertices.extend([x, y, z])
            # Color intensity based on gain
            colors.extend([0.0, 0.5 + 0.5 * gain, 1.0 - 0.5 * gain, 0.6 * gain + 0.2])
            
            if i > 0:
                indices.extend([0, i])
                indices.extend([i, i + 1] if i < segments else [i, 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=beam_name,
            albedo=(0.0, 0.8, 1.0),
            emission=(0.0, 1.0, 0.8),
            emission_strength=0.7,
            opacity=0.5,
            wireframe=True
        )
        
        beam = Object3D(
            name=beam_name,
            mesh=mesh,
            material=material,
            data={"type": "mimo_beam", "sensor_id": sensor_id, "direction": beam_direction}
        )
        
        # Rotating beam animation
        def animate_beam(obj: Object3D, dt: float):
            t = time.time()
            obj.rotation = (0, t * 0.2, 0)  # Slow rotation
        
        beam.animation_callback = animate_beam
        self.scene.add_object(beam)
        return beam

    def create_micro_doppler_signature(self, position: Tuple[float, float, float],
                                        signature_type: str = "walking",
                                        intensity: float = 0.8):
        """
        Visualize micro-Doppler signature for fine-grained activity recognition.
        Shows characteristic patterns of different movements.
        """
        sig_name = f"micro_doppler_{signature_type}"
        existing = self.scene.find_object(sig_name)
        if existing:
            self.scene.remove_object(existing)
        
        # Signature patterns for different activities
        patterns = {
            "walking": {"freq": 2.0, "arms": True, "legs": True},
            "running": {"freq": 3.5, "arms": True, "legs": True},
            "sitting": {"freq": 0.3, "arms": False, "legs": False},
            "waving": {"freq": 4.0, "arms": True, "legs": False},
            "falling": {"freq": 1.0, "arms": True, "legs": True, "vertical": True},
        }
        
        pattern = patterns.get(signature_type, patterns["walking"])
        
        vertices = []
        colors = []
        indices = []
        
        t = time.time()
        num_points = 32
        
        # Create signature visualization (spectrogram-like)
        for i in range(num_points):
            freq = (i / num_points) * 10 - 5  # -5 to +5 Hz range
            
            # Generate pattern based on activity
            if pattern.get("arms") and abs(freq) > 1 and abs(freq) < 3:
                amplitude = 0.5 * intensity
            elif pattern.get("legs") and abs(freq) > 0.5 and abs(freq) < 2:
                amplitude = 0.8 * intensity
            elif pattern.get("vertical") and freq > 2:
                amplitude = intensity
            else:
                amplitude = 0.1
            
            # Add time-varying component
            amplitude *= 0.5 + 0.5 * math.sin(t * pattern["freq"] + i * 0.2)
            
            x = position[0] + (i / num_points - 0.5) * 2
            y = position[1] + 2.0 + amplitude * 0.5
            z = position[2]
            
            vertices.extend([x, y, z])
            
            # Color based on frequency (red=positive, blue=negative)
            if freq > 0:
                colors.extend([0.8 * amplitude, 0.2, 0.2, amplitude])
            else:
                colors.extend([0.2, 0.2, 0.8 * amplitude, amplitude])
        
        for i in range(num_points - 1):
            indices.extend([i, i + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=sig_name,
            albedo=(0.8, 0.4, 0.2),
            emission=(1.0, 0.5, 0.3),
            emission_strength=0.6,
            opacity=0.7,
            wireframe=True
        )
        
        signature = Object3D(
            name=sig_name,
            mesh=mesh,
            material=material,
            data={"type": "micro_doppler", "signature": signature_type}
        )
        
        # Animate the signature
        def animate_sig(obj: Object3D, dt: float, pattern=pattern):
            t = time.time()
            # Update vertex positions based on time
            phase = t * pattern["freq"]
            obj.material.emission_strength = 0.4 + 0.3 * abs(math.sin(phase))
        
        signature.animation_callback = animate_sig
        self.scene.add_object(signature)
        return signature

    def create_prediction_cone(self, entity_id: str, 
                                current_pos: Tuple[float, float, float],
                                predicted_positions: List[Tuple[float, float, float]],
                                confidence_decay: float = 0.9):
        """
        Visualize predicted future positions with uncertainty cone.
        AI-powered movement prediction visualization.
        """
        cone_name = f"prediction_{entity_id}"
        existing = self.scene.find_object(cone_name)
        if existing:
            self.scene.remove_object(existing)
        
        if not predicted_positions:
            return
        
        vertices = [current_pos[0], current_pos[1] + 0.5, current_pos[2]]
        colors = [0.0, 1.0, 0.5, 0.9]
        indices = []
        
        # Create cone expanding toward predicted positions
        confidence = 1.0
        for i, pred_pos in enumerate(predicted_positions):
            confidence *= confidence_decay
            uncertainty = (1 - confidence) * 0.5  # Uncertainty radius
            
            # Center line vertex
            vertices.extend([pred_pos[0], pred_pos[1] + 0.5, pred_pos[2]])
            colors.extend([0.0, confidence, 1.0 - confidence, confidence])
            
            # Uncertainty boundary vertices
            for angle in [0, math.pi/2, math.pi, 3*math.pi/2]:
                ux = pred_pos[0] + uncertainty * math.cos(angle)
                uz = pred_pos[2] + uncertainty * math.sin(angle)
                vertices.extend([ux, pred_pos[1] + 0.5, uz])
                colors.extend([0.3, confidence * 0.5, 0.8, confidence * 0.4])
        
        # Connect vertices
        num_points = len(predicted_positions)
        for i in range(num_points):
            base_idx = 1 + i * 5
            if i < num_points - 1:
                next_idx = base_idx + 5
                indices.extend([base_idx, next_idx])
            
            # Connect to uncertainty boundaries
            for j in range(4):
                indices.extend([base_idx, base_idx + 1 + j])
        
        # Connect from origin
        indices.extend([0, 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=cone_name,
            albedo=(0.0, 0.8, 0.6),
            emission=(0.0, 1.0, 0.8),
            emission_strength=0.5,
            opacity=0.6,
            wireframe=True
        )
        
        cone = Object3D(
            name=cone_name,
            mesh=mesh,
            material=material,
            data={"type": "prediction_cone", "entity_id": entity_id}
        )
        
        self.scene.add_object(cone)
        return cone

    def create_wall_penetration_viz(self, wall_bounds: Tuple[float, float, float, float],
                                     attenuation_db: float = 6.0,
                                     signal_paths: List[Tuple] = None):
        """
        Visualize signal penetration through walls/obstacles.
        Shows attenuation and refraction effects.
        """
        wall_name = "wall_penetration"
        existing = self.scene.find_object(wall_name)
        if existing:
            self.scene.remove_object(existing)
        
        min_x, min_z, max_x, max_z = wall_bounds
        
        # Wall thickness visualization
        thickness = 0.15
        
        vertices = []
        colors = []
        indices = []
        
        # Create wall mesh with transparency based on attenuation
        # Lower attenuation = more transparent (signal passes through)
        opacity = min(0.9, attenuation_db / 20.0)
        
        # Front face
        vertices.extend([min_x, 0, min_z])
        vertices.extend([max_x, 0, min_z])
        vertices.extend([max_x, 2.5, min_z])
        vertices.extend([min_x, 2.5, min_z])
        
        # Back face
        vertices.extend([min_x, 0, min_z + thickness])
        vertices.extend([max_x, 0, min_z + thickness])
        vertices.extend([max_x, 2.5, min_z + thickness])
        vertices.extend([min_x, 2.5, min_z + thickness])
        
        # Color based on material (concrete = gray, glass = blue, wood = brown)
        if attenuation_db > 12:
            color = (0.5, 0.5, 0.5)  # Concrete
        elif attenuation_db > 6:
            color = (0.6, 0.4, 0.2)  # Wood
        else:
            color = (0.3, 0.5, 0.8)  # Glass
        
        for _ in range(8):
            colors.extend([color[0], color[1], color[2], opacity])
        
        # Front face
        indices.extend([0, 1, 2, 0, 2, 3])
        # Back face
        indices.extend([4, 6, 5, 4, 7, 6])
        # Sides
        indices.extend([0, 4, 5, 0, 5, 1])
        indices.extend([2, 6, 7, 2, 7, 3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=wall_name,
            albedo=color,
            emission=color,
            emission_strength=0.2,
            opacity=opacity
        )
        
        wall = Object3D(
            name=wall_name,
            mesh=mesh,
            material=material,
            data={"type": "wall_penetration", "attenuation_db": attenuation_db}
        )
        
        self.scene.add_object(wall)
        
        # Visualize signal paths through wall if provided
        if signal_paths:
            for i, (start, end, strength) in enumerate(signal_paths):
                self._create_penetration_ray(i, start, end, strength, attenuation_db)
        
        return wall

    def _create_penetration_ray(self, ray_id: int, start: Tuple, end: Tuple,
                                 strength: float, attenuation: float):
        """Create a ray showing signal penetrating through wall."""
        ray_name = f"penetration_ray_{ray_id}"
        existing = self.scene.find_object(ray_name)
        if existing:
            self.scene.remove_object(existing)
        
        # Calculate attenuation effect
        output_strength = strength * math.pow(10, -attenuation / 20)
        
        vertices = [
            start[0], start[1], start[2],
            end[0], end[1], end[2]
        ]
        
        colors = [
            0.0, strength, 1.0 - strength * 0.5, strength,
            0.0, output_strength, 1.0 - output_strength * 0.5, output_strength
        ]
        
        indices = [0, 1]
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=ray_name,
            albedo=(0.0, 0.8, 1.0),
            emission=(0.0, 1.0, 1.0),
            emission_strength=strength,
            opacity=0.7,
            wireframe=True
        )
        
        ray = Object3D(
            name=ray_name,
            mesh=mesh,
            material=material,
            data={"type": "penetration_ray"}
        )
        
        self.scene.add_object(ray)

    def create_neural_activity_map(self, bounds: Tuple[float, float, float, float],
                                    activity_tensor: np.ndarray = None):
        """
        Visualize neural network activity/attention for CSI processing.
        Shows which spatial regions the AI is focusing on.
        """
        map_name = "neural_activity_map"
        existing = self.scene.find_object(map_name)
        if existing:
            self.scene.remove_object(existing)
        
        min_x, min_z, max_x, max_z = bounds
        resolution = 16
        
        # Generate simulated neural attention if not provided
        if activity_tensor is None:
            activity_tensor = np.random.rand(resolution, resolution)
            # Add hotspots near detected entities
            for entity_id, entity in self.entities.items():
                ex, ey, ez = entity.position
                # Normalize to grid
                gx = int((ex - min_x) / (max_x - min_x) * (resolution - 1))
                gz = int((ez - min_z) / (max_z - min_z) * (resolution - 1))
                gx = max(0, min(resolution - 1, gx))
                gz = max(0, min(resolution - 1, gz))
                
                # Create attention hotspot
                for di in range(-2, 3):
                    for dj in range(-2, 3):
                        ni, nj = gx + di, gz + dj
                        if 0 <= ni < resolution and 0 <= nj < resolution:
                            dist = math.sqrt(di*di + dj*dj)
                            activity_tensor[ni, nj] += max(0, 1 - dist / 3)
            
            activity_tensor = np.clip(activity_tensor / activity_tensor.max(), 0, 1)
        
        vertices = []
        colors = []
        indices = []
        
        # Create floating attention points
        for i in range(resolution):
            for j in range(resolution):
                activity = activity_tensor[i, j]
                if activity > 0.2:  # Threshold
                    x = min_x + (i / (resolution - 1)) * (max_x - min_x)
                    z = min_z + (j / (resolution - 1)) * (max_z - min_z)
                    y = 0.1 + activity * 0.5  # Height based on activity
                    
                    vertices.extend([x, y, z])
                    
                    # Color: cool (blue) to hot (red) based on activity
                    r = activity
                    g = 0.3 * (1 - activity)
                    b = 1 - activity
                    colors.extend([r, g, b, activity * 0.8])
        
        if not vertices:
            return
        
        # Connect nearby points
        num_points = len(vertices) // 3
        for i in range(num_points - 1):
            indices.extend([i, i + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=map_name,
            albedo=(0.8, 0.4, 0.1),
            emission=(1.0, 0.5, 0.2),
            emission_strength=0.6,
            opacity=0.5
        )
        
        activity_map = Object3D(
            name=map_name,
            mesh=mesh,
            material=material,
            data={"type": "neural_activity"}
        )
        
        # Animated shimmer
        def animate_neural(obj: Object3D, dt: float):
            t = time.time()
            obj.material.emission_strength = 0.4 + 0.2 * math.sin(t * 2)
        
        activity_map.animation_callback = animate_neural
        self.scene.add_object(activity_map)
        return activity_map

    def create_fall_alert(self, position: Tuple[float, float, float],
                          severity: float = 0.8) -> Optional[Object3D]:
        """
        Create fall detection alert visualization with pulsing warning.
        
        Args:
            position: Location where fall was detected
            severity: Alert severity 0-1
        """
        alert_name = "fall_alert"
        
        # Remove existing
        existing = self.scene.get_object(alert_name)
        if existing:
            self.scene.remove_object(alert_name)
        
        # Create alert ring on ground
        segments = 32
        vertices = []
        colors = []
        indices = []
        
        radius = 1.5
        for i in range(segments):
            angle = (i / segments) * 2 * math.pi
            x = position[0] + radius * math.cos(angle)
            z = position[2] + radius * math.sin(angle)
            y = 0.05
            vertices.extend([x, y, z])
            colors.extend([1.0, 0.2, 0.2, severity])
            
            if i > 0:
                indices.extend([i-1, i])
        indices.extend([segments-1, 0])
        
        # Inner ring
        inner_radius = 0.5
        offset = segments
        for i in range(segments):
            angle = (i / segments) * 2 * math.pi
            x = position[0] + inner_radius * math.cos(angle)
            z = position[2] + inner_radius * math.sin(angle)
            y = 0.05
            vertices.extend([x, y, z])
            colors.extend([1.0, 0.0, 0.0, severity])
            
            if i > 0:
                indices.extend([offset + i-1, offset + i])
        indices.extend([offset + segments-1, offset])
        
        # Cross lines
        cross_offset = len(vertices) // 3
        for angle in [0, math.pi/2, math.pi, 3*math.pi/2]:
            x1 = position[0] + inner_radius * math.cos(angle)
            z1 = position[2] + inner_radius * math.sin(angle)
            x2 = position[0] + radius * math.cos(angle)
            z2 = position[2] + radius * math.sin(angle)
            
            idx = len(vertices) // 3
            vertices.extend([x1, 0.05, z1, x2, 0.05, z2])
            colors.extend([1.0, 0.3, 0.1, severity, 1.0, 0.1, 0.1, severity])
            indices.extend([idx, idx + 1])
        
        # Warning symbol (exclamation mark-like)
        warn_offset = len(vertices) // 3
        # Vertical line
        vertices.extend([position[0], 0.3, position[2], position[0], 1.5, position[2]])
        colors.extend([1.0, 0.8, 0.0, 1.0, 1.0, 1.0, 0.0, 1.0])
        indices.extend([warn_offset, warn_offset + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=alert_name,
            albedo=(1.0, 0.2, 0.2),
            emission=(1.0, 0.2, 0.0),
            emission_strength=1.5,
            opacity=severity
        )
        
        alert = Object3D(
            name=alert_name,
            mesh=mesh,
            material=material,
            data={"type": "fall_alert", "severity": severity}
        )
        
        # Pulsing animation
        def animate_alert(obj: Object3D, dt: float):
            t = time.time()
            pulse = 0.5 + 0.5 * math.sin(t * 8)  # Fast pulse
            obj.material.emission_strength = 1.0 + pulse * 2
            obj.material.opacity = 0.5 + 0.5 * pulse
        
        alert.animation_callback = animate_alert
        self.scene.add_object(alert)
        return alert

    def create_sleep_visualization(self, position: Tuple[float, float, float],
                                   sleep_stage: str = 'light',
                                   breathing_rate: float = 14.0,
                                   quality_score: float = 0.7) -> Optional[Object3D]:
        """
        Visualize sleep state with ambient glow and breathing indicator.
        
        Args:
            position: Person's position
            sleep_stage: Current sleep stage (awake/light/deep/rem)
            breathing_rate: Breaths per minute
            quality_score: Sleep quality 0-1
        """
        sleep_name = "sleep_viz"
        
        # Remove existing
        existing = self.scene.get_object(sleep_name)
        if existing:
            self.scene.remove_object(sleep_name)
        
        # Stage colors
        stage_colors = {
            'awake': (0.8, 0.8, 0.3),
            'light': (0.3, 0.6, 0.9),
            'deep': (0.1, 0.2, 0.6),
            'rem': (0.7, 0.3, 0.8)
        }
        color = stage_colors.get(sleep_stage, (0.5, 0.5, 0.5))
        
        vertices = []
        colors = []
        indices = []
        
        # Aura around person
        layers = 5
        for layer in range(layers):
            radius = 0.5 + layer * 0.3
            segments = 24
            alpha = 0.3 * (1 - layer / layers)
            
            for i in range(segments):
                angle = (i / segments) * 2 * math.pi
                x = position[0] + radius * math.cos(angle)
                z = position[2] + radius * math.sin(angle)
                y = 0.1 + layer * 0.1
                
                vertices.extend([x, y, z])
                colors.extend([color[0], color[1], color[2], alpha])
                
                if i > 0:
                    idx = layer * segments + i
                    indices.extend([idx - 1, idx])
            
            indices.extend([layer * segments + segments - 1, layer * segments])
        
        # Breathing wave indicator
        wave_points = 20
        wave_width = 1.5
        wave_start = len(vertices) // 3
        
        for i in range(wave_points):
            x = position[0] - wave_width/2 + (i / (wave_points-1)) * wave_width
            wave_amp = 0.2 * quality_score
            y = 0.3 + wave_amp * math.sin(i * 0.5)
            z = position[2] - 1.0
            
            vertices.extend([x, y, z])
            colors.extend([0.3, 1.0, 0.5, 0.6])
            
            if i > 0:
                indices.extend([wave_start + i - 1, wave_start + i])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=sleep_name,
            albedo=color,
            emission=color,
            emission_strength=0.4,
            opacity=0.5
        )
        
        sleep_obj = Object3D(
            name=sleep_name,
            mesh=mesh,
            material=material,
            data={"type": "sleep_viz", "stage": sleep_stage}
        )
        
        # Gentle breathing animation
        breathing_freq = breathing_rate / 60.0  # Convert to Hz
        
        def animate_sleep(obj: Object3D, dt: float):
            t = time.time()
            breath = 0.5 + 0.5 * math.sin(t * breathing_freq * 2 * math.pi)
            obj.material.emission_strength = 0.3 + 0.2 * breath
        
        sleep_obj.animation_callback = animate_sleep
        self.scene.add_object(sleep_obj)
        return sleep_obj

    def create_behavior_pattern_viz(self, patterns: List[dict],
                                    center: Tuple[float, float, float] = (0, 0, 0)) -> Optional[Object3D]:
        """
        Visualize detected behavior patterns as connected nodes.
        
        Args:
            patterns: List of behavior patterns with hour/activity/confidence
            center: Center of visualization
        """
        pattern_name = "behavior_patterns"
        
        # Remove existing
        existing = self.scene.get_object(pattern_name)
        if existing:
            self.scene.remove_object(pattern_name)
        
        if not patterns:
            return None
        
        vertices = []
        colors = []
        indices = []
        
        # Create circular arrangement representing 24-hour clock
        clock_radius = 2.5
        
        # Hour markers
        for hour in range(24):
            angle = (hour / 24) * 2 * math.pi - math.pi / 2  # Start at top
            x = center[0] + clock_radius * math.cos(angle)
            z = center[2] + clock_radius * math.sin(angle)
            y = 2.0
            
            idx = len(vertices) // 3
            vertices.extend([x, y, z])
            
            # Color based on whether there's a pattern at this hour
            has_pattern = any(p['hour'] == hour for p in patterns)
            if has_pattern:
                colors.extend([0.2, 0.8, 1.0, 0.8])
            else:
                colors.extend([0.3, 0.3, 0.3, 0.3])
            
            # Connect hours
            if hour > 0:
                indices.extend([idx - 1, idx])
        # Close the loop
        indices.extend([23, 0])
        
        # Add pattern indicators
        for pattern in patterns[:10]:  # Limit to 10
            hour = pattern['hour']
            confidence = pattern.get('confidence', 0.5)
            
            angle = (hour / 24) * 2 * math.pi - math.pi / 2
            x = center[0] + clock_radius * 0.7 * math.cos(angle)
            z = center[2] + clock_radius * 0.7 * math.sin(angle)
            y = 2.0
            
            idx = len(vertices) // 3
            
            # Inner point
            vertices.extend([x, y, z])
            colors.extend([0.0, 1.0, 0.5, confidence])
            
            # Connect to outer ring
            outer_idx = hour
            indices.extend([outer_idx, idx])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=pattern_name,
            albedo=(0.2, 0.8, 1.0),
            emission=(0.0, 0.6, 0.8),
            emission_strength=0.5,
            opacity=0.7
        )
        
        pattern_obj = Object3D(
            name=pattern_name,
            mesh=mesh,
            material=material,
            data={"type": "behavior_patterns"}
        )
        
        # Slow rotation animation
        def animate_patterns(obj: Object3D, dt: float):
            obj.rotation[1] += dt * 0.1
        
        pattern_obj.animation_callback = animate_patterns
        self.scene.add_object(pattern_obj)
        return pattern_obj

    def create_anomaly_indicator(self, position: Tuple[float, float, float],
                                 anomaly_type: str = 'unknown',
                                 confidence: float = 0.7) -> Optional[Object3D]:
        """
        Create visual indicator for detected anomaly.
        
        Args:
            position: Location of anomaly
            anomaly_type: Type of anomaly detected
            confidence: Detection confidence 0-1
        """
        anomaly_name = f"anomaly_{anomaly_type}"
        
        # Remove existing
        existing = self.scene.get_object(anomaly_name)
        if existing:
            self.scene.remove_object(anomaly_name)
        
        vertices = []
        colors = []
        indices = []
        
        # Warning triangle
        size = 0.5 + confidence * 0.5
        height = position[1] + 2.5
        
        # Triangle vertices
        angles = [0, 2*math.pi/3, 4*math.pi/3]
        for i, angle in enumerate(angles):
            x = position[0] + size * math.cos(angle + math.pi/2)
            z = position[2] + size * math.sin(angle + math.pi/2)
            vertices.extend([x, height, z])
            colors.extend([1.0, 0.7, 0.0, 0.9])
        
        # Triangle edges
        indices.extend([0, 1, 1, 2, 2, 0])
        
        # Connecting line to position
        idx = len(vertices) // 3
        vertices.extend([position[0], height, position[2]])
        vertices.extend([position[0], 0.1, position[2]])
        colors.extend([1.0, 0.5, 0.0, 0.5, 1.0, 0.5, 0.0, 0.3])
        indices.extend([idx, idx + 1])
        
        # Add type indicator (different shapes for different anomalies)
        type_offset = len(vertices) // 3
        
        if anomaly_type == 'unusual_speed':
            # Speed arrow
            vertices.extend([position[0], height + 0.3, position[2]])
            vertices.extend([position[0] + 0.3, height, position[2]])
            vertices.extend([position[0] - 0.3, height, position[2]])
            colors.extend([1.0, 0.3, 0.3, 0.8] * 3)
            indices.extend([type_offset, type_offset + 1, type_offset, type_offset + 2])
        elif anomaly_type == 'crowd_detected':
            # Multiple dots
            for i in range(5):
                angle = (i / 5) * 2 * math.pi
                x = position[0] + 0.2 * math.cos(angle)
                z = position[2] + 0.2 * math.sin(angle)
                idx = len(vertices) // 3
                vertices.extend([x, height - 0.2, z])
                colors.extend([0.8, 0.3, 1.0, 0.7])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=anomaly_name,
            albedo=(1.0, 0.6, 0.0),
            emission=(1.0, 0.5, 0.0),
            emission_strength=1.0,
            opacity=confidence
        )
        
        anomaly_obj = Object3D(
            name=anomaly_name,
            mesh=mesh,
            material=material,
            data={"type": "anomaly", "anomaly_type": anomaly_type}
        )
        
        # Flashing animation
        def animate_anomaly(obj: Object3D, dt: float):
            t = time.time()
            flash = abs(math.sin(t * 4))
            obj.material.emission_strength = 0.5 + flash * 1.5
        
        anomaly_obj.animation_callback = animate_anomaly
        self.scene.add_object(anomaly_obj)
        return anomaly_obj

    def create_prediction_trajectory(self, current_pos: Tuple[float, float, float],
                                     predicted_positions: List[Tuple[Tuple[float, float, float], float]],
                                     color: Tuple[float, float, float] = (0.2, 0.8, 1.0)) -> Optional[Object3D]:
        """
        Visualize predicted future trajectory.
        
        Args:
            current_pos: Current position
            predicted_positions: List of (position, time_offset) tuples
            color: Base color for trajectory
        """
        traj_name = "prediction_trajectory"
        
        # Remove existing
        existing = self.scene.get_object(traj_name)
        if existing:
            self.scene.remove_object(traj_name)
        
        if not predicted_positions:
            return None
        
        vertices = []
        colors = []
        indices = []
        
        # Start with current position
        vertices.extend([current_pos[0], current_pos[1], current_pos[2]])
        colors.extend([color[0], color[1], color[2], 1.0])
        
        # Add predicted positions with fading alpha
        max_time = max(p[1] for p in predicted_positions) or 1
        
        for i, (pos, t_offset) in enumerate(predicted_positions):
            idx = len(vertices) // 3
            
            # Fade based on time
            alpha = 1.0 - (t_offset / max_time) * 0.8
            
            vertices.extend([pos[0], pos[1], pos[2]])
            colors.extend([color[0], color[1], color[2], alpha])
            
            # Connect to previous
            indices.extend([idx - 1, idx])
        
        # Add uncertainty rings at prediction points
        for i, (pos, t_offset) in enumerate(predicted_positions[::2]):  # Every other prediction
            uncertainty = 0.1 + t_offset * 0.15  # Grows with time
            segments = 12
            ring_start = len(vertices) // 3
            
            alpha = 0.5 - (t_offset / max_time) * 0.3
            
            for j in range(segments):
                angle = (j / segments) * 2 * math.pi
                x = pos[0] + uncertainty * math.cos(angle)
                z = pos[2] + uncertainty * math.sin(angle)
                
                vertices.extend([x, pos[1], z])
                colors.extend([color[0] * 0.7, color[1] * 0.7, color[2], alpha])
                
                if j > 0:
                    indices.extend([ring_start + j - 1, ring_start + j])
            indices.extend([ring_start + segments - 1, ring_start])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=traj_name,
            albedo=color,
            emission=color,
            emission_strength=0.6,
            opacity=0.8
        )
        
        traj_obj = Object3D(
            name=traj_name,
            mesh=mesh,
            material=material,
            data={"type": "prediction_trajectory"}
        )
        
        # Shimmer animation
        def animate_traj(obj: Object3D, dt: float):
            t = time.time()
            obj.material.emission_strength = 0.4 + 0.3 * math.sin(t * 3)
        
        traj_obj.animation_callback = animate_traj
        self.scene.add_object(traj_obj)
        return traj_obj

    def create_quality_hud(self, metrics: dict,
                          position: Tuple[float, float, float] = (4, 3, 0)) -> Optional[Object3D]:
        """
        Create a heads-up display showing various quality metrics.
        
        Args:
            metrics: Dictionary of metric name -> value (0-1)
            position: Position of HUD
        """
        hud_name = "quality_hud"
        
        # Remove existing
        existing = self.scene.get_object(hud_name)
        if existing:
            self.scene.remove_object(hud_name)
        
        vertices = []
        colors = []
        indices = []
        
        # Create vertical bar indicators
        bar_width = 0.1
        bar_spacing = 0.3
        max_height = 1.5
        
        metric_names = list(metrics.keys())[:6]  # Limit to 6 metrics
        
        for i, name in enumerate(metric_names):
            value = max(0, min(1, metrics[name]))
            
            x = position[0] + i * bar_spacing
            y_base = position[1]
            z = position[2]
            
            bar_height = value * max_height
            
            # Bar vertices (quad as two triangles worth of lines)
            idx = len(vertices) // 3
            
            # Background bar (darker)
            vertices.extend([
                x, y_base, z,
                x + bar_width, y_base, z,
                x + bar_width, y_base + max_height, z,
                x, y_base + max_height, z
            ])
            colors.extend([0.2, 0.2, 0.2, 0.4] * 4)
            indices.extend([idx, idx+1, idx+1, idx+2, idx+2, idx+3, idx+3, idx])
            
            # Value bar (colored based on value)
            idx2 = len(vertices) // 3
            
            # Color: red (low) -> yellow (mid) -> green (high)
            if value < 0.5:
                r, g, b = 1.0, value * 2, 0.0
            else:
                r, g, b = 2.0 - value * 2, 1.0, 0.0
            
            vertices.extend([
                x, y_base, z + 0.01,
                x + bar_width, y_base, z + 0.01,
                x + bar_width, y_base + bar_height, z + 0.01,
                x, y_base + bar_height, z + 0.01
            ])
            colors.extend([r, g, b, 0.9] * 4)
            indices.extend([idx2, idx2+1, idx2+1, idx2+2, idx2+2, idx2+3, idx2+3, idx2])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=hud_name,
            albedo=(0.5, 0.8, 0.3),
            emission=(0.3, 0.6, 0.2),
            emission_strength=0.3,
            opacity=0.9
        )
        
        hud_obj = Object3D(
            name=hud_name,
            mesh=mesh,
            material=material,
            data={"type": "quality_hud", "metrics": list(metrics.keys())}
        )
        
        self.scene.add_object(hud_obj)
        return hud_obj

    # ========================================
    # ULTRA-ADVANCED VISUALIZATION METHODS
    # ========================================

    def create_through_wall_image(self, grid: list, objects: list, walls: list,
                                  position: tuple = (0, 2, 0), scale: float = 4.0):
        """Create through-wall imaging visualization showing detected objects behind walls."""
        twi_name = "through_wall_imager"
        self._remove_old_object(twi_name)
        
        vertices = []
        colors = []
        indices = []
        
        grid_size = len(grid)
        if grid_size == 0:
            return None
            
        cell_size = scale / grid_size
        start_x = position[0] - scale / 2
        start_z = position[2] - scale / 2
        y_base = position[1]
        
        # Draw the imaging grid
        for i, row in enumerate(grid):
            for j, value in enumerate(row):
                x = start_x + j * cell_size
                z = start_z + i * cell_size
                
                idx = len(vertices) // 3
                
                # Height based on detection strength
                height = value * 0.5
                
                # Color based on detection type
                if value > 0.7:
                    r, g, b = 1.0, 0.3, 0.0  # Strong detection - orange
                elif value > 0.4:
                    r, g, b = 0.0, 0.8, 0.3  # Medium - green
                else:
                    r, g, b = 0.1, 0.3, 0.6  # Weak - blue
                
                alpha = 0.3 + value * 0.5
                
                # Create elevated cell
                vertices.extend([
                    x, y_base, z,
                    x + cell_size * 0.9, y_base, z,
                    x + cell_size * 0.9, y_base + height, z,
                    x, y_base + height, z,
                    x, y_base, z + cell_size * 0.9,
                    x + cell_size * 0.9, y_base, z + cell_size * 0.9,
                    x + cell_size * 0.9, y_base + height, z + cell_size * 0.9,
                    x, y_base + height, z + cell_size * 0.9
                ])
                
                colors.extend([r, g, b, alpha] * 8)
                
                # Box faces
                indices.extend([
                    idx, idx+1, idx+1, idx+2, idx+2, idx+3, idx+3, idx,
                    idx+4, idx+5, idx+5, idx+6, idx+6, idx+7, idx+7, idx+4,
                    idx, idx+4, idx+1, idx+5, idx+2, idx+6, idx+3, idx+7
                ])
        
        # Draw wall boundaries
        for wall in walls:
            idx = len(vertices) // 3
            x1, z1, x2, z2 = wall.get('x1', 0), wall.get('z1', 0), wall.get('x2', 1), wall.get('z2', 1)
            wall_height = 2.5
            
            vertices.extend([
                x1, y_base, z1,
                x2, y_base, z2,
                x2, y_base + wall_height, z2,
                x1, y_base + wall_height, z1
            ])
            colors.extend([0.6, 0.6, 0.8, 0.6] * 4)
            indices.extend([idx, idx+1, idx+1, idx+2, idx+2, idx+3, idx+3, idx])
        
        # Draw detected objects
        for obj in objects:
            idx = len(vertices) // 3
            ox, oz = obj.get('x', 0), obj.get('z', 0)
            conf = obj.get('confidence', 0.5)
            
            # Create marker for detected object
            marker_size = 0.3 + conf * 0.2
            for angle in range(0, 360, 60):
                rad = math.radians(angle)
                rad2 = math.radians(angle + 60)
                vertices.extend([
                    ox, y_base + 0.5, oz,
                    ox + math.cos(rad) * marker_size, y_base + 0.5, oz + math.sin(rad) * marker_size,
                    ox + math.cos(rad2) * marker_size, y_base + 0.5, oz + math.sin(rad2) * marker_size
                ])
                colors.extend([1.0, 0.5, 0.0, 0.8] * 3)
        
        if len(vertices) == 0:
            return None
            
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None
        )
        
        material = Material3D(
            name=twi_name,
            albedo=(0.3, 0.5, 0.8),
            emission=(0.2, 0.4, 0.6),
            emission_strength=0.4,
            opacity=0.7
        )
        
        twi_obj = Object3D(
            name=twi_name,
            mesh=mesh,
            material=material,
            data={"type": "through_wall_image", "grid_size": grid_size}
        )
        
        self.scene.add_object(twi_obj)
        return twi_obj

    def create_doppler_spectrogram_viz(self, spectrogram: list, peaks: list,
                                        velocity: float, time_axis: list,
                                        position: tuple = (-4, 1, -4)):
        """Create time-frequency Doppler spectrogram visualization."""
        spec_name = "doppler_spectrogram_viz"
        self._remove_old_object(spec_name)
        
        vertices = []
        colors = []
        indices = []
        
        if not spectrogram or len(spectrogram) == 0:
            return None
        
        width = 3.0
        height = 2.0
        time_bins = len(spectrogram)
        freq_bins = len(spectrogram[0]) if spectrogram else 8
        
        cell_w = width / time_bins
        cell_h = height / freq_bins
        
        # Draw spectrogram as colored grid
        for t_idx, time_slice in enumerate(spectrogram):
            for f_idx, value in enumerate(time_slice):
                x = position[0] + t_idx * cell_w
                y = position[1] + f_idx * cell_h
                z = position[2]
                
                idx = len(vertices) // 3
                
                # Color map: cool to hot
                if value < 0.33:
                    r, g, b = 0.0, value * 3, 0.5 + value
                elif value < 0.67:
                    r, g, b = (value - 0.33) * 3, 1.0, 1.0 - (value - 0.33) * 3
                else:
                    r, g, b = 1.0, 1.0 - (value - 0.67) * 3, 0.0
                
                vertices.extend([
                    x, y, z,
                    x + cell_w * 0.95, y, z,
                    x + cell_w * 0.95, y + cell_h * 0.95, z,
                    x, y + cell_h * 0.95, z
                ])
                colors.extend([r, g, b, 0.8] * 4)
                indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Mark peaks with bright indicators
        for peak in peaks:
            if 'time_idx' in peak and 'freq_idx' in peak:
                px = position[0] + peak['time_idx'] * cell_w + cell_w / 2
                py = position[1] + peak['freq_idx'] * cell_h + cell_h / 2
                pz = position[2] + 0.02
                
                idx = len(vertices) // 3
                size = 0.08
                
                # Diamond marker
                vertices.extend([
                    px, py - size, pz,
                    px + size, py, pz,
                    px, py + size, pz,
                    px - size, py, pz
                ])
                colors.extend([1.0, 1.0, 1.0, 1.0] * 4)
                indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Velocity indicator line
        idx = len(vertices) // 3
        vel_y = position[1] + height / 2 + velocity * 0.5
        vertices.extend([
            position[0], vel_y, position[2] + 0.05,
            position[0] + width, vel_y, position[2] + 0.05
        ])
        colors.extend([1.0, 0.5, 0.0, 1.0] * 2)
        indices.extend([idx, idx+1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=spec_name,
            albedo=(0.4, 0.6, 0.9),
            emission=(0.3, 0.5, 0.8),
            emission_strength=0.5,
            opacity=0.85
        )
        
        spec_obj = Object3D(
            name=spec_name,
            mesh=mesh,
            material=material,
            data={"type": "doppler_spectrogram", "velocity": velocity}
        )
        
        self.scene.add_object(spec_obj)
        return spec_obj

    def create_multi_room_display(self, rooms: dict, current_room: str,
                                   transitions: list, dwell_times: dict,
                                   layout_offset: tuple = (0, 0, 0)):
        """Create multi-room occupancy and flow visualization."""
        room_name = "multi_room_display"
        self._remove_old_object(room_name)
        
        vertices = []
        colors = []
        indices = []
        
        # Room layout positions (default grid)
        room_positions = {
            'living_room': (-2, 0, -2),
            'bedroom': (2, 0, -2),
            'kitchen': (-2, 0, 2),
            'bathroom': (2, 0, 2),
            'hallway': (0, 0, 0)
        }
        
        room_size = 1.5
        
        for room_id, occupancy in rooms.items():
            if room_id not in room_positions:
                continue
                
            rx, ry, rz = room_positions[room_id]
            rx += layout_offset[0]
            rz += layout_offset[2]
            
            idx = len(vertices) // 3
            
            # Color based on occupancy
            if room_id == current_room:
                r, g, b = 0.0, 1.0, 0.5  # Current room - green
                alpha = 0.8
            elif occupancy > 0:
                r, g, b = 1.0, 0.7, 0.0  # Occupied - amber
                alpha = 0.6
            else:
                r, g, b = 0.3, 0.3, 0.5  # Empty - gray
                alpha = 0.3
            
            # Room floor
            hs = room_size / 2
            vertices.extend([
                rx - hs, ry + 0.01, rz - hs,
                rx + hs, ry + 0.01, rz - hs,
                rx + hs, ry + 0.01, rz + hs,
                rx - hs, ry + 0.01, rz + hs
            ])
            colors.extend([r, g, b, alpha] * 4)
            indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
            
            # Room walls (outline)
            idx = len(vertices) // 3
            wall_h = 0.8
            vertices.extend([
                rx - hs, ry, rz - hs,
                rx + hs, ry, rz - hs,
                rx + hs, ry + wall_h, rz - hs,
                rx - hs, ry + wall_h, rz - hs,
            ])
            colors.extend([r * 0.7, g * 0.7, b * 0.7, 0.5] * 4)
            indices.extend([idx, idx+1, idx+1, idx+2, idx+2, idx+3, idx+3, idx])
            
            # Dwell time indicator (height pillar)
            dwell = dwell_times.get(room_id, 0)
            if dwell > 0:
                idx = len(vertices) // 3
                pillar_h = min(dwell / 60, 2.0)  # Max 2 units for 1 minute
                
                vertices.extend([
                    rx - 0.1, ry, rz - 0.1,
                    rx + 0.1, ry, rz - 0.1,
                    rx + 0.1, ry + pillar_h, rz - 0.1,
                    rx - 0.1, ry + pillar_h, rz - 0.1,
                    rx - 0.1, ry, rz + 0.1,
                    rx + 0.1, ry, rz + 0.1,
                    rx + 0.1, ry + pillar_h, rz + 0.1,
                    rx - 0.1, ry + pillar_h, rz + 0.1
                ])
                colors.extend([0.8, 0.4, 1.0, 0.7] * 8)
                for fi in range(6):
                    base = idx + [0,1,2,3, 4,5,6,7, 0,1,5,4, 2,3,7,6, 0,3,7,4, 1,2,6,5][fi*4:(fi+1)*4]
                    indices.extend([base[0], base[1], base[2], base[0], base[2], base[3]])
        
        # Draw transitions as arrows
        for trans in transitions[-5:]:  # Last 5 transitions
            from_room = trans.get('from')
            to_room = trans.get('to')
            if from_room in room_positions and to_room in room_positions:
                fx, fy, fz = room_positions[from_room]
                tx, ty, tz = room_positions[to_room]
                fx += layout_offset[0]
                tx += layout_offset[0]
                fz += layout_offset[2]
                tz += layout_offset[2]
                
                idx = len(vertices) // 3
                vertices.extend([
                    fx, fy + 0.5, fz,
                    tx, ty + 0.5, tz
                ])
                colors.extend([0.0, 1.0, 1.0, 0.8] * 2)
                indices.extend([idx, idx+1])
        
        if len(vertices) == 0:
            return None
            
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=room_name,
            albedo=(0.5, 0.7, 0.5),
            emission=(0.3, 0.5, 0.3),
            emission_strength=0.3,
            opacity=0.8
        )
        
        room_obj = Object3D(
            name=room_name,
            mesh=mesh,
            material=material,
            data={"type": "multi_room", "current_room": current_room}
        )
        
        self.scene.add_object(room_obj)
        return room_obj

    def create_localization_overlay(self, position: tuple, confidence: float,
                                     method: str, fingerprint_match: dict = None):
        """Create device-free localization visualization with confidence cone."""
        loc_name = "localization_overlay"
        self._remove_old_object(loc_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Confidence circle
        segments = 32
        radius = 0.5 + (1 - confidence) * 2  # Larger circle = less confidence
        
        for i in range(segments):
            angle1 = 2 * math.pi * i / segments
            angle2 = 2 * math.pi * (i + 1) / segments
            
            idx = len(vertices) // 3
            
            # Filled wedge
            vertices.extend([
                px, py + 0.02, pz,
                px + math.cos(angle1) * radius, py + 0.02, pz + math.sin(angle1) * radius,
                px + math.cos(angle2) * radius, py + 0.02, pz + math.sin(angle2) * radius
            ])
            
            # Color based on method
            if method == 'fingerprint':
                r, g, b = 0.3, 0.8, 1.0
            elif method == 'knn':
                r, g, b = 0.8, 0.5, 1.0
            else:
                r, g, b = 0.5, 1.0, 0.5
            
            alpha = confidence * 0.5
            colors.extend([r, g, b, alpha] * 3)
            indices.extend([idx, idx+1, idx+2])
        
        # Center marker - cross pattern
        idx = len(vertices) // 3
        cross_size = 0.2
        vertices.extend([
            px - cross_size, py + 0.1, pz,
            px + cross_size, py + 0.1, pz,
            px, py + 0.1, pz - cross_size,
            px, py + 0.1, pz + cross_size
        ])
        colors.extend([1.0, 1.0, 1.0, 1.0] * 4)
        indices.extend([idx, idx+1, idx+2, idx+3])
        
        # Vertical beacon
        idx = len(vertices) // 3
        beacon_height = 0.5 + confidence * 1.5
        vertices.extend([
            px, py, pz,
            px, py + beacon_height, pz
        ])
        colors.extend([1.0, 0.8, 0.3, 0.9] * 2)
        indices.extend([idx, idx+1])
        
        # Fingerprint match indicator
        if fingerprint_match and 'similarity' in fingerprint_match:
            sim = fingerprint_match['similarity']
            idx = len(vertices) // 3
            ring_radius = 0.3
            for i in range(8):
                angle = 2 * math.pi * i / 8
                vertices.extend([
                    px + math.cos(angle) * ring_radius, py + 0.3, pz + math.sin(angle) * ring_radius
                ])
                colors.extend([sim, 1.0 - sim * 0.5, 0.5, 0.8])
            for i in range(8):
                indices.extend([idx + i, idx + (i + 1) % 8])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=loc_name,
            albedo=(0.5, 0.8, 1.0),
            emission=(0.3, 0.6, 0.8),
            emission_strength=0.5,
            opacity=0.75
        )
        
        loc_obj = Object3D(
            name=loc_name,
            mesh=mesh,
            material=material,
            data={"type": "localization", "confidence": confidence, "method": method}
        )
        
        self.scene.add_object(loc_obj)
        return loc_obj

    def create_emotion_aura(self, position: tuple, emotion: str,
                            intensity: float, stress_level: float = 0):
        """Create emotional state visualization as colored aura around person."""
        aura_name = "emotion_aura"
        self._remove_old_object(aura_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Emotion color mapping
        emotion_colors = {
            'calm': (0.3, 0.7, 1.0),
            'relaxed': (0.4, 0.8, 0.6),
            'focused': (0.9, 0.7, 0.2),
            'stressed': (1.0, 0.4, 0.2),
            'anxious': (1.0, 0.2, 0.4),
            'excited': (1.0, 0.6, 0.8),
            'neutral': (0.6, 0.6, 0.6)
        }
        
        r, g, b = emotion_colors.get(emotion, (0.5, 0.5, 0.5))
        
        # Multi-layer aura
        layers = 3
        base_radius = 0.6
        
        for layer in range(layers):
            layer_radius = base_radius + layer * 0.3
            layer_alpha = (0.5 - layer * 0.15) * intensity
            layer_height = py + 0.8 + layer * 0.2
            
            segments = 24
            for i in range(segments):
                angle1 = 2 * math.pi * i / segments
                angle2 = 2 * math.pi * (i + 1) / segments
                
                # Add wave distortion based on stress
                wave = math.sin(angle1 * 4 + stress_level * 10) * stress_level * 0.1
                
                idx = len(vertices) // 3
                
                vertices.extend([
                    px, layer_height, pz,
                    px + math.cos(angle1) * (layer_radius + wave), layer_height - 0.1, pz + math.sin(angle1) * (layer_radius + wave),
                    px + math.cos(angle2) * (layer_radius + wave), layer_height - 0.1, pz + math.sin(angle2) * (layer_radius + wave)
                ])
                
                # Blend color with stress
                sr = r * (1 - stress_level * 0.3) + stress_level * 0.3
                sg = g * (1 - stress_level * 0.5)
                sb = b * (1 - stress_level * 0.3)
                
                colors.extend([sr, sg, sb, layer_alpha] * 3)
                indices.extend([idx, idx+1, idx+2])
        
        # Particle effects for high intensity
        if intensity > 0.5:
            num_particles = int(intensity * 10)
            for i in range(num_particles):
                angle = 2 * math.pi * i / num_particles
                dist = base_radius * 1.5
                
                part_x = px + math.cos(angle) * dist
                part_y = py + 0.5 + (i % 3) * 0.3
                part_z = pz + math.sin(angle) * dist
                
                idx = len(vertices) // 3
                size = 0.05
                
                vertices.extend([
                    part_x - size, part_y, part_z,
                    part_x + size, part_y, part_z,
                    part_x, part_y + size * 2, part_z
                ])
                colors.extend([r, g, b, 0.8] * 3)
                indices.extend([idx, idx+1, idx+2])
        
        # Stress indicator ring
        if stress_level > 0.3:
            idx = len(vertices) // 3
            stress_radius = base_radius + 0.8
            for i in range(16):
                angle = 2 * math.pi * i / 16
                vertices.extend([
                    px + math.cos(angle) * stress_radius, py + 0.3, pz + math.sin(angle) * stress_radius
                ])
                colors.extend([1.0, 0.3, 0.2, stress_level])
            for i in range(16):
                indices.extend([idx + i, idx + (i + 1) % 16])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=aura_name,
            albedo=(r, g, b),
            emission=(r * 0.5, g * 0.5, b * 0.5),
            emission_strength=intensity * 0.8,
            opacity=0.6
        )
        
        # Add pulsing animation
        def pulse_aura(obj, time_val):
            scale = 1.0 + math.sin(time_val * 2) * 0.1 * intensity
            obj.transform.scale = (scale, scale, scale)
        
        aura_obj = Object3D(
            name=aura_name,
            mesh=mesh,
            material=material,
            animation_callback=pulse_aura,
            data={"type": "emotion_aura", "emotion": emotion, "intensity": intensity}
        )
        
        self.scene.add_object(aura_obj)
        return aura_obj

    def create_respiration_waveform(self, waveform: list, bpm: float,
                                     confidence: float, phase_quality: float = 0.5,
                                     position: tuple = (4, 1.5, -4)):
        """Create high-precision respiration waveform visualization."""
        resp_name = "respiration_waveform"
        self._remove_old_object(resp_name)
        
        vertices = []
        colors = []
        indices = []
        
        if not waveform or len(waveform) < 2:
            return None
        
        width = 3.0
        height = 1.0
        
        # Normalize waveform
        min_val = min(waveform)
        max_val = max(waveform)
        range_val = max_val - min_val if max_val != min_val else 1
        
        # Draw waveform
        num_points = len(waveform)
        for i in range(num_points - 1):
            x1 = position[0] + (i / num_points) * width
            x2 = position[0] + ((i + 1) / num_points) * width
            
            y1 = position[1] + ((waveform[i] - min_val) / range_val - 0.5) * height
            y2 = position[1] + ((waveform[i + 1] - min_val) / range_val - 0.5) * height
            
            z = position[2]
            
            idx = len(vertices) // 3
            
            # Color based on phase quality
            if phase_quality > 0.7:
                r, g, b = 0.3, 1.0, 0.5
            elif phase_quality > 0.4:
                r, g, b = 1.0, 0.8, 0.2
            else:
                r, g, b = 1.0, 0.4, 0.3
            
            vertices.extend([x1, y1, z, x2, y2, z])
            colors.extend([r, g, b, 0.9] * 2)
            indices.extend([idx, idx + 1])
        
        # BPM indicator
        idx = len(vertices) // 3
        bpm_y = position[1] + height / 2 + 0.3
        
        # Create number display using line segments (simplified)
        bpm_x = position[0] + width + 0.3
        
        # Simple bar for BPM value
        bar_width = min(bpm / 30, 1.0) * 0.5  # Normalize to 0-30 BPM range
        vertices.extend([
            bpm_x, bpm_y, position[2],
            bpm_x + bar_width, bpm_y, position[2],
            bpm_x + bar_width, bpm_y + 0.15, position[2],
            bpm_x, bpm_y + 0.15, position[2]
        ])
        
        # Color based on normal breathing rate
        if 12 <= bpm <= 20:
            br, bg, bb = 0.3, 1.0, 0.5  # Normal
        elif 8 <= bpm <= 25:
            br, bg, bb = 1.0, 0.8, 0.2  # Slightly abnormal
        else:
            br, bg, bb = 1.0, 0.3, 0.3  # Concerning
        
        colors.extend([br, bg, bb, 0.9] * 4)
        indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Confidence indicator
        idx = len(vertices) // 3
        conf_y = position[1] - height / 2 - 0.2
        vertices.extend([
            position[0], conf_y, position[2],
            position[0] + width * confidence, conf_y, position[2]
        ])
        colors.extend([0.5, 0.5, 1.0, 0.7] * 2)
        indices.extend([idx, idx+1])
        
        # Grid lines
        for i in range(5):
            idx = len(vertices) // 3
            gx = position[0] + (i / 4) * width
            vertices.extend([
                gx, position[1] - height / 2, position[2] - 0.01,
                gx, position[1] + height / 2, position[2] - 0.01
            ])
            colors.extend([0.3, 0.3, 0.3, 0.3] * 2)
            indices.extend([idx, idx+1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=resp_name,
            albedo=(0.4, 0.9, 0.5),
            emission=(0.2, 0.5, 0.3),
            emission_strength=0.4,
            opacity=0.85
        )
        
        resp_obj = Object3D(
            name=resp_name,
            mesh=mesh,
            material=material,
            data={"type": "respiration", "bpm": bpm, "confidence": confidence}
        )
        
        self.scene.add_object(resp_obj)
        return resp_obj

    # ========================================
    # NEXT-GEN VISUALIZATION METHODS
    # ========================================

    def create_sar_image(self, image: list, targets: list, resolution: int,
                         position: tuple = (0, 0.1, 0), scale: float = 5.0):
        """Create synthetic aperture radar image visualization."""
        sar_name = "sar_image"
        self._remove_old_object(sar_name)
        
        vertices = []
        colors = []
        indices = []
        
        if not image or len(image) == 0:
            return None
        
        grid_size = len(image)
        cell_size = scale / grid_size
        start_x = position[0] - scale / 2
        start_z = position[2] - scale / 2
        y_base = position[1]
        
        # Draw SAR image grid
        for i, row in enumerate(image):
            for j, value in enumerate(row):
                x = start_x + j * cell_size
                z = start_z + i * cell_size
                
                idx = len(vertices) // 3
                
                # Height based on intensity
                height = value * 0.3
                
                # Color: dark blue to bright cyan
                r = value * 0.3
                g = 0.3 + value * 0.7
                b = 0.5 + value * 0.5
                alpha = 0.4 + value * 0.4
                
                # Create cell
                vertices.extend([
                    x, y_base, z,
                    x + cell_size * 0.95, y_base, z,
                    x + cell_size * 0.95, y_base + height, z,
                    x, y_base + height, z,
                    x, y_base, z + cell_size * 0.95,
                    x + cell_size * 0.95, y_base, z + cell_size * 0.95,
                    x + cell_size * 0.95, y_base + height, z + cell_size * 0.95,
                    x, y_base + height, z + cell_size * 0.95
                ])
                
                colors.extend([r, g, b, alpha] * 8)
                
                # Connect vertices
                indices.extend([
                    idx, idx+1, idx+1, idx+2, idx+2, idx+3, idx+3, idx,
                    idx+4, idx+5, idx+5, idx+6, idx+6, idx+7, idx+7, idx+4,
                    idx, idx+4, idx+1, idx+5, idx+2, idx+6, idx+3, idx+7
                ])
        
        # Mark detected targets
        for target in targets:
            tx, tz = target.get('x', 0), target.get('z', 0)
            intensity = target.get('intensity', 0.5)
            
            idx = len(vertices) // 3
            marker_height = 0.5 + intensity * 0.5
            
            # Vertical marker
            vertices.extend([
                tx, y_base, tz,
                tx, y_base + marker_height, tz
            ])
            colors.extend([1.0, 1.0, 0.0, 1.0] * 2)
            indices.extend([idx, idx+1])
            
            # Cross marker at top
            idx = len(vertices) // 3
            size = 0.2
            vertices.extend([
                tx - size, y_base + marker_height, tz,
                tx + size, y_base + marker_height, tz,
                tx, y_base + marker_height, tz - size,
                tx, y_base + marker_height, tz + size
            ])
            colors.extend([1.0, 0.5, 0.0, 1.0] * 4)
            indices.extend([idx, idx+1, idx+2, idx+3])
        
        if len(vertices) == 0:
            return None
            
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=sar_name,
            albedo=(0.2, 0.6, 0.8),
            emission=(0.1, 0.4, 0.6),
            emission_strength=0.4,
            opacity=0.7
        )
        
        sar_obj = Object3D(
            name=sar_name,
            mesh=mesh,
            material=material,
            data={"type": "sar_image", "resolution": resolution}
        )
        
        self.scene.add_object(sar_obj)
        return sar_obj

    def create_gesture_indicator(self, gesture: str, confidence: float,
                                  position: tuple = (0, 2, 0)):
        """Create hand gesture recognition indicator."""
        gest_name = "gesture_indicator"
        self._remove_old_object(gest_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Gesture icon patterns
        gesture_patterns = {
            'swipe_left': [(-0.5, 0), (-0.2, 0.2), (-0.2, -0.2), (0.3, 0)],
            'swipe_right': [(0.5, 0), (0.2, 0.2), (0.2, -0.2), (-0.3, 0)],
            'swipe_up': [(0, 0.5), (-0.2, 0.2), (0.2, 0.2), (0, -0.3)],
            'swipe_down': [(0, -0.5), (-0.2, -0.2), (0.2, -0.2), (0, 0.3)],
            'push': [(0, 0), (0.15, 0.15), (-0.15, 0.15), (-0.15, -0.15), (0.15, -0.15)],
            'pull': [(0.2, 0.2), (-0.2, 0.2), (-0.2, -0.2), (0.2, -0.2)],
            'circle_cw': [(0.3, 0), (0.21, 0.21), (0, 0.3), (-0.21, 0.21), (-0.3, 0), (-0.21, -0.21), (0, -0.3), (0.21, -0.21)],
            'circle_ccw': [(0.3, 0), (0.21, -0.21), (0, -0.3), (-0.21, -0.21), (-0.3, 0), (-0.21, 0.21), (0, 0.3), (0.21, 0.21)],
            'wave': [(-0.4, 0.1), (-0.2, -0.1), (0, 0.1), (0.2, -0.1), (0.4, 0.1)],
            'grab': [(0, 0), (0.2, 0.2), (-0.2, 0.2), (-0.2, -0.2), (0.2, -0.2)]
        }
        
        # Get pattern or default
        pattern = gesture_patterns.get(gesture, [(0, 0)])
        
        # Draw gesture icon
        for i, (dx, dz) in enumerate(pattern):
            idx = len(vertices) // 3
            vertices.extend([px + dx * 0.5, py, pz + dz * 0.5])
            
            # Color based on confidence
            r, g, b = 0.3 + confidence * 0.7, 1.0, 0.3 + confidence * 0.4
            colors.extend([r, g, b, 0.9])
            
            if i > 0:
                indices.extend([idx - 1, idx])
        
        # Close shape for circular gestures
        if 'circle' in gesture and len(pattern) > 2:
            indices.extend([len(vertices) // 3 - 1, len(vertices) // 3 - len(pattern)])
        
        # Add confidence ring
        segments = 16
        radius = 0.4 + confidence * 0.2
        
        for i in range(segments):
            angle = 2 * math.pi * i / segments
            idx = len(vertices) // 3
            vertices.extend([
                px + math.cos(angle) * radius,
                py - 0.3,
                pz + math.sin(angle) * radius
            ])
            
            alpha = confidence * 0.8
            colors.extend([0.5, 1.0, 0.7, alpha])
            
            if i > 0:
                indices.extend([idx - 1, idx])
        indices.extend([len(vertices) // 3 - 1, len(vertices) // 3 - segments])
        
        # Gesture name text indicator (simplified as vertical bar)
        idx = len(vertices) // 3
        bar_height = confidence * 0.8
        vertices.extend([
            px + 0.5, py - 0.3, pz,
            px + 0.5, py - 0.3 + bar_height, pz
        ])
        colors.extend([1.0, 0.8, 0.2, 0.9] * 2)
        indices.extend([idx, idx + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=gest_name,
            albedo=(0.5, 1.0, 0.6),
            emission=(0.3, 0.8, 0.4),
            emission_strength=0.6,
            opacity=0.85
        )
        
        # Pulse animation
        def pulse_gesture(obj, time_val):
            scale = 1.0 + math.sin(time_val * 4) * 0.1
            obj.transform.scale = (scale, scale, scale)
        
        gest_obj = Object3D(
            name=gest_name,
            mesh=mesh,
            material=material,
            animation_callback=pulse_gesture,
            data={"type": "gesture", "gesture": gesture, "confidence": confidence}
        )
        
        self.scene.add_object(gest_obj)
        return gest_obj

    def create_gait_display(self, stride_freq: float, walking_speed: float,
                            symmetry: float, fall_risk: float, person_id: str,
                            position: tuple = (-4, 0.5, 4)):
        """Create gait analysis visualization display."""
        gait_name = "gait_display"
        self._remove_old_object(gait_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Create footstep visualization
        num_steps = 5
        step_spacing = 0.6
        
        for i in range(num_steps):
            idx = len(vertices) // 3
            
            # Alternate left/right feet
            x_offset = 0.15 if i % 2 == 0 else -0.15
            z_pos = pz + i * step_spacing
            
            # Fade older steps
            alpha = 0.3 + (i / num_steps) * 0.5
            
            # Footprint shape (ellipse approximation)
            foot_length = 0.2
            foot_width = 0.08
            
            for angle in range(0, 360, 30):
                rad = math.radians(angle)
                fx = px + x_offset + math.cos(rad) * foot_width
                fz = z_pos + math.sin(rad) * foot_length
                vertices.extend([fx, py, fz])
                
                # Color based on symmetry
                if symmetry > 0.8:
                    r, g, b = 0.3, 1.0, 0.5
                elif symmetry > 0.5:
                    r, g, b = 1.0, 0.8, 0.3
                else:
                    r, g, b = 1.0, 0.4, 0.3
                
                colors.extend([r, g, b, alpha])
            
            # Connect footprint
            base_idx = idx
            for j in range(12):
                indices.extend([base_idx + j, base_idx + (j + 1) % 12])
        
        # Speed indicator bar
        idx = len(vertices) // 3
        speed_bar_len = min(walking_speed / 2.0, 1.0) * 1.5
        vertices.extend([
            px - 0.6, py + 0.3, pz,
            px - 0.6 + speed_bar_len, py + 0.3, pz,
            px - 0.6 + speed_bar_len, py + 0.4, pz,
            px - 0.6, py + 0.4, pz
        ])
        colors.extend([0.3, 0.8, 1.0, 0.8] * 4)
        indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Fall risk indicator
        idx = len(vertices) // 3
        
        if fall_risk > 0.6:
            risk_color = (1.0, 0.3, 0.2)
        elif fall_risk > 0.3:
            risk_color = (1.0, 0.7, 0.2)
        else:
            risk_color = (0.3, 1.0, 0.5)
        
        # Triangle warning for high risk
        if fall_risk > 0.5:
            vertices.extend([
                px + 0.6, py + 0.5, pz,
                px + 0.8, py + 0.2, pz,
                px + 0.4, py + 0.2, pz
            ])
            colors.extend([risk_color[0], risk_color[1], risk_color[2], 0.9] * 3)
            indices.extend([idx, idx+1, idx+2])
        
        # Stride frequency wave
        idx = len(vertices) // 3
        wave_points = 20
        for i in range(wave_points):
            t = i / wave_points * 4 * math.pi
            x = px - 0.6 + (i / wave_points) * 1.2
            y = py + 0.6 + math.sin(t * stride_freq) * 0.1
            vertices.extend([x, y, pz])
            colors.extend([0.8, 0.5, 1.0, 0.7])
            
            if i > 0:
                indices.extend([idx + i - 1, idx + i])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=gait_name,
            albedo=(0.6, 0.8, 0.5),
            emission=(0.3, 0.5, 0.3),
            emission_strength=0.3,
            opacity=0.8
        )
        
        gait_obj = Object3D(
            name=gait_name,
            mesh=mesh,
            material=material,
            data={"type": "gait", "speed": walking_speed, "fall_risk": fall_risk, "person": person_id}
        )
        
        self.scene.add_object(gait_obj)
        return gait_obj

    def create_occupancy_heatmap(self, grid: list, peak: tuple,
                                  coverage: float, position: tuple = (0, 0.02, 0)):
        """Create occupancy heatmap floor overlay."""
        heat_name = "occupancy_heatmap"
        self._remove_old_object(heat_name)
        
        vertices = []
        colors = []
        indices = []
        
        if not grid or len(grid) == 0:
            return None
        
        grid_size = len(grid)
        room_size = 10.0
        cell_size = room_size / grid_size
        
        start_x = position[0] - room_size / 2
        start_z = position[2] - room_size / 2
        y = position[1]
        
        for i, row in enumerate(grid):
            for j, value in enumerate(row):
                x = start_x + j * cell_size
                z = start_z + i * cell_size
                
                idx = len(vertices) // 3
                
                # Heat color map: blue -> green -> yellow -> red
                if value < 0.25:
                    r, g, b = 0.0, value * 4, 0.5 + value * 2
                elif value < 0.5:
                    r, g, b = 0.0, 1.0, 1.0 - (value - 0.25) * 4
                elif value < 0.75:
                    r, g, b = (value - 0.5) * 4, 1.0, 0.0
                else:
                    r, g, b = 1.0, 1.0 - (value - 0.75) * 4, 0.0
                
                alpha = 0.1 + value * 0.5
                
                vertices.extend([
                    x, y, z,
                    x + cell_size, y, z,
                    x + cell_size, y, z + cell_size,
                    x, y, z + cell_size
                ])
                colors.extend([r, g, b, alpha] * 4)
                indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Mark peak location
        if peak:
            idx = len(vertices) // 3
            peak_x, peak_z = peak
            
            # Star marker
            for angle in range(0, 360, 72):
                rad1 = math.radians(angle)
                rad2 = math.radians(angle + 36)
                
                vertices.extend([
                    peak_x, y + 0.05, peak_z,
                    peak_x + math.cos(rad1) * 0.3, y + 0.05, peak_z + math.sin(rad1) * 0.3,
                    peak_x + math.cos(rad2) * 0.15, y + 0.05, peak_z + math.sin(rad2) * 0.15
                ])
                colors.extend([1.0, 1.0, 0.0, 1.0] * 3)
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=heat_name,
            albedo=(0.8, 0.4, 0.2),
            emission=(0.4, 0.2, 0.1),
            emission_strength=0.3,
            opacity=0.6
        )
        
        heat_obj = Object3D(
            name=heat_name,
            mesh=mesh,
            material=material,
            data={"type": "heatmap", "coverage": coverage}
        )
        
        self.scene.add_object(heat_obj)
        return heat_obj

    def create_interference_indicator(self, interference_type: str,
                                       strength: float, confidence: float,
                                       position: tuple = (4, 2.5, 4)):
        """Create interference warning indicator."""
        interf_name = "interference_indicator"
        self._remove_old_object(interf_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Interference colors by type
        type_colors = {
            'microwave': (1.0, 0.3, 0.8),
            'bluetooth': (0.3, 0.5, 1.0),
            'other_wifi': (1.0, 0.8, 0.2),
            'baby_monitor': (0.5, 1.0, 0.5),
            'cordless_phone': (1.0, 0.5, 0.3),
            'unknown': (0.7, 0.7, 0.7)
        }
        
        r, g, b = type_colors.get(interference_type, (0.7, 0.7, 0.7))
        
        # Warning icon - jagged signal burst
        num_rays = 8
        for i in range(num_rays):
            angle = 2 * math.pi * i / num_rays
            
            # Inner point
            idx = len(vertices) // 3
            inner_r = 0.2
            outer_r = 0.4 + strength * 0.3
            
            # Jagged ray
            vertices.extend([
                px + math.cos(angle) * inner_r, py, pz + math.sin(angle) * inner_r,
                px + math.cos(angle) * outer_r, py + 0.1, pz + math.sin(angle) * outer_r
            ])
            colors.extend([r, g, b, 0.9] * 2)
            indices.extend([idx, idx + 1])
            
            # Connect to next ray
            if i > 0:
                indices.extend([idx, idx - 1])
        
        # Pulsing rings based on strength
        num_rings = int(1 + strength * 3)
        for ring in range(num_rings):
            ring_radius = 0.5 + ring * 0.3
            ring_alpha = 0.6 - ring * 0.15
            
            idx = len(vertices) // 3
            for i in range(16):
                angle = 2 * math.pi * i / 16
                vertices.extend([
                    px + math.cos(angle) * ring_radius,
                    py - 0.2 - ring * 0.1,
                    pz + math.sin(angle) * ring_radius
                ])
                colors.extend([r * 0.7, g * 0.7, b * 0.7, ring_alpha])
                
                if i > 0:
                    indices.extend([idx + i - 1, idx + i])
            indices.extend([idx + 15, idx])
        
        # Strength bar
        idx = len(vertices) // 3
        bar_height = strength * 0.5
        vertices.extend([
            px + 0.6, py - 0.4, pz,
            px + 0.7, py - 0.4, pz,
            px + 0.7, py - 0.4 + bar_height, pz,
            px + 0.6, py - 0.4 + bar_height, pz
        ])
        colors.extend([r, g, b, 0.8] * 4)
        indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=interf_name,
            albedo=(r, g, b),
            emission=(r * 0.5, g * 0.5, b * 0.5),
            emission_strength=strength * 0.8,
            opacity=0.85
        )
        
        # Flashing animation for strong interference
        def flash_interference(obj, time_val):
            flash = 0.7 + math.sin(time_val * 6) * 0.3 * strength
            obj.material.emission_strength = flash
        
        interf_obj = Object3D(
            name=interf_name,
            mesh=mesh,
            material=material,
            animation_callback=flash_interference,
            data={"type": "interference", "interference_type": interference_type, "strength": strength}
        )
        
        self.scene.add_object(interf_obj)
        return interf_obj

    # ========================================
    # CUTTING-EDGE VISUALIZATION METHODS
    # ========================================

    def create_signal_quality_display(self, snr: float, stability: float,
                                       outlier_rate: float, position: tuple = (4, 2.5, -4)):
        """Create signal quality metrics display."""
        qual_name = "signal_quality_display"
        self._remove_old_object(qual_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Create 3 vertical bars for metrics
        metrics = [
            ('SNR', min(1.0, (snr + 10) / 40), (0.3, 0.8, 1.0)),  # Normalize -10 to 30 dB
            ('Stability', stability, (0.3, 1.0, 0.5)),
            ('Clean', 1.0 - outlier_rate, (1.0, 0.8, 0.3))
        ]
        
        bar_width = 0.15
        bar_spacing = 0.25
        max_height = 1.0
        
        for i, (name, value, color) in enumerate(metrics):
            x = px + i * bar_spacing
            
            idx = len(vertices) // 3
            bar_height = max(0.05, value * max_height)
            
            # Bar base
            vertices.extend([
                x, py, pz,
                x + bar_width, py, pz,
                x + bar_width, py + bar_height, pz,
                x, py + bar_height, pz
            ])
            
            r, g, b = color
            alpha = 0.7 + value * 0.2
            colors.extend([r, g, b, alpha] * 4)
            indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
            
            # Background bar (gray)
            idx = len(vertices) // 3
            vertices.extend([
                x, py, pz - 0.02,
                x + bar_width, py, pz - 0.02,
                x + bar_width, py + max_height, pz - 0.02,
                x, py + max_height, pz - 0.02
            ])
            colors.extend([0.3, 0.3, 0.3, 0.3] * 4)
            indices.extend([idx, idx+1, idx+1, idx+2, idx+2, idx+3, idx+3, idx])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=qual_name,
            albedo=(0.5, 0.8, 0.6),
            emission=(0.2, 0.4, 0.3),
            emission_strength=0.3,
            opacity=0.8
        )
        
        qual_obj = Object3D(
            name=qual_name,
            mesh=mesh,
            material=material,
            data={"type": "signal_quality", "snr": snr, "stability": stability}
        )
        
        self.scene.add_object(qual_obj)
        return qual_obj

    def create_beamforming_pattern(self, direction: float, width: float,
                                    gain: float, weights: list,
                                    position: tuple = (0, 2, 0)):
        """Create MIMO beamforming pattern visualization."""
        bf_name = "beamforming_pattern"
        self._remove_old_object(bf_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Draw beam pattern as polar plot
        num_angles = 72
        radius = 2.0
        
        for i in range(num_angles):
            angle = 2 * math.pi * i / num_angles
            
            # Calculate beam pattern value at this angle
            # Main lobe centered at 'direction'
            angle_diff = abs(angle - math.radians(direction))
            if angle_diff > math.pi:
                angle_diff = 2 * math.pi - angle_diff
            
            width_rad = math.radians(max(width, 10))
            
            # Gaussian-like beam pattern
            if angle_diff < width_rad:
                pattern = 1.0 * math.exp(-2 * (angle_diff / width_rad) ** 2)
            else:
                # Sidelobe
                pattern = 0.2 * math.exp(-((angle_diff - width_rad) / width_rad) ** 2)
            
            r = radius * (0.3 + pattern * 0.7)
            
            idx = len(vertices) // 3
            vertices.extend([
                px, py, pz,
                px + math.cos(angle) * r, py, pz + math.sin(angle) * r
            ])
            
            # Color based on pattern strength
            if pattern > 0.5:
                cr, cg, cb = 0.0, 1.0, 0.5  # Main lobe - green
            else:
                cr, cg, cb = 0.3, 0.5, 1.0  # Sidelobe - blue
            
            alpha = 0.3 + pattern * 0.5
            colors.extend([cr, cg, cb, alpha] * 2)
            indices.extend([idx, idx + 1])
        
        # Draw antenna array representation
        num_antennas = len(weights) if weights else 4
        antenna_spacing = 0.3
        start_x = px - (num_antennas - 1) * antenna_spacing / 2
        
        for i in range(num_antennas):
            idx = len(vertices) // 3
            ax = start_x + i * antenna_spacing
            
            # Antenna element (vertical line)
            vertices.extend([
                ax, py - 0.3, pz,
                ax, py + 0.3, pz
            ])
            
            # Color based on weight magnitude
            if weights and i < len(weights):
                w_mag = math.sqrt(weights[i][0]**2 + weights[i][1]**2)
            else:
                w_mag = 1.0 / num_antennas
            
            colors.extend([1.0, 0.8 * w_mag, 0.2, 0.9] * 2)
            indices.extend([idx, idx + 1])
        
        # Beam direction indicator arrow
        idx = len(vertices) // 3
        dir_rad = math.radians(direction)
        arrow_len = radius * 1.2
        
        vertices.extend([
            px, py, pz,
            px + math.cos(dir_rad) * arrow_len, py, pz + math.sin(dir_rad) * arrow_len
        ])
        colors.extend([1.0, 1.0, 0.0, 1.0] * 2)
        indices.extend([idx, idx + 1])
        
        # Arrow head
        idx = len(vertices) // 3
        head_len = 0.2
        head_angle = 0.3
        
        vertices.extend([
            px + math.cos(dir_rad) * arrow_len, py, pz + math.sin(dir_rad) * arrow_len,
            px + math.cos(dir_rad - head_angle) * (arrow_len - head_len), py, pz + math.sin(dir_rad - head_angle) * (arrow_len - head_len),
            px + math.cos(dir_rad) * arrow_len, py, pz + math.sin(dir_rad) * arrow_len,
            px + math.cos(dir_rad + head_angle) * (arrow_len - head_len), py, pz + math.sin(dir_rad + head_angle) * (arrow_len - head_len)
        ])
        colors.extend([1.0, 1.0, 0.0, 1.0] * 4)
        indices.extend([idx, idx+1, idx+2, idx+3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=bf_name,
            albedo=(0.3, 0.8, 0.5),
            emission=(0.2, 0.5, 0.3),
            emission_strength=0.4,
            opacity=0.75
        )
        
        # Rotation animation
        def rotate_pattern(obj, time_val):
            # Subtle wobble
            wobble = math.sin(time_val * 0.5) * 0.02
            obj.transform.rotation = (0, wobble, 0)
        
        bf_obj = Object3D(
            name=bf_name,
            mesh=mesh,
            material=material,
            animation_callback=rotate_pattern,
            data={"type": "beamforming", "direction": direction, "gain": gain}
        )
        
        self.scene.add_object(bf_obj)
        return bf_obj

    def create_context_display(self, activity: str, room: str,
                                social: str, time: str,
                                position: tuple = (-4, 2.5, -4)):
        """Create context awareness display panel."""
        ctx_name = "context_display"
        self._remove_old_object(ctx_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Context icons and colors
        context_visuals = {
            'sleeping': ('💤', (0.3, 0.3, 0.8)),
            'cooking': ('🍳', (1.0, 0.6, 0.2)),
            'working': ('💻', (0.5, 0.7, 1.0)),
            'exercising': ('🏃', (0.3, 1.0, 0.5)),
            'watching_tv': ('📺', (0.8, 0.5, 1.0)),
            'entertaining': ('🎉', (1.0, 0.8, 0.3)),
            'unknown': ('❓', (0.5, 0.5, 0.5))
        }
        
        r, g, b = context_visuals.get(activity, ('❓', (0.5, 0.5, 0.5)))[1]
        
        # Main activity indicator (circle)
        idx = len(vertices) // 3
        segments = 24
        activity_radius = 0.4
        
        for i in range(segments):
            angle1 = 2 * math.pi * i / segments
            angle2 = 2 * math.pi * (i + 1) / segments
            
            vertices.extend([
                px, py, pz,
                px + math.cos(angle1) * activity_radius, py, pz + math.sin(angle1) * activity_radius,
                px + math.cos(angle2) * activity_radius, py, pz + math.sin(angle2) * activity_radius
            ])
            colors.extend([r, g, b, 0.8] * 3)
            indices.extend([idx + i*3, idx + i*3 + 1, idx + i*3 + 2])
        
        # Time indicator arc
        time_colors = {
            'early_morning': (0.8, 0.6, 0.3),
            'morning': (1.0, 0.9, 0.4),
            'afternoon': (1.0, 0.8, 0.2),
            'evening': (0.8, 0.4, 0.2),
            'night': (0.3, 0.3, 0.6)
        }
        
        tr, tg, tb = time_colors.get(time, (0.5, 0.5, 0.5))
        
        idx = len(vertices) // 3
        arc_radius = 0.6
        for i in range(8):
            angle = math.pi * i / 7 - math.pi / 2  # Top arc
            vertices.extend([
                px + math.cos(angle) * arc_radius, py + 0.5, pz + math.sin(angle) * arc_radius
            ])
            colors.extend([tr, tg, tb, 0.7])
            if i > 0:
                indices.extend([idx + i - 1, idx + i])
        
        # Social context indicator (people icons)
        social_sizes = {'alone': 1, 'small_group': 3, 'gathering': 5, 'empty': 0}
        num_people = social_sizes.get(social, 0)
        
        for p in range(min(num_people, 5)):
            idx = len(vertices) // 3
            person_x = px - 0.5 + p * 0.25
            person_y = py - 0.5
            
            # Simple person shape (line)
            vertices.extend([
                person_x, person_y, pz,
                person_x, person_y + 0.3, pz
            ])
            colors.extend([0.8, 0.8, 1.0, 0.7] * 2)
            indices.extend([idx, idx + 1])
            
            # Head
            idx = len(vertices) // 3
            for angle in range(0, 360, 60):
                rad = math.radians(angle)
                vertices.extend([
                    person_x + math.cos(rad) * 0.05, person_y + 0.35, pz + math.sin(rad) * 0.05
                ])
                colors.extend([0.8, 0.8, 1.0, 0.7])
        
        # Room type indicator (corner bracket)
        room_colors = {
            'bedroom': (0.5, 0.5, 0.8),
            'kitchen': (0.8, 0.6, 0.3),
            'living_room': (0.5, 0.8, 0.5),
            'bathroom': (0.4, 0.7, 0.8),
            'unknown': (0.5, 0.5, 0.5)
        }
        
        rr, rg, rb = room_colors.get(room, (0.5, 0.5, 0.5))
        
        idx = len(vertices) // 3
        bracket_size = 0.15
        vertices.extend([
            px + 0.5, py + 0.5, pz,
            px + 0.5 - bracket_size, py + 0.5, pz,
            px + 0.5, py + 0.5, pz,
            px + 0.5, py + 0.5 - bracket_size, pz
        ])
        colors.extend([rr, rg, rb, 0.8] * 4)
        indices.extend([idx, idx+1, idx+2, idx+3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=ctx_name,
            albedo=(r, g, b),
            emission=(r * 0.3, g * 0.3, b * 0.3),
            emission_strength=0.4,
            opacity=0.8
        )
        
        ctx_obj = Object3D(
            name=ctx_name,
            mesh=mesh,
            material=material,
            data={"type": "context", "activity": activity, "room": room, "social": social}
        )
        
        self.scene.add_object(ctx_obj)
        return ctx_obj

    # ========================================
    # NEXT-GENERATION AI VISUALIZATION METHODS
    # ========================================

    def create_channel_prediction_viz(self, current: float, predicted: list,
                                       confidence: float, trend: str,
                                       position: tuple = (4.5, 2.5, -4)):
        """Create channel prediction visualization with future trajectory."""
        pred_name = "channel_prediction"
        self._remove_old_object(pred_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Trend colors
        trend_colors = {
            'rising': (0.3, 1.0, 0.4),
            'falling': (1.0, 0.3, 0.3),
            'stable': (0.5, 0.8, 1.0),
            'fluctuating': (1.0, 0.8, 0.3)
        }
        
        r, g, b = trend_colors.get(trend, (0.5, 0.5, 0.5))
        
        # Current value indicator (solid bar)
        idx = len(vertices) // 3
        bar_height = min(1.0, max(0.1, current))
        bar_width = 0.1
        
        vertices.extend([
            px, py, pz,
            px + bar_width, py, pz,
            px + bar_width, py + bar_height, pz,
            px, py + bar_height, pz
        ])
        colors.extend([r, g, b, 0.9] * 4)
        indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Predicted values (gradient bars)
        for i, pred_val in enumerate(predicted[:5]):
            idx = len(vertices) // 3
            pred_height = min(1.0, max(0.1, pred_val))
            alpha = 0.8 - i * 0.1
            offset = (i + 1) * 0.15
            
            vertices.extend([
                px + offset, py, pz,
                px + offset + bar_width * 0.8, py, pz,
                px + offset + bar_width * 0.8, py + pred_height, pz,
                px + offset, py + pred_height, pz
            ])
            colors.extend([r * 0.8, g * 0.8, b * 0.8, alpha] * 4)
            indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Trend arrow
        idx = len(vertices) // 3
        arrow_y_offset = 0.1 if trend == 'rising' else -0.1 if trend == 'falling' else 0
        
        vertices.extend([
            px - 0.2, py + 0.5, pz,
            px - 0.3, py + 0.5 + arrow_y_offset, pz,
            px - 0.1, py + 0.5 + arrow_y_offset * 2, pz
        ])
        colors.extend([r, g, b, 0.9] * 3)
        indices.extend([idx, idx+1, idx+2])
        
        # Confidence ring
        idx = len(vertices) // 3
        ring_segments = int(24 * confidence)
        ring_radius = 0.3
        
        for i in range(ring_segments):
            angle = 2 * math.pi * i / 24
            vertices.extend([
                px - 0.2 + math.cos(angle) * ring_radius,
                py + 1.2,
                pz + math.sin(angle) * ring_radius
            ])
            colors.extend([r, g, b, 0.6])
            if i > 0:
                indices.extend([idx + i - 1, idx + i])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=pred_name,
            albedo=(r, g, b),
            emission=(r * 0.4, g * 0.4, b * 0.4),
            emission_strength=0.5,
            opacity=0.85
        )
        
        pred_obj = Object3D(
            name=pred_name,
            mesh=mesh,
            material=material,
            data={"type": "prediction", "trend": trend, "confidence": confidence}
        )
        
        self.scene.add_object(pred_obj)
        return pred_obj

    def create_pose_skeleton(self, joints: dict, pose_type: str,
                              confidence: float,
                              position: tuple = (4.0, 0.0, 4.0)):
        """Create human pose skeleton visualization from CSI-estimated joint positions."""
        pose_name = "pose_skeleton"
        self._remove_old_object(pose_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Pose type colors
        pose_colors = {
            'standing': (0.3, 1.0, 0.5),
            'sitting': (0.5, 0.8, 1.0),
            'lying': (0.8, 0.5, 1.0),
            'walking': (1.0, 0.8, 0.3),
            'crouching': (0.8, 0.6, 0.4),
            'unknown': (0.5, 0.5, 0.5)
        }
        
        r, g, b = pose_colors.get(pose_type, (0.5, 0.5, 0.5))
        
        # Skeleton connections
        skeleton_bones = [
            ('head', 'neck'),
            ('neck', 'left_shoulder'),
            ('neck', 'right_shoulder'),
            ('left_shoulder', 'left_elbow'),
            ('left_elbow', 'left_wrist'),
            ('right_shoulder', 'right_elbow'),
            ('right_elbow', 'right_wrist'),
            ('neck', 'spine'),
            ('spine', 'hip'),
            ('hip', 'left_hip'),
            ('hip', 'right_hip'),
            ('left_hip', 'left_knee'),
            ('left_knee', 'left_ankle'),
            ('right_hip', 'right_knee'),
            ('right_knee', 'right_ankle')
        ]
        
        # Draw joints as small spheres (approximated as triangles)
        for joint_name, joint_pos in joints.items():
            if joint_pos is None:
                continue
                
            jx, jy, jz = joint_pos
            idx = len(vertices) // 3
            joint_radius = 0.05
            
            # Simple octagon for joint
            for i in range(8):
                angle1 = 2 * math.pi * i / 8
                angle2 = 2 * math.pi * (i + 1) / 8
                
                vertices.extend([
                    px + jx, py + jy, pz + jz,
                    px + jx + math.cos(angle1) * joint_radius,
                    py + jy + math.sin(angle1) * joint_radius,
                    pz + jz,
                    px + jx + math.cos(angle2) * joint_radius,
                    py + jy + math.sin(angle2) * joint_radius,
                    pz + jz
                ])
                colors.extend([r, g, b, 0.9] * 3)
                indices.extend([idx + i*3, idx + i*3 + 1, idx + i*3 + 2])
        
        # Draw bones as lines
        for bone_start, bone_end in skeleton_bones:
            if bone_start not in joints or bone_end not in joints:
                continue
            if joints[bone_start] is None or joints[bone_end] is None:
                continue
            
            idx = len(vertices) // 3
            s = joints[bone_start]
            e = joints[bone_end]
            
            vertices.extend([
                px + s[0], py + s[1], pz + s[2],
                px + e[0], py + e[1], pz + e[2]
            ])
            colors.extend([r * 0.8, g * 0.8, b * 0.8, 0.8] * 2)
            indices.extend([idx, idx + 1])
        
        # Confidence indicator around skeleton
        idx = len(vertices) // 3
        ring_segments = int(20 * confidence)
        ring_radius = 0.8
        
        for i in range(ring_segments):
            angle = 2 * math.pi * i / 20
            vertices.extend([
                px + math.cos(angle) * ring_radius, py + 0.9, pz + math.sin(angle) * ring_radius
            ])
            colors.extend([r, g, b, 0.4])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=pose_name,
            albedo=(r, g, b),
            emission=(r * 0.5, g * 0.5, b * 0.5),
            emission_strength=0.6,
            opacity=0.85
        )
        
        pose_obj = Object3D(
            name=pose_name,
            mesh=mesh,
            material=material,
            data={"type": "pose", "pose_type": pose_type, "confidence": confidence}
        )
        
        self.scene.add_object(pose_obj)
        return pose_obj

    def create_object_marker(self, object_type: str, position: tuple,
                              size: float, material: str, confidence: float):
        """Create 3D marker for recognized objects from CSI reflections."""
        obj_name = f"object_{object_type}_{hash(position) % 10000}"
        self._remove_old_object(obj_name)
        
        vertices = []
        colors = []
        indices = []
        
        ox, oy, oz = position
        
        # Object type colors and shapes
        object_visuals = {
            'furniture': ((0.6, 0.4, 0.2), 'cube'),
            'appliance': ((0.7, 0.7, 0.8), 'cylinder'),
            'person': ((1.0, 0.8, 0.6), 'capsule'),
            'pet': ((0.8, 0.6, 0.4), 'sphere'),
            'vehicle': ((0.5, 0.5, 0.6), 'box'),
            'unknown': ((0.5, 0.5, 0.5), 'cube')
        }
        
        (r, g, b), shape = object_visuals.get(object_type, ((0.5, 0.5, 0.5), 'cube'))
        
        # Material modifiers
        material_mods = {
            'metal': (0.8, 0.8, 0.9),
            'wood': (0.7, 0.5, 0.3),
            'plastic': (0.6, 0.6, 0.7),
            'fabric': (0.5, 0.4, 0.5),
            'glass': (0.4, 0.6, 0.8),
            'organic': (0.6, 0.7, 0.5)
        }
        
        if material in material_mods:
            mr, mg, mb = material_mods[material]
            r = (r + mr) / 2
            g = (g + mg) / 2
            b = (b + mb) / 2
        
        # Create shape based on object type
        half_size = size / 2
        
        if shape == 'cube':
            # Cube vertices
            idx = len(vertices) // 3
            cube_verts = [
                [ox - half_size, oy, oz - half_size],
                [ox + half_size, oy, oz - half_size],
                [ox + half_size, oy + size, oz - half_size],
                [ox - half_size, oy + size, oz - half_size],
                [ox - half_size, oy, oz + half_size],
                [ox + half_size, oy, oz + half_size],
                [ox + half_size, oy + size, oz + half_size],
                [ox - half_size, oy + size, oz + half_size]
            ]
            
            for v in cube_verts:
                vertices.extend(v)
                colors.extend([r, g, b, 0.7])
            
            # Cube faces
            cube_faces = [
                [0, 1, 2, 3], [4, 5, 6, 7], [0, 1, 5, 4],
                [2, 3, 7, 6], [0, 3, 7, 4], [1, 2, 6, 5]
            ]
            for face in cube_faces:
                indices.extend([idx + face[0], idx + face[1], idx + face[2]])
                indices.extend([idx + face[0], idx + face[2], idx + face[3]])
        
        elif shape == 'sphere':
            # Sphere approximation
            idx = len(vertices) // 3
            lat_segments = 8
            lon_segments = 12
            
            for lat in range(lat_segments + 1):
                theta = math.pi * lat / lat_segments
                for lon in range(lon_segments + 1):
                    phi = 2 * math.pi * lon / lon_segments
                    
                    x = ox + half_size * math.sin(theta) * math.cos(phi)
                    y = oy + half_size + half_size * math.cos(theta)
                    z = oz + half_size * math.sin(theta) * math.sin(phi)
                    
                    vertices.extend([x, y, z])
                    colors.extend([r, g, b, 0.7])
            
            for lat in range(lat_segments):
                for lon in range(lon_segments):
                    current = idx + lat * (lon_segments + 1) + lon
                    next_lat = current + lon_segments + 1
                    
                    indices.extend([current, next_lat, current + 1])
                    indices.extend([current + 1, next_lat, next_lat + 1])
        
        else:  # cylinder
            idx = len(vertices) // 3
            segments = 12
            
            for i in range(segments + 1):
                angle = 2 * math.pi * i / segments
                cx = ox + half_size * 0.5 * math.cos(angle)
                cz = oz + half_size * 0.5 * math.sin(angle)
                
                vertices.extend([cx, oy, cz])
                vertices.extend([cx, oy + size, cz])
                colors.extend([r, g, b, 0.7] * 2)
            
            for i in range(segments):
                base = idx + i * 2
                indices.extend([base, base + 2, base + 1])
                indices.extend([base + 1, base + 2, base + 3])
        
        # Confidence aura
        idx = len(vertices) // 3
        aura_segments = int(16 * confidence)
        aura_radius = size * 0.7
        
        for i in range(aura_segments):
            angle = 2 * math.pi * i / 16
            vertices.extend([
                ox + math.cos(angle) * aura_radius,
                oy + size + 0.1,
                oz + math.sin(angle) * aura_radius
            ])
            colors.extend([r, g, b, 0.3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        mat = Material3D(
            name=obj_name,
            albedo=(r, g, b),
            emission=(r * 0.2, g * 0.2, b * 0.2),
            emission_strength=0.3,
            opacity=0.75
        )
        
        obj = Object3D(
            name=obj_name,
            mesh=mesh,
            material=mat,
            data={"type": "detected_object", "object_type": object_type, "material": material}
        )
        
        self.scene.add_object(obj)
        return obj

    def create_anomaly_explanation(self, primary_cause: str,
                                    contributing_factors: list,
                                    confidence: float,
                                    suggested_action: str,
                                    position: tuple = (-4.5, 2.0, 4.5)):
        """Create visual explanation for detected anomalies."""
        anom_name = "anomaly_explanation"
        self._remove_old_object(anom_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Anomaly severity color
        r, g, b = (1.0, 0.4, 0.3)  # Warning color
        
        # Central warning icon (triangle)
        idx = len(vertices) // 3
        tri_size = 0.3
        
        vertices.extend([
            px, py + tri_size * 1.5, pz,
            px - tri_size, py, pz,
            px + tri_size, py, pz
        ])
        colors.extend([r, g, b, 0.9] * 3)
        indices.extend([idx, idx + 1, idx + 2])
        
        # Exclamation point in center
        idx = len(vertices) // 3
        vertices.extend([
            px, py + tri_size * 1.2, pz + 0.01,
            px, py + tri_size * 0.5, pz + 0.01,
            px - 0.02, py + tri_size * 0.3, pz + 0.01,
            px + 0.02, py + tri_size * 0.3, pz + 0.01
        ])
        colors.extend([0.1, 0.1, 0.1, 1.0] * 4)
        indices.extend([idx, idx + 1, idx + 2, idx + 3])
        
        # Contributing factor rays
        factor_colors = [
            (1.0, 0.6, 0.3),
            (1.0, 0.8, 0.3),
            (0.8, 1.0, 0.3),
            (0.5, 0.8, 1.0),
            (0.8, 0.5, 1.0)
        ]
        
        num_factors = min(len(contributing_factors), 5)
        for i, factor in enumerate(contributing_factors[:5]):
            idx = len(vertices) // 3
            angle = 2 * math.pi * i / max(num_factors, 1) - math.pi / 2
            
            ray_length = 0.5 * factor.get('weight', 0.5) if isinstance(factor, dict) else 0.4
            fr, fg, fb = factor_colors[i % len(factor_colors)]
            
            vertices.extend([
                px, py + tri_size * 0.75, pz,
                px + math.cos(angle) * ray_length, py + tri_size * 0.75, pz + math.sin(angle) * ray_length
            ])
            colors.extend([fr, fg, fb, 0.7] * 2)
            indices.extend([idx, idx + 1])
            
            # Factor endpoint marker
            idx = len(vertices) // 3
            for j in range(6):
                a1 = 2 * math.pi * j / 6
                a2 = 2 * math.pi * (j + 1) / 6
                end_x = px + math.cos(angle) * ray_length
                end_z = pz + math.sin(angle) * ray_length
                
                vertices.extend([
                    end_x, py + tri_size * 0.75, end_z,
                    end_x + math.cos(a1) * 0.05, py + tri_size * 0.75, end_z + math.sin(a1) * 0.05,
                    end_x + math.cos(a2) * 0.05, py + tri_size * 0.75, end_z + math.sin(a2) * 0.05
                ])
                colors.extend([fr, fg, fb, 0.8] * 3)
                indices.extend([idx + j*3, idx + j*3 + 1, idx + j*3 + 2])
        
        # Confidence ring
        idx = len(vertices) // 3
        ring_segments = int(20 * confidence)
        ring_radius = 0.6
        
        for i in range(ring_segments):
            angle = 2 * math.pi * i / 20
            vertices.extend([
                px + math.cos(angle) * ring_radius, py + tri_size * 0.75, pz + math.sin(angle) * ring_radius
            ])
            colors.extend([r * 0.8, g * 0.8, b * 0.8, 0.5])
            if i > 0:
                indices.extend([idx + i - 1, idx + i])
        
        # Action indicator arrow
        idx = len(vertices) // 3
        vertices.extend([
            px, py - 0.3, pz,
            px - 0.15, py - 0.5, pz,
            px, py - 0.7, pz,
            px + 0.15, py - 0.5, pz
        ])
        colors.extend([0.3, 0.8, 1.0, 0.7] * 4)
        indices.extend([idx, idx + 1, idx + 2, idx + 3, idx])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=anom_name,
            albedo=(r, g, b),
            emission=(r * 0.5, g * 0.3, b * 0.2),
            emission_strength=0.6,
            opacity=0.85
        )
        
        anom_obj = Object3D(
            name=anom_name,
            mesh=mesh,
            material=material,
            data={
                "type": "anomaly_explanation",
                "primary_cause": primary_cause,
                "suggested_action": suggested_action
            }
        )
        
        self.scene.add_object(anom_obj)
        return anom_obj

    def create_fusion_display(self, fused_state: dict, confidence: float,
                               active_sensors: list, state_stability: float,
                               position: tuple = (4.5, 2.5, 4.5)):
        """Create multi-sensor fusion visualization showing combined state."""
        fusion_name = "sensor_fusion"
        self._remove_old_object(fusion_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Fusion quality color (stability-based)
        stability_color = (
            0.3 + 0.7 * (1 - state_stability),
            0.3 + 0.7 * state_stability,
            0.5
        )
        r, g, b = stability_color
        
        # Central fusion core (layered spheres)
        idx = len(vertices) // 3
        core_layers = 3
        for layer in range(core_layers):
            layer_radius = 0.15 + layer * 0.1
            layer_alpha = 0.8 - layer * 0.2
            segments = 16
            
            for i in range(segments):
                angle1 = 2 * math.pi * i / segments
                angle2 = 2 * math.pi * (i + 1) / segments
                
                vertices.extend([
                    px, py, pz,
                    px + math.cos(angle1) * layer_radius, py, pz + math.sin(angle1) * layer_radius,
                    px + math.cos(angle2) * layer_radius, py, pz + math.sin(angle2) * layer_radius
                ])
                layer_r = r * (1 - layer * 0.2)
                layer_g = g * (1 - layer * 0.2)
                layer_b = b * (1 - layer * 0.2)
                colors.extend([layer_r, layer_g, layer_b, layer_alpha] * 3)
                indices.extend([idx, idx + 1, idx + 2])
                idx += 3
        
        # Sensor input rays
        sensor_colors = {
            'csi': (0.3, 0.8, 1.0),
            'doppler': (1.0, 0.6, 0.3),
            'rssi': (0.5, 1.0, 0.5),
            'vital_signs': (1.0, 0.4, 0.4),
            'pose': (0.8, 0.5, 1.0),
            'accelerometer': (1.0, 1.0, 0.3),
            'gyroscope': (0.3, 1.0, 0.8)
        }
        
        num_sensors = len(active_sensors)
        for i, sensor in enumerate(active_sensors):
            idx = len(vertices) // 3
            angle = 2 * math.pi * i / max(num_sensors, 1)
            
            sr, sg, sb = sensor_colors.get(sensor, (0.5, 0.5, 0.5))
            ray_length = 0.6
            
            # Ray from sensor to center
            vertices.extend([
                px + math.cos(angle) * ray_length, py, pz + math.sin(angle) * ray_length,
                px, py, pz
            ])
            colors.extend([sr, sg, sb, 0.8] * 2)
            indices.extend([idx, idx + 1])
            
            # Sensor icon (small circle at ray end)
            idx = len(vertices) // 3
            icon_radius = 0.08
            for j in range(8):
                a1 = 2 * math.pi * j / 8
                a2 = 2 * math.pi * (j + 1) / 8
                icon_x = px + math.cos(angle) * ray_length
                icon_z = pz + math.sin(angle) * ray_length
                
                vertices.extend([
                    icon_x, py, icon_z,
                    icon_x + math.cos(a1) * icon_radius, py, icon_z + math.sin(a1) * icon_radius,
                    icon_x + math.cos(a2) * icon_radius, py, icon_z + math.sin(a2) * icon_radius
                ])
                colors.extend([sr, sg, sb, 0.9] * 3)
                indices.extend([idx + j*3, idx + j*3 + 1, idx + j*3 + 2])
        
        # Confidence orbit
        idx = len(vertices) // 3
        orbit_segments = int(24 * confidence)
        orbit_radius = 0.5
        
        for i in range(orbit_segments):
            angle = 2 * math.pi * i / 24
            vertices.extend([
                px + math.cos(angle) * orbit_radius, py + 0.3, pz + math.sin(angle) * orbit_radius
            ])
            colors.extend([r, g, b, 0.5])
            if i > 0:
                indices.extend([idx + i - 1, idx + i])
        
        # State stability indicator (vertical bars)
        idx = len(vertices) // 3
        num_bars = 5
        bar_width = 0.05
        
        for i in range(num_bars):
            bar_height = 0.5 * state_stability * (0.5 + 0.5 * ((i + 1) / num_bars))
            bar_x = px - 0.3 + i * 0.15
            
            vertices.extend([
                bar_x, py - 0.6, pz,
                bar_x + bar_width, py - 0.6, pz,
                bar_x + bar_width, py - 0.6 + bar_height, pz,
                bar_x, py - 0.6 + bar_height, pz
            ])
            bar_alpha = 0.5 + 0.3 * ((i + 1) / num_bars)
            colors.extend([g, r, b, bar_alpha] * 4)
            indices.extend([idx + i*4, idx + i*4 + 1, idx + i*4 + 2])
            indices.extend([idx + i*4, idx + i*4 + 2, idx + i*4 + 3])
        
        # Fused state value indicators
        idx = len(vertices) // 3
        state_items = list(fused_state.items())[:4]  # Max 4 items
        
        for i, (key, value) in enumerate(state_items):
            if isinstance(value, (int, float)):
                normalized = min(1.0, max(0.0, float(value)))
            else:
                normalized = 0.5
            
            angle = -math.pi / 4 + i * math.pi / 6
            indicator_x = px + math.cos(angle) * 0.8
            indicator_z = pz + math.sin(angle) * 0.8
            
            # Value bar
            vertices.extend([
                indicator_x, py + 0.4, indicator_z,
                indicator_x, py + 0.4 + normalized * 0.4, indicator_z
            ])
            colors.extend([0.8, 0.8, 1.0, 0.7] * 2)
            indices.extend([idx + i*2, idx + i*2 + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=fusion_name,
            albedo=(r, g, b),
            emission=(r * 0.4, g * 0.4, b * 0.4),
            emission_strength=0.5,
            opacity=0.8
        )
        
        fusion_obj = Object3D(
            name=fusion_name,
            mesh=mesh,
            material=material,
            data={"type": "sensor_fusion", "active_sensors": active_sensors, "stability": state_stability}
        )
        
        self.scene.add_object(fusion_obj)
        return fusion_obj

    def create_temporal_pattern_viz(self, embedding: list, matched_pattern: str,
                                     confidence: float, attention_focus: int,
                                     memory_size: int,
                                     position: tuple = (-4.5, 1.5, -4.5)):
        """Visualize temporal pattern learning with attention and memory."""
        temp_name = "temporal_pattern"
        self._remove_old_object(temp_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Pattern type colors
        pattern_colors = {
            'walking': (0.3, 1.0, 0.5),
            'breathing': (0.5, 0.8, 1.0),
            'gesture': (1.0, 0.8, 0.3),
            'ambient': (0.5, 0.5, 0.5),
            'interference': (1.0, 0.4, 0.4),
            'unknown': (0.4, 0.4, 0.6)
        }
        
        r, g, b = pattern_colors.get(matched_pattern, (0.4, 0.4, 0.6))
        
        # Embedding visualization (neural network-like nodes)
        num_nodes = min(len(embedding), 10)
        node_positions = []
        
        for i in range(num_nodes):
            node_x = px + (i % 5) * 0.2 - 0.4
            node_y = py + (i // 5) * 0.3
            node_z = pz
            
            node_positions.append((node_x, node_y, node_z))
            
            # Node size based on embedding value
            node_size = 0.03 + 0.05 * min(1.0, abs(embedding[i]) if i < len(embedding) else 0.1)
            
            idx = len(vertices) // 3
            segments = 8
            for j in range(segments):
                angle1 = 2 * math.pi * j / segments
                angle2 = 2 * math.pi * (j + 1) / segments
                
                vertices.extend([
                    node_x, node_y, node_z,
                    node_x + math.cos(angle1) * node_size, node_y + math.sin(angle1) * node_size, node_z,
                    node_x + math.cos(angle2) * node_size, node_y + math.sin(angle2) * node_size, node_z
                ])
                
                node_alpha = 0.5 + 0.5 * min(1.0, abs(embedding[i]) if i < len(embedding) else 0.3)
                colors.extend([r, g, b, node_alpha] * 3)
                indices.extend([idx + j*3, idx + j*3 + 1, idx + j*3 + 2])
        
        # Connections between nodes (neural network style)
        for i in range(num_nodes - 1):
            if i % 5 < 4:  # Horizontal connections
                idx = len(vertices) // 3
                p1 = node_positions[i]
                p2 = node_positions[i + 1]
                vertices.extend([p1[0], p1[1], p1[2], p2[0], p2[1], p2[2]])
                colors.extend([r * 0.6, g * 0.6, b * 0.6, 0.4] * 2)
                indices.extend([idx, idx + 1])
            
            if i < 5:  # Vertical connections
                idx = len(vertices) // 3
                p1 = node_positions[i]
                p2 = node_positions[min(i + 5, num_nodes - 1)]
                vertices.extend([p1[0], p1[1], p1[2], p2[0], p2[1], p2[2]])
                colors.extend([r * 0.6, g * 0.6, b * 0.6, 0.3] * 2)
                indices.extend([idx, idx + 1])
        
        # Attention focus indicator
        if 0 <= attention_focus < len(node_positions):
            idx = len(vertices) // 3
            ax, ay, az = node_positions[attention_focus]
            
            # Spotlight cone above focused node
            for i in range(12):
                angle1 = 2 * math.pi * i / 12
                angle2 = 2 * math.pi * (i + 1) / 12
                cone_radius = 0.1
                
                vertices.extend([
                    ax, ay + 0.3, az,
                    ax + math.cos(angle1) * cone_radius, ay, az + math.sin(angle1) * cone_radius,
                    ax + math.cos(angle2) * cone_radius, ay, az + math.sin(angle2) * cone_radius
                ])
                colors.extend([1.0, 1.0, 0.5, 0.5] * 3)
                indices.extend([idx + i*3, idx + i*3 + 1, idx + i*3 + 2])
        
        # Memory bank indicator (stacked blocks)
        idx = len(vertices) // 3
        memory_blocks = min(memory_size // 100, 10)
        
        for i in range(memory_blocks):
            block_y = py - 0.5 + i * 0.08
            block_size = 0.15
            
            vertices.extend([
                px + 0.6, block_y, pz,
                px + 0.6 + block_size, block_y, pz,
                px + 0.6 + block_size, block_y + 0.06, pz,
                px + 0.6, block_y + 0.06, pz
            ])
            block_alpha = 0.3 + 0.05 * i
            colors.extend([0.4, 0.6, 0.8, block_alpha] * 4)
            indices.extend([idx + i*4, idx + i*4 + 1, idx + i*4 + 2])
            indices.extend([idx + i*4, idx + i*4 + 2, idx + i*4 + 3])
        
        # Confidence arc
        idx = len(vertices) // 3
        arc_segments = int(16 * confidence)
        arc_radius = 0.5
        
        for i in range(arc_segments):
            angle = math.pi * i / 16 - math.pi / 2
            vertices.extend([
                px + math.cos(angle) * arc_radius, py + 0.6, pz + math.sin(angle) * arc_radius
            ])
            colors.extend([r, g, b, 0.6])
            if i > 0:
                indices.extend([idx + i - 1, idx + i])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=temp_name,
            albedo=(r, g, b),
            emission=(r * 0.4, g * 0.4, b * 0.4),
            emission_strength=0.5,
            opacity=0.8
        )
        
        temp_obj = Object3D(
            name=temp_name,
            mesh=mesh,
            material=material,
            data={"type": "temporal_pattern", "pattern": matched_pattern, "memory": memory_size}
        )
        
        self.scene.add_object(temp_obj)
        return temp_obj

    def create_noise_filter_viz(self, snr_improvement: float, noise_level: float,
                                 wiener_gain: float,
                                 position: tuple = (4.5, 1.5, -4.5)):
        """Visualize adaptive noise filtering status."""
        filter_name = "noise_filter"
        self._remove_old_object(filter_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Color based on SNR improvement
        if snr_improvement > 5:
            r, g, b = 0.3, 1.0, 0.4  # Great improvement
        elif snr_improvement > 0:
            r, g, b = 0.8, 0.9, 0.3  # Good improvement
        else:
            r, g, b = 1.0, 0.5, 0.3  # No improvement
        
        # SNR improvement bar
        idx = len(vertices) // 3
        bar_height = min(1.0, max(0.1, snr_improvement / 10))
        bar_width = 0.15
        
        vertices.extend([
            px, py, pz,
            px + bar_width, py, pz,
            px + bar_width, py + bar_height, pz,
            px, py + bar_height, pz
        ])
        colors.extend([r, g, b, 0.8] * 4)
        indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Noise level indicator (inverted - lower is better)
        idx = len(vertices) // 3
        noise_height = min(1.0, noise_level * 10)
        
        vertices.extend([
            px + 0.25, py, pz,
            px + 0.25 + bar_width, py, pz,
            px + 0.25 + bar_width, py + noise_height, pz,
            px + 0.25, py + noise_height, pz
        ])
        nr, ng, nb = 1.0 - noise_height * 0.5, 0.5, 0.3 + noise_height * 0.5
        colors.extend([nr, ng, nb, 0.7] * 4)
        indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Wiener gain dial
        idx = len(vertices) // 3
        dial_center_x = px - 0.2
        dial_radius = 0.15
        
        # Dial background
        for i in range(16):
            angle1 = 2 * math.pi * i / 16
            angle2 = 2 * math.pi * (i + 1) / 16
            
            vertices.extend([
                dial_center_x, py + 0.3, pz,
                dial_center_x + math.cos(angle1) * dial_radius, py + 0.3, pz + math.sin(angle1) * dial_radius,
                dial_center_x + math.cos(angle2) * dial_radius, py + 0.3, pz + math.sin(angle2) * dial_radius
            ])
            colors.extend([0.3, 0.3, 0.4, 0.5] * 3)
            indices.extend([idx + i*3, idx + i*3 + 1, idx + i*3 + 2])
        
        # Dial needle
        idx = len(vertices) // 3
        needle_angle = math.pi * (1 - wiener_gain)  # 0 = right, 1 = left
        
        vertices.extend([
            dial_center_x, py + 0.3, pz,
            dial_center_x + math.cos(needle_angle) * dial_radius * 0.9,
            py + 0.3,
            pz + math.sin(needle_angle) * dial_radius * 0.9
        ])
        colors.extend([1.0, 0.8, 0.2, 0.9] * 2)
        indices.extend([idx, idx + 1])
        
        # Filter wave effect
        idx = len(vertices) // 3
        wave_segments = 20
        
        for i in range(wave_segments):
            x = px - 0.4 + i * 0.05
            # Noisy input wave
            y_noisy = py - 0.3 + 0.1 * math.sin(i * 0.5) + 0.05 * math.sin(i * 2.3)
            # Filtered output wave
            y_clean = py - 0.3 + 0.1 * math.sin(i * 0.5) * wiener_gain
            
            vertices.extend([x, y_noisy, pz - 0.1])
            colors.extend([0.8, 0.4, 0.4, 0.6])
            
            vertices.extend([x, y_clean, pz + 0.1])
            colors.extend([0.4, 0.8, 0.4, 0.8])
        
        for i in range(wave_segments - 1):
            indices.extend([idx + i*2, idx + (i+1)*2])
            indices.extend([idx + i*2 + 1, idx + (i+1)*2 + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=filter_name,
            albedo=(r, g, b),
            emission=(r * 0.3, g * 0.3, b * 0.3),
            emission_strength=0.4,
            opacity=0.8
        )
        
        filter_obj = Object3D(
            name=filter_name,
            mesh=mesh,
            material=material,
            data={"type": "noise_filter", "snr_improvement": snr_improvement}
        )
        
        self.scene.add_object(filter_obj)
        return filter_obj

    def create_digital_twin_viz(self, entities: list, ray_paths: list,
                                 predicted_csi: np.ndarray,
                                 position: tuple = (0, 0, 0)):
        """Visualize digital twin simulation with ray tracing."""
        twin_name = "digital_twin"
        self._remove_old_object(twin_name)
        
        vertices = []
        colors = []
        indices = []
        
        # Draw entities in digital twin
        for entity in entities:
            ex, ey, ez = entity['position']
            
            # Entity marker (vertical capsule shape)
            idx = len(vertices) // 3
            
            # Body cylinder
            segments = 8
            for i in range(segments):
                angle1 = 2 * math.pi * i / segments
                angle2 = 2 * math.pi * (i + 1) / segments
                radius = 0.15
                
                vertices.extend([
                    ex + math.cos(angle1) * radius, ey, ez + math.sin(angle1) * radius,
                    ex + math.cos(angle2) * radius, ey, ez + math.sin(angle2) * radius,
                    ex + math.cos(angle2) * radius, ey + 0.5, ez + math.sin(angle2) * radius,
                    ex + math.cos(angle1) * radius, ey + 0.5, ez + math.sin(angle1) * radius
                ])
                colors.extend([0.3, 0.7, 1.0, 0.6] * 4)
                indices.extend([idx + i*4, idx + i*4 + 1, idx + i*4 + 2])
                indices.extend([idx + i*4, idx + i*4 + 2, idx + i*4 + 3])
            
            # Trajectory trail
            if 'trajectory' in entity and len(entity['trajectory']) > 1:
                idx = len(vertices) // 3
                for i, pos in enumerate(entity['trajectory'][-20:]):
                    tx, ty, tz = pos
                    alpha = 0.1 + 0.4 * (i / 20)
                    vertices.extend([tx, ty + 0.1, tz])
                    colors.extend([0.5, 0.8, 1.0, alpha])
                
                for i in range(len(entity['trajectory'][-20:]) - 1):
                    indices.extend([idx + i, idx + i + 1])
        
        # Draw ray paths
        for path in ray_paths[:10]:  # Limit to 10 paths
            if 'points' not in path:
                continue
            
            points = path['points']
            power = path.get('power', 0.5)
            
            idx = len(vertices) // 3
            
            for point in points:
                px, py_pt, pz_pt = point
                vertices.extend([px, py_pt + 0.5, pz_pt])
                # Color based on power (red = weak, green = strong)
                ray_r = 1.0 - power
                ray_g = power
                colors.extend([ray_r, ray_g, 0.3, 0.4 * power])
            
            for i in range(len(points) - 1):
                indices.extend([idx + i, idx + i + 1])
        
        # Predicted CSI spectrum
        if len(predicted_csi) > 0:
            idx = len(vertices) // 3
            spectrum_width = 2.0
            
            for i, val in enumerate(predicted_csi):
                x = -4.0 + (i / len(predicted_csi)) * spectrum_width
                normalized = min(1.0, val / (np.max(predicted_csi) + 1e-8))
                y = -0.5 + normalized * 0.5
                
                vertices.extend([x, y, -4.0])
                colors.extend([0.8, 0.6, 1.0, 0.7])
            
            for i in range(len(predicted_csi) - 1):
                indices.extend([idx + i, idx + i + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=twin_name,
            albedo=(0.4, 0.7, 1.0),
            emission=(0.2, 0.4, 0.6),
            emission_strength=0.4,
            opacity=0.7
        )
        
        twin_obj = Object3D(
            name=twin_name,
            mesh=mesh,
            material=material,
            data={"type": "digital_twin", "num_entities": len(entities)}
        )
        
        self.scene.add_object(twin_obj)
        return twin_obj

    def create_multipath_viz(self, num_paths: int, paths: list,
                              static_count: int, dynamic_count: int,
                              richness: float,
                              position: tuple = (-4.5, 2.0, 4.5)):
        """Visualize multi-path propagation analysis."""
        mp_name = "multipath_analysis"
        self._remove_old_object(mp_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Central hub (receiver)
        idx = len(vertices) // 3
        hub_radius = 0.12
        
        for i in range(12):
            angle1 = 2 * math.pi * i / 12
            angle2 = 2 * math.pi * (i + 1) / 12
            
            vertices.extend([
                px, py, pz,
                px + math.cos(angle1) * hub_radius, py, pz + math.sin(angle1) * hub_radius,
                px + math.cos(angle2) * hub_radius, py, pz + math.sin(angle2) * hub_radius
            ])
            colors.extend([0.8, 0.8, 1.0, 0.9] * 3)
            indices.extend([idx + i*3, idx + i*3 + 1, idx + i*3 + 2])
        
        # Path rays emanating from hub
        for i, path_info in enumerate(paths):
            idx = len(vertices) // 3
            angle = 2 * math.pi * i / max(len(paths), 1)
            
            strength = path_info.get('strength', 0.5)
            is_dynamic = path_info.get('is_dynamic', False)
            doppler = path_info.get('doppler', 0)
            
            # Path color: static = blue, dynamic = green/red based on Doppler
            if is_dynamic:
                if doppler > 0:
                    pr, pg, pb = 0.3, 1.0, 0.4  # Moving toward
                else:
                    pr, pg, pb = 1.0, 0.6, 0.3  # Moving away
            else:
                pr, pg, pb = 0.4, 0.6, 1.0  # Static
            
            # Ray length based on strength
            ray_length = 0.3 + 0.5 * strength
            
            # Main ray
            vertices.extend([
                px, py, pz,
                px + math.cos(angle) * ray_length, py, pz + math.sin(angle) * ray_length
            ])
            colors.extend([pr, pg, pb, 0.8] * 2)
            indices.extend([idx, idx + 1])
            
            # Strength indicator ring at end
            idx = len(vertices) // 3
            end_x = px + math.cos(angle) * ray_length
            end_z = pz + math.sin(angle) * ray_length
            ring_radius = 0.05 * (1 + strength)
            
            for j in range(8):
                a1 = 2 * math.pi * j / 8
                a2 = 2 * math.pi * (j + 1) / 8
                
                vertices.extend([
                    end_x, py, end_z,
                    end_x + math.cos(a1) * ring_radius, py, end_z + math.sin(a1) * ring_radius,
                    end_x + math.cos(a2) * ring_radius, py, end_z + math.sin(a2) * ring_radius
                ])
                colors.extend([pr, pg, pb, 0.7] * 3)
                indices.extend([idx + j*3, idx + j*3 + 1, idx + j*3 + 2])
            
            # Doppler wave effect for dynamic paths
            if is_dynamic:
                idx = len(vertices) // 3
                wave_count = 3
                for w in range(wave_count):
                    wave_offset = 0.1 + w * 0.08
                    wave_radius = 0.03 - w * 0.005
                    wave_pos = 0.3 + wave_offset
                    
                    wx = px + math.cos(angle) * wave_pos
                    wz = pz + math.sin(angle) * wave_pos
                    
                    vertices.extend([
                        wx - wave_radius, py + 0.02, wz,
                        wx + wave_radius, py + 0.02, wz
                    ])
                    wave_alpha = 0.5 - w * 0.1
                    colors.extend([pr, pg, pb, wave_alpha] * 2)
                    indices.extend([idx + w*2, idx + w*2 + 1])
        
        # Richness indicator (arc around hub)
        idx = len(vertices) // 3
        richness_segments = int(24 * richness)
        richness_radius = 0.25
        
        for i in range(richness_segments):
            angle = 2 * math.pi * i / 24
            vertices.extend([
                px + math.cos(angle) * richness_radius, py + 0.2, pz + math.sin(angle) * richness_radius
            ])
            # Color gradient from blue (low) to green (high richness)
            rich_r = 0.3
            rich_g = 0.4 + 0.6 * richness
            rich_b = 1.0 - 0.5 * richness
            colors.extend([rich_r, rich_g, rich_b, 0.6])
            if i > 0:
                indices.extend([idx + i - 1, idx + i])
        
        # Path count indicators
        idx = len(vertices) // 3
        
        # Static paths (blue bars)
        for i in range(min(static_count, 5)):
            bar_x = px + 0.4 + i * 0.08
            vertices.extend([
                bar_x, py - 0.3, pz,
                bar_x + 0.05, py - 0.3, pz,
                bar_x + 0.05, py - 0.1, pz,
                bar_x, py - 0.1, pz
            ])
            colors.extend([0.4, 0.6, 1.0, 0.7] * 4)
            indices.extend([idx + i*4, idx + i*4 + 1, idx + i*4 + 2])
            indices.extend([idx + i*4, idx + i*4 + 2, idx + i*4 + 3])
        
        # Dynamic paths (green bars)
        idx = len(vertices) // 3
        for i in range(min(dynamic_count, 5)):
            bar_x = px + 0.4 + i * 0.08
            vertices.extend([
                bar_x, py - 0.5, pz,
                bar_x + 0.05, py - 0.5, pz,
                bar_x + 0.05, py - 0.35, pz,
                bar_x, py - 0.35, pz
            ])
            colors.extend([0.3, 1.0, 0.5, 0.7] * 4)
            indices.extend([idx + i*4, idx + i*4 + 1, idx + i*4 + 2])
            indices.extend([idx + i*4, idx + i*4 + 2, idx + i*4 + 3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=mp_name,
            albedo=(0.5, 0.7, 0.9),
            emission=(0.3, 0.4, 0.6),
            emission_strength=0.4,
            opacity=0.8
        )
        
        mp_obj = Object3D(
            name=mp_name,
            mesh=mesh,
            material=material,
            data={"type": "multipath", "num_paths": num_paths, "richness": richness}
        )
        
        self.scene.add_object(mp_obj)
        return mp_obj

    def create_subspace_tracking_viz(self, targets: list, num_targets: int,
                                      signal_rank: int, noise_floor: float,
                                      position: tuple = (0, 2.5, 0)):
        """Visualize ESPRIT-based subspace target tracking."""
        track_name = "subspace_tracking"
        self._remove_old_object(track_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Central radar display (circular)
        idx = len(vertices) // 3
        radar_radius = 1.0
        
        for i in range(32):
            angle1 = 2 * math.pi * i / 32
            angle2 = 2 * math.pi * (i + 1) / 32
            
            vertices.extend([
                px, py, pz,
                px + math.cos(angle1) * radar_radius, py, pz + math.sin(angle1) * radar_radius,
                px + math.cos(angle2) * radar_radius, py, pz + math.sin(angle2) * radar_radius
            ])
            colors.extend([0.1, 0.2, 0.3, 0.6] * 3)
            indices.extend([idx + i*3, idx + i*3 + 1, idx + i*3 + 2])
        
        # Range rings
        for ring_idx, ring_radius in enumerate([0.3, 0.6, 0.9]):
            idx = len(vertices) // 3
            for i in range(24):
                angle = 2 * math.pi * i / 24
                vertices.extend([
                    px + math.cos(angle) * ring_radius, py + 0.01, pz + math.sin(angle) * ring_radius
                ])
                colors.extend([0.3, 0.5, 0.7, 0.4])
                if i > 0:
                    indices.extend([idx + i - 1, idx + i])
            indices.extend([idx + 23, idx])
        
        # Sweep line
        idx = len(vertices) // 3
        import time
        sweep_angle = (time.time() * 0.5) % (2 * math.pi)
        vertices.extend([
            px, py + 0.02, pz,
            px + math.cos(sweep_angle) * radar_radius, py + 0.02, pz + math.sin(sweep_angle) * radar_radius
        ])
        colors.extend([0.3, 1.0, 0.5, 0.8] * 2)
        indices.extend([idx, idx + 1])
        
        # Target markers
        for target in targets:
            idx = len(vertices) // 3
            
            # Convert angle to position on radar
            angle_rad = math.radians(target['angle'])
            confidence = target.get('confidence', 0.5)
            
            # Target position (angle determines direction, confidence determines distance)
            tx = px + math.cos(angle_rad + math.pi/2) * radar_radius * 0.8
            tz = pz + math.sin(angle_rad + math.pi/2) * radar_radius * 0.8
            
            # Target color based on velocity
            velocity = target.get('velocity', 0)
            if velocity > 0:
                tr, tg, tb = 0.3, 1.0, 0.4  # Approaching
            elif velocity < 0:
                tr, tg, tb = 1.0, 0.5, 0.3  # Receding
            else:
                tr, tg, tb = 0.5, 0.8, 1.0  # Stationary
            
            # Target diamond shape
            target_size = 0.08 * (0.5 + confidence)
            vertices.extend([
                tx, py + 0.05, tz - target_size,
                tx + target_size, py + 0.05, tz,
                tx, py + 0.05, tz + target_size,
                tx - target_size, py + 0.05, tz
            ])
            colors.extend([tr, tg, tb, 0.9] * 4)
            indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
            
            # Direction indicator
            if abs(velocity) > 0.1:
                idx = len(vertices) // 3
                arrow_length = 0.15 * abs(velocity)
                arrow_dir = 1 if velocity > 0 else -1
                
                vertices.extend([
                    tx, py + 0.05, tz,
                    tx + arrow_dir * arrow_length * math.cos(angle_rad + math.pi/2),
                    py + 0.05,
                    tz + arrow_dir * arrow_length * math.sin(angle_rad + math.pi/2)
                ])
                colors.extend([tr, tg, tb, 0.7] * 2)
                indices.extend([idx, idx + 1])
        
        # Signal rank indicator
        idx = len(vertices) // 3
        for i in range(min(signal_rank, 10)):
            rank_x = px + 1.2
            rank_y = py - 0.4 + i * 0.1
            
            vertices.extend([
                rank_x, rank_y, pz,
                rank_x + 0.08, rank_y, pz,
                rank_x + 0.08, rank_y + 0.08, pz,
                rank_x, rank_y + 0.08, pz
            ])
            rank_alpha = 0.4 + 0.4 * (1 - i / 10)
            colors.extend([0.5, 0.8, 1.0, rank_alpha] * 4)
            indices.extend([idx + i*4, idx + i*4 + 1, idx + i*4 + 2])
            indices.extend([idx + i*4, idx + i*4 + 2, idx + i*4 + 3])
        
        # Noise floor indicator
        idx = len(vertices) // 3
        noise_height = min(0.5, noise_floor * 10)
        vertices.extend([
            px - 1.2, py - 0.4, pz,
            px - 1.1, py - 0.4, pz,
            px - 1.1, py - 0.4 + noise_height, pz,
            px - 1.2, py - 0.4 + noise_height, pz
        ])
        noise_color = (1.0 - noise_height, 0.5 + noise_height * 0.5, 0.3)
        colors.extend([noise_color[0], noise_color[1], noise_color[2], 0.7] * 4)
        indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=track_name,
            albedo=(0.3, 0.6, 0.8),
            emission=(0.2, 0.4, 0.5),
            emission_strength=0.4,
            opacity=0.8
        )
        
        track_obj = Object3D(
            name=track_name,
            mesh=mesh,
            material=material,
            data={"type": "subspace_tracking", "num_targets": num_targets}
        )
        
        self.scene.add_object(track_obj)
        return track_obj

    def create_waveform_viz(self, waveform_type: str, range_resolution: float,
                             velocity_resolution: float, bandwidth: float,
                             position: tuple = (-4.5, 1.0, 0)):
        """Visualize optimized sensing waveform characteristics."""
        wave_name = "waveform_viz"
        self._remove_old_object(wave_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Waveform type colors
        waveform_colors = {
            'chirp': (0.3, 0.8, 1.0),
            'stepped_freq': (1.0, 0.8, 0.3),
            'doppler_optimized': (0.8, 0.5, 1.0),
            'pulse': (1.0, 0.5, 0.5),
            'ofdm': (0.5, 1.0, 0.5),
            'barker': (0.8, 0.8, 0.3)
        }
        
        r, g, b = waveform_colors.get(waveform_type, (0.5, 0.5, 0.5))
        
        # Waveform display (time domain)
        idx = len(vertices) // 3
        num_samples = 50
        waveform_width = 1.0
        
        for i in range(num_samples):
            t_norm = i / num_samples
            x = px + t_norm * waveform_width
            
            # Generate sample waveform shape
            if waveform_type == 'chirp':
                y = py + 0.2 * math.sin(2 * math.pi * t_norm * (1 + t_norm * 5))
            elif waveform_type == 'stepped_freq':
                step = int(t_norm * 5)
                y = py + 0.2 * math.sin(2 * math.pi * t_norm * (step + 1))
            elif waveform_type == 'pulse':
                y = py + 0.2 if t_norm < 0.1 else py
            else:
                y = py + 0.2 * math.sin(2 * math.pi * t_norm * 3)
            
            vertices.extend([x, y, pz])
            colors.extend([r, g, b, 0.9])
        
        for i in range(num_samples - 1):
            indices.extend([idx + i, idx + i + 1])
        
        # Ambiguity function representation (2D grid)
        idx = len(vertices) // 3
        grid_size = 10
        grid_spacing = 0.08
        
        for i in range(grid_size):
            for j in range(grid_size):
                gx = px + 0.2 + i * grid_spacing
                gz = pz + 0.3 + j * grid_spacing
                
                # Height based on simplified ambiguity (diagonal ridge for chirp)
                if waveform_type == 'chirp':
                    height = 0.15 * math.exp(-((i - j)**2) / 5)
                elif waveform_type == 'pulse':
                    height = 0.15 * math.exp(-(i**2 + j**2) / 10)
                else:
                    height = 0.1 * math.exp(-((i - grid_size/2)**2 + (j - grid_size/2)**2) / 8)
                
                vertices.extend([gx, py - 0.3 + height, gz])
                colors.extend([r * height * 5, g * height * 5, b * height * 5, 0.6])
        
        # Connect grid points
        for i in range(grid_size):
            for j in range(grid_size):
                current = idx + i * grid_size + j
                if j < grid_size - 1:
                    indices.extend([current, current + 1])
                if i < grid_size - 1:
                    indices.extend([current, current + grid_size])
        
        # Resolution indicators
        idx = len(vertices) // 3
        
        # Range resolution bar
        range_bar_width = min(0.5, 0.1 / (range_resolution + 0.01))
        vertices.extend([
            px - 0.3, py + 0.4, pz,
            px - 0.3 + range_bar_width, py + 0.4, pz,
            px - 0.3 + range_bar_width, py + 0.5, pz,
            px - 0.3, py + 0.5, pz
        ])
        colors.extend([0.3, 1.0, 0.5, 0.8] * 4)
        indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Velocity resolution bar
        idx = len(vertices) // 3
        vel_bar_width = min(0.5, velocity_resolution / 100)
        vertices.extend([
            px - 0.3, py + 0.55, pz,
            px - 0.3 + vel_bar_width, py + 0.55, pz,
            px - 0.3 + vel_bar_width, py + 0.65, pz,
            px - 0.3, py + 0.65, pz
        ])
        colors.extend([1.0, 0.6, 0.3, 0.8] * 4)
        indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Bandwidth indicator (arc)
        idx = len(vertices) // 3
        bw_segments = int(min(24, bandwidth / 50))
        arc_radius = 0.25
        
        for i in range(bw_segments):
            angle = math.pi * i / 24 - math.pi / 2
            vertices.extend([
                px + 0.8 + math.cos(angle) * arc_radius,
                py + 0.5,
                pz + math.sin(angle) * arc_radius
            ])
            colors.extend([r, g, b, 0.7])
            if i > 0:
                indices.extend([idx + i - 1, idx + i])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=wave_name,
            albedo=(r, g, b),
            emission=(r * 0.3, g * 0.3, b * 0.3),
            emission_strength=0.4,
            opacity=0.8
        )
        
        wave_obj = Object3D(
            name=wave_name,
            mesh=mesh,
            material=material,
            data={"type": "waveform", "waveform_type": waveform_type}
        )
        
        self.scene.add_object(wave_obj)
        return wave_obj

    def create_reconstruction_viz(self, quality: float, sparsity: float,
                                   dominant_components: int, features: list,
                                   position: tuple = (4.5, 1.0, 0)):
        """Visualize neural network signal reconstruction quality."""
        recon_name = "reconstruction_viz"
        self._remove_old_object(recon_name)
        
        vertices = []
        colors = []
        indices = []
        
        px, py, pz = position
        
        # Quality-based color
        if quality > 0.8:
            r, g, b = 0.3, 1.0, 0.4
        elif quality > 0.5:
            r, g, b = 1.0, 0.9, 0.3
        else:
            r, g, b = 1.0, 0.5, 0.3
        
        # Neural network layer visualization
        layer_sizes = [10, 8, 6, 4]  # Representing network layers
        layer_spacing = 0.25
        
        for layer_idx, num_nodes in enumerate(layer_sizes):
            for node_idx in range(num_nodes):
                idx = len(vertices) // 3
                
                nx = px + layer_idx * layer_spacing
                ny = py + (node_idx - num_nodes / 2) * 0.1
                
                # Node circle
                node_radius = 0.03
                for i in range(8):
                    angle1 = 2 * math.pi * i / 8
                    angle2 = 2 * math.pi * (i + 1) / 8
                    
                    vertices.extend([
                        nx, ny, pz,
                        nx + math.cos(angle1) * node_radius, ny + math.sin(angle1) * node_radius, pz,
                        nx + math.cos(angle2) * node_radius, ny + math.sin(angle2) * node_radius, pz
                    ])
                    
                    # Activation color
                    if layer_idx < len(features) and node_idx < len(features):
                        activation = min(1.0, abs(features[node_idx]) if node_idx < len(features) else 0.3)
                    else:
                        activation = 0.3
                    
                    colors.extend([r * activation, g * activation, b * activation, 0.8] * 3)
                    indices.extend([idx + i*3, idx + i*3 + 1, idx + i*3 + 2])
                
                # Connections to next layer
                if layer_idx < len(layer_sizes) - 1:
                    next_nodes = layer_sizes[layer_idx + 1]
                    for next_node in range(min(3, next_nodes)):  # Limit connections for clarity
                        idx = len(vertices) // 3
                        next_ny = py + (next_node - next_nodes / 2) * 0.1
                        
                        vertices.extend([
                            nx + node_radius, ny, pz,
                            px + (layer_idx + 1) * layer_spacing - node_radius, next_ny, pz
                        ])
                        colors.extend([r * 0.5, g * 0.5, b * 0.5, 0.3] * 2)
                        indices.extend([idx, idx + 1])
        
        # Quality meter
        idx = len(vertices) // 3
        meter_height = quality * 0.6
        vertices.extend([
            px - 0.2, py - 0.4, pz,
            px - 0.1, py - 0.4, pz,
            px - 0.1, py - 0.4 + meter_height, pz,
            px - 0.2, py - 0.4 + meter_height, pz
        ])
        colors.extend([r, g, b, 0.9] * 4)
        indices.extend([idx, idx+1, idx+2, idx, idx+2, idx+3])
        
        # Sparsity indicator (dots)
        idx = len(vertices) // 3
        num_dots = int(sparsity * 20)
        
        for i in range(num_dots):
            dot_x = px + 1.0 + (i % 5) * 0.06
            dot_y = py - 0.4 + (i // 5) * 0.06
            
            vertices.extend([
                dot_x, dot_y, pz,
                dot_x + 0.02, dot_y, pz,
                dot_x + 0.02, dot_y + 0.02, pz,
                dot_x, dot_y + 0.02, pz
            ])
            colors.extend([0.8, 0.6, 1.0, 0.7] * 4)
            indices.extend([idx + i*4, idx + i*4 + 1, idx + i*4 + 2])
            indices.extend([idx + i*4, idx + i*4 + 2, idx + i*4 + 3])
        
        # Dominant components indicator
        idx = len(vertices) // 3
        for i in range(min(dominant_components, 8)):
            comp_height = 0.3 * (1 - i * 0.1)
            comp_x = px + 0.8 + i * 0.08
            
            vertices.extend([
                comp_x, py + 0.3, pz,
                comp_x + 0.05, py + 0.3, pz,
                comp_x + 0.05, py + 0.3 + comp_height, pz,
                comp_x, py + 0.3 + comp_height, pz
            ])
            colors.extend([0.5, 0.8, 1.0, 0.7] * 4)
            indices.extend([idx + i*4, idx + i*4 + 1, idx + i*4 + 2])
            indices.extend([idx + i*4, idx + i*4 + 2, idx + i*4 + 3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            colors=np.array(colors, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name=recon_name,
            albedo=(r, g, b),
            emission=(r * 0.4, g * 0.4, b * 0.4),
            emission_strength=0.5,
            opacity=0.8
        )
        
        recon_obj = Object3D(
            name=recon_name,
            mesh=mesh,
            material=material,
            data={"type": "reconstruction", "quality": quality}
        )
        
        self.scene.add_object(recon_obj)
        return recon_obj
    
    def create_scene_graph_viz(self, nodes: list, edges: list, confidence: float = 0.8) -> 'Object3D':
        """Create semantic scene graph visualization with nodes and connections."""
        import numpy as np
        
        # Create graph structure
        vertices = []
        indices = []
        colors = []
        
        # Node type colors
        node_colors = {
            'person': (0.2, 0.7, 1.0),
            'object': (0.7, 0.5, 0.2),
            'furniture': (0.5, 0.3, 0.1),
            'zone': (0.3, 0.8, 0.3),
            'activity': (1.0, 0.6, 0.2),
            'unknown': (0.5, 0.5, 0.5)
        }
        
        # Create node spheres
        for i, node in enumerate(nodes[:50]):  # Limit to 50 nodes
            node_type = node.get('type', 'unknown')
            position = node.get('position', [0, 0, 0])
            importance = node.get('importance', 0.5)
            
            color = node_colors.get(node_type, (0.5, 0.5, 0.5))
            radius = 0.1 + importance * 0.15
            
            # Generate sphere vertices
            u_steps = 12
            v_steps = 8
            for u in range(u_steps):
                for v in range(v_steps):
                    theta1 = 2 * np.pi * u / u_steps
                    theta2 = 2 * np.pi * (u + 1) / u_steps
                    phi1 = np.pi * v / v_steps
                    phi2 = np.pi * (v + 1) / v_steps
                    
                    base_idx = len(vertices) // 6
                    
                    # Vertices
                    for theta in [theta1, theta2]:
                        for phi in [phi1, phi2]:
                            x = position[0] + radius * np.sin(phi) * np.cos(theta)
                            y = position[1] + radius * np.sin(phi) * np.sin(theta)
                            z = position[2] + radius * np.cos(phi)
                            vertices.extend([x, y, z])
                            colors.extend([color[0], color[1], color[2]])
                    
                    indices.extend([base_idx, base_idx + 1, base_idx + 2])
                    indices.extend([base_idx + 1, base_idx + 3, base_idx + 2])
        
        # Create edge lines
        for edge in edges[:100]:  # Limit edges
            source_idx = edge.get('source', 0)
            target_idx = edge.get('target', 1)
            relation = edge.get('relation', 'connected')
            weight = edge.get('weight', 0.5)
            
            if source_idx < len(nodes) and target_idx < len(nodes):
                p1 = nodes[source_idx].get('position', [0, 0, 0])
                p2 = nodes[target_idx].get('position', [0, 0, 0])
                
                # Create tube for edge
                edge_color = (0.8 * weight, 0.8 * weight, 1.0 * weight)
                num_segments = 8
                tube_radius = 0.02 + weight * 0.02
                
                direction = np.array(p2) - np.array(p1)
                length = np.linalg.norm(direction)
                if length > 0.01:
                    direction = direction / length
                    
                    # Create perpendicular vectors
                    perp1 = np.cross(direction, [0, 0, 1])
                    if np.linalg.norm(perp1) < 0.01:
                        perp1 = np.cross(direction, [0, 1, 0])
                    perp1 = perp1 / np.linalg.norm(perp1)
                    perp2 = np.cross(direction, perp1)
                    
                    for t in range(10):
                        t_ratio = t / 9
                        center = np.array(p1) + direction * length * t_ratio
                        
                        for s in range(num_segments):
                            angle = 2 * np.pi * s / num_segments
                            offset = perp1 * np.cos(angle) + perp2 * np.sin(angle)
                            point = center + offset * tube_radius
                            
                            vertices.extend([point[0], point[1], point[2]])
                            colors.extend([edge_color[0], edge_color[1], edge_color[2]])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.6, 0.6, 0.8),
            emissive=(0.1, 0.1, 0.2),
            metallic=0.3,
            roughness=0.6
        )
        
        graph_obj = Object3D(
            name="scene_graph",
            position=(0, 0, 0),
            mesh=mesh,
            material=material,
            data={"type": "scene_graph", "node_count": len(nodes), "edge_count": len(edges), "confidence": confidence}
        )
        
        self.scene.add_object(graph_obj)
        return graph_obj
    
    def create_forecast_viz(self, predictions: dict, probability: float = 0.7, horizon: float = 300.0) -> 'Object3D':
        """Create activity forecast visualization with timeline and predictions."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Activity colors
        activity_colors = {
            'walking': (0.2, 0.8, 0.3),
            'sitting': (0.3, 0.5, 0.8),
            'standing': (0.8, 0.7, 0.2),
            'sleeping': (0.4, 0.3, 0.6),
            'exercising': (1.0, 0.4, 0.2),
            'cooking': (0.9, 0.5, 0.1),
            'working': (0.5, 0.5, 0.7),
            'absent': (0.3, 0.3, 0.3),
            'unknown': (0.5, 0.5, 0.5)
        }
        
        # Create timeline base
        timeline_length = 5.0
        timeline_width = 0.5
        
        # Base platform vertices
        base_vertices = [
            [-timeline_length/2, -timeline_width/2, 0],
            [timeline_length/2, -timeline_width/2, 0],
            [timeline_length/2, timeline_width/2, 0],
            [-timeline_length/2, timeline_width/2, 0]
        ]
        
        for v in base_vertices:
            vertices.extend(v)
            colors.extend([0.2, 0.2, 0.3])
        
        indices.extend([0, 1, 2, 0, 2, 3])
        
        # Create prediction bars
        timeline_slots = predictions.get('timeline', [])
        num_slots = len(timeline_slots) if timeline_slots else 10
        slot_width = timeline_length / max(num_slots, 1)
        
        for i, slot in enumerate(timeline_slots[:20]):  # Limit to 20 slots
            activity = slot.get('activity', 'unknown')
            prob = slot.get('probability', 0.5)
            time_offset = slot.get('time_offset', i * 30)
            
            color = activity_colors.get(activity, (0.5, 0.5, 0.5))
            bar_height = 0.5 + prob * 1.5
            
            x_start = -timeline_length/2 + i * slot_width
            x_end = x_start + slot_width * 0.9
            
            base_idx = len(vertices) // 3
            
            # Create bar
            bar_verts = [
                [x_start, -timeline_width/4, 0],
                [x_end, -timeline_width/4, 0],
                [x_end, timeline_width/4, 0],
                [x_start, timeline_width/4, 0],
                [x_start, -timeline_width/4, bar_height],
                [x_end, -timeline_width/4, bar_height],
                [x_end, timeline_width/4, bar_height],
                [x_start, timeline_width/4, bar_height]
            ]
            
            for v in bar_verts:
                vertices.extend(v)
                intensity = 0.5 + prob * 0.5
                colors.extend([color[0] * intensity, color[1] * intensity, color[2] * intensity])
            
            # Box indices
            box_indices = [
                [0, 1, 5], [0, 5, 4],  # Front
                [2, 3, 7], [2, 7, 6],  # Back
                [0, 3, 7], [0, 7, 4],  # Left
                [1, 2, 6], [1, 6, 5],  # Right
                [4, 5, 6], [4, 6, 7]   # Top
            ]
            
            for tri in box_indices:
                indices.extend([base_idx + t for t in tri])
        
        # Create probability confidence arc
        arc_radius = 1.0
        arc_segments = 32
        arc_angle = probability * np.pi
        
        for i in range(arc_segments):
            angle = -np.pi/2 + arc_angle * i / arc_segments
            x = arc_radius * np.cos(angle)
            z = arc_radius * np.sin(angle) + 2.5
            vertices.extend([x, 0, z])
            
            t = i / arc_segments
            colors.extend([1.0 - t, t, 0.5])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.6, 0.8),
            emissive=(0.1, 0.15, 0.2),
            metallic=0.2,
            roughness=0.5
        )
        
        forecast_obj = Object3D(
            name="activity_forecast",
            position=(0, 0, 2),
            mesh=mesh,
            material=material,
            data={"type": "forecast", "probability": probability, "horizon_sec": horizon}
        )
        
        self.scene.add_object(forecast_obj)
        return forecast_obj
    
    def create_privacy_viz(self, privacy_level: float = 0.8, anonymized_count: int = 0, protection_type: str = "differential") -> 'Object3D':
        """Create privacy shield visualization showing anonymization status."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Privacy shield dome
        dome_radius = 2.0
        dome_segments_u = 32
        dome_segments_v = 16
        
        # Color based on privacy level
        if privacy_level > 0.8:
            base_color = (0.2, 0.9, 0.3)  # Green - high privacy
        elif privacy_level > 0.5:
            base_color = (0.9, 0.8, 0.2)  # Yellow - medium privacy
        else:
            base_color = (0.9, 0.3, 0.2)  # Red - low privacy
        
        # Create dome vertices
        for u in range(dome_segments_u + 1):
            for v in range(dome_segments_v + 1):
                theta = 2 * np.pi * u / dome_segments_u
                phi = np.pi * v / (2 * dome_segments_v)  # Half sphere
                
                x = dome_radius * np.sin(phi) * np.cos(theta)
                y = dome_radius * np.sin(phi) * np.sin(theta)
                z = dome_radius * np.cos(phi)
                
                # Add noise pattern for shield effect
                noise = np.sin(theta * 8 + phi * 4) * 0.05
                
                vertices.extend([x * (1 + noise), y * (1 + noise), z])
                
                # Transparency effect via color alpha simulation
                alpha = 0.3 + privacy_level * 0.4
                colors.extend([
                    base_color[0] * alpha,
                    base_color[1] * alpha,
                    base_color[2] * alpha
                ])
        
        # Create indices for dome
        for u in range(dome_segments_u):
            for v in range(dome_segments_v):
                idx0 = u * (dome_segments_v + 1) + v
                idx1 = idx0 + 1
                idx2 = idx0 + dome_segments_v + 1
                idx3 = idx2 + 1
                
                indices.extend([idx0, idx1, idx2])
                indices.extend([idx1, idx3, idx2])
        
        # Add privacy level indicator ring
        ring_base_idx = len(vertices) // 3
        ring_segments = 64
        ring_radius = dome_radius * 1.1
        ring_height = 0.1
        
        filled_segments = int(ring_segments * privacy_level)
        
        for i in range(ring_segments):
            angle = 2 * np.pi * i / ring_segments
            
            x_inner = ring_radius * 0.95 * np.cos(angle)
            y_inner = ring_radius * 0.95 * np.sin(angle)
            x_outer = ring_radius * np.cos(angle)
            y_outer = ring_radius * np.sin(angle)
            
            vertices.extend([x_inner, y_inner, ring_height])
            vertices.extend([x_outer, y_outer, ring_height])
            
            if i < filled_segments:
                ring_color = base_color
            else:
                ring_color = (0.2, 0.2, 0.2)
            
            colors.extend([ring_color[0], ring_color[1], ring_color[2]])
            colors.extend([ring_color[0], ring_color[1], ring_color[2]])
        
        # Ring indices
        for i in range(ring_segments):
            idx0 = ring_base_idx + i * 2
            idx1 = idx0 + 1
            idx2 = ring_base_idx + ((i + 1) % ring_segments) * 2
            idx3 = idx2 + 1
            
            indices.extend([idx0, idx1, idx3])
            indices.extend([idx0, idx3, idx2])
        
        # Add anonymization counter display
        if anonymized_count > 0:
            counter_z = dome_radius * 0.8
            # Simple geometric counter indicator
            for i in range(min(anonymized_count, 10)):
                angle = 2 * np.pi * i / min(anonymized_count, 10)
                cx = 0.5 * np.cos(angle)
                cy = 0.5 * np.sin(angle)
                
                for j in range(6):
                    a = 2 * np.pi * j / 6
                    vertices.extend([cx + 0.05 * np.cos(a), cy + 0.05 * np.sin(a), counter_z])
                    colors.extend([0.8, 0.8, 1.0])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=base_color,
            emissive=(base_color[0] * 0.2, base_color[1] * 0.2, base_color[2] * 0.2),
            metallic=0.1,
            roughness=0.3,
            opacity=0.6
        )
        
        privacy_obj = Object3D(
            name="privacy_shield",
            position=(0, 0, 0),
            mesh=mesh,
            material=material,
            data={"type": "privacy", "level": privacy_level, "anonymized": anonymized_count, "protection": protection_type}
        )
        
        self.scene.add_object(privacy_obj)
        return privacy_obj
    
    def create_semantic_viz(self, segments: dict, dominant_class: str = "empty", coverage: float = 0.5) -> 'Object3D':
        """Create semantic segmentation visualization with classified spatial regions."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Semantic class colors
        class_colors = {
            'empty': (0.2, 0.2, 0.2),
            'wall': (0.5, 0.4, 0.3),
            'floor': (0.4, 0.35, 0.3),
            'furniture': (0.6, 0.4, 0.2),
            'person': (0.2, 0.7, 1.0),
            'door': (0.7, 0.5, 0.3),
            'window': (0.3, 0.6, 0.9),
            'appliance': (0.5, 0.5, 0.6),
            'obstacle': (0.8, 0.3, 0.3),
            'pathway': (0.3, 0.8, 0.4)
        }
        
        # Create segmented voxel grid
        grid = segments.get('grid', [])
        grid_size = segments.get('size', (10, 10, 5))
        voxel_size = 0.3
        
        if not grid:
            # Generate demo grid if empty
            grid = []
            for x in range(grid_size[0]):
                for y in range(grid_size[1]):
                    for z in range(grid_size[2]):
                        # Random class assignment for demo
                        classes = list(class_colors.keys())
                        idx = int((x * 7 + y * 13 + z * 23) % len(classes))
                        prob = 0.3 + 0.6 * abs(np.sin(x * 0.5 + y * 0.7 + z * 0.3))
                        if prob > 0.5:  # Only show confident segments
                            grid.append({
                                'position': [x, y, z],
                                'class': classes[idx],
                                'confidence': prob
                            })
        
        # Create voxels for each segment
        for voxel in grid[:500]:  # Limit voxels
            pos = voxel.get('position', [0, 0, 0])
            seg_class = voxel.get('class', 'empty')
            confidence = voxel.get('confidence', 0.5)
            
            if confidence < 0.4:
                continue  # Skip low confidence
            
            color = class_colors.get(seg_class, (0.5, 0.5, 0.5))
            
            # Voxel center
            cx = (pos[0] - grid_size[0]/2) * voxel_size
            cy = (pos[1] - grid_size[1]/2) * voxel_size
            cz = pos[2] * voxel_size
            
            half = voxel_size * 0.45 * confidence  # Size by confidence
            
            base_idx = len(vertices) // 3
            
            # Voxel vertices (cube)
            cube_verts = [
                [cx - half, cy - half, cz - half],
                [cx + half, cy - half, cz - half],
                [cx + half, cy + half, cz - half],
                [cx - half, cy + half, cz - half],
                [cx - half, cy - half, cz + half],
                [cx + half, cy - half, cz + half],
                [cx + half, cy + half, cz + half],
                [cx - half, cy + half, cz + half]
            ]
            
            for v in cube_verts:
                vertices.extend(v)
                intensity = 0.5 + confidence * 0.5
                colors.extend([color[0] * intensity, color[1] * intensity, color[2] * intensity])
            
            # Cube face indices
            cube_faces = [
                [0, 1, 2], [0, 2, 3],  # Bottom
                [4, 6, 5], [4, 7, 6],  # Top
                [0, 4, 5], [0, 5, 1],  # Front
                [2, 6, 7], [2, 7, 3],  # Back
                [0, 7, 4], [0, 3, 7],  # Left
                [1, 5, 6], [1, 6, 2]   # Right
            ]
            
            for face in cube_faces:
                indices.extend([base_idx + f for f in face])
        
        # Add dominant class indicator
        dominant_color = class_colors.get(dominant_class, (0.5, 0.5, 0.5))
        indicator_base_idx = len(vertices) // 3
        
        # Create glowing sphere for dominant class
        sphere_radius = 0.4
        sphere_x, sphere_y, sphere_z = 0, 0, grid_size[2] * voxel_size + 1
        
        u_steps = 16
        v_steps = 12
        
        for u in range(u_steps):
            for v in range(v_steps):
                theta = 2 * np.pi * u / u_steps
                phi = np.pi * v / v_steps
                
                x = sphere_x + sphere_radius * np.sin(phi) * np.cos(theta)
                y = sphere_y + sphere_radius * np.sin(phi) * np.sin(theta)
                z = sphere_z + sphere_radius * np.cos(phi)
                
                vertices.extend([x, y, z])
                glow = 0.8 + 0.2 * np.sin(theta * 4)
                colors.extend([dominant_color[0] * glow, dominant_color[1] * glow, dominant_color[2] * glow])
        
        # Coverage bar
        bar_length = 3.0
        bar_filled = bar_length * coverage
        bar_z = grid_size[2] * voxel_size + 0.5
        
        bar_base_idx = len(vertices) // 3
        
        # Filled portion
        vertices.extend([-bar_length/2, -0.1, bar_z])
        vertices.extend([-bar_length/2 + bar_filled, -0.1, bar_z])
        vertices.extend([-bar_length/2 + bar_filled, 0.1, bar_z])
        vertices.extend([-bar_length/2, 0.1, bar_z])
        
        for _ in range(4):
            colors.extend([0.3, 0.9, 0.4])
        
        indices.extend([bar_base_idx, bar_base_idx + 1, bar_base_idx + 2])
        indices.extend([bar_base_idx, bar_base_idx + 2, bar_base_idx + 3])
        
        # Empty portion
        empty_base_idx = len(vertices) // 3
        vertices.extend([-bar_length/2 + bar_filled, -0.1, bar_z])
        vertices.extend([bar_length/2, -0.1, bar_z])
        vertices.extend([bar_length/2, 0.1, bar_z])
        vertices.extend([-bar_length/2 + bar_filled, 0.1, bar_z])
        
        for _ in range(4):
            colors.extend([0.3, 0.3, 0.3])
        
        indices.extend([empty_base_idx, empty_base_idx + 1, empty_base_idx + 2])
        indices.extend([empty_base_idx, empty_base_idx + 2, empty_base_idx + 3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.6, 0.6, 0.7),
            emissive=(0.1, 0.1, 0.15),
            metallic=0.2,
            roughness=0.5
        )
        
        semantic_obj = Object3D(
            name="semantic_segmentation",
            position=(0, 0, 0),
            mesh=mesh,
            material=material,
            data={"type": "semantic", "dominant_class": dominant_class, "coverage": coverage}
        )
        
        self.scene.add_object(semantic_obj)
        return semantic_obj
    
    def create_optimization_viz(self, best_fitness: float = 0.5, convergence_rate: float = 0.0,
                                  generation: int = 0, optimal_params: dict = None) -> 'Object3D':
        """Create quantum-inspired optimization visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Optimization landscape visualization
        landscape_size = 4.0
        resolution = 20
        
        # Generate fitness landscape
        for i in range(resolution):
            for j in range(resolution):
                x = (i - resolution/2) * landscape_size / resolution
                z = (j - resolution/2) * landscape_size / resolution
                
                # Simulated multi-modal fitness landscape
                y = 0.5 * np.sin(x * 2) * np.cos(z * 2) + 0.3 * np.cos(x * 3 + z)
                y = y * best_fitness + 0.2
                
                vertices.extend([x, y, z])
                
                # Color by height
                r = 0.2 + y * 0.6
                g = 0.3 + (1 - abs(y)) * 0.5
                b = 0.8 - y * 0.3
                colors.extend([r, g, b])
        
        # Create mesh indices
        for i in range(resolution - 1):
            for j in range(resolution - 1):
                idx = i * resolution + j
                indices.extend([idx, idx + 1, idx + resolution])
                indices.extend([idx + 1, idx + resolution + 1, idx + resolution])
        
        # Add current best solution marker
        marker_base_idx = len(vertices) // 3
        marker_radius = 0.15
        marker_height = best_fitness + 0.5
        
        # Cone for best solution
        for i in range(16):
            angle = 2 * np.pi * i / 16
            vertices.extend([marker_radius * np.cos(angle), 0.1, marker_radius * np.sin(angle)])
            colors.extend([1.0, 0.8, 0.2])
        
        # Apex
        vertices.extend([0, marker_height, 0])
        colors.extend([1.0, 1.0, 0.5])
        
        apex_idx = marker_base_idx + 16
        for i in range(16):
            next_i = (i + 1) % 16
            indices.extend([marker_base_idx + i, marker_base_idx + next_i, apex_idx])
        
        # Convergence indicator ring
        ring_base_idx = len(vertices) // 3
        ring_radius = 2.0
        ring_fill = min(1.0, abs(convergence_rate) * 10)
        
        for i in range(32):
            angle = 2 * np.pi * i / 32
            vertices.extend([ring_radius * np.cos(angle), 0.05, ring_radius * np.sin(angle)])
            
            if i / 32 < ring_fill:
                colors.extend([0.3, 0.9, 0.4])  # Green for progress
            else:
                colors.extend([0.2, 0.2, 0.3])  # Gray for remaining
        
        # Generation counter visualization
        gen_display = min(generation, 100)
        gen_base_idx = len(vertices) // 3
        
        for g in range(gen_display):
            angle = 2 * np.pi * g / 100
            r = 2.3 + 0.1 * (g % 10)
            vertices.extend([r * np.cos(angle), 0.02, r * np.sin(angle)])
            colors.extend([0.5, 0.5, 0.8])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.4, 0.5, 0.8),
            emissive=(0.05, 0.1, 0.15),
            metallic=0.3,
            roughness=0.6
        )
        
        opt_obj = Object3D(
            name="optimization_landscape",
            position=(0, 0, 3),
            mesh=mesh,
            material=material,
            data={"type": "optimization", "fitness": best_fitness, "generation": generation}
        )
        
        self.scene.add_object(opt_obj)
        return opt_obj
    
    def create_neural_decode_viz(self, features: list, snr_db: float = 0.0,
                                   hidden_state_norm: float = 0.0) -> 'Object3D':
        """Create neural channel decoder visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Neural network architecture visualization
        layer_positions = [(-2, 0, 0), (-1, 0, 0), (0, 0, 0), (1, 0, 0), (2, 0, 0)]
        layer_sizes = [16, 32, 64, 32, len(features) if features else 16]
        
        # Create neurons for each layer
        neuron_idx = 0
        layer_neuron_indices = []
        
        for layer_idx, (layer_pos, num_neurons) in enumerate(zip(layer_positions, layer_sizes)):
            layer_indices = []
            num_display = min(num_neurons, 8)  # Limit displayed neurons
            
            for n in range(num_display):
                # Neuron position
                ny = (n - num_display/2) * 0.3
                
                # Create sphere for neuron
                sphere_radius = 0.08
                u_steps = 8
                v_steps = 6
                
                base_idx = len(vertices) // 3
                layer_indices.append(base_idx)
                
                for u in range(u_steps):
                    for v in range(v_steps):
                        theta = 2 * np.pi * u / u_steps
                        phi = np.pi * v / v_steps
                        
                        x = layer_pos[0] + sphere_radius * np.sin(phi) * np.cos(theta)
                        y = layer_pos[1] + ny + sphere_radius * np.sin(phi) * np.sin(theta)
                        z = layer_pos[2] + sphere_radius * np.cos(phi)
                        
                        vertices.extend([x, y, z])
                        
                        # Color by activation (feature value)
                        if features and n < len(features):
                            activation = abs(features[n]) / (max(abs(f) for f in features) + 1e-10)
                        else:
                            activation = 0.5
                        
                        r = 0.2 + activation * 0.7
                        g = 0.3 + (1 - activation) * 0.4
                        b = 0.8 - activation * 0.3
                        colors.extend([r, g, b])
                        
                        neuron_idx += 1
            
            layer_neuron_indices.append(layer_indices)
        
        # SNR indicator bar
        snr_normalized = (snr_db + 20) / 40  # Normalize -20 to 20 dB
        snr_normalized = max(0, min(1, snr_normalized))
        
        bar_base_idx = len(vertices) // 3
        bar_height = 1.0
        bar_filled = bar_height * snr_normalized
        
        # Filled portion
        vertices.extend([-2.5, -0.5, -0.1])
        vertices.extend([-2.3, -0.5, -0.1])
        vertices.extend([-2.3, -0.5 + bar_filled, -0.1])
        vertices.extend([-2.5, -0.5 + bar_filled, -0.1])
        
        for _ in range(4):
            colors.extend([0.2, 0.8, 0.3])
        
        indices.extend([bar_base_idx, bar_base_idx + 1, bar_base_idx + 2])
        indices.extend([bar_base_idx, bar_base_idx + 2, bar_base_idx + 3])
        
        # Hidden state norm indicator
        norm_base_idx = len(vertices) // 3
        norm_radius = 0.3 * hidden_state_norm / 10  # Scale
        
        for i in range(16):
            angle = 2 * np.pi * i / 16
            vertices.extend([2.5 + norm_radius * np.cos(angle), norm_radius * np.sin(angle), 0])
            colors.extend([0.8, 0.4, 0.8])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.5, 0.7),
            emissive=(0.1, 0.1, 0.2),
            metallic=0.2,
            roughness=0.5
        )
        
        neural_obj = Object3D(
            name="neural_decoder",
            position=(0, 2, 0),
            mesh=mesh,
            material=material,
            data={"type": "neural_decode", "snr_db": snr_db}
        )
        
        self.scene.add_object(neural_obj)
        return neural_obj
    
    def create_causal_graph_viz(self, edges: list, num_variables: int = 5,
                                  confidence: float = 0.5) -> 'Object3D':
        """Create causal inference graph visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Arrange variables in a circle
        radius = 2.0
        
        variable_positions = []
        for i in range(num_variables):
            angle = 2 * np.pi * i / num_variables
            x = radius * np.cos(angle)
            z = radius * np.sin(angle)
            variable_positions.append((x, 0, z))
        
        # Create variable nodes
        for i, pos in enumerate(variable_positions):
            # Hexagonal node
            node_radius = 0.2
            for j in range(6):
                angle = np.pi / 3 * j
                vertices.extend([
                    pos[0] + node_radius * np.cos(angle),
                    pos[1] + 0.1,
                    pos[2] + node_radius * np.sin(angle)
                ])
                colors.extend([0.3, 0.6, 0.9])
            
            # Center
            base_idx = len(vertices) // 3 - 6
            center_idx = len(vertices) // 3
            vertices.extend([pos[0], pos[1] + 0.1, pos[2]])
            colors.extend([0.5, 0.8, 1.0])
            
            for j in range(6):
                next_j = (j + 1) % 6
                indices.extend([base_idx + j, base_idx + next_j, center_idx])
        
        # Create causal edges (arrows)
        for edge in edges[:20]:  # Limit edges
            if len(edge) >= 3:
                cause_name, effect_name, strength = edge[0], edge[1], edge[2]
                
                # Find indices (simplified - use modulo)
                cause_idx = hash(cause_name) % num_variables
                effect_idx = hash(effect_name) % num_variables
                
                if cause_idx != effect_idx and cause_idx < len(variable_positions) and effect_idx < len(variable_positions):
                    p1 = variable_positions[cause_idx]
                    p2 = variable_positions[effect_idx]
                    
                    # Create arrow
                    direction = np.array(p2) - np.array(p1)
                    length = np.linalg.norm(direction)
                    if length > 0.01:
                        direction = direction / length
                        
                        # Arrow shaft
                        arrow_width = 0.05 * abs(strength)
                        perp = np.array([-direction[2], 0, direction[0]])
                        
                        for t in np.linspace(0.2, 0.8, 5):
                            center = np.array(p1) + direction * length * t
                            
                            vertices.extend([
                                center[0] + perp[0] * arrow_width,
                                center[1] + 0.05,
                                center[2] + perp[2] * arrow_width
                            ])
                            vertices.extend([
                                center[0] - perp[0] * arrow_width,
                                center[1] + 0.05,
                                center[2] - perp[2] * arrow_width
                            ])
                            
                            # Color by strength
                            if strength > 0:
                                colors.extend([0.3, 0.8, 0.3])
                                colors.extend([0.3, 0.8, 0.3])
                            else:
                                colors.extend([0.8, 0.3, 0.3])
                                colors.extend([0.8, 0.3, 0.3])
        
        # Confidence indicator
        conf_base_idx = len(vertices) // 3
        conf_arc_segments = int(32 * confidence)
        
        for i in range(conf_arc_segments):
            angle = 2 * np.pi * i / 32
            vertices.extend([
                radius * 1.3 * np.cos(angle),
                -0.1,
                radius * 1.3 * np.sin(angle)
            ])
            colors.extend([confidence, 0.5, 1 - confidence])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.6, 0.8),
            emissive=(0.1, 0.15, 0.2),
            metallic=0.3,
            roughness=0.5
        )
        
        causal_obj = Object3D(
            name="causal_graph",
            position=(0, 3, 0),
            mesh=mesh,
            material=material,
            data={"type": "causal", "num_edges": len(edges), "confidence": confidence}
        )
        
        self.scene.add_object(causal_obj)
        return causal_obj
    
    def create_transformer_viz(self, embeddings: list, attention_summary: list,
                                 pooled_features: list) -> 'Object3D':
        """Create spatio-temporal transformer attention visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Attention matrix heatmap
        matrix_size = 3.0
        resolution = min(len(attention_summary), 16) if attention_summary else 8
        cell_size = matrix_size / resolution
        
        for i in range(resolution):
            for j in range(resolution):
                x = (i - resolution/2) * cell_size
                z = (j - resolution/2) * cell_size
                
                # Get attention value
                if attention_summary and i < len(attention_summary):
                    attn_val = abs(attention_summary[i]) if isinstance(attention_summary[i], (int, float)) else 0.5
                else:
                    attn_val = 0.3
                
                y = attn_val * 0.5
                
                base_idx = len(vertices) // 3
                
                # Cell vertices
                vertices.extend([x, y, z])
                vertices.extend([x + cell_size * 0.9, y, z])
                vertices.extend([x + cell_size * 0.9, y, z + cell_size * 0.9])
                vertices.extend([x, y, z + cell_size * 0.9])
                
                # Color by attention
                r = attn_val
                g = 0.3 + (1 - attn_val) * 0.4
                b = 1 - attn_val * 0.5
                
                for _ in range(4):
                    colors.extend([r, g, b])
                
                indices.extend([base_idx, base_idx + 1, base_idx + 2])
                indices.extend([base_idx, base_idx + 2, base_idx + 3])
        
        # Embedding vectors visualization
        embed_base_idx = len(vertices) // 3
        
        for idx, embed in enumerate(embeddings[:5]):
            if isinstance(embed, list):
                for dim_idx, val in enumerate(embed[:8]):
                    x = -matrix_size/2 - 0.5 - idx * 0.3
                    z = (dim_idx - 4) * 0.2
                    y = abs(val) if isinstance(val, (int, float)) else 0.2
                    
                    vertices.extend([x, 0, z])
                    vertices.extend([x, y, z])
                    
                    colors.extend([0.8, 0.5, 0.2])
                    colors.extend([1.0, 0.7, 0.3])
        
        # Pooled features as radial bars
        pool_base_idx = len(vertices) // 3
        pool_radius = matrix_size / 2 + 0.5
        
        for idx, feat in enumerate(pooled_features[:16]):
            angle = 2 * np.pi * idx / 16
            feat_val = abs(feat) if isinstance(feat, (int, float)) else 0.3
            
            x1 = pool_radius * np.cos(angle)
            z1 = pool_radius * np.sin(angle)
            x2 = (pool_radius + feat_val * 0.5) * np.cos(angle)
            z2 = (pool_radius + feat_val * 0.5) * np.sin(angle)
            
            vertices.extend([x1, 0.1, z1])
            vertices.extend([x2, 0.1, z2])
            
            colors.extend([0.4, 0.7, 0.9])
            colors.extend([0.6, 0.9, 1.0])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.6, 0.5, 0.7),
            emissive=(0.1, 0.1, 0.15),
            metallic=0.2,
            roughness=0.4
        )
        
        transformer_obj = Object3D(
            name="transformer_attention",
            position=(0, 4, 0),
            mesh=mesh,
            material=material,
            data={"type": "transformer", "num_embeddings": len(embeddings)}
        )
        
        self.scene.add_object(transformer_obj)
        return transformer_obj
    
    def create_hierarchical_activity_viz(self, hierarchy: dict, confidence: dict,
                                          full_path: str = "") -> 'Object3D':
        """Create hierarchical activity recognition visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Activity colors
        activity_colors = {
            'stationary': (0.3, 0.5, 0.8),
            'locomotion': (0.8, 0.5, 0.2),
            'interaction': (0.5, 0.8, 0.3),
            'sitting': (0.4, 0.4, 0.7),
            'standing': (0.5, 0.5, 0.6),
            'lying': (0.3, 0.3, 0.5),
            'walking': (0.7, 0.5, 0.2),
            'running': (0.9, 0.4, 0.2),
            'gesturing': (0.4, 0.7, 0.3),
            'physical': (0.6, 0.8, 0.3),
            'unknown': (0.4, 0.4, 0.4)
        }
        
        levels = ['coarse', 'medium', 'fine']
        level_heights = [0, 0.8, 1.6]
        level_radii = [1.5, 1.0, 0.5]
        
        for level_idx, (level_name, height, radius) in enumerate(zip(levels, level_heights, level_radii)):
            activity = hierarchy.get(level_name, 'unknown')
            conf = confidence.get(level_name, 0.5)
            
            color = activity_colors.get(activity, (0.4, 0.4, 0.4))
            
            # Create ring for each level
            segments = 32
            ring_width = 0.1 * (1 + conf)
            
            for i in range(segments):
                angle1 = 2 * np.pi * i / segments
                angle2 = 2 * np.pi * (i + 1) / segments
                
                base_idx = len(vertices) // 3
                
                # Inner and outer ring vertices
                vertices.extend([
                    (radius - ring_width) * np.cos(angle1), height, (radius - ring_width) * np.sin(angle1)
                ])
                vertices.extend([
                    radius * np.cos(angle1), height, radius * np.sin(angle1)
                ])
                vertices.extend([
                    radius * np.cos(angle2), height, radius * np.sin(angle2)
                ])
                vertices.extend([
                    (radius - ring_width) * np.cos(angle2), height, (radius - ring_width) * np.sin(angle2)
                ])
                
                # Intensity by confidence
                intensity = 0.5 + conf * 0.5
                for _ in range(4):
                    colors.extend([color[0] * intensity, color[1] * intensity, color[2] * intensity])
                
                indices.extend([base_idx, base_idx + 1, base_idx + 2])
                indices.extend([base_idx, base_idx + 2, base_idx + 3])
        
        # Connecting pillars between levels
        for i in range(4):
            angle = np.pi / 2 * i
            
            for level_idx in range(len(levels) - 1):
                h1 = level_heights[level_idx]
                h2 = level_heights[level_idx + 1]
                r1 = level_radii[level_idx] * 0.9
                r2 = level_radii[level_idx + 1] * 0.9
                
                pillar_base_idx = len(vertices) // 3
                
                x1 = r1 * np.cos(angle)
                z1 = r1 * np.sin(angle)
                x2 = r2 * np.cos(angle)
                z2 = r2 * np.sin(angle)
                
                vertices.extend([x1, h1, z1])
                vertices.extend([x2, h2, z2])
                
                colors.extend([0.5, 0.5, 0.6])
                colors.extend([0.7, 0.7, 0.8])
        
        # Top indicator for current fine activity
        fine_activity = hierarchy.get('fine', 'unknown')
        fine_color = activity_colors.get(fine_activity, (0.4, 0.4, 0.4))
        
        top_base_idx = len(vertices) // 3
        top_height = level_heights[-1] + 0.3
        
        # Diamond indicator
        vertices.extend([0, top_height, 0])  # Center
        vertices.extend([0.2, top_height - 0.1, 0])
        vertices.extend([0, top_height - 0.1, 0.2])
        vertices.extend([-0.2, top_height - 0.1, 0])
        vertices.extend([0, top_height - 0.1, -0.2])
        vertices.extend([0, top_height - 0.2, 0])  # Bottom
        
        for _ in range(6):
            colors.extend([fine_color[0], fine_color[1], fine_color[2]])
        
        # Diamond faces
        indices.extend([top_base_idx, top_base_idx + 1, top_base_idx + 2])
        indices.extend([top_base_idx, top_base_idx + 2, top_base_idx + 3])
        indices.extend([top_base_idx, top_base_idx + 3, top_base_idx + 4])
        indices.extend([top_base_idx, top_base_idx + 4, top_base_idx + 1])
        indices.extend([top_base_idx + 5, top_base_idx + 2, top_base_idx + 1])
        indices.extend([top_base_idx + 5, top_base_idx + 3, top_base_idx + 2])
        indices.extend([top_base_idx + 5, top_base_idx + 4, top_base_idx + 3])
        indices.extend([top_base_idx + 5, top_base_idx + 1, top_base_idx + 4])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.6, 0.7),
            emissive=(0.1, 0.12, 0.15),
            metallic=0.25,
            roughness=0.45
        )
        
        hierarchy_obj = Object3D(
            name="hierarchical_activity",
            position=(3, 0, 3),
            mesh=mesh,
            material=material,
            data={"type": "hierarchical_activity", "full_path": full_path}
        )
        
        self.scene.add_object(hierarchy_obj)
        return hierarchy_obj
    
    def create_robustness_viz(self, defense_strength: float = 0.8, attacks_detected: int = 0,
                               certified_radius: float = 0.0) -> 'Object3D':
        """Create adversarial robustness shield visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Defense shield dome
        shield_radius = 2.5
        shield_segments = 24
        shield_rings = 12
        
        # Color based on defense strength
        if defense_strength > 0.7:
            shield_color = (0.2, 0.8, 0.3)  # Green
        elif defense_strength > 0.4:
            shield_color = (0.8, 0.7, 0.2)  # Yellow
        else:
            shield_color = (0.8, 0.3, 0.2)  # Red
        
        # Create geodesic-style shield
        for ring in range(shield_rings):
            ring_angle = np.pi * ring / (shield_rings * 2)
            ring_radius = shield_radius * np.sin(ring_angle)
            ring_height = shield_radius * np.cos(ring_angle)
            
            for seg in range(shield_segments):
                seg_angle = 2 * np.pi * seg / shield_segments
                
                x = ring_radius * np.cos(seg_angle)
                z = ring_radius * np.sin(seg_angle)
                
                # Add hexagonal pattern effect
                pattern = np.sin(seg_angle * 6 + ring * 2) * 0.05
                
                vertices.extend([x * (1 + pattern), ring_height, z * (1 + pattern)])
                
                # Pulsing effect based on defense strength
                intensity = 0.5 + defense_strength * 0.5 * (1 + np.sin(ring * 0.5 + seg * 0.3))
                colors.extend([
                    shield_color[0] * intensity,
                    shield_color[1] * intensity,
                    shield_color[2] * intensity
                ])
        
        # Create mesh for shield
        for ring in range(shield_rings - 1):
            for seg in range(shield_segments):
                idx = ring * shield_segments + seg
                next_seg = ring * shield_segments + (seg + 1) % shield_segments
                next_ring = (ring + 1) * shield_segments + seg
                next_ring_seg = (ring + 1) * shield_segments + (seg + 1) % shield_segments
                
                indices.extend([idx, next_seg, next_ring])
                indices.extend([next_seg, next_ring_seg, next_ring])
        
        # Attack indicators
        for i in range(min(attacks_detected, 8)):
            angle = 2 * np.pi * i / 8
            attack_radius = shield_radius * 1.1
            
            # Spike for each attack
            base_idx = len(vertices) // 3
            
            # Spike base
            spike_base_r = 0.1
            for j in range(6):
                a = 2 * np.pi * j / 6
                x = attack_radius * np.cos(angle) + spike_base_r * np.cos(a)
                z = attack_radius * np.sin(angle) + spike_base_r * np.sin(a)
                vertices.extend([x, shield_radius * 0.5, z])
                colors.extend([0.9, 0.2, 0.2])
            
            # Spike tip
            vertices.extend([attack_radius * np.cos(angle), shield_radius * 0.5 + 0.3, attack_radius * np.sin(angle)])
            colors.extend([1.0, 0.4, 0.3])
            
            tip_idx = base_idx + 6
            for j in range(6):
                next_j = (j + 1) % 6
                indices.extend([base_idx + j, base_idx + next_j, tip_idx])
        
        # Certified radius ring
        if certified_radius > 0:
            cert_ring_base = len(vertices) // 3
            cert_radius = 1.0 + certified_radius * 2
            
            for i in range(32):
                angle = 2 * np.pi * i / 32
                vertices.extend([cert_radius * np.cos(angle), 0.05, cert_radius * np.sin(angle)])
                colors.extend([0.3, 0.9, 1.0])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=shield_color,
            emissive=(shield_color[0] * 0.2, shield_color[1] * 0.2, shield_color[2] * 0.2),
            metallic=0.4,
            roughness=0.3,
            opacity=0.7
        )
        
        robustness_obj = Object3D(
            name="robustness_shield",
            position=(0, 0, 0),
            mesh=mesh,
            material=material,
            data={"type": "robustness", "defense_strength": defense_strength, "attacks": attacks_detected}
        )
        
        self.scene.add_object(robustness_obj)
        return robustness_obj
    
    def create_federated_viz(self, round_num: int = 0, num_clients: int = 5,
                              participating: int = 0, loss_history: list = None) -> 'Object3D':
        """Create federated learning network visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Central server
        server_radius = 0.4
        server_segments = 16
        
        for u in range(server_segments):
            for v in range(server_segments // 2):
                theta = 2 * np.pi * u / server_segments
                phi = np.pi * v / (server_segments // 2)
                
                x = server_radius * np.sin(phi) * np.cos(theta)
                y = server_radius * np.sin(phi) * np.sin(theta) + 2
                z = server_radius * np.cos(phi)
                
                vertices.extend([x, y, z])
                colors.extend([0.2, 0.6, 1.0])
        
        # Client nodes in circle
        client_radius = 2.0
        client_node_radius = 0.2
        
        for client_id in range(num_clients):
            angle = 2 * np.pi * client_id / num_clients
            cx = client_radius * np.cos(angle)
            cz = client_radius * np.sin(angle)
            
            # Client sphere
            client_base_idx = len(vertices) // 3
            
            for u in range(8):
                for v in range(4):
                    theta = 2 * np.pi * u / 8
                    phi = np.pi * v / 4
                    
                    x = cx + client_node_radius * np.sin(phi) * np.cos(theta)
                    y = client_node_radius * np.sin(phi) * np.sin(theta) + 0.5
                    z = cz + client_node_radius * np.cos(phi)
                    
                    vertices.extend([x, y, z])
                    
                    # Color by participation
                    if client_id < participating:
                        colors.extend([0.3, 0.9, 0.4])
                    else:
                        colors.extend([0.4, 0.4, 0.5])
            
            # Connection line to server
            line_base_idx = len(vertices) // 3
            vertices.extend([cx, 0.5, cz])
            vertices.extend([0, 2, 0])
            
            if client_id < participating:
                colors.extend([0.5, 0.8, 1.0])
                colors.extend([0.5, 0.8, 1.0])
            else:
                colors.extend([0.3, 0.3, 0.4])
                colors.extend([0.3, 0.3, 0.4])
        
        # Loss history visualization
        if loss_history:
            loss_base_idx = len(vertices) // 3
            loss_scale = 2.0
            
            for i, loss in enumerate(loss_history[-20:]):
                x = -2 + (i / 20) * 4
                y = 3 + (1 - min(1.0, loss)) * loss_scale
                
                vertices.extend([x, y, 2])
                colors.extend([1.0 - loss, loss, 0.3])
        
        # Round counter
        round_base_idx = len(vertices) // 3
        
        for i in range(min(round_num, 20)):
            angle = 2 * np.pi * i / 20
            vertices.extend([0.6 * np.cos(angle), 2 + 0.6 * np.sin(angle), 0])
            colors.extend([0.8, 0.8, 0.3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.4, 0.6, 0.9),
            emissive=(0.1, 0.15, 0.2),
            metallic=0.3,
            roughness=0.5
        )
        
        federated_obj = Object3D(
            name="federated_network",
            position=(-3, 0, 0),
            mesh=mesh,
            material=material,
            data={"type": "federated", "round": round_num, "clients": num_clients}
        )
        
        self.scene.add_object(federated_obj)
        return federated_obj
    
    def create_meta_learning_viz(self, num_environments: int = 0, total_adaptations: int = 0,
                                   recent: list = None) -> 'Object3D':
        """Create meta-learning adaptation visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Environment bubbles
        env_radius = 0.3
        bubble_distance = 1.5
        
        for env_id in range(min(num_environments, 8)):
            angle = 2 * np.pi * env_id / 8
            ex = bubble_distance * np.cos(angle)
            ez = bubble_distance * np.sin(angle)
            
            # Bubble sphere
            for u in range(12):
                for v in range(8):
                    theta = 2 * np.pi * u / 12
                    phi = np.pi * v / 8
                    
                    x = ex + env_radius * np.sin(phi) * np.cos(theta)
                    y = env_radius * np.sin(phi) * np.sin(theta) + 1
                    z = ez + env_radius * np.cos(phi)
                    
                    vertices.extend([x, y, z])
                    
                    # Color gradient by environment
                    hue = env_id / 8
                    colors.extend([0.3 + hue * 0.5, 0.5 + (1 - hue) * 0.3, 0.8 - hue * 0.3])
        
        # Adaptation arrows
        if recent:
            for i, adapt in enumerate(recent[-5:]):
                arrow_base_idx = len(vertices) // 3
                
                # Arrow from center to environment
                env_id_hash = hash(adapt.get('env_id', '')) % 8
                angle = 2 * np.pi * env_id_hash / 8
                ex = bubble_distance * np.cos(angle)
                ez = bubble_distance * np.sin(angle)
                
                # Arrow shaft
                for t in np.linspace(0, 1, 5):
                    x = t * ex
                    z = t * ez
                    vertices.extend([x, 0.5, z])
                    
                    # Color by adaptation success
                    similarity = adapt.get('similarity', 0.5)
                    colors.extend([0.3 + similarity * 0.5, 0.8, 0.4])
        
        # Adaptation counter ring
        adapt_ring_base = len(vertices) // 3
        adapt_normalized = min(1.0, total_adaptations / 50)
        ring_segments = int(32 * adapt_normalized)
        
        for i in range(ring_segments):
            angle = 2 * np.pi * i / 32
            vertices.extend([2 * np.cos(angle), 0.1, 2 * np.sin(angle)])
            colors.extend([0.5, 0.9, 0.6])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.7, 0.6),
            emissive=(0.1, 0.15, 0.12),
            metallic=0.2,
            roughness=0.5
        )
        
        meta_obj = Object3D(
            name="meta_learning",
            position=(3, 0, -3),
            mesh=mesh,
            material=material,
            data={"type": "meta_learning", "environments": num_environments, "adaptations": total_adaptations}
        )
        
        self.scene.add_object(meta_obj)
        return meta_obj
    
    def create_ssl_viz(self, total_steps: int = 0, recent_losses: list = None,
                        embedding_dim: int = 256) -> 'Object3D':
        """Create self-supervised learning progress visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Embedding space visualization (t-SNE style)
        num_points = min(total_steps, 100)
        
        for i in range(num_points):
            # Simulated embedding positions
            angle1 = 2 * np.pi * i / num_points + np.sin(i * 0.3) * 0.5
            angle2 = np.pi * 0.5 * np.sin(i * 0.1 + 1)
            r = 1.5 + 0.5 * np.sin(i * 0.2)
            
            x = r * np.cos(angle1) * np.sin(angle2)
            y = r * np.cos(angle2) + 1
            z = r * np.sin(angle1) * np.sin(angle2)
            
            vertices.extend([x, y, z])
            
            # Color by cluster
            cluster = int(angle1 * 3 / (2 * np.pi)) % 3
            cluster_colors = [(0.8, 0.3, 0.3), (0.3, 0.8, 0.3), (0.3, 0.3, 0.8)]
            colors.extend(cluster_colors[cluster])
        
        # Loss curve
        if recent_losses:
            loss_base_idx = len(vertices) // 3
            
            for i, loss in enumerate(recent_losses[-20:]):
                x = -2 + (i / 20) * 4
                y = 2.5 + (1 - min(1.0, loss * 2)) * 1.5
                
                vertices.extend([x, y, -2])
                
                # Color by loss
                colors.extend([min(1.0, loss * 2), max(0, 1 - loss * 2), 0.3])
            
            # Connect loss curve
            for i in range(len(recent_losses[-20:]) - 1):
                idx = loss_base_idx + i
                # Line segment
        
        # Embedding dimension indicator
        dim_base_idx = len(vertices) // 3
        dim_normalized = min(1.0, embedding_dim / 512)
        
        # Circular bar
        bar_segments = int(32 * dim_normalized)
        for i in range(bar_segments):
            angle = 2 * np.pi * i / 32
            vertices.extend([2.2 * np.cos(angle), 0.05, 2.2 * np.sin(angle)])
            colors.extend([0.7, 0.5, 0.9])
        
        # Contrastive pairs visualization
        pair_base_idx = len(vertices) // 3
        
        for i in range(5):
            # Anchor
            ax = np.random.uniform(-1.5, 1.5)
            az = np.random.uniform(-1.5, 1.5)
            
            vertices.extend([ax, 0.5, az])
            colors.extend([0.9, 0.7, 0.2])
            
            # Positive
            vertices.extend([ax + 0.2, 0.5, az + 0.2])
            colors.extend([0.3, 0.9, 0.4])
            
            # Negative
            vertices.extend([ax + np.random.uniform(0.5, 1.0), 0.5, az + np.random.uniform(0.5, 1.0)])
            colors.extend([0.9, 0.3, 0.3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.6, 0.5, 0.8),
            emissive=(0.12, 0.1, 0.16),
            metallic=0.2,
            roughness=0.5
        )
        
        ssl_obj = Object3D(
            name="ssl_pretraining",
            position=(-3, 0, -3),
            mesh=mesh,
            material=material,
            data={"type": "ssl", "steps": total_steps, "embedding_dim": embedding_dim}
        )
        
        self.scene.add_object(ssl_obj)
        return ssl_obj
    
    def create_reasoning_viz(self, symbols: list, inferred: list, rules_fired: int = 0,
                              trace: list = None) -> 'Object3D':
        """Create neuro-symbolic reasoning visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Symbol nodes on left side
        symbol_radius = 0.15
        
        for i, symbol in enumerate(symbols[:10]):
            y = 2 - i * 0.4
            
            # Hexagon for symbol
            base_idx = len(vertices) // 3
            for j in range(6):
                angle = np.pi / 3 * j
                vertices.extend([-2 + symbol_radius * np.cos(angle), y + symbol_radius * np.sin(angle), 0])
                colors.extend([0.3, 0.7, 0.9])
            
            center_idx = len(vertices) // 3
            vertices.extend([-2, y, 0])
            colors.extend([0.5, 0.9, 1.0])
            
            for j in range(6):
                indices.extend([base_idx + j, base_idx + (j + 1) % 6, center_idx])
        
        # Inferred symbols on right side
        for i, inferred_sym in enumerate(inferred[:10]):
            y = 2 - i * 0.4
            
            # Circle for inferred
            base_idx = len(vertices) // 3
            for j in range(12):
                angle = 2 * np.pi * j / 12
                vertices.extend([2 + symbol_radius * np.cos(angle), y + symbol_radius * np.sin(angle), 0])
                colors.extend([0.9, 0.6, 0.3])
            
            center_idx = len(vertices) // 3
            vertices.extend([2, y, 0])
            colors.extend([1.0, 0.8, 0.4])
            
            for j in range(12):
                indices.extend([base_idx + j, base_idx + (j + 1) % 12, center_idx])
        
        # Reasoning trace arrows
        if trace:
            for i, step in enumerate(trace[:5]):
                arrow_base_idx = len(vertices) // 3
                
                # Arrow from left to right
                y = 1.5 - i * 0.5
                
                # Arrow shaft
                vertices.extend([-1.5, y, 0.1])
                vertices.extend([1.5, y, 0.1])
                colors.extend([0.6, 0.9, 0.5])
                colors.extend([0.8, 1.0, 0.6])
                
                # Arrow head
                vertices.extend([1.3, y + 0.1, 0.1])
                vertices.extend([1.3, y - 0.1, 0.1])
                vertices.extend([1.5, y, 0.1])
                
                colors.extend([0.8, 1.0, 0.6])
                colors.extend([0.8, 1.0, 0.6])
                colors.extend([0.8, 1.0, 0.6])
        
        # Rules fired counter
        rule_base_idx = len(vertices) // 3
        
        for i in range(min(rules_fired, 10)):
            angle = 2 * np.pi * i / 10
            vertices.extend([0.3 * np.cos(angle), 3 + 0.3 * np.sin(angle), 0])
            colors.extend([0.9, 0.4, 0.8])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.7, 0.8),
            emissive=(0.1, 0.15, 0.2),
            metallic=0.2,
            roughness=0.5
        )
        
        reasoning_obj = Object3D(
            name="neurosymbolic_reasoning",
            position=(0, 0, 4),
            mesh=mesh,
            material=material,
            data={"type": "reasoning", "rules_fired": rules_fired, "num_symbols": len(symbols)}
        )
        
        self.scene.add_object(reasoning_obj)
        return reasoning_obj
    
    def create_rl_viz(self, steps: int = 0, avg_reward: float = 0.0,
                       epsilon: float = 0.1, action: int = 0) -> 'Object3D':
        """Create reinforcement learning agent visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Agent representation (robot-like)
        agent_radius = 0.4
        
        # Body sphere
        for u in range(16):
            for v in range(12):
                theta = 2 * np.pi * u / 16
                phi = np.pi * v / 12
                
                x = agent_radius * np.sin(phi) * np.cos(theta)
                y = agent_radius * np.sin(phi) * np.sin(theta) + 0.5
                z = agent_radius * np.cos(phi)
                
                vertices.extend([x, y, z])
                
                # Color by exploration rate
                r = 0.2 + epsilon * 0.6
                g = 0.5 + (1 - epsilon) * 0.4
                b = 0.8
                colors.extend([r, g, b])
        
        # Action arrows (8 directions)
        arrow_length = 0.8
        
        for a in range(8):
            angle = 2 * np.pi * a / 8
            
            # Arrow start
            vertices.extend([0, 0.5, 0])
            
            # Arrow end
            end_x = arrow_length * np.cos(angle)
            end_z = arrow_length * np.sin(angle)
            vertices.extend([end_x, 0.5, end_z])
            
            # Color current action
            if a == action:
                colors.extend([1.0, 0.8, 0.2])
                colors.extend([1.0, 0.9, 0.4])
            else:
                colors.extend([0.3, 0.3, 0.4])
                colors.extend([0.4, 0.4, 0.5])
        
        # Reward history bar
        reward_normalized = (avg_reward + 10) / 20  # Normalize to 0-1
        reward_normalized = max(0, min(1, reward_normalized))
        
        reward_bar_height = 2.0 * reward_normalized
        reward_base_idx = len(vertices) // 3
        
        vertices.extend([-1.5, 0, -0.1])
        vertices.extend([-1.3, 0, -0.1])
        vertices.extend([-1.3, reward_bar_height, -0.1])
        vertices.extend([-1.5, reward_bar_height, -0.1])
        
        reward_color = (0.3 + reward_normalized * 0.6, 0.8 * reward_normalized, 0.3)
        for _ in range(4):
            colors.extend([reward_color[0], reward_color[1], reward_color[2]])
        
        indices.extend([reward_base_idx, reward_base_idx + 1, reward_base_idx + 2])
        indices.extend([reward_base_idx, reward_base_idx + 2, reward_base_idx + 3])
        
        # Steps counter ring
        steps_normalized = min(1.0, steps / 10000)
        step_segments = int(32 * steps_normalized)
        
        for i in range(step_segments):
            angle = 2 * np.pi * i / 32
            vertices.extend([1.5 * np.cos(angle), 0.05, 1.5 * np.sin(angle)])
            colors.extend([0.7, 0.5, 0.9])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.6, 0.8),
            emissive=(0.1, 0.12, 0.18),
            metallic=0.3,
            roughness=0.4
        )
        
        rl_obj = Object3D(
            name="rl_agent",
            position=(0, 0, -4),
            mesh=mesh,
            material=material,
            data={"type": "rl", "steps": steps, "avg_reward": avg_reward, "epsilon": epsilon}
        )
        
        self.scene.add_object(rl_obj)
        return rl_obj
    
    def create_fusion_viz(self, modality_importance: list, attention: dict,
                           fused_dim: int = 128) -> 'Object3D':
        """Create attention-based multi-modal fusion visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Modality streams
        modalities = ['csi_amplitude', 'csi_phase', 'doppler', 'rssi']
        modality_colors = [(0.2, 0.6, 1.0), (0.8, 0.4, 0.2), (0.3, 0.8, 0.4), (0.7, 0.3, 0.7)]
        
        stream_length = 3.0
        stream_width = 0.2
        
        for i, (mod, color) in enumerate(zip(modalities, modality_colors)):
            y = 1.5 - i * 0.8
            
            # Importance determines stream thickness
            importance = modality_importance[i] if i < len(modality_importance) else 0.5
            thickness = stream_width * (0.5 + importance)
            
            base_idx = len(vertices) // 3
            
            # Stream quad
            vertices.extend([-stream_length/2, y - thickness, 0])
            vertices.extend([stream_length/2, y - thickness, 0])
            vertices.extend([stream_length/2, y + thickness, 0])
            vertices.extend([-stream_length/2, y + thickness, 0])
            
            for _ in range(4):
                intensity = 0.5 + importance * 0.5
                colors.extend([color[0] * intensity, color[1] * intensity, color[2] * intensity])
            
            indices.extend([base_idx, base_idx + 1, base_idx + 2])
            indices.extend([base_idx, base_idx + 2, base_idx + 3])
        
        # Fusion point
        fusion_base_idx = len(vertices) // 3
        fusion_radius = 0.4
        
        for u in range(16):
            for v in range(8):
                theta = 2 * np.pi * u / 16
                phi = np.pi * v / 8
                
                x = stream_length/2 + 0.5 + fusion_radius * np.sin(phi) * np.cos(theta)
                y = 0.3 + fusion_radius * np.sin(phi) * np.sin(theta)
                z = fusion_radius * np.cos(phi)
                
                vertices.extend([x, y, z])
                colors.extend([0.9, 0.7, 0.2])
        
        # Attention weight visualization
        attn_base_idx = len(vertices) // 3
        
        for i, mod in enumerate(modalities):
            if mod in attention and attention[mod]:
                attn_weights = attention[mod]
                
                for j, w in enumerate(attn_weights[:4]):
                    if isinstance(w, (int, float)):
                        y1 = 1.5 - i * 0.8
                        y2 = 1.5 - j * 0.8
                        
                        # Attention line
                        vertices.extend([-stream_length/4, y1, 0.1])
                        vertices.extend([stream_length/4, y2, 0.1])
                        
                        intensity = abs(w) if isinstance(w, (int, float)) else 0.5
                        colors.extend([intensity, intensity * 0.8, 0.3])
                        colors.extend([intensity, intensity * 0.8, 0.3])
        
        # Fused dimension indicator
        dim_base_idx = len(vertices) // 3
        dim_normalized = min(1.0, fused_dim / 256)
        
        for i in range(int(16 * dim_normalized)):
            angle = 2 * np.pi * i / 16
            vertices.extend([
                stream_length/2 + 0.5 + 0.6 * np.cos(angle),
                0.3 + 0.6 * np.sin(angle),
                0.3
            ])
            colors.extend([0.4, 0.9, 0.6])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.6, 0.6, 0.7),
            emissive=(0.12, 0.12, 0.14),
            metallic=0.25,
            roughness=0.45
        )
        
        fusion_obj = Object3D(
            name="attention_fusion",
            position=(4, 0, 0),
            mesh=mesh,
            material=material,
            data={"type": "fusion", "num_modalities": len(modalities), "fused_dim": fused_dim}
        )
        
        self.scene.add_object(fusion_obj)
        return fusion_obj
    
    def create_uncertainty_viz(self, prediction: int = 0, confidence: float = 0.5,
                                epistemic: float = 0.0, aleatoric: float = 0.0,
                                total: float = 0.0) -> 'Object3D':
        """Create uncertainty quantification visualization."""
        import numpy as np
        
        vertices = []
        colors = []
        indices = []
        
        # Prediction confidence cone
        cone_height = 2.0 * confidence
        cone_radius = 0.5 + (1 - confidence) * 0.5  # Wider for less confident
        cone_segments = 24
        
        # Cone base
        base_idx = len(vertices) // 3
        for i in range(cone_segments):
            angle = 2 * np.pi * i / cone_segments
            vertices.extend([cone_radius * np.cos(angle), 0, cone_radius * np.sin(angle)])
            
            # Color by confidence
            colors.extend([confidence, 0.3 + confidence * 0.5, 1 - confidence * 0.5])
        
        # Cone apex
        apex_idx = len(vertices) // 3
        vertices.extend([0, cone_height, 0])
        colors.extend([0.9, 0.9, 0.3])
        
        for i in range(cone_segments):
            indices.extend([base_idx + i, base_idx + (i + 1) % cone_segments, apex_idx])
        
        # Epistemic uncertainty ring (outer)
        epistemic_radius = 1.0 + epistemic * 2
        epistemic_segments = int(32 * min(1.0, epistemic * 10))
        
        for i in range(epistemic_segments):
            angle = 2 * np.pi * i / 32
            vertices.extend([epistemic_radius * np.cos(angle), 0.1, epistemic_radius * np.sin(angle)])
            colors.extend([0.9, 0.3, 0.3])  # Red for model uncertainty
        
        # Aleatoric uncertainty ring (inner)
        aleatoric_radius = 0.8 + aleatoric * 1.5
        aleatoric_segments = int(32 * min(1.0, aleatoric * 10))
        
        for i in range(aleatoric_segments):
            angle = 2 * np.pi * i / 32
            vertices.extend([aleatoric_radius * np.cos(angle), 0.15, aleatoric_radius * np.sin(angle)])
            colors.extend([0.3, 0.3, 0.9])  # Blue for data uncertainty
        
        # Total uncertainty halo
        halo_radius = 1.5 + total
        halo_intensity = min(1.0, total * 5)
        
        for i in range(48):
            angle = 2 * np.pi * i / 48
            vertices.extend([halo_radius * np.cos(angle), 0.05, halo_radius * np.sin(angle)])
            
            # Fade color based on position
            t = i / 48
            colors.extend([
                0.5 + halo_intensity * 0.3 * np.sin(t * np.pi * 4),
                0.3 + halo_intensity * 0.2,
                0.7 - halo_intensity * 0.2
            ])
        
        # Prediction class indicator
        pred_base_idx = len(vertices) // 3
        pred_angle = 2 * np.pi * prediction / 10  # Assume 10 classes
        
        vertices.extend([0, cone_height + 0.2, 0])
        vertices.extend([0.3 * np.cos(pred_angle), cone_height + 0.4, 0.3 * np.sin(pred_angle)])
        colors.extend([0.9, 0.8, 0.2])
        colors.extend([1.0, 0.9, 0.3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.6, 0.5, 0.7),
            emissive=(0.12, 0.1, 0.14),
            metallic=0.2,
            roughness=0.5,
            opacity=0.8
        )
        
        uncertainty_obj = Object3D(
            name="uncertainty_quantification",
            position=(-4, 0, 0),
            mesh=mesh,
            material=material,
            data={"type": "uncertainty", "confidence": confidence, "total_uncertainty": total}
        )
        
        self.scene.add_object(uncertainty_obj)
        return uncertainty_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: GRAPH NEURAL NETWORK
    # =========================================================================

    def create_gnn_viz(self, gnn_data: dict) -> 'Object3D':
        """Create visualization for Graph Neural Network spatial reasoning."""
        import numpy as np
        
        num_clusters = gnn_data.get('spatial_clusters', 4)
        flow_vectors = gnn_data.get('flow_vectors', [])
        connectivity = gnn_data.get('graph_connectivity', 0.5)
        
        vertices = []
        colors = []
        indices = []
        
        # Create graph nodes in 3D grid
        grid_size = 4
        node_idx = 0
        node_positions = []
        
        for x in range(grid_size):
            for y in range(grid_size):
                for z in range(grid_size):
                    # Node sphere
                    cx, cy, cz = (x - 1.5) * 0.4, (y - 1.5) * 0.4, (z - 1.5) * 0.4
                    node_positions.append((cx, cy, cz))
                    
                    # Color based on cluster
                    cluster = (x + y + z) % num_clusters
                    cluster_colors = [
                        (0.9, 0.3, 0.3), (0.3, 0.9, 0.3),
                        (0.3, 0.3, 0.9), (0.9, 0.9, 0.3)
                    ]
                    color = cluster_colors[cluster % len(cluster_colors)]
                    
                    # Add node vertices
                    for theta in range(4):
                        for phi in range(4):
                            t = theta * np.pi / 3
                            p = phi * 2 * np.pi / 4
                            r = 0.05
                            
                            vx = cx + r * np.sin(t) * np.cos(p)
                            vy = cy + r * np.sin(t) * np.sin(p)
                            vz = cz + r * np.cos(t)
                            
                            vertices.extend([vx, vy, vz])
                            colors.extend(color)
                    
                    node_idx += 1
        
        # Add edges between nearby nodes
        for i, (x1, y1, z1) in enumerate(node_positions):
            for j, (x2, y2, z2) in enumerate(node_positions):
                if i < j:
                    dist = np.sqrt((x1-x2)**2 + (y1-y2)**2 + (z1-z2)**2)
                    if dist < 0.6 and np.random.rand() < connectivity:
                        # Edge line
                        base_idx = len(vertices) // 3
                        vertices.extend([x1, y1, z1])
                        vertices.extend([x2, y2, z2])
                        colors.extend([0.4, 0.6, 0.8])
                        colors.extend([0.4, 0.6, 0.8])
                        indices.extend([base_idx, base_idx + 1])
        
        # Add flow arrows
        for i, flow in enumerate(flow_vectors[:4]):
            if isinstance(flow, dict):
                magnitude = flow.get('magnitude', 0.3)
                direction = flow.get('direction', [1, 0, 0])
                
                base_pos = node_positions[i * 16] if i * 16 < len(node_positions) else (0, 0, 0)
                
                base_idx = len(vertices) // 3
                vertices.extend(base_pos)
                end_pos = (
                    base_pos[0] + direction[0] * magnitude * 2,
                    base_pos[1] + direction[1] * magnitude * 2 if len(direction) > 1 else base_pos[1],
                    base_pos[2] + direction[2] * magnitude * 2 if len(direction) > 2 else base_pos[2]
                )
                vertices.extend(end_pos)
                colors.extend([1.0, 0.8, 0.2])
                colors.extend([1.0, 0.4, 0.1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.6, 0.8),
            emissive=(0.1, 0.12, 0.15),
            metallic=0.3,
            roughness=0.6,
            opacity=0.85
        )
        
        gnn_obj = Object3D(
            name="graph_neural_network",
            position=(5, 0, 0),
            mesh=mesh,
            material=material,
            data={"type": "gnn", "clusters": num_clusters, "connectivity": connectivity}
        )
        
        self.scene.add_object(gnn_obj)
        return gnn_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: TRANSFORMER ENCODER
    # =========================================================================

    def create_transformer_viz(self, transformer_data: dict) -> 'Object3D':
        """Create visualization for Transformer encoder with attention patterns."""
        import numpy as np
        
        seq_length = transformer_data.get('sequence_length', 64)
        cls_activation = transformer_data.get('cls_activation', 0.5)
        recon_error = transformer_data.get('reconstruction_error', 0.1)
        
        vertices = []
        colors = []
        indices = []
        
        # Sequence positions as vertical bars
        num_display = min(32, seq_length)
        bar_spacing = 0.1
        
        for i in range(num_display):
            x = (i - num_display / 2) * bar_spacing
            height = 0.3 + np.random.rand() * 0.4
            
            # Bar quad
            base_idx = len(vertices) // 3
            vertices.extend([x - 0.02, 0, -0.02])
            vertices.extend([x + 0.02, 0, -0.02])
            vertices.extend([x + 0.02, height, -0.02])
            vertices.extend([x - 0.02, height, -0.02])
            
            # Color gradient based on position
            t = i / num_display
            color = (0.3 + 0.4 * t, 0.5 + 0.3 * (1 - t), 0.8)
            for _ in range(4):
                colors.extend(color)
            
            indices.extend([base_idx, base_idx + 1, base_idx + 2])
            indices.extend([base_idx, base_idx + 2, base_idx + 3])
        
        # CLS token (special marker)
        cls_x = -num_display / 2 * bar_spacing - 0.3
        cls_height = 0.5 + cls_activation * 0.5
        
        for theta in range(8):
            for phi in range(8):
                t = theta * np.pi / 7
                p = phi * 2 * np.pi / 8
                r = 0.08
                
                vertices.extend([
                    cls_x + r * np.sin(t) * np.cos(p),
                    cls_height + r * np.sin(t) * np.sin(p),
                    r * np.cos(t)
                ])
                colors.extend([0.9, 0.7, 0.2])  # Gold for CLS
        
        # Attention arcs between positions
        for _ in range(8):
            src = np.random.randint(num_display)
            tgt = np.random.randint(num_display)
            if src != tgt:
                x1 = (src - num_display / 2) * bar_spacing
                x2 = (tgt - num_display / 2) * bar_spacing
                
                # Curved arc
                base_idx = len(vertices) // 3
                for t in np.linspace(0, 1, 10):
                    x = x1 + t * (x2 - x1)
                    y = 0.8 + 0.3 * np.sin(t * np.pi)
                    vertices.extend([x, y, 0])
                    colors.extend([0.5, 0.8, 0.9, 0.5])  # Semi-transparent
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.4, 0.5, 0.7),
            emissive=(0.08, 0.1, 0.14),
            metallic=0.4,
            roughness=0.4,
            opacity=0.9
        )
        
        transformer_obj = Object3D(
            name="transformer_encoder",
            position=(5, 0, 3),
            mesh=mesh,
            material=material,
            data={"type": "transformer", "seq_length": seq_length, "cls_activation": cls_activation}
        )
        
        self.scene.add_object(transformer_obj)
        return transformer_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: REINFORCEMENT LEARNING AGENT
    # =========================================================================

    def create_rl_agent_viz(self, rl_data: dict) -> 'Object3D':
        """Create visualization for Reinforcement Learning sensing agent."""
        import numpy as np
        
        episode_reward = rl_data.get('episode_reward', 0.0)
        exploration_noise = rl_data.get('exploration_noise', 0.1)
        buffer_size = rl_data.get('buffer_size', 100)
        state_value = rl_data.get('state_value', 0.5)
        
        vertices = []
        colors = []
        indices = []
        
        # Agent sphere
        agent_radius = 0.2 + state_value * 0.1
        for theta in range(12):
            for phi in range(12):
                t = theta * np.pi / 11
                p = phi * 2 * np.pi / 12
                
                vertices.extend([
                    agent_radius * np.sin(t) * np.cos(p),
                    agent_radius * np.sin(t) * np.sin(p) + 0.5,
                    agent_radius * np.cos(t)
                ])
                
                # Color based on value
                value_color = (0.2 + state_value * 0.6, 0.7 - state_value * 0.3, 0.3)
                colors.extend(value_color)
        
        # Exploration cloud (noise visualization)
        num_noise_points = int(20 * exploration_noise * 10)
        for _ in range(num_noise_points):
            offset = np.random.randn(3) * exploration_noise * 2
            vertices.extend([offset[0], offset[1] + 0.5, offset[2]])
            colors.extend([0.8, 0.8, 0.9])
        
        # Reward trail
        reward_norm = np.clip(episode_reward / 100, -1, 1)
        trail_length = 20
        for i in range(trail_length):
            t = i / trail_length
            x = np.cos(t * 4 * np.pi) * 0.5
            y = t * 1.5
            z = np.sin(t * 4 * np.pi) * 0.5
            
            base_idx = len(vertices) // 3
            vertices.extend([x, y, z])
            
            if reward_norm > 0:
                colors.extend([0.2 + reward_norm * 0.6, 0.8, 0.3])
            else:
                colors.extend([0.8, 0.3 + abs(reward_norm) * 0.3, 0.2])
        
        # Action arrows (4 directions)
        action = rl_data.get('action', [0.5, 0.3, -0.2, 0.1])
        for i, a in enumerate(action[:4]):
            angle = i * np.pi / 2
            length = abs(a) * 0.3
            
            base_idx = len(vertices) // 3
            vertices.extend([0, 0.5, 0])
            vertices.extend([
                length * np.cos(angle),
                0.5 + length * 0.3,
                length * np.sin(angle)
            ])
            
            if a > 0:
                colors.extend([0.3, 0.9, 0.4])
                colors.extend([0.5, 1.0, 0.6])
            else:
                colors.extend([0.9, 0.4, 0.3])
                colors.extend([1.0, 0.6, 0.5])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.7, 0.5),
            emissive=(0.1, 0.15, 0.1),
            metallic=0.3,
            roughness=0.5,
            opacity=0.85
        )
        
        rl_obj = Object3D(
            name="rl_sensing_agent",
            position=(5, 0, -3),
            mesh=mesh,
            material=material,
            data={"type": "rl_agent", "reward": episode_reward, "exploration": exploration_noise}
        )
        
        self.scene.add_object(rl_obj)
        return rl_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: DIFFUSION MODEL GENERATOR
    # =========================================================================

    def create_diffusion_viz(self, diffusion_data: dict) -> 'Object3D':
        """Create visualization for Diffusion model CSI generation."""
        import numpy as np
        
        quality = diffusion_data.get('reconstruction_quality', 0.5)
        training_loss = diffusion_data.get('training_loss', 0.5)
        num_generated = diffusion_data.get('num_generated', 10)
        
        vertices = []
        colors = []
        indices = []
        
        # Noise-to-signal progression (diffusion steps)
        num_steps = 10
        for step in range(num_steps):
            t = step / (num_steps - 1)
            noise_level = 1.0 - t
            
            # Ring at each step
            ring_y = step * 0.15
            ring_radius = 0.4 - noise_level * 0.2
            
            for i in range(24):
                angle = 2 * np.pi * i / 24
                
                # Add noise to position based on step
                noise_offset = np.random.randn(3) * noise_level * 0.1
                
                vertices.extend([
                    ring_radius * np.cos(angle) + noise_offset[0],
                    ring_y + noise_offset[1],
                    ring_radius * np.sin(angle) + noise_offset[2]
                ])
                
                # Color: noisy (purple) -> clean (green)
                color = (
                    0.6 * noise_level + 0.2 * (1 - noise_level),
                    0.2 * noise_level + 0.8 * (1 - noise_level),
                    0.8 * noise_level + 0.3 * (1 - noise_level)
                )
                colors.extend(color)
        
        # Generated samples (floating particles)
        for i in range(num_generated):
            angle = 2 * np.pi * i / num_generated
            radius = 0.6 + 0.2 * np.sin(i * 0.5)
            
            for j in range(6):
                theta = j * np.pi / 5
                r = 0.03
                vertices.extend([
                    radius * np.cos(angle) + r * np.cos(theta),
                    1.5 + r * np.sin(theta) + i * 0.02,
                    radius * np.sin(angle)
                ])
                colors.extend([0.3, 0.9, 0.5])
        
        # Quality indicator (central beam)
        beam_height = quality * 2.0
        for i in range(16):
            angle = 2 * np.pi * i / 16
            r = 0.05
            
            base_idx = len(vertices) // 3
            vertices.extend([r * np.cos(angle), 0, r * np.sin(angle)])
            vertices.extend([r * 0.5 * np.cos(angle), beam_height, r * 0.5 * np.sin(angle)])
            
            colors.extend([0.2, 0.6, 0.9])
            colors.extend([0.4, 0.9, 1.0])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.4, 0.6, 0.7),
            emissive=(0.08, 0.12, 0.14),
            metallic=0.25,
            roughness=0.5,
            opacity=0.88
        )
        
        diffusion_obj = Object3D(
            name="diffusion_generator",
            position=(-5, 0, 3),
            mesh=mesh,
            material=material,
            data={"type": "diffusion", "quality": quality, "samples": num_generated}
        )
        
        self.scene.add_object(diffusion_obj)
        return diffusion_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: NEURAL ODE DYNAMICS
    # =========================================================================

    def create_neural_ode_viz(self, ode_data: dict) -> 'Object3D':
        """Create visualization for Neural ODE continuous dynamics."""
        import numpy as np
        
        trajectory_length = ode_data.get('trajectory_length', 50)
        stability_margin = ode_data.get('stability_margin', 0.5)
        state_norm = ode_data.get('state_norm', 1.0)
        
        vertices = []
        colors = []
        indices = []
        
        # Phase space trajectory (3D Lorenz-like attractor visualization)
        for i in range(100):
            t = i / 100
            
            # Parametric curve
            x = np.sin(t * 4 * np.pi) * (1 + 0.3 * np.sin(t * 13 * np.pi))
            y = t * 2
            z = np.cos(t * 4 * np.pi) * (1 + 0.3 * np.cos(t * 17 * np.pi))
            
            scale = 0.5
            vertices.extend([x * scale, y, z * scale])
            
            # Color based on velocity (derivative)
            velocity = abs(np.cos(t * 4 * np.pi))
            colors.extend([0.3 + velocity * 0.5, 0.5, 0.8 - velocity * 0.3])
        
        # Stability region (ellipsoid if stable)
        if stability_margin > 0:
            for theta in range(8):
                for phi in range(16):
                    t = theta * np.pi / 7
                    p = phi * 2 * np.pi / 16
                    r = 0.3 * stability_margin
                    
                    vertices.extend([
                        r * np.sin(t) * np.cos(p),
                        1.0 + r * np.sin(t) * np.sin(p),
                        r * np.cos(t)
                    ])
                    colors.extend([0.2, 0.8, 0.4])  # Green = stable
        else:
            # Unstable: red spikes
            for i in range(8):
                angle = 2 * np.pi * i / 8
                vertices.extend([0, 1.0, 0])
                vertices.extend([0.5 * np.cos(angle), 1.5, 0.5 * np.sin(angle)])
                colors.extend([0.9, 0.2, 0.2])
                colors.extend([1.0, 0.4, 0.3])
        
        # State vector indicator
        state_scale = min(state_norm, 2.0)
        vertices.extend([0, 0, 0])
        vertices.extend([state_scale * 0.3, state_scale * 0.3, state_scale * 0.3])
        colors.extend([0.9, 0.7, 0.2])
        colors.extend([1.0, 0.9, 0.4])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.5, 0.7),
            emissive=(0.1, 0.1, 0.14),
            metallic=0.35,
            roughness=0.45,
            opacity=0.9
        )
        
        ode_obj = Object3D(
            name="neural_ode_dynamics",
            position=(-5, 0, -3),
            mesh=mesh,
            material=material,
            data={"type": "neural_ode", "stability": stability_margin, "trajectory": trajectory_length}
        )
        
        self.scene.add_object(ode_obj)
        return ode_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: VAE LATENT SPACE
    # =========================================================================

    def create_vae_latent_viz(self, vae_data: dict) -> 'Object3D':
        """Create visualization for VAE probabilistic latent space."""
        import numpy as np
        
        latent_mean = vae_data.get('latent_mean', [0] * 8)[:8]
        latent_std = vae_data.get('latent_std', [1] * 8)[:8]
        kl_loss = vae_data.get('kl_loss', 0.5)
        active_dims = vae_data.get('active_dimensions', 4)
        
        vertices = []
        colors = []
        indices = []
        
        # Latent dimensions as Gaussian ellipsoids
        for i, (mu, std) in enumerate(zip(latent_mean, latent_std)):
            angle = 2 * np.pi * i / len(latent_mean)
            radius = 0.6
            
            cx = radius * np.cos(angle)
            cz = radius * np.sin(angle)
            cy = mu * 0.2  # Height based on mean
            
            # Ellipsoid size based on std
            rx = std * 0.15
            ry = std * 0.15
            rz = std * 0.15
            
            # Draw ellipsoid
            for theta in range(6):
                for phi in range(6):
                    t = theta * np.pi / 5
                    p = phi * 2 * np.pi / 6
                    
                    vertices.extend([
                        cx + rx * np.sin(t) * np.cos(p),
                        cy + ry * np.sin(t) * np.sin(p),
                        cz + rz * np.cos(t)
                    ])
                    
                    # Active dimensions are brighter
                    if i < active_dims:
                        colors.extend([0.3, 0.8, 0.9])
                    else:
                        colors.extend([0.5, 0.5, 0.6])
        
        # KL divergence visualization (central indicator)
        kl_height = min(kl_loss * 0.5, 2.0)
        for i in range(12):
            angle = 2 * np.pi * i / 12
            r = 0.1
            
            vertices.extend([r * np.cos(angle), 0, r * np.sin(angle)])
            vertices.extend([r * 0.7 * np.cos(angle), kl_height, r * 0.7 * np.sin(angle)])
            colors.extend([0.8, 0.3, 0.3])
            colors.extend([0.9, 0.5, 0.4])
        
        # Sampling paths (random walk in latent space)
        for _ in range(5):
            path_vertices = []
            x, y, z = 0, 0, 0
            for step in range(10):
                x += np.random.randn() * 0.1
                y += np.random.randn() * 0.1
                z += np.random.randn() * 0.1
                vertices.extend([x, y + 0.5, z])
                colors.extend([0.9, 0.8, 0.3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.6, 0.7),
            emissive=(0.1, 0.12, 0.14),
            metallic=0.3,
            roughness=0.5,
            opacity=0.85
        )
        
        vae_obj = Object3D(
            name="vae_latent_space",
            position=(0, 0, 5),
            mesh=mesh,
            material=material,
            data={"type": "vae", "active_dims": active_dims, "kl_loss": kl_loss}
        )
        
        self.scene.add_object(vae_obj)
        return vae_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: SPIKING NEURAL NETWORK
    # =========================================================================

    def create_snn_viz(self, snn_data: dict) -> 'Object3D':
        """Create visualization for Spiking Neural Network neuromorphic processing."""
        import numpy as np
        
        output_rates = snn_data.get('output_rates', [0.5] * 16)
        hidden_spike_rate = snn_data.get('hidden_spike_rate', 0.3)
        total_spikes = snn_data.get('total_spikes', 100)
        energy = snn_data.get('energy_estimate', 0.001)
        
        vertices = []
        colors = []
        indices = []
        
        # Neuron grid (hidden layer)
        grid_size = 8
        for x in range(grid_size):
            for z in range(grid_size):
                cx = (x - grid_size / 2) * 0.15
                cz = (z - grid_size / 2) * 0.15
                
                # Neuron membrane potential (random visualization)
                potential = np.random.rand()
                height = 0.05 + potential * 0.1
                
                # Spike flash if above threshold
                is_spiking = potential > 0.8
                
                for theta in range(4):
                    for phi in range(4):
                        t = theta * np.pi / 3
                        p = phi * 2 * np.pi / 4
                        r = 0.03
                        
                        vertices.extend([
                            cx + r * np.sin(t) * np.cos(p),
                            height + r * np.sin(t) * np.sin(p),
                            cz + r * np.cos(t)
                        ])
                        
                        if is_spiking:
                            colors.extend([1.0, 0.9, 0.3])  # Yellow spike
                        else:
                            colors.extend([0.3, 0.4, 0.6])  # Resting blue
        
        # Output neurons (larger)
        for i, rate in enumerate(output_rates[:16]):
            angle = 2 * np.pi * i / 16
            radius = 0.8
            
            cx = radius * np.cos(angle)
            cz = radius * np.sin(angle)
            cy = 0.4 + rate * 0.3
            
            for theta in range(6):
                for phi in range(6):
                    t = theta * np.pi / 5
                    p = phi * 2 * np.pi / 6
                    r = 0.05 + rate * 0.03
                    
                    vertices.extend([
                        cx + r * np.sin(t) * np.cos(p),
                        cy + r * np.sin(t) * np.sin(p),
                        cz + r * np.cos(t)
                    ])
                    
                    colors.extend([0.4 + rate * 0.5, 0.7, 0.3])
        
        # Spike traces (connections showing spike propagation)
        for _ in range(int(hidden_spike_rate * 50)):
            src_x = np.random.rand() * 0.8 - 0.4
            src_z = np.random.rand() * 0.8 - 0.4
            tgt_angle = np.random.rand() * 2 * np.pi
            
            vertices.extend([src_x, 0.1, src_z])
            vertices.extend([0.8 * np.cos(tgt_angle), 0.5, 0.8 * np.sin(tgt_angle)])
            colors.extend([0.8, 0.7, 0.2])
            colors.extend([0.4, 0.3, 0.1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.4, 0.5, 0.6),
            emissive=(0.08, 0.1, 0.12),
            metallic=0.2,
            roughness=0.6,
            opacity=0.9
        )
        
        snn_obj = Object3D(
            name="spiking_neural_network",
            position=(0, 0, -5),
            mesh=mesh,
            material=material,
            data={"type": "snn", "spike_rate": hidden_spike_rate, "energy": energy}
        )
        
        self.scene.add_object(snn_obj)
        return snn_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: WORLD MODEL
    # =========================================================================

    def create_world_model_viz(self, world_data: dict) -> 'Object3D':
        """Create visualization for World Model imagination and planning."""
        import numpy as np
        
        uncertainty = world_data.get('uncertainty', 0.3)
        imagination_horizon = world_data.get('imagination_horizon', 10)
        hidden_norm = world_data.get('hidden_state_norm', 1.0)
        
        vertices = []
        colors = []
        indices = []
        
        # Reality sphere (observed)
        for theta in range(10):
            for phi in range(10):
                t = theta * np.pi / 9
                p = phi * 2 * np.pi / 10
                r = 0.3
                
                vertices.extend([
                    r * np.sin(t) * np.cos(p),
                    r * np.sin(t) * np.sin(p),
                    r * np.cos(t)
                ])
                colors.extend([0.2, 0.7, 0.9])  # Blue for reality
        
        # Imagination trajectories (branching futures)
        num_branches = 4
        for branch in range(num_branches):
            angle = 2 * np.pi * branch / num_branches
            
            for step in range(imagination_horizon):
                t = step / imagination_horizon
                
                # Spiral outward
                radius = 0.3 + t * 0.5
                height = t * 1.0
                spread = t * 0.3
                
                x = radius * np.cos(angle + t * np.pi)
                z = radius * np.sin(angle + t * np.pi)
                y = height
                
                # Add uncertainty noise
                x += np.random.randn() * uncertainty * t * 0.2
                y += np.random.randn() * uncertainty * t * 0.2
                z += np.random.randn() * uncertainty * t * 0.2
                
                vertices.extend([x, y, z])
                
                # Color fades with uncertainty
                alpha = 1.0 - t * uncertainty
                colors.extend([0.9 * alpha, 0.7 * alpha, 0.3 * alpha])
        
        # Uncertainty cloud
        cloud_size = int(50 * uncertainty)
        for _ in range(cloud_size):
            offset = np.random.randn(3) * 0.5
            vertices.extend([offset[0], 1.0 + offset[1], offset[2]])
            colors.extend([0.7, 0.7, 0.8])
        
        # Hidden state representation (center tower)
        tower_height = min(hidden_norm * 0.5, 1.5)
        for i in range(16):
            angle = 2 * np.pi * i / 16
            r = 0.08
            
            vertices.extend([r * np.cos(angle), 0, r * np.sin(angle)])
            vertices.extend([r * 0.6 * np.cos(angle), tower_height, r * 0.6 * np.sin(angle)])
            colors.extend([0.8, 0.5, 0.2])
            colors.extend([0.9, 0.7, 0.3])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.5, 0.6),
            emissive=(0.1, 0.1, 0.12),
            metallic=0.25,
            roughness=0.55,
            opacity=0.85
        )
        
        world_obj = Object3D(
            name="world_model",
            position=(3, 0, 4),
            mesh=mesh,
            material=material,
            data={"type": "world_model", "uncertainty": uncertainty, "horizon": imagination_horizon}
        )
        
        self.scene.add_object(world_obj)
        return world_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: HTM TEMPORAL MEMORY
    # =========================================================================

    def create_htm_viz(self, htm_data: dict) -> 'Object3D':
        """Create visualization for Hierarchical Temporal Memory."""
        import numpy as np
        
        active_columns = htm_data.get('active_column_count', 40)
        predictive_cells = htm_data.get('predictive_cell_count', 100)
        anomaly_score = htm_data.get('anomaly_score', 0.2)
        sparsity = htm_data.get('sparsity', 0.02)
        
        vertices = []
        colors = []
        indices = []
        
        # Column grid
        grid_size = 16
        for x in range(grid_size):
            for z in range(grid_size):
                cx = (x - grid_size / 2) * 0.1
                cz = (z - grid_size / 2) * 0.1
                
                # Active column is taller
                is_active = np.random.rand() < sparsity * 5
                height = 0.3 if is_active else 0.1
                
                # Column as thin box
                w = 0.03
                base_idx = len(vertices) // 3
                
                vertices.extend([cx - w, 0, cz - w])
                vertices.extend([cx + w, 0, cz - w])
                vertices.extend([cx + w, height, cz - w])
                vertices.extend([cx - w, height, cz - w])
                
                if is_active:
                    color = (0.2, 0.9, 0.4)  # Green for active
                else:
                    color = (0.4, 0.4, 0.5)  # Gray for inactive
                
                for _ in range(4):
                    colors.extend(color)
                
                indices.extend([base_idx, base_idx + 1, base_idx + 2])
                indices.extend([base_idx, base_idx + 2, base_idx + 3])
        
        # Predictive cells (floating above)
        num_pred_display = min(predictive_cells // 10, 20)
        for i in range(num_pred_display):
            x = np.random.rand() * 1.4 - 0.7
            z = np.random.rand() * 1.4 - 0.7
            y = 0.5 + np.random.rand() * 0.2
            
            for theta in range(4):
                for phi in range(4):
                    t = theta * np.pi / 3
                    p = phi * 2 * np.pi / 4
                    r = 0.02
                    
                    vertices.extend([x + r * np.sin(t) * np.cos(p), y + r * np.sin(t) * np.sin(p), z + r * np.cos(t)])
                    colors.extend([0.9, 0.7, 0.2])  # Orange for predictive
        
        # Anomaly indicator (red ring when anomalous)
        if anomaly_score > 0.3:
            ring_radius = 0.8 + anomaly_score * 0.2
            for i in range(32):
                angle = 2 * np.pi * i / 32
                vertices.extend([ring_radius * np.cos(angle), 0.05, ring_radius * np.sin(angle)])
                colors.extend([0.9, 0.2 + anomaly_score * 0.3, 0.2])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.6, 0.5),
            emissive=(0.1, 0.12, 0.1),
            metallic=0.2,
            roughness=0.6,
            opacity=0.9
        )
        
        htm_obj = Object3D(
            name="hierarchical_temporal_memory",
            position=(-3, 0, 4),
            mesh=mesh,
            material=material,
            data={"type": "htm", "active_columns": active_columns, "anomaly": anomaly_score}
        )
        
        self.scene.add_object(htm_obj)
        return htm_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: NORMALIZING FLOW
    # =========================================================================

    def create_flow_viz(self, flow_data: dict) -> 'Object3D':
        """Create visualization for Normalizing Flow density estimation."""
        import numpy as np
        
        log_likelihood = flow_data.get('log_likelihood', -50)
        z_norm = flow_data.get('z_norm', 1.0)
        bits_per_dim = flow_data.get('bits_per_dim', 5.0)
        
        vertices = []
        colors = []
        indices = []
        
        # Flow transformation (warped grid)
        grid_res = 10
        for x in range(grid_res):
            for z in range(grid_res):
                # Original grid point
                gx = (x - grid_res / 2) * 0.15
                gz = (z - grid_res / 2) * 0.15
                
                # Apply flow-like transformation
                scale = 1.0 + 0.3 * np.sin(gx * 3) * np.cos(gz * 3)
                tx = gx * scale
                tz = gz * scale
                ty = 0.2 * np.sin(gx * 4 + gz * 4)
                
                # Draw transformed point
                for theta in range(4):
                    for phi in range(4):
                        t = theta * np.pi / 3
                        p = phi * 2 * np.pi / 4
                        r = 0.02
                        
                        vertices.extend([tx + r * np.sin(t) * np.cos(p), ty + r * np.sin(t) * np.sin(p), tz + r * np.cos(t)])
                        
                        # Color by local density
                        density = np.exp(-0.5 * (gx ** 2 + gz ** 2))
                        colors.extend([0.3 + density * 0.5, 0.5 + density * 0.4, 0.8])
        
        # Likelihood contours (circles at different heights)
        ll_norm = max(0, min(1, (log_likelihood + 100) / 100))
        for level in range(5):
            radius = 0.3 + level * 0.15
            height = level * 0.1
            
            for i in range(24):
                angle = 2 * np.pi * i / 24
                vertices.extend([radius * np.cos(angle), height, radius * np.sin(angle)])
                colors.extend([0.2 + ll_norm * 0.6, 0.7 * ll_norm, 0.3])
        
        # Base distribution (Gaussian at origin)
        for theta in range(8):
            for phi in range(8):
                t = theta * np.pi / 7
                p = phi * 2 * np.pi / 8
                r = 0.15 * z_norm
                
                vertices.extend([
                    r * np.sin(t) * np.cos(p),
                    -0.3 + r * np.sin(t) * np.sin(p),
                    r * np.cos(t)
                ])
                colors.extend([0.8, 0.8, 0.9])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.6, 0.6, 0.7),
            emissive=(0.12, 0.12, 0.14),
            metallic=0.3,
            roughness=0.5,
            opacity=0.88
        )
        
        flow_obj = Object3D(
            name="normalizing_flow",
            position=(-3, 0, -4),
            mesh=mesh,
            material=material,
            data={"type": "flow", "log_likelihood": log_likelihood, "bits_per_dim": bits_per_dim}
        )
        
        self.scene.add_object(flow_obj)
        return flow_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: CAPSULE NETWORK
    # =========================================================================

    def create_capsnet_viz(self, caps_data: dict) -> 'Object3D':
        """Create visualization for Capsule Network hierarchical features."""
        import numpy as np
        
        capsule_norms = caps_data.get('capsule_norms', [0.5] * 10)
        predicted_class = caps_data.get('predicted_class', 0)
        agreement = caps_data.get('capsule_agreement', 0.7)
        
        vertices = []
        colors = []
        indices = []
        
        # Primary capsules (lower layer)
        num_primary = 32
        for i in range(num_primary):
            angle = 2 * np.pi * i / num_primary
            radius = 0.7
            
            cx = radius * np.cos(angle)
            cz = radius * np.sin(angle)
            cy = 0
            
            # Capsule as oriented ellipsoid
            for theta in range(4):
                for phi in range(4):
                    t = theta * np.pi / 3
                    p = phi * 2 * np.pi / 4
                    
                    # Oriented based on angle
                    rx = 0.04
                    ry = 0.06
                    rz = 0.04
                    
                    vertices.extend([
                        cx + rx * np.sin(t) * np.cos(p),
                        cy + ry * np.sin(t) * np.sin(p),
                        cz + rz * np.cos(t)
                    ])
                    colors.extend([0.4, 0.5, 0.7])
        
        # Digit capsules (upper layer)
        for i, norm in enumerate(capsule_norms):
            angle = 2 * np.pi * i / len(capsule_norms)
            radius = 0.4
            
            cx = radius * np.cos(angle)
            cz = radius * np.sin(angle)
            cy = 0.5
            
            # Size based on norm (activity)
            cap_size = 0.05 + norm * 0.08
            
            for theta in range(6):
                for phi in range(6):
                    t = theta * np.pi / 5
                    p = phi * 2 * np.pi / 6
                    
                    vertices.extend([
                        cx + cap_size * np.sin(t) * np.cos(p),
                        cy + cap_size * np.sin(t) * np.sin(p),
                        cz + cap_size * np.cos(t)
                    ])
                    
                    if i == predicted_class:
                        colors.extend([0.9, 0.7, 0.2])  # Gold for predicted
                    else:
                        colors.extend([0.3 + norm * 0.4, 0.5, 0.7])
        
        # Routing connections (agreement visualization)
        for i in range(int(agreement * 20)):
            # Connection from random primary to random digit
            src_angle = np.random.rand() * 2 * np.pi
            tgt_angle = np.random.rand() * 2 * np.pi
            
            vertices.extend([0.7 * np.cos(src_angle), 0, 0.7 * np.sin(src_angle)])
            vertices.extend([0.4 * np.cos(tgt_angle), 0.5, 0.4 * np.sin(tgt_angle)])
            colors.extend([0.6, 0.6, 0.8])
            colors.extend([0.4, 0.4, 0.6])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.5, 0.7),
            emissive=(0.1, 0.1, 0.14),
            metallic=0.35,
            roughness=0.45,
            opacity=0.9
        )
        
        caps_obj = Object3D(
            name="capsule_network",
            position=(3, 0, -4),
            mesh=mesh,
            material=material,
            data={"type": "capsnet", "predicted_class": predicted_class, "agreement": agreement}
        )
        
        self.scene.add_object(caps_obj)
        return caps_obj

    # =========================================================================
    # BREAKTHROUGH VISUALIZATION: MEMORY AUGMENTED NETWORK
    # =========================================================================

    def create_mann_viz(self, mann_data: dict) -> 'Object3D':
        """Create visualization for Memory-Augmented Neural Network."""
        import numpy as np
        
        memory_usage = mann_data.get('memory_usage', 0.3)
        read_entropy = mann_data.get('read_entropy', 2.0)
        write_entropy = mann_data.get('write_entropy', 2.0)
        memory_sparsity = mann_data.get('memory_sparsity', 0.8)
        
        vertices = []
        colors = []
        indices = []
        
        # Memory matrix (grid of cells)
        mem_rows = 8
        mem_cols = 16
        
        for row in range(mem_rows):
            for col in range(mem_cols):
                cx = (col - mem_cols / 2) * 0.08
                cz = (row - mem_rows / 2) * 0.08
                
                # Height based on content (random for viz)
                content = np.random.rand() if np.random.rand() > memory_sparsity else 0
                height = 0.02 + content * 0.1
                
                # Cell quad
                w = 0.03
                base_idx = len(vertices) // 3
                
                vertices.extend([cx - w, 0, cz - w])
                vertices.extend([cx + w, 0, cz - w])
                vertices.extend([cx + w, height, cz - w])
                vertices.extend([cx - w, height, cz - w])
                
                if content > 0.5:
                    color = (0.3, 0.8, 0.5)  # Active memory
                elif content > 0:
                    color = (0.5, 0.6, 0.7)  # Partial
                else:
                    color = (0.3, 0.3, 0.4)  # Empty
                
                for _ in range(4):
                    colors.extend(color)
                
                indices.extend([base_idx, base_idx + 1, base_idx + 2])
                indices.extend([base_idx, base_idx + 2, base_idx + 3])
        
        # Read head (beam scanning memory)
        read_pos = np.random.rand() * mem_cols * 0.08 - mem_cols * 0.04
        for i in range(8):
            angle = 2 * np.pi * i / 8
            vertices.extend([read_pos, 0.3, 0])
            vertices.extend([read_pos + 0.1 * np.cos(angle), 0.1, 0.1 * np.sin(angle)])
            colors.extend([0.2, 0.8, 0.9])
            colors.extend([0.4, 0.9, 1.0])
        
        # Write head (different color)
        write_pos = np.random.rand() * mem_cols * 0.08 - mem_cols * 0.04
        for i in range(8):
            angle = 2 * np.pi * i / 8
            vertices.extend([write_pos, 0.35, 0.1])
            vertices.extend([write_pos + 0.1 * np.cos(angle), 0.15, 0.1 + 0.1 * np.sin(angle)])
            colors.extend([0.9, 0.5, 0.2])
            colors.extend([1.0, 0.7, 0.4])
        
        # Controller (central sphere)
        for theta in range(8):
            for phi in range(8):
                t = theta * np.pi / 7
                p = phi * 2 * np.pi / 8
                r = 0.1
                
                vertices.extend([
                    r * np.sin(t) * np.cos(p),
                    0.5 + r * np.sin(t) * np.sin(p),
                    r * np.cos(t)
                ])
                colors.extend([0.7, 0.4, 0.8])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32) if indices else None,
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            diffuse=(0.5, 0.5, 0.6),
            emissive=(0.1, 0.1, 0.12),
            metallic=0.3,
            roughness=0.5,
            opacity=0.9
        )
        
        mann_obj = Object3D(
            name="memory_augmented_network",
            position=(0, 2, 0),
            mesh=mesh,
            material=material,
            data={"type": "mann", "memory_usage": memory_usage, "sparsity": memory_sparsity}
        )
        
        self.scene.add_object(mann_obj)
        return mann_obj
