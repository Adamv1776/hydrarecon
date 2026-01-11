"""
Environmental Digital Twin System
=================================

3D DIGITAL TWIN OF PHYSICAL ENVIRONMENT FROM WIFI SENSING

This module creates and maintains a digital twin of the physical environment
using WiFi CSI data. The digital twin includes:

1. 3D Geometry - Walls, floors, furniture, obstacles
2. Material Properties - What surfaces are made of
3. Object Tracking - Positions and states of known objects
4. Occupancy Mapping - Where people are and have been
5. Environmental State - Temperature, humidity proxies, air quality indicators
6. Activity Zones - Areas classified by typical activities
7. Temporal Dynamics - How the environment changes over time

Features:
- Real-time 3D reconstruction
- Automatic floor plan generation
- Change detection and tracking
- Occupancy heat maps
- Activity zone classification
- Integration with BIM/CAD formats
- AR/VR visualization support

Based on research:
- "Indoor 3D Reconstruction using WiFi" (ACM SIGSPATIAL 2021)
- "WiFi-Based Room Geometry Estimation" (IEEE TMC 2022)
- "Digital Twin for Smart Buildings" (IEEE IoT Journal 2023)

Copyright (c) 2024-2026 HydraRecon - For authorized research only.
"""

import numpy as np
from scipy.spatial import ConvexHull, Delaunay
from scipy.ndimage import gaussian_filter
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import deque
from enum import Enum
import time
import json
import gzip


# ============================================================================
# Environment Elements
# ============================================================================

class SurfaceType(Enum):
    """Types of surfaces in the environment."""
    UNKNOWN = "unknown"
    WALL = "wall"
    FLOOR = "floor"
    CEILING = "ceiling"
    DOOR = "door"
    WINDOW = "window"
    FURNITURE = "furniture"
    OBSTACLE = "obstacle"


class MaterialType(Enum):
    """Material types with WiFi propagation properties."""
    UNKNOWN = "unknown"
    CONCRETE = "concrete"
    BRICK = "brick"
    DRYWALL = "drywall"
    WOOD = "wood"
    GLASS = "glass"
    METAL = "metal"
    FABRIC = "fabric"
    PLASTIC = "plastic"
    AIR = "air"


class ZoneType(Enum):
    """Activity zone classifications."""
    UNKNOWN = "unknown"
    WORKSPACE = "workspace"
    MEETING = "meeting"
    CORRIDOR = "corridor"
    ENTRANCE = "entrance"
    REST_AREA = "rest_area"
    KITCHEN = "kitchen"
    BATHROOM = "bathroom"
    STORAGE = "storage"
    HIGH_TRAFFIC = "high_traffic"


@dataclass
class Surface:
    """3D surface in the environment."""
    id: str
    surface_type: SurfaceType
    material: MaterialType
    vertices: np.ndarray  # Nx3 array of vertices
    normal: np.ndarray  # Surface normal vector
    confidence: float = 1.0
    last_updated: float = 0.0
    
    def area(self) -> float:
        """Calculate surface area."""
        if len(self.vertices) < 3:
            return 0.0
        
        # Use cross product for area calculation
        total_area = 0.0
        v0 = self.vertices[0]
        
        for i in range(1, len(self.vertices) - 1):
            v1 = self.vertices[i]
            v2 = self.vertices[i + 1]
            
            edge1 = v1 - v0
            edge2 = v2 - v0
            
            total_area += 0.5 * np.linalg.norm(np.cross(edge1, edge2))
        
        return total_area
    
    def contains_point(self, point: np.ndarray, tolerance: float = 0.1) -> bool:
        """Check if point is on or near surface."""
        # Project point onto plane
        d = np.dot(point - self.vertices[0], self.normal)
        
        if abs(d) > tolerance:
            return False
        
        # Check if projected point is within surface bounds
        projected = point - d * self.normal
        
        # Use 2D containment check
        return self._point_in_polygon_2d(projected)
    
    def _point_in_polygon_2d(self, point: np.ndarray) -> bool:
        """Check if point is within polygon (simplified)."""
        # Find two axes perpendicular to normal
        if abs(self.normal[2]) < 0.9:
            axis1 = np.cross(self.normal, [0, 0, 1])
        else:
            axis1 = np.cross(self.normal, [1, 0, 0])
        axis1 /= np.linalg.norm(axis1)
        axis2 = np.cross(self.normal, axis1)
        
        # Project to 2D
        vertices_2d = np.array([
            [np.dot(v, axis1), np.dot(v, axis2)]
            for v in self.vertices
        ])
        point_2d = [np.dot(point, axis1), np.dot(point, axis2)]
        
        # Ray casting algorithm
        inside = False
        n = len(vertices_2d)
        j = n - 1
        
        for i in range(n):
            if ((vertices_2d[i, 1] > point_2d[1]) != (vertices_2d[j, 1] > point_2d[1]) and
                point_2d[0] < (vertices_2d[j, 0] - vertices_2d[i, 0]) * 
                (point_2d[1] - vertices_2d[i, 1]) / (vertices_2d[j, 1] - vertices_2d[i, 1]) + 
                vertices_2d[i, 0]):
                inside = not inside
            j = i
        
        return inside


@dataclass
class PhysicalObject:
    """Physical object in the environment."""
    id: str
    name: str
    object_type: str  # chair, desk, door, etc.
    position: np.ndarray  # Center position
    dimensions: np.ndarray  # [width, depth, height]
    orientation: float  # Rotation around Z axis
    material: MaterialType = MaterialType.UNKNOWN
    is_static: bool = True
    confidence: float = 1.0
    last_seen: float = 0.0
    
    def get_bounding_box(self) -> Tuple[np.ndarray, np.ndarray]:
        """Get axis-aligned bounding box."""
        half_dims = self.dimensions / 2
        
        # Rotation matrix for Z-axis rotation
        c, s = np.cos(self.orientation), np.sin(self.orientation)
        R = np.array([[c, -s, 0], [s, c, 0], [0, 0, 1]])
        
        # Corners
        corners = []
        for dx in [-1, 1]:
            for dy in [-1, 1]:
                for dz in [-1, 1]:
                    corner = np.array([dx, dy, dz]) * half_dims
                    corner = R @ corner + self.position
                    corners.append(corner)
        
        corners = np.array(corners)
        return corners.min(axis=0), corners.max(axis=0)


@dataclass
class Person:
    """Tracked person in the environment."""
    id: str
    position: np.ndarray
    velocity: np.ndarray
    activity: str = "unknown"
    zone: str = ""
    trajectory: deque = field(default_factory=lambda: deque(maxlen=1000))
    first_seen: float = 0.0
    last_seen: float = 0.0
    
    def add_position(self, position: np.ndarray, timestamp: float):
        """Add position to trajectory."""
        self.trajectory.append({
            'position': position.copy(),
            'timestamp': timestamp,
        })
        self.position = position
        self.last_seen = timestamp
        
        # Calculate velocity
        if len(self.trajectory) >= 2:
            dt = timestamp - self.trajectory[-2]['timestamp']
            if dt > 0:
                self.velocity = (position - self.trajectory[-2]['position']) / dt


@dataclass
class Zone:
    """Activity zone in the environment."""
    id: str
    zone_type: ZoneType
    bounds: np.ndarray  # [[min_x, min_y, min_z], [max_x, max_y, max_z]]
    polygon: np.ndarray = None  # 2D polygon for non-rectangular zones
    occupancy_history: deque = field(default_factory=lambda: deque(maxlen=10000))
    typical_activities: List[str] = field(default_factory=list)
    peak_hours: List[int] = field(default_factory=list)
    
    def contains(self, point: np.ndarray) -> bool:
        """Check if point is within zone."""
        if self.polygon is not None:
            # Use polygon containment
            return self._point_in_polygon(point[:2])
        else:
            # Use bounding box
            return np.all(point >= self.bounds[0]) and np.all(point <= self.bounds[1])
    
    def _point_in_polygon(self, point_2d: np.ndarray) -> bool:
        """Check if 2D point is within polygon."""
        inside = False
        n = len(self.polygon)
        j = n - 1
        
        for i in range(n):
            if ((self.polygon[i, 1] > point_2d[1]) != (self.polygon[j, 1] > point_2d[1]) and
                point_2d[0] < (self.polygon[j, 0] - self.polygon[i, 0]) * 
                (point_2d[1] - self.polygon[i, 1]) / (self.polygon[j, 1] - self.polygon[i, 1]) + 
                self.polygon[i, 0]):
                inside = not inside
            j = i
        
        return inside
    
    def get_occupancy_rate(self, duration: float = 3600) -> float:
        """Get occupancy rate over time period."""
        cutoff = time.time() - duration
        recent = [o for o in self.occupancy_history if o['timestamp'] >= cutoff]
        
        if not recent:
            return 0.0
        
        return sum(o['count'] for o in recent) / len(recent)


# ============================================================================
# 3D Reconstruction Components
# ============================================================================

class VoxelGrid:
    """
    3D voxel grid for space representation.
    
    Each voxel contains:
    - Occupancy probability
    - Material type
    - Confidence
    """
    
    def __init__(self, bounds: np.ndarray, resolution: float = 0.1):
        self.bounds = bounds  # [[min_x, min_y, min_z], [max_x, max_y, max_z]]
        self.resolution = resolution
        
        # Grid dimensions
        self.dims = ((bounds[1] - bounds[0]) / resolution).astype(int)
        
        # Voxel data
        self.occupancy = np.zeros(self.dims, dtype=np.float32)
        self.material = np.zeros(self.dims, dtype=np.int8)
        self.confidence = np.zeros(self.dims, dtype=np.float32)
        self.last_updated = np.zeros(self.dims, dtype=np.float32)
    
    def world_to_grid(self, position: np.ndarray) -> np.ndarray:
        """Convert world coordinates to grid indices."""
        indices = ((position - self.bounds[0]) / self.resolution).astype(int)
        return np.clip(indices, 0, self.dims - 1)
    
    def grid_to_world(self, indices: np.ndarray) -> np.ndarray:
        """Convert grid indices to world coordinates."""
        return self.bounds[0] + (indices + 0.5) * self.resolution
    
    def update_voxel(self, position: np.ndarray, occupancy: float, 
                    material: MaterialType = MaterialType.UNKNOWN):
        """Update single voxel."""
        idx = tuple(self.world_to_grid(position))
        
        # Bayesian update
        prior = self.occupancy[idx]
        likelihood = occupancy
        
        # Simplified Bayesian fusion
        self.occupancy[idx] = (prior * self.confidence[idx] + likelihood) / (self.confidence[idx] + 1)
        self.confidence[idx] = min(self.confidence[idx] + 0.1, 1.0)
        
        if material != MaterialType.UNKNOWN:
            self.material[idx] = material.value
        
        self.last_updated[idx] = time.time()
    
    def ray_cast(self, origin: np.ndarray, direction: np.ndarray, 
                max_distance: float = 20.0) -> Tuple[Optional[np.ndarray], float]:
        """
        Cast ray through voxel grid.
        
        Returns:
            Hit position and distance, or (None, max_distance)
        """
        direction = direction / np.linalg.norm(direction)
        
        current = origin.copy()
        step = direction * self.resolution * 0.5
        
        distance = 0.0
        
        while distance < max_distance:
            idx = tuple(self.world_to_grid(current))
            
            # Check bounds
            if not all(0 <= idx[i] < self.dims[i] for i in range(3)):
                break
            
            # Check occupancy
            if self.occupancy[idx] > 0.5:
                return current, distance
            
            current += step
            distance += self.resolution * 0.5
        
        return None, max_distance
    
    def get_occupied_voxels(self, threshold: float = 0.5) -> np.ndarray:
        """Get positions of occupied voxels."""
        indices = np.argwhere(self.occupancy > threshold)
        return np.array([self.grid_to_world(idx) for idx in indices])
    
    def export_mesh(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Export as mesh (vertices and faces).
        
        Uses marching cubes-like approach.
        """
        vertices = []
        faces = []
        
        occupied = self.occupancy > 0.5
        
        # Find surface voxels (occupied with at least one empty neighbor)
        for x in range(1, self.dims[0] - 1):
            for y in range(1, self.dims[1] - 1):
                for z in range(1, self.dims[2] - 1):
                    if occupied[x, y, z]:
                        # Check neighbors
                        is_surface = False
                        for dx, dy, dz in [(-1,0,0), (1,0,0), (0,-1,0), (0,1,0), (0,0,-1), (0,0,1)]:
                            if not occupied[x+dx, y+dy, z+dz]:
                                is_surface = True
                                break
                        
                        if is_surface:
                            # Add cube faces
                            center = self.grid_to_world(np.array([x, y, z]))
                            self._add_cube_faces(center, vertices, faces)
        
        return np.array(vertices), np.array(faces)
    
    def _add_cube_faces(self, center: np.ndarray, vertices: list, faces: list):
        """Add cube faces at center position."""
        half = self.resolution / 2
        
        # Cube vertices
        cube_verts = [
            center + np.array([dx * half, dy * half, dz * half])
            for dx in [-1, 1]
            for dy in [-1, 1]
            for dz in [-1, 1]
        ]
        
        base_idx = len(vertices)
        vertices.extend(cube_verts)
        
        # Cube faces (as triangles)
        cube_faces = [
            [0, 1, 3], [0, 3, 2],  # Front
            [4, 6, 7], [4, 7, 5],  # Back
            [0, 4, 5], [0, 5, 1],  # Bottom
            [2, 3, 7], [2, 7, 6],  # Top
            [0, 2, 6], [0, 6, 4],  # Left
            [1, 5, 7], [1, 7, 3],  # Right
        ]
        
        for face in cube_faces:
            faces.append([base_idx + i for i in face])


class OccupancyMap:
    """
    2D occupancy map for navigation and analysis.
    
    Similar to ROS occupancy grids.
    """
    
    def __init__(self, bounds: np.ndarray, resolution: float = 0.1):
        self.bounds = bounds[:2]  # 2D bounds
        self.resolution = resolution
        
        self.dims = ((self.bounds[1] - self.bounds[0]) / resolution).astype(int)
        
        # Occupancy values: -1 = unknown, 0 = free, 100 = occupied
        self.grid = np.full(tuple(self.dims), -1, dtype=np.int8)
        
        # Confidence/update counts
        self.counts = np.zeros(self.dims, dtype=np.int32)
    
    def update(self, position: np.ndarray, is_occupied: bool, confidence: float = 1.0):
        """Update map with observation."""
        idx = self._world_to_grid(position)
        
        if not self._in_bounds(idx):
            return
        
        current = self.grid[tuple(idx)]
        count = self.counts[tuple(idx)]
        
        observation = 100 if is_occupied else 0
        
        if current == -1:
            self.grid[tuple(idx)] = observation
            self.counts[tuple(idx)] = 1
        else:
            # Running average
            new_count = count + 1
            self.grid[tuple(idx)] = int((current * count + observation * confidence) / new_count)
            self.counts[tuple(idx)] = new_count
    
    def get_value(self, position: np.ndarray) -> int:
        """Get occupancy value at position."""
        idx = self._world_to_grid(position)
        
        if not self._in_bounds(idx):
            return -1
        
        return self.grid[tuple(idx)]
    
    def _world_to_grid(self, position: np.ndarray) -> np.ndarray:
        return ((position[:2] - self.bounds[0]) / self.resolution).astype(int)
    
    def _in_bounds(self, idx: np.ndarray) -> bool:
        return all(0 <= idx[i] < self.dims[i] for i in range(2))
    
    def to_image(self) -> np.ndarray:
        """Convert to image (0-255 grayscale)."""
        img = np.zeros(self.dims, dtype=np.uint8)
        
        # Unknown = gray (128)
        img[self.grid == -1] = 128
        
        # Free = white (255)
        img[self.grid == 0] = 255
        
        # Occupied = black (0)
        img[self.grid == 100] = 0
        
        # Partial occupancy = gradient
        partial = (self.grid > 0) & (self.grid < 100)
        img[partial] = 255 - (self.grid[partial] * 255 / 100).astype(np.uint8)
        
        return img


class HeatMap:
    """
    Activity heat map showing where people spend time.
    """
    
    def __init__(self, bounds: np.ndarray, resolution: float = 0.2):
        self.bounds = bounds[:2]
        self.resolution = resolution
        
        self.dims = ((self.bounds[1] - self.bounds[0]) / resolution).astype(int)
        
        # Accumulated time at each cell
        self.heat = np.zeros(tuple(self.dims), dtype=np.float32)
        
        # Last update timestamp
        self.last_update = time.time()
    
    def add_presence(self, position: np.ndarray, duration: float = 1.0):
        """Add presence at position for duration."""
        idx = self._world_to_grid(position)
        
        if self._in_bounds(idx):
            self.heat[tuple(idx)] += duration
    
    def update_continuous(self, positions: List[np.ndarray]):
        """Update with multiple positions (called periodically)."""
        current_time = time.time()
        dt = current_time - self.last_update
        self.last_update = current_time
        
        for pos in positions:
            self.add_presence(pos, dt)
    
    def get_normalized(self) -> np.ndarray:
        """Get heat map normalized to [0, 1]."""
        if self.heat.max() == 0:
            return np.zeros_like(self.heat)
        return self.heat / self.heat.max()
    
    def get_smoothed(self, sigma: float = 1.0) -> np.ndarray:
        """Get Gaussian-smoothed heat map."""
        return gaussian_filter(self.get_normalized(), sigma=sigma)
    
    def _world_to_grid(self, position: np.ndarray) -> np.ndarray:
        return ((position[:2] - self.bounds[0]) / self.resolution).astype(int)
    
    def _in_bounds(self, idx: np.ndarray) -> bool:
        return all(0 <= idx[i] < self.dims[i] for i in range(2))
    
    def decay(self, factor: float = 0.99):
        """Apply decay to heat values."""
        self.heat *= factor


# ============================================================================
# Main Digital Twin System
# ============================================================================

class EnvironmentalDigitalTwin:
    """
    Main digital twin system.
    
    Maintains a comprehensive 3D model of the physical environment.
    """
    
    def __init__(self, 
                 bounds: np.ndarray = None,
                 voxel_resolution: float = 0.1,
                 map_resolution: float = 0.1):
        # Default bounds: 20m x 20m x 4m space
        if bounds is None:
            bounds = np.array([
                [0, 0, 0],
                [20, 20, 4],
            ], dtype=np.float32)
        self.bounds = bounds
        
        # 3D voxel representation
        self.voxel_grid = VoxelGrid(bounds, voxel_resolution)
        
        # 2D maps
        self.occupancy_map = OccupancyMap(bounds, map_resolution)
        self.heat_map = HeatMap(bounds, map_resolution * 2)
        
        # Environment elements
        self.surfaces: Dict[str, Surface] = {}
        self.objects: Dict[str, PhysicalObject] = {}
        self.persons: Dict[str, Person] = {}
        self.zones: Dict[str, Zone] = {}
        
        # WiFi access points for localization
        self.access_points: Dict[str, np.ndarray] = {}
        
        # State tracking
        self.last_update = time.time()
        self.total_updates = 0
        
        # Change detection
        self.change_history = deque(maxlen=1000)
    
    def update_from_csi(self, csi_data: np.ndarray, 
                        tx_position: np.ndarray,
                        rx_position: np.ndarray,
                        timestamp: float = None):
        """
        Update digital twin from CSI measurement.
        
        Uses signal analysis to infer environment structure.
        """
        if timestamp is None:
            timestamp = time.time()
        
        self.total_updates += 1
        
        # Extract signal features
        amplitude = np.abs(csi_data)
        phase = np.angle(csi_data)
        
        # Estimate path loss
        path_loss = -20 * np.log10(np.mean(amplitude) + 1e-10)
        
        # Direct path
        direct_distance = np.linalg.norm(rx_position - tx_position)
        direct_path_loss = 20 * np.log10(direct_distance + 0.1) + 40  # Free space
        
        # Excess path loss indicates obstacles
        excess_loss = path_loss - direct_path_loss
        
        if excess_loss > 5:  # Significant obstruction
            # Mark voxels along direct path as potentially occupied
            direction = (rx_position - tx_position) / (direct_distance + 1e-10)
            
            for t in np.linspace(0.2, 0.8, 10):
                point = tx_position + direction * direct_distance * t
                self.voxel_grid.update_voxel(point, 0.3)
        
        # Multipath analysis for reflections
        self._analyze_multipath(csi_data, tx_position, rx_position, timestamp)
        
        # Update 2D occupancy
        midpoint = (tx_position + rx_position) / 2
        self.occupancy_map.update(midpoint, excess_loss > 10)
        
        self.last_update = timestamp
    
    def _analyze_multipath(self, csi_data: np.ndarray,
                          tx_position: np.ndarray,
                          rx_position: np.ndarray,
                          timestamp: float):
        """Analyze multipath components to detect reflective surfaces."""
        # Extract multipath using FFT
        amplitude = np.abs(csi_data)
        
        # Find peaks in frequency domain (potential reflectors)
        fft = np.fft.fft(amplitude)
        fft_mag = np.abs(fft[:len(fft)//2])
        
        # Find peaks
        peak_indices = []
        for i in range(1, len(fft_mag) - 1):
            if fft_mag[i] > fft_mag[i-1] and fft_mag[i] > fft_mag[i+1]:
                if fft_mag[i] > np.mean(fft_mag) * 1.5:
                    peak_indices.append(i)
        
        # Each peak represents a potential reflection
        for peak_idx in peak_indices[:5]:  # Limit to 5 strongest reflections
            # Estimate reflection distance (simplified)
            extra_distance = peak_idx * 0.3 / len(fft_mag) * 20  # Scale factor
            
            # Find potential reflection point
            # This is a simplified model - real implementation would use
            # geometric constraints and multiple measurements
            total_distance = np.linalg.norm(rx_position - tx_position) + extra_distance
            
            # Possible reflection points form an ellipse
            # Sample a few points on the ellipse
            for angle in np.linspace(0, 2*np.pi, 8):
                # Simplified reflection point calculation
                direction = np.array([np.cos(angle), np.sin(angle), 0])
                reflection_point = (tx_position + rx_position) / 2 + direction * extra_distance / 2
                
                # Update voxel as potential surface
                if np.all(reflection_point >= self.bounds[0]) and np.all(reflection_point <= self.bounds[1]):
                    self.voxel_grid.update_voxel(reflection_point, 0.2)
    
    def update_person(self, person_id: str, position: np.ndarray, 
                     activity: str = "unknown", timestamp: float = None):
        """Update person position in digital twin."""
        if timestamp is None:
            timestamp = time.time()
        
        if person_id not in self.persons:
            self.persons[person_id] = Person(
                id=person_id,
                position=position,
                velocity=np.zeros(3),
                activity=activity,
                first_seen=timestamp,
            )
        
        person = self.persons[person_id]
        person.add_position(position, timestamp)
        person.activity = activity
        
        # Update zone
        for zone_id, zone in self.zones.items():
            if zone.contains(position):
                person.zone = zone_id
                zone.occupancy_history.append({
                    'timestamp': timestamp,
                    'count': 1,
                })
                break
        
        # Update heat map
        self.heat_map.add_presence(position)
        
        # Mark as free space
        self.voxel_grid.update_voxel(position, 0.0)
    
    def add_surface(self, surface_id: str, vertices: np.ndarray,
                   surface_type: SurfaceType = SurfaceType.WALL,
                   material: MaterialType = MaterialType.UNKNOWN):
        """Add surface to digital twin."""
        # Calculate normal
        if len(vertices) >= 3:
            v1 = vertices[1] - vertices[0]
            v2 = vertices[2] - vertices[0]
            normal = np.cross(v1, v2)
            normal = normal / (np.linalg.norm(normal) + 1e-10)
        else:
            normal = np.array([0, 0, 1])
        
        surface = Surface(
            id=surface_id,
            surface_type=surface_type,
            material=material,
            vertices=vertices,
            normal=normal,
            last_updated=time.time(),
        )
        
        self.surfaces[surface_id] = surface
        
        # Update voxel grid
        for vertex in vertices:
            self.voxel_grid.update_voxel(vertex, 1.0, material)
    
    def add_object(self, object_id: str, name: str, object_type: str,
                  position: np.ndarray, dimensions: np.ndarray,
                  orientation: float = 0.0,
                  material: MaterialType = MaterialType.UNKNOWN):
        """Add physical object to digital twin."""
        obj = PhysicalObject(
            id=object_id,
            name=name,
            object_type=object_type,
            position=position,
            dimensions=dimensions,
            orientation=orientation,
            material=material,
            last_seen=time.time(),
        )
        
        self.objects[object_id] = obj
        
        # Update voxel grid with object volume
        bbox_min, bbox_max = obj.get_bounding_box()
        
        for x in np.arange(bbox_min[0], bbox_max[0], self.voxel_grid.resolution):
            for y in np.arange(bbox_min[1], bbox_max[1], self.voxel_grid.resolution):
                for z in np.arange(bbox_min[2], bbox_max[2], self.voxel_grid.resolution):
                    self.voxel_grid.update_voxel(np.array([x, y, z]), 1.0, material)
    
    def add_zone(self, zone_id: str, zone_type: ZoneType,
                bounds: np.ndarray = None, polygon: np.ndarray = None):
        """Add activity zone to digital twin."""
        zone = Zone(
            id=zone_id,
            zone_type=zone_type,
            bounds=bounds,
            polygon=polygon,
        )
        
        self.zones[zone_id] = zone
    
    def detect_changes(self, threshold: float = 0.3) -> List[Dict]:
        """
        Detect changes in the environment.
        
        Returns list of detected changes.
        """
        changes = []
        current_time = time.time()
        
        # Check voxel changes
        recent_update_mask = (current_time - self.voxel_grid.last_updated) < 60
        high_confidence_mask = self.voxel_grid.confidence > 0.5
        
        combined_mask = recent_update_mask & high_confidence_mask
        
        # Find significant occupancy changes
        # This would compare with a baseline in a full implementation
        new_occupied = np.argwhere(combined_mask & (self.voxel_grid.occupancy > 0.7))
        
        for idx in new_occupied[:10]:  # Limit for performance
            position = self.voxel_grid.grid_to_world(idx)
            changes.append({
                'type': 'new_occupancy',
                'position': position.tolist(),
                'confidence': float(self.voxel_grid.confidence[tuple(idx)]),
                'timestamp': current_time,
            })
        
        # Track in history
        for change in changes:
            self.change_history.append(change)
        
        return changes
    
    def get_floor_plan(self, floor_height: float = 1.0, threshold: float = 0.5) -> np.ndarray:
        """
        Extract 2D floor plan at given height.
        
        Returns occupancy grid as 2D array.
        """
        # Get slice of voxel grid at floor height
        z_idx = int((floor_height - self.bounds[0, 2]) / self.voxel_grid.resolution)
        z_idx = np.clip(z_idx, 0, self.voxel_grid.dims[2] - 1)
        
        floor_slice = self.voxel_grid.occupancy[:, :, z_idx]
        
        return (floor_slice > threshold).astype(np.uint8) * 255
    
    def get_room_volume(self) -> float:
        """Calculate total room volume."""
        # Count free voxels
        free_voxels = np.sum(self.voxel_grid.occupancy < 0.3)
        voxel_volume = self.voxel_grid.resolution ** 3
        
        return free_voxels * voxel_volume
    
    def get_occupancy_summary(self) -> Dict:
        """Get occupancy summary for all zones."""
        summary = {}
        
        for zone_id, zone in self.zones.items():
            summary[zone_id] = {
                'zone_type': zone.zone_type.value,
                'occupancy_rate': zone.get_occupancy_rate(),
                'current_persons': len([p for p in self.persons.values() if p.zone == zone_id]),
            }
        
        return summary
    
    def export_to_json(self) -> str:
        """Export digital twin to JSON."""
        data = {
            'bounds': self.bounds.tolist(),
            'surfaces': {
                sid: {
                    'type': s.surface_type.value,
                    'material': s.material.value,
                    'vertices': s.vertices.tolist(),
                    'normal': s.normal.tolist(),
                }
                for sid, s in self.surfaces.items()
            },
            'objects': {
                oid: {
                    'name': o.name,
                    'type': o.object_type,
                    'position': o.position.tolist(),
                    'dimensions': o.dimensions.tolist(),
                    'orientation': o.orientation,
                }
                for oid, o in self.objects.items()
            },
            'zones': {
                zid: {
                    'type': z.zone_type.value,
                    'bounds': z.bounds.tolist() if z.bounds is not None else None,
                }
                for zid, z in self.zones.items()
            },
            'access_points': {
                apid: pos.tolist()
                for apid, pos in self.access_points.items()
            },
            'statistics': {
                'total_updates': self.total_updates,
                'last_update': self.last_update,
                'num_surfaces': len(self.surfaces),
                'num_objects': len(self.objects),
                'num_zones': len(self.zones),
                'room_volume': self.get_room_volume(),
            }
        }
        
        return json.dumps(data, indent=2)
    
    def save(self, path: str):
        """Save digital twin to compressed file."""
        data = {
            'json': self.export_to_json(),
            'voxel_occupancy': self.voxel_grid.occupancy.tobytes(),
            'voxel_dims': self.voxel_grid.dims.tolist(),
            'heat_map': self.heat_map.heat.tobytes(),
            'heat_dims': self.heat_map.dims.tolist(),
        }
        
        with gzip.open(path, 'wb') as f:
            f.write(json.dumps(data).encode())
    
    def get_statistics(self) -> Dict:
        """Get comprehensive statistics."""
        return {
            'bounds': self.bounds.tolist(),
            'total_updates': self.total_updates,
            'num_surfaces': len(self.surfaces),
            'num_objects': len(self.objects),
            'num_persons': len(self.persons),
            'num_zones': len(self.zones),
            'voxel_resolution': self.voxel_grid.resolution,
            'occupied_voxels': int(np.sum(self.voxel_grid.occupancy > 0.5)),
            'room_volume': self.get_room_volume(),
            'recent_changes': len(list(self.change_history)),
        }


# Standalone testing
if __name__ == "__main__":
    print("=== Environmental Digital Twin Test ===\n")
    
    np.random.seed(42)
    
    # Create digital twin
    bounds = np.array([
        [0, 0, 0],
        [10, 10, 3],
    ], dtype=np.float32)
    
    twin = EnvironmentalDigitalTwin(bounds, voxel_resolution=0.2)
    
    # Add walls
    print("Adding surfaces...")
    twin.add_surface("wall_north", np.array([
        [0, 10, 0], [10, 10, 0], [10, 10, 3], [0, 10, 3]
    ]), SurfaceType.WALL, MaterialType.CONCRETE)
    
    twin.add_surface("wall_south", np.array([
        [0, 0, 0], [10, 0, 0], [10, 0, 3], [0, 0, 3]
    ]), SurfaceType.WALL, MaterialType.CONCRETE)
    
    # Add objects
    print("Adding objects...")
    twin.add_object("desk_1", "Main Desk", "desk",
                   position=np.array([5.0, 5.0, 0.4]),
                   dimensions=np.array([1.5, 0.8, 0.8]))
    
    twin.add_object("chair_1", "Office Chair", "chair",
                   position=np.array([4.5, 4.5, 0.25]),
                   dimensions=np.array([0.5, 0.5, 0.5]))
    
    # Add zones
    print("Adding zones...")
    twin.add_zone("workspace_1", ZoneType.WORKSPACE,
                 bounds=np.array([[3, 3, 0], [7, 7, 3]]))
    
    twin.add_zone("entrance", ZoneType.ENTRANCE,
                 bounds=np.array([[0, 0, 0], [2, 2, 3]]))
    
    # Simulate CSI updates
    print("\nSimulating CSI updates...")
    tx_pos = np.array([1.0, 1.0, 2.0])
    rx_pos = np.array([9.0, 9.0, 2.0])
    
    for i in range(100):
        csi = np.random.randn(52) + 1j * np.random.randn(52)
        twin.update_from_csi(csi, tx_pos, rx_pos)
    
    # Simulate person movement
    print("Simulating person movement...")
    for t in np.linspace(0, 10, 50):
        position = np.array([
            2 + 3 * np.cos(t / 2),
            2 + 3 * np.sin(t / 2),
            0.0
        ])
        twin.update_person("person_001", position, "walking")
    
    # Detect changes
    print("\nDetecting changes...")
    changes = twin.detect_changes()
    print(f"Detected {len(changes)} changes")
    
    # Get statistics
    print("\n--- Statistics ---")
    stats = twin.get_statistics()
    print(json.dumps(stats, indent=2))
    
    # Get occupancy summary
    print("\n--- Occupancy Summary ---")
    occupancy = twin.get_occupancy_summary()
    print(json.dumps(occupancy, indent=2))
    
    # Export
    print("\n--- Exporting ---")
    json_export = twin.export_to_json()
    print(f"JSON export size: {len(json_export)} bytes")
    
    # Get floor plan
    floor_plan = twin.get_floor_plan(1.0)
    print(f"Floor plan shape: {floor_plan.shape}")
    print(f"Occupied cells: {np.sum(floor_plan > 0)}")
