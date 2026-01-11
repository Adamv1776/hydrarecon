"""
WiFi Material Tomography Engine
===============================

CUTTING-EDGE MATERIAL IDENTIFICATION VIA WIFI SIGNALS

Identifies wall and object materials from WiFi signal properties:
1. Multi-frequency signal attenuation analysis
2. Reflection coefficient estimation
3. Dielectric constant inference
4. Multi-path signature classification
5. 3D material distribution mapping

Theory:
- Different materials have unique dielectric properties at 2.4/5 GHz
- Signal attenuation = f(material thickness, dielectric constant)
- Reflection coefficient depends on material impedance mismatch
- Phase changes reveal material thickness and layering
- Multi-frequency analysis separates material effects

Material Properties (2.4 GHz):
- Air: εr ≈ 1.0, very low attenuation
- Drywall: εr ≈ 2.1, ~3 dB/wall
- Wood: εr ≈ 2-4, ~4 dB/wall
- Glass: εr ≈ 5-8, ~4 dB/wall
- Concrete: εr ≈ 4-8, ~12-18 dB/wall
- Brick: εr ≈ 4-6, ~8-12 dB/wall
- Metal: εr → ∞, complete reflection

Applications:
- Building structure mapping
- Hidden object detection
- Wall material classification
- Construction quality assessment
- Stud/pipe detection

Based on research:
- "WiSee: Whole-Home Gesture Recognition Using Commodity WiFi" (MobiCom 2013)
- "See Through Walls with WiFi!" (SIGCOMM 2013)
- "RF-Based Inertial Measurement" (SIGCOMM 2019)

Copyright (c) 2024-2026 HydraRecon - For authorized research only.
"""

import numpy as np
from scipy import signal
from scipy.optimize import minimize, curve_fit
from scipy.spatial.distance import cdist
from scipy.interpolate import griddata
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import deque
from enum import Enum, auto
import time
import json
from pathlib import Path


class MaterialType(Enum):
    """Common building material types."""
    AIR = auto()
    DRYWALL = auto()
    PLYWOOD = auto()
    CONCRETE = auto()
    BRICK = auto()
    GLASS = auto()
    METAL = auto()
    WATER = auto()
    WOOD = auto()
    INSULATION = auto()
    HUMAN = auto()
    UNKNOWN = auto()


@dataclass
class MaterialProperties:
    """Electromagnetic properties of a material."""
    material_type: MaterialType
    name: str
    
    # Dielectric properties
    relative_permittivity: float  # εr (real part)
    loss_tangent: float  # tan δ = ε''/ε'
    
    # Derived properties at 2.4 GHz
    attenuation_per_meter: float  # dB/m
    reflection_coefficient: float  # |Γ| at normal incidence from air
    
    # Thickness range (typical)
    typical_thickness_range: Tuple[float, float]  # meters


# Material database
MATERIAL_DATABASE: Dict[MaterialType, MaterialProperties] = {
    MaterialType.AIR: MaterialProperties(
        material_type=MaterialType.AIR,
        name="Air",
        relative_permittivity=1.0,
        loss_tangent=0.0,
        attenuation_per_meter=0.0,
        reflection_coefficient=0.0,
        typical_thickness_range=(0.0, 100.0)
    ),
    MaterialType.DRYWALL: MaterialProperties(
        material_type=MaterialType.DRYWALL,
        name="Drywall/Gypsum",
        relative_permittivity=2.1,
        loss_tangent=0.01,
        attenuation_per_meter=3.0,  # dB/m
        reflection_coefficient=0.18,
        typical_thickness_range=(0.01, 0.03)
    ),
    MaterialType.PLYWOOD: MaterialProperties(
        material_type=MaterialType.PLYWOOD,
        name="Plywood",
        relative_permittivity=2.8,
        loss_tangent=0.02,
        attenuation_per_meter=4.0,
        reflection_coefficient=0.25,
        typical_thickness_range=(0.01, 0.025)
    ),
    MaterialType.WOOD: MaterialProperties(
        material_type=MaterialType.WOOD,
        name="Solid Wood",
        relative_permittivity=3.5,
        loss_tangent=0.05,
        attenuation_per_meter=6.0,
        reflection_coefficient=0.30,
        typical_thickness_range=(0.05, 0.15)
    ),
    MaterialType.GLASS: MaterialProperties(
        material_type=MaterialType.GLASS,
        name="Glass",
        relative_permittivity=6.0,
        loss_tangent=0.005,
        attenuation_per_meter=3.0,
        reflection_coefficient=0.42,
        typical_thickness_range=(0.003, 0.025)
    ),
    MaterialType.CONCRETE: MaterialProperties(
        material_type=MaterialType.CONCRETE,
        name="Concrete",
        relative_permittivity=5.0,
        loss_tangent=0.15,
        attenuation_per_meter=15.0,
        reflection_coefficient=0.38,
        typical_thickness_range=(0.1, 0.3)
    ),
    MaterialType.BRICK: MaterialProperties(
        material_type=MaterialType.BRICK,
        name="Brick",
        relative_permittivity=4.5,
        loss_tangent=0.10,
        attenuation_per_meter=10.0,
        reflection_coefficient=0.35,
        typical_thickness_range=(0.1, 0.25)
    ),
    MaterialType.METAL: MaterialProperties(
        material_type=MaterialType.METAL,
        name="Metal/Steel",
        relative_permittivity=1e6,
        loss_tangent=1e6,
        attenuation_per_meter=1000.0,  # Essentially infinite
        reflection_coefficient=0.99,
        typical_thickness_range=(0.001, 0.01)
    ),
    MaterialType.WATER: MaterialProperties(
        material_type=MaterialType.WATER,
        name="Water",
        relative_permittivity=80.0,
        loss_tangent=0.1,
        attenuation_per_meter=30.0,
        reflection_coefficient=0.80,
        typical_thickness_range=(0.01, 1.0)
    ),
    MaterialType.INSULATION: MaterialProperties(
        material_type=MaterialType.INSULATION,
        name="Insulation",
        relative_permittivity=1.2,
        loss_tangent=0.001,
        attenuation_per_meter=0.5,
        reflection_coefficient=0.05,
        typical_thickness_range=(0.05, 0.2)
    ),
    MaterialType.HUMAN: MaterialProperties(
        material_type=MaterialType.HUMAN,
        name="Human Body",
        relative_permittivity=50.0,
        loss_tangent=0.5,
        attenuation_per_meter=25.0,
        reflection_coefficient=0.75,
        typical_thickness_range=(0.15, 0.5)
    ),
}


@dataclass
class MaterialEstimate:
    """Estimated material at a location."""
    position: Tuple[float, float, float]  # (x, y, z) in meters
    material_type: MaterialType
    confidence: float  # 0-1
    thickness: float  # meters
    
    # Alternative candidates
    alternatives: List[Tuple[MaterialType, float]]  # (type, probability)
    
    # Measurement data
    measured_attenuation: float  # dB
    measured_reflection: float  # 0-1
    estimated_permittivity: float


@dataclass
class WallSegment:
    """Detected wall segment with material."""
    start: Tuple[float, float]
    end: Tuple[float, float]
    material: MaterialType
    thickness: float
    confidence: float


@dataclass
class MaterialMap:
    """3D material distribution map."""
    # Grid parameters
    grid_resolution: float  # meters
    x_range: Tuple[float, float]
    y_range: Tuple[float, float]
    z_range: Tuple[float, float]
    
    # Material grid
    # Shape: (nx, ny, nz) with MaterialType enum values
    material_grid: np.ndarray
    confidence_grid: np.ndarray
    
    # Estimated thickness per voxel
    thickness_grid: np.ndarray


class AttenuationModel:
    """
    Model signal attenuation through materials.
    
    Uses multi-frequency analysis to estimate material properties.
    """
    
    # Free space path loss at 2.4 GHz
    WAVELENGTH_24 = 0.125  # meters
    WAVELENGTH_5 = 0.06   # meters
    
    def __init__(self):
        # Calibration
        self.reference_power = -30  # dBm at 1 meter in free space
        self.noise_floor = -90  # dBm
    
    def free_space_path_loss(self, distance: float, frequency_ghz: float = 2.4) -> float:
        """Calculate free space path loss in dB."""
        if distance <= 0:
            return 0
        
        # FSPL = 20*log10(d) + 20*log10(f) + 20*log10(4π/c)
        # Simplified for 2.4 GHz: FSPL ≈ 40 + 20*log10(d)
        fspl = 20 * np.log10(frequency_ghz * 1e9) + 20 * np.log10(distance) - 147.55
        return fspl
    
    def material_attenuation(self, material: MaterialProperties, 
                            thickness: float) -> float:
        """Calculate attenuation through material in dB."""
        return material.attenuation_per_meter * thickness
    
    def reflection_loss(self, material: MaterialProperties) -> float:
        """Calculate reflection loss at material interface in dB."""
        # Power reflection coefficient
        gamma_squared = material.reflection_coefficient ** 2
        
        # Transmission coefficient
        transmission = 1 - gamma_squared
        
        return -10 * np.log10(transmission + 1e-10)
    
    def estimate_material_from_attenuation(self, 
                                           measured_attenuation: float,
                                           path_length: float) -> List[Tuple[MaterialType, float, float]]:
        """
        Estimate material from measured attenuation.
        
        Returns list of (material, probability, estimated_thickness) tuples.
        """
        # Excess attenuation (above free space)
        fspl = self.free_space_path_loss(path_length)
        excess_attenuation = measured_attenuation - fspl
        
        if excess_attenuation < 1:
            return [(MaterialType.AIR, 0.9, 0.0)]
        
        candidates = []
        
        for mat_type, props in MATERIAL_DATABASE.items():
            if mat_type == MaterialType.AIR:
                continue
            
            # Estimate thickness from attenuation
            # Include both transmission and reflection losses
            reflection_loss = self.reflection_loss(props)
            transmission_atten = excess_attenuation - reflection_loss
            
            if transmission_atten <= 0:
                # All attenuation from reflection - thin layer
                thickness = props.typical_thickness_range[0]
            else:
                thickness = transmission_atten / props.attenuation_per_meter
            
            # Check if thickness is plausible
            min_thick, max_thick = props.typical_thickness_range
            
            if thickness < min_thick:
                # Too thin - unlikely this material
                probability = 0.1 * (thickness / min_thick)
            elif thickness > max_thick * 3:
                # Too thick - unlikely single layer
                probability = 0.2
            else:
                # Plausible
                if min_thick <= thickness <= max_thick:
                    probability = 0.8
                else:
                    probability = 0.5
            
            candidates.append((mat_type, probability, thickness))
        
        # Normalize probabilities
        total_prob = sum(c[1] for c in candidates)
        candidates = [(c[0], c[1] / total_prob, c[2]) for c in candidates]
        
        # Sort by probability
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        return candidates[:5]


class ReflectionAnalyzer:
    """
    Analyze reflections to identify materials.
    
    Different materials have characteristic reflection signatures.
    """
    
    def __init__(self):
        # Minimum reflection to consider
        self.min_reflection = 0.05
    
    def estimate_permittivity_from_reflection(self, 
                                              reflection_coefficient: float,
                                              incident_angle: float = 0) -> float:
        """
        Estimate relative permittivity from reflection coefficient.
        
        Uses Fresnel equations at normal incidence:
        Γ = (η2 - η1) / (η2 + η1) = (sqrt(εr1) - sqrt(εr2)) / (sqrt(εr1) + sqrt(εr2))
        
        For air -> material: εr1 = 1
        |Γ| = (1 - sqrt(εr2)) / (1 + sqrt(εr2))
        """
        if reflection_coefficient >= 0.99:
            return 1e6  # Metal
        
        if reflection_coefficient < 0.01:
            return 1.0  # Air
        
        # Solve for εr2
        # |Γ| * (1 + sqrt(εr)) = |1 - sqrt(εr)|
        
        # Numerical solution
        def equation(er):
            sqrt_er = np.sqrt(max(er, 1.0))
            gamma = abs(1 - sqrt_er) / (1 + sqrt_er)
            return (gamma - reflection_coefficient) ** 2
        
        from scipy.optimize import minimize_scalar
        result = minimize_scalar(equation, bounds=(1, 100), method='bounded')
        
        return result.x
    
    def classify_from_permittivity(self, permittivity: float) -> List[Tuple[MaterialType, float]]:
        """
        Classify material from estimated permittivity.
        
        Returns list of (material, probability) tuples.
        """
        candidates = []
        
        for mat_type, props in MATERIAL_DATABASE.items():
            # Distance from material's permittivity
            diff = abs(permittivity - props.relative_permittivity)
            
            # Probability based on closeness
            if props.relative_permittivity < 100:
                sigma = 0.5 * props.relative_permittivity
            else:
                sigma = 10  # Wide range for conductors
            
            probability = np.exp(-diff**2 / (2 * sigma**2))
            candidates.append((mat_type, probability))
        
        # Normalize
        total = sum(c[1] for c in candidates)
        candidates = [(c[0], c[1] / total) for c in candidates]
        
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        return candidates[:5]


class MultiPathAnalyzer:
    """
    Analyze multi-path signatures for material identification.
    
    Different materials create different multi-path patterns.
    """
    
    def __init__(self, num_subcarriers: int = 52):
        self.num_subcarriers = num_subcarriers
        
        # Subcarrier frequency separation (20 MHz bandwidth)
        self.subcarrier_spacing = 312.5e3  # Hz
    
    def compute_channel_impulse_response(self, csi: np.ndarray) -> np.ndarray:
        """
        Compute channel impulse response from CSI.
        
        CIR reveals multi-path components.
        """
        # IFFT of CSI gives time-domain impulse response
        cir = np.fft.ifft(csi)
        return np.abs(cir)
    
    def detect_multi_path(self, csi: np.ndarray, 
                         threshold: float = 0.1) -> List[Tuple[float, float]]:
        """
        Detect multi-path components.
        
        Returns list of (delay_ns, amplitude) for each path.
        """
        cir = self.compute_channel_impulse_response(csi)
        
        # Find peaks
        from scipy.signal import find_peaks
        peaks, properties = find_peaks(cir, height=threshold * np.max(cir))
        
        # Convert sample index to delay
        # Sample period = 1 / (num_subcarriers * subcarrier_spacing)
        sample_period = 1 / (self.num_subcarriers * self.subcarrier_spacing)
        
        paths = []
        for peak in peaks:
            delay_ns = peak * sample_period * 1e9
            amplitude = cir[peak]
            paths.append((delay_ns, amplitude))
        
        return paths
    
    def infer_material_from_multipath(self, 
                                      paths: List[Tuple[float, float]]) -> MaterialType:
        """
        Infer material from multi-path signature.
        
        Different materials create different multi-path patterns:
        - Metal: Strong single reflection
        - Glass: Multiple reflections at regular intervals
        - Concrete: Dispersed reflections
        """
        if len(paths) == 0:
            return MaterialType.AIR
        
        if len(paths) == 1:
            # Single dominant path
            return MaterialType.AIR
        
        # Sort by amplitude
        paths.sort(key=lambda x: x[1], reverse=True)
        
        # Ratio of strongest to second strongest
        if len(paths) >= 2:
            ratio = paths[0][1] / (paths[1][1] + 1e-10)
            
            if ratio > 10:
                # Strong dominant reflection -> Metal
                return MaterialType.METAL
            elif ratio > 3:
                # Moderate reflection -> Glass or concrete
                # Check delay pattern
                delays = sorted([p[0] for p in paths])
                if len(delays) >= 3:
                    # Check for regular spacing (glass layers)
                    intervals = np.diff(delays)
                    interval_std = np.std(intervals)
                    if interval_std < 0.5:
                        return MaterialType.GLASS
                
                return MaterialType.CONCRETE
            else:
                # Dispersed reflections -> Complex structure
                return MaterialType.BRICK
        
        return MaterialType.UNKNOWN


class MaterialTomographyEngine:
    """
    Main material tomography engine.
    
    Combines multiple analysis methods to identify materials
    and build 3D material maps.
    """
    
    def __init__(self, room_bounds: Tuple[float, float, float, float] = (-5, 5, -5, 5)):
        """
        Initialize engine.
        
        Args:
            room_bounds: (x_min, x_max, y_min, y_max) in meters
        """
        self.room_bounds = room_bounds
        
        # Components
        self.attenuation_model = AttenuationModel()
        self.reflection_analyzer = ReflectionAnalyzer()
        self.multipath_analyzer = MultiPathAnalyzer()
        
        # Material estimates
        self.material_estimates: List[MaterialEstimate] = []
        
        # Wall segments
        self.wall_segments: List[WallSegment] = []
        
        # Material map (lazy initialization)
        self.material_map: Optional[MaterialMap] = None
        self.map_resolution = 0.1  # meters
    
    def process_csi_measurement(self, 
                                tx_position: Tuple[float, float, float],
                                rx_position: Tuple[float, float, float],
                                csi_amplitude: np.ndarray,
                                csi_phase: np.ndarray) -> Optional[MaterialEstimate]:
        """
        Process a CSI measurement to estimate material.
        
        Args:
            tx_position: Transmitter position (x, y, z)
            rx_position: Receiver position (x, y, z)
            csi_amplitude: CSI amplitude per subcarrier
            csi_phase: CSI phase per subcarrier
        
        Returns:
            Material estimate for the path between TX and RX
        """
        tx = np.array(tx_position)
        rx = np.array(rx_position)
        
        # Path characteristics
        path_length = np.linalg.norm(rx - tx)
        midpoint = (tx + rx) / 2
        
        # 1. Attenuation analysis
        measured_power = 20 * np.log10(np.mean(csi_amplitude) + 1e-10)
        measured_attenuation = -30 - measured_power + self.attenuation_model.free_space_path_loss(path_length)
        
        attenuation_candidates = self.attenuation_model.estimate_material_from_attenuation(
            measured_attenuation, path_length
        )
        
        # 2. Reflection analysis
        # Estimate reflection from amplitude variance across subcarriers
        amplitude_var = np.var(csi_amplitude) / (np.mean(csi_amplitude) ** 2 + 1e-10)
        estimated_reflection = min(0.99, amplitude_var * 2)
        
        estimated_permittivity = self.reflection_analyzer.estimate_permittivity_from_reflection(
            estimated_reflection
        )
        
        permittivity_candidates = self.reflection_analyzer.classify_from_permittivity(
            estimated_permittivity
        )
        
        # 3. Multi-path analysis
        csi_complex = csi_amplitude * np.exp(1j * csi_phase)
        paths = self.multipath_analyzer.detect_multi_path(csi_complex)
        multipath_material = self.multipath_analyzer.infer_material_from_multipath(paths)
        
        # 4. Combine evidence
        combined_scores = {}
        
        for mat_type, prob, thickness in attenuation_candidates:
            combined_scores[mat_type] = combined_scores.get(mat_type, 0) + prob * 0.4
        
        for mat_type, prob in permittivity_candidates:
            combined_scores[mat_type] = combined_scores.get(mat_type, 0) + prob * 0.4
        
        # Multipath evidence
        combined_scores[multipath_material] = combined_scores.get(multipath_material, 0) + 0.2
        
        # Find best match
        best_material = max(combined_scores, key=combined_scores.get)
        confidence = combined_scores[best_material]
        
        # Get thickness from attenuation candidates
        thickness = 0.1  # default
        for mat, prob, thick in attenuation_candidates:
            if mat == best_material:
                thickness = thick
                break
        
        # Build alternatives list
        alternatives = sorted(
            [(mat, score) for mat, score in combined_scores.items() if mat != best_material],
            key=lambda x: x[1], reverse=True
        )[:3]
        
        estimate = MaterialEstimate(
            position=tuple(midpoint),
            material_type=best_material,
            confidence=confidence,
            thickness=thickness,
            alternatives=alternatives,
            measured_attenuation=measured_attenuation,
            measured_reflection=estimated_reflection,
            estimated_permittivity=estimated_permittivity
        )
        
        self.material_estimates.append(estimate)
        
        return estimate
    
    def detect_walls(self, min_samples: int = 5) -> List[WallSegment]:
        """
        Detect wall segments from accumulated estimates.
        
        Groups nearby non-air estimates into wall segments.
        """
        # Filter non-air estimates with reasonable confidence
        wall_estimates = [
            e for e in self.material_estimates
            if e.material_type != MaterialType.AIR and e.confidence > 0.3
        ]
        
        if len(wall_estimates) < min_samples:
            return []
        
        # Simple clustering based on position proximity
        from scipy.cluster.hierarchy import fcluster, linkage
        
        positions = np.array([e.position[:2] for e in wall_estimates])
        
        if len(positions) < 2:
            return []
        
        # Hierarchical clustering
        Z = linkage(positions, method='ward')
        clusters = fcluster(Z, t=0.5, criterion='distance')
        
        # Process each cluster
        wall_segments = []
        
        for cluster_id in np.unique(clusters):
            cluster_mask = clusters == cluster_id
            cluster_estimates = [e for e, m in zip(wall_estimates, cluster_mask) if m]
            
            if len(cluster_estimates) < min_samples:
                continue
            
            # Fit line to cluster
            cluster_positions = np.array([e.position[:2] for e in cluster_estimates])
            
            # PCA for line direction
            centroid = np.mean(cluster_positions, axis=0)
            centered = cluster_positions - centroid
            
            cov = np.cov(centered.T)
            eigenvalues, eigenvectors = np.linalg.eig(cov)
            
            # Principal direction
            principal = eigenvectors[:, np.argmax(eigenvalues)]
            
            # Project points onto line
            projections = centered @ principal
            
            # Line endpoints
            start = centroid + np.min(projections) * principal
            end = centroid + np.max(projections) * principal
            
            # Majority material vote
            material_counts = {}
            for e in cluster_estimates:
                mat = e.material_type
                material_counts[mat] = material_counts.get(mat, 0) + 1
            
            dominant_material = max(material_counts, key=material_counts.get)
            
            # Average thickness and confidence
            avg_thickness = np.mean([e.thickness for e in cluster_estimates])
            avg_confidence = np.mean([e.confidence for e in cluster_estimates])
            
            segment = WallSegment(
                start=tuple(start),
                end=tuple(end),
                material=dominant_material,
                thickness=avg_thickness,
                confidence=avg_confidence
            )
            
            wall_segments.append(segment)
        
        self.wall_segments = wall_segments
        return wall_segments
    
    def build_material_map(self, resolution: float = 0.1) -> MaterialMap:
        """
        Build 3D material distribution map.
        
        Interpolates from discrete estimates to create volumetric map.
        """
        x_min, x_max, y_min, y_max = self.room_bounds
        z_min, z_max = 0, 3.0  # Typical room height
        
        # Grid dimensions
        nx = int((x_max - x_min) / resolution) + 1
        ny = int((y_max - y_min) / resolution) + 1
        nz = int((z_max - z_min) / resolution) + 1
        
        # Initialize grids
        material_grid = np.full((nx, ny, nz), MaterialType.AIR.value, dtype=np.int32)
        confidence_grid = np.zeros((nx, ny, nz), dtype=np.float32)
        thickness_grid = np.zeros((nx, ny, nz), dtype=np.float32)
        
        # Place estimates into grid
        for estimate in self.material_estimates:
            if estimate.material_type == MaterialType.AIR:
                continue
            
            x, y, z = estimate.position
            
            # Grid indices
            ix = int((x - x_min) / resolution)
            iy = int((y - y_min) / resolution)
            iz = int((z - z_min) / resolution)
            
            if 0 <= ix < nx and 0 <= iy < ny and 0 <= iz < nz:
                # Update if higher confidence
                if estimate.confidence > confidence_grid[ix, iy, iz]:
                    material_grid[ix, iy, iz] = estimate.material_type.value
                    confidence_grid[ix, iy, iz] = estimate.confidence
                    thickness_grid[ix, iy, iz] = estimate.thickness
        
        # Add wall segments
        for segment in self.wall_segments:
            # Rasterize line segment
            start = np.array(segment.start)
            end = np.array(segment.end)
            
            length = np.linalg.norm(end - start)
            num_points = int(length / resolution) + 1
            
            for i in range(num_points):
                t = i / max(1, num_points - 1)
                point = start + t * (end - start)
                
                ix = int((point[0] - x_min) / resolution)
                iy = int((point[1] - y_min) / resolution)
                
                # Wall extends full height
                for iz in range(nz):
                    if 0 <= ix < nx and 0 <= iy < ny:
                        material_grid[ix, iy, iz] = segment.material.value
                        confidence_grid[ix, iy, iz] = segment.confidence
                        thickness_grid[ix, iy, iz] = segment.thickness
        
        self.material_map = MaterialMap(
            grid_resolution=resolution,
            x_range=(x_min, x_max),
            y_range=(y_min, y_max),
            z_range=(z_min, z_max),
            material_grid=material_grid,
            confidence_grid=confidence_grid,
            thickness_grid=thickness_grid
        )
        
        return self.material_map
    
    def get_material_at(self, x: float, y: float, z: float = 1.5) -> Tuple[MaterialType, float]:
        """
        Get material at a specific location.
        
        Returns (material_type, confidence)
        """
        if self.material_map is None:
            self.build_material_map()
        
        m = self.material_map
        
        ix = int((x - m.x_range[0]) / m.grid_resolution)
        iy = int((y - m.y_range[0]) / m.grid_resolution)
        iz = int((z - m.z_range[0]) / m.grid_resolution)
        
        if (0 <= ix < m.material_grid.shape[0] and
            0 <= iy < m.material_grid.shape[1] and
            0 <= iz < m.material_grid.shape[2]):
            
            mat_value = m.material_grid[ix, iy, iz]
            confidence = m.confidence_grid[ix, iy, iz]
            
            return MaterialType(mat_value), confidence
        
        return MaterialType.UNKNOWN, 0.0
    
    def get_statistics(self) -> Dict:
        """Get engine statistics."""
        material_counts = {}
        for estimate in self.material_estimates:
            mat = estimate.material_type.name
            material_counts[mat] = material_counts.get(mat, 0) + 1
        
        return {
            'total_estimates': len(self.material_estimates),
            'wall_segments': len(self.wall_segments),
            'material_distribution': material_counts,
            'avg_confidence': float(np.mean([e.confidence for e in self.material_estimates])) if self.material_estimates else 0,
            'room_bounds': self.room_bounds,
        }
    
    def export_map_json(self) -> str:
        """Export material map as JSON."""
        if self.material_map is None:
            self.build_material_map()
        
        m = self.material_map
        
        # Convert to serializable format
        cells = []
        for ix in range(m.material_grid.shape[0]):
            for iy in range(m.material_grid.shape[1]):
                for iz in range(m.material_grid.shape[2]):
                    if m.confidence_grid[ix, iy, iz] > 0.1:
                        x = m.x_range[0] + ix * m.grid_resolution
                        y = m.y_range[0] + iy * m.grid_resolution
                        z = m.z_range[0] + iz * m.grid_resolution
                        
                        cells.append({
                            'x': x, 'y': y, 'z': z,
                            'material': MaterialType(m.material_grid[ix, iy, iz]).name,
                            'confidence': float(m.confidence_grid[ix, iy, iz]),
                            'thickness': float(m.thickness_grid[ix, iy, iz])
                        })
        
        return json.dumps({
            'resolution': m.grid_resolution,
            'bounds': {
                'x': m.x_range,
                'y': m.y_range,
                'z': m.z_range
            },
            'cells': cells
        }, indent=2)


# Standalone testing
if __name__ == "__main__":
    print("=== WiFi Material Tomography Test ===\n")
    
    engine = MaterialTomographyEngine(room_bounds=(-5, 5, -5, 5))
    
    # Simulate CSI measurements through different materials
    np.random.seed(42)
    
    # Measurement 1: Through drywall
    print("Measurement 1: Signal through drywall...")
    csi_amp = 30 + np.random.randn(52) * 2  # Moderate signal
    csi_phase = np.random.randn(52) * 0.3
    
    estimate = engine.process_csi_measurement(
        tx_position=(0, -3, 1.5),
        rx_position=(0, 3, 1.5),
        csi_amplitude=csi_amp,
        csi_phase=csi_phase
    )
    
    print(f"  Material: {estimate.material_type.name}")
    print(f"  Confidence: {estimate.confidence:.2f}")
    print(f"  Est. thickness: {estimate.thickness:.2f}m")
    print(f"  Est. permittivity: {estimate.estimated_permittivity:.1f}")
    
    # Measurement 2: Through concrete
    print("\nMeasurement 2: Signal through concrete...")
    csi_amp = 10 + np.random.randn(52) * 3  # Weak signal
    csi_phase = np.random.randn(52) * 0.5
    
    estimate = engine.process_csi_measurement(
        tx_position=(-3, 0, 1.5),
        rx_position=(3, 0, 1.5),
        csi_amplitude=csi_amp,
        csi_phase=csi_phase
    )
    
    print(f"  Material: {estimate.material_type.name}")
    print(f"  Confidence: {estimate.confidence:.2f}")
    print(f"  Est. thickness: {estimate.thickness:.2f}m")
    
    # Measurement 3: Through glass window
    print("\nMeasurement 3: Signal through glass...")
    csi_amp = 40 + np.random.randn(52) * 5  # Good signal with variance
    csi_phase = np.random.randn(52) * 0.2
    
    estimate = engine.process_csi_measurement(
        tx_position=(2, -2, 1.5),
        rx_position=(2, 2, 1.5),
        csi_amplitude=csi_amp,
        csi_phase=csi_phase
    )
    
    print(f"  Material: {estimate.material_type.name}")
    print(f"  Confidence: {estimate.confidence:.2f}")
    
    # Add more measurements along a wall
    print("\nAdding measurements along a wall...")
    for i in range(10):
        x = -4 + i * 0.8
        csi_amp = 35 + np.random.randn(52) * 2
        csi_phase = np.random.randn(52) * 0.3
        
        engine.process_csi_measurement(
            tx_position=(x, -3, 1.5),
            rx_position=(x, 3, 1.5),
            csi_amplitude=csi_amp,
            csi_phase=csi_phase
        )
    
    # Detect walls
    walls = engine.detect_walls(min_samples=3)
    print(f"\nDetected {len(walls)} wall segments:")
    for i, wall in enumerate(walls):
        print(f"  Wall {i+1}: {wall.material.name}, thickness={wall.thickness:.2f}m")
    
    # Build material map
    print("\nBuilding material map...")
    engine.build_material_map(resolution=0.2)
    
    # Query specific location
    mat, conf = engine.get_material_at(0, 0, 1.5)
    print(f"Material at (0, 0, 1.5): {mat.name} (confidence: {conf:.2f})")
    
    print("\n--- Statistics ---")
    print(json.dumps(engine.get_statistics(), indent=2))
