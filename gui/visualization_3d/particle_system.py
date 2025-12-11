"""
3D Particle System for Visual Effects

Advanced particle system supporting:
- Explosions, fire, smoke
- Network traffic flows
- Data streams
- Attack visualizations
- Energy effects
- Holographic displays
"""

import math
import time
import random
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable
from enum import Enum

try:
    from PyQt6.QtCore import Qt, QTimer
except ImportError:
    pass


class ParticleBlendMode(Enum):
    """Particle blending modes"""
    ADDITIVE = "additive"
    ALPHA = "alpha"
    MULTIPLY = "multiply"
    SCREEN = "screen"


class EmitterShape(Enum):
    """Particle emitter shapes"""
    POINT = "point"
    SPHERE = "sphere"
    BOX = "box"
    CONE = "cone"
    LINE = "line"
    RING = "ring"
    MESH = "mesh"


@dataclass
class Particle:
    """Single particle"""
    position: np.ndarray
    velocity: np.ndarray
    acceleration: np.ndarray = field(default_factory=lambda: np.zeros(3))
    
    # Life
    age: float = 0.0
    lifetime: float = 1.0
    
    # Visual
    color: np.ndarray = field(default_factory=lambda: np.array([1.0, 1.0, 1.0, 1.0]))
    size: float = 1.0
    rotation: float = 0.0
    rotation_speed: float = 0.0
    
    # Physics
    mass: float = 1.0
    drag: float = 0.0
    
    # Custom data
    data: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_alive(self) -> bool:
        return self.age < self.lifetime
    
    @property
    def normalized_age(self) -> float:
        return self.age / self.lifetime if self.lifetime > 0 else 1.0
    
    def update(self, dt: float, gravity: np.ndarray = None):
        """Update particle physics"""
        # Apply gravity
        if gravity is not None:
            self.acceleration = self.acceleration + gravity
        
        # Apply drag
        if self.drag > 0:
            drag_force = -self.velocity * self.drag
            self.acceleration = self.acceleration + drag_force / self.mass
        
        # Integrate
        self.velocity = self.velocity + self.acceleration * dt
        self.position = self.position + self.velocity * dt
        
        # Reset acceleration for next frame
        self.acceleration = np.zeros(3)
        
        # Update rotation
        self.rotation += self.rotation_speed * dt
        
        # Age
        self.age += dt


@dataclass
class ParticleGradient:
    """Color gradient over particle lifetime"""
    colors: List[Tuple[float, Tuple[float, float, float, float]]] = field(default_factory=list)
    
    def sample(self, t: float) -> Tuple[float, float, float, float]:
        """Sample color at time t (0-1)"""
        if not self.colors:
            return (1, 1, 1, 1)
        
        if len(self.colors) == 1:
            return self.colors[0][1]
        
        # Find surrounding colors
        for i in range(len(self.colors) - 1):
            t0, c0 = self.colors[i]
            t1, c1 = self.colors[i + 1]
            
            if t0 <= t <= t1:
                # Interpolate
                local_t = (t - t0) / (t1 - t0) if t1 != t0 else 0
                return tuple(
                    c0[j] + (c1[j] - c0[j]) * local_t
                    for j in range(4)
                )
        
        return self.colors[-1][1]


@dataclass
class SizeOverLife:
    """Size curve over particle lifetime"""
    curve: List[Tuple[float, float]] = field(default_factory=list)
    
    def sample(self, t: float) -> float:
        """Sample size at time t (0-1)"""
        if not self.curve:
            return 1.0
        
        if len(self.curve) == 1:
            return self.curve[0][1]
        
        for i in range(len(self.curve) - 1):
            t0, s0 = self.curve[i]
            t1, s1 = self.curve[i + 1]
            
            if t0 <= t <= t1:
                local_t = (t - t0) / (t1 - t0) if t1 != t0 else 0
                return s0 + (s1 - s0) * local_t
        
        return self.curve[-1][1]


class ParticleEmitter:
    """Particle emitter"""
    
    def __init__(self,
                 position: Tuple[float, float, float] = (0, 0, 0),
                 shape: EmitterShape = EmitterShape.POINT):
        
        self.position = np.array(position)
        self.rotation = np.array([0.0, 0.0, 0.0])
        self.shape = shape
        
        # Emission
        self.emission_rate: float = 10.0  # particles per second
        self.burst_count: int = 0  # One-time burst
        
        # Shape parameters
        self.radius: float = 1.0
        self.angle: float = 30.0  # For cone
        self.box_size: Tuple[float, float, float] = (1, 1, 1)
        self.line_end: Tuple[float, float, float] = (1, 0, 0)
        
        # Initial particle properties
        self.start_lifetime: Tuple[float, float] = (1.0, 2.0)
        self.start_speed: Tuple[float, float] = (1.0, 3.0)
        self.start_size: Tuple[float, float] = (0.1, 0.2)
        self.start_rotation: Tuple[float, float] = (0, 360)
        self.start_rotation_speed: Tuple[float, float] = (0, 0)
        self.start_color: Tuple[float, float, float, float] = (1, 1, 1, 1)
        
        # Over lifetime
        self.color_over_lifetime: Optional[ParticleGradient] = None
        self.size_over_lifetime: Optional[SizeOverLife] = None
        
        # Physics
        self.gravity: Optional[np.ndarray] = None
        self.drag: float = 0.0
        
        # Rendering
        self.blend_mode: ParticleBlendMode = ParticleBlendMode.ADDITIVE
        self.texture: Optional[str] = None
        
        # State
        self.particles: List[Particle] = []
        self.emission_accumulator: float = 0.0
        self.is_playing: bool = True
        self.max_particles: int = 1000
        
        # Custom spawn function
        self.spawn_callback: Optional[Callable[[Particle], None]] = None
        self.update_callback: Optional[Callable[[Particle, float], None]] = None
    
    def _random_range(self, range_tuple: Tuple[float, float]) -> float:
        """Get random value in range"""
        return random.uniform(range_tuple[0], range_tuple[1])
    
    def _get_emission_point(self) -> Tuple[np.ndarray, np.ndarray]:
        """Get emission position and direction based on shape"""
        if self.shape == EmitterShape.POINT:
            pos = self.position.copy()
            dir = np.array([0, 1, 0])  # Up
            
        elif self.shape == EmitterShape.SPHERE:
            # Random point on sphere
            theta = random.uniform(0, 2 * math.pi)
            phi = random.uniform(0, math.pi)
            
            x = self.radius * math.sin(phi) * math.cos(theta)
            y = self.radius * math.sin(phi) * math.sin(theta)
            z = self.radius * math.cos(phi)
            
            pos = self.position + np.array([x, y, z])
            dir = np.array([x, y, z])
            dir = dir / np.linalg.norm(dir) if np.linalg.norm(dir) > 0 else np.array([0, 1, 0])
            
        elif self.shape == EmitterShape.BOX:
            x = random.uniform(-self.box_size[0]/2, self.box_size[0]/2)
            y = random.uniform(-self.box_size[1]/2, self.box_size[1]/2)
            z = random.uniform(-self.box_size[2]/2, self.box_size[2]/2)
            
            pos = self.position + np.array([x, y, z])
            dir = np.array([0, 1, 0])
            
        elif self.shape == EmitterShape.CONE:
            # Random angle within cone
            angle = random.uniform(0, math.radians(self.angle))
            rotation = random.uniform(0, 2 * math.pi)
            
            x = math.sin(angle) * math.cos(rotation)
            z = math.sin(angle) * math.sin(rotation)
            y = math.cos(angle)
            
            pos = self.position.copy()
            dir = np.array([x, y, z])
            
        elif self.shape == EmitterShape.LINE:
            t = random.uniform(0, 1)
            end = np.array(self.line_end)
            pos = self.position + (end - self.position) * t
            dir = np.array([0, 1, 0])
            
        elif self.shape == EmitterShape.RING:
            angle = random.uniform(0, 2 * math.pi)
            x = self.radius * math.cos(angle)
            z = self.radius * math.sin(angle)
            
            pos = self.position + np.array([x, 0, z])
            dir = np.array([x, 1, z])
            dir = dir / np.linalg.norm(dir)
            
        else:
            pos = self.position.copy()
            dir = np.array([0, 1, 0])
        
        return pos, dir
    
    def spawn_particle(self) -> Optional[Particle]:
        """Spawn a new particle"""
        if len(self.particles) >= self.max_particles:
            return None
        
        pos, direction = self._get_emission_point()
        
        speed = self._random_range(self.start_speed)
        velocity = direction * speed
        
        particle = Particle(
            position=pos,
            velocity=velocity,
            lifetime=self._random_range(self.start_lifetime),
            size=self._random_range(self.start_size),
            rotation=self._random_range(self.start_rotation),
            rotation_speed=self._random_range(self.start_rotation_speed),
            color=np.array(self.start_color),
            drag=self.drag
        )
        
        if self.spawn_callback:
            self.spawn_callback(particle)
        
        self.particles.append(particle)
        return particle
    
    def emit_burst(self, count: int = None):
        """Emit a burst of particles"""
        count = count or self.burst_count
        for _ in range(count):
            self.spawn_particle()
    
    def update(self, dt: float):
        """Update all particles"""
        if not self.is_playing:
            return
        
        # Emit new particles
        self.emission_accumulator += self.emission_rate * dt
        while self.emission_accumulator >= 1.0:
            self.spawn_particle()
            self.emission_accumulator -= 1.0
        
        # Update existing particles
        alive_particles = []
        
        for particle in self.particles:
            particle.update(dt, self.gravity)
            
            # Apply custom update
            if self.update_callback:
                self.update_callback(particle, dt)
            
            # Apply over-lifetime effects
            t = particle.normalized_age
            
            if self.color_over_lifetime:
                color = self.color_over_lifetime.sample(t)
                particle.color = np.array(color)
            
            if self.size_over_lifetime:
                size_mult = self.size_over_lifetime.sample(t)
                particle.size *= size_mult
            
            if particle.is_alive:
                alive_particles.append(particle)
        
        self.particles = alive_particles
    
    def get_vertex_data(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Get vertex data for rendering (positions, colors, sizes)"""
        if not self.particles:
            return np.array([]), np.array([]), np.array([])
        
        positions = np.array([p.position for p in self.particles], dtype=np.float32)
        colors = np.array([p.color for p in self.particles], dtype=np.float32)
        sizes = np.array([p.size for p in self.particles], dtype=np.float32)
        
        return positions, colors, sizes
    
    def play(self):
        """Start emission"""
        self.is_playing = True
    
    def pause(self):
        """Pause emission"""
        self.is_playing = False
    
    def stop(self):
        """Stop and clear"""
        self.is_playing = False
        self.particles.clear()
    
    def clear(self):
        """Clear all particles"""
        self.particles.clear()


class ParticleSystem:
    """
    Complete particle system managing multiple emitters
    with OpenGL rendering support
    """
    
    def __init__(self):
        self.emitters: Dict[str, ParticleEmitter] = {}
        self.global_time: float = 0.0
        
        # Rendering
        self.vao: int = 0
        self.vbo_positions: int = 0
        self.vbo_colors: int = 0
        self.vbo_sizes: int = 0
        self.shader_program: int = 0
        
        self._initialized = False
    
    def add_emitter(self, name: str, emitter: ParticleEmitter):
        """Add an emitter"""
        self.emitters[name] = emitter
    
    def remove_emitter(self, name: str):
        """Remove an emitter"""
        if name in self.emitters:
            del self.emitters[name]
    
    def get_emitter(self, name: str) -> Optional[ParticleEmitter]:
        """Get emitter by name"""
        return self.emitters.get(name)
    
    def update(self, dt: float):
        """Update all emitters"""
        self.global_time += dt
        
        for emitter in self.emitters.values():
            emitter.update(dt)
    
    def get_total_particle_count(self) -> int:
        """Get total number of active particles"""
        return sum(len(e.particles) for e in self.emitters.values())
    
    def clear_all(self):
        """Clear all particles from all emitters"""
        for emitter in self.emitters.values():
            emitter.clear()
    
    # Preset emitter factories
    
    @staticmethod
    def create_fire_emitter(position: Tuple[float, float, float] = (0, 0, 0)) -> ParticleEmitter:
        """Create fire effect emitter"""
        emitter = ParticleEmitter(position=position, shape=EmitterShape.CONE)
        
        emitter.angle = 15
        emitter.emission_rate = 50
        emitter.start_lifetime = (0.5, 1.5)
        emitter.start_speed = (2, 5)
        emitter.start_size = (0.1, 0.3)
        emitter.gravity = np.array([0, 2, 0])  # Float up
        
        # Orange to red gradient
        emitter.color_over_lifetime = ParticleGradient([
            (0.0, (1.0, 0.8, 0.2, 1.0)),
            (0.3, (1.0, 0.4, 0.1, 0.8)),
            (0.7, (0.8, 0.2, 0.1, 0.5)),
            (1.0, (0.2, 0.1, 0.1, 0.0)),
        ])
        
        # Shrink over time
        emitter.size_over_lifetime = SizeOverLife([
            (0.0, 1.0),
            (0.5, 1.2),
            (1.0, 0.0),
        ])
        
        return emitter
    
    @staticmethod
    def create_smoke_emitter(position: Tuple[float, float, float] = (0, 0, 0)) -> ParticleEmitter:
        """Create smoke effect emitter"""
        emitter = ParticleEmitter(position=position, shape=EmitterShape.SPHERE)
        
        emitter.radius = 0.2
        emitter.emission_rate = 20
        emitter.start_lifetime = (2, 4)
        emitter.start_speed = (0.5, 1.5)
        emitter.start_size = (0.2, 0.5)
        emitter.gravity = np.array([0, 0.5, 0])
        emitter.drag = 0.5
        emitter.blend_mode = ParticleBlendMode.ALPHA
        
        # Gray with fade
        emitter.color_over_lifetime = ParticleGradient([
            (0.0, (0.3, 0.3, 0.3, 0.5)),
            (0.5, (0.5, 0.5, 0.5, 0.3)),
            (1.0, (0.7, 0.7, 0.7, 0.0)),
        ])
        
        # Grow then shrink
        emitter.size_over_lifetime = SizeOverLife([
            (0.0, 0.5),
            (0.5, 1.5),
            (1.0, 2.0),
        ])
        
        return emitter
    
    @staticmethod
    def create_explosion_emitter(position: Tuple[float, float, float] = (0, 0, 0)) -> ParticleEmitter:
        """Create explosion effect emitter"""
        emitter = ParticleEmitter(position=position, shape=EmitterShape.SPHERE)
        
        emitter.radius = 0.1
        emitter.emission_rate = 0  # Burst only
        emitter.burst_count = 100
        emitter.start_lifetime = (0.5, 1.5)
        emitter.start_speed = (5, 15)
        emitter.start_size = (0.1, 0.3)
        emitter.gravity = np.array([0, -5, 0])
        emitter.drag = 1.0
        
        # Bright to dark
        emitter.color_over_lifetime = ParticleGradient([
            (0.0, (1.0, 1.0, 0.8, 1.0)),
            (0.2, (1.0, 0.6, 0.2, 1.0)),
            (0.5, (0.8, 0.3, 0.1, 0.8)),
            (1.0, (0.3, 0.1, 0.0, 0.0)),
        ])
        
        emitter.size_over_lifetime = SizeOverLife([
            (0.0, 1.0),
            (0.3, 1.5),
            (1.0, 0.0),
        ])
        
        return emitter
    
    @staticmethod
    def create_data_stream_emitter(
        start: Tuple[float, float, float],
        end: Tuple[float, float, float],
        color: Tuple[float, float, float] = (0, 1, 0.5)
    ) -> ParticleEmitter:
        """Create data stream effect between two points"""
        emitter = ParticleEmitter(position=start, shape=EmitterShape.POINT)
        
        emitter.emission_rate = 30
        emitter.start_lifetime = (0.5, 1.0)
        emitter.start_size = (0.05, 0.1)
        
        # Calculate direction to target
        direction = np.array(end) - np.array(start)
        distance = np.linalg.norm(direction)
        direction = direction / distance if distance > 0 else np.array([0, 1, 0])
        
        emitter.start_speed = (distance * 0.8, distance * 1.2)
        
        # Set velocity towards target
        def spawn_towards_target(particle: Particle):
            speed = np.linalg.norm(particle.velocity)
            particle.velocity = direction * speed
        
        emitter.spawn_callback = spawn_towards_target
        
        # Cyan data stream
        emitter.color_over_lifetime = ParticleGradient([
            (0.0, (*color, 0.0)),
            (0.2, (*color, 1.0)),
            (0.8, (*color, 1.0)),
            (1.0, (*color, 0.0)),
        ])
        
        return emitter
    
    @staticmethod
    def create_attack_stream_emitter(
        source: Tuple[float, float, float],
        target: Tuple[float, float, float],
        severity: str = "medium"
    ) -> ParticleEmitter:
        """Create attack visualization stream"""
        emitter = ParticleEmitter(position=source, shape=EmitterShape.POINT)
        
        # Color based on severity
        severity_colors = {
            "low": (0.2, 0.8, 0.2),
            "medium": (0.9, 0.7, 0.1),
            "high": (0.9, 0.4, 0.1),
            "critical": (0.9, 0.1, 0.1),
        }
        color = severity_colors.get(severity, (0.5, 0.5, 0.5))
        
        emitter.emission_rate = 50
        emitter.start_lifetime = (0.3, 0.6)
        emitter.start_size = (0.08, 0.15)
        
        direction = np.array(target) - np.array(source)
        distance = np.linalg.norm(direction)
        direction = direction / distance if distance > 0 else np.array([1, 0, 0])
        
        emitter.start_speed = (distance * 1.5, distance * 2.0)
        
        def spawn_attack(particle: Particle):
            speed = np.linalg.norm(particle.velocity)
            # Add some spread
            spread = np.array([
                random.uniform(-0.1, 0.1),
                random.uniform(-0.1, 0.1),
                random.uniform(-0.1, 0.1)
            ])
            particle.velocity = (direction + spread) * speed
        
        emitter.spawn_callback = spawn_attack
        
        emitter.color_over_lifetime = ParticleGradient([
            (0.0, (*color, 0.0)),
            (0.1, (*color, 1.0)),
            (0.8, (*color, 0.8)),
            (1.0, (*color, 0.0)),
        ])
        
        return emitter
    
    @staticmethod
    def create_scan_ring_emitter(position: Tuple[float, float, float] = (0, 0, 0)) -> ParticleEmitter:
        """Create expanding scan ring effect"""
        emitter = ParticleEmitter(position=position, shape=EmitterShape.RING)
        
        emitter.radius = 0.5
        emitter.emission_rate = 100
        emitter.start_lifetime = (1.5, 2.5)
        emitter.start_speed = (2, 4)
        emitter.start_size = (0.03, 0.06)
        
        def spawn_outward(particle: Particle):
            # Velocity pointing outward from center
            pos = particle.position - np.array(position)
            pos[1] = 0  # Keep on horizontal plane
            norm = np.linalg.norm(pos)
            if norm > 0:
                direction = pos / norm
                speed = np.linalg.norm(particle.velocity)
                particle.velocity = direction * speed
        
        emitter.spawn_callback = spawn_outward
        
        # Cyan scan color
        emitter.color_over_lifetime = ParticleGradient([
            (0.0, (0.0, 1.0, 1.0, 0.0)),
            (0.2, (0.0, 1.0, 1.0, 0.8)),
            (0.7, (0.0, 0.8, 1.0, 0.5)),
            (1.0, (0.0, 0.5, 1.0, 0.0)),
        ])
        
        return emitter
    
    @staticmethod
    def create_holographic_emitter(
        position: Tuple[float, float, float] = (0, 0, 0),
        size: Tuple[float, float, float] = (2, 3, 2)
    ) -> ParticleEmitter:
        """Create holographic display effect"""
        emitter = ParticleEmitter(position=position, shape=EmitterShape.BOX)
        
        emitter.box_size = size
        emitter.emission_rate = 100
        emitter.start_lifetime = (0.5, 1.5)
        emitter.start_speed = (0.0, 0.2)
        emitter.start_size = (0.02, 0.05)
        emitter.start_rotation_speed = (0, 360)
        
        # Random vertical drift
        def holographic_spawn(particle: Particle):
            particle.velocity = np.array([
                random.uniform(-0.1, 0.1),
                random.uniform(0.5, 1.5),
                random.uniform(-0.1, 0.1)
            ])
        
        emitter.spawn_callback = holographic_spawn
        
        # Cyan holographic
        emitter.color_over_lifetime = ParticleGradient([
            (0.0, (0.0, 0.8, 1.0, 0.0)),
            (0.3, (0.0, 0.9, 1.0, 0.5)),
            (0.7, (0.2, 0.9, 1.0, 0.5)),
            (1.0, (0.0, 0.8, 1.0, 0.0)),
        ])
        
        # Flicker effect
        def holographic_update(particle: Particle, dt: float):
            # Random flicker
            if random.random() < 0.1:
                particle.color[3] *= random.uniform(0.5, 1.0)
        
        emitter.update_callback = holographic_update
        
        return emitter
    
    @staticmethod
    def create_energy_field_emitter(
        position: Tuple[float, float, float] = (0, 0, 0),
        radius: float = 3.0
    ) -> ParticleEmitter:
        """Create energy field effect"""
        emitter = ParticleEmitter(position=position, shape=EmitterShape.SPHERE)
        
        emitter.radius = radius
        emitter.emission_rate = 80
        emitter.start_lifetime = (1.0, 2.0)
        emitter.start_speed = (0.1, 0.3)
        emitter.start_size = (0.03, 0.08)
        
        # Particles orbit around center
        def energy_update(particle: Particle, dt: float):
            center = np.array(position)
            to_center = center - particle.position
            dist = np.linalg.norm(to_center)
            
            if dist > 0.1:
                # Orbital velocity
                tangent = np.cross(to_center / dist, np.array([0, 1, 0]))
                if np.linalg.norm(tangent) > 0:
                    tangent = tangent / np.linalg.norm(tangent)
                    particle.velocity = tangent * 2.0 + to_center * 0.1
        
        emitter.update_callback = energy_update
        
        # Electric blue
        emitter.color_over_lifetime = ParticleGradient([
            (0.0, (0.3, 0.5, 1.0, 0.0)),
            (0.2, (0.5, 0.7, 1.0, 0.8)),
            (0.8, (0.4, 0.6, 1.0, 0.6)),
            (1.0, (0.2, 0.4, 1.0, 0.0)),
        ])
        
        return emitter


# Effect presets for quick use
class EffectPresets:
    """Pre-configured particle effects"""
    
    @staticmethod
    def create_breach_effect(position: Tuple[float, float, float]) -> List[ParticleEmitter]:
        """Create security breach visual effect"""
        emitters = []
        
        # Main explosion
        explosion = ParticleSystem.create_explosion_emitter(position)
        explosion.start_color = (1, 0.2, 0.2, 1)
        explosion.color_over_lifetime = ParticleGradient([
            (0.0, (1.0, 0.5, 0.2, 1.0)),
            (0.3, (1.0, 0.2, 0.1, 0.8)),
            (0.7, (0.5, 0.1, 0.1, 0.4)),
            (1.0, (0.2, 0.0, 0.0, 0.0)),
        ])
        emitters.append(explosion)
        
        # Sparks
        sparks = ParticleEmitter(position=position, shape=EmitterShape.SPHERE)
        sparks.radius = 0.2
        sparks.burst_count = 50
        sparks.emission_rate = 0
        sparks.start_lifetime = (1, 2)
        sparks.start_speed = (10, 20)
        sparks.start_size = (0.02, 0.05)
        sparks.gravity = np.array([0, -10, 0])
        sparks.color_over_lifetime = ParticleGradient([
            (0.0, (1.0, 0.8, 0.3, 1.0)),
            (0.5, (1.0, 0.4, 0.1, 1.0)),
            (1.0, (0.5, 0.1, 0.0, 0.0)),
        ])
        emitters.append(sparks)
        
        return emitters
    
    @staticmethod
    def create_defense_shield(position: Tuple[float, float, float], radius: float = 2.0) -> ParticleEmitter:
        """Create defensive shield effect"""
        emitter = ParticleSystem.create_energy_field_emitter(position, radius)
        
        # Green protective color
        emitter.color_over_lifetime = ParticleGradient([
            (0.0, (0.2, 1.0, 0.4, 0.0)),
            (0.3, (0.3, 1.0, 0.5, 0.6)),
            (0.7, (0.2, 0.9, 0.4, 0.4)),
            (1.0, (0.1, 0.8, 0.3, 0.0)),
        ])
        
        return emitter
    
    @staticmethod
    def create_data_exfiltration(
        source: Tuple[float, float, float],
        target: Tuple[float, float, float]
    ) -> ParticleEmitter:
        """Create data exfiltration visualization"""
        emitter = ParticleSystem.create_attack_stream_emitter(source, target, "critical")
        
        # Red warning color
        emitter.color_over_lifetime = ParticleGradient([
            (0.0, (1.0, 0.0, 0.0, 0.0)),
            (0.2, (1.0, 0.2, 0.0, 1.0)),
            (0.8, (1.0, 0.1, 0.0, 0.8)),
            (1.0, (0.5, 0.0, 0.0, 0.0)),
        ])
        
        return emitter
    
    @staticmethod
    def create_network_pulse(position: Tuple[float, float, float]) -> ParticleEmitter:
        """Create network activity pulse"""
        emitter = ParticleSystem.create_scan_ring_emitter(position)
        
        # Blue network color
        emitter.color_over_lifetime = ParticleGradient([
            (0.0, (0.2, 0.5, 1.0, 0.0)),
            (0.2, (0.3, 0.6, 1.0, 0.6)),
            (0.6, (0.2, 0.5, 0.9, 0.4)),
            (1.0, (0.1, 0.3, 0.8, 0.0)),
        ])
        
        return emitter
