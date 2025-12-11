"""
3D Rendering Engine Core

OpenGL-based 3D rendering engine with modern features:
- PBR (Physically Based Rendering)
- Real-time shadows
- Post-processing effects
- Instanced rendering for large datasets
- Bloom, HDR, SSAO effects
"""

import math
import time
import ctypes
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable
from enum import Enum

from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QPoint
from PyQt6.QtGui import QMatrix4x4, QVector3D, QVector4D, QQuaternion, QColor

try:
    from PyQt6.QtOpenGLWidgets import QOpenGLWidget
    from PyQt6.QtOpenGL import (
        QOpenGLShaderProgram, QOpenGLShader, 
        QOpenGLBuffer, QOpenGLVertexArrayObject,
        QOpenGLFramebufferObject, QOpenGLTexture
    )
    OPENGL_AVAILABLE = True
except ImportError:
    OPENGL_AVAILABLE = False
    QOpenGLWidget = QWidget

try:
    from OpenGL import GL
    from OpenGL.GL import shaders
    PYOPENGL_AVAILABLE = True
except ImportError:
    PYOPENGL_AVAILABLE = False


class RenderMode(Enum):
    """Rendering modes"""
    SOLID = "solid"
    WIREFRAME = "wireframe"
    POINTS = "points"
    HOLOGRAPHIC = "holographic"


class LightType(Enum):
    """Light types"""
    DIRECTIONAL = "directional"
    POINT = "point"
    SPOT = "spot"
    AMBIENT = "ambient"


@dataclass
class Material3D:
    """PBR Material definition"""
    name: str = "default"
    albedo: Tuple[float, float, float] = (0.8, 0.8, 0.8)
    metallic: float = 0.0
    roughness: float = 0.5
    emission: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    emission_strength: float = 0.0
    opacity: float = 1.0
    wireframe: bool = False
    double_sided: bool = False
    
    # Textures (paths or IDs)
    albedo_map: Optional[str] = None
    normal_map: Optional[str] = None
    metallic_map: Optional[str] = None
    roughness_map: Optional[str] = None
    emission_map: Optional[str] = None


@dataclass
class Light3D:
    """Light source definition"""
    light_type: LightType = LightType.DIRECTIONAL
    position: Tuple[float, float, float] = (0, 10, 0)
    direction: Tuple[float, float, float] = (0, -1, 0)
    color: Tuple[float, float, float] = (1.0, 1.0, 1.0)
    intensity: float = 1.0
    range: float = 50.0
    spot_angle: float = 45.0
    cast_shadows: bool = True


@dataclass
class Camera3D:
    """Camera definition"""
    position: Tuple[float, float, float] = (0, 5, 10)
    target: Tuple[float, float, float] = (0, 0, 0)
    up: Tuple[float, float, float] = (0, 1, 0)
    fov: float = 60.0
    near: float = 0.1
    far: float = 1000.0
    orthographic: bool = False
    ortho_size: float = 10.0
    
    # Animation
    orbit_enabled: bool = True
    orbit_speed: float = 0.5
    zoom_speed: float = 0.1
    pan_speed: float = 0.01
    
    def get_view_matrix(self) -> QMatrix4x4:
        """Calculate view matrix"""
        view = QMatrix4x4()
        view.lookAt(
            QVector3D(*self.position),
            QVector3D(*self.target),
            QVector3D(*self.up)
        )
        return view
    
    def get_projection_matrix(self, aspect: float) -> QMatrix4x4:
        """Calculate projection matrix"""
        proj = QMatrix4x4()
        if self.orthographic:
            proj.ortho(
                -self.ortho_size * aspect, self.ortho_size * aspect,
                -self.ortho_size, self.ortho_size,
                self.near, self.far
            )
        else:
            proj.perspective(self.fov, aspect, self.near, self.far)
        return proj
    
    def orbit(self, dx: float, dy: float):
        """Orbit camera around target"""
        # Calculate current angles
        pos = QVector3D(*self.position)
        target = QVector3D(*self.target)
        offset = pos - target
        
        radius = offset.length()
        theta = math.atan2(offset.x(), offset.z())
        phi = math.acos(offset.y() / radius) if radius > 0 else 0
        
        # Apply rotation
        theta -= dx * self.orbit_speed * 0.01
        phi = max(0.1, min(math.pi - 0.1, phi + dy * self.orbit_speed * 0.01))
        
        # Calculate new position
        self.position = (
            target.x() + radius * math.sin(phi) * math.sin(theta),
            target.y() + radius * math.cos(phi),
            target.z() + radius * math.sin(phi) * math.cos(theta)
        )
    
    def zoom(self, delta: float):
        """Zoom camera"""
        pos = QVector3D(*self.position)
        target = QVector3D(*self.target)
        direction = (pos - target).normalized()
        
        distance = (pos - target).length()
        new_distance = max(1.0, distance - delta * self.zoom_speed * distance)
        
        new_pos = target + direction * new_distance
        self.position = (new_pos.x(), new_pos.y(), new_pos.z())
    
    def pan(self, dx: float, dy: float):
        """Pan camera"""
        pos = QVector3D(*self.position)
        target = QVector3D(*self.target)
        
        forward = (target - pos).normalized()
        right = QVector3D.crossProduct(forward, QVector3D(*self.up)).normalized()
        up = QVector3D.crossProduct(right, forward).normalized()
        
        offset = right * (-dx * self.pan_speed) + up * (dy * self.pan_speed)
        
        self.position = (
            pos.x() + offset.x(),
            pos.y() + offset.y(),
            pos.z() + offset.z()
        )
        self.target = (
            target.x() + offset.x(),
            target.y() + offset.y(),
            target.z() + offset.z()
        )


@dataclass
class Mesh3D:
    """3D mesh data"""
    vertices: np.ndarray = field(default_factory=lambda: np.array([], dtype=np.float32))
    normals: np.ndarray = field(default_factory=lambda: np.array([], dtype=np.float32))
    uvs: np.ndarray = field(default_factory=lambda: np.array([], dtype=np.float32))
    indices: np.ndarray = field(default_factory=lambda: np.array([], dtype=np.uint32))
    colors: np.ndarray = field(default_factory=lambda: np.array([], dtype=np.float32))
    
    # GPU resources
    vao: Optional[Any] = None
    vbo_vertices: Optional[Any] = None
    vbo_normals: Optional[Any] = None
    vbo_uvs: Optional[Any] = None
    vbo_colors: Optional[Any] = None
    ebo: Optional[Any] = None
    
    @classmethod
    def create_cube(cls, size: float = 1.0) -> 'Mesh3D':
        """Create a cube mesh"""
        s = size / 2
        vertices = np.array([
            # Front face
            -s, -s,  s,   s, -s,  s,   s,  s,  s,  -s,  s,  s,
            # Back face
            -s, -s, -s,  -s,  s, -s,   s,  s, -s,   s, -s, -s,
            # Top face
            -s,  s, -s,  -s,  s,  s,   s,  s,  s,   s,  s, -s,
            # Bottom face
            -s, -s, -s,   s, -s, -s,   s, -s,  s,  -s, -s,  s,
            # Right face
             s, -s, -s,   s,  s, -s,   s,  s,  s,   s, -s,  s,
            # Left face
            -s, -s, -s,  -s, -s,  s,  -s,  s,  s,  -s,  s, -s,
        ], dtype=np.float32)
        
        normals = np.array([
            # Front
            0, 0, 1,  0, 0, 1,  0, 0, 1,  0, 0, 1,
            # Back
            0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1,
            # Top
            0, 1, 0,  0, 1, 0,  0, 1, 0,  0, 1, 0,
            # Bottom
            0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0,
            # Right
            1, 0, 0,  1, 0, 0,  1, 0, 0,  1, 0, 0,
            # Left
            -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0,
        ], dtype=np.float32)
        
        indices = np.array([
            0, 1, 2, 0, 2, 3,       # Front
            4, 5, 6, 4, 6, 7,       # Back
            8, 9, 10, 8, 10, 11,    # Top
            12, 13, 14, 12, 14, 15, # Bottom
            16, 17, 18, 16, 18, 19, # Right
            20, 21, 22, 20, 22, 23, # Left
        ], dtype=np.uint32)
        
        return cls(vertices=vertices, normals=normals, indices=indices)
    
    @classmethod
    def create_box(cls, width: float = 1.0, height: float = 1.0, depth: float = 1.0) -> 'Mesh3D':
        """Create a box mesh with specified dimensions"""
        w, h, d = width / 2, height / 2, depth / 2
        vertices = np.array([
            # Front face
            -w, -h,  d,   w, -h,  d,   w,  h,  d,  -w,  h,  d,
            # Back face
            -w, -h, -d,  -w,  h, -d,   w,  h, -d,   w, -h, -d,
            # Top face
            -w,  h, -d,  -w,  h,  d,   w,  h,  d,   w,  h, -d,
            # Bottom face
            -w, -h, -d,   w, -h, -d,   w, -h,  d,  -w, -h,  d,
            # Right face
             w, -h, -d,   w,  h, -d,   w,  h,  d,   w, -h,  d,
            # Left face
            -w, -h, -d,  -w, -h,  d,  -w,  h,  d,  -w,  h, -d,
        ], dtype=np.float32)
        
        normals = np.array([
            # Front
            0, 0, 1,  0, 0, 1,  0, 0, 1,  0, 0, 1,
            # Back
            0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1,
            # Top
            0, 1, 0,  0, 1, 0,  0, 1, 0,  0, 1, 0,
            # Bottom
            0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0,
            # Right
            1, 0, 0,  1, 0, 0,  1, 0, 0,  1, 0, 0,
            # Left
            -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0,
        ], dtype=np.float32)
        
        indices = np.array([
            0, 1, 2, 0, 2, 3,       # Front
            4, 5, 6, 4, 6, 7,       # Back
            8, 9, 10, 8, 10, 11,    # Top
            12, 13, 14, 12, 14, 15, # Bottom
            16, 17, 18, 16, 18, 19, # Right
            20, 21, 22, 20, 22, 23, # Left
        ], dtype=np.uint32)
        
        return cls(vertices=vertices, normals=normals, indices=indices)
    
    @classmethod
    def create_sphere(cls, radius: float = 1.0, segments: int = 32, rings: int = 16) -> 'Mesh3D':
        """Create a sphere mesh"""
        vertices = []
        normals = []
        indices = []
        
        for ring in range(rings + 1):
            phi = math.pi * ring / rings
            for seg in range(segments + 1):
                theta = 2 * math.pi * seg / segments
                
                x = radius * math.sin(phi) * math.cos(theta)
                y = radius * math.cos(phi)
                z = radius * math.sin(phi) * math.sin(theta)
                
                vertices.extend([x, y, z])
                
                # Normal is same as position for unit sphere
                length = math.sqrt(x*x + y*y + z*z)
                if length > 0:
                    normals.extend([x/length, y/length, z/length])
                else:
                    normals.extend([0, 1, 0])
        
        for ring in range(rings):
            for seg in range(segments):
                current = ring * (segments + 1) + seg
                next_ring = (ring + 1) * (segments + 1) + seg
                
                indices.extend([
                    current, next_ring, current + 1,
                    current + 1, next_ring, next_ring + 1
                ])
        
        return cls(
            vertices=np.array(vertices, dtype=np.float32),
            normals=np.array(normals, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
    
    @classmethod
    def create_cylinder(cls, radius: float = 1.0, height: float = 2.0, segments: int = 32) -> 'Mesh3D':
        """Create a cylinder mesh"""
        vertices = []
        normals = []
        indices = []
        
        half_height = height / 2
        
        # Side vertices
        for i in range(segments + 1):
            theta = 2 * math.pi * i / segments
            x = radius * math.cos(theta)
            z = radius * math.sin(theta)
            
            # Bottom
            vertices.extend([x, -half_height, z])
            normals.extend([math.cos(theta), 0, math.sin(theta)])
            
            # Top
            vertices.extend([x, half_height, z])
            normals.extend([math.cos(theta), 0, math.sin(theta)])
        
        # Side indices
        for i in range(segments):
            base = i * 2
            indices.extend([
                base, base + 1, base + 2,
                base + 2, base + 1, base + 3
            ])
        
        # Cap centers
        bottom_center = len(vertices) // 3
        vertices.extend([0, -half_height, 0])
        normals.extend([0, -1, 0])
        
        top_center = len(vertices) // 3
        vertices.extend([0, half_height, 0])
        normals.extend([0, 1, 0])
        
        # Cap vertices and indices
        for i in range(segments + 1):
            theta = 2 * math.pi * i / segments
            x = radius * math.cos(theta)
            z = radius * math.sin(theta)
            
            # Bottom cap
            bottom_idx = len(vertices) // 3
            vertices.extend([x, -half_height, z])
            normals.extend([0, -1, 0])
            
            # Top cap
            top_idx = len(vertices) // 3
            vertices.extend([x, half_height, z])
            normals.extend([0, 1, 0])
            
            if i > 0:
                indices.extend([bottom_center, bottom_idx, bottom_idx - 2])
                indices.extend([top_center, top_idx - 2, top_idx])
        
        return cls(
            vertices=np.array(vertices, dtype=np.float32),
            normals=np.array(normals, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
    
    @classmethod
    def create_torus(cls, major_radius: float = 1.0, minor_radius: float = 0.3,
                     major_segments: int = 24, minor_segments: int = 12) -> 'Mesh3D':
        """Create a torus (donut) mesh"""
        vertices = []
        normals = []
        indices = []
        
        for i in range(major_segments):
            theta = 2 * math.pi * i / major_segments
            cos_theta = math.cos(theta)
            sin_theta = math.sin(theta)
            
            for j in range(minor_segments):
                phi = 2 * math.pi * j / minor_segments
                cos_phi = math.cos(phi)
                sin_phi = math.sin(phi)
                
                # Position on torus
                x = (major_radius + minor_radius * cos_phi) * cos_theta
                y = minor_radius * sin_phi
                z = (major_radius + minor_radius * cos_phi) * sin_theta
                
                # Normal
                nx = cos_phi * cos_theta
                ny = sin_phi
                nz = cos_phi * sin_theta
                
                vertices.extend([x, y, z])
                normals.extend([nx, ny, nz])
        
        # Indices
        for i in range(major_segments):
            next_i = (i + 1) % major_segments
            for j in range(minor_segments):
                next_j = (j + 1) % minor_segments
                
                current = i * minor_segments + j
                next_ring = next_i * minor_segments + j
                
                indices.extend([
                    current, next_ring, i * minor_segments + next_j,
                    i * minor_segments + next_j, next_ring, next_i * minor_segments + next_j
                ])
        
        return cls(
            vertices=np.array(vertices, dtype=np.float32),
            normals=np.array(normals, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
    
    @classmethod
    def create_cone(cls, radius: float = 1.0, height: float = 2.0, 
                    segments: int = 24) -> 'Mesh3D':
        """Create a cone mesh"""
        vertices = []
        normals = []
        indices = []
        
        # Apex at top
        apex_idx = 0
        vertices.extend([0, height, 0])
        normals.extend([0, 1, 0])
        
        # Base center
        base_center_idx = 1
        vertices.extend([0, 0, 0])
        normals.extend([0, -1, 0])
        
        # Base rim and sides
        slope = radius / height
        for i in range(segments + 1):
            theta = 2 * math.pi * i / segments
            cos_t = math.cos(theta)
            sin_t = math.sin(theta)
            
            x = radius * cos_t
            z = radius * sin_t
            
            # Side vertex
            side_idx = len(vertices) // 3
            vertices.extend([x, 0, z])
            
            # Normal for cone side (points outward and up)
            ny = slope / math.sqrt(1 + slope * slope)
            nxz = 1 / math.sqrt(1 + slope * slope)
            normals.extend([nxz * cos_t, ny, nxz * sin_t])
            
            # Base vertex
            base_idx = len(vertices) // 3
            vertices.extend([x, 0, z])
            normals.extend([0, -1, 0])
            
            if i > 0:
                # Side triangle
                indices.extend([apex_idx, side_idx - 2, side_idx])
                # Base triangle
                indices.extend([base_center_idx, base_idx, base_idx - 2])
        
        return cls(
            vertices=np.array(vertices, dtype=np.float32),
            normals=np.array(normals, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
    
    @classmethod
    def create_plane(cls, width: float = 10.0, depth: float = 10.0, 
                    subdivisions: int = 1) -> 'Mesh3D':
        """Create a plane mesh"""
        vertices = []
        normals = []
        uvs = []
        indices = []
        
        step_x = width / subdivisions
        step_z = depth / subdivisions
        
        for z in range(subdivisions + 1):
            for x in range(subdivisions + 1):
                px = -width / 2 + x * step_x
                pz = -depth / 2 + z * step_z
                
                vertices.extend([px, 0, pz])
                normals.extend([0, 1, 0])
                uvs.extend([x / subdivisions, z / subdivisions])
        
        for z in range(subdivisions):
            for x in range(subdivisions):
                current = z * (subdivisions + 1) + x
                indices.extend([
                    current, current + subdivisions + 1, current + 1,
                    current + 1, current + subdivisions + 1, current + subdivisions + 2
                ])
        
        return cls(
            vertices=np.array(vertices, dtype=np.float32),
            normals=np.array(normals, dtype=np.float32),
            uvs=np.array(uvs, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
    
    @classmethod
    def create_line(cls, start: Tuple[float, float, float], 
                   end: Tuple[float, float, float]) -> 'Mesh3D':
        """Create a line mesh"""
        vertices = np.array([*start, *end], dtype=np.float32)
        indices = np.array([0, 1], dtype=np.uint32)
        return cls(vertices=vertices, indices=indices)
    
    @classmethod
    def create_grid(cls, size: float = 20.0, divisions: int = 20) -> 'Mesh3D':
        """Create a grid mesh"""
        vertices = []
        indices = []
        
        step = size / divisions
        half = size / 2
        
        idx = 0
        for i in range(divisions + 1):
            pos = -half + i * step
            
            # X-axis lines
            vertices.extend([pos, 0, -half, pos, 0, half])
            indices.extend([idx, idx + 1])
            idx += 2
            
            # Z-axis lines
            vertices.extend([-half, 0, pos, half, 0, pos])
            indices.extend([idx, idx + 1])
            idx += 2
        
        return cls(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )


@dataclass
class Object3D:
    """3D object with transform"""
    name: str = "object"
    mesh: Optional[Mesh3D] = None
    material: Material3D = field(default_factory=Material3D)
    
    position: Tuple[float, float, float] = (0, 0, 0)
    rotation: Tuple[float, float, float] = (0, 0, 0)  # Euler angles in degrees
    scale: Tuple[float, float, float] = (1, 1, 1)
    
    visible: bool = True
    cast_shadows: bool = True
    receive_shadows: bool = True
    
    children: List['Object3D'] = field(default_factory=list)
    parent: Optional['Object3D'] = None
    
    # Animation
    animation_callback: Optional[Callable] = None
    
    # User data
    data: Dict[str, Any] = field(default_factory=dict)
    
    def get_model_matrix(self) -> QMatrix4x4:
        """Calculate model matrix"""
        matrix = QMatrix4x4()
        matrix.translate(*self.position)
        matrix.rotate(self.rotation[0], 1, 0, 0)
        matrix.rotate(self.rotation[1], 0, 1, 0)
        matrix.rotate(self.rotation[2], 0, 0, 1)
        matrix.scale(*self.scale)
        return matrix
    
    def get_world_matrix(self) -> QMatrix4x4:
        """Get world transform matrix"""
        local = self.get_model_matrix()
        if self.parent:
            return self.parent.get_world_matrix() * local
        return local
    
    def add_child(self, child: 'Object3D'):
        """Add child object"""
        child.parent = self
        self.children.append(child)
    
    def update(self, delta_time: float):
        """Update object"""
        if self.animation_callback:
            self.animation_callback(self, delta_time)
        
        for child in self.children:
            child.update(delta_time)


@dataclass
class Scene3D:
    """3D scene container"""
    name: str = "scene"
    objects: List[Object3D] = field(default_factory=list)
    lights: List[Light3D] = field(default_factory=list)
    camera: Camera3D = field(default_factory=Camera3D)
    
    # Environment
    ambient_color: Tuple[float, float, float] = (0.1, 0.1, 0.15)
    background_color: Tuple[float, float, float] = (0.02, 0.02, 0.05)
    fog_enabled: bool = False
    fog_density: float = 0.01
    fog_color: Tuple[float, float, float] = (0.5, 0.5, 0.5)
    
    # Post-processing
    bloom_enabled: bool = True
    bloom_intensity: float = 1.0
    bloom_threshold: float = 0.8
    
    hdr_enabled: bool = True
    exposure: float = 1.0
    gamma: float = 2.2
    
    ssao_enabled: bool = False
    ssao_radius: float = 0.5
    ssao_intensity: float = 1.0
    
    def add_object(self, obj: Object3D):
        """Add object to scene"""
        self.objects.append(obj)
    
    def add_light(self, light: Light3D):
        """Add light to scene"""
        self.lights.append(light)
    
    def remove_object(self, obj: Object3D):
        """Remove object from scene"""
        if obj in self.objects:
            self.objects.remove(obj)
    
    def find_object(self, name: str) -> Optional[Object3D]:
        """Find object by name"""
        for obj in self.objects:
            if obj.name == name:
                return obj
        return None
    
    def update(self, delta_time: float):
        """Update scene"""
        for obj in self.objects:
            obj.update(delta_time)


@dataclass
class Shader3D:
    """Shader program wrapper"""
    name: str = "default"
    vertex_source: str = ""
    fragment_source: str = ""
    geometry_source: str = ""
    program: Optional[Any] = None


@dataclass
class RenderTarget3D:
    """Render target for post-processing"""
    width: int = 1920
    height: int = 1080
    fbo: Optional[Any] = None
    color_texture: Optional[Any] = None
    depth_texture: Optional[Any] = None
    samples: int = 4  # MSAA samples


# Shader sources
VERTEX_SHADER_PBR = """
#version 330 core

layout(location = 0) in vec3 aPos;
layout(location = 1) in vec3 aNormal;
layout(location = 2) in vec2 aTexCoord;
layout(location = 3) in vec4 aColor;

uniform mat4 model;
uniform mat4 view;
uniform mat4 projection;
uniform mat3 normalMatrix;

out vec3 FragPos;
out vec3 Normal;
out vec2 TexCoord;
out vec4 VertexColor;

void main() {
    FragPos = vec3(model * vec4(aPos, 1.0));
    Normal = normalMatrix * aNormal;
    TexCoord = aTexCoord;
    VertexColor = aColor;
    gl_Position = projection * view * model * vec4(aPos, 1.0);
}
"""

FRAGMENT_SHADER_PBR = """
#version 330 core

in vec3 FragPos;
in vec3 Normal;
in vec2 TexCoord;
in vec4 VertexColor;

out vec4 FragColor;

// Material
uniform vec3 albedo;
uniform float metallic;
uniform float roughness;
uniform vec3 emission;
uniform float emissionStrength;
uniform float opacity;

// Lights
uniform vec3 lightPositions[8];
uniform vec3 lightColors[8];
uniform float lightIntensities[8];
uniform int numLights;

uniform vec3 viewPos;
uniform vec3 ambientColor;

const float PI = 3.14159265359;

// PBR functions
float DistributionGGX(vec3 N, vec3 H, float roughness) {
    float a = roughness * roughness;
    float a2 = a * a;
    float NdotH = max(dot(N, H), 0.0);
    float NdotH2 = NdotH * NdotH;
    
    float num = a2;
    float denom = (NdotH2 * (a2 - 1.0) + 1.0);
    denom = PI * denom * denom;
    
    return num / denom;
}

float GeometrySchlickGGX(float NdotV, float roughness) {
    float r = (roughness + 1.0);
    float k = (r * r) / 8.0;
    
    float num = NdotV;
    float denom = NdotV * (1.0 - k) + k;
    
    return num / denom;
}

float GeometrySmith(vec3 N, vec3 V, vec3 L, float roughness) {
    float NdotV = max(dot(N, V), 0.0);
    float NdotL = max(dot(N, L), 0.0);
    float ggx2 = GeometrySchlickGGX(NdotV, roughness);
    float ggx1 = GeometrySchlickGGX(NdotL, roughness);
    
    return ggx1 * ggx2;
}

vec3 fresnelSchlick(float cosTheta, vec3 F0) {
    return F0 + (1.0 - F0) * pow(clamp(1.0 - cosTheta, 0.0, 1.0), 5.0);
}

void main() {
    vec3 N = normalize(Normal);
    vec3 V = normalize(viewPos - FragPos);
    
    vec3 F0 = vec3(0.04);
    F0 = mix(F0, albedo, metallic);
    
    vec3 Lo = vec3(0.0);
    
    for(int i = 0; i < numLights && i < 8; i++) {
        vec3 L = normalize(lightPositions[i] - FragPos);
        vec3 H = normalize(V + L);
        float distance = length(lightPositions[i] - FragPos);
        float attenuation = 1.0 / (distance * distance);
        vec3 radiance = lightColors[i] * lightIntensities[i] * attenuation;
        
        float NDF = DistributionGGX(N, H, roughness);
        float G = GeometrySmith(N, V, L, roughness);
        vec3 F = fresnelSchlick(max(dot(H, V), 0.0), F0);
        
        vec3 kS = F;
        vec3 kD = vec3(1.0) - kS;
        kD *= 1.0 - metallic;
        
        vec3 numerator = NDF * G * F;
        float denominator = 4.0 * max(dot(N, V), 0.0) * max(dot(N, L), 0.0) + 0.0001;
        vec3 specular = numerator / denominator;
        
        float NdotL = max(dot(N, L), 0.0);
        Lo += (kD * albedo / PI + specular) * radiance * NdotL;
    }
    
    vec3 ambient = ambientColor * albedo;
    vec3 color = ambient + Lo + emission * emissionStrength;
    
    // HDR tonemapping
    color = color / (color + vec3(1.0));
    
    // Gamma correction
    color = pow(color, vec3(1.0/2.2));
    
    FragColor = vec4(color, opacity);
}
"""

VERTEX_SHADER_HOLOGRAPHIC = """
#version 330 core

layout(location = 0) in vec3 aPos;
layout(location = 1) in vec3 aNormal;

uniform mat4 model;
uniform mat4 view;
uniform mat4 projection;
uniform float time;

out vec3 FragPos;
out vec3 Normal;
out float ScanLine;

void main() {
    vec3 pos = aPos;
    
    // Add subtle wave effect
    pos += aNormal * sin(time * 2.0 + aPos.y * 5.0) * 0.01;
    
    FragPos = vec3(model * vec4(pos, 1.0));
    Normal = mat3(transpose(inverse(model))) * aNormal;
    ScanLine = aPos.y + time * 0.5;
    
    gl_Position = projection * view * model * vec4(pos, 1.0);
}
"""

FRAGMENT_SHADER_HOLOGRAPHIC = """
#version 330 core

in vec3 FragPos;
in vec3 Normal;
in float ScanLine;

out vec4 FragColor;

uniform vec3 holoColor;
uniform float time;
uniform vec3 viewPos;

void main() {
    vec3 N = normalize(Normal);
    vec3 V = normalize(viewPos - FragPos);
    
    // Fresnel effect for edges
    float fresnel = pow(1.0 - max(dot(N, V), 0.0), 3.0);
    
    // Scan lines
    float scanLineIntensity = sin(ScanLine * 50.0) * 0.5 + 0.5;
    scanLineIntensity = mix(0.8, 1.0, scanLineIntensity);
    
    // Flicker
    float flicker = sin(time * 30.0) * 0.05 + 0.95;
    
    // Base color with fresnel glow
    vec3 color = holoColor * (0.3 + fresnel * 0.7);
    color *= scanLineIntensity * flicker;
    
    // Alpha based on fresnel and scan lines
    float alpha = mix(0.3, 0.8, fresnel) * scanLineIntensity;
    
    FragColor = vec4(color, alpha);
}
"""

VERTEX_SHADER_LINE = """
#version 330 core

layout(location = 0) in vec3 aPos;
layout(location = 1) in vec4 aColor;

uniform mat4 model;
uniform mat4 view;
uniform mat4 projection;

out vec4 VertexColor;

void main() {
    VertexColor = aColor;
    gl_Position = projection * view * model * vec4(aPos, 1.0);
}
"""

FRAGMENT_SHADER_LINE = """
#version 330 core

in vec4 VertexColor;
out vec4 FragColor;

uniform vec4 lineColor;

void main() {
    FragColor = VertexColor * lineColor;
}
"""

VERTEX_SHADER_BLOOM = """
#version 330 core

layout(location = 0) in vec2 aPos;
layout(location = 1) in vec2 aTexCoord;

out vec2 TexCoord;

void main() {
    TexCoord = aTexCoord;
    gl_Position = vec4(aPos, 0.0, 1.0);
}
"""

FRAGMENT_SHADER_BLOOM_BRIGHT = """
#version 330 core

in vec2 TexCoord;
out vec4 FragColor;

uniform sampler2D scene;
uniform float threshold;

void main() {
    vec3 color = texture(scene, TexCoord).rgb;
    float brightness = dot(color, vec3(0.2126, 0.7152, 0.0722));
    
    if(brightness > threshold)
        FragColor = vec4(color, 1.0);
    else
        FragColor = vec4(0.0, 0.0, 0.0, 1.0);
}
"""

FRAGMENT_SHADER_BLOOM_BLUR = """
#version 330 core

in vec2 TexCoord;
out vec4 FragColor;

uniform sampler2D image;
uniform bool horizontal;
uniform float weight[5] = float[] (0.227027, 0.1945946, 0.1216216, 0.054054, 0.016216);

void main() {
    vec2 tex_offset = 1.0 / textureSize(image, 0);
    vec3 result = texture(image, TexCoord).rgb * weight[0];
    
    if(horizontal) {
        for(int i = 1; i < 5; ++i) {
            result += texture(image, TexCoord + vec2(tex_offset.x * i, 0.0)).rgb * weight[i];
            result += texture(image, TexCoord - vec2(tex_offset.x * i, 0.0)).rgb * weight[i];
        }
    } else {
        for(int i = 1; i < 5; ++i) {
            result += texture(image, TexCoord + vec2(0.0, tex_offset.y * i)).rgb * weight[i];
            result += texture(image, TexCoord - vec2(0.0, tex_offset.y * i)).rgb * weight[i];
        }
    }
    
    FragColor = vec4(result, 1.0);
}
"""

FRAGMENT_SHADER_BLOOM_FINAL = """
#version 330 core

in vec2 TexCoord;
out vec4 FragColor;

uniform sampler2D scene;
uniform sampler2D bloomBlur;
uniform float bloomIntensity;
uniform float exposure;
uniform float gamma;

void main() {
    vec3 hdrColor = texture(scene, TexCoord).rgb;
    vec3 bloomColor = texture(bloomBlur, TexCoord).rgb;
    
    hdrColor += bloomColor * bloomIntensity;
    
    // Exposure tone mapping
    vec3 result = vec3(1.0) - exp(-hdrColor * exposure);
    
    // Gamma correction
    result = pow(result, vec3(1.0 / gamma));
    
    FragColor = vec4(result, 1.0);
}
"""


class Visualization3DEngine(QOpenGLWidget if OPENGL_AVAILABLE else QWidget):
    """Main 3D visualization engine widget"""
    
    objectClicked = pyqtSignal(object)
    objectHovered = pyqtSignal(object)
    sceneUpdated = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.scene = Scene3D()
        self.render_mode = RenderMode.SOLID
        
        # Shaders
        self.shaders: Dict[str, Any] = {}
        
        # Timing
        self.last_time = time.time()
        self.delta_time = 0.0
        self.frame_count = 0
        self.fps = 0.0
        
        # Render targets for post-processing
        self.render_targets: Dict[str, RenderTarget3D] = {}
        
        # Mouse interaction
        self.last_mouse_pos = QPoint()
        self.mouse_pressed = False
        self.mouse_button = Qt.MouseButton.NoButton
        
        # Picking
        self.hovered_object: Optional[Object3D] = None
        self.selected_objects: List[Object3D] = []
        
        # Setup
        self.setMinimumSize(400, 300)
        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        
        # Animation timer
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self.update)
        self.animation_timer.start(16)  # ~60 FPS
    
    def initializeGL(self):
        """Initialize OpenGL"""
        if not PYOPENGL_AVAILABLE:
            return
        
        # Enable features
        GL.glEnable(GL.GL_DEPTH_TEST)
        GL.glEnable(GL.GL_BLEND)
        GL.glBlendFunc(GL.GL_SRC_ALPHA, GL.GL_ONE_MINUS_SRC_ALPHA)
        GL.glEnable(GL.GL_CULL_FACE)
        GL.glCullFace(GL.GL_BACK)
        GL.glEnable(GL.GL_MULTISAMPLE)
        
        # Set background color
        bg = self.scene.background_color
        GL.glClearColor(bg[0], bg[1], bg[2], 1.0)
        
        # Compile shaders
        self._compile_shaders()
        
        # Create default meshes
        self._create_default_meshes()
        
        # Setup render targets
        self._setup_render_targets()
    
    def _compile_shaders(self):
        """Compile shader programs"""
        if not PYOPENGL_AVAILABLE:
            return
        
        shader_sources = {
            'pbr': (VERTEX_SHADER_PBR, FRAGMENT_SHADER_PBR),
            'holographic': (VERTEX_SHADER_HOLOGRAPHIC, FRAGMENT_SHADER_HOLOGRAPHIC),
            'line': (VERTEX_SHADER_LINE, FRAGMENT_SHADER_LINE),
            'bloom_bright': (VERTEX_SHADER_BLOOM, FRAGMENT_SHADER_BLOOM_BRIGHT),
            'bloom_blur': (VERTEX_SHADER_BLOOM, FRAGMENT_SHADER_BLOOM_BLUR),
            'bloom_final': (VERTEX_SHADER_BLOOM, FRAGMENT_SHADER_BLOOM_FINAL),
        }
        
        for name, (vert, frag) in shader_sources.items():
            try:
                vertex_shader = shaders.compileShader(vert, GL.GL_VERTEX_SHADER)
                fragment_shader = shaders.compileShader(frag, GL.GL_FRAGMENT_SHADER)
                program = shaders.compileProgram(vertex_shader, fragment_shader)
                self.shaders[name] = program
            except Exception as e:
                print(f"Failed to compile shader '{name}': {e}")
    
    def _create_default_meshes(self):
        """Create default primitive meshes"""
        pass  # Meshes are created on demand
    
    def _setup_render_targets(self):
        """Setup framebuffers for post-processing"""
        if not PYOPENGL_AVAILABLE:
            return
        
        w, h = self.width() or 800, self.height() or 600
        
        # Main render target
        self.render_targets['main'] = self._create_render_target(w, h)
        
        # Bloom targets
        self.render_targets['bloom_bright'] = self._create_render_target(w // 2, h // 2)
        self.render_targets['bloom_blur_h'] = self._create_render_target(w // 2, h // 2)
        self.render_targets['bloom_blur_v'] = self._create_render_target(w // 2, h // 2)
    
    def _create_render_target(self, width: int, height: int) -> RenderTarget3D:
        """Create a render target"""
        target = RenderTarget3D(width=width, height=height)
        
        if PYOPENGL_AVAILABLE:
            # Create FBO
            target.fbo = GL.glGenFramebuffers(1)
            GL.glBindFramebuffer(GL.GL_FRAMEBUFFER, target.fbo)
            
            # Color texture
            target.color_texture = GL.glGenTextures(1)
            GL.glBindTexture(GL.GL_TEXTURE_2D, target.color_texture)
            GL.glTexImage2D(GL.GL_TEXTURE_2D, 0, GL.GL_RGBA16F, width, height, 
                           0, GL.GL_RGBA, GL.GL_FLOAT, None)
            GL.glTexParameteri(GL.GL_TEXTURE_2D, GL.GL_TEXTURE_MIN_FILTER, GL.GL_LINEAR)
            GL.glTexParameteri(GL.GL_TEXTURE_2D, GL.GL_TEXTURE_MAG_FILTER, GL.GL_LINEAR)
            GL.glTexParameteri(GL.GL_TEXTURE_2D, GL.GL_TEXTURE_WRAP_S, GL.GL_CLAMP_TO_EDGE)
            GL.glTexParameteri(GL.GL_TEXTURE_2D, GL.GL_TEXTURE_WRAP_T, GL.GL_CLAMP_TO_EDGE)
            GL.glFramebufferTexture2D(GL.GL_FRAMEBUFFER, GL.GL_COLOR_ATTACHMENT0,
                                      GL.GL_TEXTURE_2D, target.color_texture, 0)
            
            # Depth texture
            target.depth_texture = GL.glGenTextures(1)
            GL.glBindTexture(GL.GL_TEXTURE_2D, target.depth_texture)
            GL.glTexImage2D(GL.GL_TEXTURE_2D, 0, GL.GL_DEPTH_COMPONENT24, width, height,
                           0, GL.GL_DEPTH_COMPONENT, GL.GL_FLOAT, None)
            GL.glFramebufferTexture2D(GL.GL_FRAMEBUFFER, GL.GL_DEPTH_ATTACHMENT,
                                      GL.GL_TEXTURE_2D, target.depth_texture, 0)
            
            GL.glBindFramebuffer(GL.GL_FRAMEBUFFER, 0)
        
        return target
    
    def _upload_mesh(self, mesh: Mesh3D):
        """Upload mesh data to GPU"""
        if not PYOPENGL_AVAILABLE or mesh.vao is not None:
            return
        
        mesh.vao = GL.glGenVertexArrays(1)
        GL.glBindVertexArray(mesh.vao)
        
        # Vertices
        if len(mesh.vertices) > 0:
            mesh.vbo_vertices = GL.glGenBuffers(1)
            GL.glBindBuffer(GL.GL_ARRAY_BUFFER, mesh.vbo_vertices)
            GL.glBufferData(GL.GL_ARRAY_BUFFER, mesh.vertices.nbytes, 
                           mesh.vertices, GL.GL_STATIC_DRAW)
            GL.glVertexAttribPointer(0, 3, GL.GL_FLOAT, GL.GL_FALSE, 0, None)
            GL.glEnableVertexAttribArray(0)
        
        # Normals
        if len(mesh.normals) > 0:
            mesh.vbo_normals = GL.glGenBuffers(1)
            GL.glBindBuffer(GL.GL_ARRAY_BUFFER, mesh.vbo_normals)
            GL.glBufferData(GL.GL_ARRAY_BUFFER, mesh.normals.nbytes,
                           mesh.normals, GL.GL_STATIC_DRAW)
            GL.glVertexAttribPointer(1, 3, GL.GL_FLOAT, GL.GL_FALSE, 0, None)
            GL.glEnableVertexAttribArray(1)
        
        # UVs
        if len(mesh.uvs) > 0:
            mesh.vbo_uvs = GL.glGenBuffers(1)
            GL.glBindBuffer(GL.GL_ARRAY_BUFFER, mesh.vbo_uvs)
            GL.glBufferData(GL.GL_ARRAY_BUFFER, mesh.uvs.nbytes,
                           mesh.uvs, GL.GL_STATIC_DRAW)
            GL.glVertexAttribPointer(2, 2, GL.GL_FLOAT, GL.GL_FALSE, 0, None)
            GL.glEnableVertexAttribArray(2)
        
        # Colors
        if len(mesh.colors) > 0:
            mesh.vbo_colors = GL.glGenBuffers(1)
            GL.glBindBuffer(GL.GL_ARRAY_BUFFER, mesh.vbo_colors)
            GL.glBufferData(GL.GL_ARRAY_BUFFER, mesh.colors.nbytes,
                           mesh.colors, GL.GL_STATIC_DRAW)
            GL.glVertexAttribPointer(3, 4, GL.GL_FLOAT, GL.GL_FALSE, 0, None)
            GL.glEnableVertexAttribArray(3)
        
        # Indices
        if len(mesh.indices) > 0:
            mesh.ebo = GL.glGenBuffers(1)
            GL.glBindBuffer(GL.GL_ELEMENT_ARRAY_BUFFER, mesh.ebo)
            GL.glBufferData(GL.GL_ELEMENT_ARRAY_BUFFER, mesh.indices.nbytes,
                           mesh.indices, GL.GL_STATIC_DRAW)
        
        GL.glBindVertexArray(0)
    
    def resizeGL(self, width: int, height: int):
        """Handle resize"""
        if PYOPENGL_AVAILABLE:
            GL.glViewport(0, 0, width, height)
            self._setup_render_targets()
    
    def paintGL(self):
        """Render the scene"""
        if not PYOPENGL_AVAILABLE:
            return
        
        # Calculate delta time
        current_time = time.time()
        self.delta_time = current_time - self.last_time
        self.last_time = current_time
        
        # Update FPS
        self.frame_count += 1
        if self.frame_count % 60 == 0:
            self.fps = 60.0 / max(0.001, self.delta_time * 60)
        
        # Update scene
        self.scene.update(self.delta_time)
        
        # Clear
        bg = self.scene.background_color
        GL.glClearColor(bg[0], bg[1], bg[2], 1.0)
        GL.glClear(GL.GL_COLOR_BUFFER_BIT | GL.GL_DEPTH_BUFFER_BIT)
        
        # Get matrices
        aspect = self.width() / max(1, self.height())
        view = self.scene.camera.get_view_matrix()
        projection = self.scene.camera.get_projection_matrix(aspect)
        
        # Render objects
        for obj in self.scene.objects:
            if obj.visible:
                self._render_object(obj, view, projection)
        
        self.sceneUpdated.emit()
    
    def _render_object(self, obj: Object3D, view: QMatrix4x4, projection: QMatrix4x4):
        """Render a single object"""
        if not obj.mesh or not PYOPENGL_AVAILABLE:
            return
        
        # Upload mesh if needed
        self._upload_mesh(obj.mesh)
        
        # Select shader based on render mode
        if self.render_mode == RenderMode.HOLOGRAPHIC:
            shader = self.shaders.get('holographic')
        else:
            shader = self.shaders.get('pbr')
        
        if not shader:
            return
        
        GL.glUseProgram(shader)
        
        # Set matrices
        model = obj.get_world_matrix()
        
        model_loc = GL.glGetUniformLocation(shader, "model")
        view_loc = GL.glGetUniformLocation(shader, "view")
        proj_loc = GL.glGetUniformLocation(shader, "projection")
        
        GL.glUniformMatrix4fv(model_loc, 1, GL.GL_FALSE, self._matrix_to_array(model))
        GL.glUniformMatrix4fv(view_loc, 1, GL.GL_FALSE, self._matrix_to_array(view))
        GL.glUniformMatrix4fv(proj_loc, 1, GL.GL_FALSE, self._matrix_to_array(projection))
        
        # Set material properties
        mat = obj.material
        
        albedo_loc = GL.glGetUniformLocation(shader, "albedo")
        if albedo_loc >= 0:
            GL.glUniform3f(albedo_loc, *mat.albedo)
        
        metallic_loc = GL.glGetUniformLocation(shader, "metallic")
        if metallic_loc >= 0:
            GL.glUniform1f(metallic_loc, mat.metallic)
        
        roughness_loc = GL.glGetUniformLocation(shader, "roughness")
        if roughness_loc >= 0:
            GL.glUniform1f(roughness_loc, mat.roughness)
        
        emission_loc = GL.glGetUniformLocation(shader, "emission")
        if emission_loc >= 0:
            GL.glUniform3f(emission_loc, *mat.emission)
        
        emission_strength_loc = GL.glGetUniformLocation(shader, "emissionStrength")
        if emission_strength_loc >= 0:
            GL.glUniform1f(emission_strength_loc, mat.emission_strength)
        
        opacity_loc = GL.glGetUniformLocation(shader, "opacity")
        if opacity_loc >= 0:
            GL.glUniform1f(opacity_loc, mat.opacity)
        
        # Set camera position
        view_pos_loc = GL.glGetUniformLocation(shader, "viewPos")
        if view_pos_loc >= 0:
            GL.glUniform3f(view_pos_loc, *self.scene.camera.position)
        
        # Set ambient
        ambient_loc = GL.glGetUniformLocation(shader, "ambientColor")
        if ambient_loc >= 0:
            GL.glUniform3f(ambient_loc, *self.scene.ambient_color)
        
        # Set lights
        num_lights_loc = GL.glGetUniformLocation(shader, "numLights")
        if num_lights_loc >= 0:
            GL.glUniform1i(num_lights_loc, len(self.scene.lights))
        
        for i, light in enumerate(self.scene.lights[:8]):
            pos_loc = GL.glGetUniformLocation(shader, f"lightPositions[{i}]")
            color_loc = GL.glGetUniformLocation(shader, f"lightColors[{i}]")
            intensity_loc = GL.glGetUniformLocation(shader, f"lightIntensities[{i}]")
            
            if pos_loc >= 0:
                GL.glUniform3f(pos_loc, *light.position)
            if color_loc >= 0:
                GL.glUniform3f(color_loc, *light.color)
            if intensity_loc >= 0:
                GL.glUniform1f(intensity_loc, light.intensity)
        
        # Set time for holographic shader
        time_loc = GL.glGetUniformLocation(shader, "time")
        if time_loc >= 0:
            GL.glUniform1f(time_loc, time.time() % 1000)
        
        holo_color_loc = GL.glGetUniformLocation(shader, "holoColor")
        if holo_color_loc >= 0:
            GL.glUniform3f(holo_color_loc, *mat.emission if mat.emission_strength > 0 else mat.albedo)
        
        # Set render mode
        if self.render_mode == RenderMode.WIREFRAME or mat.wireframe:
            GL.glPolygonMode(GL.GL_FRONT_AND_BACK, GL.GL_LINE)
        elif self.render_mode == RenderMode.POINTS:
            GL.glPolygonMode(GL.GL_FRONT_AND_BACK, GL.GL_POINT)
            GL.glPointSize(5.0)
        else:
            GL.glPolygonMode(GL.GL_FRONT_AND_BACK, GL.GL_FILL)
        
        # Double-sided
        if mat.double_sided:
            GL.glDisable(GL.GL_CULL_FACE)
        else:
            GL.glEnable(GL.GL_CULL_FACE)
        
        # Transparency
        if mat.opacity < 1.0:
            GL.glEnable(GL.GL_BLEND)
            GL.glDepthMask(GL.GL_FALSE)
        
        # Draw
        GL.glBindVertexArray(obj.mesh.vao)
        
        if len(obj.mesh.indices) > 0:
            GL.glDrawElements(GL.GL_TRIANGLES, len(obj.mesh.indices),
                             GL.GL_UNSIGNED_INT, None)
        else:
            GL.glDrawArrays(GL.GL_TRIANGLES, 0, len(obj.mesh.vertices) // 3)
        
        GL.glBindVertexArray(0)
        
        # Restore state
        if mat.opacity < 1.0:
            GL.glDepthMask(GL.GL_TRUE)
        
        GL.glPolygonMode(GL.GL_FRONT_AND_BACK, GL.GL_FILL)
        
        # Render children
        for child in obj.children:
            if child.visible:
                self._render_object(child, view, projection)
    
    def _matrix_to_array(self, matrix: QMatrix4x4) -> np.ndarray:
        """Convert QMatrix4x4 to numpy array"""
        data = []
        for row in range(4):
            for col in range(4):
                data.append(matrix.data()[row * 4 + col])
        return np.array(data, dtype=np.float32)
    
    def mousePressEvent(self, event):
        """Handle mouse press"""
        self.mouse_pressed = True
        self.mouse_button = event.button()
        self.last_mouse_pos = event.pos()
    
    def mouseReleaseEvent(self, event):
        """Handle mouse release"""
        self.mouse_pressed = False
        self.mouse_button = Qt.MouseButton.NoButton
    
    def mouseMoveEvent(self, event):
        """Handle mouse move"""
        if not self.mouse_pressed:
            return
        
        dx = event.pos().x() - self.last_mouse_pos.x()
        dy = event.pos().y() - self.last_mouse_pos.y()
        
        if self.mouse_button == Qt.MouseButton.LeftButton:
            # Orbit
            self.scene.camera.orbit(dx, dy)
        elif self.mouse_button == Qt.MouseButton.MiddleButton:
            # Pan
            self.scene.camera.pan(dx, dy)
        elif self.mouse_button == Qt.MouseButton.RightButton:
            # Zoom
            self.scene.camera.zoom(dy)
        
        self.last_mouse_pos = event.pos()
        self.update()
    
    def wheelEvent(self, event):
        """Handle mouse wheel"""
        delta = event.angleDelta().y() / 120.0
        self.scene.camera.zoom(delta)
        self.update()
    
    def keyPressEvent(self, event):
        """Handle key press"""
        key = event.key()
        
        if key == Qt.Key.Key_1:
            self.render_mode = RenderMode.SOLID
        elif key == Qt.Key.Key_2:
            self.render_mode = RenderMode.WIREFRAME
        elif key == Qt.Key.Key_3:
            self.render_mode = RenderMode.POINTS
        elif key == Qt.Key.Key_4:
            self.render_mode = RenderMode.HOLOGRAPHIC
        elif key == Qt.Key.Key_R:
            # Reset camera
            self.scene.camera = Camera3D()
        elif key == Qt.Key.Key_G:
            # Toggle grid
            grid = self.scene.find_object("grid")
            if grid:
                grid.visible = not grid.visible
        
        self.update()
    
    def add_grid(self, size: float = 20.0, divisions: int = 20):
        """Add a grid to the scene"""
        grid_mesh = Mesh3D.create_grid(size, divisions)
        grid_obj = Object3D(
            name="grid",
            mesh=grid_mesh,
            material=Material3D(
                albedo=(0.3, 0.3, 0.3),
                opacity=0.5,
                wireframe=True
            )
        )
        self.scene.add_object(grid_obj)
    
    def add_default_lights(self):
        """Add default lighting"""
        # Key light
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(10, 15, 10),
            color=(1.0, 0.95, 0.9),
            intensity=100.0
        ))
        
        # Fill light
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(-10, 10, 5),
            color=(0.3, 0.4, 0.5),
            intensity=50.0
        ))
        
        # Back light
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(0, 5, -15),
            color=(0.2, 0.3, 0.4),
            intensity=30.0
        ))
    
    def get_fps(self) -> float:
        """Get current FPS"""
        return self.fps
    
    def set_background_color(self, color: Tuple[float, float, float]):
        """Set background color"""
        self.scene.background_color = color
    
    def set_render_mode(self, mode: RenderMode):
        """Set render mode"""
        self.render_mode = mode
        self.update()
    
    def take_screenshot(self, path: str):
        """Save screenshot"""
        image = self.grabFramebuffer()
        image.save(path)
