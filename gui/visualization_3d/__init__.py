"""
3D Visualization Engine for HydraRecon

Advanced 3D visualization components using OpenGL and PyQt6.
Provides immersive visualizations for:
- Network topology
- Attack paths and exploit chains  
- Threat landscape globe
- WiFi sensing / indoor mapping
- Real-time data streams
- Particle effects
- Data flow visualization
- Exploit chain builder
"""

# Core 3D engine components
from .engine_3d import (
    Visualization3DEngine,
    Scene3D,
    Camera3D,
    Light3D,
    LightType,
    Object3D,
    Mesh3D,
    Material3D,
    Shader3D,
    RenderTarget3D
)

# Network visualization
from .network_topology_3d import (
    NetworkTopology3D,
    NetworkNode,
    NetworkConnection
)

# Attack visualization
from .attack_path_3d import (
    AttackPath3D,
    AttackStep,
    AttackPhase
)

# Threat globe
from .threat_globe_3d import (
    ThreatGlobe3D,
    ThreatEvent,
    ThreatCluster,
    ThreatSeverity,
    ThreatType,
    GeoLocation
)

# WiFi sensing
from .wifi_sensing_3d import (
    WifiSensing3D,
    WifiSensor,
    DetectedEntity,
    Room,
    SensorType,
    DetectionType
)

# Particle system
from .particle_system import (
    ParticleSystem,
    ParticleEmitter,
    Particle,
    ParticleGradient,
    SizeOverLife,
    ParticleBlendMode,
    EmitterShape,
    EffectPresets
)

# Data flow visualization
from .data_flow_3d import (
    DataFlow3D,
    NetworkNode,
    DataPacket,
    DataFlow,
    ProtocolType,
    FlowStatus
)

# Exploit chain visualization
from .exploit_chain_3d import (
    ExploitChain3D,
    ExploitNode,
    ExploitLink,
    ExploitChain,
    Vulnerability,
    AttackPhase,
    ExploitSeverity,
    NodeStatus
)

__all__ = [
    # Core engine
    'Visualization3DEngine',
    'Scene3D',
    'Camera3D',
    'Light3D',
    'LightType',
    'Object3D',
    'Mesh3D',
    'Material3D',
    'Shader3D',
    'RenderTarget3D',
    
    # Network topology
    'NetworkTopology3D',
    'NetworkNode',
    'NetworkConnection',
    
    # Attack paths
    'AttackPath3D',
    'AttackStep',
    'AttackPhase',
    
    # Threat globe
    'ThreatGlobe3D',
    'ThreatEvent',
    'ThreatCluster',
    'ThreatSeverity',
    'ThreatType',
    'GeoLocation',
    
    # WiFi sensing
    'WifiSensing3D',
    'WifiSensor',
    'DetectedEntity',
    'Room',
    'SensorType',
    'DetectionType',
    
    # Particles
    'ParticleSystem',
    'ParticleEmitter',
    'Particle',
    'ParticleGradient',
    'SizeOverLife',
    'ParticleBlendMode',
    'EmitterShape',
    'EffectPresets',
    
    # Data flow
    'DataFlow3D',
    'NetworkNode',
    'DataPacket',
    'DataFlow',
    'ProtocolType',
    'FlowStatus',
    
    # Exploit chain
    'ExploitChain3D',
    'ExploitNode',
    'ExploitLink',
    'ExploitChain',
    'Vulnerability',
    'AttackPhase',
    'ExploitSeverity',
    'NodeStatus',
]
