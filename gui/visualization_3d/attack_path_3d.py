"""
3D Attack Path Visualization

Visualizes attack chains and exploit paths in 3D:
- Step-by-step attack visualization
- Technique nodes with MITRE ATT&CK mapping
- Animated attack flow
- Impact visualization
- Timeline view
"""

import math
import time
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor

from .engine_3d import (
    Visualization3DEngine, Scene3D, Object3D, Mesh3D, Material3D,
    Light3D, Camera3D, LightType
)


class AttackPhase(Enum):
    """MITRE ATT&CK kill chain phases"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class StepStatus(Enum):
    """Attack step status"""
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class AttackStep:
    """Single step in an attack chain"""
    id: str
    name: str
    description: str = ""
    phase: AttackPhase = AttackPhase.INITIAL_ACCESS
    technique_id: str = ""  # MITRE ATT&CK ID
    technique_name: str = ""
    
    target: str = ""
    prerequisites: List[str] = field(default_factory=list)
    
    status: StepStatus = StepStatus.PENDING
    success_probability: float = 0.8
    impact_score: float = 5.0
    
    # Timing
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration: float = 0.0
    
    # 3D
    position: Tuple[float, float, float] = (0, 0, 0)
    object_3d: Optional[Object3D] = None
    
    # Data
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChain:
    """Complete attack chain"""
    id: str
    name: str
    description: str = ""
    steps: List[AttackStep] = field(default_factory=list)
    
    # Metadata
    attacker: str = ""
    target: str = ""
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    overall_success: float = 0.0
    total_impact: float = 0.0


class AttackPath3D(Visualization3DEngine):
    """3D Attack Path Visualization"""
    
    stepClicked = pyqtSignal(object)
    stepHovered = pyqtSignal(object)
    chainCompleted = pyqtSignal(object)
    
    # Phase colors
    PHASE_COLORS = {
        AttackPhase.RECONNAISSANCE: (0.3, 0.5, 0.8),
        AttackPhase.RESOURCE_DEVELOPMENT: (0.4, 0.5, 0.7),
        AttackPhase.INITIAL_ACCESS: (0.8, 0.4, 0.2),
        AttackPhase.EXECUTION: (0.9, 0.3, 0.3),
        AttackPhase.PERSISTENCE: (0.7, 0.3, 0.5),
        AttackPhase.PRIVILEGE_ESCALATION: (0.9, 0.2, 0.4),
        AttackPhase.DEFENSE_EVASION: (0.5, 0.5, 0.5),
        AttackPhase.CREDENTIAL_ACCESS: (0.8, 0.6, 0.2),
        AttackPhase.DISCOVERY: (0.3, 0.7, 0.5),
        AttackPhase.LATERAL_MOVEMENT: (0.4, 0.6, 0.8),
        AttackPhase.COLLECTION: (0.6, 0.4, 0.7),
        AttackPhase.COMMAND_AND_CONTROL: (0.2, 0.2, 0.2),
        AttackPhase.EXFILTRATION: (0.7, 0.2, 0.2),
        AttackPhase.IMPACT: (1.0, 0.0, 0.0),
    }
    
    STATUS_COLORS = {
        StepStatus.PENDING: (0.3, 0.3, 0.3),
        StepStatus.ACTIVE: (1.0, 0.8, 0.0),
        StepStatus.COMPLETED: (0.2, 0.8, 0.2),
        StepStatus.FAILED: (0.8, 0.2, 0.2),
        StepStatus.BLOCKED: (0.5, 0.5, 0.5),
    }
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.chains: Dict[str, AttackChain] = {}
        self.active_chain: Optional[AttackChain] = None
        
        # Animation
        self.animation_speed = 1.0
        self.is_playing = False
        self.current_step_index = 0
        
        # Particles for effects
        self.particles: List[Dict] = []
        
        # Setup
        self._setup_scene()
    
    def _setup_scene(self):
        """Setup the 3D scene"""
        self.scene.background_color = (0.02, 0.02, 0.05)
        self.scene.ambient_color = (0.1, 0.1, 0.15)
        
        # Add grid
        self.add_grid(size=100.0, divisions=50)
        
        # Add lights
        self.add_default_lights()
        
        # Red accent light for danger
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(0, 15, 0),
            color=(1.0, 0.2, 0.1),
            intensity=20.0
        ))
        
        # Set camera for timeline view
        self.scene.camera.position = (0, 30, 40)
        self.scene.camera.target = (0, 0, 0)
    
    def add_chain(self, chain: AttackChain):
        """Add an attack chain"""
        self.chains[chain.id] = chain
        self._layout_chain(chain)
    
    def _layout_chain(self, chain: AttackChain):
        """Layout attack chain in 3D space"""
        if not chain.steps:
            return
        
        # Group by phase
        phases = {}
        for step in chain.steps:
            if step.phase not in phases:
                phases[step.phase] = []
            phases[step.phase].append(step)
        
        # Layout phases along X axis, steps within phase along Z
        phase_list = list(AttackPhase)
        phase_x_positions = {phase: i * 8 - len(phase_list) * 4 for i, phase in enumerate(phase_list)}
        
        for phase, steps in phases.items():
            x = phase_x_positions.get(phase, 0)
            
            for i, step in enumerate(steps):
                z = (i - (len(steps) - 1) / 2) * 4
                y = 0
                
                step.position = (x, y, z)
                self._create_step_object(step)
        
        # Create connections between steps
        self._create_connections(chain)
    
    def _create_step_object(self, step: AttackStep) -> Object3D:
        """Create 3D object for attack step"""
        # Create mesh based on phase importance
        if step.phase in [AttackPhase.INITIAL_ACCESS, AttackPhase.IMPACT]:
            mesh = Mesh3D.create_cube(1.5)
        elif step.phase in [AttackPhase.PRIVILEGE_ESCALATION, AttackPhase.LATERAL_MOVEMENT]:
            mesh = Mesh3D.create_sphere(0.8, 16, 8)
        else:
            mesh = Mesh3D.create_cube(1.0)
        
        # Get colors
        phase_color = self.PHASE_COLORS.get(step.phase, (0.5, 0.5, 0.5))
        status_color = self.STATUS_COLORS.get(step.status, (0.5, 0.5, 0.5))
        
        # Material with emission for active/completed
        is_active = step.status in [StepStatus.ACTIVE, StepStatus.COMPLETED]
        
        material = Material3D(
            name=f"step_{step.id}",
            albedo=phase_color,
            metallic=0.4,
            roughness=0.3,
            emission=phase_color if is_active else (0, 0, 0),
            emission_strength=0.8 if is_active else 0.0
        )
        
        obj = Object3D(
            name=f"step_{step.id}",
            mesh=mesh,
            material=material,
            position=step.position,
            data={"step_id": step.id, "type": "attack_step"}
        )
        
        # Add status ring
        ring = self._create_status_ring(step)
        if ring:
            obj.add_child(ring)
        
        # Animation based on status
        def animate_step(obj: Object3D, dt: float):
            if step.status == StepStatus.ACTIVE:
                # Pulsing
                pulse = math.sin(time.time() * 5) * 0.1 + 1.0
                obj.scale = (pulse, pulse, pulse)
                
                # Rotation
                obj.rotation = (
                    obj.rotation[0],
                    obj.rotation[1] + 45 * dt,
                    obj.rotation[2]
                )
            elif step.status == StepStatus.COMPLETED:
                # Glow pulse
                glow = math.sin(time.time() * 2) * 0.3 + 0.7
                obj.material.emission_strength = glow
        
        obj.animation_callback = animate_step
        
        step.object_3d = obj
        self.scene.add_object(obj)
        
        return obj
    
    def _create_status_ring(self, step: AttackStep) -> Object3D:
        """Create status indicator ring around step"""
        color = self.STATUS_COLORS.get(step.status, (0.5, 0.5, 0.5))
        
        # Create ring mesh (torus would be better, using cylinder as approximation)
        vertices = []
        indices = []
        
        segments = 32
        inner_radius = 1.2
        outer_radius = 1.4
        height = 0.1
        
        for i in range(segments + 1):
            angle = 2 * math.pi * i / segments
            cos_a = math.cos(angle)
            sin_a = math.sin(angle)
            
            # Inner ring
            vertices.extend([inner_radius * cos_a, -height/2, inner_radius * sin_a])
            vertices.extend([inner_radius * cos_a, height/2, inner_radius * sin_a])
            
            # Outer ring
            vertices.extend([outer_radius * cos_a, -height/2, outer_radius * sin_a])
            vertices.extend([outer_radius * cos_a, height/2, outer_radius * sin_a])
        
        for i in range(segments):
            base = i * 4
            next_base = (i + 1) * 4
            
            # Top face
            indices.extend([base + 1, next_base + 1, base + 3])
            indices.extend([base + 3, next_base + 1, next_base + 3])
            
            # Bottom face
            indices.extend([base, base + 2, next_base])
            indices.extend([next_base, base + 2, next_base + 2])
            
            # Outer side
            indices.extend([base + 2, base + 3, next_base + 2])
            indices.extend([next_base + 2, base + 3, next_base + 3])
            
            # Inner side
            indices.extend([base, next_base, base + 1])
            indices.extend([base + 1, next_base, next_base + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            albedo=color,
            emission=color,
            emission_strength=1.0,
            metallic=0.0,
            roughness=1.0
        )
        
        ring = Object3D(
            name=f"ring_{step.id}",
            mesh=mesh,
            material=material
        )
        
        # Rotation animation
        def animate_ring(obj: Object3D, dt: float):
            obj.rotation = (0, obj.rotation[1] + 30 * dt, 0)
        
        ring.animation_callback = animate_ring
        
        return ring
    
    def _create_connections(self, chain: AttackChain):
        """Create connections between steps"""
        step_map = {s.id: s for s in chain.steps}
        
        for step in chain.steps:
            for prereq_id in step.prerequisites:
                prereq = step_map.get(prereq_id)
                if prereq:
                    self._create_arrow(prereq, step)
    
    def _create_arrow(self, from_step: AttackStep, to_step: AttackStep):
        """Create arrow between two steps"""
        start = from_step.position
        end = to_step.position
        
        # Create line/tube mesh
        dx = end[0] - start[0]
        dy = end[1] - start[1]
        dz = end[2] - start[2]
        length = math.sqrt(dx*dx + dy*dy + dz*dz)
        
        if length < 0.1:
            return
        
        # Shorten to not overlap with step objects
        margin = 1.5
        if length > margin * 2:
            t_start = margin / length
            t_end = 1 - margin / length
            
            start = (
                start[0] + dx * t_start,
                start[1] + dy * t_start,
                start[2] + dz * t_start
            )
            end = (
                start[0] + dx * (t_end - t_start) * length / (length - 2 * margin),
                start[1] + dy * (t_end - t_start) * length / (length - 2 * margin),
                start[2] + dz * (t_end - t_start) * length / (length - 2 * margin)
            )
        
        # Create vertices for a simple line
        vertices = np.array([*start, *end], dtype=np.float32)
        indices = np.array([0, 1], dtype=np.uint32)
        
        mesh = Mesh3D(vertices=vertices, indices=indices)
        
        # Determine color based on status
        if from_step.status == StepStatus.COMPLETED and to_step.status == StepStatus.COMPLETED:
            color = (0.2, 0.8, 0.2)
        elif to_step.status == StepStatus.ACTIVE:
            color = (1.0, 0.8, 0.0)
        else:
            color = (0.4, 0.4, 0.4)
        
        material = Material3D(
            albedo=color,
            emission=color,
            emission_strength=0.5,
            wireframe=True
        )
        
        arrow = Object3D(
            name=f"arrow_{from_step.id}_{to_step.id}",
            mesh=mesh,
            material=material,
            data={"type": "arrow", "from": from_step.id, "to": to_step.id}
        )
        
        self.scene.add_object(arrow)
    
    def set_active_chain(self, chain_id: str):
        """Set the active attack chain"""
        chain = self.chains.get(chain_id)
        if chain:
            self.active_chain = chain
            self.current_step_index = 0
    
    def play_animation(self, speed: float = 1.0):
        """Start playing attack animation"""
        if not self.active_chain:
            return
        
        self.animation_speed = speed
        self.is_playing = True
        self.current_step_index = 0
        
        # Reset all steps
        for step in self.active_chain.steps:
            self.update_step_status(step.id, StepStatus.PENDING)
        
        self._animate_next_step()
    
    def _animate_next_step(self):
        """Animate the next step"""
        if not self.is_playing or not self.active_chain:
            return
        
        if self.current_step_index >= len(self.active_chain.steps):
            self.is_playing = False
            self.chainCompleted.emit(self.active_chain)
            return
        
        step = self.active_chain.steps[self.current_step_index]
        
        # Check prerequisites
        all_prereqs_complete = all(
            self._get_step(pid).status == StepStatus.COMPLETED
            for pid in step.prerequisites
            if self._get_step(pid)
        )
        
        if not all_prereqs_complete and step.prerequisites:
            # Wait for prerequisites
            QTimer.singleShot(100, self._animate_next_step)
            return
        
        # Activate step
        self.update_step_status(step.id, StepStatus.ACTIVE)
        step.start_time = time.time()
        
        # Focus camera on step
        self._focus_camera_on(step.position)
        
        # Simulate step execution
        duration = int((step.duration or 2.0) * 1000 / self.animation_speed)
        
        def complete_step():
            # Determine success/failure based on probability
            import random
            if random.random() < step.success_probability:
                self.update_step_status(step.id, StepStatus.COMPLETED)
            else:
                self.update_step_status(step.id, StepStatus.FAILED)
            
            step.end_time = time.time()
            self.current_step_index += 1
            self._animate_next_step()
        
        QTimer.singleShot(duration, complete_step)
    
    def _get_step(self, step_id: str) -> Optional[AttackStep]:
        """Get step by ID from active chain"""
        if not self.active_chain:
            return None
        
        for step in self.active_chain.steps:
            if step.id == step_id:
                return step
        return None
    
    def pause_animation(self):
        """Pause animation"""
        self.is_playing = False
    
    def resume_animation(self):
        """Resume animation"""
        self.is_playing = True
        self._animate_next_step()
    
    def update_step_status(self, step_id: str, status: StepStatus):
        """Update step status"""
        for chain in self.chains.values():
            for step in chain.steps:
                if step.id == step_id:
                    step.status = status
                    
                    if step.object_3d:
                        # Update material
                        phase_color = self.PHASE_COLORS.get(step.phase, (0.5, 0.5, 0.5))
                        is_active = status in [StepStatus.ACTIVE, StepStatus.COMPLETED]
                        
                        step.object_3d.material.emission = phase_color if is_active else (0, 0, 0)
                        step.object_3d.material.emission_strength = 0.8 if is_active else 0.0
                        
                        # Update ring
                        if step.object_3d.children:
                            ring = step.object_3d.children[0]
                            status_color = self.STATUS_COLORS.get(status, (0.5, 0.5, 0.5))
                            ring.material.albedo = status_color
                            ring.material.emission = status_color
                    
                    return
    
    def _focus_camera_on(self, position: Tuple[float, float, float], 
                        distance: float = 15.0):
        """Focus camera on a position"""
        self.scene.camera.target = position
        
        # Calculate new camera position
        direction = np.array(self.scene.camera.position) - np.array(self.scene.camera.target)
        direction = direction / np.linalg.norm(direction) if np.linalg.norm(direction) > 0 else np.array([0, 1, 1])
        
        new_pos = np.array(position) + direction * distance
        self.scene.camera.position = tuple(new_pos)
    
    def highlight_step(self, step_id: str):
        """Highlight a specific step"""
        for chain in self.chains.values():
            for step in chain.steps:
                if step.id == step_id:
                    if step.object_3d:
                        step.object_3d.material.emission = (1.0, 1.0, 1.0)
                        step.object_3d.material.emission_strength = 1.5
                        
                        self._focus_camera_on(step.position)
                else:
                    if step.object_3d:
                        phase_color = self.PHASE_COLORS.get(step.phase, (0.5, 0.5, 0.5))
                        is_active = step.status in [StepStatus.ACTIVE, StepStatus.COMPLETED]
                        step.object_3d.material.emission = phase_color if is_active else (0, 0, 0)
                        step.object_3d.material.emission_strength = 0.8 if is_active else 0.0
    
    def create_sample_chain(self) -> AttackChain:
        """Create a sample attack chain for demonstration"""
        chain = AttackChain(
            id="sample_chain",
            name="Sample APT Attack",
            description="Demonstration of a multi-stage attack"
        )
        
        # Reconnaissance
        chain.steps.append(AttackStep(
            id="recon_1",
            name="Port Scan",
            phase=AttackPhase.RECONNAISSANCE,
            technique_id="T1046",
            technique_name="Network Service Discovery",
            duration=2.0
        ))
        
        # Initial Access
        chain.steps.append(AttackStep(
            id="initial_1",
            name="Phishing Email",
            phase=AttackPhase.INITIAL_ACCESS,
            technique_id="T1566",
            technique_name="Phishing",
            prerequisites=["recon_1"],
            duration=3.0
        ))
        
        # Execution
        chain.steps.append(AttackStep(
            id="exec_1",
            name="Malicious Macro",
            phase=AttackPhase.EXECUTION,
            technique_id="T1059.005",
            technique_name="Visual Basic",
            prerequisites=["initial_1"],
            duration=2.0
        ))
        
        # Persistence
        chain.steps.append(AttackStep(
            id="persist_1",
            name="Registry Run Key",
            phase=AttackPhase.PERSISTENCE,
            technique_id="T1547.001",
            technique_name="Registry Run Keys",
            prerequisites=["exec_1"],
            duration=1.5
        ))
        
        # Privilege Escalation
        chain.steps.append(AttackStep(
            id="privesc_1",
            name="Token Impersonation",
            phase=AttackPhase.PRIVILEGE_ESCALATION,
            technique_id="T1134",
            technique_name="Access Token Manipulation",
            prerequisites=["persist_1"],
            duration=2.5
        ))
        
        # Credential Access
        chain.steps.append(AttackStep(
            id="cred_1",
            name="LSASS Dump",
            phase=AttackPhase.CREDENTIAL_ACCESS,
            technique_id="T1003.001",
            technique_name="LSASS Memory",
            prerequisites=["privesc_1"],
            duration=2.0
        ))
        
        # Lateral Movement
        chain.steps.append(AttackStep(
            id="lateral_1",
            name="Pass the Hash",
            phase=AttackPhase.LATERAL_MOVEMENT,
            technique_id="T1550.002",
            technique_name="Pass the Hash",
            prerequisites=["cred_1"],
            duration=3.0
        ))
        
        # Collection
        chain.steps.append(AttackStep(
            id="collect_1",
            name="Data Staging",
            phase=AttackPhase.COLLECTION,
            technique_id="T1074",
            technique_name="Data Staged",
            prerequisites=["lateral_1"],
            duration=4.0
        ))
        
        # Exfiltration
        chain.steps.append(AttackStep(
            id="exfil_1",
            name="C2 Exfiltration",
            phase=AttackPhase.EXFILTRATION,
            technique_id="T1041",
            technique_name="Exfiltration Over C2",
            prerequisites=["collect_1"],
            duration=5.0
        ))
        
        # Impact
        chain.steps.append(AttackStep(
            id="impact_1",
            name="Data Encrypted",
            phase=AttackPhase.IMPACT,
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            prerequisites=["exfil_1"],
            duration=6.0,
            impact_score=10.0
        ))
        
        return chain
