"""
3D Network Topology Visualization

Visualizes network infrastructure in 3D space:
- Nodes as 3D objects (servers, routers, endpoints)
- Connections as animated lines/tubes
- Traffic flow visualization
- Attack path highlighting
- Real-time status updates
"""

import math
import time
import random
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor

from .engine_3d import (
    Visualization3DEngine, Scene3D, Object3D, Mesh3D, Material3D,
    Light3D, Camera3D, LightType, RenderMode
)


class NodeType(Enum):
    """Network node types"""
    SERVER = "server"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    ENDPOINT = "endpoint"
    DATABASE = "database"
    CLOUD = "cloud"
    IOT = "iot"
    ATTACKER = "attacker"
    VICTIM = "victim"


class ConnectionType(Enum):
    """Connection types"""
    NORMAL = "normal"
    ENCRYPTED = "encrypted"
    SUSPICIOUS = "suspicious"
    ATTACK = "attack"
    BLOCKED = "blocked"


class NodeStatus(Enum):
    """Node status"""
    ONLINE = "online"
    OFFLINE = "offline"
    COMPROMISED = "compromised"
    SCANNING = "scanning"
    UNDER_ATTACK = "under_attack"


@dataclass
class NetworkNode:
    """Network node data"""
    id: str
    name: str
    node_type: NodeType
    ip_address: str = ""
    mac_address: str = ""
    hostname: str = ""
    os: str = ""
    services: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    status: NodeStatus = NodeStatus.ONLINE
    
    # Position in 3D space
    position: Tuple[float, float, float] = (0, 0, 0)
    
    # Visualization
    object_3d: Optional[Object3D] = None
    color: Tuple[float, float, float] = (0.5, 0.5, 0.5)
    size: float = 1.0
    glow: bool = False
    
    # Metadata
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkConnection:
    """Network connection data"""
    id: str
    source_id: str
    target_id: str
    connection_type: ConnectionType = ConnectionType.NORMAL
    protocol: str = "TCP"
    port: int = 0
    bandwidth: float = 0.0
    latency: float = 0.0
    packets_sent: int = 0
    packets_received: int = 0
    
    # Visualization
    object_3d: Optional[Object3D] = None
    color: Tuple[float, float, float] = (0.3, 0.3, 0.3)
    width: float = 0.05
    animated: bool = True
    particle_flow: bool = False


class NetworkTopology3D(Visualization3DEngine):
    """3D Network Topology Visualization"""
    
    nodeClicked = pyqtSignal(object)
    nodeHovered = pyqtSignal(object)
    connectionClicked = pyqtSignal(object)
    
    # Node type colors
    NODE_COLORS = {
        NodeType.SERVER: (0.2, 0.6, 1.0),
        NodeType.ROUTER: (0.3, 0.8, 0.3),
        NodeType.SWITCH: (0.4, 0.7, 0.9),
        NodeType.FIREWALL: (1.0, 0.5, 0.2),
        NodeType.ENDPOINT: (0.6, 0.6, 0.6),
        NodeType.DATABASE: (0.8, 0.4, 0.8),
        NodeType.CLOUD: (0.5, 0.8, 1.0),
        NodeType.IOT: (0.3, 0.9, 0.7),
        NodeType.ATTACKER: (1.0, 0.1, 0.1),
        NodeType.VICTIM: (1.0, 0.8, 0.2),
    }
    
    # Status colors
    STATUS_COLORS = {
        NodeStatus.ONLINE: (0.2, 0.8, 0.2),
        NodeStatus.OFFLINE: (0.3, 0.3, 0.3),
        NodeStatus.COMPROMISED: (1.0, 0.0, 0.0),
        NodeStatus.SCANNING: (1.0, 1.0, 0.0),
        NodeStatus.UNDER_ATTACK: (1.0, 0.3, 0.0),
    }
    
    # Connection colors
    CONNECTION_COLORS = {
        ConnectionType.NORMAL: (0.3, 0.5, 0.7),
        ConnectionType.ENCRYPTED: (0.2, 0.8, 0.4),
        ConnectionType.SUSPICIOUS: (1.0, 0.7, 0.0),
        ConnectionType.ATTACK: (1.0, 0.0, 0.0),
        ConnectionType.BLOCKED: (0.5, 0.5, 0.5),
    }
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.nodes: Dict[str, NetworkNode] = {}
        self.connections: Dict[str, NetworkConnection] = {}
        
        # Layout settings
        self.layout_algorithm = "force_directed"
        self.layout_iterations = 100
        self.node_repulsion = 5.0
        self.connection_attraction = 0.5
        self.damping = 0.9
        
        # Animation
        self.flow_particles: List[Dict] = []
        self.pulse_time = 0.0
        
        # Interaction
        self.selected_node: Optional[NetworkNode] = None
        self.highlighted_path: List[str] = []
        
        # Setup scene
        self._setup_scene()
    
    def _setup_scene(self):
        """Setup the 3D scene"""
        # Set cyberpunk-style background
        self.scene.background_color = (0.02, 0.02, 0.05)
        self.scene.ambient_color = (0.1, 0.1, 0.15)
        
        # Add grid
        self.add_grid(size=50.0, divisions=50)
        
        # Add lights
        self.add_default_lights()
        
        # Add additional accent lights
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(0, 20, 0),
            color=(0.0, 0.5, 1.0),
            intensity=30.0
        ))
        
        # Set camera
        self.scene.camera.position = (30, 25, 30)
        self.scene.camera.target = (0, 0, 0)
    
    def add_node(self, node: NetworkNode) -> Object3D:
        """Add a network node"""
        # Create mesh based on node type
        mesh = self._create_node_mesh(node.node_type)
        
        # Get color
        color = self.NODE_COLORS.get(node.node_type, (0.5, 0.5, 0.5))
        
        # Create material
        material = Material3D(
            name=f"node_{node.id}",
            albedo=color,
            metallic=0.3,
            roughness=0.4,
            emission=color if node.glow else (0, 0, 0),
            emission_strength=0.5 if node.glow else 0.0
        )
        
        # Create 3D object
        obj = Object3D(
            name=f"node_{node.id}",
            mesh=mesh,
            material=material,
            position=node.position,
            scale=(node.size, node.size, node.size),
            data={"node_id": node.id, "type": "node"}
        )
        
        # Add status indicator
        status_indicator = self._create_status_indicator(node)
        if status_indicator:
            obj.add_child(status_indicator)
        
        # Add label (placeholder - would need text rendering)
        
        # Store reference
        node.object_3d = obj
        node.color = color
        self.nodes[node.id] = node
        
        # Add to scene
        self.scene.add_object(obj)
        
        # Add animation
        def animate_node(obj: Object3D, dt: float):
            if node.status == NodeStatus.SCANNING:
                obj.rotation = (
                    obj.rotation[0],
                    obj.rotation[1] + 90 * dt,
                    obj.rotation[2]
                )
            elif node.status == NodeStatus.UNDER_ATTACK:
                pulse = math.sin(time.time() * 5) * 0.1 + 1.0
                obj.scale = (node.size * pulse, node.size * pulse, node.size * pulse)
        
        obj.animation_callback = animate_node
        
        return obj
    
    def _create_node_mesh(self, node_type: NodeType) -> Mesh3D:
        """Create mesh for node type"""
        if node_type == NodeType.SERVER:
            return Mesh3D.create_cube(1.0)
        elif node_type == NodeType.ROUTER:
            return Mesh3D.create_cylinder(0.5, 0.3, 6)
        elif node_type == NodeType.SWITCH:
            return Mesh3D.create_cube(0.8)
        elif node_type == NodeType.FIREWALL:
            return Mesh3D.create_cube(1.2)
        elif node_type == NodeType.DATABASE:
            return Mesh3D.create_cylinder(0.5, 0.8, 16)
        elif node_type == NodeType.CLOUD:
            return Mesh3D.create_sphere(0.6, 16, 8)
        elif node_type == NodeType.IOT:
            return Mesh3D.create_sphere(0.3, 8, 4)
        elif node_type == NodeType.ATTACKER:
            return self._create_skull_mesh()
        elif node_type == NodeType.VICTIM:
            return Mesh3D.create_sphere(0.5, 16, 8)
        else:
            return Mesh3D.create_sphere(0.5, 16, 8)
    
    def _create_skull_mesh(self) -> Mesh3D:
        """Create a simplified skull-like mesh for attacker nodes"""
        # Use a sphere as base (would be more detailed in production)
        return Mesh3D.create_sphere(0.5, 16, 8)
    
    def _create_status_indicator(self, node: NetworkNode) -> Optional[Object3D]:
        """Create status indicator above node"""
        color = self.STATUS_COLORS.get(node.status, (0.5, 0.5, 0.5))
        
        mesh = Mesh3D.create_sphere(0.15, 8, 4)
        material = Material3D(
            albedo=color,
            emission=color,
            emission_strength=1.0,
            metallic=0.0,
            roughness=1.0
        )
        
        indicator = Object3D(
            name=f"status_{node.id}",
            mesh=mesh,
            material=material,
            position=(0, node.size + 0.5, 0)
        )
        
        # Pulsing animation
        def animate_indicator(obj: Object3D, dt: float):
            pulse = math.sin(time.time() * 3) * 0.2 + 1.0
            obj.scale = (pulse, pulse, pulse)
        
        indicator.animation_callback = animate_indicator
        
        return indicator
    
    def add_connection(self, connection: NetworkConnection) -> Optional[Object3D]:
        """Add a network connection"""
        source = self.nodes.get(connection.source_id)
        target = self.nodes.get(connection.target_id)
        
        if not source or not target:
            return None
        
        # Create line mesh
        mesh = self._create_connection_mesh(source.position, target.position, connection.width)
        
        # Get color
        color = self.CONNECTION_COLORS.get(connection.connection_type, (0.3, 0.3, 0.3))
        
        # Create material
        material = Material3D(
            name=f"conn_{connection.id}",
            albedo=color,
            emission=color if connection.connection_type == ConnectionType.ATTACK else (0, 0, 0),
            emission_strength=0.5 if connection.connection_type == ConnectionType.ATTACK else 0.0,
            opacity=0.8,
            double_sided=True
        )
        
        obj = Object3D(
            name=f"conn_{connection.id}",
            mesh=mesh,
            material=material,
            data={"connection_id": connection.id, "type": "connection"}
        )
        
        connection.object_3d = obj
        connection.color = color
        self.connections[connection.id] = connection
        
        self.scene.add_object(obj)
        
        # Add flow animation
        if connection.animated:
            def animate_connection(obj: Object3D, dt: float):
                # Pulse effect for active connections
                if connection.connection_type == ConnectionType.ATTACK:
                    pulse = math.sin(time.time() * 10) * 0.3 + 0.7
                    obj.material.opacity = pulse
            
            obj.animation_callback = animate_connection
        
        return obj
    
    def _create_connection_mesh(self, start: Tuple[float, float, float],
                                end: Tuple[float, float, float],
                                width: float) -> Mesh3D:
        """Create a tube/line mesh between two points"""
        # Calculate direction
        dx = end[0] - start[0]
        dy = end[1] - start[1]
        dz = end[2] - start[2]
        length = math.sqrt(dx*dx + dy*dy + dz*dz)
        
        if length < 0.01:
            return Mesh3D()
        
        # Create cylinder
        segments = 8
        vertices = []
        normals = []
        indices = []
        
        # Create ring at each end
        for t in [0, 1]:
            pos_t = (
                start[0] + dx * t,
                start[1] + dy * t,
                start[2] + dz * t
            )
            
            # Calculate perpendicular vectors
            up = (0, 1, 0) if abs(dy / length) < 0.9 else (1, 0, 0)
            
            # Cross product to get perpendicular
            px = up[1] * dz - up[2] * dy
            py = up[2] * dx - up[0] * dz
            pz = up[0] * dy - up[1] * dx
            pl = math.sqrt(px*px + py*py + pz*pz)
            if pl > 0:
                px, py, pz = px/pl, py/pl, pz/pl
            
            # Second perpendicular
            qx = py * dz - pz * dy
            qy = pz * dx - px * dz
            qz = px * dy - py * dx
            ql = math.sqrt(qx*qx + qy*qy + qz*qz)
            if ql > 0:
                qx, qy, qz = qx/ql, qy/ql, qz/ql
            
            for i in range(segments):
                angle = 2 * math.pi * i / segments
                cos_a = math.cos(angle) * width
                sin_a = math.sin(angle) * width
                
                vx = pos_t[0] + px * cos_a + qx * sin_a
                vy = pos_t[1] + py * cos_a + qy * sin_a
                vz = pos_t[2] + pz * cos_a + qz * sin_a
                
                vertices.extend([vx, vy, vz])
                
                # Normal
                nx = px * math.cos(angle) + qx * math.sin(angle)
                ny = py * math.cos(angle) + qy * math.sin(angle)
                nz = pz * math.cos(angle) + qz * math.sin(angle)
                normals.extend([nx, ny, nz])
        
        # Create indices
        for i in range(segments):
            next_i = (i + 1) % segments
            
            # Bottom ring indices
            b0 = i
            b1 = next_i
            
            # Top ring indices
            t0 = segments + i
            t1 = segments + next_i
            
            indices.extend([b0, t0, b1, b1, t0, t1])
        
        return Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            normals=np.array(normals, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
    
    def remove_node(self, node_id: str):
        """Remove a node"""
        node = self.nodes.get(node_id)
        if node and node.object_3d:
            self.scene.remove_object(node.object_3d)
            del self.nodes[node_id]
            
            # Remove connections
            to_remove = [cid for cid, conn in self.connections.items()
                        if conn.source_id == node_id or conn.target_id == node_id]
            for cid in to_remove:
                self.remove_connection(cid)
    
    def remove_connection(self, connection_id: str):
        """Remove a connection"""
        conn = self.connections.get(connection_id)
        if conn and conn.object_3d:
            self.scene.remove_object(conn.object_3d)
            del self.connections[connection_id]
    
    def update_node_status(self, node_id: str, status: NodeStatus):
        """Update node status"""
        node = self.nodes.get(node_id)
        if node:
            node.status = status
            
            # Update status indicator color
            if node.object_3d and node.object_3d.children:
                indicator = node.object_3d.children[0]
                color = self.STATUS_COLORS.get(status, (0.5, 0.5, 0.5))
                indicator.material.albedo = color
                indicator.material.emission = color
    
    def highlight_path(self, node_ids: List[str], color: Tuple[float, float, float] = (1.0, 0.5, 0.0)):
        """Highlight a path through the network"""
        # Clear previous highlights
        self.clear_highlights()
        
        self.highlighted_path = node_ids
        
        # Highlight nodes
        for node_id in node_ids:
            node = self.nodes.get(node_id)
            if node and node.object_3d:
                node.object_3d.material.emission = color
                node.object_3d.material.emission_strength = 1.0
        
        # Highlight connections between nodes
        for i in range(len(node_ids) - 1):
            source_id = node_ids[i]
            target_id = node_ids[i + 1]
            
            for conn in self.connections.values():
                if (conn.source_id == source_id and conn.target_id == target_id) or \
                   (conn.source_id == target_id and conn.target_id == source_id):
                    if conn.object_3d:
                        conn.object_3d.material.emission = color
                        conn.object_3d.material.emission_strength = 1.0
    
    def clear_highlights(self):
        """Clear all highlights"""
        for node in self.nodes.values():
            if node.object_3d:
                node.object_3d.material.emission = (0, 0, 0)
                node.object_3d.material.emission_strength = 0.0
        
        for conn in self.connections.values():
            if conn.object_3d:
                conn.object_3d.material.emission = (0, 0, 0)
                conn.object_3d.material.emission_strength = 0.0
        
        self.highlighted_path = []
    
    def apply_force_directed_layout(self, iterations: int = None):
        """Apply force-directed layout algorithm"""
        if iterations is None:
            iterations = self.layout_iterations
        
        nodes = list(self.nodes.values())
        if len(nodes) < 2:
            return
        
        # Initialize velocities
        velocities = {n.id: np.array([0.0, 0.0, 0.0]) for n in nodes}
        
        for _ in range(iterations):
            forces = {n.id: np.array([0.0, 0.0, 0.0]) for n in nodes}
            
            # Repulsion between all nodes
            for i, n1 in enumerate(nodes):
                for j, n2 in enumerate(nodes):
                    if i >= j:
                        continue
                    
                    pos1 = np.array(n1.position)
                    pos2 = np.array(n2.position)
                    
                    diff = pos1 - pos2
                    dist = np.linalg.norm(diff)
                    
                    if dist < 0.1:
                        dist = 0.1
                        diff = np.array([random.uniform(-1, 1) for _ in range(3)])
                    
                    # Repulsion force
                    force = self.node_repulsion / (dist * dist) * (diff / dist)
                    
                    forces[n1.id] += force
                    forces[n2.id] -= force
            
            # Attraction along connections
            for conn in self.connections.values():
                source = self.nodes.get(conn.source_id)
                target = self.nodes.get(conn.target_id)
                
                if not source or not target:
                    continue
                
                pos1 = np.array(source.position)
                pos2 = np.array(target.position)
                
                diff = pos2 - pos1
                dist = np.linalg.norm(diff)
                
                if dist > 0:
                    # Attraction force
                    force = self.connection_attraction * dist * (diff / dist)
                    
                    forces[source.id] += force
                    forces[target.id] -= force
            
            # Apply forces
            for node in nodes:
                velocities[node.id] = velocities[node.id] * self.damping + forces[node.id]
                
                new_pos = np.array(node.position) + velocities[node.id] * 0.1
                node.position = tuple(new_pos)
                
                if node.object_3d:
                    node.object_3d.position = node.position
            
            # Update connection meshes
            for conn in self.connections.values():
                source = self.nodes.get(conn.source_id)
                target = self.nodes.get(conn.target_id)
                
                if source and target and conn.object_3d:
                    conn.object_3d.mesh = self._create_connection_mesh(
                        source.position, target.position, conn.width
                    )
                    conn.object_3d.mesh.vao = None  # Force re-upload
        
        self.update()
    
    def apply_hierarchical_layout(self, root_id: str = None):
        """Apply hierarchical layout"""
        nodes = list(self.nodes.values())
        if not nodes:
            return
        
        # Find root (first node if not specified)
        if root_id and root_id in self.nodes:
            root = self.nodes[root_id]
        else:
            root = nodes[0]
        
        # BFS to assign levels
        levels: Dict[str, int] = {root.id: 0}
        queue = [root.id]
        
        while queue:
            current_id = queue.pop(0)
            current_level = levels[current_id]
            
            # Find connected nodes
            for conn in self.connections.values():
                neighbor_id = None
                if conn.source_id == current_id:
                    neighbor_id = conn.target_id
                elif conn.target_id == current_id:
                    neighbor_id = conn.source_id
                
                if neighbor_id and neighbor_id not in levels:
                    levels[neighbor_id] = current_level + 1
                    queue.append(neighbor_id)
        
        # Position nodes by level
        level_counts: Dict[int, int] = {}
        level_indices: Dict[int, int] = {}
        
        for node_id, level in levels.items():
            level_counts[level] = level_counts.get(level, 0) + 1
        
        for node in nodes:
            level = levels.get(node.id, 0)
            count = level_counts.get(level, 1)
            index = level_indices.get(level, 0)
            level_indices[level] = index + 1
            
            # Position
            x = (index - (count - 1) / 2) * 5
            y = 0
            z = -level * 5
            
            node.position = (x, y, z)
            
            if node.object_3d:
                node.object_3d.position = node.position
        
        # Update connections
        self._update_all_connections()
        self.update()
    
    def apply_circular_layout(self, center: Tuple[float, float, float] = (0, 0, 0), radius: float = 10):
        """Apply circular layout"""
        nodes = list(self.nodes.values())
        if not nodes:
            return
        
        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / len(nodes)
            
            x = center[0] + radius * math.cos(angle)
            y = center[1]
            z = center[2] + radius * math.sin(angle)
            
            node.position = (x, y, z)
            
            if node.object_3d:
                node.object_3d.position = node.position
        
        self._update_all_connections()
        self.update()
    
    def apply_sphere_layout(self, center: Tuple[float, float, float] = (0, 0, 0), radius: float = 10):
        """Apply spherical layout"""
        nodes = list(self.nodes.values())
        if not nodes:
            return
        
        # Fibonacci sphere for even distribution
        phi = math.pi * (3.0 - math.sqrt(5.0))
        
        for i, node in enumerate(nodes):
            y = 1 - (i / (len(nodes) - 1)) * 2 if len(nodes) > 1 else 0
            r = math.sqrt(1 - y * y)
            theta = phi * i
            
            x = center[0] + radius * r * math.cos(theta)
            py = center[1] + radius * y
            z = center[2] + radius * r * math.sin(theta)
            
            node.position = (x, py, z)
            
            if node.object_3d:
                node.object_3d.position = node.position
        
        self._update_all_connections()
        self.update()
    
    def _update_all_connections(self):
        """Update all connection meshes"""
        for conn in self.connections.values():
            source = self.nodes.get(conn.source_id)
            target = self.nodes.get(conn.target_id)
            
            if source and target and conn.object_3d:
                conn.object_3d.mesh = self._create_connection_mesh(
                    source.position, target.position, conn.width
                )
                conn.object_3d.mesh.vao = None
    
    def simulate_attack(self, attacker_id: str, path: List[str], speed: float = 1.0):
        """Simulate an attack animation along a path"""
        self.highlight_path([attacker_id] + path, color=(1.0, 0.0, 0.0))
        
        # Animate through path
        # This would use QPropertyAnimation or similar in production
        for i, node_id in enumerate(path):
            def update_status():
                node = self.nodes.get(node_id)
                if node:
                    node.status = NodeStatus.COMPROMISED
                    self.update_node_status(node_id, NodeStatus.COMPROMISED)
            
            QTimer.singleShot(int(i * 1000 / speed), update_status)
    
    def load_from_scan_results(self, scan_data: Dict[str, Any]):
        """Load network topology from scan results"""
        # Parse hosts
        for host in scan_data.get("hosts", []):
            node_type = self._detect_node_type(host)
            
            node = NetworkNode(
                id=host.get("ip", str(id(host))),
                name=host.get("hostname", host.get("ip", "Unknown")),
                node_type=node_type,
                ip_address=host.get("ip", ""),
                mac_address=host.get("mac", ""),
                hostname=host.get("hostname", ""),
                os=host.get("os", ""),
                services=host.get("services", []),
                vulnerabilities=host.get("vulnerabilities", []),
                position=(random.uniform(-10, 10), 0, random.uniform(-10, 10))
            )
            
            self.add_node(node)
        
        # Parse connections (from routing or traffic data)
        for conn_data in scan_data.get("connections", []):
            conn = NetworkConnection(
                id=f"{conn_data['source']}_{conn_data['target']}",
                source_id=conn_data["source"],
                target_id=conn_data["target"],
                protocol=conn_data.get("protocol", "TCP"),
                port=conn_data.get("port", 0)
            )
            
            self.add_connection(conn)
        
        # Apply layout
        self.apply_force_directed_layout()
    
    def _detect_node_type(self, host_data: Dict) -> NodeType:
        """Detect node type from host data"""
        services = host_data.get("services", [])
        os_info = host_data.get("os", "").lower()
        
        # Check for common services
        service_ports = {s.get("port", 0) for s in services}
        
        if 3306 in service_ports or 5432 in service_ports or 1433 in service_ports:
            return NodeType.DATABASE
        elif 22 in service_ports or 80 in service_ports or 443 in service_ports:
            if "router" in os_info or "cisco" in os_info:
                return NodeType.ROUTER
            return NodeType.SERVER
        elif "firewall" in os_info or "pfsense" in os_info:
            return NodeType.FIREWALL
        elif "switch" in os_info:
            return NodeType.SWITCH
        elif "iot" in os_info or "embedded" in os_info:
            return NodeType.IOT
        else:
            return NodeType.ENDPOINT
    
    def export_topology(self) -> Dict[str, Any]:
        """Export topology as dictionary"""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "name": n.name,
                    "type": n.node_type.value,
                    "ip": n.ip_address,
                    "position": n.position,
                    "status": n.status.value
                }
                for n in self.nodes.values()
            ],
            "connections": [
                {
                    "id": c.id,
                    "source": c.source_id,
                    "target": c.target_id,
                    "type": c.connection_type.value,
                    "protocol": c.protocol,
                    "port": c.port
                }
                for c in self.connections.values()
            ]
        }
