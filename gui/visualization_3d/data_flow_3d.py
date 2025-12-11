"""
3D Data Flow Visualization

Visualizes data movement through networks:
- Packet flows between nodes
- Protocol-specific visualization
- Bandwidth heatmaps
- Latency visualization
- Anomaly highlighting
- Real-time traffic analysis
"""

import math
import time
import random
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum

from PyQt6.QtCore import Qt, QTimer, pyqtSignal

from .engine_3d import (
    Visualization3DEngine, Scene3D, Object3D, Mesh3D, Material3D,
    Light3D, Camera3D, LightType
)
from .particle_system import ParticleSystem, ParticleEmitter


class ProtocolType(Enum):
    """Network protocol types"""
    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    ICMP = "icmp"
    CUSTOM = "custom"


class FlowStatus(Enum):
    """Data flow status"""
    NORMAL = "normal"
    WARNING = "warning"
    ANOMALY = "anomaly"
    BLOCKED = "blocked"
    ENCRYPTED = "encrypted"


@dataclass
class NetworkNode:
    """Network node for data flow"""
    id: str
    name: str
    position: Tuple[float, float, float]
    
    # Type
    node_type: str = "server"  # server, router, client, firewall, cloud
    
    # Stats
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    connections: int = 0
    
    # Visual
    object_3d: Optional[Object3D] = None
    label_object: Optional[Object3D] = None
    
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataPacket:
    """Single data packet"""
    id: str
    source_id: str
    target_id: str
    
    protocol: ProtocolType = ProtocolType.TCP
    size: int = 64
    
    # Position (for animation)
    position: Tuple[float, float, float] = (0, 0, 0)
    progress: float = 0.0  # 0-1 along path
    
    # Status
    status: FlowStatus = FlowStatus.NORMAL
    
    # Timing
    timestamp: float = 0.0
    latency: float = 0.0
    
    # Visual
    object_3d: Optional[Object3D] = None
    
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataFlow:
    """Continuous data flow between nodes"""
    id: str
    source_id: str
    target_id: str
    
    # Properties
    protocol: ProtocolType = ProtocolType.TCP
    bandwidth: float = 0.0  # Mbps
    latency: float = 0.0  # ms
    
    # Status
    status: FlowStatus = FlowStatus.NORMAL
    active: bool = True
    
    # Stats
    total_bytes: int = 0
    total_packets: int = 0
    
    # Packets in flight
    packets: List[DataPacket] = field(default_factory=list)
    
    # Visual
    path_object: Optional[Object3D] = None
    emitter: Optional[ParticleEmitter] = None
    
    data: Dict[str, Any] = field(default_factory=dict)


class DataFlow3D(Visualization3DEngine):
    """3D Data Flow Visualization"""
    
    nodeClicked = pyqtSignal(object)
    flowClicked = pyqtSignal(object)
    packetCaptured = pyqtSignal(object)
    anomalyDetected = pyqtSignal(object)
    
    # Protocol colors
    PROTOCOL_COLORS = {
        ProtocolType.TCP: (0.2, 0.6, 0.9),
        ProtocolType.UDP: (0.4, 0.8, 0.4),
        ProtocolType.HTTP: (0.9, 0.6, 0.2),
        ProtocolType.HTTPS: (0.2, 0.8, 0.4),
        ProtocolType.DNS: (0.7, 0.5, 0.9),
        ProtocolType.SSH: (0.3, 0.3, 0.3),
        ProtocolType.FTP: (0.6, 0.4, 0.2),
        ProtocolType.SMTP: (0.8, 0.4, 0.6),
        ProtocolType.ICMP: (0.5, 0.8, 0.8),
        ProtocolType.CUSTOM: (0.5, 0.5, 0.5),
    }
    
    # Status colors
    STATUS_COLORS = {
        FlowStatus.NORMAL: (0.3, 0.8, 0.4),
        FlowStatus.WARNING: (0.9, 0.7, 0.1),
        FlowStatus.ANOMALY: (0.9, 0.2, 0.2),
        FlowStatus.BLOCKED: (0.4, 0.4, 0.4),
        FlowStatus.ENCRYPTED: (0.3, 0.6, 0.9),
    }
    
    # Node colors
    NODE_COLORS = {
        "server": (0.2, 0.6, 0.9),
        "router": (0.4, 0.8, 0.4),
        "client": (0.7, 0.7, 0.7),
        "firewall": (0.9, 0.4, 0.2),
        "cloud": (0.5, 0.7, 0.9),
        "database": (0.8, 0.5, 0.2),
        "attacker": (0.9, 0.1, 0.1),
    }
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.nodes: Dict[str, NetworkNode] = {}
        self.flows: Dict[str, DataFlow] = {}
        
        # Particle system for data visualization
        self.particle_system = ParticleSystem()
        
        # Animation settings
        self.packet_speed = 5.0  # Units per second
        self.show_packets = True
        self.show_flow_lines = True
        self.show_bandwidth = True
        
        # Stats
        self.total_bytes = 0
        self.total_packets = 0
        
        self._setup_scene()
        
        # Animation timer
        self.flow_timer = QTimer()
        self.flow_timer.timeout.connect(self._update_flows)
        self.flow_timer.start(16)  # ~60 FPS
    
    def _setup_scene(self):
        """Setup the 3D scene"""
        self.scene.background_color = (0.02, 0.02, 0.04)
        self.scene.ambient_color = (0.08, 0.1, 0.12)
        
        self._setup_lighting()
        
        self.scene.camera.position = (20, 15, 20)
        self.scene.camera.target = (0, 0, 0)
        
        # Add floor grid
        self._create_floor_grid()
    
    def _setup_lighting(self):
        """Setup lighting"""
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(10, 20, 10),
            color=(1.0, 0.95, 0.9),
            intensity=200.0
        ))
        
        self.scene.add_light(Light3D(
            light_type=LightType.POINT,
            position=(-15, 10, -15),
            color=(0.6, 0.7, 0.9),
            intensity=100.0
        ))
    
    def _create_floor_grid(self):
        """Create floor grid"""
        vertices = []
        indices = []
        
        size = 30
        spacing = 2.0
        idx = 0
        
        for i in range(-size, size + 1):
            # X lines
            vertices.extend([i * spacing, 0, -size * spacing])
            vertices.extend([i * spacing, 0, size * spacing])
            indices.extend([idx, idx + 1])
            idx += 2
            
            # Z lines
            vertices.extend([-size * spacing, 0, i * spacing])
            vertices.extend([size * spacing, 0, i * spacing])
            indices.extend([idx, idx + 1])
            idx += 2
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        material = Material3D(
            name="floor_grid",
            albedo=(0.15, 0.2, 0.25),
            emission=(0.05, 0.08, 0.1),
            emission_strength=0.3,
            opacity=0.3,
            wireframe=True
        )
        
        grid = Object3D(
            name="floor_grid",
            mesh=mesh,
            material=material
        )
        
        self.scene.add_object(grid)
    
    def add_node(self, node: NetworkNode):
        """Add a network node"""
        self.nodes[node.id] = node
        
        # Create node visualization
        node_obj = self._create_node_object(node)
        node.object_3d = node_obj
        self.scene.add_object(node_obj)
        
        # Create label
        # (Labels would require text rendering, simplified here)
    
    def _create_node_object(self, node: NetworkNode) -> Object3D:
        """Create 3D object for network node"""
        color = self.NODE_COLORS.get(node.node_type, (0.5, 0.5, 0.5))
        
        # Different shapes for different types
        if node.node_type == "server":
            mesh = Mesh3D.create_box(1.0, 1.5, 0.5)
        elif node.node_type == "router":
            mesh = Mesh3D.create_box(0.8, 0.4, 0.8)
        elif node.node_type == "firewall":
            mesh = Mesh3D.create_box(0.3, 2.0, 2.0)
        elif node.node_type == "cloud":
            mesh = Mesh3D.create_sphere(1.0, 16, 8)
        elif node.node_type == "database":
            mesh = Mesh3D.create_sphere(0.7, 8, 16)  # Cylinder-ish
        else:
            mesh = Mesh3D.create_box(0.6, 0.6, 0.6)
        
        material = Material3D(
            name=f"node_{node.id}",
            albedo=color,
            emission=color,
            emission_strength=0.5,
            metallic=0.3,
            roughness=0.5
        )
        
        node_obj = Object3D(
            name=f"node_{node.id}",
            mesh=mesh,
            material=material,
            position=node.position,
            data={"type": "node", "node_id": node.id}
        )
        
        # Pulse animation for active nodes
        def animate_node(obj: Object3D, dt: float):
            if node.connections > 0:
                pulse = math.sin(time.time() * 2) * 0.1 + 1.0
                obj.material.emission_strength = 0.3 + pulse * 0.3
        
        node_obj.animation_callback = animate_node
        
        return node_obj
    
    def add_flow(self, flow: DataFlow):
        """Add a data flow"""
        self.flows[flow.id] = flow
        
        # Create flow path visualization
        if self.show_flow_lines:
            path_obj = self._create_flow_path(flow)
            flow.path_object = path_obj
            if path_obj:
                self.scene.add_object(path_obj)
        
        # Create particle emitter for data packets
        if flow.source_id in self.nodes and flow.target_id in self.nodes:
            source_pos = self.nodes[flow.source_id].position
            target_pos = self.nodes[flow.target_id].position
            
            color = self.PROTOCOL_COLORS.get(flow.protocol, (0.5, 0.5, 0.5))
            
            emitter = ParticleSystem.create_data_stream_emitter(
                source_pos, target_pos, color
            )
            emitter.emission_rate = min(50, flow.bandwidth * 5)
            
            flow.emitter = emitter
            self.particle_system.add_emitter(flow.id, emitter)
    
    def _create_flow_path(self, flow: DataFlow) -> Optional[Object3D]:
        """Create flow path line"""
        if flow.source_id not in self.nodes or flow.target_id not in self.nodes:
            return None
        
        source = self.nodes[flow.source_id]
        target = self.nodes[flow.target_id]
        
        # Create curved path
        vertices = self._create_bezier_path(
            source.position, target.position
        )
        
        indices = []
        for i in range(len(vertices) // 3 - 1):
            indices.extend([i, i + 1])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32)
        )
        
        color = self.STATUS_COLORS.get(flow.status, (0.5, 0.5, 0.5))
        
        # Width based on bandwidth
        width = min(0.1, 0.01 + flow.bandwidth * 0.005)
        
        material = Material3D(
            name=f"flow_{flow.id}",
            albedo=color,
            emission=color,
            emission_strength=0.3 + flow.bandwidth * 0.05,
            opacity=0.4 + flow.bandwidth * 0.02,
            wireframe=True
        )
        
        path = Object3D(
            name=f"flow_{flow.id}",
            mesh=mesh,
            material=material,
            data={"type": "flow", "flow_id": flow.id}
        )
        
        # Animate flow line
        def animate_flow(obj: Object3D, dt: float):
            if flow.active:
                pulse = (math.sin(time.time() * 4) + 1) * 0.5
                obj.material.emission_strength = 0.2 + pulse * 0.3
                obj.material.opacity = 0.3 + pulse * 0.2
            else:
                obj.material.emission_strength = 0.1
                obj.material.opacity = 0.2
        
        path.animation_callback = animate_flow
        
        return path
    
    def _create_bezier_path(self, start: Tuple[float, float, float],
                            end: Tuple[float, float, float],
                            segments: int = 30) -> List[float]:
        """Create curved bezier path between two points"""
        start = np.array(start)
        end = np.array(end)
        
        # Control point for curve
        mid = (start + end) / 2
        distance = np.linalg.norm(end - start)
        height = min(3.0, distance * 0.2)
        mid[1] += height
        
        vertices = []
        
        for i in range(segments + 1):
            t = i / segments
            
            # Quadratic bezier
            point = (1-t)**2 * start + 2*(1-t)*t * mid + t**2 * end
            vertices.extend(point.tolist())
        
        return vertices
    
    def send_packet(self, source_id: str, target_id: str,
                    protocol: ProtocolType = ProtocolType.TCP,
                    size: int = 64,
                    status: FlowStatus = FlowStatus.NORMAL):
        """Send a data packet"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return
        
        packet = DataPacket(
            id=f"pkt_{int(time.time() * 1000)}_{random.randint(0, 9999)}",
            source_id=source_id,
            target_id=target_id,
            protocol=protocol,
            size=size,
            status=status,
            timestamp=time.time(),
            position=self.nodes[source_id].position
        )
        
        # Create packet visualization
        packet_obj = self._create_packet_object(packet)
        packet.object_3d = packet_obj
        self.scene.add_object(packet_obj)
        
        # Add to flow or create temporary flow
        flow_id = f"{source_id}_{target_id}"
        if flow_id in self.flows:
            self.flows[flow_id].packets.append(packet)
        else:
            # Create temporary tracking
            if not hasattr(self, '_temp_packets'):
                self._temp_packets = []
            self._temp_packets.append(packet)
        
        # Update stats
        self.total_packets += 1
        self.total_bytes += size
        self.nodes[source_id].packets_out += 1
        self.nodes[source_id].bytes_out += size
        
        self.packetCaptured.emit(packet)
    
    def _create_packet_object(self, packet: DataPacket) -> Object3D:
        """Create packet visualization"""
        # Size based on packet size
        size = 0.05 + min(0.2, packet.size / 1000)
        
        mesh = Mesh3D.create_sphere(size, 8, 4)
        
        color = self.PROTOCOL_COLORS.get(packet.protocol, (0.5, 0.5, 0.5))
        
        # Modify color based on status
        if packet.status == FlowStatus.ANOMALY:
            color = self.STATUS_COLORS[FlowStatus.ANOMALY]
        elif packet.status == FlowStatus.WARNING:
            color = self.STATUS_COLORS[FlowStatus.WARNING]
        
        material = Material3D(
            name=f"packet_{packet.id}",
            albedo=color,
            emission=color,
            emission_strength=1.0,
            metallic=0.0,
            roughness=1.0
        )
        
        packet_obj = Object3D(
            name=f"packet_{packet.id}",
            mesh=mesh,
            material=material,
            position=packet.position,
            data={"type": "packet", "packet_id": packet.id}
        )
        
        return packet_obj
    
    def _update_flows(self):
        """Update data flows and packet positions"""
        dt = 0.016  # ~60 FPS
        
        # Update particle system
        self.particle_system.update(dt)
        
        # Update packets in flows
        for flow in self.flows.values():
            if not flow.active:
                continue
            
            completed = []
            
            for packet in flow.packets:
                self._update_packet(packet, dt)
                
                if packet.progress >= 1.0:
                    completed.append(packet)
                    self._complete_packet(packet)
            
            for packet in completed:
                flow.packets.remove(packet)
        
        # Update temporary packets
        if hasattr(self, '_temp_packets'):
            completed = []
            
            for packet in self._temp_packets:
                self._update_packet(packet, dt)
                
                if packet.progress >= 1.0:
                    completed.append(packet)
                    self._complete_packet(packet)
            
            for packet in completed:
                self._temp_packets.remove(packet)
    
    def _update_packet(self, packet: DataPacket, dt: float):
        """Update single packet position"""
        if packet.source_id not in self.nodes or packet.target_id not in self.nodes:
            return
        
        source = self.nodes[packet.source_id]
        target = self.nodes[packet.target_id]
        
        # Calculate travel time based on distance
        distance = np.linalg.norm(
            np.array(target.position) - np.array(source.position)
        )
        travel_time = distance / self.packet_speed
        
        # Update progress
        packet.progress += dt / travel_time
        
        # Interpolate position along bezier curve
        t = min(1.0, packet.progress)
        
        start = np.array(source.position)
        end = np.array(target.position)
        mid = (start + end) / 2
        mid[1] += min(3.0, distance * 0.2)
        
        pos = (1-t)**2 * start + 2*(1-t)*t * mid + t**2 * end
        packet.position = tuple(pos)
        
        # Update 3D object
        if packet.object_3d:
            packet.object_3d.position = packet.position
    
    def _complete_packet(self, packet: DataPacket):
        """Handle packet arrival"""
        if packet.target_id in self.nodes:
            target = self.nodes[packet.target_id]
            target.packets_in += 1
            target.bytes_in += packet.size
        
        # Remove visualization
        if packet.object_3d:
            self.scene.remove_object(packet.object_3d)
        
        # Calculate latency
        packet.latency = (time.time() - packet.timestamp) * 1000  # ms
    
    def set_flow_status(self, flow_id: str, status: FlowStatus):
        """Update flow status"""
        if flow_id not in self.flows:
            return
        
        flow = self.flows[flow_id]
        flow.status = status
        
        # Update visualization
        if flow.path_object:
            color = self.STATUS_COLORS.get(status, (0.5, 0.5, 0.5))
            flow.path_object.material.albedo = color
            flow.path_object.material.emission = color
        
        # Emit anomaly if detected
        if status == FlowStatus.ANOMALY:
            self.anomalyDetected.emit(flow)
    
    def highlight_node(self, node_id: str, highlight: bool = True):
        """Highlight a node"""
        if node_id not in self.nodes:
            return
        
        node = self.nodes[node_id]
        
        if node.object_3d:
            if highlight:
                node.object_3d.material.emission_strength = 1.5
                node.object_3d.scale = (1.2, 1.2, 1.2)
            else:
                node.object_3d.material.emission_strength = 0.5
                node.object_3d.scale = (1.0, 1.0, 1.0)
    
    def highlight_flow(self, flow_id: str, highlight: bool = True):
        """Highlight a flow"""
        if flow_id not in self.flows:
            return
        
        flow = self.flows[flow_id]
        
        if flow.path_object:
            if highlight:
                flow.path_object.material.emission_strength = 1.0
                flow.path_object.material.opacity = 0.8
            else:
                flow.path_object.material.emission_strength = 0.3
                flow.path_object.material.opacity = 0.4
    
    def create_bandwidth_heatmap(self):
        """Create bandwidth heatmap on floor"""
        # Calculate bandwidth at each point
        resolution = 30
        size = 20
        
        vertices = []
        colors = []
        indices = []
        
        for i in range(resolution):
            for j in range(resolution):
                x = (i / resolution - 0.5) * size * 2
                z = (j / resolution - 0.5) * size * 2
                
                # Calculate bandwidth influence from flows
                bandwidth = 0
                for flow in self.flows.values():
                    if flow.source_id in self.nodes and flow.target_id in self.nodes:
                        source = np.array(self.nodes[flow.source_id].position)
                        target = np.array(self.nodes[flow.target_id].position)
                        
                        # Distance to flow line
                        point = np.array([x, 0, z])
                        line_vec = target - source
                        line_len = np.linalg.norm(line_vec)
                        
                        if line_len > 0:
                            line_vec = line_vec / line_len
                            proj = np.dot(point - source, line_vec)
                            proj = max(0, min(line_len, proj))
                            
                            closest = source + line_vec * proj
                            dist = np.linalg.norm(point - closest)
                            
                            # Bandwidth contribution
                            bandwidth += flow.bandwidth / (1 + dist * 0.5)
                
                vertices.extend([x, 0.01, z])
                
                # Color based on bandwidth
                normalized = min(1.0, bandwidth / 50)
                r = normalized
                g = 0.5 - abs(normalized - 0.5)
                b = 1 - normalized
                colors.extend([r, g, b])
        
        # Create triangles
        for i in range(resolution - 1):
            for j in range(resolution - 1):
                idx = i * resolution + j
                indices.extend([
                    idx, idx + 1, idx + resolution,
                    idx + 1, idx + resolution + 1, idx + resolution
                ])
        
        mesh = Mesh3D(
            vertices=np.array(vertices, dtype=np.float32),
            indices=np.array(indices, dtype=np.uint32),
            colors=np.array(colors, dtype=np.float32) if colors else None
        )
        
        material = Material3D(
            name="bandwidth_heatmap",
            albedo=(1, 1, 1),
            emission=(0.3, 0.3, 0.3),
            emission_strength=0.5,
            opacity=0.5
        )
        
        heatmap = Object3D(
            name="bandwidth_heatmap",
            mesh=mesh,
            material=material
        )
        
        self.scene.add_object(heatmap)
    
    def simulate_traffic(self, packets_per_second: float = 5.0):
        """Simulate network traffic"""
        node_ids = list(self.nodes.keys())
        
        if len(node_ids) < 2:
            return
        
        def generate_packet():
            source = random.choice(node_ids)
            target = random.choice([n for n in node_ids if n != source])
            
            protocol = random.choice(list(ProtocolType))
            size = random.randint(64, 1500)
            
            # Occasionally create anomalies
            status = FlowStatus.NORMAL
            if random.random() < 0.05:
                status = FlowStatus.ANOMALY
            elif random.random() < 0.1:
                status = FlowStatus.WARNING
            
            self.send_packet(source, target, protocol, size, status)
        
        interval = int(1000 / packets_per_second)
        
        self.traffic_timer = QTimer()
        self.traffic_timer.timeout.connect(generate_packet)
        self.traffic_timer.start(interval)
    
    def stop_simulation(self):
        """Stop traffic simulation"""
        if hasattr(self, 'traffic_timer'):
            self.traffic_timer.stop()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        return {
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "active_flows": sum(1 for f in self.flows.values() if f.active),
            "nodes": len(self.nodes),
            "flows": len(self.flows),
            "node_stats": {
                node_id: {
                    "bytes_in": node.bytes_in,
                    "bytes_out": node.bytes_out,
                    "packets_in": node.packets_in,
                    "packets_out": node.packets_out,
                }
                for node_id, node in self.nodes.items()
            }
        }
    
    def create_demo_network(self):
        """Create a demo network topology"""
        # Create nodes
        nodes = [
            NetworkNode("server1", "Web Server", (-8, 2, 0), "server"),
            NetworkNode("server2", "Database", (-8, 2, -6), "database"),
            NetworkNode("router1", "Core Router", (0, 1, 0), "router"),
            NetworkNode("firewall", "Firewall", (0, 1.5, -8), "firewall"),
            NetworkNode("client1", "Client 1", (8, 0.5, 3), "client"),
            NetworkNode("client2", "Client 2", (8, 0.5, -3), "client"),
            NetworkNode("cloud", "Cloud", (0, 4, 8), "cloud"),
            NetworkNode("attacker", "Attacker", (12, 0.5, 0), "attacker"),
        ]
        
        for node in nodes:
            self.add_node(node)
        
        # Create flows
        flows = [
            DataFlow("f1", "client1", "router1", ProtocolType.HTTP, 10),
            DataFlow("f2", "client2", "router1", ProtocolType.HTTPS, 5),
            DataFlow("f3", "router1", "server1", ProtocolType.HTTP, 15),
            DataFlow("f4", "server1", "server2", ProtocolType.TCP, 20),
            DataFlow("f5", "router1", "firewall", ProtocolType.TCP, 8),
            DataFlow("f6", "firewall", "cloud", ProtocolType.HTTPS, 12),
            DataFlow("f7", "attacker", "router1", ProtocolType.TCP, 2, status=FlowStatus.ANOMALY),
        ]
        
        for flow in flows:
            self.add_flow(flow)
        
        # Create bandwidth heatmap
        self.create_bandwidth_heatmap()
        
        # Start simulation
        self.simulate_traffic(10)
