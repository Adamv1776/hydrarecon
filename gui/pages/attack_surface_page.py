#!/usr/bin/env python3
"""
HydraRecon Attack Surface Visualization
████████████████████████████████████████████████████████████████████████████████
█  REAL-TIME NETWORK TOPOLOGY & ATTACK PATH VISUALIZATION                       █
████████████████████████████████████████████████████████████████████████████████
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QGroupBox, QFrame, QSlider, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QScrollArea, QToolBar, QStatusBar, QMenu, QGraphicsView,
    QGraphicsScene, QGraphicsEllipseItem, QGraphicsLineItem,
    QGraphicsTextItem, QGraphicsRectItem, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, QTimer, QPointF, QRectF, pyqtSignal, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import (
    QFont, QColor, QPen, QBrush, QPainter, QRadialGradient,
    QLinearGradient, QPainterPath, QTransform
)

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum


class NodeType(Enum):
    ATTACKER = "attacker"
    TARGET = "target"
    ROUTER = "router"
    SERVER = "server"
    WORKSTATION = "workstation"
    DATABASE = "database"
    FIREWALL = "firewall"
    COMPROMISED = "compromised"
    UNKNOWN = "unknown"


class ConnectionType(Enum):
    NETWORK = "network"
    ATTACK_PATH = "attack_path"
    DATA_FLOW = "data_flow"
    PIVOT = "pivot"


@dataclass
class NetworkNode:
    """Network node representation"""
    id: str
    ip: str
    hostname: str = ""
    node_type: NodeType = NodeType.UNKNOWN
    os: str = ""
    services: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    compromised: bool = False
    x: float = 0.0
    y: float = 0.0
    risk_score: float = 0.0


@dataclass
class NetworkConnection:
    """Connection between nodes"""
    source_id: str
    target_id: str
    connection_type: ConnectionType = ConnectionType.NETWORK
    port: int = 0
    protocol: str = ""
    encrypted: bool = False


class NetworkNodeItem(QGraphicsEllipseItem):
    """Graphical representation of a network node"""
    
    # Node colors by type
    NODE_COLORS = {
        NodeType.ATTACKER: ("#ff0040", "#cc0033"),
        NodeType.TARGET: ("#00ff9d", "#00cc7d"),
        NodeType.ROUTER: ("#00d4ff", "#00a8cc"),
        NodeType.SERVER: ("#8866ff", "#6644cc"),
        NodeType.WORKSTATION: ("#4488ff", "#2266cc"),
        NodeType.DATABASE: ("#ffaa00", "#cc8800"),
        NodeType.FIREWALL: ("#ff6644", "#cc4422"),
        NodeType.COMPROMISED: ("#ff0040", "#cc0033"),
        NodeType.UNKNOWN: ("#888888", "#666666"),
    }
    
    def __init__(self, node: NetworkNode, size: float = 60):
        super().__init__(-size/2, -size/2, size, size)
        self.node = node
        self.size = size
        self._setup_appearance()
        self._create_label()
        
        # Enable interactions
        self.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsSelectable)
        self.setAcceptHoverEvents(True)
        
        # Position
        self.setPos(node.x, node.y)
        
        # Animation properties
        self.pulse_timer = QTimer()
        self.pulse_phase = 0
        
        if node.compromised:
            self._start_pulse_animation()
    
    def _setup_appearance(self):
        """Setup node visual appearance"""
        colors = self.NODE_COLORS.get(self.node.node_type, self.NODE_COLORS[NodeType.UNKNOWN])
        primary_color = QColor(colors[0])
        secondary_color = QColor(colors[1])
        
        # Gradient fill
        gradient = QRadialGradient(0, 0, self.size/2)
        gradient.setColorAt(0, primary_color.lighter(150))
        gradient.setColorAt(0.5, primary_color)
        gradient.setColorAt(1, secondary_color)
        
        self.setBrush(QBrush(gradient))
        
        # Border
        pen = QPen(QColor("#ffffff"), 2)
        if self.node.compromised:
            pen = QPen(QColor("#ff0040"), 3)
        elif self.node.node_type == NodeType.ATTACKER:
            pen = QPen(QColor("#ff0040"), 3)
        self.setPen(pen)
        
        # Shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(primary_color)
        shadow.setOffset(0, 0)
        self.setGraphicsEffect(shadow)
    
    def _create_label(self):
        """Create node label"""
        label_text = self.node.hostname or self.node.ip
        if len(label_text) > 15:
            label_text = label_text[:12] + "..."
        
        self.label = QGraphicsTextItem(label_text, self)
        self.label.setDefaultTextColor(QColor("#e0e0e0"))
        font = QFont("Consolas", 9)
        font.setBold(True)
        self.label.setFont(font)
        
        # Center label below node
        label_rect = self.label.boundingRect()
        self.label.setPos(-label_rect.width()/2, self.size/2 + 5)
        
        # Icon based on type
        icon_map = {
            NodeType.ATTACKER: "👤",
            NodeType.TARGET: "🎯",
            NodeType.ROUTER: "📡",
            NodeType.SERVER: "🖥️",
            NodeType.WORKSTATION: "💻",
            NodeType.DATABASE: "🗄️",
            NodeType.FIREWALL: "🛡️",
            NodeType.COMPROMISED: "💀",
            NodeType.UNKNOWN: "❓",
        }
        
        icon = icon_map.get(self.node.node_type, "❓")
        icon_item = QGraphicsTextItem(icon, self)
        icon_item.setFont(QFont("Segoe UI Emoji", 18))
        icon_rect = icon_item.boundingRect()
        icon_item.setPos(-icon_rect.width()/2, -icon_rect.height()/2)
    
    def _start_pulse_animation(self):
        """Start pulsing animation for compromised nodes"""
        self.pulse_timer.timeout.connect(self._pulse)
        self.pulse_timer.start(50)
    
    def _pulse(self):
        """Pulse animation step"""
        self.pulse_phase += 0.1
        scale = 1.0 + 0.1 * math.sin(self.pulse_phase)
        self.setScale(scale)
    
    def hoverEnterEvent(self, event):
        """Handle hover enter"""
        self.setScale(1.2)
        super().hoverEnterEvent(event)
    
    def hoverLeaveEvent(self, event):
        """Handle hover leave"""
        if not self.node.compromised:
            self.setScale(1.0)
        super().hoverLeaveEvent(event)
    
    def get_tooltip_text(self) -> str:
        """Generate tooltip text"""
        lines = [
            f"<b>{self.node.hostname or 'Unknown Host'}</b>",
            f"IP: {self.node.ip}",
            f"Type: {self.node.node_type.value}",
            f"OS: {self.node.os or 'Unknown'}",
        ]
        
        if self.node.services:
            lines.append(f"Services: {len(self.node.services)}")
        
        if self.node.vulnerabilities:
            lines.append(f"<span style='color: #ff0040;'>Vulnerabilities: {len(self.node.vulnerabilities)}</span>")
        
        if self.node.compromised:
            lines.append("<span style='color: #ff0040;'><b>⚠️ COMPROMISED</b></span>")
        
        return "<br>".join(lines)


class NetworkConnectionItem(QGraphicsLineItem):
    """Graphical representation of a network connection"""
    
    CONNECTION_COLORS = {
        ConnectionType.NETWORK: "#444444",
        ConnectionType.ATTACK_PATH: "#ff0040",
        ConnectionType.DATA_FLOW: "#00ff9d",
        ConnectionType.PIVOT: "#ffaa00",
    }
    
    def __init__(self, connection: NetworkConnection, 
                 source_pos: QPointF, target_pos: QPointF):
        super().__init__(source_pos.x(), source_pos.y(), 
                        target_pos.x(), target_pos.y())
        
        self.connection = connection
        self._setup_appearance()
    
    def _setup_appearance(self):
        """Setup connection visual appearance"""
        color = QColor(self.CONNECTION_COLORS.get(
            self.connection.connection_type, 
            self.CONNECTION_COLORS[ConnectionType.NETWORK]
        ))
        
        width = 2
        if self.connection.connection_type == ConnectionType.ATTACK_PATH:
            width = 4
        elif self.connection.connection_type == ConnectionType.PIVOT:
            width = 3
        
        pen = QPen(color, width)
        
        if self.connection.connection_type == ConnectionType.ATTACK_PATH:
            pen.setStyle(Qt.PenStyle.DashLine)
        elif self.connection.connection_type == ConnectionType.DATA_FLOW:
            pen.setStyle(Qt.PenStyle.DotLine)
        
        self.setPen(pen)
    
    def update_positions(self, source_pos: QPointF, target_pos: QPointF):
        """Update line positions"""
        self.setLine(source_pos.x(), source_pos.y(),
                    target_pos.x(), target_pos.y())


class AttackSurfaceScene(QGraphicsScene):
    """Custom scene for attack surface visualization"""
    
    node_selected = pyqtSignal(object)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setBackgroundBrush(QBrush(QColor("#0a0e17")))
        
        self.nodes: Dict[str, NetworkNodeItem] = {}
        self.connections: List[NetworkConnectionItem] = []
        
        # Draw grid
        self._draw_grid()
    
    def _draw_grid(self):
        """Draw background grid"""
        grid_color = QColor("#1a2235")
        pen = QPen(grid_color, 1)
        
        # Grid size
        grid_size = 50
        
        # Draw vertical lines
        for x in range(-2000, 2000, grid_size):
            line = self.addLine(x, -2000, x, 2000, pen)
            line.setZValue(-100)
        
        # Draw horizontal lines
        for y in range(-2000, 2000, grid_size):
            line = self.addLine(-2000, y, 2000, y, pen)
            line.setZValue(-100)
    
    def add_node(self, node: NetworkNode):
        """Add a node to the scene"""
        node_item = NetworkNodeItem(node)
        self.addItem(node_item)
        self.nodes[node.id] = node_item
        return node_item
    
    def add_connection(self, connection: NetworkConnection):
        """Add a connection to the scene"""
        source_item = self.nodes.get(connection.source_id)
        target_item = self.nodes.get(connection.target_id)
        
        if source_item and target_item:
            conn_item = NetworkConnectionItem(
                connection,
                source_item.pos(),
                target_item.pos()
            )
            conn_item.setZValue(-10)  # Behind nodes
            self.addItem(conn_item)
            self.connections.append(conn_item)
            return conn_item
        return None
    
    def update_connections(self):
        """Update all connection positions"""
        for conn_item in self.connections:
            source_item = self.nodes.get(conn_item.connection.source_id)
            target_item = self.nodes.get(conn_item.connection.target_id)
            
            if source_item and target_item:
                conn_item.update_positions(source_item.pos(), target_item.pos())
    
    def clear_all(self):
        """Clear all nodes and connections"""
        for item in self.items():
            if isinstance(item, (NetworkNodeItem, NetworkConnectionItem)):
                self.removeItem(item)
        self.nodes.clear()
        self.connections.clear()
    
    def auto_layout(self, layout_type: str = "circular"):
        """Auto-arrange nodes"""
        if not self.nodes:
            return
        
        nodes_list = list(self.nodes.values())
        count = len(nodes_list)
        
        if layout_type == "circular":
            radius = 200 + count * 20
            for i, node_item in enumerate(nodes_list):
                angle = 2 * math.pi * i / count
                x = radius * math.cos(angle)
                y = radius * math.sin(angle)
                node_item.setPos(x, y)
        
        elif layout_type == "grid":
            cols = int(math.ceil(math.sqrt(count)))
            spacing = 150
            for i, node_item in enumerate(nodes_list):
                row = i // cols
                col = i % cols
                x = (col - cols/2) * spacing
                y = (row - cols/2) * spacing
                node_item.setPos(x, y)
        
        elif layout_type == "hierarchical":
            # Group by node type
            type_groups = {}
            for node_item in nodes_list:
                node_type = node_item.node.node_type
                if node_type not in type_groups:
                    type_groups[node_type] = []
                type_groups[node_type].append(node_item)
            
            y_offset = 0
            for node_type, items in type_groups.items():
                for i, node_item in enumerate(items):
                    x = (i - len(items)/2) * 150
                    node_item.setPos(x, y_offset)
                y_offset += 200
        
        self.update_connections()


class AttackSurfaceView(QGraphicsView):
    """Custom view for attack surface visualization"""
    
    def __init__(self, scene: AttackSurfaceScene, parent=None):
        super().__init__(scene, parent)
        self._setup_view()
        
        self._zoom_factor = 1.0
        self._pan_start = None
    
    def _setup_view(self):
        """Setup view properties"""
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        
        self.setStyleSheet("""
            QGraphicsView {
                background: #0a0e17;
                border: 1px solid #2a3548;
                border-radius: 5px;
            }
        """)
    
    def wheelEvent(self, event):
        """Handle zoom with mouse wheel"""
        factor = 1.15
        
        if event.angleDelta().y() > 0:
            self._zoom_factor *= factor
            self.scale(factor, factor)
        else:
            self._zoom_factor /= factor
            self.scale(1/factor, 1/factor)
    
    def mousePressEvent(self, event):
        """Handle pan start"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self._pan_start = event.pos()
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
        super().mousePressEvent(event)
    
    def mouseMoveEvent(self, event):
        """Handle panning"""
        if self._pan_start:
            delta = event.pos() - self._pan_start
            self._pan_start = event.pos()
            self.horizontalScrollBar().setValue(
                self.horizontalScrollBar().value() - delta.x()
            )
            self.verticalScrollBar().setValue(
                self.verticalScrollBar().value() - delta.y()
            )
        super().mouseMoveEvent(event)
    
    def mouseReleaseEvent(self, event):
        """Handle pan end"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self._pan_start = None
            self.setCursor(Qt.CursorShape.ArrowCursor)
        super().mouseReleaseEvent(event)
    
    def fit_all(self):
        """Fit all items in view"""
        self.fitInView(self.scene().itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)


class AttackSurfacePage(QWidget):
    """Main attack surface visualization page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._load_demo_data()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Visualization panel
        viz_panel = self._create_visualization_panel()
        splitter.addWidget(viz_panel)
        
        # Info panel
        info_panel = self._create_info_panel()
        splitter.addWidget(info_panel)
        
        splitter.setSizes([800, 300])
        layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = QLabel("Ready")
        self.status_bar.setStyleSheet("color: #888; padding: 5px;")
        layout.addWidget(self.status_bar)
    
    def _create_header(self) -> QWidget:
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #151b2d, stop:1 #1a2235);
                border: 1px solid #00ff9d;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🌐 ATTACK SURFACE VISUALIZATION")
        title.setStyleSheet("color: #00ff9d; font-size: 20px; font-weight: bold;")
        subtitle = QLabel("Real-time network topology and attack path visualization")
        subtitle.setStyleSheet("color: #888;")
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Control buttons
        controls = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background: #1a2235;
                color: #00ff9d;
                border: 1px solid #00ff9d;
                padding: 8px 15px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: rgba(0, 255, 157, 0.2);
            }
        """)
        refresh_btn.clicked.connect(self._refresh_visualization)
        controls.addWidget(refresh_btn)
        
        layout_combo = QComboBox()
        layout_combo.addItems(["Circular", "Grid", "Hierarchical"])
        layout_combo.setStyleSheet("""
            QComboBox {
                background: #1a2235;
                color: #e0e0e0;
                border: 1px solid #2a3548;
                padding: 8px;
                border-radius: 5px;
                min-width: 120px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background: #1a2235;
                color: #e0e0e0;
                selection-background-color: rgba(0, 255, 157, 0.3);
            }
        """)
        layout_combo.currentTextChanged.connect(self._change_layout)
        controls.addWidget(layout_combo)
        
        fit_btn = QPushButton("⬜ Fit View")
        fit_btn.setStyleSheet(refresh_btn.styleSheet())
        fit_btn.clicked.connect(self._fit_view)
        controls.addWidget(fit_btn)
        
        layout.addLayout(controls)
        
        return header
    
    def _create_visualization_panel(self) -> QWidget:
        panel = QGroupBox("Network Topology")
        panel.setStyleSheet("""
            QGroupBox {
                color: #00ff9d;
                font-weight: bold;
                border: 1px solid #2a3548;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        
        # Create scene and view
        self.scene = AttackSurfaceScene()
        self.view = AttackSurfaceView(self.scene)
        layout.addWidget(self.view)
        
        # Legend
        legend = self._create_legend()
        layout.addWidget(legend)
        
        return panel
    
    def _create_legend(self) -> QWidget:
        legend = QFrame()
        legend.setStyleSheet("""
            QFrame {
                background: rgba(0, 0, 0, 0.3);
                border-radius: 5px;
                padding: 10px;
            }
        """)
        
        layout = QHBoxLayout(legend)
        layout.setSpacing(20)
        
        items = [
            ("🎯", "Target", "#00ff9d"),
            ("💀", "Compromised", "#ff0040"),
            ("🖥️", "Server", "#8866ff"),
            ("💻", "Workstation", "#4488ff"),
            ("📡", "Router", "#00d4ff"),
            ("🛡️", "Firewall", "#ff6644"),
            ("🗄️", "Database", "#ffaa00"),
        ]
        
        for icon, label, color in items:
            item_layout = QHBoxLayout()
            icon_label = QLabel(icon)
            text_label = QLabel(label)
            text_label.setStyleSheet(f"color: {color}; font-size: 11px;")
            item_layout.addWidget(icon_label)
            item_layout.addWidget(text_label)
            layout.addLayout(item_layout)
        
        layout.addStretch()
        
        return legend
    
    def _create_info_panel(self) -> QWidget:
        panel = QGroupBox("Node Details")
        panel.setStyleSheet("""
            QGroupBox {
                color: #00d4ff;
                font-weight: bold;
                border: 1px solid #2a3548;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        
        # Node info area
        self.node_info = QLabel("Select a node to view details")
        self.node_info.setStyleSheet("""
            QLabel {
                color: #888;
                padding: 20px;
                background: #0a0e17;
                border-radius: 5px;
            }
        """)
        self.node_info.setWordWrap(True)
        self.node_info.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.node_info)
        
        # Services table
        services_label = QLabel("Services")
        services_label.setStyleSheet("color: #00ff9d; font-weight: bold;")
        layout.addWidget(services_label)
        
        self.services_table = QTableWidget()
        self.services_table.setColumnCount(3)
        self.services_table.setHorizontalHeaderLabels(["Port", "Service", "State"])
        self.services_table.setStyleSheet("""
            QTableWidget {
                background: #0a0e17;
                color: #e0e0e0;
                border: 1px solid #2a3548;
                border-radius: 5px;
                gridline-color: #2a3548;
            }
            QHeaderView::section {
                background: #1a2235;
                color: #00ff9d;
                padding: 8px;
                border: none;
            }
        """)
        self.services_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.services_table)
        
        # Vulnerabilities table
        vuln_label = QLabel("Vulnerabilities")
        vuln_label.setStyleSheet("color: #ff0040; font-weight: bold;")
        layout.addWidget(vuln_label)
        
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(3)
        self.vuln_table.setHorizontalHeaderLabels(["CVE", "Severity", "Service"])
        self.vuln_table.setStyleSheet(self.services_table.styleSheet())
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.vuln_table)
        
        return panel
    
    def _load_demo_data(self):
        """Load demo network data"""
        # Demo nodes
        nodes = [
            NetworkNode("1", "192.168.1.1", "Gateway", NodeType.ROUTER),
            NetworkNode("2", "192.168.1.10", "WebServer", NodeType.SERVER, 
                       services=[{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]),
            NetworkNode("3", "192.168.1.20", "DBServer", NodeType.DATABASE,
                       services=[{"port": 3306, "service": "MySQL"}, {"port": 5432, "service": "PostgreSQL"}]),
            NetworkNode("4", "192.168.1.30", "Workstation1", NodeType.WORKSTATION),
            NetworkNode("5", "192.168.1.31", "Workstation2", NodeType.WORKSTATION, compromised=True),
            NetworkNode("6", "192.168.1.100", "Firewall", NodeType.FIREWALL),
            NetworkNode("7", "10.0.0.5", "Attacker", NodeType.ATTACKER),
        ]
        
        # Add nodes to scene
        for node in nodes:
            self.scene.add_node(node)
        
        # Demo connections
        connections = [
            NetworkConnection("7", "6", ConnectionType.ATTACK_PATH),
            NetworkConnection("6", "1"),
            NetworkConnection("1", "2"),
            NetworkConnection("1", "3"),
            NetworkConnection("1", "4"),
            NetworkConnection("1", "5"),
            NetworkConnection("2", "3"),
            NetworkConnection("7", "5", ConnectionType.ATTACK_PATH),  # Attack path to compromised
        ]
        
        for conn in connections:
            self.scene.add_connection(conn)
        
        # Auto layout
        self.scene.auto_layout("circular")
        self.view.fit_all()
        
        self.status_bar.setText(f"Loaded {len(nodes)} nodes, {len(connections)} connections")
    
    def _refresh_visualization(self):
        """Refresh the visualization"""
        self.scene.update_connections()
        self.status_bar.setText("Visualization refreshed")
    
    def _change_layout(self, layout_name: str):
        """Change the node layout"""
        self.scene.auto_layout(layout_name.lower())
        self.view.fit_all()
        self.status_bar.setText(f"Layout changed to {layout_name}")
    
    def _fit_view(self):
        """Fit all nodes in view"""
        self.view.fit_all()
    
    def add_scan_results(self, results: Dict):
        """Add nodes from scan results"""
        # Clear existing
        self.scene.clear_all()
        
        # Add attacker node
        attacker = NetworkNode("attacker", "LOCAL", "Attacker", NodeType.ATTACKER)
        self.scene.add_node(attacker)
        
        # Process scan results
        for host_data in results.get("hosts", []):
            ip = host_data.get("ip", "unknown")
            hostname = host_data.get("hostname", "")
            
            # Determine node type
            node_type = NodeType.UNKNOWN
            services = host_data.get("services", [])
            
            if any(s.get("port") in [80, 443, 8080] for s in services):
                node_type = NodeType.SERVER
            elif any(s.get("port") in [3306, 5432, 1433, 27017] for s in services):
                node_type = NodeType.DATABASE
            elif any(s.get("port") in [22, 3389] for s in services):
                node_type = NodeType.WORKSTATION
            
            node = NetworkNode(
                id=ip,
                ip=ip,
                hostname=hostname,
                node_type=node_type,
                services=services,
                vulnerabilities=host_data.get("vulnerabilities", [])
            )
            
            self.scene.add_node(node)
            
            # Connect to attacker (scanned hosts)
            conn = NetworkConnection("attacker", ip)
            self.scene.add_connection(conn)
        
        # Auto layout
        self.scene.auto_layout("circular")
        self.view.fit_all()
        
        self.status_bar.setText(f"Added {len(results.get('hosts', []))} hosts from scan results")
