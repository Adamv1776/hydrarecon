"""
HydraRecon - Network Topology Mapper GUI
Interactive visual network topology discovery and mapping
"""

import math
import random
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QTextEdit, QComboBox,
    QProgressBar, QSplitter, QGroupBox, QLineEdit, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QListWidget, QListWidgetItem, QCheckBox, QDialog, QFormLayout,
    QDialogButtonBox, QGraphicsView, QGraphicsScene, QGraphicsItem,
    QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem,
    QSlider, QToolButton, QMenu
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QPointF, QRectF, QLineF
from PyQt6.QtGui import (
    QFont, QColor, QPainter, QPen, QBrush, QRadialGradient,
    QLinearGradient, QPainterPath, QTransform, QWheelEvent
)


class NetworkNodeItem(QGraphicsEllipseItem):
    """Visual representation of a network node"""
    
    TYPE_COLORS = {
        "router": "#e74c3c",
        "switch": "#3498db",
        "firewall": "#e67e22",
        "server": "#27ae60",
        "workstation": "#9b59b6",
        "printer": "#95a5a6",
        "iot": "#f1c40f",
        "mobile": "#1abc9c",
        "wireless_ap": "#00bcd4",
        "load_balancer": "#ff5722",
        "database": "#8e44ad",
        "storage": "#607d8b",
        "virtual": "#673ab7",
        "cloud": "#03a9f4",
        "unknown": "#bdc3c7",
    }
    
    TYPE_ICONS = {
        "router": "🌐",
        "switch": "🔀",
        "firewall": "🛡️",
        "server": "🖥️",
        "workstation": "💻",
        "printer": "🖨️",
        "iot": "📡",
        "mobile": "📱",
        "wireless_ap": "📶",
        "load_balancer": "⚖️",
        "database": "💾",
        "storage": "🗄️",
        "virtual": "☁️",
        "cloud": "🌩️",
        "unknown": "❓",
    }
    
    def __init__(self, node_data: Dict, x: float, y: float, size: float = 50):
        super().__init__(-size/2, -size/2, size, size)
        self.node_data = node_data
        self.node_id = node_data.get("id", "")
        self.node_name = node_data.get("name", "Unknown")
        self.node_type = node_data.get("type", "unknown")
        self.node_ip = node_data.get("ip", "")
        self.is_critical = node_data.get("is_critical", False)
        self.is_compromised = node_data.get("is_compromised", False)
        
        self.setPos(x, y)
        self.setup_appearance()
        
        # Make node interactive
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAcceptHoverEvents(True)
        
        # Add label
        self.label = QGraphicsTextItem(self.node_name, self)
        self.label.setDefaultTextColor(QColor("#ffffff"))
        self.label.setFont(QFont("Arial", 8))
        label_rect = self.label.boundingRect()
        self.label.setPos(-label_rect.width()/2, size/2 + 2)
        
        # Store connected edges
        self.edges: List = []
        
    def setup_appearance(self):
        """Setup node visual appearance"""
        color = QColor(self.TYPE_COLORS.get(self.node_type, "#bdc3c7"))
        
        if self.is_compromised:
            color = QColor("#e74c3c")
        elif self.is_critical:
            # Add glow effect for critical assets
            pass
            
        # Create gradient
        gradient = QRadialGradient(0, 0, 25)
        gradient.setColorAt(0, color.lighter(150))
        gradient.setColorAt(0.7, color)
        gradient.setColorAt(1, color.darker(120))
        
        self.setBrush(QBrush(gradient))
        
        # Border
        if self.is_critical:
            self.setPen(QPen(QColor("#ffd700"), 3))
        elif self.is_compromised:
            self.setPen(QPen(QColor("#ff0000"), 3))
        else:
            self.setPen(QPen(color.darker(150), 2))
            
    def add_edge(self, edge):
        """Add a connected edge"""
        self.edges.append(edge)
        
    def itemChange(self, change, value):
        """Handle item changes"""
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            # Update connected edges
            for edge in self.edges:
                edge.adjust()
        return super().itemChange(change, value)
        
    def hoverEnterEvent(self, event):
        """Handle hover enter"""
        self.setScale(1.2)
        super().hoverEnterEvent(event)
        
    def hoverLeaveEvent(self, event):
        """Handle hover leave"""
        self.setScale(1.0)
        super().hoverLeaveEvent(event)
        
    def paint(self, painter, option, widget):
        """Custom paint with icon"""
        super().paint(painter, option, widget)
        
        # Draw icon
        icon = self.TYPE_ICONS.get(self.node_type, "❓")
        painter.setFont(QFont("Arial", 16))
        painter.setPen(QPen(QColor("#ffffff")))
        rect = self.boundingRect()
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, icon)


class NetworkEdgeItem(QGraphicsLineItem):
    """Visual representation of a network connection"""
    
    def __init__(self, source_node: NetworkNodeItem, target_node: NetworkNodeItem, 
                 edge_data: Dict):
        super().__init__()
        self.source_node = source_node
        self.target_node = target_node
        self.edge_data = edge_data
        
        # Register with nodes
        source_node.add_edge(self)
        target_node.add_edge(self)
        
        # Setup appearance
        self.is_active = edge_data.get("active", True)
        self.setup_appearance()
        
        # Initial position
        self.adjust()
        
    def setup_appearance(self):
        """Setup edge appearance"""
        if self.is_active:
            pen = QPen(QColor("#3498db80"), 2)
        else:
            pen = QPen(QColor("#e74c3c50"), 2, Qt.PenStyle.DashLine)
        self.setPen(pen)
        
    def adjust(self):
        """Update edge position based on connected nodes"""
        if not self.source_node or not self.target_node:
            return
            
        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()
        
        self.setLine(QLineF(source_pos, target_pos))


class TopologyGraphicsView(QGraphicsView):
    """Interactive network topology view"""
    
    node_selected = pyqtSignal(dict)
    node_double_clicked = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        
        self.setup_view()
        
        self.nodes: Dict[str, NetworkNodeItem] = {}
        self.edges: List[NetworkEdgeItem] = []
        
        self._zoom_factor = 1.0
        self._pan_start = None
        
    def setup_view(self):
        """Setup view properties"""
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        
        self.setBackgroundBrush(QColor("#0a0a15"))
        
        self.scene.setSceneRect(-2000, -2000, 4000, 4000)
        
    def load_topology(self, topology_data: Dict):
        """Load and display network topology"""
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        
        nodes_data = topology_data.get("nodes", [])
        edges_data = topology_data.get("edges", [])
        
        # Create nodes
        for node_data in nodes_data:
            x = node_data.get("x", random.randint(-500, 500))
            y = node_data.get("y", random.randint(-300, 300))
            
            node_item = NetworkNodeItem(node_data, x, y)
            self.scene.addItem(node_item)
            self.nodes[node_data["id"]] = node_item
            
        # Create edges
        for edge_data in edges_data:
            source_id = edge_data.get("source")
            target_id = edge_data.get("target")
            
            if source_id in self.nodes and target_id in self.nodes:
                edge_item = NetworkEdgeItem(
                    self.nodes[source_id],
                    self.nodes[target_id],
                    edge_data
                )
                self.scene.addItem(edge_item)
                self.edges.append(edge_item)
                
        # Fit view
        self.fitInView(self.scene.itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)
        self.scale(0.8, 0.8)
        
    def wheelEvent(self, event: QWheelEvent):
        """Handle zoom with mouse wheel"""
        zoom_in_factor = 1.15
        zoom_out_factor = 1 / zoom_in_factor
        
        if event.angleDelta().y() > 0:
            zoom_factor = zoom_in_factor
        else:
            zoom_factor = zoom_out_factor
            
        self._zoom_factor *= zoom_factor
        
        # Limit zoom
        if self._zoom_factor < 0.1:
            self._zoom_factor = 0.1
            return
        if self._zoom_factor > 10:
            self._zoom_factor = 10
            return
            
        self.scale(zoom_factor, zoom_factor)
        
    def mouseDoubleClickEvent(self, event):
        """Handle double click on nodes"""
        item = self.itemAt(event.pos())
        if isinstance(item, NetworkNodeItem):
            self.node_double_clicked.emit(item.node_data)
        super().mouseDoubleClickEvent(event)
        
    def mousePressEvent(self, event):
        """Handle node selection"""
        item = self.itemAt(event.pos())
        if isinstance(item, NetworkNodeItem):
            self.node_selected.emit(item.node_data)
        super().mousePressEvent(event)


class StatCard(QFrame):
    """Statistic card widget"""
    
    def __init__(self, title: str, value: str = "0", icon: str = "📊", color: str = "#3498db"):
        super().__init__()
        self.color = color
        self.setup_ui(title, value, icon)
        
    def setup_ui(self, title: str, value: str, icon: str):
        self.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {self.color}30, stop:1 {self.color}10);
                border: 1px solid {self.color}50;
                border-radius: 12px;
                padding: 15px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 12, 15, 12)
        layout.setSpacing(5)
        
        # Icon and value
        header = QHBoxLayout()
        
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Arial", 24))
        icon_label.setStyleSheet("background: transparent;")
        header.addWidget(icon_label)
        
        header.addStretch()
        
        self.value_label = QLabel(value)
        self.value_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        self.value_label.setStyleSheet(f"color: {self.color}; background: transparent;")
        header.addWidget(self.value_label)
        
        layout.addLayout(header)
        
        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #888; font-size: 11px; background: transparent;")
        layout.addWidget(title_label)
        
    def set_value(self, value: str):
        self.value_label.setText(value)


class NodeDetailsPanel(QFrame):
    """Panel showing details of selected node"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        self.setStyleSheet("""
            QFrame {
                background: #16213e;
                border-radius: 12px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Title
        self.title_label = QLabel("Select a node")
        self.title_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.title_label.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(self.title_label)
        
        # Details grid
        self.details_grid = QGridLayout()
        self.details_grid.setSpacing(8)
        
        self.detail_labels = {}
        details = [
            ("IP Address", "ip"),
            ("Type", "type"),
            ("Zone", "zone"),
            ("Vendor", "vendor"),
            ("OS", "os"),
            ("Status", "status"),
        ]
        
        for i, (label, key) in enumerate(details):
            name = QLabel(f"{label}:")
            name.setStyleSheet("color: #888; font-size: 11px; background: transparent;")
            value = QLabel("-")
            value.setStyleSheet("color: #fff; font-size: 11px; background: transparent;")
            self.detail_labels[key] = value
            self.details_grid.addWidget(name, i, 0)
            self.details_grid.addWidget(value, i, 1)
            
        layout.addLayout(self.details_grid)
        
        # Connected nodes
        layout.addWidget(QLabel("Connected To:"))
        self.connections_list = QListWidget()
        self.connections_list.setMaximumHeight(100)
        self.connections_list.setStyleSheet("""
            QListWidget {
                background: #0a0a15;
                border: none;
                border-radius: 5px;
                color: #fff;
            }
            QListWidget::item {
                padding: 5px;
            }
        """)
        layout.addWidget(self.connections_list)
        
        layout.addStretch()
        
    def show_node(self, node_data: Dict, connected_nodes: List[str] = None):
        """Display node details"""
        self.title_label.setText(f"🖥️ {node_data.get('name', 'Unknown')}")
        
        self.detail_labels["ip"].setText(node_data.get("ip", "-"))
        self.detail_labels["type"].setText(node_data.get("type", "-").title())
        self.detail_labels["zone"].setText(node_data.get("zone", "-").title())
        self.detail_labels["vendor"].setText(node_data.get("vendor", "-"))
        self.detail_labels["os"].setText(node_data.get("os", "-") or "-")
        
        if node_data.get("is_compromised"):
            self.detail_labels["status"].setText("⚠️ COMPROMISED")
            self.detail_labels["status"].setStyleSheet("color: #e74c3c; font-weight: bold; background: transparent;")
        elif node_data.get("is_critical"):
            self.detail_labels["status"].setText("⭐ Critical Asset")
            self.detail_labels["status"].setStyleSheet("color: #f1c40f; background: transparent;")
        else:
            self.detail_labels["status"].setText("✅ Normal")
            self.detail_labels["status"].setStyleSheet("color: #27ae60; background: transparent;")
            
        # Update connections
        self.connections_list.clear()
        if connected_nodes:
            for name in connected_nodes[:10]:
                self.connections_list.addItem(f"→ {name}")


class TopologyMapperPage(QWidget):
    """Main page for Network Topology Mapper"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.mapper = None
        self.topology_data = None
        self.setup_ui()
        self.load_mapper()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Stats bar
        stats_bar = self.create_stats_bar()
        layout.addWidget(stats_bar)
        
        # Main content with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Filters and Legend
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)
        
        # Center - Topology view
        center_panel = self.create_center_panel()
        splitter.addWidget(center_panel)
        
        # Right panel - Details
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([250, 800, 300])
        layout.addWidget(splitter, 1)
        
    def create_header(self) -> QFrame:
        """Create header with controls"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:0.5 #16213e, stop:1 #0f3460);
                border-radius: 15px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title section
        title_section = QVBoxLayout()
        
        title = QLabel("🗺️ Network Topology Mapper")
        title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #3498db; background: transparent;")
        title_section.addWidget(title)
        
        subtitle = QLabel("Visual Network Discovery and Mapping")
        subtitle.setStyleSheet("color: #888; font-size: 12px; background: transparent;")
        title_section.addWidget(subtitle)
        
        layout.addLayout(title_section)
        layout.addStretch()
        
        # Controls
        btn_style = """
            QPushButton {
                background: %s;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 25px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background: %s;
            }
        """
        
        self.scan_btn = QPushButton("🔍 Discover Network")
        self.scan_btn.setStyleSheet(btn_style % ("#27ae60", "#1e8449"))
        self.scan_btn.clicked.connect(self.start_discovery)
        layout.addWidget(self.scan_btn)
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.setStyleSheet(btn_style % ("#3498db", "#2980b9"))
        self.refresh_btn.clicked.connect(self.refresh_topology)
        layout.addWidget(self.refresh_btn)
        
        self.export_btn = QPushButton("📤 Export")
        self.export_btn.setStyleSheet(btn_style % ("#9b59b6", "#8e44ad"))
        self.export_btn.clicked.connect(self.export_topology)
        layout.addWidget(self.export_btn)
        
        return frame
        
    def create_stats_bar(self) -> QFrame:
        """Create statistics bar"""
        frame = QFrame()
        layout = QHBoxLayout(frame)
        layout.setSpacing(15)
        
        self.stat_cards = {}
        
        stats = [
            ("Total Nodes", "0", "🖥️", "#3498db"),
            ("Connections", "0", "🔗", "#27ae60"),
            ("Subnets", "0", "🌐", "#9b59b6"),
            ("Critical Assets", "0", "⭐", "#f1c40f"),
            ("Security Zones", "0", "🛡️", "#e67e22"),
            ("Issues Found", "0", "⚠️", "#e74c3c"),
        ]
        
        for title, value, icon, color in stats:
            card = StatCard(title, value, icon, color)
            self.stat_cards[title] = card
            layout.addWidget(card)
            
        return frame
        
    def create_left_panel(self) -> QFrame:
        """Create left panel with filters and legend"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 12px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setSpacing(15)
        
        # Filters section
        filters_title = QLabel("🎛️ Filters")
        filters_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        filters_title.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(filters_title)
        
        # Zone filter
        zone_label = QLabel("Security Zone:")
        zone_label.setStyleSheet("color: #888; background: transparent;")
        layout.addWidget(zone_label)
        
        self.zone_combo = QComboBox()
        self.zone_combo.addItems(["All Zones", "External", "DMZ", "Internal", "Management", "Guest"])
        self.zone_combo.setStyleSheet("""
            QComboBox {
                background: #16213e;
                color: #fff;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
            }
            QComboBox::drop-down {
                border: none;
            }
        """)
        self.zone_combo.currentIndexChanged.connect(self.apply_filters)
        layout.addWidget(self.zone_combo)
        
        # Type filter
        type_label = QLabel("Device Type:")
        type_label.setStyleSheet("color: #888; background: transparent;")
        layout.addWidget(type_label)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["All Types", "Router", "Switch", "Firewall", "Server", 
                                  "Workstation", "Database", "Wireless AP", "IoT"])
        self.type_combo.setStyleSheet("""
            QComboBox {
                background: #16213e;
                color: #fff;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        self.type_combo.currentIndexChanged.connect(self.apply_filters)
        layout.addWidget(self.type_combo)
        
        # Quick filters
        layout.addWidget(QLabel("Quick Filters:"))
        
        self.critical_check = QCheckBox("Critical Assets Only")
        self.critical_check.setStyleSheet("color: #f1c40f; background: transparent;")
        self.critical_check.stateChanged.connect(self.apply_filters)
        layout.addWidget(self.critical_check)
        
        self.compromised_check = QCheckBox("Compromised Hosts")
        self.compromised_check.setStyleSheet("color: #e74c3c; background: transparent;")
        self.compromised_check.stateChanged.connect(self.apply_filters)
        layout.addWidget(self.compromised_check)
        
        # Legend section
        layout.addSpacing(20)
        
        legend_title = QLabel("📋 Legend")
        legend_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        legend_title.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(legend_title)
        
        legend_items = [
            ("🌐 Router", "#e74c3c"),
            ("🔀 Switch", "#3498db"),
            ("🛡️ Firewall", "#e67e22"),
            ("🖥️ Server", "#27ae60"),
            ("💻 Workstation", "#9b59b6"),
            ("💾 Database", "#8e44ad"),
            ("📶 Wireless AP", "#00bcd4"),
            ("📡 IoT Device", "#f1c40f"),
            ("☁️ Cloud/Virtual", "#03a9f4"),
        ]
        
        legend_frame = QFrame()
        legend_frame.setStyleSheet("background: #16213e; border-radius: 8px; padding: 10px;")
        legend_layout = QVBoxLayout(legend_frame)
        legend_layout.setSpacing(5)
        
        for item, color in legend_items:
            row = QHBoxLayout()
            indicator = QLabel("●")
            indicator.setStyleSheet(f"color: {color}; font-size: 16px; background: transparent;")
            row.addWidget(indicator)
            label = QLabel(item)
            label.setStyleSheet("color: #ccc; font-size: 11px; background: transparent;")
            row.addWidget(label)
            row.addStretch()
            legend_layout.addLayout(row)
            
        layout.addWidget(legend_frame)
        
        layout.addStretch()
        
        return frame
        
    def create_center_panel(self) -> QFrame:
        """Create center panel with topology view"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #0a0a15;
                border-radius: 12px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Toolbar
        toolbar = QFrame()
        toolbar.setStyleSheet("""
            QFrame {
                background: #16213e;
                border-radius: 8px;
                margin: 10px;
                padding: 5px;
            }
        """)
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setSpacing(10)
        
        tool_btn_style = """
            QPushButton {
                background: #1a1a2e;
                color: #888;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
                font-size: 11px;
            }
            QPushButton:hover {
                background: #2a2a4e;
                color: #fff;
            }
            QPushButton:checked {
                background: #3498db;
                color: #fff;
            }
        """
        
        self.fit_btn = QPushButton("📐 Fit View")
        self.fit_btn.setStyleSheet(tool_btn_style)
        self.fit_btn.clicked.connect(self.fit_view)
        toolbar_layout.addWidget(self.fit_btn)
        
        self.center_btn = QPushButton("⊙ Center")
        self.center_btn.setStyleSheet(tool_btn_style)
        self.center_btn.clicked.connect(self.center_view)
        toolbar_layout.addWidget(self.center_btn)
        
        toolbar_layout.addStretch()
        
        # Zoom controls
        self.zoom_out_btn = QPushButton("−")
        self.zoom_out_btn.setStyleSheet(tool_btn_style)
        self.zoom_out_btn.clicked.connect(self.zoom_out)
        toolbar_layout.addWidget(self.zoom_out_btn)
        
        self.zoom_slider = QSlider(Qt.Orientation.Horizontal)
        self.zoom_slider.setRange(10, 200)
        self.zoom_slider.setValue(100)
        self.zoom_slider.setFixedWidth(100)
        self.zoom_slider.setStyleSheet("""
            QSlider::groove:horizontal {
                background: #1a1a2e;
                height: 6px;
                border-radius: 3px;
            }
            QSlider::handle:horizontal {
                background: #3498db;
                width: 14px;
                margin: -4px 0;
                border-radius: 7px;
            }
        """)
        self.zoom_slider.valueChanged.connect(self.on_zoom_changed)
        toolbar_layout.addWidget(self.zoom_slider)
        
        self.zoom_in_btn = QPushButton("+")
        self.zoom_in_btn.setStyleSheet(tool_btn_style)
        self.zoom_in_btn.clicked.connect(self.zoom_in)
        toolbar_layout.addWidget(self.zoom_in_btn)
        
        layout.addWidget(toolbar)
        
        # Graphics view
        self.topology_view = TopologyGraphicsView()
        self.topology_view.node_selected.connect(self.on_node_selected)
        self.topology_view.node_double_clicked.connect(self.on_node_double_clicked)
        layout.addWidget(self.topology_view, 1)
        
        return frame
        
    def create_right_panel(self) -> QFrame:
        """Create right panel with details"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-radius: 12px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setSpacing(15)
        
        # Node details
        self.node_details = NodeDetailsPanel()
        layout.addWidget(self.node_details)
        
        # Security findings
        findings_title = QLabel("⚠️ Security Findings")
        findings_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        findings_title.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(findings_title)
        
        self.findings_list = QListWidget()
        self.findings_list.setStyleSheet("""
            QListWidget {
                background: #16213e;
                border: none;
                border-radius: 8px;
                color: #fff;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #333;
            }
            QListWidget::item:hover {
                background: #1a2a4e;
            }
        """)
        layout.addWidget(self.findings_list, 1)
        
        # Subnet info
        subnet_title = QLabel("🌐 Subnets")
        subnet_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        subnet_title.setStyleSheet("color: #fff; background: transparent;")
        layout.addWidget(subnet_title)
        
        self.subnet_list = QListWidget()
        self.subnet_list.setMaximumHeight(150)
        self.subnet_list.setStyleSheet("""
            QListWidget {
                background: #16213e;
                border: none;
                border-radius: 8px;
                color: #fff;
            }
            QListWidget::item {
                padding: 8px;
            }
        """)
        layout.addWidget(self.subnet_list)
        
        return frame
        
    def load_mapper(self):
        """Load the topology mapper"""
        from core.topology_mapper import get_topology_mapper
        self.mapper = get_topology_mapper()
        self.refresh_topology()
        
    def refresh_topology(self):
        """Refresh the topology display"""
        if not self.mapper:
            return
            
        self.topology_data = self.mapper.export_topology()
        self.topology_view.load_topology(self.topology_data)
        
        # Update stats
        stats = self.topology_data.get("stats", {})
        self.stat_cards["Total Nodes"].set_value(str(stats.get("total_nodes", 0)))
        self.stat_cards["Connections"].set_value(str(stats.get("total_edges", 0)))
        self.stat_cards["Subnets"].set_value(str(stats.get("total_subnets", 0)))
        self.stat_cards["Critical Assets"].set_value(str(stats.get("critical_assets", 0)))
        self.stat_cards["Security Zones"].set_value(str(len(stats.get("zones_count", {}))))
        
        # Update findings
        findings = self.mapper.get_security_findings()
        self.stat_cards["Issues Found"].set_value(str(len(findings)))
        
        self.findings_list.clear()
        for finding in findings:
            severity = finding.get("severity", "medium")
            icon = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡"
            item = QListWidgetItem(f"{icon} {finding.get('title', '')}")
            self.findings_list.addItem(item)
            
        # Update subnets
        self.subnet_list.clear()
        for subnet in self.topology_data.get("subnets", []):
            zone_icon = {
                "external": "🌍",
                "dmz": "🛡️",
                "internal": "🏢",
                "management": "⚙️",
                "guest": "👤",
            }.get(subnet.get("zone", ""), "🔲")
            item = QListWidgetItem(f"{zone_icon} {subnet.get('name', '')} ({subnet.get('cidr', '')})")
            self.subnet_list.addItem(item)
            
    def start_discovery(self):
        """Start network discovery"""
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("🔍 Scanning...")
        
        # Simulate discovery
        QTimer.singleShot(2000, self.discovery_complete)
        
    def discovery_complete(self):
        """Handle discovery completion"""
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("🔍 Discover Network")
        self.refresh_topology()
        
    def apply_filters(self):
        """Apply filters to topology view"""
        # In a real implementation, this would filter the displayed nodes
        pass
        
    def on_node_selected(self, node_data: Dict):
        """Handle node selection"""
        # Get connected nodes
        connected = []
        if self.mapper:
            node = self.mapper.get_node_by_id(node_data.get("id", ""))
            if node:
                connected_nodes = self.mapper.get_connected_nodes(node.id)
                connected = [n.name for n in connected_nodes]
                
        self.node_details.show_node(node_data, connected)
        
    def on_node_double_clicked(self, node_data: Dict):
        """Handle node double click - show detailed info"""
        from PyQt6.QtWidgets import QMessageBox
        
        msg = QMessageBox(self)
        msg.setWindowTitle(f"Node: {node_data.get('name', 'Unknown')}")
        msg.setText(f"""
IP Address: {node_data.get('ip', 'N/A')}
Type: {node_data.get('type', 'unknown').title()}
Zone: {node_data.get('zone', 'unknown').title()}
Vendor: {node_data.get('vendor', 'Unknown')}
OS: {node_data.get('os', 'N/A')}
Critical: {'Yes' if node_data.get('is_critical') else 'No'}
        """)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.exec()
        
    def fit_view(self):
        """Fit topology to view"""
        self.topology_view.fitInView(
            self.topology_view.scene.itemsBoundingRect(),
            Qt.AspectRatioMode.KeepAspectRatio
        )
        
    def center_view(self):
        """Center the view"""
        self.topology_view.centerOn(0, 0)
        
    def zoom_in(self):
        """Zoom in"""
        self.topology_view.scale(1.2, 1.2)
        self.zoom_slider.setValue(min(200, self.zoom_slider.value() + 10))
        
    def zoom_out(self):
        """Zoom out"""
        self.topology_view.scale(0.8, 0.8)
        self.zoom_slider.setValue(max(10, self.zoom_slider.value() - 10))
        
    def on_zoom_changed(self, value):
        """Handle zoom slider change"""
        pass  # Handled by wheel events
        
    def export_topology(self):
        """Export topology data"""
        from PyQt6.QtWidgets import QFileDialog, QMessageBox
        import json
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Topology", "", "JSON Files (*.json)"
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(self.topology_data, f, indent=2, default=str)
                
            QMessageBox.information(
                self, "Export Complete",
                f"Topology exported to {filepath}"
            )
