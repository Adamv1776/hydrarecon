"""
Network Mapper Page
GUI for network topology mapping and visualization
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QComboBox, QCheckBox, QProgressBar,
    QSplitter, QFrame, QHeaderView, QSpinBox, QGraphicsView,
    QGraphicsScene, QGraphicsEllipseItem, QGraphicsLineItem,
    QGraphicsTextItem, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QPointF, QRectF
from PyQt6.QtGui import QFont, QColor, QPen, QBrush, QPainter
import asyncio
import math
import random


class NetworkScanWorker(QThread):
    """Worker thread for network scanning"""
    progress = pyqtSignal(str, int)
    host_found = pyqtSignal(dict)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, target_range, options):
        super().__init__()
        self.target_range = target_range
        self.options = options
        
    def run(self):
        try:
            import sys
            sys.path.insert(0, '..')
            from core.network_mapper import NetworkMapper
            
            async def scan():
                mapper = NetworkMapper()
                topology = await mapper.discover_network(
                    self.target_range,
                    scan_type=self.options.get('scan_type', 'ping'),
                    service_detection=self.options.get('service_detection', False)
                )
                return topology
                
            results = asyncio.run(scan())
            self.finished.emit(results)
            
        except Exception as e:
            self.error.emit(str(e))


class NetworkGraphView(QGraphicsView):
    """Interactive network topology visualization"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(QBrush(QColor("#0f0f1a")))
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.nodes = {}
        self.edges = []
        
    def add_node(self, node_id, node_type, label, x=None, y=None):
        """Add a node to the graph"""
        if x is None:
            x = random.randint(50, 700)
        if y is None:
            y = random.randint(50, 500)
            
        # Node colors by type
        colors = {
            'router': '#ff6b6b',
            'switch': '#ffd93d',
            'server': '#00ff88',
            'workstation': '#6bcbff',
            'firewall': '#ff9500',
            'unknown': '#888888'
        }
        
        color = colors.get(node_type, '#888888')
        
        # Create ellipse
        size = 40 if node_type in ['router', 'firewall', 'switch'] else 30
        ellipse = QGraphicsEllipseItem(-size/2, -size/2, size, size)
        ellipse.setBrush(QBrush(QColor(color)))
        ellipse.setPen(QPen(QColor("#ffffff"), 2))
        ellipse.setPos(x, y)
        ellipse.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsMovable)
        ellipse.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsSelectable)
        
        # Add label
        text = QGraphicsTextItem(label)
        text.setDefaultTextColor(QColor("#ffffff"))
        text.setPos(x - len(label) * 3, y + size/2 + 5)
        
        self.scene.addItem(ellipse)
        self.scene.addItem(text)
        
        self.nodes[node_id] = {
            'ellipse': ellipse,
            'text': text,
            'type': node_type,
            'x': x,
            'y': y
        }
        
        return ellipse
        
    def add_edge(self, from_id, to_id, label=""):
        """Add an edge between nodes"""
        if from_id not in self.nodes or to_id not in self.nodes:
            return
            
        from_node = self.nodes[from_id]
        to_node = self.nodes[to_id]
        
        line = QGraphicsLineItem(
            from_node['x'], from_node['y'],
            to_node['x'], to_node['y']
        )
        line.setPen(QPen(QColor("#444444"), 2))
        self.scene.addItem(line)
        self.edges.append(line)
        
    def clear_graph(self):
        """Clear all nodes and edges"""
        self.scene.clear()
        self.nodes = {}
        self.edges = []
        
    def layout_circular(self):
        """Arrange nodes in a circular layout"""
        if not self.nodes:
            return
            
        center_x, center_y = 400, 300
        radius = 200
        
        nodes = list(self.nodes.items())
        for i, (node_id, node_data) in enumerate(nodes):
            angle = 2 * math.pi * i / len(nodes)
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            
            node_data['ellipse'].setPos(x, y)
            node_data['text'].setPos(x - 20, y + 25)
            node_data['x'] = x
            node_data['y'] = y
            
        # Update edges
        for edge in self.edges:
            self.scene.removeItem(edge)
        self.edges = []


class NetworkMapperPage(QWidget):
    """Network Mapper Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Header
        header = QLabel("🌐 Network Topology Mapper")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #6bcbff;
            padding-bottom: 10px;
        """)
        layout.addWidget(header)
        
        # Scan configuration
        config_group = QGroupBox("Network Discovery Configuration")
        config_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #1a1a2e;
            }
            QGroupBox::title {
                color: #6bcbff;
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
        config_layout = QHBoxLayout(config_group)
        
        # Target range
        target_label = QLabel("Target Range:")
        target_label.setStyleSheet("color: #888;")
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.0/24, 10.0.0.0/8")
        self.target_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #16213e;
                color: white;
                min-width: 200px;
            }
        """)
        
        # Scan type
        type_label = QLabel("Scan Type:")
        type_label.setStyleSheet("color: #888;")
        
        self.scan_type = QComboBox()
        self.scan_type.addItems([
            "Ping Sweep", "ARP Scan", "TCP SYN", "Full Discovery"
        ])
        self.scan_type.setStyleSheet("""
            QComboBox {
                padding: 10px;
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #16213e;
                color: white;
                min-width: 120px;
            }
        """)
        
        # Options
        self.service_detect = QCheckBox("Service Detection")
        self.service_detect.setStyleSheet("color: white;")
        
        self.os_detect = QCheckBox("OS Detection")
        self.os_detect.setStyleSheet("color: white;")
        
        # Scan button
        self.scan_btn = QPushButton("🔍 Map Network")
        self.scan_btn.clicked.connect(self._start_scan)
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #6bcbff, #4ba8d8);
                color: white;
                font-weight: bold;
                padding: 12px 25px;
                border-radius: 5px;
                border: none;
            }
            QPushButton:hover {
                background: linear-gradient(135deg, #4ba8d8, #6bcbff);
            }
        """)
        
        config_layout.addWidget(target_label)
        config_layout.addWidget(self.target_input)
        config_layout.addWidget(type_label)
        config_layout.addWidget(self.scan_type)
        config_layout.addWidget(self.service_detect)
        config_layout.addWidget(self.os_detect)
        config_layout.addWidget(self.scan_btn)
        
        layout.addWidget(config_group)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #333;
                border-radius: 5px;
                background-color: #16213e;
                height: 20px;
            }
            QProgressBar::chunk {
                background: linear-gradient(90deg, #6bcbff, #4ba8d8);
            }
        """)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Main content - splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Graph visualization
        graph_widget = QWidget()
        graph_layout = QVBoxLayout(graph_widget)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        
        graph_header = QHBoxLayout()
        graph_label = QLabel("Network Topology")
        graph_label.setStyleSheet("color: #6bcbff; font-weight: bold; font-size: 14px;")
        
        # Graph controls
        layout_btn = QPushButton("⚙️ Circular Layout")
        layout_btn.clicked.connect(self._apply_circular_layout)
        layout_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 5px 10px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        export_btn = QPushButton("💾 Export")
        export_btn.clicked.connect(self._export_topology)
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e;
                color: white;
                padding: 5px 10px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        
        graph_header.addWidget(graph_label)
        graph_header.addStretch()
        graph_header.addWidget(layout_btn)
        graph_header.addWidget(export_btn)
        graph_layout.addLayout(graph_header)
        
        self.graph_view = NetworkGraphView()
        self.graph_view.setMinimumHeight(400)
        graph_layout.addWidget(self.graph_view)
        
        splitter.addWidget(graph_widget)
        
        # Right side - Details
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(0, 0, 0, 0)
        
        # Device tree
        tree_label = QLabel("Discovered Devices")
        tree_label.setStyleSheet("color: #6bcbff; font-weight: bold; font-size: 14px;")
        details_layout.addWidget(tree_label)
        
        self.device_tree = QTreeWidget()
        self.device_tree.setHeaderLabels(["Device", "Type", "Status"])
        self.device_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #16213e;
                color: white;
                border: 1px solid #333;
                border-radius: 5px;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QTreeWidget::item:selected {
                background-color: #0f3460;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #6bcbff;
                padding: 8px;
                border: 1px solid #333;
            }
        """)
        self.device_tree.itemClicked.connect(self._show_device_details)
        details_layout.addWidget(self.device_tree)
        
        # Device details
        details_label = QLabel("Device Details")
        details_label.setStyleSheet("color: #6bcbff; font-weight: bold; font-size: 14px;")
        details_layout.addWidget(details_label)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
        self.details_text.setStyleSheet("""
            QTextEdit {
                background-color: #16213e;
                color: white;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        details_layout.addWidget(self.details_text)
        
        splitter.addWidget(details_widget)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        # Statistics bar
        stats_row = QHBoxLayout()
        
        self.status_label = QLabel("Ready to scan")
        self.status_label.setStyleSheet("color: #888;")
        
        self.hosts_count = QLabel("Hosts: 0")
        self.hosts_count.setStyleSheet("color: #00ff88;")
        
        self.routers_count = QLabel("Routers: 0")
        self.routers_count.setStyleSheet("color: #ff6b6b;")
        
        self.services_count = QLabel("Services: 0")
        self.services_count.setStyleSheet("color: #ffd93d;")
        
        stats_row.addWidget(self.status_label)
        stats_row.addStretch()
        stats_row.addWidget(self.hosts_count)
        stats_row.addWidget(self.routers_count)
        stats_row.addWidget(self.services_count)
        
        layout.addLayout(stats_row)
        
        # Store topology data
        self.topology_data = None
        
    def _start_scan(self):
        """Start network discovery scan"""
        target = self.target_input.text().strip()
        
        if not target:
            self.status_label.setText("❌ Please enter a target range")
            return
            
        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_label.setText(f"Scanning {target}...")
        
        # Clear previous results
        self.graph_view.clear_graph()
        self.device_tree.clear()
        
        options = {
            'scan_type': self.scan_type.currentText().lower().replace(' ', '_'),
            'service_detection': self.service_detect.isChecked(),
            'os_detection': self.os_detect.isChecked()
        }
        
        self.worker = NetworkScanWorker(target, options)
        self.worker.progress.connect(lambda msg, pct: self.status_label.setText(msg))
        self.worker.host_found.connect(self._add_host)
        self.worker.finished.connect(self._on_scan_complete)
        self.worker.error.connect(self._on_scan_error)
        self.worker.start()
        
    def _add_host(self, host_data):
        """Add discovered host to visualization"""
        ip = host_data.get('ip', 'Unknown')
        host_type = host_data.get('type', 'unknown')
        
        # Add to graph
        self.graph_view.add_node(ip, host_type, ip)
        
        # Add to tree
        item = QTreeWidgetItem([ip, host_type, '🟢 Up'])
        self.device_tree.addTopLevelItem(item)
        
    def _on_scan_complete(self, topology):
        """Handle scan completion"""
        self.progress_bar.setVisible(False)
        self.scan_btn.setEnabled(True)
        self.topology_data = topology
        
        # Update statistics
        hosts = getattr(topology, 'hosts', []) if topology else []
        routers = [h for h in hosts if h.get('type') == 'router']
        services = sum(len(h.get('services', [])) for h in hosts)
        
        self.hosts_count.setText(f"Hosts: {len(hosts)}")
        self.routers_count.setText(f"Routers: {len(routers)}")
        self.services_count.setText(f"Services: {services}")
        
        self.status_label.setText(f"✅ Scan complete - Found {len(hosts)} hosts")
        
        # Apply layout
        self._apply_circular_layout()
        
    def _on_scan_error(self, error):
        """Handle scan error"""
        self.progress_bar.setVisible(False)
        self.scan_btn.setEnabled(True)
        self.status_label.setText(f"❌ Error: {error}")
        
    def _show_device_details(self, item):
        """Show details for selected device"""
        ip = item.text(0)
        
        if not self.topology_data:
            return
            
        hosts = getattr(self.topology_data, 'hosts', [])
        host = next((h for h in hosts if h.get('ip') == ip), None)
        
        if host:
            details = f"""
<h3 style="color: #6bcbff;">{ip}</h3>
<p><b>Type:</b> {host.get('type', 'Unknown')}</p>
<p><b>MAC:</b> {host.get('mac', 'Unknown')}</p>
<p><b>Hostname:</b> {host.get('hostname', 'Unknown')}</p>
<p><b>OS:</b> {host.get('os', 'Unknown')}</p>

<h4>Open Ports:</h4>
<p>{', '.join(str(p) for p in host.get('ports', [])) or 'None detected'}</p>

<h4>Services:</h4>
<ul>
{''.join(f'<li>{s}</li>' for s in host.get('services', [])) or '<li>None detected</li>'}
</ul>
"""
            self.details_text.setHtml(details)
            
    def _apply_circular_layout(self):
        """Apply circular layout to graph"""
        self.graph_view.layout_circular()
        
    def _export_topology(self):
        """Export topology data"""
        from PyQt6.QtWidgets import QFileDialog
        import json
        
        if not self.topology_data:
            self.status_label.setText("❌ No topology data to export")
            return
            
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Export Topology",
            "network_topology.json",
            "JSON Files (*.json)"
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(self.topology_data.__dict__ if hasattr(self.topology_data, '__dict__') else {}, f, indent=2, default=str)
                
            self.status_label.setText(f"✅ Exported to {filepath}")
