"""
Network Pivoting Page
Multi-hop tunneling and lateral movement interface
"""

import asyncio
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QComboBox,
    QSpinBox, QGroupBox, QTextEdit, QLineEdit, QProgressBar,
    QSplitter, QFrame, QHeaderView, QCheckBox, QMessageBox,
    QFileDialog, QListWidget, QListWidgetItem, QFormLayout,
    QPlainTextEdit, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QColor, QFont

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.network_pivoting import (
    NetworkPivotingModule, TunnelType, PivotStatus, PivotHost
)


class PivotWorker(QThread):
    """Background worker for pivot operations"""
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, operation, *args, **kwargs):
        super().__init__()
        self.operation = operation
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.operation(*self.args, **self.kwargs))
            self.result_ready.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class NetworkPivotingPage(QWidget):
    """Network Pivoting GUI Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pivot_module = NetworkPivotingModule()
        self.selected_pivot = None
        self.workers = []
        
        self.setup_ui()
        
        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_pivot_status)
        self.status_timer.start(5000)
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("🕸️ Network Pivoting Framework")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #9d4edd;
            padding: 10px;
        """)
        layout.addWidget(header)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Network topology
        left_panel = self.create_topology_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Tabs
        right_panel = QTabWidget()
        right_panel.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #333;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #888;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #9d4edd;
                color: #fff;
            }
        """)
        
        right_panel.addTab(self.create_pivots_tab(), "🎯 Pivots")
        right_panel.addTab(self.create_tunnels_tab(), "🔗 Tunnels")
        right_panel.addTab(self.create_forwards_tab(), "➡️ Port Forwards")
        right_panel.addTab(self.create_proxies_tab(), "🧦 SOCKS Proxies")
        right_panel.addTab(self.create_lateral_tab(), "🦀 Lateral Movement")
        right_panel.addTab(self.create_config_tab(), "⚙️ Configuration")
        
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 800])
        
        layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = QLabel("Ready - Add pivots to build tunnel network")
        self.status_bar.setStyleSheet("""
            background: #1a1a2e;
            padding: 8px;
            border-radius: 4px;
            color: #00ff88;
        """)
        layout.addWidget(self.status_bar)
    
    def create_topology_panel(self) -> QWidget:
        """Create network topology panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Header
        header = QLabel("🗺️ Network Topology")
        header.setStyleSheet("""
            font-size: 16px;
            font-weight: bold;
            color: #9d4edd;
            padding: 5px;
        """)
        layout.addWidget(header)
        
        # Topology tree
        self.topology_tree = QTreeWidget()
        self.topology_tree.setHeaderLabels(["Host", "Status", "Hop"])
        self.topology_tree.setColumnWidth(0, 200)
        self.topology_tree.itemClicked.connect(self.on_pivot_selected)
        self.topology_tree.setStyleSheet("""
            QTreeWidget {
                background: #0d0d1a;
                border: 1px solid #333;
                border-radius: 4px;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QTreeWidget::item:selected {
                background: #9d4edd;
                color: #fff;
            }
        """)
        layout.addWidget(self.topology_tree)
        
        # Statistics
        stats_group = QGroupBox("Network Statistics")
        stats_layout = QFormLayout(stats_group)
        
        self.stat_pivots = QLabel("0")
        stats_layout.addRow("Active Pivots:", self.stat_pivots)
        
        self.stat_networks = QLabel("0")
        stats_layout.addRow("Discovered Networks:", self.stat_networks)
        
        self.stat_hosts = QLabel("0")
        stats_layout.addRow("Discovered Hosts:", self.stat_hosts)
        
        self.stat_tunnels = QLabel("0")
        stats_layout.addRow("Active Tunnels:", self.stat_tunnels)
        
        layout.addWidget(stats_group)
        
        # Quick actions
        actions_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_topology)
        actions_layout.addWidget(refresh_btn)
        
        scan_btn = QPushButton("🔍 Scan Networks")
        scan_btn.clicked.connect(self.scan_networks)
        actions_layout.addWidget(scan_btn)
        
        layout.addLayout(actions_layout)
        
        return panel
    
    def create_pivots_tab(self) -> QWidget:
        """Create pivots management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Add pivot
        add_group = QGroupBox("Add New Pivot Point")
        add_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #9d4edd;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title { color: #9d4edd; }
        """)
        add_layout = QFormLayout(add_group)
        
        self.pivot_ip = QLineEdit()
        self.pivot_ip.setPlaceholderText("192.168.1.100")
        add_layout.addRow("Target IP:", self.pivot_ip)
        
        self.pivot_user = QLineEdit()
        self.pivot_user.setPlaceholderText("root")
        add_layout.addRow("Username:", self.pivot_user)
        
        self.pivot_port = QSpinBox()
        self.pivot_port.setRange(1, 65535)
        self.pivot_port.setValue(22)
        add_layout.addRow("Remote Port:", self.pivot_port)
        
        self.pivot_tunnel_type = QComboBox()
        for tt in TunnelType:
            self.pivot_tunnel_type.addItem(tt.value.replace('_', ' ').title(), tt)
        add_layout.addRow("Tunnel Type:", self.pivot_tunnel_type)
        
        # Auth options
        auth_layout = QHBoxLayout()
        self.auth_password = QLineEdit()
        self.auth_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.auth_password.setPlaceholderText("Password")
        auth_layout.addWidget(self.auth_password)
        
        self.auth_key = QLineEdit()
        self.auth_key.setPlaceholderText("SSH Key Path")
        auth_layout.addWidget(self.auth_key)
        
        browse_key_btn = QPushButton("📂")
        browse_key_btn.clicked.connect(self.browse_ssh_key)
        auth_layout.addWidget(browse_key_btn)
        
        add_layout.addRow("Authentication:", auth_layout)
        
        # Parent pivot
        self.parent_pivot = QComboBox()
        self.parent_pivot.addItem("None (Direct)", None)
        add_layout.addRow("Parent Pivot:", self.parent_pivot)
        
        add_btn = QPushButton("➕ Add Pivot")
        add_btn.clicked.connect(self.add_pivot)
        add_btn.setStyleSheet("background: #9d4edd; color: white; padding: 10px;")
        add_layout.addRow("", add_btn)
        
        layout.addWidget(add_group)
        
        # Pivots table
        pivots_group = QGroupBox("Active Pivot Points")
        pivots_layout = QVBoxLayout(pivots_group)
        
        self.pivots_table = QTableWidget()
        self.pivots_table.setColumnCount(7)
        self.pivots_table.setHorizontalHeaderLabels([
            "ID", "IP Address", "Type", "Status", "Local Port", "Hop", "Networks"
        ])
        self.pivots_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.pivots_table.itemSelectionChanged.connect(self.on_table_pivot_selected)
        pivots_layout.addWidget(self.pivots_table)
        
        # Pivot actions
        pivot_actions = QHBoxLayout()
        
        connect_btn = QPushButton("🔌 Connect")
        connect_btn.clicked.connect(self.connect_pivot)
        pivot_actions.addWidget(connect_btn)
        
        disconnect_btn = QPushButton("❌ Disconnect")
        disconnect_btn.clicked.connect(self.disconnect_pivot)
        pivot_actions.addWidget(disconnect_btn)
        
        remove_btn = QPushButton("🗑️ Remove")
        remove_btn.clicked.connect(self.remove_pivot)
        pivot_actions.addWidget(remove_btn)
        
        pivot_actions.addStretch()
        pivots_layout.addLayout(pivot_actions)
        
        layout.addWidget(pivots_group)
        
        return widget
    
    def create_tunnels_tab(self) -> QWidget:
        """Create tunnels tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Active tunnels
        tunnels_group = QGroupBox("Active Tunnels")
        tunnels_layout = QVBoxLayout(tunnels_group)
        
        self.tunnels_table = QTableWidget()
        self.tunnels_table.setColumnCount(5)
        self.tunnels_table.setHorizontalHeaderLabels([
            "Pivot", "Type", "Local Port", "Remote", "Started"
        ])
        self.tunnels_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tunnels_layout.addWidget(self.tunnels_table)
        
        layout.addWidget(tunnels_group)
        
        # Routes
        routes_group = QGroupBox("Network Routes")
        routes_layout = QVBoxLayout(routes_group)
        
        route_form = QFormLayout()
        
        self.route_dest = QLineEdit()
        self.route_dest.setPlaceholderText("10.10.10.100")
        route_form.addRow("Destination:", self.route_dest)
        
        self.route_port = QSpinBox()
        self.route_port.setRange(1, 65535)
        self.route_port.setValue(80)
        route_form.addRow("Port:", self.route_port)
        
        self.route_pivots = QLineEdit()
        self.route_pivots.setPlaceholderText("pivot1,pivot2 (comma separated)")
        route_form.addRow("Pivot Chain:", self.route_pivots)
        
        routes_layout.addLayout(route_form)
        
        create_route_btn = QPushButton("🔀 Create Route")
        create_route_btn.clicked.connect(self.create_route)
        routes_layout.addWidget(create_route_btn)
        
        self.routes_table = QTableWidget()
        self.routes_table.setColumnCount(5)
        self.routes_table.setHorizontalHeaderLabels([
            "Destination", "Port", "Chain", "Local Port", "Status"
        ])
        self.routes_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        routes_layout.addWidget(self.routes_table)
        
        layout.addWidget(routes_group)
        
        return widget
    
    def create_forwards_tab(self) -> QWidget:
        """Create port forwards tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Add forward
        add_group = QGroupBox("Create Port Forward")
        add_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #00d4ff;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title { color: #00d4ff; }
        """)
        add_layout = QFormLayout(add_group)
        
        self.forward_direction = QComboBox()
        self.forward_direction.addItems(["Local (-L)", "Remote (-R)"])
        add_layout.addRow("Direction:", self.forward_direction)
        
        self.forward_pivot = QComboBox()
        add_layout.addRow("Through Pivot:", self.forward_pivot)
        
        local_layout = QHBoxLayout()
        self.forward_local_host = QLineEdit()
        self.forward_local_host.setText("127.0.0.1")
        local_layout.addWidget(self.forward_local_host)
        local_layout.addWidget(QLabel(":"))
        self.forward_local_port = QSpinBox()
        self.forward_local_port.setRange(1, 65535)
        self.forward_local_port.setValue(8080)
        local_layout.addWidget(self.forward_local_port)
        add_layout.addRow("Local:", local_layout)
        
        remote_layout = QHBoxLayout()
        self.forward_remote_host = QLineEdit()
        self.forward_remote_host.setPlaceholderText("10.10.10.100")
        remote_layout.addWidget(self.forward_remote_host)
        remote_layout.addWidget(QLabel(":"))
        self.forward_remote_port = QSpinBox()
        self.forward_remote_port.setRange(1, 65535)
        self.forward_remote_port.setValue(80)
        remote_layout.addWidget(self.forward_remote_port)
        add_layout.addRow("Remote:", remote_layout)
        
        create_forward_btn = QPushButton("➕ Create Port Forward")
        create_forward_btn.clicked.connect(self.create_port_forward)
        add_layout.addRow("", create_forward_btn)
        
        layout.addWidget(add_group)
        
        # Forwards table
        forwards_group = QGroupBox("Active Port Forwards")
        forwards_layout = QVBoxLayout(forwards_group)
        
        self.forwards_table = QTableWidget()
        self.forwards_table.setColumnCount(6)
        self.forwards_table.setHorizontalHeaderLabels([
            "Direction", "Local", "Remote", "Pivot", "Status", "Actions"
        ])
        self.forwards_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        forwards_layout.addWidget(self.forwards_table)
        
        layout.addWidget(forwards_group)
        
        return widget
    
    def create_proxies_tab(self) -> QWidget:
        """Create SOCKS proxies tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Proxies list
        proxies_group = QGroupBox("Active SOCKS Proxies")
        proxies_layout = QVBoxLayout(proxies_group)
        
        self.proxies_table = QTableWidget()
        self.proxies_table.setColumnCount(5)
        self.proxies_table.setHorizontalHeaderLabels([
            "Type", "Address", "Pivot", "Status", "Usage"
        ])
        self.proxies_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        proxies_layout.addWidget(self.proxies_table)
        
        layout.addWidget(proxies_group)
        
        # Proxy chain builder
        chain_group = QGroupBox("Proxy Chain Builder")
        chain_layout = QVBoxLayout(chain_group)
        
        chain_layout.addWidget(QLabel("Select proxies in order to build chain:"))
        
        self.proxy_chain_list = QListWidget()
        self.proxy_chain_list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        chain_layout.addWidget(self.proxy_chain_list)
        
        chain_buttons = QHBoxLayout()
        
        add_to_chain_btn = QPushButton("➕ Add Selected")
        add_to_chain_btn.clicked.connect(self.add_to_proxy_chain)
        chain_buttons.addWidget(add_to_chain_btn)
        
        clear_chain_btn = QPushButton("🗑️ Clear Chain")
        clear_chain_btn.clicked.connect(lambda: self.proxy_chain_list.clear())
        chain_buttons.addWidget(clear_chain_btn)
        
        generate_config_btn = QPushButton("📄 Generate ProxyChains Config")
        generate_config_btn.clicked.connect(self.generate_proxychains_config)
        chain_buttons.addWidget(generate_config_btn)
        
        chain_buttons.addStretch()
        chain_layout.addLayout(chain_buttons)
        
        layout.addWidget(chain_group)
        
        # Usage info
        usage_group = QGroupBox("Proxy Usage")
        usage_layout = QVBoxLayout(usage_group)
        
        usage_text = QLabel("""
        <b>Using SOCKS Proxies:</b><br><br>
        <b>Proxychains:</b> proxychains nmap -sT 10.10.10.0/24<br>
        <b>Curl:</b> curl --socks5 127.0.0.1:PORT http://target<br>
        <b>Firefox:</b> Settings → Network → Manual Proxy → SOCKS Host<br>
        <b>SSH:</b> ssh -o ProxyCommand='nc -x 127.0.0.1:PORT %h %p' user@target<br>
        <b>Nmap:</b> nmap --proxies socks5://127.0.0.1:PORT target
        """)
        usage_layout.addWidget(usage_text)
        
        layout.addWidget(usage_group)
        
        return widget
    
    def create_lateral_tab(self) -> QWidget:
        """Create lateral movement tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Lateral move
        lateral_group = QGroupBox("Lateral Movement")
        lateral_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ff6b00;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title { color: #ff6b00; }
        """)
        lateral_layout = QFormLayout(lateral_group)
        
        self.lateral_source = QComboBox()
        lateral_layout.addRow("Source Pivot:", self.lateral_source)
        
        self.lateral_target = QLineEdit()
        self.lateral_target.setPlaceholderText("10.10.10.200")
        lateral_layout.addRow("Target IP:", self.lateral_target)
        
        self.lateral_user = QLineEdit()
        self.lateral_user.setPlaceholderText("administrator")
        lateral_layout.addRow("Username:", self.lateral_user)
        
        self.lateral_cred_type = QComboBox()
        self.lateral_cred_type.addItems(["Password", "SSH Key", "Hash (PTH)", "Ticket (PTT)"])
        lateral_layout.addRow("Credential Type:", self.lateral_cred_type)
        
        self.lateral_credential = QLineEdit()
        self.lateral_credential.setPlaceholderText("Credential value")
        lateral_layout.addRow("Credential:", self.lateral_credential)
        
        lateral_btn = QPushButton("🦀 Perform Lateral Movement")
        lateral_btn.clicked.connect(self.perform_lateral_move)
        lateral_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #ff6b00, #ff4444);
                color: white;
                font-weight: bold;
                padding: 10px;
            }
        """)
        lateral_layout.addRow("", lateral_btn)
        
        layout.addWidget(lateral_group)
        
        # Command execution
        exec_group = QGroupBox("Remote Command Execution")
        exec_layout = QVBoxLayout(exec_group)
        
        exec_form = QFormLayout()
        self.exec_pivot = QComboBox()
        exec_form.addRow("Execute On:", self.exec_pivot)
        exec_layout.addLayout(exec_form)
        
        self.exec_command = QPlainTextEdit()
        self.exec_command.setPlaceholderText("whoami && hostname && ip addr")
        self.exec_command.setMaximumHeight(100)
        exec_layout.addWidget(self.exec_command)
        
        exec_btn = QPushButton("▶️ Execute Command")
        exec_btn.clicked.connect(self.execute_command)
        exec_layout.addWidget(exec_btn)
        
        self.exec_output = QPlainTextEdit()
        self.exec_output.setReadOnly(True)
        self.exec_output.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ff88;
            }
        """)
        exec_layout.addWidget(self.exec_output)
        
        layout.addWidget(exec_group)
        
        return widget
    
    def create_config_tab(self) -> QWidget:
        """Create configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # ProxyChains config
        proxychains_group = QGroupBox("ProxyChains Configuration")
        proxychains_layout = QVBoxLayout(proxychains_group)
        
        self.proxychains_config = QPlainTextEdit()
        self.proxychains_config.setReadOnly(True)
        self.proxychains_config.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #ffaa00;
            }
        """)
        proxychains_layout.addWidget(self.proxychains_config)
        
        proxychains_buttons = QHBoxLayout()
        
        gen_proxychains_btn = QPushButton("🔄 Generate")
        gen_proxychains_btn.clicked.connect(self.generate_proxychains_config)
        proxychains_buttons.addWidget(gen_proxychains_btn)
        
        save_proxychains_btn = QPushButton("💾 Save to File")
        save_proxychains_btn.clicked.connect(self.save_proxychains_config)
        proxychains_buttons.addWidget(save_proxychains_btn)
        
        proxychains_buttons.addStretch()
        proxychains_layout.addLayout(proxychains_buttons)
        
        layout.addWidget(proxychains_group)
        
        # SSH config
        ssh_group = QGroupBox("SSH Configuration")
        ssh_layout = QVBoxLayout(ssh_group)
        
        self.ssh_config = QPlainTextEdit()
        self.ssh_config.setReadOnly(True)
        self.ssh_config.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00d4ff;
            }
        """)
        ssh_layout.addWidget(self.ssh_config)
        
        ssh_buttons = QHBoxLayout()
        
        gen_ssh_btn = QPushButton("🔄 Generate")
        gen_ssh_btn.clicked.connect(self.generate_ssh_config)
        ssh_buttons.addWidget(gen_ssh_btn)
        
        save_ssh_btn = QPushButton("💾 Save to File")
        save_ssh_btn.clicked.connect(self.save_ssh_config)
        ssh_buttons.addWidget(save_ssh_btn)
        
        ssh_buttons.addStretch()
        ssh_layout.addLayout(ssh_buttons)
        
        layout.addWidget(ssh_group)
        
        return widget
    
    def browse_ssh_key(self):
        """Browse for SSH key file"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select SSH Key", os.path.expanduser("~/.ssh"),
            "All Files (*)"
        )
        if filepath:
            self.auth_key.setText(filepath)
    
    def add_pivot(self):
        """Add a new pivot point"""
        ip = self.pivot_ip.text().strip()
        user = self.pivot_user.text().strip()
        
        if not ip or not user:
            QMessageBox.warning(self, "Error", "Enter IP and username")
            return
        
        tunnel_type = self.pivot_tunnel_type.currentData()
        parent_id = self.parent_pivot.currentData()
        
        async def do_add():
            return await self.pivot_module.add_pivot(
                ip_address=ip,
                username=user,
                password=self.auth_password.text(),
                ssh_key=self.auth_key.text(),
                tunnel_type=tunnel_type,
                remote_port=self.pivot_port.value(),
                parent_pivot_id=parent_id
            )
        
        worker = PivotWorker(do_add)
        worker.result_ready.connect(self.on_pivot_added)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def on_pivot_added(self, pivot: PivotHost):
        """Handle pivot added"""
        # Add to table
        row = self.pivots_table.rowCount()
        self.pivots_table.insertRow(row)
        self.pivots_table.setItem(row, 0, QTableWidgetItem(pivot.host_id[:8]))
        self.pivots_table.setItem(row, 1, QTableWidgetItem(pivot.ip_address))
        self.pivots_table.setItem(row, 2, QTableWidgetItem(pivot.tunnel_type.value))
        self.pivots_table.setItem(row, 3, QTableWidgetItem(pivot.status.value))
        self.pivots_table.setItem(row, 4, QTableWidgetItem(str(pivot.local_port)))
        self.pivots_table.setItem(row, 5, QTableWidgetItem(str(pivot.hop_count)))
        self.pivots_table.setItem(row, 6, QTableWidgetItem(','.join(pivot.accessible_networks)))
        
        # Store full ID
        self.pivots_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, pivot.host_id)
        
        # Update parent pivot dropdowns
        self.update_pivot_dropdowns()
        self.refresh_topology()
        
        self.status_bar.setText(f"Added pivot: {pivot.ip_address}")
        
        # Clear inputs
        self.pivot_ip.clear()
        self.auth_password.clear()
    
    def connect_pivot(self):
        """Connect to selected pivot"""
        row = self.pivots_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Error", "Select a pivot first")
            return
        
        pivot_id = self.pivots_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        
        async def do_connect():
            return await self.pivot_module.connect_pivot(pivot_id)
        
        worker = PivotWorker(do_connect)
        worker.result_ready.connect(lambda r: self.on_pivot_connected(pivot_id, r))
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
        
        self.status_bar.setText(f"Connecting to pivot...")
    
    def on_pivot_connected(self, pivot_id: str, success: bool):
        """Handle pivot connection result"""
        if success:
            self.status_bar.setText("Pivot connected successfully")
            self.refresh_tables()
            self.refresh_topology()
        else:
            self.status_bar.setText("Failed to connect pivot")
    
    def disconnect_pivot(self):
        """Disconnect selected pivot"""
        row = self.pivots_table.currentRow()
        if row < 0:
            return
        
        pivot_id = self.pivots_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        self.pivot_module.disconnect_pivot(pivot_id)
        
        self.refresh_tables()
        self.refresh_topology()
        self.status_bar.setText("Pivot disconnected")
    
    def remove_pivot(self):
        """Remove selected pivot"""
        row = self.pivots_table.currentRow()
        if row < 0:
            return
        
        pivot_id = self.pivots_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        
        # Disconnect first
        self.pivot_module.disconnect_pivot(pivot_id)
        
        # Remove from module
        if pivot_id in self.pivot_module.pivots:
            del self.pivot_module.pivots[pivot_id]
        
        self.pivots_table.removeRow(row)
        self.update_pivot_dropdowns()
        self.refresh_topology()
        
        self.status_bar.setText("Pivot removed")
    
    def update_pivot_dropdowns(self):
        """Update pivot selection dropdowns"""
        pivots = [(p.host_id, f"{p.ip_address} (hop {p.hop_count})") 
                  for p in self.pivot_module.pivots.values()]
        
        # Parent pivot dropdown
        self.parent_pivot.clear()
        self.parent_pivot.addItem("None (Direct)", None)
        for pid, label in pivots:
            self.parent_pivot.addItem(label, pid)
        
        # Forward pivot dropdown
        self.forward_pivot.clear()
        for pid, label in pivots:
            self.forward_pivot.addItem(label, pid)
        
        # Lateral source dropdown
        self.lateral_source.clear()
        for pid, label in pivots:
            self.lateral_source.addItem(label, pid)
        
        # Exec pivot dropdown
        self.exec_pivot.clear()
        for pid, label in pivots:
            self.exec_pivot.addItem(label, pid)
    
    def refresh_tables(self):
        """Refresh all tables"""
        # Pivots table
        self.pivots_table.setRowCount(0)
        for pivot in self.pivot_module.pivots.values():
            row = self.pivots_table.rowCount()
            self.pivots_table.insertRow(row)
            self.pivots_table.setItem(row, 0, QTableWidgetItem(pivot.host_id[:8]))
            self.pivots_table.setItem(row, 1, QTableWidgetItem(pivot.ip_address))
            self.pivots_table.setItem(row, 2, QTableWidgetItem(pivot.tunnel_type.value))
            
            status_item = QTableWidgetItem(pivot.status.value)
            if pivot.status == PivotStatus.ACTIVE:
                status_item.setForeground(QColor(0, 255, 136))
            elif pivot.status == PivotStatus.ERROR:
                status_item.setForeground(QColor(255, 68, 68))
            self.pivots_table.setItem(row, 3, status_item)
            
            self.pivots_table.setItem(row, 4, QTableWidgetItem(str(pivot.local_port)))
            self.pivots_table.setItem(row, 5, QTableWidgetItem(str(pivot.hop_count)))
            self.pivots_table.setItem(row, 6, QTableWidgetItem(','.join(pivot.accessible_networks)))
            
            self.pivots_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, pivot.host_id)
        
        # Tunnels table
        self.tunnels_table.setRowCount(0)
        for tid, tunnel in self.pivot_module.active_tunnels.items():
            pivot = self.pivot_module.pivots.get(tid)
            if pivot:
                row = self.tunnels_table.rowCount()
                self.tunnels_table.insertRow(row)
                self.tunnels_table.setItem(row, 0, QTableWidgetItem(pivot.ip_address))
                self.tunnels_table.setItem(row, 1, QTableWidgetItem(tunnel.get('type', '')))
                self.tunnels_table.setItem(row, 2, QTableWidgetItem(str(tunnel.get('local_port', ''))))
                self.tunnels_table.setItem(row, 3, QTableWidgetItem(tunnel.get('remote', '')))
                self.tunnels_table.setItem(row, 4, QTableWidgetItem(tunnel.get('started', '')[:19]))
        
        # Proxies table
        self.proxies_table.setRowCount(0)
        for proxy in self.pivot_module.socks_proxies.values():
            pivot = self.pivot_module.pivots.get(proxy.pivot_id)
            row = self.proxies_table.rowCount()
            self.proxies_table.insertRow(row)
            self.proxies_table.setItem(row, 0, QTableWidgetItem(proxy.proxy_type.upper()))
            self.proxies_table.setItem(row, 1, QTableWidgetItem(f"{proxy.bind_address}:{proxy.bind_port}"))
            self.proxies_table.setItem(row, 2, QTableWidgetItem(pivot.ip_address if pivot else ''))
            self.proxies_table.setItem(row, 3, QTableWidgetItem("Active" if proxy.is_active else "Inactive"))
            self.proxies_table.setItem(row, 4, QTableWidgetItem(""))
        
        # Forwards table
        self.forwards_table.setRowCount(0)
        for forward in self.pivot_module.port_forwards.values():
            pivot = self.pivot_module.pivots.get(forward.pivot_id)
            row = self.forwards_table.rowCount()
            self.forwards_table.insertRow(row)
            self.forwards_table.setItem(row, 0, QTableWidgetItem(forward.direction.upper()))
            self.forwards_table.setItem(row, 1, QTableWidgetItem(f"{forward.local_host}:{forward.local_port}"))
            self.forwards_table.setItem(row, 2, QTableWidgetItem(f"{forward.remote_host}:{forward.remote_port}"))
            self.forwards_table.setItem(row, 3, QTableWidgetItem(pivot.ip_address if pivot else ''))
            self.forwards_table.setItem(row, 4, QTableWidgetItem("Active" if forward.is_active else "Inactive"))
    
    def refresh_topology(self):
        """Refresh network topology tree"""
        self.topology_tree.clear()
        
        topology = self.pivot_module.get_network_topology()
        
        # Build tree from topology
        root_items = {}
        for node in topology['nodes']:
            item = QTreeWidgetItem([
                f"{node['ip']} ({node.get('hostname', '')})",
                node['status'],
                str(node['hop_count'])
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, node['id'])
            
            # Color based on status
            if node['status'] == 'active':
                item.setForeground(1, QColor(0, 255, 136))
            else:
                item.setForeground(1, QColor(136, 136, 136))
            
            root_items[node['id']] = item
        
        # Build hierarchy
        for edge in topology['edges']:
            source = root_items.get(edge['source'])
            target = root_items.get(edge['target'])
            if source and target:
                source.addChild(target)
                if edge['target'] in root_items:
                    del root_items[edge['target']]
        
        # Add remaining items as roots
        for item in root_items.values():
            self.topology_tree.addTopLevelItem(item)
        
        self.topology_tree.expandAll()
        
        # Update stats
        active_pivots = sum(1 for p in self.pivot_module.pivots.values() 
                          if p.status == PivotStatus.ACTIVE)
        self.stat_pivots.setText(str(active_pivots))
        self.stat_networks.setText(str(len(self.pivot_module.network_map)))
        
        total_hosts = sum(len(p.discovered_hosts) for p in self.pivot_module.pivots.values())
        self.stat_hosts.setText(str(total_hosts))
        self.stat_tunnels.setText(str(len(self.pivot_module.active_tunnels)))
    
    def on_pivot_selected(self, item: QTreeWidgetItem, column: int):
        """Handle pivot selection in topology tree"""
        pivot_id = item.data(0, Qt.ItemDataRole.UserRole)
        if pivot_id and pivot_id in self.pivot_module.pivots:
            self.selected_pivot = self.pivot_module.pivots[pivot_id]
    
    def on_table_pivot_selected(self):
        """Handle pivot selection in table"""
        row = self.pivots_table.currentRow()
        if row >= 0:
            pivot_id = self.pivots_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            if pivot_id in self.pivot_module.pivots:
                self.selected_pivot = self.pivot_module.pivots[pivot_id]
    
    def create_port_forward(self):
        """Create port forward"""
        pivot_id = self.forward_pivot.currentData()
        if not pivot_id:
            QMessageBox.warning(self, "Error", "Select a pivot")
            return
        
        direction = "local" if self.forward_direction.currentIndex() == 0 else "remote"
        
        async def do_forward():
            return await self.pivot_module.create_port_forward(
                pivot_id=pivot_id,
                direction=direction,
                local_host=self.forward_local_host.text(),
                local_port=self.forward_local_port.value(),
                remote_host=self.forward_remote_host.text(),
                remote_port=self.forward_remote_port.value()
            )
        
        worker = PivotWorker(do_forward)
        worker.result_ready.connect(lambda r: self.on_forward_created(r))
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def on_forward_created(self, forward):
        """Handle forward created"""
        self.refresh_tables()
        self.status_bar.setText(f"Port forward created: {forward.local_port} -> {forward.remote_host}:{forward.remote_port}")
    
    def create_route(self):
        """Create network route"""
        dest = self.route_dest.text().strip()
        if not dest:
            return
        
        pivot_chain = [p.strip() for p in self.route_pivots.text().split(',') if p.strip()]
        
        async def do_route():
            return await self.pivot_module.create_route(
                destination=dest,
                destination_port=self.route_port.value(),
                pivot_chain=pivot_chain
            )
        
        worker = PivotWorker(do_route)
        worker.result_ready.connect(lambda r: self.status_bar.setText(f"Route created to {dest}"))
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def perform_lateral_move(self):
        """Perform lateral movement"""
        source_id = self.lateral_source.currentData()
        target = self.lateral_target.text().strip()
        user = self.lateral_user.text().strip()
        cred = self.lateral_credential.text()
        cred_type = "password" if self.lateral_cred_type.currentIndex() == 0 else "key"
        
        if not source_id or not target or not user:
            QMessageBox.warning(self, "Error", "Fill all fields")
            return
        
        async def do_lateral():
            return await self.pivot_module.lateral_move(
                source_pivot_id=source_id,
                target_ip=target,
                username=user,
                credential_type=cred_type,
                credential=cred
            )
        
        worker = PivotWorker(do_lateral)
        worker.result_ready.connect(self.on_lateral_complete)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
        
        self.status_bar.setText("Attempting lateral movement...")
    
    def on_lateral_complete(self, pivot):
        """Handle lateral movement result"""
        if pivot:
            self.status_bar.setText(f"Lateral movement successful: {pivot.ip_address}")
            self.on_pivot_added(pivot)
        else:
            self.status_bar.setText("Lateral movement failed")
    
    def execute_command(self):
        """Execute command through pivot"""
        pivot_id = self.exec_pivot.currentData()
        command = self.exec_command.toPlainText()
        
        if not pivot_id or not command:
            return
        
        async def do_exec():
            return await self.pivot_module.execute_through_pivot(pivot_id, command)
        
        worker = PivotWorker(do_exec)
        worker.result_ready.connect(lambda r: self.exec_output.setPlainText(r))
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def scan_networks(self):
        """Scan networks through pivots"""
        if not self.selected_pivot:
            QMessageBox.warning(self, "Error", "Select a pivot first")
            return
        
        self.status_bar.setText("Scanning networks...")
    
    def add_to_proxy_chain(self):
        """Add selected proxy to chain"""
        row = self.proxies_table.currentRow()
        if row >= 0:
            address = self.proxies_table.item(row, 1).text()
            proxy_type = self.proxies_table.item(row, 0).text().lower()
            self.proxy_chain_list.addItem(f"{proxy_type} {address}")
    
    def generate_proxychains_config(self):
        """Generate proxychains configuration"""
        config = self.pivot_module.generate_proxychains_config()
        self.proxychains_config.setPlainText(config)
    
    def save_proxychains_config(self):
        """Save proxychains config to file"""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save ProxyChains Config", "proxychains.conf",
            "Config Files (*.conf)"
        )
        if filepath:
            with open(filepath, 'w') as f:
                f.write(self.proxychains_config.toPlainText())
            self.status_bar.setText(f"Config saved to {filepath}")
    
    def generate_ssh_config(self):
        """Generate SSH configuration"""
        config = self.pivot_module.generate_ssh_config()
        self.ssh_config.setPlainText(config)
    
    def save_ssh_config(self):
        """Save SSH config to file"""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save SSH Config", "ssh_config",
            "All Files (*)"
        )
        if filepath:
            with open(filepath, 'w') as f:
                f.write(self.ssh_config.toPlainText())
            self.status_bar.setText(f"Config saved to {filepath}")
    
    def update_pivot_status(self):
        """Periodic status update"""
        self.refresh_tables()
    
    def on_error(self, error: str):
        """Handle errors"""
        self.status_bar.setText(f"Error: {error}")
        QMessageBox.critical(self, "Error", error)
