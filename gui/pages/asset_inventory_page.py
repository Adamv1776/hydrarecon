"""
Asset Inventory Page - Comprehensive asset discovery and management
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QFrame,
    QLineEdit, QComboBox, QTextEdit, QSpinBox, QProgressBar,
    QSplitter, QTreeWidget, QTreeWidgetItem, QGroupBox,
    QFormLayout, QCheckBox, QHeaderView, QMenu, QDialog,
    QDialogButtonBox, QMessageBox, QFileDialog, QGridLayout,
    QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QAction
from datetime import datetime
import json


class AssetDiscoveryThread(QThread):
    """Background thread for asset discovery"""
    progress = pyqtSignal(str, str)  # type, message
    asset_found = pyqtSignal(dict)
    completed = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, engine, target, methods):
        super().__init__()
        self.engine = engine
        self.target = target
        self.methods = methods
    
    def run(self):
        import asyncio
        
        def callback(msg_type, message):
            self.progress.emit(msg_type, message)
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            result = loop.run_until_complete(
                self.engine.discover_network(self.target, self.methods, callback)
            )
            
            self.completed.emit({
                "discovered": result.discovered_assets,
                "new": result.new_assets,
                "updated": result.updated_assets,
                "duration": (result.end_time - result.start_time).total_seconds()
            })
            
            loop.close()
        except Exception as e:
            self.error.emit(str(e))


class AssetDetailsDialog(QDialog):
    """Dialog for viewing/editing asset details"""
    
    def __init__(self, asset, parent=None):
        super().__init__(parent)
        self.asset = asset
        self.setWindowTitle(f"Asset Details - {asset.name}")
        self.setMinimumSize(700, 600)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Tabs for different sections
        tabs = QTabWidget()
        
        # General tab
        general_tab = self._create_general_tab()
        tabs.addTab(general_tab, "General")
        
        # Network tab
        network_tab = self._create_network_tab()
        tabs.addTab(network_tab, "Network")
        
        # Services tab
        services_tab = self._create_services_tab()
        tabs.addTab(services_tab, "Services")
        
        # Software tab
        software_tab = self._create_software_tab()
        tabs.addTab(software_tab, "Software")
        
        # Security tab
        security_tab = self._create_security_tab()
        tabs.addTab(security_tab, "Security")
        
        layout.addWidget(tabs)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def _create_general_tab(self):
        widget = QWidget()
        layout = QFormLayout(widget)
        layout.setSpacing(10)
        
        self.name_edit = QLineEdit(self.asset.name)
        layout.addRow("Name:", self.name_edit)
        
        self.hostname_edit = QLineEdit(self.asset.hostname)
        layout.addRow("Hostname:", self.hostname_edit)
        
        self.type_combo = QComboBox()
        types = ["server", "workstation", "network_device", "firewall", "router",
                "switch", "database", "web_server", "application_server", "storage",
                "printer", "iot_device", "mobile_device", "virtual_machine",
                "container", "cloud_instance", "api_endpoint", "unknown"]
        self.type_combo.addItems(types)
        self.type_combo.setCurrentText(self.asset.asset_type.value)
        layout.addRow("Type:", self.type_combo)
        
        self.status_combo = QComboBox()
        self.status_combo.addItems(["active", "inactive", "maintenance", "decommissioned"])
        self.status_combo.setCurrentText(self.asset.status.value)
        layout.addRow("Status:", self.status_combo)
        
        self.criticality_combo = QComboBox()
        self.criticality_combo.addItems(["critical", "high", "medium", "low", "informational"])
        self.criticality_combo.setCurrentText(self.asset.criticality.value)
        layout.addRow("Criticality:", self.criticality_combo)
        
        self.os_family_edit = QLineEdit(self.asset.os_family)
        layout.addRow("OS Family:", self.os_family_edit)
        
        self.os_version_edit = QLineEdit(self.asset.os_version)
        layout.addRow("OS Version:", self.os_version_edit)
        
        self.manufacturer_edit = QLineEdit(self.asset.manufacturer)
        layout.addRow("Manufacturer:", self.manufacturer_edit)
        
        self.model_edit = QLineEdit(self.asset.model)
        layout.addRow("Model:", self.model_edit)
        
        self.serial_edit = QLineEdit(self.asset.serial_number)
        layout.addRow("Serial Number:", self.serial_edit)
        
        self.owner_edit = QLineEdit(self.asset.owner)
        layout.addRow("Owner:", self.owner_edit)
        
        self.department_edit = QLineEdit(self.asset.department)
        layout.addRow("Department:", self.department_edit)
        
        self.location_edit = QLineEdit(self.asset.location)
        layout.addRow("Location:", self.location_edit)
        
        self.tags_edit = QLineEdit(", ".join(self.asset.tags))
        layout.addRow("Tags:", self.tags_edit)
        
        self.notes_edit = QTextEdit()
        self.notes_edit.setText(self.asset.notes)
        self.notes_edit.setMaximumHeight(100)
        layout.addRow("Notes:", self.notes_edit)
        
        return widget
    
    def _create_network_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Primary IP
        ip_group = QGroupBox("Network Information")
        ip_layout = QFormLayout(ip_group)
        
        self.ip_edit = QLineEdit(self.asset.primary_ip)
        ip_layout.addRow("Primary IP:", self.ip_edit)
        
        self.fqdn_edit = QLineEdit(self.asset.fqdn)
        ip_layout.addRow("FQDN:", self.fqdn_edit)
        
        layout.addWidget(ip_group)
        
        # Network interfaces
        iface_group = QGroupBox("Network Interfaces")
        iface_layout = QVBoxLayout(iface_group)
        
        self.iface_table = QTableWidget()
        self.iface_table.setColumnCount(4)
        self.iface_table.setHorizontalHeaderLabels(["Interface", "MAC Address", "IP Addresses", "VLAN"])
        self.iface_table.horizontalHeader().setStretchLastSection(True)
        
        for iface in self.asset.network_interfaces:
            row = self.iface_table.rowCount()
            self.iface_table.insertRow(row)
            self.iface_table.setItem(row, 0, QTableWidgetItem(iface.interface_name))
            self.iface_table.setItem(row, 1, QTableWidgetItem(iface.mac_address))
            self.iface_table.setItem(row, 2, QTableWidgetItem(", ".join(iface.ip_addresses)))
            self.iface_table.setItem(row, 3, QTableWidgetItem(str(iface.vlan_id or "")))
        
        iface_layout.addWidget(self.iface_table)
        layout.addWidget(iface_group)
        
        layout.addStretch()
        return widget
    
    def _create_services_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.services_table = QTableWidget()
        self.services_table.setColumnCount(5)
        self.services_table.setHorizontalHeaderLabels(["Port", "Protocol", "Service", "Version", "State"])
        self.services_table.horizontalHeader().setStretchLastSection(True)
        
        for service in self.asset.services:
            row = self.services_table.rowCount()
            self.services_table.insertRow(row)
            self.services_table.setItem(row, 0, QTableWidgetItem(str(service.port)))
            self.services_table.setItem(row, 1, QTableWidgetItem(service.protocol))
            self.services_table.setItem(row, 2, QTableWidgetItem(service.name))
            self.services_table.setItem(row, 3, QTableWidgetItem(service.version))
            self.services_table.setItem(row, 4, QTableWidgetItem(service.state))
        
        layout.addWidget(self.services_table)
        return widget
    
    def _create_software_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.software_table = QTableWidget()
        self.software_table.setColumnCount(4)
        self.software_table.setHorizontalHeaderLabels(["Software", "Version", "Vendor", "Security"])
        self.software_table.horizontalHeader().setStretchLastSection(True)
        
        for sw in self.asset.software:
            row = self.software_table.rowCount()
            self.software_table.insertRow(row)
            self.software_table.setItem(row, 0, QTableWidgetItem(sw.name))
            self.software_table.setItem(row, 1, QTableWidgetItem(sw.version))
            self.software_table.setItem(row, 2, QTableWidgetItem(sw.vendor))
            self.software_table.setItem(row, 3, QTableWidgetItem("Yes" if sw.is_security_related else "No"))
        
        layout.addWidget(self.software_table)
        return widget
    
    def _create_security_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Risk score
        risk_group = QGroupBox("Risk Assessment")
        risk_layout = QFormLayout(risk_group)
        
        risk_label = QLabel(f"{self.asset.risk_score:.1f} / 10.0")
        risk_label.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        if self.asset.risk_score >= 7:
            risk_label.setStyleSheet("color: #f85149;")
        elif self.asset.risk_score >= 4:
            risk_label.setStyleSheet("color: #d29922;")
        else:
            risk_label.setStyleSheet("color: #3fb950;")
        risk_layout.addRow("Risk Score:", risk_label)
        
        layout.addWidget(risk_group)
        
        # Vulnerabilities
        vuln_group = QGroupBox(f"Vulnerabilities ({len(self.asset.vulnerabilities)})")
        vuln_layout = QVBoxLayout(vuln_group)
        
        vuln_list = QTextEdit()
        vuln_list.setReadOnly(True)
        vuln_list.setText("\n".join(self.asset.vulnerabilities) if self.asset.vulnerabilities else "No vulnerabilities recorded")
        vuln_layout.addWidget(vuln_list)
        
        layout.addWidget(vuln_group)
        
        # Credentials
        cred_group = QGroupBox("Credentials")
        cred_layout = QVBoxLayout(cred_group)
        
        self.cred_table = QTableWidget()
        self.cred_table.setColumnCount(4)
        self.cred_table.setHorizontalHeaderLabels(["Username", "Type", "Privileged", "Weak"])
        
        for cred in self.asset.credentials:
            row = self.cred_table.rowCount()
            self.cred_table.insertRow(row)
            self.cred_table.setItem(row, 0, QTableWidgetItem(cred.username))
            self.cred_table.setItem(row, 1, QTableWidgetItem(cred.credential_type))
            self.cred_table.setItem(row, 2, QTableWidgetItem("Yes" if cred.privileged else "No"))
            self.cred_table.setItem(row, 3, QTableWidgetItem("Yes" if cred.is_weak else "No"))
        
        cred_layout.addWidget(self.cred_table)
        layout.addWidget(cred_group)
        
        return widget
    
    def get_updated_asset(self):
        """Return asset with updated values"""
        self.asset.name = self.name_edit.text()
        self.asset.hostname = self.hostname_edit.text()
        self.asset.primary_ip = self.ip_edit.text()
        self.asset.fqdn = self.fqdn_edit.text()
        self.asset.os_family = self.os_family_edit.text()
        self.asset.os_version = self.os_version_edit.text()
        self.asset.manufacturer = self.manufacturer_edit.text()
        self.asset.model = self.model_edit.text()
        self.asset.serial_number = self.serial_edit.text()
        self.asset.owner = self.owner_edit.text()
        self.asset.department = self.department_edit.text()
        self.asset.location = self.location_edit.text()
        self.asset.notes = self.notes_edit.toPlainText()
        
        tags = self.tags_edit.text().split(",")
        self.asset.tags = [t.strip() for t in tags if t.strip()]
        
        return self.asset


class AssetInventoryPage(QWidget):
    """Asset Inventory management page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = None
        self._init_engine()
        self._setup_ui()
    
    def _init_engine(self):
        """Initialize the asset inventory engine"""
        try:
            from core.asset_inventory import AssetInventoryEngine
            self.engine = AssetInventoryEngine()
        except ImportError:
            self.engine = None
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Header
        header = QLabel("Asset Inventory")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #58a6ff;")
        layout.addWidget(header)
        
        subtitle = QLabel("Discover, track, and manage all network assets")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        layout.addWidget(subtitle)
        
        # Tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                border-radius: 8px;
                background: #0d1117;
            }
            QTabBar::tab {
                background: #21262d;
                color: #8b949e;
                padding: 12px 24px;
                border: none;
                font-weight: 600;
            }
            QTabBar::tab:selected {
                background: #30363d;
                color: #58a6ff;
            }
        """)
        
        # Discovery tab
        discovery_tab = self._create_discovery_tab()
        tabs.addTab(discovery_tab, "🔍 Discovery")
        
        # Inventory tab
        inventory_tab = self._create_inventory_tab()
        tabs.addTab(inventory_tab, "📋 Inventory")
        
        # Groups tab
        groups_tab = self._create_groups_tab()
        tabs.addTab(groups_tab, "📁 Groups")
        
        # Topology tab
        topology_tab = self._create_topology_tab()
        tabs.addTab(topology_tab, "🕸️ Topology")
        
        # Statistics tab
        stats_tab = self._create_statistics_tab()
        tabs.addTab(stats_tab, "📊 Statistics")
        
        layout.addWidget(tabs)
    
    def _create_discovery_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Discovery controls
        control_frame = QFrame()
        control_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        control_layout = QVBoxLayout(control_frame)
        
        # Target input
        target_layout = QHBoxLayout()
        
        target_label = QLabel("Target Range:")
        target_label.setStyleSheet("color: #c9d1d9; font-weight: 600;")
        target_layout.addWidget(target_label)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.0/24 or 10.0.0.0/16")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
                font-size: 14px;
            }
        """)
        target_layout.addWidget(self.target_input)
        
        control_layout.addLayout(target_layout)
        
        # Discovery methods
        methods_layout = QHBoxLayout()
        
        methods_label = QLabel("Methods:")
        methods_label.setStyleSheet("color: #c9d1d9; font-weight: 600;")
        methods_layout.addWidget(methods_label)
        
        self.arp_check = QCheckBox("ARP Discovery")
        self.arp_check.setChecked(True)
        self.arp_check.setStyleSheet("color: #c9d1d9;")
        methods_layout.addWidget(self.arp_check)
        
        self.ping_check = QCheckBox("Ping Sweep")
        self.ping_check.setChecked(True)
        self.ping_check.setStyleSheet("color: #c9d1d9;")
        methods_layout.addWidget(self.ping_check)
        
        self.dns_check = QCheckBox("DNS Enumeration")
        self.dns_check.setStyleSheet("color: #c9d1d9;")
        methods_layout.addWidget(self.dns_check)
        
        self.port_check = QCheckBox("Port Scan")
        self.port_check.setChecked(True)
        self.port_check.setStyleSheet("color: #c9d1d9;")
        methods_layout.addWidget(self.port_check)
        
        self.os_check = QCheckBox("OS Detection")
        self.os_check.setStyleSheet("color: #c9d1d9;")
        methods_layout.addWidget(self.os_check)
        
        methods_layout.addStretch()
        control_layout.addLayout(methods_layout)
        
        # Start button and progress
        action_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 Start Discovery")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                border-radius: 6px;
                color: white;
                padding: 12px 24px;
                font-weight: 600;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #2ea043;
            }
            QPushButton:disabled {
                background: #21262d;
                color: #484f58;
            }
        """)
        self.start_btn.clicked.connect(self._start_discovery)
        action_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background: #da3633;
                border: none;
                border-radius: 6px;
                color: white;
                padding: 12px 24px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #f85149;
            }
            QPushButton:disabled {
                background: #21262d;
                color: #484f58;
            }
        """)
        action_layout.addWidget(self.stop_btn)
        
        action_layout.addStretch()
        
        self.discovery_progress = QProgressBar()
        self.discovery_progress.setVisible(False)
        self.discovery_progress.setStyleSheet("""
            QProgressBar {
                background: #21262d;
                border: none;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar::chunk {
                background: #58a6ff;
                border-radius: 4px;
            }
        """)
        action_layout.addWidget(self.discovery_progress)
        
        control_layout.addLayout(action_layout)
        
        layout.addWidget(control_frame)
        
        # Discovery status
        self.discovery_status = QLabel("")
        self.discovery_status.setStyleSheet("color: #8b949e; font-size: 13px;")
        layout.addWidget(self.discovery_status)
        
        # Discovery log
        log_group = QGroupBox("Discovery Log")
        log_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: 600;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
            }
        """)
        log_layout = QVBoxLayout(log_group)
        
        self.discovery_log = QTextEdit()
        self.discovery_log.setReadOnly(True)
        self.discovery_log.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                padding: 8px;
            }
        """)
        log_layout.addWidget(self.discovery_log)
        
        layout.addWidget(log_group)
        
        return widget
    
    def _create_inventory_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        # Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search assets...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #c9d1d9;
                font-size: 14px;
                min-width: 300px;
            }
        """)
        self.search_input.textChanged.connect(self._filter_assets)
        toolbar.addWidget(self.search_input)
        
        # Type filter
        self.type_filter = QComboBox()
        self.type_filter.addItem("All Types", None)
        self.type_filter.addItems([
            "server", "workstation", "network_device", "firewall", "router",
            "database", "web_server", "container", "cloud_instance"
        ])
        self.type_filter.setStyleSheet("""
            QComboBox {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c9d1d9;
                min-width: 150px;
            }
        """)
        self.type_filter.currentIndexChanged.connect(self._filter_assets)
        toolbar.addWidget(self.type_filter)
        
        # Status filter
        self.status_filter = QComboBox()
        self.status_filter.addItem("All Statuses", None)
        self.status_filter.addItems(["active", "inactive", "maintenance", "decommissioned"])
        self.status_filter.setStyleSheet("""
            QComboBox {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c9d1d9;
                min-width: 150px;
            }
        """)
        self.status_filter.currentIndexChanged.connect(self._filter_assets)
        toolbar.addWidget(self.status_filter)
        
        toolbar.addStretch()
        
        # Actions
        add_btn = QPushButton("➕ Add Asset")
        add_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                border-radius: 6px;
                color: white;
                padding: 10px 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        add_btn.clicked.connect(self._add_asset)
        toolbar.addWidget(add_btn)
        
        import_btn = QPushButton("📥 Import")
        import_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
                padding: 10px 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #30363d;
            }
        """)
        import_btn.clicked.connect(self._import_assets)
        toolbar.addWidget(import_btn)
        
        export_btn = QPushButton("📤 Export")
        export_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
                padding: 10px 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #30363d;
            }
        """)
        export_btn.clicked.connect(self._export_assets)
        toolbar.addWidget(export_btn)
        
        layout.addLayout(toolbar)
        
        # Asset count
        self.asset_count_label = QLabel("0 assets")
        self.asset_count_label.setStyleSheet("color: #8b949e; font-size: 13px;")
        layout.addWidget(self.asset_count_label)
        
        # Asset table
        self.asset_table = QTableWidget()
        self.asset_table.setColumnCount(9)
        self.asset_table.setHorizontalHeaderLabels([
            "Name", "IP Address", "Type", "Status", "Criticality",
            "OS", "Open Ports", "Risk Score", "Last Seen"
        ])
        self.asset_table.horizontalHeader().setStretchLastSection(True)
        self.asset_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.asset_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.asset_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.asset_table.customContextMenuRequested.connect(self._show_context_menu)
        self.asset_table.doubleClicked.connect(self._view_asset_details)
        self.asset_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 8px;
                color: #c9d1d9;
                border-bottom: 1px solid #21262d;
            }
            QTableWidget::item:selected {
                background: #388bfd;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 12px;
                border: none;
                border-bottom: 1px solid #30363d;
                font-weight: 600;
            }
        """)
        layout.addWidget(self.asset_table)
        
        # Load initial data
        self._refresh_asset_table()
        
        return widget
    
    def _create_groups_tab(self):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        
        # Groups tree
        groups_frame = QFrame()
        groups_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        groups_frame.setMaximumWidth(300)
        groups_layout = QVBoxLayout(groups_frame)
        
        groups_header = QLabel("Asset Groups")
        groups_header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        groups_header.setStyleSheet("color: #c9d1d9; padding: 8px;")
        groups_layout.addWidget(groups_header)
        
        self.groups_tree = QTreeWidget()
        self.groups_tree.setHeaderHidden(True)
        self.groups_tree.setStyleSheet("""
            QTreeWidget {
                background: transparent;
                border: none;
                color: #c9d1d9;
            }
            QTreeWidget::item {
                padding: 8px;
            }
            QTreeWidget::item:selected {
                background: #388bfd;
            }
        """)
        groups_layout.addWidget(self.groups_tree)
        
        # Group actions
        group_actions = QHBoxLayout()
        
        add_group_btn = QPushButton("➕")
        add_group_btn.setToolTip("Add Group")
        add_group_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: none;
                border-radius: 4px;
                padding: 8px 12px;
                color: #c9d1d9;
            }
            QPushButton:hover {
                background: #30363d;
            }
        """)
        add_group_btn.clicked.connect(self._add_group)
        group_actions.addWidget(add_group_btn)
        
        delete_group_btn = QPushButton("🗑️")
        delete_group_btn.setToolTip("Delete Group")
        delete_group_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: none;
                border-radius: 4px;
                padding: 8px 12px;
                color: #c9d1d9;
            }
            QPushButton:hover {
                background: #da3633;
            }
        """)
        group_actions.addWidget(delete_group_btn)
        
        group_actions.addStretch()
        groups_layout.addLayout(group_actions)
        
        layout.addWidget(groups_frame)
        
        # Group members
        members_frame = QFrame()
        members_frame.setStyleSheet("""
            QFrame {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        members_layout = QVBoxLayout(members_frame)
        
        members_header = QLabel("Group Members")
        members_header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        members_header.setStyleSheet("color: #c9d1d9; padding: 8px;")
        members_layout.addWidget(members_header)
        
        self.group_members_table = QTableWidget()
        self.group_members_table.setColumnCount(4)
        self.group_members_table.setHorizontalHeaderLabels(["Name", "IP", "Type", "Status"])
        self.group_members_table.horizontalHeader().setStretchLastSection(True)
        self.group_members_table.setStyleSheet("""
            QTableWidget {
                background: transparent;
                border: none;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 8px;
                color: #c9d1d9;
            }
            QHeaderView::section {
                background: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        members_layout.addWidget(self.group_members_table)
        
        layout.addWidget(members_frame)
        
        return widget
    
    def _create_topology_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Placeholder for network topology visualization
        topology_frame = QFrame()
        topology_frame.setStyleSheet("""
            QFrame {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        topology_layout = QVBoxLayout(topology_frame)
        
        placeholder = QLabel("🕸️ Network Topology Visualization")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setFont(QFont("Segoe UI", 18))
        placeholder.setStyleSheet("color: #8b949e;")
        topology_layout.addWidget(placeholder)
        
        info = QLabel("Interactive network map showing asset relationships and connections")
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info.setStyleSheet("color: #484f58;")
        topology_layout.addWidget(info)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh Topology")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
                padding: 10px 20px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #30363d;
            }
        """)
        refresh_btn.clicked.connect(self._refresh_topology)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(refresh_btn)
        btn_layout.addStretch()
        topology_layout.addLayout(btn_layout)
        
        layout.addWidget(topology_frame)
        
        return widget
    
    def _create_statistics_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Stats cards
        cards_layout = QHBoxLayout()
        
        self.stat_cards = {}
        stats = [
            ("total", "Total Assets", "📊", "#58a6ff"),
            ("active", "Active", "✅", "#3fb950"),
            ("critical", "Critical", "🔴", "#f85149"),
            ("risky", "High Risk", "⚠️", "#d29922"),
            ("new", "New (7d)", "🆕", "#a371f7"),
            ("stale", "Stale (30d)", "⏰", "#8b949e")
        ]
        
        for key, title, icon, color in stats:
            card = self._create_stat_card(title, icon, "0", color)
            self.stat_cards[key] = card
            cards_layout.addWidget(card)
        
        layout.addLayout(cards_layout)
        
        # Charts area
        charts_frame = QFrame()
        charts_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        charts_layout = QGridLayout(charts_frame)
        
        # Assets by type
        type_group = QGroupBox("Assets by Type")
        type_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: 600;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        type_layout = QVBoxLayout(type_group)
        self.type_stats_label = QLabel("No data")
        self.type_stats_label.setStyleSheet("color: #8b949e;")
        type_layout.addWidget(self.type_stats_label)
        charts_layout.addWidget(type_group, 0, 0)
        
        # Assets by OS
        os_group = QGroupBox("Assets by OS")
        os_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: 600;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        os_layout = QVBoxLayout(os_group)
        self.os_stats_label = QLabel("No data")
        self.os_stats_label.setStyleSheet("color: #8b949e;")
        os_layout.addWidget(self.os_stats_label)
        charts_layout.addWidget(os_group, 0, 1)
        
        # Assets by criticality
        crit_group = QGroupBox("Assets by Criticality")
        crit_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: 600;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        crit_layout = QVBoxLayout(crit_group)
        self.crit_stats_label = QLabel("No data")
        self.crit_stats_label.setStyleSheet("color: #8b949e;")
        crit_layout.addWidget(self.crit_stats_label)
        charts_layout.addWidget(crit_group, 1, 0)
        
        # Assets by status
        status_group = QGroupBox("Assets by Status")
        status_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: 600;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        status_layout = QVBoxLayout(status_group)
        self.status_stats_label = QLabel("No data")
        self.status_stats_label.setStyleSheet("color: #8b949e;")
        status_layout.addWidget(self.status_stats_label)
        charts_layout.addWidget(status_group, 1, 1)
        
        layout.addWidget(charts_frame)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh Statistics")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: none;
                border-radius: 6px;
                color: white;
                padding: 12px 24px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        refresh_btn.clicked.connect(self._refresh_statistics)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(refresh_btn)
        layout.addLayout(btn_layout)
        
        return widget
    
    def _create_stat_card(self, title, icon, value, color):
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }}
        """)
        layout = QVBoxLayout(card)
        
        header = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI", 20))
        header.addWidget(icon_label)
        header.addStretch()
        layout.addLayout(header)
        
        value_label = QLabel(value)
        value_label.setObjectName("value")
        value_label.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        layout.addWidget(value_label)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #8b949e; font-size: 13px;")
        layout.addWidget(title_label)
        
        return card
    
    def _start_discovery(self):
        if not self.engine:
            QMessageBox.warning(self, "Error", "Asset inventory engine not available")
            return
        
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target range")
            return
        
        # Get selected methods
        methods = []
        from core.asset_inventory import DiscoveryMethod
        
        if self.arp_check.isChecked():
            methods.append(DiscoveryMethod.ARP_DISCOVERY)
        if self.ping_check.isChecked():
            methods.append(DiscoveryMethod.NETWORK_SCAN)
        if self.dns_check.isChecked():
            methods.append(DiscoveryMethod.DNS_ENUMERATION)
        
        if not methods:
            methods = [DiscoveryMethod.NETWORK_SCAN]
        
        # Start discovery thread
        self.discovery_thread = AssetDiscoveryThread(self.engine, target, methods)
        self.discovery_thread.progress.connect(self._on_discovery_progress)
        self.discovery_thread.completed.connect(self._on_discovery_complete)
        self.discovery_thread.error.connect(self._on_discovery_error)
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.discovery_progress.setVisible(True)
        self.discovery_progress.setRange(0, 0)  # Indeterminate
        
        self.discovery_log.clear()
        self._log_discovery(f"Starting discovery scan on {target}...")
        
        self.discovery_thread.start()
    
    def _on_discovery_progress(self, msg_type, message):
        self.discovery_status.setText(message)
        self._log_discovery(message)
    
    def _on_discovery_complete(self, result):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.discovery_progress.setVisible(False)
        
        self._log_discovery(f"\n✅ Discovery completed!")
        self._log_discovery(f"   Discovered: {result['discovered']} assets")
        self._log_discovery(f"   New: {result['new']} assets")
        self._log_discovery(f"   Updated: {result['updated']} assets")
        self._log_discovery(f"   Duration: {result['duration']:.1f} seconds")
        
        self.discovery_status.setText(
            f"Completed: {result['discovered']} discovered, {result['new']} new"
        )
        
        # Refresh asset table
        self._refresh_asset_table()
        self._refresh_statistics()
    
    def _on_discovery_error(self, error):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.discovery_progress.setVisible(False)
        
        self._log_discovery(f"\n❌ Error: {error}")
        self.discovery_status.setText(f"Error: {error}")
    
    def _log_discovery(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.discovery_log.append(f"[{timestamp}] {message}")
    
    def _refresh_asset_table(self):
        if not self.engine:
            return
        
        self.asset_table.setRowCount(0)
        assets = list(self.engine.assets.values())
        
        self.asset_count_label.setText(f"{len(assets)} assets")
        
        for asset in assets:
            row = self.asset_table.rowCount()
            self.asset_table.insertRow(row)
            
            # Name
            name_item = QTableWidgetItem(asset.name)
            name_item.setData(Qt.ItemDataRole.UserRole, asset.id)
            self.asset_table.setItem(row, 0, name_item)
            
            # IP
            self.asset_table.setItem(row, 1, QTableWidgetItem(asset.primary_ip))
            
            # Type
            type_item = QTableWidgetItem(asset.asset_type.value)
            self.asset_table.setItem(row, 2, type_item)
            
            # Status
            status_item = QTableWidgetItem(asset.status.value)
            if asset.status.value == "active":
                status_item.setForeground(QColor("#3fb950"))
            elif asset.status.value == "inactive":
                status_item.setForeground(QColor("#f85149"))
            self.asset_table.setItem(row, 3, status_item)
            
            # Criticality
            crit_item = QTableWidgetItem(asset.criticality.value)
            crit_colors = {
                "critical": "#f85149",
                "high": "#db6d28",
                "medium": "#d29922",
                "low": "#3fb950",
                "informational": "#8b949e"
            }
            crit_item.setForeground(QColor(crit_colors.get(asset.criticality.value, "#c9d1d9")))
            self.asset_table.setItem(row, 4, crit_item)
            
            # OS
            self.asset_table.setItem(row, 5, QTableWidgetItem(asset.os_family or "Unknown"))
            
            # Open Ports
            ports = ", ".join(str(p) for p in asset.open_ports[:5])
            if len(asset.open_ports) > 5:
                ports += f" (+{len(asset.open_ports) - 5})"
            self.asset_table.setItem(row, 6, QTableWidgetItem(ports))
            
            # Risk Score
            risk_item = QTableWidgetItem(f"{asset.risk_score:.1f}")
            if asset.risk_score >= 7:
                risk_item.setForeground(QColor("#f85149"))
            elif asset.risk_score >= 4:
                risk_item.setForeground(QColor("#d29922"))
            else:
                risk_item.setForeground(QColor("#3fb950"))
            self.asset_table.setItem(row, 7, risk_item)
            
            # Last Seen
            last_seen = asset.last_seen.strftime("%Y-%m-%d %H:%M")
            self.asset_table.setItem(row, 8, QTableWidgetItem(last_seen))
    
    def _filter_assets(self):
        if not self.engine:
            return
        
        query = self.search_input.text().lower()
        type_filter = self.type_filter.currentText()
        status_filter = self.status_filter.currentText()
        
        for row in range(self.asset_table.rowCount()):
            show = True
            
            # Query filter
            if query:
                name = self.asset_table.item(row, 0).text().lower()
                ip = self.asset_table.item(row, 1).text().lower()
                if query not in name and query not in ip:
                    show = False
            
            # Type filter
            if show and type_filter != "All Types":
                asset_type = self.asset_table.item(row, 2).text()
                if asset_type != type_filter:
                    show = False
            
            # Status filter
            if show and status_filter != "All Statuses":
                status = self.asset_table.item(row, 3).text()
                if status != status_filter:
                    show = False
            
            self.asset_table.setRowHidden(row, not show)
    
    def _show_context_menu(self, pos):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 4px;
            }
            QMenu::item {
                padding: 8px 20px;
                color: #c9d1d9;
            }
            QMenu::item:selected {
                background: #388bfd;
            }
        """)
        
        view_action = menu.addAction("👁️ View Details")
        view_action.triggered.connect(self._view_asset_details)
        
        edit_action = menu.addAction("✏️ Edit Asset")
        edit_action.triggered.connect(self._edit_asset)
        
        scan_action = menu.addAction("🔍 Scan Asset")
        scan_action.triggered.connect(self._scan_asset)
        
        menu.addSeparator()
        
        delete_action = menu.addAction("🗑️ Delete Asset")
        delete_action.triggered.connect(self._delete_asset)
        
        menu.exec(self.asset_table.mapToGlobal(pos))
    
    def _view_asset_details(self):
        row = self.asset_table.currentRow()
        if row < 0:
            return
        
        asset_id = self.asset_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        asset = self.engine.get_asset(asset_id)
        
        if asset:
            dialog = AssetDetailsDialog(asset, self)
            dialog.exec()
    
    def _edit_asset(self):
        row = self.asset_table.currentRow()
        if row < 0:
            return
        
        asset_id = self.asset_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        asset = self.engine.get_asset(asset_id)
        
        if asset:
            dialog = AssetDetailsDialog(asset, self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                updated = dialog.get_updated_asset()
                # Asset is updated in place
                self._refresh_asset_table()
    
    def _scan_asset(self):
        row = self.asset_table.currentRow()
        if row < 0:
            return
        
        ip = self.asset_table.item(row, 1).text()
        self.target_input.setText(ip)
        QMessageBox.information(self, "Scan Asset", f"Target set to {ip}. Go to Discovery tab to start scan.")
    
    def _delete_asset(self):
        row = self.asset_table.currentRow()
        if row < 0:
            return
        
        asset_id = self.asset_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        name = self.asset_table.item(row, 0).text()
        
        reply = QMessageBox.question(
            self, "Delete Asset",
            f"Are you sure you want to delete '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.engine.delete_asset(asset_id)
            self._refresh_asset_table()
    
    def _add_asset(self):
        from core.asset_inventory import Asset, AssetType, AssetStatus, Criticality
        import uuid
        
        # Create a new empty asset
        asset = Asset(
            id=str(uuid.uuid4()),
            name="New Asset",
            asset_type=AssetType.UNKNOWN,
            status=AssetStatus.ACTIVE,
            criticality=Criticality.MEDIUM,
            primary_ip=""
        )
        
        dialog = AssetDetailsDialog(asset, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            updated = dialog.get_updated_asset()
            self.engine.add_asset(updated)
            self._refresh_asset_table()
    
    def _import_assets(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Assets", "", "JSON Files (*.json);;CSV Files (*.csv)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    data = f.read()
                
                fmt = "json" if file_path.endswith(".json") else "csv"
                imported = self.engine.import_inventory(data, fmt)
                
                QMessageBox.information(
                    self, "Import Complete",
                    f"Successfully imported {imported} assets"
                )
                self._refresh_asset_table()
            except Exception as e:
                QMessageBox.critical(self, "Import Error", str(e))
    
    def _export_assets(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Assets", "assets.json",
            "JSON Files (*.json);;CSV Files (*.csv)"
        )
        
        if file_path:
            try:
                fmt = "json" if file_path.endswith(".json") else "csv"
                data = self.engine.export_inventory(fmt)
                
                with open(file_path, 'w') as f:
                    f.write(data)
                
                QMessageBox.information(
                    self, "Export Complete",
                    f"Assets exported to {file_path}"
                )
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))
    
    def _add_group(self):
        # Simple dialog for group name
        from PyQt6.QtWidgets import QInputDialog
        
        name, ok = QInputDialog.getText(self, "New Group", "Group name:")
        if ok and name:
            self.engine.create_group(name)
            self._refresh_groups()
    
    def _refresh_groups(self):
        self.groups_tree.clear()
        
        if not self.engine:
            return
        
        for group in self.engine.groups.values():
            item = QTreeWidgetItem([f"📁 {group.name} ({len(group.asset_ids)})"])
            item.setData(0, Qt.ItemDataRole.UserRole, group.id)
            self.groups_tree.addTopLevelItem(item)
    
    def _refresh_topology(self):
        if not self.engine:
            return
        
        topology = self.engine.get_network_topology()
        # Topology visualization would be implemented with a graphics library
        QMessageBox.information(
            self, "Topology",
            f"Topology: {len(topology['nodes'])} nodes, {len(topology['edges'])} edges"
        )
    
    def _refresh_statistics(self):
        if not self.engine:
            return
        
        stats = self.engine.get_asset_statistics()
        
        # Update stat cards
        self.stat_cards["total"].findChild(QLabel, "value").setText(str(stats["total_assets"]))
        self.stat_cards["active"].findChild(QLabel, "value").setText(str(stats["by_status"].get("active", 0)))
        self.stat_cards["critical"].findChild(QLabel, "value").setText(str(stats["by_criticality"].get("critical", 0)))
        self.stat_cards["risky"].findChild(QLabel, "value").setText(str(stats["high_risk"]))
        self.stat_cards["new"].findChild(QLabel, "value").setText(str(stats["recently_discovered"]))
        self.stat_cards["stale"].findChild(QLabel, "value").setText(str(stats["stale_assets"]))
        
        # Update distribution labels
        type_text = "\n".join(f"• {k}: {v}" for k, v in stats["by_type"].items())
        self.type_stats_label.setText(type_text or "No data")
        
        os_text = "\n".join(f"• {k}: {v}" for k, v in stats["by_os"].items())
        self.os_stats_label.setText(os_text or "No data")
        
        crit_text = "\n".join(f"• {k}: {v}" for k, v in stats["by_criticality"].items())
        self.crit_stats_label.setText(crit_text or "No data")
        
        status_text = "\n".join(f"• {k}: {v}" for k, v in stats["by_status"].items())
        self.status_stats_label.setText(status_text or "No data")
