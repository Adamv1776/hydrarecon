#!/usr/bin/env python3
"""
HydraRecon SCADA/ICS Security Page
GUI for industrial control system security assessment.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QComboBox,
    QTextEdit, QTableWidget, QTableWidgetItem, QProgressBar,
    QTabWidget, QGroupBox, QCheckBox, QSpinBox, QSplitter,
    QHeaderView, QTreeWidget, QTreeWidgetItem, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QPainter, QPen

import asyncio
from datetime import datetime
from typing import Optional

try:
    from ...core.scada_security import (
        SCADASecurityEngine, ICSProtocol, DeviceType,
        VulnerabilitySeverity, ICSDevice, SCADAScanResult
    )
    SCADA_AVAILABLE = True
except ImportError:
    SCADA_AVAILABLE = False


class NetworkTopologyWidget(QWidget):
    """Custom widget for displaying ICS network topology"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.devices = []
        self.setMinimumSize(400, 300)
        self.setStyleSheet("background-color: #0d1117;")
    
    def set_devices(self, devices):
        """Set devices to display"""
        self.devices = devices
        self.update()
    
    def paintEvent(self, event):
        """Paint the network topology"""
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        if not self.devices:
            painter.setPen(QPen(QColor("#8b949e")))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, 
                           "No devices discovered yet")
            return
        
        # Group devices by subnet
        subnets = {}
        for device in self.devices:
            subnet = '.'.join(device.ip.split('.')[:-1])
            if subnet not in subnets:
                subnets[subnet] = []
            subnets[subnet].append(device)
        
        # Draw zones
        width = self.width()
        height = self.height()
        padding = 30
        zone_height = (height - padding * 2) / max(1, len(subnets))
        
        y = padding
        for subnet, devices in subnets.items():
            # Zone background
            painter.setPen(QPen(QColor("#21262d")))
            painter.setBrush(QColor("#161b22"))
            painter.drawRoundedRect(padding, int(y), 
                                   width - padding * 2, int(zone_height - 10), 8, 8)
            
            # Zone label
            painter.setPen(QPen(QColor("#58a6ff")))
            painter.drawText(padding + 10, int(y + 20), f"Subnet: {subnet}.0/24")
            
            # Draw devices
            device_width = 80
            device_height = 50
            spacing = (width - padding * 2 - 20) / max(1, len(devices))
            
            for i, device in enumerate(devices):
                x = padding + 10 + i * spacing
                dy = y + 35
                
                # Device color based on type
                if device.device_type.value == "plc":
                    color = QColor("#f85149")
                elif device.device_type.value == "hmi":
                    color = QColor("#ffa657")
                elif device.device_type.value == "scada_server":
                    color = QColor("#a371f7")
                else:
                    color = QColor("#3fb950")
                
                painter.setPen(QPen(color))
                painter.setBrush(QColor(color.red(), color.green(), color.blue(), 50))
                painter.drawRoundedRect(int(x), int(dy), device_width, device_height, 5, 5)
                
                # Device info
                painter.setPen(QPen(QColor("#e6e6e6")))
                font = painter.font()
                font.setPointSize(8)
                painter.setFont(font)
                painter.drawText(int(x + 5), int(dy + 15), device.ip.split('.')[-1])
                painter.drawText(int(x + 5), int(dy + 30), device.protocol.value[:10])
                painter.drawText(int(x + 5), int(dy + 45), str(device.port))
            
            y += zone_height


class ScanWorker(QThread):
    """Worker thread for SCADA scanning"""
    progress = pyqtSignal(str, float)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, engine, target, scan_type):
        super().__init__()
        self.engine = engine
        self.target = target
        self.scan_type = scan_type
    
    def run(self):
        """Run the scan"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            def callback(msg, progress):
                self.progress.emit(msg, progress)
            
            if self.scan_type == "discovery":
                result = loop.run_until_complete(
                    self.engine.discover_ics_devices(self.target, callback)
                )
            else:
                result = loop.run_until_complete(
                    self.engine.full_security_assessment(self.target, callback)
                )
            
            loop.close()
            self.finished.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class SCADASecurityPage(QWidget):
    """SCADA/ICS Security Assessment Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.engine = SCADASecurityEngine() if SCADA_AVAILABLE else None
        self.current_result: Optional[SCADAScanResult] = None
        self.scan_worker: Optional[ScanWorker] = None
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #21262d;
                border-radius: 8px;
                background-color: #0d1117;
            }
            QTabBar::tab {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px 20px;
                border: 1px solid #21262d;
                border-bottom: none;
                border-radius: 6px 6px 0 0;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #e6e6e6;
            }
        """)
        
        # Tab 1: Discovery & Scanning
        self.tabs.addTab(self._create_discovery_tab(), "🔍 Device Discovery")
        
        # Tab 2: Vulnerability Analysis
        self.tabs.addTab(self._create_vuln_tab(), "⚠️ Vulnerabilities")
        
        # Tab 3: Protocol Analysis
        self.tabs.addTab(self._create_protocol_tab(), "📡 Protocol Analysis")
        
        # Tab 4: Network Topology
        self.tabs.addTab(self._create_topology_tab(), "🗺️ Network Topology")
        
        # Tab 5: Compliance
        self.tabs.addTab(self._create_compliance_tab(), "📋 Compliance")
        
        layout.addWidget(self.tabs, stretch=1)
    
    def _create_header(self) -> QWidget:
        """Create header section"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #f85149, stop:1 #ffa657);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("⚡ SCADA/ICS Security Assessment")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: 700;
            color: white;
        """)
        
        subtitle = QLabel("Industrial Control System vulnerability assessment and security analysis")
        subtitle.setStyleSheet("font-size: 14px; color: rgba(255,255,255,0.8);")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout, stretch=1)
        
        # Stats
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(24)
        
        self.stat_devices = self._create_stat_widget("Devices", "0")
        self.stat_vulns = self._create_stat_widget("Vulnerabilities", "0")
        self.stat_risk = self._create_stat_widget("Risk Score", "0%")
        
        stats_layout.addWidget(self.stat_devices)
        stats_layout.addWidget(self.stat_vulns)
        stats_layout.addWidget(self.stat_risk)
        
        layout.addLayout(stats_layout)
        
        return header
    
    def _create_stat_widget(self, label: str, value: str) -> QWidget:
        """Create a stat display widget"""
        widget = QFrame()
        widget.setStyleSheet("""
            QFrame {
                background-color: rgba(0,0,0,0.3);
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        value_label.setObjectName("value")
        
        text_label = QLabel(label)
        text_label.setStyleSheet("font-size: 11px; color: rgba(255,255,255,0.7);")
        
        layout.addWidget(value_label, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(text_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        return widget
    
    def _create_discovery_tab(self) -> QWidget:
        """Create device discovery tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
            }
        """)
        
        target_layout = QGridLayout(target_group)
        target_layout.setSpacing(12)
        
        # Network input
        target_layout.addWidget(QLabel("Network Range:"), 0, 0)
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("e.g., 192.168.1.0/24 or 192.168.1.1-50")
        self.network_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        target_layout.addWidget(self.network_input, 0, 1)
        
        # Protocol selection
        target_layout.addWidget(QLabel("Protocols:"), 1, 0)
        protocol_layout = QHBoxLayout()
        
        self.proto_modbus = QCheckBox("Modbus")
        self.proto_modbus.setChecked(True)
        self.proto_s7 = QCheckBox("S7comm")
        self.proto_s7.setChecked(True)
        self.proto_dnp3 = QCheckBox("DNP3")
        self.proto_dnp3.setChecked(True)
        self.proto_opcua = QCheckBox("OPC UA")
        self.proto_opcua.setChecked(True)
        self.proto_bacnet = QCheckBox("BACnet")
        self.proto_ethernetip = QCheckBox("EtherNet/IP")
        
        for cb in [self.proto_modbus, self.proto_s7, self.proto_dnp3, 
                   self.proto_opcua, self.proto_bacnet, self.proto_ethernetip]:
            cb.setStyleSheet("color: #e6e6e6;")
            protocol_layout.addWidget(cb)
        
        protocol_layout.addStretch()
        target_layout.addLayout(protocol_layout, 1, 1)
        
        # Scan type
        target_layout.addWidget(QLabel("Scan Type:"), 2, 0)
        self.scan_type = QComboBox()
        self.scan_type.addItems([
            "Device Discovery Only",
            "Full Security Assessment",
            "Protocol Analysis",
            "Compliance Check"
        ])
        self.scan_type.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        target_layout.addWidget(self.scan_type, 2, 1)
        
        layout.addWidget(target_group)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 Start Scan")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #2ea043; }
            QPushButton:disabled { background-color: #21262d; color: #8b949e; }
        """)
        self.start_btn.clicked.connect(self._start_scan)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #f85149;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #da3633; }
            QPushButton:disabled { background-color: #21262d; color: #8b949e; }
        """)
        self.stop_btn.clicked.connect(self._stop_scan)
        
        self.export_btn = QPushButton("📥 Export Report")
        self.export_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
        """)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.export_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #21262d;
                border: none;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #238636;
                border-radius: 4px;
            }
        """)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #8b949e;")
        
        progress_layout.addWidget(self.progress_bar, stretch=1)
        progress_layout.addWidget(self.status_label)
        
        layout.addLayout(progress_layout)
        
        # Discovered devices table
        self.devices_table = QTableWidget()
        self.devices_table.setColumnCount(7)
        self.devices_table.setHorizontalHeaderLabels([
            "IP Address", "Port", "Protocol", "Device Type", 
            "Vendor", "Model", "Vulnerabilities"
        ])
        self.devices_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                color: #e6e6e6;
                padding: 8px;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        self.devices_table.horizontalHeader().setStretchLastSection(True)
        self.devices_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.devices_table, stretch=1)
        
        return widget
    
    def _create_vuln_tab(self) -> QWidget:
        """Create vulnerability analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Severity filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by Severity:"))
        
        self.filter_critical = QCheckBox("Critical")
        self.filter_critical.setChecked(True)
        self.filter_critical.setStyleSheet("color: #f85149;")
        
        self.filter_high = QCheckBox("High")
        self.filter_high.setChecked(True)
        self.filter_high.setStyleSheet("color: #ffa657;")
        
        self.filter_medium = QCheckBox("Medium")
        self.filter_medium.setChecked(True)
        self.filter_medium.setStyleSheet("color: #d29922;")
        
        self.filter_low = QCheckBox("Low")
        self.filter_low.setChecked(True)
        self.filter_low.setStyleSheet("color: #3fb950;")
        
        for cb in [self.filter_critical, self.filter_high, 
                   self.filter_medium, self.filter_low]:
            filter_layout.addWidget(cb)
        
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Vulnerability table
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(6)
        self.vuln_table.setHorizontalHeaderLabels([
            "ID", "Title", "Severity", "Protocol", "Affected Device", "CVSS"
        ])
        self.vuln_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                color: #e6e6e6;
                padding: 8px;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        self.vuln_table.horizontalHeader().setStretchLastSection(True)
        self.vuln_table.itemSelectionChanged.connect(self._on_vuln_selected)
        
        layout.addWidget(self.vuln_table)
        
        # Vulnerability details
        details_group = QGroupBox("Vulnerability Details")
        details_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        details_layout = QVBoxLayout(details_group)
        
        self.vuln_details = QTextEdit()
        self.vuln_details.setReadOnly(True)
        self.vuln_details.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                padding: 12px;
            }
        """)
        self.vuln_details.setPlaceholderText("Select a vulnerability to view details...")
        
        details_layout.addWidget(self.vuln_details)
        
        layout.addWidget(details_group)
        
        return widget
    
    def _create_protocol_tab(self) -> QWidget:
        """Create protocol analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Protocol breakdown
        info_label = QLabel(
            "Protocol analysis provides deep inspection of ICS communication patterns "
            "and security weaknesses in each protocol."
        )
        info_label.setStyleSheet("color: #8b949e;")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Protocol tree
        self.protocol_tree = QTreeWidget()
        self.protocol_tree.setHeaderLabels(["Protocol/Feature", "Status", "Security Level"])
        self.protocol_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                color: #e6e6e6;
            }
            QTreeWidget::item {
                padding: 8px;
            }
            QTreeWidget::item:selected {
                background-color: #21262d;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        
        # Add default protocol items
        protocols = [
            ("Modbus TCP", [
                ("Authentication", "Not Supported", "⚠️ Vulnerable"),
                ("Encryption", "Not Supported", "⚠️ Vulnerable"),
                ("Function Codes", "All Allowed", "⚠️ Risky")
            ]),
            ("S7comm", [
                ("Authentication", "Optional", "⚠️ Varies"),
                ("Encryption", "Not Supported", "⚠️ Vulnerable"),
                ("CPU Protection", "Optional", "⚠️ Varies")
            ]),
            ("DNP3", [
                ("Secure Auth", "SAv5 Available", "✅ Available"),
                ("Encryption", "TLS Available", "✅ Available"),
                ("Link Layer", "Basic", "⚠️ Limited")
            ]),
            ("OPC UA", [
                ("Authentication", "Supported", "✅ Secure"),
                ("Encryption", "Supported", "✅ Secure"),
                ("Certificates", "X.509", "✅ Secure")
            ])
        ]
        
        for proto_name, features in protocols:
            proto_item = QTreeWidgetItem([proto_name, "", ""])
            for feature, status, security in features:
                child = QTreeWidgetItem([feature, status, security])
                proto_item.addChild(child)
            self.protocol_tree.addTopLevelItem(proto_item)
            proto_item.setExpanded(True)
        
        layout.addWidget(self.protocol_tree, stretch=1)
        
        return widget
    
    def _create_topology_tab(self) -> QWidget:
        """Create network topology tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Topology visualization
        self.topology_widget = NetworkTopologyWidget()
        layout.addWidget(self.topology_widget, stretch=1)
        
        # Legend
        legend_layout = QHBoxLayout()
        legend_layout.addWidget(QLabel("Legend:"))
        
        legend_items = [
            ("🔴 PLC", "#f85149"),
            ("🟠 HMI", "#ffa657"),
            ("🟣 SCADA Server", "#a371f7"),
            ("🟢 Field Device", "#3fb950")
        ]
        
        for text, color in legend_items:
            label = QLabel(text)
            label.setStyleSheet(f"color: {color}; margin-left: 20px;")
            legend_layout.addWidget(label)
        
        legend_layout.addStretch()
        layout.addLayout(legend_layout)
        
        return widget
    
    def _create_compliance_tab(self) -> QWidget:
        """Create compliance check tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Compliance frameworks
        info = QLabel(
            "Check your ICS environment against industry security standards and compliance frameworks."
        )
        info.setStyleSheet("color: #8b949e;")
        info.setWordWrap(True)
        layout.addWidget(info)
        
        # Framework selection
        framework_group = QGroupBox("Compliance Frameworks")
        framework_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #e6e6e6;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
            }
        """)
        
        framework_layout = QVBoxLayout(framework_group)
        
        frameworks = [
            ("NIST CSF", "NIST Cybersecurity Framework for Critical Infrastructure"),
            ("IEC 62443", "Industrial Automation and Control Systems Security"),
            ("NERC CIP", "North American Electric Reliability Corporation CIP"),
            ("ICS-CERT", "ICS-CERT Security Advisories and Recommendations"),
            ("ISO 27001", "Information Security Management (OT Extension)")
        ]
        
        self.framework_checks = {}
        for fw_id, fw_desc in frameworks:
            cb = QCheckBox(f"{fw_id} - {fw_desc}")
            cb.setStyleSheet("color: #e6e6e6;")
            self.framework_checks[fw_id] = cb
            framework_layout.addWidget(cb)
        
        layout.addWidget(framework_group)
        
        # Compliance results
        self.compliance_tree = QTreeWidget()
        self.compliance_tree.setHeaderLabels(["Control", "Status", "Finding"])
        self.compliance_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 8px;
                color: #e6e6e6;
            }
            QTreeWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 10px;
                border: none;
            }
        """)
        
        layout.addWidget(self.compliance_tree, stretch=1)
        
        # Run compliance check button
        check_btn = QPushButton("🔍 Run Compliance Check")
        check_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
        """)
        layout.addWidget(check_btn, alignment=Qt.AlignmentFlag.AlignRight)
        
        return widget
    
    def _start_scan(self):
        """Start SCADA scan"""
        if not SCADA_AVAILABLE:
            QMessageBox.warning(self, "Error", "SCADA security module not available")
            return
        
        target = self.network_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target network")
            return
        
        scan_type = "discovery" if self.scan_type.currentIndex() == 0 else "full"
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        
        self.scan_worker = ScanWorker(self.engine, target, scan_type)
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.finished.connect(self._on_scan_finished)
        self.scan_worker.error.connect(self._on_scan_error)
        self.scan_worker.start()
    
    def _stop_scan(self):
        """Stop ongoing scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.terminate()
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Scan stopped")
    
    def _on_scan_progress(self, message: str, progress: float):
        """Handle scan progress update"""
        self.status_label.setText(message)
        self.progress_bar.setValue(int(progress))
    
    def _on_scan_finished(self, result):
        """Handle scan completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Scan complete")
        self.progress_bar.setValue(100)
        
        if isinstance(result, list):
            # Discovery result (list of devices)
            self._populate_devices_table(result)
            self.topology_widget.set_devices(result)
            self._update_stats(devices=result)
        elif isinstance(result, SCADAScanResult):
            # Full assessment result
            self.current_result = result
            self._populate_devices_table(result.devices)
            self._populate_vuln_table(result.vulnerabilities)
            self.topology_widget.set_devices(result.devices)
            self._update_stats(result=result)
    
    def _on_scan_error(self, error: str):
        """Handle scan error"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText(f"Error: {error}")
        QMessageBox.critical(self, "Scan Error", error)
    
    def _populate_devices_table(self, devices):
        """Populate devices table"""
        self.devices_table.setRowCount(len(devices))
        
        for row, device in enumerate(devices):
            self.devices_table.setItem(row, 0, QTableWidgetItem(device.ip))
            self.devices_table.setItem(row, 1, QTableWidgetItem(str(device.port)))
            self.devices_table.setItem(row, 2, QTableWidgetItem(device.protocol.value))
            self.devices_table.setItem(row, 3, QTableWidgetItem(device.device_type.value))
            self.devices_table.setItem(row, 4, QTableWidgetItem(device.vendor))
            self.devices_table.setItem(row, 5, QTableWidgetItem(device.model))
            self.devices_table.setItem(row, 6, 
                QTableWidgetItem(str(len(device.vulnerabilities))))
    
    def _populate_vuln_table(self, vulns):
        """Populate vulnerability table"""
        self.vuln_table.setRowCount(len(vulns))
        
        severity_colors = {
            VulnerabilitySeverity.CRITICAL: "#f85149",
            VulnerabilitySeverity.HIGH: "#ffa657",
            VulnerabilitySeverity.MEDIUM: "#d29922",
            VulnerabilitySeverity.LOW: "#3fb950",
            VulnerabilitySeverity.INFO: "#8b949e"
        }
        
        for row, vuln in enumerate(vulns):
            self.vuln_table.setItem(row, 0, QTableWidgetItem(vuln.vulnerability_id))
            self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln.title))
            
            severity_item = QTableWidgetItem(vuln.severity.value.upper())
            severity_item.setForeground(QColor(severity_colors.get(vuln.severity, "#8b949e")))
            self.vuln_table.setItem(row, 2, severity_item)
            
            self.vuln_table.setItem(row, 3, QTableWidgetItem(vuln.protocol.value))
            
            device_info = vuln.affected_device.ip if vuln.affected_device else "N/A"
            self.vuln_table.setItem(row, 4, QTableWidgetItem(device_info))
            
            self.vuln_table.setItem(row, 5, QTableWidgetItem(str(vuln.cvss_score)))
    
    def _on_vuln_selected(self):
        """Handle vulnerability selection"""
        if not self.current_result:
            return
        
        selected = self.vuln_table.selectedItems()
        if not selected:
            return
        
        row = selected[0].row()
        if row < len(self.current_result.vulnerabilities):
            vuln = self.current_result.vulnerabilities[row]
            
            details = f"""<h3 style="color: #e6e6e6;">{vuln.title}</h3>
            <p><b>ID:</b> {vuln.vulnerability_id}</p>
            <p><b>Severity:</b> {vuln.severity.value.upper()}</p>
            <p><b>Protocol:</b> {vuln.protocol.value}</p>
            <p><b>CVSS Score:</b> {vuln.cvss_score}</p>
            <hr>
            <p><b>Description:</b><br>{vuln.description}</p>
            <p><b>Impact:</b><br>{vuln.impact}</p>
            <p><b>Remediation:</b><br>{vuln.remediation}</p>
            """
            
            self.vuln_details.setHtml(details)
    
    def _update_stats(self, devices=None, result=None):
        """Update statistics display"""
        if result:
            device_count = len(result.devices)
            vuln_count = len(result.vulnerabilities)
            risk = f"{result.risk_score:.0f}%"
        elif devices:
            device_count = len(devices)
            vuln_count = sum(len(d.vulnerabilities) for d in devices)
            risk = "N/A"
        else:
            return
        
        self.stat_devices.findChild(QLabel, "value").setText(str(device_count))
        self.stat_vulns.findChild(QLabel, "value").setText(str(vuln_count))
        self.stat_risk.findChild(QLabel, "value").setText(risk)
