"""
Wireless Attacks Page
Advanced WiFi reconnaissance and attack interface
"""

import asyncio
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QComboBox,
    QSpinBox, QGroupBox, QTextEdit, QLineEdit, QProgressBar,
    QSplitter, QFrame, QHeaderView, QCheckBox, QMessageBox,
    QFileDialog, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QColor, QFont

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.wireless_attacks import (
    WirelessAttacks, AccessPoint, Client, Handshake,
    SecurityType, AttackType
)


class WirelessWorker(QThread):
    """Background worker for wireless operations"""
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


class WirelessAttacksPage(QWidget):
    """Wireless Attacks GUI Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.wireless = WirelessAttacks()
        self.current_interface = None
        self.monitor_interface = None
        self.scanning = False
        self.workers = []
        
        self.setup_ui()
        self.refresh_interfaces()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("🛜 Wireless Attack Framework")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #00d4ff;
            padding: 10px;
        """)
        layout.addWidget(header)
        
        # Interface Selection
        interface_group = QGroupBox("Interface Configuration")
        interface_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #00d4ff;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #00d4ff;
            }
        """)
        interface_layout = QHBoxLayout(interface_group)
        
        interface_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(150)
        interface_layout.addWidget(self.interface_combo)
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_interfaces)
        interface_layout.addWidget(self.refresh_btn)
        
        self.monitor_btn = QPushButton("📡 Enable Monitor Mode")
        self.monitor_btn.clicked.connect(self.toggle_monitor_mode)
        self.monitor_btn.setStyleSheet("""
            QPushButton {
                background: #ff6b00;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background: #ff8533;
            }
        """)
        interface_layout.addWidget(self.monitor_btn)
        
        self.interface_status = QLabel("Status: Not Ready")
        self.interface_status.setStyleSheet("color: #ff4444;")
        interface_layout.addWidget(self.interface_status)
        
        interface_layout.addStretch()
        layout.addWidget(interface_group)
        
        # Main content tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
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
                background: #00d4ff;
                color: #000;
            }
        """)
        
        # Scanner Tab
        tabs.addTab(self.create_scanner_tab(), "📶 Network Scanner")
        
        # Attacks Tab
        tabs.addTab(self.create_attacks_tab(), "⚔️ Attacks")
        
        # Handshakes Tab
        tabs.addTab(self.create_handshakes_tab(), "🤝 Handshakes")
        
        # Clients Tab
        tabs.addTab(self.create_clients_tab(), "👥 Clients")
        
        layout.addWidget(tabs)
        
        # Status bar
        self.status_bar = QLabel("Ready")
        self.status_bar.setStyleSheet("""
            background: #1a1a2e;
            padding: 8px;
            border-radius: 4px;
            color: #00ff88;
        """)
        layout.addWidget(self.status_bar)
    
    def create_scanner_tab(self):
        """Create network scanner tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Scan controls
        controls = QHBoxLayout()
        
        controls.addWidget(QLabel("Channel:"))
        self.channel_spin = QSpinBox()
        self.channel_spin.setRange(0, 165)
        self.channel_spin.setValue(0)
        self.channel_spin.setSpecialValueText("All")
        controls.addWidget(self.channel_spin)
        
        controls.addWidget(QLabel("Duration:"))
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(5, 300)
        self.duration_spin.setValue(30)
        self.duration_spin.setSuffix(" sec")
        controls.addWidget(self.duration_spin)
        
        self.scan_btn = QPushButton("🔍 Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: #00ff88;
                color: #000;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background: #00cc6a;
            }
        """)
        controls.addWidget(self.scan_btn)
        
        self.stop_scan_btn = QPushButton("⏹️ Stop")
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setEnabled(False)
        controls.addWidget(self.stop_scan_btn)
        
        controls.addStretch()
        layout.addLayout(controls)
        
        # Progress
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        layout.addWidget(self.scan_progress)
        
        # Networks table
        self.networks_table = QTableWidget()
        self.networks_table.setColumnCount(10)
        self.networks_table.setHorizontalHeaderLabels([
            "BSSID", "ESSID", "Channel", "Signal", "Security",
            "Cipher", "WPS", "Clients", "Beacons", "Vendor"
        ])
        self.networks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.networks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.networks_table.setAlternatingRowColors(True)
        self.networks_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #333;
                background-color: #0d0d1a;
            }
            QTableWidget::item:selected {
                background-color: #00d4ff;
                color: #000;
            }
        """)
        layout.addWidget(self.networks_table)
        
        # Stats
        stats_layout = QHBoxLayout()
        self.total_aps = QLabel("Total APs: 0")
        self.open_aps = QLabel("Open: 0")
        self.wep_aps = QLabel("WEP: 0")
        self.wpa_aps = QLabel("WPA/WPA2: 0")
        self.wps_aps = QLabel("WPS Enabled: 0")
        
        for label in [self.total_aps, self.open_aps, self.wep_aps, self.wpa_aps, self.wps_aps]:
            label.setStyleSheet("padding: 5px; background: #1a1a2e; border-radius: 4px;")
            stats_layout.addWidget(label)
        
        stats_layout.addStretch()
        layout.addLayout(stats_layout)
        
        return widget
    
    def create_attacks_tab(self):
        """Create attacks tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Attack type selection
        type_group = QGroupBox("Attack Configuration")
        type_layout = QVBoxLayout(type_group)
        
        # Target selection
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target BSSID:"))
        self.target_bssid = QLineEdit()
        self.target_bssid.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        target_layout.addWidget(self.target_bssid)
        
        target_layout.addWidget(QLabel("Channel:"))
        self.attack_channel = QSpinBox()
        self.attack_channel.setRange(1, 165)
        target_layout.addWidget(self.attack_channel)
        
        self.use_selected_btn = QPushButton("Use Selected AP")
        self.use_selected_btn.clicked.connect(self.use_selected_ap)
        target_layout.addWidget(self.use_selected_btn)
        
        type_layout.addLayout(target_layout)
        
        # Client selection
        client_layout = QHBoxLayout()
        client_layout.addWidget(QLabel("Client MAC:"))
        self.target_client = QLineEdit()
        self.target_client.setPlaceholderText("FF:FF:FF:FF:FF:FF (broadcast)")
        self.target_client.setText("FF:FF:FF:FF:FF:FF")
        client_layout.addWidget(self.target_client)
        type_layout.addLayout(client_layout)
        
        layout.addWidget(type_group)
        
        # Attack buttons grid
        attacks_group = QGroupBox("Available Attacks")
        attacks_layout = QHBoxLayout(attacks_group)
        
        # Deauth Attack
        deauth_frame = QFrame()
        deauth_frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border: 2px solid #ff4444;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        deauth_layout = QVBoxLayout(deauth_frame)
        deauth_layout.addWidget(QLabel("💀 Deauthentication Attack"))
        
        deauth_opts = QHBoxLayout()
        deauth_opts.addWidget(QLabel("Packets:"))
        self.deauth_packets = QSpinBox()
        self.deauth_packets.setRange(1, 10000)
        self.deauth_packets.setValue(100)
        deauth_opts.addWidget(self.deauth_packets)
        deauth_layout.addLayout(deauth_opts)
        
        self.deauth_btn = QPushButton("Send Deauth")
        self.deauth_btn.clicked.connect(self.send_deauth)
        self.deauth_btn.setStyleSheet("background: #ff4444; color: white;")
        deauth_layout.addWidget(self.deauth_btn)
        attacks_layout.addWidget(deauth_frame)
        
        # Handshake Capture
        handshake_frame = QFrame()
        handshake_frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border: 2px solid #00ff88;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        handshake_layout = QVBoxLayout(handshake_frame)
        handshake_layout.addWidget(QLabel("🤝 Handshake Capture"))
        
        handshake_opts = QHBoxLayout()
        handshake_opts.addWidget(QLabel("Timeout:"))
        self.handshake_timeout = QSpinBox()
        self.handshake_timeout.setRange(10, 300)
        self.handshake_timeout.setValue(60)
        self.handshake_timeout.setSuffix(" sec")
        handshake_opts.addWidget(self.handshake_timeout)
        handshake_layout.addLayout(handshake_opts)
        
        self.auto_deauth = QCheckBox("Auto Deauth")
        self.auto_deauth.setChecked(True)
        handshake_layout.addWidget(self.auto_deauth)
        
        self.capture_handshake_btn = QPushButton("Capture Handshake")
        self.capture_handshake_btn.clicked.connect(self.capture_handshake)
        self.capture_handshake_btn.setStyleSheet("background: #00ff88; color: black;")
        handshake_layout.addWidget(self.capture_handshake_btn)
        attacks_layout.addWidget(handshake_frame)
        
        # PMKID Capture
        pmkid_frame = QFrame()
        pmkid_frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border: 2px solid #00d4ff;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        pmkid_layout = QVBoxLayout(pmkid_frame)
        pmkid_layout.addWidget(QLabel("🔑 PMKID Capture"))
        pmkid_layout.addWidget(QLabel("(Clientless attack)"))
        
        self.pmkid_btn = QPushButton("Capture PMKID")
        self.pmkid_btn.clicked.connect(self.capture_pmkid)
        self.pmkid_btn.setStyleSheet("background: #00d4ff; color: black;")
        pmkid_layout.addWidget(self.pmkid_btn)
        attacks_layout.addWidget(pmkid_frame)
        
        # WPS Attack
        wps_frame = QFrame()
        wps_frame.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border: 2px solid #ff6b00;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        wps_layout = QVBoxLayout(wps_frame)
        wps_layout.addWidget(QLabel("📍 WPS Attack"))
        
        wps_method = QHBoxLayout()
        wps_method.addWidget(QLabel("Method:"))
        self.wps_method = QComboBox()
        self.wps_method.addItems(["reaver", "bully"])
        wps_method.addWidget(self.wps_method)
        wps_layout.addLayout(wps_method)
        
        self.wps_btn = QPushButton("Start WPS Attack")
        self.wps_btn.clicked.connect(self.wps_attack)
        self.wps_btn.setStyleSheet("background: #ff6b00; color: white;")
        wps_layout.addWidget(self.wps_btn)
        attacks_layout.addWidget(wps_frame)
        
        layout.addWidget(attacks_group)
        
        # Attack log
        log_group = QGroupBox("Attack Log")
        log_layout = QVBoxLayout(log_group)
        self.attack_log = QTextEdit()
        self.attack_log.setReadOnly(True)
        self.attack_log.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                color: #00ff88;
                font-family: 'Consolas', 'Monaco', monospace;
                border: 1px solid #333;
            }
        """)
        log_layout.addWidget(self.attack_log)
        layout.addWidget(log_group)
        
        return widget
    
    def create_handshakes_tab(self):
        """Create handshakes management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Handshakes table
        self.handshakes_table = QTableWidget()
        self.handshakes_table.setColumnCount(6)
        self.handshakes_table.setHorizontalHeaderLabels([
            "BSSID", "ESSID", "Client", "Capture Time", "File", "Status"
        ])
        self.handshakes_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.handshakes_table)
        
        # Cracking section
        crack_group = QGroupBox("Crack Handshake")
        crack_layout = QVBoxLayout(crack_group)
        
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(QLabel("Wordlist:"))
        self.wordlist_path = QLineEdit()
        self.wordlist_path.setPlaceholderText("/usr/share/wordlists/rockyou.txt")
        wordlist_layout.addWidget(self.wordlist_path)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_wordlist)
        wordlist_layout.addWidget(browse_btn)
        crack_layout.addLayout(wordlist_layout)
        
        crack_buttons = QHBoxLayout()
        self.crack_btn = QPushButton("🔓 Crack with Aircrack-ng")
        self.crack_btn.clicked.connect(self.crack_handshake)
        self.crack_btn.setStyleSheet("background: #ff6b00; color: white; padding: 10px;")
        crack_buttons.addWidget(self.crack_btn)
        
        self.hashcat_btn = QPushButton("🐱 Send to Hashcat")
        self.hashcat_btn.clicked.connect(self.send_to_hashcat)
        crack_buttons.addWidget(self.hashcat_btn)
        crack_layout.addLayout(crack_buttons)
        
        layout.addWidget(crack_group)
        
        # Results
        results_group = QGroupBox("Cracking Results")
        results_layout = QVBoxLayout(results_group)
        self.crack_results = QTextEdit()
        self.crack_results.setReadOnly(True)
        self.crack_results.setMaximumHeight(150)
        results_layout.addWidget(self.crack_results)
        layout.addWidget(results_group)
        
        return widget
    
    def create_clients_tab(self):
        """Create clients monitoring tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Clients table
        self.clients_table = QTableWidget()
        self.clients_table.setColumnCount(7)
        self.clients_table.setHorizontalHeaderLabels([
            "MAC", "Associated AP", "Signal", "Packets", "Probes", "Vendor", "First Seen"
        ])
        self.clients_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.clients_table)
        
        # Probe requests
        probe_group = QGroupBox("Probe Request Sniffer")
        probe_layout = QVBoxLayout(probe_group)
        
        probe_controls = QHBoxLayout()
        probe_controls.addWidget(QLabel("Duration:"))
        self.probe_duration = QSpinBox()
        self.probe_duration.setRange(10, 300)
        self.probe_duration.setValue(60)
        self.probe_duration.setSuffix(" sec")
        probe_controls.addWidget(self.probe_duration)
        
        self.probe_btn = QPushButton("📡 Sniff Probes")
        self.probe_btn.clicked.connect(self.sniff_probes)
        probe_controls.addWidget(self.probe_btn)
        probe_controls.addStretch()
        probe_layout.addLayout(probe_controls)
        
        self.probe_list = QListWidget()
        self.probe_list.setStyleSheet("""
            QListWidget {
                background: #0d0d1a;
                border: 1px solid #333;
            }
            QListWidget::item {
                padding: 5px;
            }
        """)
        probe_layout.addWidget(self.probe_list)
        layout.addWidget(probe_group)
        
        return widget
    
    def refresh_interfaces(self):
        """Refresh list of wireless interfaces"""
        self.interface_combo.clear()
        
        worker = WirelessWorker(self.wireless.get_interfaces)
        worker.result_ready.connect(self.on_interfaces_loaded)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def on_interfaces_loaded(self, interfaces):
        """Handle loaded interfaces"""
        for iface in interfaces:
            mode = iface.get('mode', 'unknown')
            text = f"{iface['name']} ({mode})"
            self.interface_combo.addItem(text, iface)
        
        if interfaces:
            self.interface_status.setText("Status: Ready")
            self.interface_status.setStyleSheet("color: #00ff88;")
    
    def toggle_monitor_mode(self):
        """Toggle monitor mode on selected interface"""
        if self.interface_combo.currentIndex() < 0:
            return
        
        iface = self.interface_combo.currentData()
        if not iface:
            return
        
        if iface.get('mode') == 'monitor':
            # Disable monitor mode
            worker = WirelessWorker(self.wireless.disable_monitor_mode, iface['name'])
            worker.result_ready.connect(lambda x: self.on_monitor_disabled())
            worker.error.connect(self.on_error)
            worker.start()
            self.workers.append(worker)
        else:
            # Enable monitor mode
            worker = WirelessWorker(self.wireless.enable_monitor_mode, iface['name'])
            worker.result_ready.connect(self.on_monitor_enabled)
            worker.error.connect(self.on_error)
            worker.start()
            self.workers.append(worker)
        
        self.status_bar.setText("Changing interface mode...")
    
    def on_monitor_enabled(self, mon_interface):
        """Handle monitor mode enabled"""
        if mon_interface:
            self.monitor_interface = mon_interface
            self.monitor_btn.setText("📡 Disable Monitor Mode")
            self.interface_status.setText(f"Status: Monitor Mode ({mon_interface})")
            self.interface_status.setStyleSheet("color: #00ff88;")
            self.status_bar.setText(f"Monitor mode enabled on {mon_interface}")
            self.refresh_interfaces()
    
    def on_monitor_disabled(self):
        """Handle monitor mode disabled"""
        self.monitor_interface = None
        self.monitor_btn.setText("📡 Enable Monitor Mode")
        self.interface_status.setText("Status: Managed Mode")
        self.status_bar.setText("Monitor mode disabled")
        self.refresh_interfaces()
    
    def start_scan(self):
        """Start network scanning"""
        iface = self.interface_combo.currentData()
        if not iface:
            QMessageBox.warning(self, "Error", "No interface selected")
            return
        
        interface_name = self.monitor_interface or iface['name']
        channel = self.channel_spin.value()
        duration = self.duration_spin.value()
        
        self.scanning = True
        self.scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.scan_progress.setVisible(True)
        self.scan_progress.setRange(0, 0)  # Indeterminate
        
        self.status_bar.setText(f"Scanning on {interface_name}...")
        
        worker = WirelessWorker(
            self.wireless.scan_networks,
            interface_name,
            duration,
            channel
        )
        worker.result_ready.connect(self.on_scan_complete)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def stop_scan(self):
        """Stop scanning"""
        self.scanning = False
        self.scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.scan_progress.setVisible(False)
    
    def on_scan_complete(self, result):
        """Handle scan completion"""
        self.stop_scan()
        
        # Update networks table
        self.networks_table.setRowCount(len(result.access_points))
        
        security_counts = {'open': 0, 'wep': 0, 'wpa': 0, 'wps': 0}
        
        for row, ap in enumerate(result.access_points):
            self.networks_table.setItem(row, 0, QTableWidgetItem(ap.bssid))
            self.networks_table.setItem(row, 1, QTableWidgetItem(ap.essid or "<hidden>"))
            self.networks_table.setItem(row, 2, QTableWidgetItem(str(ap.channel)))
            
            # Signal strength with color
            signal_item = QTableWidgetItem(f"{ap.signal_strength} dBm")
            if ap.signal_strength > -50:
                signal_item.setBackground(QColor("#00ff88"))
            elif ap.signal_strength > -70:
                signal_item.setBackground(QColor("#ffff00"))
            else:
                signal_item.setBackground(QColor("#ff4444"))
            self.networks_table.setItem(row, 3, signal_item)
            
            # Security with color
            sec_item = QTableWidgetItem(ap.security.value.upper())
            if ap.security == SecurityType.OPEN:
                sec_item.setBackground(QColor("#ff4444"))
                security_counts['open'] += 1
            elif ap.security == SecurityType.WEP:
                sec_item.setBackground(QColor("#ff6b00"))
                security_counts['wep'] += 1
            else:
                sec_item.setBackground(QColor("#00ff88"))
                security_counts['wpa'] += 1
            self.networks_table.setItem(row, 4, sec_item)
            
            self.networks_table.setItem(row, 5, QTableWidgetItem(ap.cipher))
            
            wps_item = QTableWidgetItem("Yes" if ap.wps_enabled else "No")
            if ap.wps_enabled:
                wps_item.setBackground(QColor("#ff6b00"))
                security_counts['wps'] += 1
            self.networks_table.setItem(row, 6, wps_item)
            
            self.networks_table.setItem(row, 7, QTableWidgetItem(str(len(ap.clients))))
            self.networks_table.setItem(row, 8, QTableWidgetItem(str(ap.beacons)))
            self.networks_table.setItem(row, 9, QTableWidgetItem(ap.vendor))
        
        # Update clients table
        self.clients_table.setRowCount(len(result.clients))
        for row, client in enumerate(result.clients):
            self.clients_table.setItem(row, 0, QTableWidgetItem(client.mac))
            self.clients_table.setItem(row, 1, QTableWidgetItem(client.bssid))
            self.clients_table.setItem(row, 2, QTableWidgetItem(f"{client.signal_strength} dBm"))
            self.clients_table.setItem(row, 3, QTableWidgetItem(str(client.packets)))
            self.clients_table.setItem(row, 4, QTableWidgetItem(", ".join(client.probes[:3])))
            self.clients_table.setItem(row, 5, QTableWidgetItem(client.vendor))
            self.clients_table.setItem(row, 6, QTableWidgetItem(client.first_seen.strftime("%H:%M:%S")))
        
        # Update stats
        total = len(result.access_points)
        self.total_aps.setText(f"Total APs: {total}")
        self.open_aps.setText(f"Open: {security_counts['open']}")
        self.wep_aps.setText(f"WEP: {security_counts['wep']}")
        self.wpa_aps.setText(f"WPA/WPA2: {security_counts['wpa']}")
        self.wps_aps.setText(f"WPS Enabled: {security_counts['wps']}")
        
        self.status_bar.setText(f"Scan complete: {total} networks, {len(result.clients)} clients")
    
    def use_selected_ap(self):
        """Use selected AP from table"""
        row = self.networks_table.currentRow()
        if row >= 0:
            bssid = self.networks_table.item(row, 0).text()
            channel = self.networks_table.item(row, 2).text()
            self.target_bssid.setText(bssid)
            self.attack_channel.setValue(int(channel))
    
    def send_deauth(self):
        """Send deauthentication attack"""
        if not self.validate_attack_params():
            return
        
        interface = self.monitor_interface or self.interface_combo.currentData()['name']
        bssid = self.target_bssid.text()
        client = self.target_client.text() or "FF:FF:FF:FF:FF:FF"
        packets = self.deauth_packets.value()
        channel = self.attack_channel.value()
        
        self.log_attack(f"Sending {packets} deauth packets to {bssid} (client: {client})")
        
        worker = WirelessWorker(
            self.wireless.deauth_attack,
            interface, bssid, client, packets, channel
        )
        worker.result_ready.connect(lambda x: self.log_attack("Deauth attack completed"))
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def capture_handshake(self):
        """Capture WPA handshake"""
        if not self.validate_attack_params():
            return
        
        interface = self.monitor_interface or self.interface_combo.currentData()['name']
        bssid = self.target_bssid.text()
        channel = self.attack_channel.value()
        timeout = self.handshake_timeout.value()
        deauth = self.auto_deauth.isChecked()
        
        # Get ESSID from table if available
        essid = ""
        row = self.networks_table.currentRow()
        if row >= 0:
            essid = self.networks_table.item(row, 1).text()
        
        self.log_attack(f"Starting handshake capture for {bssid} ({essid})")
        
        worker = WirelessWorker(
            self.wireless.capture_handshake,
            interface, bssid, essid, channel, timeout, deauth
        )
        worker.result_ready.connect(self.on_handshake_captured)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def on_handshake_captured(self, handshake):
        """Handle captured handshake"""
        if handshake:
            self.log_attack(f"✅ Handshake captured! File: {handshake.capture_file}")
            
            # Add to table
            row = self.handshakes_table.rowCount()
            self.handshakes_table.insertRow(row)
            self.handshakes_table.setItem(row, 0, QTableWidgetItem(handshake.bssid))
            self.handshakes_table.setItem(row, 1, QTableWidgetItem(handshake.essid))
            self.handshakes_table.setItem(row, 2, QTableWidgetItem(handshake.client_mac))
            self.handshakes_table.setItem(row, 3, QTableWidgetItem(
                handshake.capture_time.strftime("%Y-%m-%d %H:%M:%S")
            ))
            self.handshakes_table.setItem(row, 4, QTableWidgetItem(handshake.capture_file))
            
            status_item = QTableWidgetItem("Complete" if handshake.is_complete else "Partial")
            status_item.setBackground(QColor("#00ff88" if handshake.is_complete else "#ffff00"))
            self.handshakes_table.setItem(row, 5, status_item)
        else:
            self.log_attack("❌ Failed to capture handshake")
    
    def capture_pmkid(self):
        """Capture PMKID"""
        if not self.validate_attack_params():
            return
        
        interface = self.monitor_interface or self.interface_combo.currentData()['name']
        bssid = self.target_bssid.text()
        channel = self.attack_channel.value()
        
        self.log_attack(f"Starting PMKID capture for {bssid}")
        
        worker = WirelessWorker(
            self.wireless.capture_pmkid,
            interface, bssid, channel
        )
        worker.result_ready.connect(self.on_pmkid_captured)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def on_pmkid_captured(self, hash_file):
        """Handle captured PMKID"""
        if hash_file:
            self.log_attack(f"✅ PMKID captured! Hash file: {hash_file}")
            self.crack_results.append(f"PMKID hash saved to: {hash_file}")
        else:
            self.log_attack("❌ Failed to capture PMKID")
    
    def wps_attack(self):
        """Start WPS attack"""
        if not self.validate_attack_params():
            return
        
        interface = self.monitor_interface or self.interface_combo.currentData()['name']
        bssid = self.target_bssid.text()
        method = self.wps_method.currentText()
        
        self.log_attack(f"Starting WPS attack on {bssid} using {method}")
        
        worker = WirelessWorker(
            self.wireless.wps_attack,
            interface, bssid, method
        )
        worker.result_ready.connect(self.on_wps_result)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def on_wps_result(self, result):
        """Handle WPS attack result"""
        if result:
            self.log_attack(f"✅ WPS Attack successful! Key: {result}")
            self.crack_results.append(f"WPS Key found: {result}")
        else:
            self.log_attack("❌ WPS attack failed or WPS locked")
    
    def browse_wordlist(self):
        """Browse for wordlist file"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", "/usr/share/wordlists",
            "Text Files (*.txt);;All Files (*)"
        )
        if filepath:
            self.wordlist_path.setText(filepath)
    
    def crack_handshake(self):
        """Crack selected handshake"""
        row = self.handshakes_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Error", "Select a handshake to crack")
            return
        
        capture_file = self.handshakes_table.item(row, 4).text()
        essid = self.handshakes_table.item(row, 1).text()
        wordlist = self.wordlist_path.text()
        
        if not wordlist:
            QMessageBox.warning(self, "Error", "Select a wordlist")
            return
        
        self.crack_results.append(f"Starting crack attempt on {essid}...")
        
        worker = WirelessWorker(
            self.wireless.crack_handshake,
            capture_file, wordlist, essid
        )
        worker.result_ready.connect(self.on_crack_result)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def on_crack_result(self, key):
        """Handle cracking result"""
        if key:
            self.crack_results.append(f"✅ KEY FOUND: {key}")
            QMessageBox.information(self, "Success", f"Password found: {key}")
        else:
            self.crack_results.append("❌ Key not found in wordlist")
    
    def send_to_hashcat(self):
        """Export handshake for hashcat"""
        row = self.handshakes_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Error", "Select a handshake")
            return
        
        capture_file = self.handshakes_table.item(row, 4).text()
        self.crack_results.append(f"Convert with: hcxpcapngtool -o output.22000 {capture_file}")
        self.crack_results.append("Then run: hashcat -m 22000 output.22000 wordlist.txt")
    
    def sniff_probes(self):
        """Sniff probe requests"""
        iface = self.interface_combo.currentData()
        if not iface:
            return
        
        interface = self.monitor_interface or iface['name']
        duration = self.probe_duration.value()
        
        self.probe_list.clear()
        self.status_bar.setText(f"Sniffing probe requests for {duration}s...")
        
        worker = WirelessWorker(
            self.wireless.probe_request_sniff,
            interface, duration
        )
        worker.result_ready.connect(self.on_probes_captured)
        worker.error.connect(self.on_error)
        worker.start()
        self.workers.append(worker)
    
    def on_probes_captured(self, probes):
        """Handle captured probes"""
        for probe in probes:
            item = QListWidgetItem(
                f"📱 {probe['client_mac']} ({probe['vendor']}) → {probe['ssid']}"
            )
            self.probe_list.addItem(item)
        
        self.status_bar.setText(f"Captured {len(probes)} probe requests")
    
    def validate_attack_params(self) -> bool:
        """Validate attack parameters"""
        if not self.target_bssid.text():
            QMessageBox.warning(self, "Error", "Target BSSID required")
            return False
        
        if not self.monitor_interface:
            iface = self.interface_combo.currentData()
            if not iface or iface.get('mode') != 'monitor':
                QMessageBox.warning(self, "Error", "Enable monitor mode first")
                return False
        
        return True
    
    def log_attack(self, message: str):
        """Log attack message"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.attack_log.append(f"[{timestamp}] {message}")
    
    def on_error(self, error: str):
        """Handle errors"""
        self.status_bar.setText(f"Error: {error}")
        self.log_attack(f"❌ Error: {error}")
        QMessageBox.critical(self, "Error", error)
