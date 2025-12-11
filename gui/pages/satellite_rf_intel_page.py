"""
Satellite & RF Intelligence GUI Page
Signal intelligence, spectrum analysis, and satellite tracking.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTextEdit, QLineEdit, QComboBox, QProgressBar, QTabWidget,
    QGroupBox, QSpinBox, QCheckBox, QSplitter, QGridLayout,
    QListWidget, QSlider, QDoubleSpinBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from datetime import datetime
import random


class SignalScanWorker(QThread):
    """Worker for signal scanning"""
    progress = pyqtSignal(int)
    signal_found = pyqtSignal(dict)
    result = pyqtSignal(dict)
    finished = pyqtSignal()
    
    def __init__(self, engine, freq_range, mode):
        super().__init__()
        self.engine = engine
        self.freq_range = freq_range
        self.mode = mode
    
    def run(self):
        try:
            signals = []
            for i in range(100):
                self.progress.emit(i + 1)
                if i % 10 == 0:
                    signal = {
                        "freq": f"{random.uniform(100, 900):.2f} MHz",
                        "strength": random.randint(-80, -20)
                    }
                    self.signal_found.emit(signal)
                    signals.append(signal)
                self.msleep(30)
            
            self.result.emit({
                "status": "completed",
                "signals_found": len(signals)
            })
        except Exception as e:
            self.result.emit({"error": str(e)})
        finally:
            self.finished.emit()


class SatelliteRFIntelPage(QWidget):
    """Satellite & RF Intelligence GUI"""
    
    def __init__(self, config, db):
        super().__init__()
        self.config = config
        self.db = db
        self.engine = None
        self.worker = None
        
        self._init_engine()
        self._setup_ui()
        self._apply_styles()
        self._start_demo_updates()
    
    def _init_engine(self):
        """Initialize RF intel engine"""
        try:
            from core.satellite_rf_intel import SatelliteRFIntelEngine
            self.engine = SatelliteRFIntelEngine()
        except ImportError:
            self.engine = None
    
    def _setup_ui(self):
        """Setup user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main tabs
        tabs = QTabWidget()
        tabs.setObjectName("rfTabs")
        
        tabs.addTab(self._create_spectrum_tab(), "📡 Spectrum Analysis")
        tabs.addTab(self._create_satellite_tab(), "🛰️ Satellite Tracking")
        tabs.addTab(self._create_signals_tab(), "📶 Signal Detection")
        tabs.addTab(self._create_decode_tab(), "🔓 Signal Decoding")
        tabs.addTab(self._create_emitter_tab(), "📍 Emitter Location")
        
        layout.addWidget(tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setObjectName("headerFrame")
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("📡 Satellite & RF Intelligence")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #1abc9c;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Signal intelligence, spectrum analysis, and satellite tracking")
        subtitle.setStyleSheet("color: #888; font-size: 12px;")
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Live indicators
        indicators = QHBoxLayout()
        
        self.sdr_status = QLabel("● SDR: Ready")
        self.sdr_status.setStyleSheet("color: #00ff88; font-size: 11px;")
        indicators.addWidget(self.sdr_status)
        
        self.scan_status = QLabel("● Idle")
        self.scan_status.setStyleSheet("color: #888; font-size: 11px;")
        indicators.addWidget(self.scan_status)
        
        layout.addLayout(indicators)
        
        # Action button
        self.scan_btn = QPushButton("📡 Start Scan")
        self.scan_btn.setObjectName("primaryButton")
        self.scan_btn.setCheckable(True)
        self.scan_btn.clicked.connect(self._toggle_scan)
        layout.addWidget(self.scan_btn)
        
        return frame
    
    def _create_spectrum_tab(self) -> QWidget:
        """Create spectrum analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Configuration
        config_panel = QFrame()
        config_panel.setObjectName("configPanel")
        config_layout = QVBoxLayout(config_panel)
        
        # SDR settings
        sdr_group = QGroupBox("SDR Configuration")
        sdr_layout = QGridLayout(sdr_group)
        
        sdr_layout.addWidget(QLabel("Device:"), 0, 0)
        self.sdr_device = QComboBox()
        self.sdr_device.addItems([
            "RTL-SDR (Generic)",
            "HackRF One",
            "USRP B200",
            "BladeRF x40",
            "Airspy Mini"
        ])
        sdr_layout.addWidget(self.sdr_device, 0, 1)
        
        sdr_layout.addWidget(QLabel("Center Freq (MHz):"), 1, 0)
        self.center_freq = QDoubleSpinBox()
        self.center_freq.setRange(1, 6000)
        self.center_freq.setValue(433.92)
        sdr_layout.addWidget(self.center_freq, 1, 1)
        
        sdr_layout.addWidget(QLabel("Bandwidth (MHz):"), 2, 0)
        self.bandwidth = QDoubleSpinBox()
        self.bandwidth.setRange(0.1, 20)
        self.bandwidth.setValue(2.0)
        sdr_layout.addWidget(self.bandwidth, 2, 1)
        
        sdr_layout.addWidget(QLabel("Sample Rate (MHz):"), 3, 0)
        self.sample_rate = QDoubleSpinBox()
        self.sample_rate.setRange(0.25, 20)
        self.sample_rate.setValue(2.4)
        sdr_layout.addWidget(self.sample_rate, 3, 1)
        
        sdr_layout.addWidget(QLabel("Gain (dB):"), 4, 0)
        self.gain = QSlider(Qt.Orientation.Horizontal)
        self.gain.setRange(0, 50)
        self.gain.setValue(30)
        sdr_layout.addWidget(self.gain, 4, 1)
        
        config_layout.addWidget(sdr_group)
        
        # Frequency bands
        bands_group = QGroupBox("Quick Bands")
        bands_layout = QVBoxLayout(bands_group)
        
        bands = [
            ("📻 FM Radio", "88-108 MHz"),
            ("✈️ ADS-B", "1090 MHz"),
            ("📟 Pager", "929-930 MHz"),
            ("🚗 Car Keys", "433.92 MHz"),
            ("📱 GSM", "890-960 MHz"),
            ("🛰️ GPS L1", "1575.42 MHz"),
        ]
        
        for name, freq in bands:
            btn = QPushButton(f"{name} ({freq})")
            btn.setProperty("freq", freq)
            bands_layout.addWidget(btn)
        
        config_layout.addWidget(bands_group)
        
        config_layout.addStretch()
        splitter.addWidget(config_panel)
        
        # Right - Spectrum display
        spectrum_panel = QFrame()
        spectrum_panel.setObjectName("spectrumPanel")
        spectrum_layout = QVBoxLayout(spectrum_panel)
        
        spectrum_layout.addWidget(QLabel("Spectrum Waterfall Display"))
        
        # Spectrum visualization placeholder
        self.spectrum_display = QTextEdit()
        self.spectrum_display.setReadOnly(True)
        self.spectrum_display.setStyleSheet("""
            background-color: #000;
            border: 1px solid #0f3460;
            font-family: monospace;
        """)
        self._update_spectrum_display()
        spectrum_layout.addWidget(self.spectrum_display)
        
        # Signal info
        info_layout = QHBoxLayout()
        
        self.freq_label = QLabel("Freq: 433.92 MHz")
        self.freq_label.setStyleSheet("color: #00ff88;")
        info_layout.addWidget(self.freq_label)
        
        self.power_label = QLabel("Power: -45 dBm")
        info_layout.addWidget(self.power_label)
        
        self.snr_label = QLabel("SNR: 23 dB")
        info_layout.addWidget(self.snr_label)
        
        spectrum_layout.addLayout(info_layout)
        
        splitter.addWidget(spectrum_panel)
        splitter.setSizes([350, 650])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_satellite_tab(self) -> QWidget:
        """Create satellite tracking tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Satellite list
        list_panel = QFrame()
        list_panel.setObjectName("listPanel")
        list_layout = QVBoxLayout(list_panel)
        
        list_layout.addWidget(QLabel("Tracked Satellites"))
        
        # Filter
        filter_layout = QHBoxLayout()
        self.sat_filter = QComboBox()
        self.sat_filter.addItems([
            "All Satellites",
            "Amateur Radio",
            "Weather",
            "GPS",
            "Communications",
            "Military",
            "ISS/Space Stations"
        ])
        filter_layout.addWidget(self.sat_filter)
        list_layout.addLayout(filter_layout)
        
        self.sat_list = QListWidget()
        satellites = [
            "🛰️ ISS (ZARYA) - Visible in 12 min",
            "🛰️ NOAA-19 - AOS: 15:42 UTC",
            "🛰️ GPS IIR-M - Overhead",
            "🛰️ Iridium 33 - In range",
            "🛰️ OSCAR 7 - Setting",
            "🛰️ Meteor M2-2 - AOS: 16:15 UTC",
        ]
        for sat in satellites:
            self.sat_list.addItem(sat)
        list_layout.addWidget(self.sat_list)
        
        # TLE update
        tle_btn = QPushButton("🔄 Update TLE Data")
        list_layout.addWidget(tle_btn)
        
        splitter.addWidget(list_panel)
        
        # Right - Tracking display
        track_panel = QFrame()
        track_panel.setObjectName("trackPanel")
        track_layout = QVBoxLayout(track_panel)
        
        track_layout.addWidget(QLabel("Satellite Tracking"))
        
        # Tracking info
        self.track_table = QTableWidget()
        self.track_table.setColumnCount(4)
        self.track_table.setHorizontalHeaderLabels([
            "Parameter", "Value", "Unit", "Status"
        ])
        self.track_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        params = [
            ("Satellite", "ISS (ZARYA)", "", "✅"),
            ("Altitude", "420.5", "km", ""),
            ("Azimuth", "245.3", "°", ""),
            ("Elevation", "42.7", "°", ""),
            ("Range", "687.2", "km", ""),
            ("Velocity", "7.66", "km/s", ""),
            ("Doppler Shift", "+1.234", "kHz", ""),
            ("Next Pass", "15:42:18", "UTC", "⏰"),
        ]
        
        self.track_table.setRowCount(len(params))
        for row, param in enumerate(params):
            for col, value in enumerate(param):
                self.track_table.setItem(row, col, QTableWidgetItem(value))
        
        track_layout.addWidget(self.track_table)
        
        # Ground track placeholder
        track_layout.addWidget(QLabel("Ground Track:"))
        ground_track = QTextEdit()
        ground_track.setReadOnly(True)
        ground_track.setMaximumHeight(150)
        ground_track.setHtml("""
<div style="text-align: center; font-family: monospace; color: #00ff88;">
<pre>
     _______________________________________________
    /                                               \\
   |        *ISS                                     |
   |            \\                                    |
   |             \\___                                |
   |                  \\___                           |
   |                       \\___                      |
   |                            \\___                 |
   |                                 \\___ *Next Pass|
    \\_____________________________________________/
</pre>
<p>Current Position: 28.5°N, 77.2°W</p>
</div>
""")
        track_layout.addWidget(ground_track)
        
        splitter.addWidget(track_panel)
        splitter.setSizes([300, 700])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_signals_tab(self) -> QWidget:
        """Create signal detection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Scan controls
        controls = QHBoxLayout()
        
        controls.addWidget(QLabel("Start Freq:"))
        self.start_freq = QDoubleSpinBox()
        self.start_freq.setRange(1, 6000)
        self.start_freq.setValue(400)
        controls.addWidget(self.start_freq)
        
        controls.addWidget(QLabel("End Freq:"))
        self.end_freq = QDoubleSpinBox()
        self.end_freq.setRange(1, 6000)
        self.end_freq.setValue(500)
        controls.addWidget(self.end_freq)
        
        controls.addWidget(QLabel("Step:"))
        self.freq_step = QDoubleSpinBox()
        self.freq_step.setRange(0.001, 10)
        self.freq_step.setValue(0.1)
        controls.addWidget(self.freq_step)
        
        scan_btn = QPushButton("🔍 Scan Range")
        scan_btn.clicked.connect(self._scan_range)
        controls.addWidget(scan_btn)
        
        layout.addLayout(controls)
        
        # Progress
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        layout.addWidget(self.scan_progress)
        
        # Detected signals
        self.signals_table = QTableWidget()
        self.signals_table.setColumnCount(7)
        self.signals_table.setHorizontalHeaderLabels([
            "Frequency", "Power", "Bandwidth", "Modulation", "Classification", "First Seen", "Status"
        ])
        self.signals_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        signals = [
            ("433.920 MHz", "-42 dBm", "200 kHz", "OOK", "Car Key Fob", "14:32:18", "Active"),
            ("868.300 MHz", "-55 dBm", "125 kHz", "FSK", "IoT Device", "14:28:45", "Active"),
            ("315.000 MHz", "-61 dBm", "100 kHz", "ASK", "Garage Door", "14:15:22", "Inactive"),
            ("1090.000 MHz", "-38 dBm", "1 MHz", "PPM", "ADS-B", "14:10:08", "Active"),
            ("462.550 MHz", "-48 dBm", "12.5 kHz", "FM", "FRS Radio", "13:55:33", "Active"),
        ]
        
        self.signals_table.setRowCount(len(signals))
        for row, signal in enumerate(signals):
            for col, value in enumerate(signal):
                item = QTableWidgetItem(value)
                if col == 6:
                    if value == "Active":
                        item.setForeground(QColor("#00ff88"))
                    else:
                        item.setForeground(QColor("#888"))
                self.signals_table.setItem(row, col, item)
        
        layout.addWidget(self.signals_table)
        
        return widget
    
    def _create_decode_tab(self) -> QWidget:
        """Create signal decoding tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Decoder settings
        decoder_panel = QFrame()
        decoder_panel.setObjectName("decoderPanel")
        decoder_layout = QVBoxLayout(decoder_panel)
        
        decoder_layout.addWidget(QLabel("Signal Decoder"))
        
        # Protocol selection
        proto_group = QGroupBox("Protocol")
        proto_layout = QVBoxLayout(proto_group)
        
        self.protocol = QComboBox()
        self.protocol.addItems([
            "Auto Detect",
            "ADS-B (1090 MHz)",
            "POCSAG (Pager)",
            "FLEX (Pager)",
            "P25 (Digital Voice)",
            "DMR (Digital Voice)",
            "ACARS (Aircraft)",
            "Iridium (Satellite)",
            "LoRa",
            "Zigbee",
            "Bluetooth LE"
        ])
        proto_layout.addWidget(self.protocol)
        
        decoder_layout.addWidget(proto_group)
        
        # Decode settings
        settings_group = QGroupBox("Settings")
        settings_layout = QGridLayout(settings_group)
        
        settings_layout.addWidget(QLabel("Symbol Rate:"), 0, 0)
        self.symbol_rate = QSpinBox()
        self.symbol_rate.setRange(100, 1000000)
        self.symbol_rate.setValue(9600)
        settings_layout.addWidget(self.symbol_rate, 0, 1)
        
        self.error_correction = QCheckBox("Error Correction")
        self.error_correction.setChecked(True)
        settings_layout.addWidget(self.error_correction, 1, 0, 1, 2)
        
        self.save_raw = QCheckBox("Save Raw IQ")
        settings_layout.addWidget(self.save_raw, 2, 0, 1, 2)
        
        decoder_layout.addWidget(settings_group)
        
        decode_btn = QPushButton("🔓 Start Decoding")
        decode_btn.setObjectName("primaryButton")
        decoder_layout.addWidget(decode_btn)
        
        decoder_layout.addStretch()
        splitter.addWidget(decoder_panel)
        
        # Right - Decoded output
        output_panel = QFrame()
        output_panel.setObjectName("outputPanel")
        output_layout = QVBoxLayout(output_panel)
        
        output_layout.addWidget(QLabel("Decoded Messages"))
        
        self.decode_output = QTextEdit()
        self.decode_output.setReadOnly(True)
        self.decode_output.setStyleSheet("""
            font-family: 'Consolas', monospace;
            font-size: 11px;
        """)
        self.decode_output.setHtml("""
<pre style="color: #00ff88;">
[14:32:18] ADS-B Frame Decoded:
  ICAO: A12345
  Callsign: UAL1234
  Altitude: 35000 ft
  Speed: 465 kts
  Heading: 278°
  Position: 40.7128°N, 74.0060°W

[14:32:15] ADS-B Frame Decoded:
  ICAO: A67890
  Callsign: DAL567
  Altitude: 28000 ft
  Speed: 420 kts

[14:32:10] POCSAG Message:
  Address: 1234567
  Function: 0
  Message: "URGENT: Meeting at 3PM"

[14:32:05] LoRa Packet:
  DevAddr: 26011234
  FCnt: 42
  Port: 1
  Payload: 0x48656C6C6F (Hello)
</pre>
""")
        output_layout.addWidget(self.decode_output)
        
        # Export
        export_layout = QHBoxLayout()
        export_btn = QPushButton("📁 Export Decoded")
        export_layout.addWidget(export_btn)
        clear_btn = QPushButton("🗑️ Clear")
        export_layout.addWidget(clear_btn)
        output_layout.addLayout(export_layout)
        
        splitter.addWidget(output_panel)
        splitter.setSizes([350, 650])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_emitter_tab(self) -> QWidget:
        """Create emitter location tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Location stats
        stats = QHBoxLayout()
        
        for icon, label, value, color in [
            ("📍", "Emitters Located", "23", "#1abc9c"),
            ("📡", "Active Signals", "8", "#3498db"),
            ("🎯", "High Confidence", "15", "#2ecc71"),
            ("⚠️", "Unknown", "5", "#e74c3c"),
        ]:
            card = self._create_stat_card(icon, label, value, color)
            stats.addWidget(card)
        
        layout.addLayout(stats)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Emitter list
        list_panel = QFrame()
        list_panel.setObjectName("listPanel")
        list_layout = QVBoxLayout(list_panel)
        
        list_layout.addWidget(QLabel("Located Emitters"))
        
        self.emitter_table = QTableWidget()
        self.emitter_table.setColumnCount(5)
        self.emitter_table.setHorizontalHeaderLabels([
            "Frequency", "Location", "Power", "Confidence", "Type"
        ])
        self.emitter_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        emitters = [
            ("433.92 MHz", "40.7128°N, 74.0060°W", "-42 dBm", "95%", "IoT Hub"),
            ("868.00 MHz", "40.7138°N, 74.0050°W", "-55 dBm", "87%", "Unknown"),
            ("915.00 MHz", "40.7118°N, 74.0070°W", "-48 dBm", "92%", "RFID Reader"),
            ("2.4 GHz", "40.7125°N, 74.0055°W", "-38 dBm", "78%", "WiFi AP"),
        ]
        
        self.emitter_table.setRowCount(len(emitters))
        for row, emitter in enumerate(emitters):
            for col, value in enumerate(emitter):
                item = QTableWidgetItem(value)
                if col == 3:  # Confidence
                    conf = int(value.replace("%", ""))
                    if conf >= 90:
                        item.setForeground(QColor("#00ff88"))
                    elif conf >= 70:
                        item.setForeground(QColor("#ff8800"))
                    else:
                        item.setForeground(QColor("#ff4444"))
                self.emitter_table.setItem(row, col, item)
        
        list_layout.addWidget(self.emitter_table)
        
        splitter.addWidget(list_panel)
        
        # Right - Map placeholder
        map_panel = QFrame()
        map_panel.setObjectName("mapPanel")
        map_layout = QVBoxLayout(map_panel)
        
        map_layout.addWidget(QLabel("Emitter Map"))
        
        map_display = QTextEdit()
        map_display.setReadOnly(True)
        map_display.setHtml("""
<div style="text-align: center; padding: 20px;">
<pre style="font-family: monospace; color: #00ff88; font-size: 10px;">
    ╔══════════════════════════════════════════╗
    ║                MAP VIEW                   ║
    ║                                           ║
    ║     📍━━━━━━━━┓                           ║
    ║               ┃                           ║
    ║         📡━━━━╋━━━━📍                     ║
    ║               ┃                           ║
    ║     📍━━━━━━━━┻━━━━━━━━📍                 ║
    ║                                           ║
    ║   Legend:                                 ║
    ║   📍 Located Emitter                      ║
    ║   📡 High Power Signal                    ║
    ║   ━━ Signal Path                          ║
    ║                                           ║
    ╚══════════════════════════════════════════╝
</pre>
<p style="color: #888;">Area: 2 km² | Emitters: 4 | Accuracy: ±5m</p>
</div>
""")
        map_layout.addWidget(map_display)
        
        # Location methods
        methods_group = QGroupBox("Location Methods")
        methods_layout = QHBoxLayout(methods_group)
        
        self.tdoa = QCheckBox("TDOA")
        self.tdoa.setChecked(True)
        methods_layout.addWidget(self.tdoa)
        
        self.aoa = QCheckBox("AOA")
        methods_layout.addWidget(self.aoa)
        
        self.rssi = QCheckBox("RSSI Trilateration")
        self.rssi.setChecked(True)
        methods_layout.addWidget(self.rssi)
        
        map_layout.addWidget(methods_group)
        
        splitter.addWidget(map_panel)
        splitter.setSizes([450, 550])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_stat_card(self, icon, label, value, color) -> QFrame:
        """Create a stat card widget"""
        card = QFrame()
        card.setObjectName("statCard")
        card.setStyleSheet(f"""
            QFrame#statCard {{
                background-color: #16213e;
                border-left: 4px solid {color};
                border-radius: 8px;
                padding: 15px;
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
        value_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        layout.addWidget(value_label)
        
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #888;")
        layout.addWidget(name_label)
        
        return card
    
    def _apply_styles(self):
        """Apply custom styles"""
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a2e;
                color: #ffffff;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            QFrame#headerFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1f3d3d, stop:1 #1a1a2e);
                border-radius: 10px;
                padding: 15px;
            }
            
            QFrame#configPanel, QFrame#spectrumPanel, QFrame#listPanel,
            QFrame#trackPanel, QFrame#decoderPanel, QFrame#outputPanel,
            QFrame#mapPanel {
                background-color: #16213e;
                border-radius: 8px;
                padding: 10px;
            }
            
            QGroupBox {
                font-weight: bold;
                border: 1px solid #0f3460;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            
            QPushButton {
                background-color: #0f3460;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                color: white;
                font-weight: bold;
            }
            
            QPushButton:hover {
                background-color: #1a4a7a;
            }
            
            QPushButton#primaryButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1abc9c, stop:1 #16a085);
                color: #fff;
            }
            
            QTableWidget {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QHeaderView::section {
                background-color: #16213e;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #1abc9c;
                font-weight: bold;
            }
            
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
            
            QTextEdit {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1abc9c, stop:1 #00ff88);
                border-radius: 4px;
            }
            
            QTabBar::tab:selected {
                background-color: #0f3460;
                border-bottom: 2px solid #1abc9c;
            }
            
            QListWidget {
                background-color: #0d1b2a;
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QCheckBox::indicator:checked {
                background-color: #1abc9c;
                border-color: #1abc9c;
            }
        """)
    
    def _start_demo_updates(self):
        """Start demo UI updates"""
        self.demo_timer = QTimer()
        self.demo_timer.timeout.connect(self._update_demo)
        self.demo_timer.start(1000)
    
    def _update_demo(self):
        """Update demo values"""
        freq = 433.92 + random.uniform(-0.01, 0.01)
        power = -45 + random.randint(-5, 5)
        snr = 23 + random.randint(-3, 3)
        
        self.freq_label.setText(f"Freq: {freq:.3f} MHz")
        self.power_label.setText(f"Power: {power} dBm")
        self.snr_label.setText(f"SNR: {snr} dB")
        
        self._update_spectrum_display()
    
    def _update_spectrum_display(self):
        """Update spectrum display"""
        lines = []
        for i in range(15):
            line = ""
            for j in range(60):
                level = random.choice(["░", "▒", "▓", "█", " ", " ", " "])
                if j == 30:  # Signal peak
                    level = "█"
                line += level
            lines.append(f'<span style="color: #00ff88;">{line}</span>')
        
        self.spectrum_display.setHtml(f"""
<pre style="line-height: 1.2;">
{"<br/>".join(lines)}
</pre>
<p style="color: #1abc9c; text-align: center;">
──────────────────────────────────────────────────────────
433.0 MHz               433.92 MHz               435.0 MHz
</p>
""")
    
    def _toggle_scan(self, checked):
        """Toggle scanning"""
        if checked:
            self.scan_btn.setText("🔴 Stop Scan")
            self.scan_status.setText("● Scanning...")
            self.scan_status.setStyleSheet("color: #00ff88; font-size: 11px;")
        else:
            self.scan_btn.setText("📡 Start Scan")
            self.scan_status.setText("● Idle")
            self.scan_status.setStyleSheet("color: #888; font-size: 11px;")
    
    def _scan_range(self):
        """Scan frequency range"""
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        
        self.worker = SignalScanWorker(
            self.engine,
            (self.start_freq.value(), self.end_freq.value()),
            "signal_detect"
        )
        self.worker.progress.connect(lambda v: self.scan_progress.setValue(v))
        self.worker.finished.connect(lambda: self.scan_progress.setVisible(False))
        self.worker.start()
