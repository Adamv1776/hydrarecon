#!/usr/bin/env python3
"""
HydraRecon Network Traffic Analysis Page
GUI for traffic capture, analysis, and threat detection.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QLineEdit, QComboBox,
    QTextEdit, QTableWidget, QTableWidgetItem, QProgressBar,
    QTabWidget, QGroupBox, QCheckBox, QSpinBox, QSplitter,
    QHeaderView, QMessageBox, QListWidget, QListWidgetItem,
    QFileDialog, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor

import asyncio
from datetime import datetime
from typing import Optional

try:
    from ...core.network_traffic import (
        NetworkTrafficAnalyzer, ProtocolType, ThreatLevel, TrafficType
    )
    TRAFFIC_AVAILABLE = True
except ImportError:
    TRAFFIC_AVAILABLE = False


class AnalysisWorker(QThread):
    """Worker thread for traffic analysis"""
    progress = pyqtSignal(str, float)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, analyzer, filepath, extract_files):
        super().__init__()
        self.analyzer = analyzer
        self.filepath = filepath
        self.extract_files = extract_files
    
    def run(self):
        """Run the analysis"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            def callback(msg, progress):
                self.progress.emit(msg, progress)
            
            result = loop.run_until_complete(
                self.analyzer.analyze_pcap(
                    self.filepath, self.extract_files, callback
                )
            )
            
            loop.close()
            self.finished.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class CaptureWorker(QThread):
    """Worker thread for live capture"""
    progress = pyqtSignal(str, float)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, analyzer, interface, duration, filter_expr):
        super().__init__()
        self.analyzer = analyzer
        self.interface = interface
        self.duration = duration
        self.filter_expr = filter_expr
    
    def run(self):
        """Run live capture"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            def callback(msg, progress):
                self.progress.emit(msg, progress)
            
            result = loop.run_until_complete(
                self.analyzer.live_capture(
                    self.interface, self.duration, self.filter_expr, callback
                )
            )
            
            loop.close()
            self.finished.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class NetworkTrafficPage(QWidget):
    """Network Traffic Analysis Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.analyzer = NetworkTrafficAnalyzer() if TRAFFIC_AVAILABLE else None
        self.analysis_worker: Optional[AnalysisWorker] = None
        self.capture_worker: Optional[CaptureWorker] = None
        self.current_result = None
        
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
        
        # Tab 1: PCAP Analysis
        self.tabs.addTab(self._create_analysis_tab(), "📂 PCAP Analysis")
        
        # Tab 2: Live Capture
        self.tabs.addTab(self._create_capture_tab(), "📡 Live Capture")
        
        # Tab 3: Flow Analysis
        self.tabs.addTab(self._create_flows_tab(), "🌊 Flow Analysis")
        
        # Tab 4: Threat Detection
        self.tabs.addTab(self._create_threats_tab(), "🚨 Threat Detection")
        
        # Tab 5: Protocol Statistics
        self.tabs.addTab(self._create_protocols_tab(), "📊 Protocol Stats")
        
        layout.addWidget(self.tabs, stretch=1)
    
    def _create_header(self) -> QWidget:
        """Create header section"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1f6feb, stop:1 #58a6ff);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("📡 Network Traffic Analysis")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: 700;
            color: white;
        """)
        
        subtitle = QLabel("Deep packet inspection, flow analysis, and threat detection")
        subtitle.setStyleSheet("font-size: 14px; color: rgba(255,255,255,0.8);")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout, stretch=1)
        
        # Status indicator
        self.capture_status = QLabel("● Idle")
        self.capture_status.setStyleSheet("color: #8b949e; font-size: 14px;")
        layout.addWidget(self.capture_status)
        
        return header
    
    def _create_analysis_tab(self) -> QWidget:
        """Create PCAP analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # File selection
        file_group = QGroupBox("PCAP File Analysis")
        file_group.setStyleSheet("""
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
        
        file_layout = QVBoxLayout(file_group)
        
        # File input
        input_layout = QHBoxLayout()
        
        self.pcap_input = QLineEdit()
        self.pcap_input.setPlaceholderText("Select PCAP file...")
        self.pcap_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 12px;
                color: #e6e6e6;
            }
        """)
        
        browse_btn = QPushButton("📂 Browse")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #e6e6e6;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        browse_btn.clicked.connect(self._browse_pcap)
        
        input_layout.addWidget(self.pcap_input, stretch=1)
        input_layout.addWidget(browse_btn)
        
        file_layout.addLayout(input_layout)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.extract_files_check = QCheckBox("Extract embedded files")
        self.extract_files_check.setStyleSheet("color: #e6e6e6;")
        
        options_layout.addWidget(self.extract_files_check)
        options_layout.addStretch()
        
        file_layout.addLayout(options_layout)
        
        # Analyze button and progress
        analyze_layout = QHBoxLayout()
        
        self.analyze_btn = QPushButton("🔍 Analyze PCAP")
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:disabled { background-color: #21262d; color: #8b949e; }
        """)
        self.analyze_btn.clicked.connect(self._start_analysis)
        
        self.analysis_progress = QProgressBar()
        self.analysis_progress.setStyleSheet("""
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
        
        self.analysis_status = QLabel("Ready")
        self.analysis_status.setStyleSheet("color: #8b949e;")
        
        analyze_layout.addWidget(self.analyze_btn)
        analyze_layout.addWidget(self.analysis_progress, stretch=1)
        analyze_layout.addWidget(self.analysis_status)
        
        file_layout.addLayout(analyze_layout)
        
        layout.addWidget(file_group)
        
        # Results summary
        summary_group = QGroupBox("Analysis Summary")
        summary_group.setStyleSheet("""
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
        
        summary_layout = QVBoxLayout(summary_group)
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.stat_widgets = {}
        stats = [
            ("packets", "Packets", "#58a6ff"),
            ("bytes", "Bytes", "#3fb950"),
            ("flows", "Flows", "#d29922"),
            ("protocols", "Protocols", "#bc8cff"),
            ("threats", "Threats", "#f85149")
        ]
        
        for key, label, color in stats:
            stat_frame = QFrame()
            stat_frame.setStyleSheet(f"""
                QFrame {{
                    background-color: #161b22;
                    border: 1px solid #21262d;
                    border-radius: 8px;
                    padding: 10px;
                }}
            """)
            
            stat_layout = QVBoxLayout(stat_frame)
            stat_layout.setContentsMargins(10, 10, 10, 10)
            
            value_label = QLabel("0")
            value_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name_label = QLabel(label)
            name_label.setStyleSheet("color: #8b949e;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            stat_layout.addWidget(value_label)
            stat_layout.addWidget(name_label)
            
            self.stat_widgets[key] = value_label
            stats_layout.addWidget(stat_frame)
        
        summary_layout.addLayout(stats_layout)
        
        # Top talkers table
        summary_layout.addWidget(QLabel("Top Talkers:"))
        
        self.talkers_table = QTableWidget()
        self.talkers_table.setColumnCount(2)
        self.talkers_table.setHorizontalHeaderLabels(["IP Address", "Bytes"])
        self.talkers_table.horizontalHeader().setStretchLastSection(True)
        self.talkers_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 8px;
                border: none;
            }
        """)
        self.talkers_table.setMaximumHeight(200)
        
        summary_layout.addWidget(self.talkers_table)
        
        layout.addWidget(summary_group, stretch=1)
        
        return widget
    
    def _create_capture_tab(self) -> QWidget:
        """Create live capture tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Capture settings
        capture_group = QGroupBox("Live Capture Settings")
        capture_group.setStyleSheet("""
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
        
        capture_layout = QVBoxLayout(capture_group)
        
        # Interface selection
        iface_layout = QHBoxLayout()
        iface_layout.addWidget(QLabel("Interface:"))
        
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["eth0", "wlan0", "lo", "any"])
        self.interface_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        
        iface_layout.addWidget(self.interface_combo)
        iface_layout.addStretch()
        
        capture_layout.addLayout(iface_layout)
        
        # Duration
        duration_layout = QHBoxLayout()
        duration_layout.addWidget(QLabel("Duration (seconds):"))
        
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(5, 300)
        self.duration_spin.setValue(30)
        self.duration_spin.setStyleSheet("""
            QSpinBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
                color: #e6e6e6;
            }
        """)
        
        duration_layout.addWidget(self.duration_spin)
        duration_layout.addStretch()
        
        capture_layout.addLayout(duration_layout)
        
        # BPF Filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("BPF Filter:"))
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g., tcp port 80 or udp")
        self.filter_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 10px;
                color: #e6e6e6;
            }
        """)
        
        filter_layout.addWidget(self.filter_input, stretch=1)
        
        capture_layout.addLayout(filter_layout)
        
        # Capture button
        self.capture_btn = QPushButton("📡 Start Capture")
        self.capture_btn.setStyleSheet("""
            QPushButton {
                background-color: #f85149;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:disabled { background-color: #21262d; color: #8b949e; }
        """)
        self.capture_btn.clicked.connect(self._start_capture)
        
        capture_layout.addWidget(self.capture_btn)
        
        layout.addWidget(capture_group)
        
        # Capture output
        output_group = QGroupBox("Capture Output")
        output_group.setStyleSheet("""
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
        
        output_layout = QVBoxLayout(output_group)
        
        self.capture_output = QTextEdit()
        self.capture_output.setReadOnly(True)
        self.capture_output.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
                padding: 12px;
                font-family: 'Consolas', monospace;
            }
        """)
        
        output_layout.addWidget(self.capture_output)
        
        layout.addWidget(output_group, stretch=1)
        
        return widget
    
    def _create_flows_tab(self) -> QWidget:
        """Create flow analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Flow table
        flow_group = QGroupBox("Network Flows")
        flow_group.setStyleSheet("""
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
        
        flow_layout = QVBoxLayout(flow_group)
        
        # Filters
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Protocol:"))
        self.flow_protocol_filter = QComboBox()
        self.flow_protocol_filter.addItems(["All", "TCP", "UDP", "HTTP", "HTTPS", "DNS"])
        self.flow_protocol_filter.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 6px;
                color: #e6e6e6;
            }
        """)
        filter_layout.addWidget(self.flow_protocol_filter)
        
        filter_layout.addWidget(QLabel("State:"))
        self.flow_state_filter = QComboBox()
        self.flow_state_filter.addItems(["All", "Established", "Closing", "Reset"])
        self.flow_state_filter.setStyleSheet("""
            QComboBox {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 6px;
                color: #e6e6e6;
            }
        """)
        filter_layout.addWidget(self.flow_state_filter)
        
        filter_layout.addStretch()
        
        flow_layout.addLayout(filter_layout)
        
        # Flow table
        self.flows_table = QTableWidget()
        self.flows_table.setColumnCount(7)
        self.flows_table.setHorizontalHeaderLabels([
            "Flow ID", "Source", "Destination", "Protocol", "Packets", "Bytes", "State"
        ])
        self.flows_table.horizontalHeader().setStretchLastSection(True)
        self.flows_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 8px;
                border: none;
            }
        """)
        
        flow_layout.addWidget(self.flows_table)
        
        layout.addWidget(flow_group, stretch=1)
        
        return widget
    
    def _create_threats_tab(self) -> QWidget:
        """Create threat detection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Threat summary
        summary_layout = QHBoxLayout()
        
        threat_levels = [
            ("critical", "Critical", "#f85149"),
            ("malicious", "Malicious", "#ffa657"),
            ("suspicious", "Suspicious", "#d29922"),
            ("clean", "Clean", "#3fb950")
        ]
        
        self.threat_counts = {}
        for key, label, color in threat_levels:
            frame = QFrame()
            frame.setStyleSheet(f"""
                QFrame {{
                    background-color: #161b22;
                    border: 2px solid {color};
                    border-radius: 8px;
                }}
            """)
            
            frame_layout = QVBoxLayout(frame)
            frame_layout.setContentsMargins(15, 15, 15, 15)
            
            count = QLabel("0")
            count.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {color};")
            count.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name = QLabel(label)
            name.setStyleSheet("color: #8b949e;")
            name.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            frame_layout.addWidget(count)
            frame_layout.addWidget(name)
            
            self.threat_counts[key] = count
            summary_layout.addWidget(frame)
        
        layout.addLayout(summary_layout)
        
        # Threat details
        details_group = QGroupBox("Detected Threats")
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
        
        self.threats_tree = QTreeWidget()
        self.threats_tree.setHeaderLabels([
            "Threat", "Level", "Type", "Source", "Destination", "Confidence"
        ])
        self.threats_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTreeWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 8px;
                border: none;
            }
        """)
        
        details_layout.addWidget(self.threats_tree)
        
        layout.addWidget(details_group, stretch=1)
        
        return widget
    
    def _create_protocols_tab(self) -> QWidget:
        """Create protocol statistics tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # Protocol breakdown
        proto_group = QGroupBox("Protocol Distribution")
        proto_group.setStyleSheet("""
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
        
        proto_layout = QVBoxLayout(proto_group)
        
        self.protocol_table = QTableWidget()
        self.protocol_table.setColumnCount(5)
        self.protocol_table.setHorizontalHeaderLabels([
            "Protocol", "Packets", "Bytes", "Flows", "Unique IPs"
        ])
        self.protocol_table.horizontalHeader().setStretchLastSection(True)
        self.protocol_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                border: 1px solid #21262d;
                border-radius: 6px;
                color: #e6e6e6;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                padding: 8px;
                border: none;
            }
        """)
        
        proto_layout.addWidget(self.protocol_table)
        
        layout.addWidget(proto_group, stretch=1)
        
        return widget
    
    def _browse_pcap(self):
        """Browse for PCAP file"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select PCAP File", "",
            "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)"
        )
        
        if filepath:
            self.pcap_input.setText(filepath)
    
    def _start_analysis(self):
        """Start PCAP analysis"""
        filepath = self.pcap_input.text().strip()
        if not filepath or not self.analyzer:
            QMessageBox.warning(self, "Error", "Please select a PCAP file")
            return
        
        self.analyze_btn.setEnabled(False)
        self.analysis_progress.setValue(0)
        
        self.analysis_worker = AnalysisWorker(
            self.analyzer, filepath, self.extract_files_check.isChecked()
        )
        self.analysis_worker.progress.connect(self._on_analysis_progress)
        self.analysis_worker.finished.connect(self._on_analysis_finished)
        self.analysis_worker.error.connect(self._on_analysis_error)
        self.analysis_worker.start()
    
    def _on_analysis_progress(self, message: str, progress: float):
        """Handle analysis progress"""
        self.analysis_status.setText(message)
        self.analysis_progress.setValue(int(progress))
    
    def _on_analysis_finished(self, result):
        """Handle analysis completion"""
        self.analyze_btn.setEnabled(True)
        self.analysis_progress.setValue(100)
        self.analysis_status.setText("Complete")
        self.current_result = result
        
        # Update statistics
        self.stat_widgets["packets"].setText(f"{result.total_packets:,}")
        self.stat_widgets["bytes"].setText(self._format_bytes(result.total_bytes))
        self.stat_widgets["flows"].setText(f"{result.total_flows:,}")
        self.stat_widgets["protocols"].setText(str(len(result.protocols)))
        self.stat_widgets["threats"].setText(str(len(result.threats)))
        
        # Update top talkers
        self.talkers_table.setRowCount(len(result.top_talkers))
        for i, talker in enumerate(result.top_talkers):
            self.talkers_table.setItem(i, 0, QTableWidgetItem(talker["ip"]))
            self.talkers_table.setItem(i, 1, QTableWidgetItem(self._format_bytes(talker["bytes"])))
        
        # Update flows tab
        self._update_flows_tab(result)
        
        # Update threats tab
        self._update_threats_tab(result)
        
        # Update protocols tab
        self._update_protocols_tab(result)
    
    def _on_analysis_error(self, error: str):
        """Handle analysis error"""
        self.analyze_btn.setEnabled(True)
        self.analysis_status.setText(f"Error: {error}")
        QMessageBox.critical(self, "Analysis Error", error)
    
    def _start_capture(self):
        """Start live capture"""
        if not self.analyzer:
            return
        
        interface = self.interface_combo.currentText()
        duration = self.duration_spin.value()
        filter_expr = self.filter_input.text().strip()
        
        self.capture_btn.setEnabled(False)
        self.capture_status.setText("● Capturing...")
        self.capture_status.setStyleSheet("color: #f85149; font-size: 14px;")
        
        self.capture_output.append(f"Starting capture on {interface}...")
        self.capture_output.append(f"Duration: {duration} seconds")
        if filter_expr:
            self.capture_output.append(f"Filter: {filter_expr}")
        
        self.capture_worker = CaptureWorker(
            self.analyzer, interface, duration, filter_expr
        )
        self.capture_worker.progress.connect(self._on_capture_progress)
        self.capture_worker.finished.connect(self._on_capture_finished)
        self.capture_worker.error.connect(self._on_capture_error)
        self.capture_worker.start()
    
    def _on_capture_progress(self, message: str, progress: float):
        """Handle capture progress"""
        self.capture_output.append(message)
    
    def _on_capture_finished(self, result):
        """Handle capture completion"""
        self.capture_btn.setEnabled(True)
        self.capture_status.setText("● Idle")
        self.capture_status.setStyleSheet("color: #3fb950; font-size: 14px;")
        
        self.capture_output.append("Capture complete!")
        self.capture_output.append(f"Captured {result.total_packets:,} packets")
        
        self.current_result = result
        self._on_analysis_finished(result)
    
    def _on_capture_error(self, error: str):
        """Handle capture error"""
        self.capture_btn.setEnabled(True)
        self.capture_status.setText("● Error")
        self.capture_status.setStyleSheet("color: #f85149; font-size: 14px;")
        self.capture_output.append(f"Error: {error}")
    
    def _update_flows_tab(self, result):
        """Update flows table"""
        flows = list(result.suspicious_flows) if hasattr(result, 'suspicious_flows') else []
        
        self.flows_table.setRowCount(len(flows))
        for i, flow in enumerate(flows):
            self.flows_table.setItem(i, 0, QTableWidgetItem(flow.flow_id))
            self.flows_table.setItem(i, 1, QTableWidgetItem(f"{flow.source_ip}:{flow.source_port}"))
            self.flows_table.setItem(i, 2, QTableWidgetItem(f"{flow.dest_ip}:{flow.dest_port}"))
            self.flows_table.setItem(i, 3, QTableWidgetItem(flow.protocol.value.upper()))
            self.flows_table.setItem(i, 4, QTableWidgetItem(str(flow.packet_count)))
            self.flows_table.setItem(i, 5, QTableWidgetItem(self._format_bytes(flow.byte_count)))
            self.flows_table.setItem(i, 6, QTableWidgetItem(flow.state))
    
    def _update_threats_tab(self, result):
        """Update threats display"""
        # Update counts
        threat_summary = self.analyzer.get_threat_summary(result) if self.analyzer else {}
        
        self.threat_counts["critical"].setText(str(threat_summary.get("by_level", {}).get("critical", 0)))
        self.threat_counts["malicious"].setText(str(threat_summary.get("by_level", {}).get("malicious", 0)))
        self.threat_counts["suspicious"].setText(str(threat_summary.get("by_level", {}).get("suspicious", 0)))
        
        # Calculate clean (total flows minus threats)
        clean_count = result.total_flows - len(result.threats)
        self.threat_counts["clean"].setText(str(max(0, clean_count)))
        
        # Update tree
        self.threats_tree.clear()
        for threat in result.threats:
            item = QTreeWidgetItem([
                threat.description,
                threat.threat_level.value,
                threat.traffic_type.value,
                threat.source_ip,
                threat.dest_ip,
                f"{threat.confidence:.0%}"
            ])
            
            # Color code by level
            colors = {
                ThreatLevel.CRITICAL: QColor("#f85149"),
                ThreatLevel.MALICIOUS: QColor("#ffa657"),
                ThreatLevel.SUSPICIOUS: QColor("#d29922"),
                ThreatLevel.CLEAN: QColor("#3fb950")
            }
            
            color = colors.get(threat.threat_level, QColor("#8b949e"))
            for col in range(6):
                item.setForeground(col, color)
            
            self.threats_tree.addTopLevelItem(item)
    
    def _update_protocols_tab(self, result):
        """Update protocol statistics"""
        self.protocol_table.setRowCount(len(result.protocols))
        
        for i, (proto, stats) in enumerate(result.protocols.items()):
            self.protocol_table.setItem(i, 0, QTableWidgetItem(proto.value.upper()))
            self.protocol_table.setItem(i, 1, QTableWidgetItem(f"{stats.packet_count:,}"))
            self.protocol_table.setItem(i, 2, QTableWidgetItem(self._format_bytes(stats.byte_count)))
            self.protocol_table.setItem(i, 3, QTableWidgetItem(str(stats.flow_count)))
            self.protocol_table.setItem(i, 4, QTableWidgetItem(
                str(len(stats.unique_sources) + len(stats.unique_destinations))
            ))
    
    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes in human-readable form"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} PB"
