#!/usr/bin/env python3
"""
Cognitive Threat Engine GUI Page
Self-learning neural network for threat detection and prediction.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem, QComboBox,
    QProgressBar, QTabWidget, QScrollArea, QGridLayout, QGroupBox,
    QSpinBox, QCheckBox, QSplitter, QListWidget, QListWidgetItem,
    QSlider, QDoubleSpinBox, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush

import asyncio
from datetime import datetime
from typing import Optional, Dict, List, Any
import json
import random
import math


class NeuralNetworkVisualizer(QWidget):
    """Custom widget to visualize neural network activity"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(400, 300)
        self.neurons = []
        self.connections = []
        self.activity_levels = {}
        self._generate_network()
        
        # Animation timer
        self.timer = QTimer()
        self.timer.timeout.connect(self._update_activity)
        self.timer.start(100)
    
    def _generate_network(self):
        """Generate neural network structure"""
        layers = [8, 12, 16, 12, 6]  # Neurons per layer
        
        self.neurons = []
        self.connections = []
        
        width = self.width() or 400
        height = self.height() or 300
        
        layer_spacing = width / (len(layers) + 1)
        
        for layer_idx, neuron_count in enumerate(layers):
            layer_x = layer_spacing * (layer_idx + 1)
            neuron_spacing = height / (neuron_count + 1)
            
            for neuron_idx in range(neuron_count):
                neuron_y = neuron_spacing * (neuron_idx + 1)
                neuron_id = f"L{layer_idx}_N{neuron_idx}"
                self.neurons.append({
                    "id": neuron_id,
                    "x": layer_x,
                    "y": neuron_y,
                    "layer": layer_idx
                })
                self.activity_levels[neuron_id] = random.random()
    
    def _update_activity(self):
        """Update neuron activity levels for animation"""
        for neuron_id in self.activity_levels:
            # Simulate activity fluctuation
            current = self.activity_levels[neuron_id]
            change = random.uniform(-0.1, 0.1)
            self.activity_levels[neuron_id] = max(0, min(1, current + change))
        self.update()
    
    def paintEvent(self, event):
        """Paint the neural network visualization"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Background
        painter.fillRect(self.rect(), QColor("#0d1117"))
        
        # Recalculate positions based on current size
        width = self.width()
        height = self.height()
        
        layers = {}
        for neuron in self.neurons:
            layer = neuron["layer"]
            if layer not in layers:
                layers[layer] = []
            layers[layer].append(neuron)
        
        layer_count = len(layers)
        layer_spacing = width / (layer_count + 1)
        
        # Update neuron positions
        for layer_idx, neurons in layers.items():
            layer_x = layer_spacing * (layer_idx + 1)
            neuron_spacing = height / (len(neurons) + 1)
            
            for i, neuron in enumerate(neurons):
                neuron["x"] = layer_x
                neuron["y"] = neuron_spacing * (i + 1)
        
        # Draw connections (only between adjacent layers)
        pen = QPen(QColor("#30363d"))
        pen.setWidth(1)
        painter.setPen(pen)
        
        for layer_idx in range(layer_count - 1):
            if layer_idx in layers and layer_idx + 1 in layers:
                for n1 in layers[layer_idx]:
                    for n2 in layers[layer_idx + 1]:
                        activity = (self.activity_levels.get(n1["id"], 0) + 
                                  self.activity_levels.get(n2["id"], 0)) / 2
                        if activity > 0.3:
                            alpha = int(activity * 100)
                            pen.setColor(QColor(0, 255, 136, alpha))
                            painter.setPen(pen)
                            painter.drawLine(
                                int(n1["x"]), int(n1["y"]),
                                int(n2["x"]), int(n2["y"])
                            )
        
        # Draw neurons
        for neuron in self.neurons:
            activity = self.activity_levels.get(neuron["id"], 0)
            
            # Color based on activity
            r = int(30 + activity * 50)
            g = int(54 + activity * 200)
            b = int(61 + activity * 100)
            
            brush = QBrush(QColor(r, g, b))
            painter.setBrush(brush)
            
            # Glow effect for active neurons
            if activity > 0.6:
                glow_pen = QPen(QColor(0, 255, 136, int(activity * 150)))
                glow_pen.setWidth(3)
                painter.setPen(glow_pen)
            else:
                painter.setPen(QPen(QColor("#30363d")))
            
            size = 8 + int(activity * 6)
            painter.drawEllipse(
                int(neuron["x"] - size/2),
                int(neuron["y"] - size/2),
                size, size
            )


class ThreatWorker(QThread):
    """Worker thread for threat analysis"""
    threat_detected = pyqtSignal(dict)
    analysis_progress = pyqtSignal(int, str)
    learning_update = pyqtSignal(dict)
    
    def __init__(self, data_source: str):
        super().__init__()
        self.data_source = data_source
        self.running = True
    
    def run(self):
        """Run continuous threat analysis"""
        threat_types = [
            "Anomalous Login Pattern",
            "Data Exfiltration Attempt",
            "Privilege Escalation",
            "Lateral Movement",
            "C2 Communication",
            "Credential Stuffing",
            "SQL Injection Probe",
            "Directory Traversal"
        ]
        
        import time
        counter = 0
        
        while self.running:
            time.sleep(1)
            counter += 1
            
            # Simulate threat detection
            if random.random() > 0.7:
                threat = {
                    "type": random.choice(threat_types),
                    "confidence": random.uniform(0.75, 0.99),
                    "source_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                    "severity": random.choice(["Low", "Medium", "High", "Critical"]),
                    "timestamp": datetime.now().isoformat()
                }
                self.threat_detected.emit(threat)
            
            # Learning updates
            if counter % 5 == 0:
                learning = {
                    "patterns_learned": random.randint(100, 500),
                    "accuracy": random.uniform(0.92, 0.99),
                    "false_positive_rate": random.uniform(0.01, 0.05)
                }
                self.learning_update.emit(learning)
    
    def stop(self):
        self.running = False


class CognitiveThreatPage(QWidget):
    """Cognitive Threat Engine Interface"""
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self.threat_worker = None
        self.detected_threats = []
        
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                background: #0d1117;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #161b22;
                color: #8b949e;
                padding: 12px 24px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background: #00d4ff;
                color: #0d1117;
            }
            QTabBar::tab:hover:!selected {
                background: #21262d;
            }
        """)
        
        tabs.addTab(self._create_neural_monitor_tab(), "🧠 Neural Monitor")
        tabs.addTab(self._create_threat_detection_tab(), "🎯 Threat Detection")
        tabs.addTab(self._create_pattern_learning_tab(), "📚 Pattern Learning")
        tabs.addTab(self._create_predictions_tab(), "🔮 Predictions")
        tabs.addTab(self._create_training_tab(), "⚡ Training")
        
        layout.addWidget(tabs, stretch=1)
    
    def _create_header(self) -> QFrame:
        """Create the page header"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1f35, stop:1 #0d1117);
                border: 1px solid #30363d;
                border-radius: 16px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title section
        title_layout = QVBoxLayout()
        
        title = QLabel("🧠 Cognitive Threat Engine")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        
        subtitle = QLabel("Self-Learning Neural Network for Threat Detection & Prediction")
        subtitle.setStyleSheet("color: #8b949e; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Status indicators
        status_frame = QFrame()
        status_layout = QGridLayout(status_frame)
        
        self.neural_status = QLabel("🧠 Neural: Active")
        self.neural_status.setStyleSheet("color: #00ff88; font-weight: bold;")
        
        self.learning_status = QLabel("📚 Learning: Enabled")
        self.learning_status.setStyleSheet("color: #00d4ff; font-weight: bold;")
        
        self.threat_status = QLabel("🎯 Threats: 0")
        self.threat_status.setStyleSheet("color: #ffcc00; font-weight: bold;")
        
        status_layout.addWidget(self.neural_status, 0, 0)
        status_layout.addWidget(self.learning_status, 0, 1)
        status_layout.addWidget(self.threat_status, 1, 0)
        
        layout.addWidget(status_frame)
        
        return frame
    
    def _create_neural_monitor_tab(self) -> QWidget:
        """Create the neural network monitor tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Splitter for network viz and stats
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Neural Network Visualization
        left_panel = QFrame()
        left_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
            }
        """)
        left_layout = QVBoxLayout(left_panel)
        
        viz_label = QLabel("🔮 Neural Network Activity")
        viz_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        left_layout.addWidget(viz_label)
        
        self.neural_viz = NeuralNetworkVisualizer()
        left_layout.addWidget(self.neural_viz, stretch=1)
        
        splitter.addWidget(left_panel)
        
        # Right panel - Network Stats
        right_panel = QFrame()
        right_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
            }
        """)
        right_layout = QVBoxLayout(right_panel)
        
        stats_label = QLabel("📊 Network Statistics")
        stats_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        right_layout.addWidget(stats_label)
        
        # Stats grid
        stats_grid = QGridLayout()
        
        stats = [
            ("Total Neurons", "54", "#00ff88"),
            ("Active Connections", "2,847", "#00d4ff"),
            ("Processing Speed", "1.2 ms", "#ffcc00"),
            ("Accuracy Rate", "97.3%", "#00ff88"),
            ("False Positives", "0.8%", "#da3633"),
            ("Patterns Learned", "12,453", "#00d4ff"),
        ]
        
        for i, (name, value, color) in enumerate(stats):
            stat_frame = QFrame()
            stat_frame.setStyleSheet(f"""
                QFrame {{
                    background: #0d1117;
                    border: 1px solid {color};
                    border-radius: 8px;
                    padding: 12px;
                }}
            """)
            stat_layout = QVBoxLayout(stat_frame)
            
            value_lbl = QLabel(value)
            value_lbl.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold;")
            value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            name_lbl = QLabel(name)
            name_lbl.setStyleSheet("color: #8b949e; font-size: 11px;")
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            stat_layout.addWidget(value_lbl)
            stat_layout.addWidget(name_lbl)
            
            stats_grid.addWidget(stat_frame, i // 2, i % 2)
        
        right_layout.addLayout(stats_grid)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.start_monitor_btn = QPushButton("▶️ Start Monitoring")
        self.start_monitor_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        self.start_monitor_btn.clicked.connect(self._start_monitoring)
        
        self.stop_monitor_btn = QPushButton("⏹️ Stop")
        self.stop_monitor_btn.setEnabled(False)
        self.stop_monitor_btn.setStyleSheet("""
            QPushButton {
                background: #da3633;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #f85149;
            }
            QPushButton:disabled {
                background: #21262d;
                color: #484f58;
            }
        """)
        self.stop_monitor_btn.clicked.connect(self._stop_monitoring)
        
        control_layout.addWidget(self.start_monitor_btn)
        control_layout.addWidget(self.stop_monitor_btn)
        
        right_layout.addLayout(control_layout)
        right_layout.addStretch()
        
        splitter.addWidget(right_panel)
        splitter.setSizes([500, 400])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_threat_detection_tab(self) -> QWidget:
        """Create the threat detection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Real-time threat feed
        feed_label = QLabel("🎯 Real-time Threat Feed")
        feed_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        layout.addWidget(feed_label)
        
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(6)
        self.threat_table.setHorizontalHeaderLabels([
            "Timestamp", "Threat Type", "Source IP", "Confidence", "Severity", "Status"
        ])
        self.threat_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6edf3;
                gridline-color: #21262d;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background: #161b22;
                color: #e6edf3;
                padding: 12px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item:selected {
                background: #238636;
            }
        """)
        layout.addWidget(self.threat_table)
        
        # Threat analysis panel
        analysis_frame = QFrame()
        analysis_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }
        """)
        analysis_layout = QVBoxLayout(analysis_frame)
        
        analysis_label = QLabel("🔍 Threat Analysis")
        analysis_label.setStyleSheet("color: #e6edf3; font-weight: bold;")
        analysis_layout.addWidget(analysis_label)
        
        self.analysis_text = QTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setMaximumHeight(150)
        self.analysis_text.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #00ff88;
                font-family: 'Consolas', monospace;
                padding: 12px;
            }
        """)
        self.analysis_text.setPlainText("Select a threat to view detailed analysis...")
        analysis_layout.addWidget(self.analysis_text)
        
        layout.addWidget(analysis_frame)
        
        return widget
    
    def _create_pattern_learning_tab(self) -> QWidget:
        """Create the pattern learning tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Pattern categories tree
        pattern_label = QLabel("📚 Learned Threat Patterns")
        pattern_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        layout.addWidget(pattern_label)
        
        self.pattern_tree = QTreeWidget()
        self.pattern_tree.setHeaderLabels(["Pattern Category", "Count", "Accuracy", "Last Updated"])
        self.pattern_tree.setStyleSheet("""
            QTreeWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6edf3;
            }
            QTreeWidget::item {
                padding: 8px;
            }
            QTreeWidget::item:selected {
                background: #238636;
            }
            QHeaderView::section {
                background: #161b22;
                color: #e6edf3;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        
        # Add pattern categories
        categories = [
            ("Network Attacks", [
                ("Port Scanning", "1,234", "98.2%"),
                ("DDoS Patterns", "567", "97.8%"),
                ("ARP Spoofing", "89", "99.1%"),
            ]),
            ("Authentication Attacks", [
                ("Brute Force", "2,345", "99.5%"),
                ("Credential Stuffing", "890", "96.7%"),
                ("Pass-the-Hash", "234", "98.9%"),
            ]),
            ("Malware Behavior", [
                ("Ransomware", "456", "99.8%"),
                ("Trojan C2", "789", "97.5%"),
                ("Rootkit Activity", "123", "98.3%"),
            ]),
            ("Data Exfiltration", [
                ("DNS Tunneling", "345", "99.2%"),
                ("HTTP Exfil", "567", "96.4%"),
                ("Steganography", "78", "95.1%"),
            ]),
        ]
        
        for category, patterns in categories:
            cat_item = QTreeWidgetItem([category, "", "", ""])
            cat_item.setForeground(0, QColor("#00d4ff"))
            
            for name, count, accuracy in patterns:
                pattern_item = QTreeWidgetItem([name, count, accuracy, datetime.now().strftime("%Y-%m-%d")])
                if float(accuracy[:-1]) > 98:
                    pattern_item.setForeground(2, QColor("#00ff88"))
                elif float(accuracy[:-1]) > 95:
                    pattern_item.setForeground(2, QColor("#ffcc00"))
                else:
                    pattern_item.setForeground(2, QColor("#da3633"))
                cat_item.addChild(pattern_item)
            
            self.pattern_tree.addTopLevelItem(cat_item)
        
        self.pattern_tree.expandAll()
        layout.addWidget(self.pattern_tree)
        
        return widget
    
    def _create_predictions_tab(self) -> QWidget:
        """Create the predictions tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        pred_label = QLabel("🔮 Threat Predictions")
        pred_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        layout.addWidget(pred_label)
        
        # Prediction cards
        pred_scroll = QScrollArea()
        pred_scroll.setWidgetResizable(True)
        pred_scroll.setStyleSheet("""
            QScrollArea {
                background: transparent;
                border: none;
            }
        """)
        
        pred_content = QWidget()
        pred_grid = QGridLayout(pred_content)
        
        predictions = [
            ("Ransomware Attack", "High", "72%", "Within 24-48 hours", "#da3633"),
            ("Phishing Campaign", "Medium", "68%", "Next 7 days", "#f0883e"),
            ("DDoS Attempt", "Low", "45%", "Possible next month", "#ffcc00"),
            ("Insider Threat", "Medium", "61%", "Ongoing monitoring", "#f0883e"),
            ("Zero-Day Exploit", "Low", "38%", "Uncertain timeline", "#00d4ff"),
            ("Supply Chain Attack", "Medium", "55%", "Next 30 days", "#f0883e"),
        ]
        
        for i, (threat, risk, prob, timeline, color) in enumerate(predictions):
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background: #161b22;
                    border: 1px solid {color};
                    border-radius: 12px;
                    padding: 16px;
                }}
            """)
            card_layout = QVBoxLayout(card)
            
            threat_lbl = QLabel(threat)
            threat_lbl.setStyleSheet(f"color: {color}; font-size: 16px; font-weight: bold;")
            
            prob_lbl = QLabel(f"Probability: {prob}")
            prob_lbl.setStyleSheet("color: #e6edf3;")
            
            risk_lbl = QLabel(f"Risk Level: {risk}")
            risk_lbl.setStyleSheet("color: #8b949e;")
            
            timeline_lbl = QLabel(f"⏱️ {timeline}")
            timeline_lbl.setStyleSheet("color: #00d4ff; font-size: 11px;")
            
            card_layout.addWidget(threat_lbl)
            card_layout.addWidget(prob_lbl)
            card_layout.addWidget(risk_lbl)
            card_layout.addWidget(timeline_lbl)
            
            pred_grid.addWidget(card, i // 3, i % 3)
        
        pred_scroll.setWidget(pred_content)
        layout.addWidget(pred_scroll)
        
        return widget
    
    def _create_training_tab(self) -> QWidget:
        """Create the training tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Training configuration
        config_group = QGroupBox("⚡ Training Configuration")
        config_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e6edf3;
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
        config_layout = QGridLayout(config_group)
        
        # Training parameters
        params = [
            ("Learning Rate:", "0.001"),
            ("Batch Size:", "128"),
            ("Epochs:", "100"),
            ("Dropout Rate:", "0.3"),
        ]
        
        for row, (label, value) in enumerate(params):
            lbl = QLabel(label)
            lbl.setStyleSheet("color: #8b949e;")
            
            input_field = QLineEdit(value)
            input_field.setStyleSheet("""
                QLineEdit {
                    background: #0d1117;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 8px;
                    color: #e6edf3;
                }
            """)
            
            config_layout.addWidget(lbl, row, 0)
            config_layout.addWidget(input_field, row, 1)
        
        layout.addWidget(config_group)
        
        # Training progress
        progress_frame = QFrame()
        progress_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 16px;
            }
        """)
        progress_layout = QVBoxLayout(progress_frame)
        
        progress_label = QLabel("📈 Training Progress")
        progress_label.setStyleSheet("color: #e6edf3; font-weight: bold;")
        progress_layout.addWidget(progress_label)
        
        self.training_progress = QProgressBar()
        self.training_progress.setStyleSheet("""
            QProgressBar {
                background: #21262d;
                border: none;
                border-radius: 8px;
                height: 24px;
                text-align: center;
                color: #e6edf3;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00d4ff, stop:1 #00ff88);
                border-radius: 8px;
            }
        """)
        progress_layout.addWidget(self.training_progress)
        
        self.training_log = QTextEdit()
        self.training_log.setReadOnly(True)
        self.training_log.setMaximumHeight(200)
        self.training_log.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #00ff88;
                font-family: 'Consolas', monospace;
                padding: 12px;
            }
        """)
        self.training_log.setPlainText("[TRAINING] Ready to begin...\n")
        progress_layout.addWidget(self.training_log)
        
        # Training buttons
        btn_layout = QHBoxLayout()
        
        train_btn = QPushButton("🚀 Start Training")
        train_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        
        stop_btn = QPushButton("⏹️ Stop")
        stop_btn.setStyleSheet("""
            QPushButton {
                background: #da3633;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
            }
        """)
        
        btn_layout.addWidget(train_btn)
        btn_layout.addWidget(stop_btn)
        btn_layout.addStretch()
        
        progress_layout.addLayout(btn_layout)
        
        layout.addWidget(progress_frame)
        layout.addStretch()
        
        return widget
    
    def _connect_signals(self):
        """Connect widget signals"""
        pass
    
    def _start_monitoring(self):
        """Start threat monitoring"""
        self.start_monitor_btn.setEnabled(False)
        self.stop_monitor_btn.setEnabled(True)
        self.neural_status.setText("🧠 Neural: Monitoring")
        
        self.threat_worker = ThreatWorker("network")
        self.threat_worker.threat_detected.connect(self._on_threat_detected)
        self.threat_worker.learning_update.connect(self._on_learning_update)
        self.threat_worker.start()
    
    def _stop_monitoring(self):
        """Stop threat monitoring"""
        if self.threat_worker:
            self.threat_worker.stop()
            self.threat_worker.wait()
        
        self.start_monitor_btn.setEnabled(True)
        self.stop_monitor_btn.setEnabled(False)
        self.neural_status.setText("🧠 Neural: Idle")
    
    def _on_threat_detected(self, threat: dict):
        """Handle detected threat"""
        self.detected_threats.append(threat)
        self.threat_status.setText(f"🎯 Threats: {len(self.detected_threats)}")
        
        # Add to table
        row = self.threat_table.rowCount()
        self.threat_table.insertRow(row)
        
        self.threat_table.setItem(row, 0, QTableWidgetItem(
            datetime.now().strftime("%H:%M:%S")))
        self.threat_table.setItem(row, 1, QTableWidgetItem(threat["type"]))
        self.threat_table.setItem(row, 2, QTableWidgetItem(threat["source_ip"]))
        
        conf_item = QTableWidgetItem(f"{threat['confidence']*100:.1f}%")
        conf_item.setForeground(QColor("#00ff88"))
        self.threat_table.setItem(row, 3, conf_item)
        
        sev_item = QTableWidgetItem(threat["severity"])
        if threat["severity"] == "Critical":
            sev_item.setForeground(QColor("#da3633"))
        elif threat["severity"] == "High":
            sev_item.setForeground(QColor("#f0883e"))
        elif threat["severity"] == "Medium":
            sev_item.setForeground(QColor("#ffcc00"))
        else:
            sev_item.setForeground(QColor("#00d4ff"))
        self.threat_table.setItem(row, 4, sev_item)
        
        self.threat_table.setItem(row, 5, QTableWidgetItem("Active"))
        
        # Update analysis
        self.analysis_text.append(
            f"[{datetime.now().strftime('%H:%M:%S')}] THREAT DETECTED: {threat['type']}\n"
            f"  Source: {threat['source_ip']}\n"
            f"  Confidence: {threat['confidence']*100:.1f}%\n"
            f"  Severity: {threat['severity']}\n"
        )
    
    def _on_learning_update(self, learning: dict):
        """Handle learning updates"""
        self.learning_status.setText(
            f"📚 Learning: {learning['accuracy']*100:.1f}% accuracy"
        )
