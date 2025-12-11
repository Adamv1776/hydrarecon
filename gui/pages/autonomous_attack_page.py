#!/usr/bin/env python3
"""
Autonomous Attack Orchestrator GUI Page
AI-driven autonomous penetration testing with self-directing attack chains.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel, QPushButton,
    QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem, QComboBox,
    QProgressBar, QTabWidget, QScrollArea, QGridLayout, QGroupBox,
    QSpinBox, QCheckBox, QSplitter, QListWidget, QListWidgetItem,
    QSlider, QDoubleSpinBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor

import asyncio
from datetime import datetime
from typing import Optional, Dict, List, Any
import json


class AttackWorker(QThread):
    """Worker thread for autonomous attack execution"""
    progress_update = pyqtSignal(int, str)
    attack_result = pyqtSignal(dict)
    phase_complete = pyqtSignal(str, dict)
    chain_complete = pyqtSignal(dict)
    
    def __init__(self, attack_config: Dict[str, Any]):
        super().__init__()
        self.attack_config = attack_config
        self.running = True
    
    def run(self):
        """Execute autonomous attack simulation"""
        phases = [
            ("reconnaissance", "Gathering intelligence..."),
            ("vulnerability_discovery", "Discovering vulnerabilities..."),
            ("exploitation", "Executing exploits..."),
            ("privilege_escalation", "Escalating privileges..."),
            ("lateral_movement", "Moving laterally..."),
            ("data_exfiltration", "Simulating exfiltration..."),
            ("persistence", "Establishing persistence..."),
            ("cleanup", "Covering tracks...")
        ]
        
        total_phases = len(phases)
        results = {}
        
        for i, (phase_name, description) in enumerate(phases):
            if not self.running:
                break
            
            progress = int((i / total_phases) * 100)
            self.progress_update.emit(progress, description)
            
            # Simulate phase execution
            import time
            time.sleep(0.5)
            
            phase_result = {
                "status": "success",
                "findings": f"Phase {phase_name} completed",
                "next_actions": ["continue_chain"]
            }
            results[phase_name] = phase_result
            self.phase_complete.emit(phase_name, phase_result)
        
        self.progress_update.emit(100, "Attack chain complete")
        self.chain_complete.emit(results)
    
    def stop(self):
        self.running = False


class AutonomousAttackPage(QWidget):
    """Autonomous Attack Orchestrator Interface"""
    
    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self.attack_worker = None
        self.attack_chains = []
        self.current_chain = None
        
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
                background: #238636;
                color: #ffffff;
            }
            QTabBar::tab:hover:!selected {
                background: #21262d;
            }
        """)
        
        # Attack Orchestrator Tab
        tabs.addTab(self._create_orchestrator_tab(), "🤖 Attack Orchestrator")
        tabs.addTab(self._create_chain_builder_tab(), "⛓️ Chain Builder")
        tabs.addTab(self._create_ai_decisions_tab(), "🧠 AI Decisions")
        tabs.addTab(self._create_results_tab(), "📊 Results")
        tabs.addTab(self._create_playbooks_tab(), "📚 Playbooks")
        
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
        
        title = QLabel("🤖 Autonomous Attack Orchestrator")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88;")
        
        subtitle = QLabel("AI-Driven Self-Directing Penetration Testing with Dynamic Attack Chains")
        subtitle.setStyleSheet("color: #c9d1d9; font-size: 14px;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Status indicators
        status_frame = QFrame()
        status_layout = QHBoxLayout(status_frame)
        
        self.ai_status = QLabel("🧠 AI: Idle")
        self.ai_status.setStyleSheet("color: #00d4ff; font-weight: bold;")
        
        self.attack_status = QLabel("⚡ Status: Ready")
        self.attack_status.setStyleSheet("color: #ffcc00; font-weight: bold;")
        
        status_layout.addWidget(self.ai_status)
        status_layout.addWidget(self.attack_status)
        
        layout.addWidget(status_frame)
        
        return frame
    
    def _create_orchestrator_tab(self) -> QWidget:
        """Create the main attack orchestrator tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Splitter for target config and attack console
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Target Configuration
        left_panel = QFrame()
        left_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
            }
        """)
        left_layout = QVBoxLayout(left_panel)
        
        # Target Configuration Group
        target_group = QGroupBox("🎯 Target Configuration")
        target_group.setStyleSheet("""
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
        target_layout = QVBoxLayout(target_group)
        
        # Target input
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Target IP, hostname, or CIDR range...")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 12px;
                color: #e6edf3;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #238636;
            }
        """)
        target_layout.addWidget(self.target_input)
        
        # Attack scope
        scope_label = QLabel("Attack Scope:")
        scope_label.setStyleSheet("color: #c9d1d9; font-weight: bold;")
        self.scope_combo = QComboBox()
        self.scope_combo.addItems([
            "Full Autonomous",
            "Guided Autonomous", 
            "Semi-Autonomous",
            "Manual with AI Suggestions"
        ])
        self.scope_combo.setStyleSheet("""
            QComboBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                color: #e6edf3;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background: #161b22;
                border: 1px solid #30363d;
                color: #e6edf3;
                selection-background-color: #238636;
            }
        """)
        target_layout.addWidget(scope_label)
        target_layout.addWidget(self.scope_combo)
        
        # Aggression level
        aggression_label = QLabel("Aggression Level:")
        aggression_label.setStyleSheet("color: #c9d1d9; font-weight: bold;")
        self.aggression_slider = QSlider(Qt.Orientation.Horizontal)
        self.aggression_slider.setMinimum(1)
        self.aggression_slider.setMaximum(10)
        self.aggression_slider.setValue(5)
        self.aggression_slider.setStyleSheet("""
            QSlider::groove:horizontal {
                background: #21262d;
                height: 8px;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #238636;
                width: 20px;
                margin: -6px 0;
                border-radius: 10px;
            }
            QSlider::sub-page:horizontal {
                background: #238636;
                border-radius: 4px;
            }
        """)
        self.aggression_value = QLabel("5")
        self.aggression_value.setStyleSheet("color: #00ff88; font-weight: bold;")
        self.aggression_slider.valueChanged.connect(
            lambda v: self.aggression_value.setText(str(v))
        )
        
        aggression_layout = QHBoxLayout()
        aggression_layout.addWidget(self.aggression_slider)
        aggression_layout.addWidget(self.aggression_value)
        
        target_layout.addWidget(aggression_label)
        target_layout.addLayout(aggression_layout)
        
        left_layout.addWidget(target_group)
        
        # AI Configuration Group
        ai_group = QGroupBox("🧠 AI Configuration")
        ai_group.setStyleSheet("""
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
        ai_layout = QVBoxLayout(ai_group)
        
        # AI Model selection
        model_label = QLabel("AI Decision Model:")
        model_label.setStyleSheet("color: #c9d1d9; font-weight: bold;")
        self.ai_model_combo = QComboBox()
        self.ai_model_combo.addItems([
            "Neural Attack Planner v2",
            "Reinforcement Learning Agent",
            "Genetic Algorithm Optimizer",
            "Hybrid Multi-Model"
        ])
        ai_layout.addWidget(model_label)
        ai_layout.addWidget(self.ai_model_combo)
        
        # Learning rate
        lr_label = QLabel("Learning Rate:")
        lr_label.setStyleSheet("color: #c9d1d9; font-weight: bold;")
        self.learning_rate = QDoubleSpinBox()
        self.learning_rate.setRange(0.001, 1.0)
        self.learning_rate.setValue(0.01)
        self.learning_rate.setSingleStep(0.001)
        self.learning_rate.setDecimals(4)
        self.learning_rate.setStyleSheet("""
            QDoubleSpinBox {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #e6edf3;
            }
        """)
        ai_layout.addWidget(lr_label)
        ai_layout.addWidget(self.learning_rate)
        
        # Checkboxes for AI features
        self.adaptive_tactics = QCheckBox("Enable Adaptive Tactics")
        self.adaptive_tactics.setChecked(True)
        self.adaptive_tactics.setStyleSheet("color: #e6edf3;")
        
        self.real_time_learning = QCheckBox("Real-time Learning")
        self.real_time_learning.setChecked(True)
        self.real_time_learning.setStyleSheet("color: #e6edf3;")
        
        self.exploit_chaining = QCheckBox("Auto Exploit Chaining")
        self.exploit_chaining.setChecked(True)
        self.exploit_chaining.setStyleSheet("color: #e6edf3;")
        
        ai_layout.addWidget(self.adaptive_tactics)
        ai_layout.addWidget(self.real_time_learning)
        ai_layout.addWidget(self.exploit_chaining)
        
        left_layout.addWidget(ai_group)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 Launch Autonomous Attack")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #238636, stop:1 #2ea043);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 14px 24px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2ea043, stop:1 #3fb950);
            }
            QPushButton:pressed {
                background: #238636;
            }
        """)
        self.start_btn.clicked.connect(self._start_attack)
        
        self.stop_btn = QPushButton("⏹️ Abort")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background: #da3633;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 14px 24px;
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
        self.stop_btn.clicked.connect(self._stop_attack)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        
        left_layout.addLayout(btn_layout)
        left_layout.addStretch()
        
        splitter.addWidget(left_panel)
        
        # Right panel - Attack Console
        right_panel = QFrame()
        right_panel.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
            }
        """)
        right_layout = QVBoxLayout(right_panel)
        
        # Progress section
        progress_frame = QFrame()
        progress_layout = QVBoxLayout(progress_frame)
        
        progress_label = QLabel("Attack Progress:")
        progress_label.setStyleSheet("color: #e6edf3; font-weight: bold;")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
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
                    stop:0 #238636, stop:1 #00ff88);
                border-radius: 8px;
            }
        """)
        
        self.progress_status = QLabel("Ready to launch...")
        self.progress_status.setStyleSheet("color: #c9d1d9; font-style: italic;")
        
        progress_layout.addWidget(progress_label)
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_status)
        
        right_layout.addWidget(progress_frame)
        
        # Attack Console
        console_label = QLabel("📟 Attack Console:")
        console_label.setStyleSheet("color: #e6edf3; font-weight: bold;")
        right_layout.addWidget(console_label)
        
        self.attack_console = QTextEdit()
        self.attack_console.setReadOnly(True)
        self.attack_console.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #00ff88;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                padding: 12px;
            }
        """)
        self.attack_console.setPlainText("[HYDRA AUTONOMOUS] System initialized...\n"
                                         "[AI ENGINE] Neural network loaded...\n"
                                         "[READY] Awaiting target configuration...\n")
        right_layout.addWidget(self.attack_console)
        
        # Phase Tracker
        phase_label = QLabel("🔄 Attack Phases:")
        phase_label.setStyleSheet("color: #e6edf3; font-weight: bold;")
        right_layout.addWidget(phase_label)
        
        self.phase_list = QListWidget()
        self.phase_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6edf3;
                padding: 8px;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListWidget::item:selected {
                background: #238636;
            }
        """)
        self.phase_list.setMaximumHeight(150)
        
        phases = [
            "⏳ Reconnaissance",
            "⏳ Vulnerability Discovery", 
            "⏳ Exploitation",
            "⏳ Privilege Escalation",
            "⏳ Lateral Movement",
            "⏳ Data Exfiltration",
            "⏳ Persistence",
            "⏳ Cleanup"
        ]
        for phase in phases:
            self.phase_list.addItem(phase)
        
        right_layout.addWidget(self.phase_list)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_chain_builder_tab(self) -> QWidget:
        """Create the attack chain builder tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Chain builder header
        header_layout = QHBoxLayout()
        
        chain_title = QLabel("⛓️ Attack Chain Builder")
        chain_title.setStyleSheet("color: #e6edf3; font-size: 18px; font-weight: bold;")
        header_layout.addWidget(chain_title)
        header_layout.addStretch()
        
        add_phase_btn = QPushButton("+ Add Phase")
        add_phase_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        header_layout.addWidget(add_phase_btn)
        
        layout.addLayout(header_layout)
        
        # Chain visualization area
        chain_scroll = QScrollArea()
        chain_scroll.setWidgetResizable(True)
        chain_scroll.setStyleSheet("""
            QScrollArea {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        
        chain_content = QWidget()
        chain_layout = QVBoxLayout(chain_content)
        
        # Example chain phases
        chain_phases = [
            ("Port Scan", "nmap", "Discover open ports"),
            ("Service Detection", "nmap", "Identify running services"),
            ("Vuln Scan", "vuln_scanner", "Check for vulnerabilities"),
            ("Exploit Selection", "ai_engine", "AI selects best exploits"),
            ("Exploitation", "exploit_framework", "Execute exploits"),
            ("Post-Exploitation", "c2", "Establish C2 connection")
        ]
        
        for i, (name, tool, desc) in enumerate(chain_phases):
            phase_frame = QFrame()
            phase_frame.setStyleSheet("""
                QFrame {
                    background: #161b22;
                    border: 1px solid #30363d;
                    border-radius: 8px;
                    padding: 12px;
                }
            """)
            phase_layout = QHBoxLayout(phase_frame)
            
            # Phase number
            num_label = QLabel(f"{i+1}")
            num_label.setStyleSheet("""
                background: #238636;
                color: white;
                font-weight: bold;
                border-radius: 15px;
                padding: 8px 12px;
                min-width: 20px;
                text-align: center;
            """)
            num_label.setFixedWidth(40)
            phase_layout.addWidget(num_label)
            
            # Phase info
            info_layout = QVBoxLayout()
            name_label = QLabel(name)
            name_label.setStyleSheet("color: #e6edf3; font-weight: bold;")
            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color: #b0b8c2; font-size: 12px;")
            tool_label = QLabel(f"Tool: {tool}")
            tool_label.setStyleSheet("color: #00d4ff; font-size: 11px;")
            info_layout.addWidget(name_label)
            info_layout.addWidget(desc_label)
            info_layout.addWidget(tool_label)
            phase_layout.addLayout(info_layout, stretch=1)
            
            # Arrow indicator
            if i < len(chain_phases) - 1:
                arrow = QLabel("→")
                arrow.setStyleSheet("color: #00ff88; font-size: 24px;")
                phase_layout.addWidget(arrow)
            
            chain_layout.addWidget(phase_frame)
        
        chain_layout.addStretch()
        chain_scroll.setWidget(chain_content)
        
        layout.addWidget(chain_scroll)
        
        return widget
    
    def _create_ai_decisions_tab(self) -> QWidget:
        """Create the AI decisions tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # AI Decision Log
        decision_label = QLabel("🧠 AI Decision History")
        decision_label.setStyleSheet("color: #e6edf3; font-size: 18px; font-weight: bold;")
        layout.addWidget(decision_label)
        
        self.decision_table = QTableWidget()
        self.decision_table.setColumnCount(5)
        self.decision_table.setHorizontalHeaderLabels([
            "Timestamp", "Decision Type", "Confidence", "Action Taken", "Reasoning"
        ])
        self.decision_table.setStyleSheet("""
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
        
        # Add sample decisions
        decisions = [
            ("12:34:56", "Exploit Selection", "94.2%", "CVE-2023-1234", "Highest success probability based on service fingerprint"),
            ("12:35:12", "Attack Vector", "87.5%", "SMB Relay", "Network topology suggests relay attack feasibility"),
            ("12:36:01", "Evasion Method", "91.0%", "Process Hollowing", "EDR signature analysis indicates best evasion technique"),
        ]
        
        self.decision_table.setRowCount(len(decisions))
        for row, (ts, dec_type, conf, action, reason) in enumerate(decisions):
            self.decision_table.setItem(row, 0, QTableWidgetItem(ts))
            self.decision_table.setItem(row, 1, QTableWidgetItem(dec_type))
            
            conf_item = QTableWidgetItem(conf)
            conf_item.setForeground(QColor("#00ff88"))
            self.decision_table.setItem(row, 2, conf_item)
            
            self.decision_table.setItem(row, 3, QTableWidgetItem(action))
            self.decision_table.setItem(row, 4, QTableWidgetItem(reason))
        
        self.decision_table.resizeColumnsToContents()
        layout.addWidget(self.decision_table)
        
        return widget
    
    def _create_results_tab(self) -> QWidget:
        """Create the results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Results summary
        summary_frame = QFrame()
        summary_frame.setStyleSheet("""
            QFrame {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        summary_layout = QGridLayout(summary_frame)
        
        # Stats cards
        stats = [
            ("Vulnerabilities Found", "47", "#da3633"),
            ("Exploits Successful", "12", "#00ff88"),
            ("Systems Compromised", "8", "#f0883e"),
            ("Credentials Harvested", "156", "#00d4ff"),
        ]
        
        for col, (label, value, color) in enumerate(stats):
            stat_frame = QFrame()
            stat_frame.setStyleSheet(f"""
                QFrame {{
                    background: #0d1117;
                    border: 1px solid {color};
                    border-radius: 8px;
                    padding: 16px;
                }}
            """)
            stat_layout = QVBoxLayout(stat_frame)
            
            value_label = QLabel(value)
            value_label.setStyleSheet(f"color: {color}; font-size: 32px; font-weight: bold;")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            label_label = QLabel(label)
            label_label.setStyleSheet("color: #c9d1d9; font-size: 12px;")
            label_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            stat_layout.addWidget(value_label)
            stat_layout.addWidget(label_label)
            
            summary_layout.addWidget(stat_frame, 0, col)
        
        layout.addWidget(summary_frame)
        
        # Detailed results table
        results_label = QLabel("📋 Detailed Results")
        results_label.setStyleSheet("color: #e6edf3; font-size: 16px; font-weight: bold;")
        layout.addWidget(results_label)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Target", "Finding", "Severity", "Status", "Evidence"
        ])
        self.results_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6edf3;
            }
            QHeaderView::section {
                background: #161b22;
                color: #e6edf3;
                padding: 12px;
                border: none;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.results_table)
        
        return widget
    
    def _create_playbooks_tab(self) -> QWidget:
        """Create the playbooks tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        playbooks_label = QLabel("📚 Attack Playbooks")
        playbooks_label.setStyleSheet("color: #e6edf3; font-size: 18px; font-weight: bold;")
        layout.addWidget(playbooks_label)
        
        # Playbook list
        self.playbook_list = QListWidget()
        self.playbook_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                color: #e6edf3;
                padding: 8px;
            }
            QListWidget::item {
                padding: 12px;
                border-radius: 6px;
                margin: 4px;
            }
            QListWidget::item:selected {
                background: #238636;
            }
            QListWidget::item:hover:!selected {
                background: #21262d;
            }
        """)
        
        playbooks = [
            "🏢 Enterprise Network Pentest",
            "☁️ Cloud Infrastructure Assessment",
            "🌐 Web Application Attack",
            "📱 Mobile Application Security",
            "🔐 Active Directory Compromise",
            "🐳 Container Escape Playbook",
            "📡 Wireless Network Attack",
            "🏭 SCADA/ICS Assessment"
        ]
        
        for playbook in playbooks:
            self.playbook_list.addItem(playbook)
        
        layout.addWidget(self.playbook_list)
        
        return widget
    
    def _connect_signals(self):
        """Connect widget signals"""
        pass
    
    def _start_attack(self):
        """Start the autonomous attack"""
        target = self.target_input.text().strip()
        if not target:
            self._log_console("[ERROR] No target specified!")
            return
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.ai_status.setText("🧠 AI: Active")
        self.attack_status.setText("⚡ Status: Running")
        
        self._log_console(f"\n[AUTONOMOUS] Initiating attack on: {target}")
        self._log_console(f"[AI ENGINE] Loading {self.ai_model_combo.currentText()}...")
        self._log_console(f"[CONFIG] Aggression Level: {self.aggression_slider.value()}/10")
        self._log_console("[ATTACK] Beginning autonomous penetration test...\n")
        
        # Start attack worker
        attack_config = {
            "target": target,
            "scope": self.scope_combo.currentText(),
            "aggression": self.aggression_slider.value(),
            "ai_model": self.ai_model_combo.currentText(),
            "learning_rate": self.learning_rate.value(),
            "adaptive": self.adaptive_tactics.isChecked(),
            "real_time_learning": self.real_time_learning.isChecked(),
            "exploit_chaining": self.exploit_chaining.isChecked()
        }
        
        self.attack_worker = AttackWorker(attack_config)
        self.attack_worker.progress_update.connect(self._update_progress)
        self.attack_worker.phase_complete.connect(self._on_phase_complete)
        self.attack_worker.chain_complete.connect(self._on_attack_complete)
        self.attack_worker.start()
    
    def _stop_attack(self):
        """Stop the autonomous attack"""
        if self.attack_worker:
            self.attack_worker.stop()
            self.attack_worker.wait()
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.ai_status.setText("🧠 AI: Idle")
        self.attack_status.setText("⚡ Status: Stopped")
        
        self._log_console("\n[ABORT] Attack chain terminated by user")
    
    def _update_progress(self, progress: int, status: str):
        """Update attack progress"""
        self.progress_bar.setValue(progress)
        self.progress_status.setText(status)
        self._log_console(f"[PROGRESS] {status}")
    
    def _on_phase_complete(self, phase_name: str, result: dict):
        """Handle phase completion"""
        phase_names = [
            "reconnaissance", "vulnerability_discovery", "exploitation",
            "privilege_escalation", "lateral_movement", "data_exfiltration",
            "persistence", "cleanup"
        ]
        
        if phase_name in phase_names:
            index = phase_names.index(phase_name)
            item = self.phase_list.item(index)
            if item:
                item.setText(f"✅ {phase_name.replace('_', ' ').title()}")
        
        self._log_console(f"[PHASE] {phase_name.upper()} completed successfully")
    
    def _on_attack_complete(self, results: dict):
        """Handle attack completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.ai_status.setText("🧠 AI: Idle")
        self.attack_status.setText("⚡ Status: Complete")
        
        self._log_console("\n" + "="*50)
        self._log_console("[COMPLETE] Autonomous attack chain finished")
        self._log_console(f"[RESULTS] Phases completed: {len(results)}")
        self._log_console("="*50)
    
    def _log_console(self, message: str):
        """Add message to attack console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.attack_console.append(f"[{timestamp}] {message}")
        
        # Scroll to bottom
        scrollbar = self.attack_console.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
