"""
Swarm Intelligence Attack Network GUI Page
Distributed attack simulation using swarm intelligence algorithms.
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


class SwarmSimulationWorker(QThread):
    """Worker for swarm simulation"""
    progress = pyqtSignal(int)
    iteration_complete = pyqtSignal(dict)
    result = pyqtSignal(dict)
    finished = pyqtSignal()
    
    def __init__(self, swarm, config):
        super().__init__()
        self.swarm = swarm
        self.config = config
    
    def run(self):
        try:
            for i in range(100):
                self.progress.emit(i + 1)
                if i % 10 == 0:
                    self.iteration_complete.emit({
                        "iteration": i,
                        "discoveries": i // 10,
                        "agents_active": 50 - i // 20
                    })
                self.msleep(50)
            
            self.result.emit({
                "status": "completed",
                "targets_discovered": 12,
                "vulnerabilities": 5
            })
        except Exception as e:
            self.result.emit({"error": str(e)})
        finally:
            self.finished.emit()


class SwarmIntelligencePage(QWidget):
    """Swarm Intelligence Attack Network GUI"""
    
    def __init__(self, config, db):
        super().__init__()
        self.config = config
        self.db = db
        self.swarm = None
        self.worker = None
        
        self._init_swarm()
        self._setup_ui()
        self._apply_styles()
    
    def _init_swarm(self):
        """Initialize swarm engine"""
        try:
            from core.swarm_intelligence import SwarmIntelligenceEngine
            self.swarm = SwarmIntelligenceEngine()
        except ImportError:
            self.swarm = None
    
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
        tabs.setObjectName("swarmTabs")
        
        tabs.addTab(self._create_simulation_tab(), "🐝 Swarm Simulation")
        tabs.addTab(self._create_algorithms_tab(), "🧬 Algorithms")
        tabs.addTab(self._create_agents_tab(), "🤖 Agent Monitor")
        tabs.addTab(self._create_visualization_tab(), "📊 Visualization")
        tabs.addTab(self._create_results_tab(), "📋 Results")
        
        layout.addWidget(tabs)
    
    def _create_header(self) -> QFrame:
        """Create header section"""
        frame = QFrame()
        frame.setObjectName("headerFrame")
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🐝 Swarm Intelligence Network")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #ffd700;")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Distributed attack simulation using bio-inspired algorithms")
        subtitle.setStyleSheet("color: #888; font-size: 12px;")
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Swarm stats
        stats_layout = QHBoxLayout()
        
        self.agents_label = QLabel("● Agents: 50")
        self.agents_label.setStyleSheet("color: #ffd700; font-size: 11px;")
        stats_layout.addWidget(self.agents_label)
        
        self.discoveries_label = QLabel("Discoveries: 0")
        self.discoveries_label.setStyleSheet("color: #00ff88; font-size: 11px;")
        stats_layout.addWidget(self.discoveries_label)
        
        layout.addLayout(stats_layout)
        
        # Action button
        self.deploy_btn = QPushButton("🐝 Deploy Swarm")
        self.deploy_btn.setObjectName("primaryButton")
        self.deploy_btn.clicked.connect(self._deploy_swarm)
        layout.addWidget(self.deploy_btn)
        
        return frame
    
    def _create_simulation_tab(self) -> QWidget:
        """Create simulation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left - Configuration
        left_panel = QFrame()
        left_panel.setObjectName("configPanel")
        left_layout = QVBoxLayout(left_panel)
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        target_layout.addWidget(QLabel("Target Network/Hosts:"))
        self.targets_input = QTextEdit()
        self.targets_input.setPlaceholderText("192.168.1.0/24\nexample.com\n10.0.0.1-10.0.0.100")
        self.targets_input.setMaximumHeight(100)
        target_layout.addWidget(self.targets_input)
        
        left_layout.addWidget(target_group)
        
        # Swarm configuration
        swarm_group = QGroupBox("Swarm Configuration")
        swarm_layout = QGridLayout(swarm_group)
        
        swarm_layout.addWidget(QLabel("Algorithm:"), 0, 0)
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems([
            "Ant Colony Optimization",
            "Particle Swarm Optimization",
            "Bee Colony Algorithm",
            "Wolf Pack Algorithm",
            "Firefly Algorithm"
        ])
        swarm_layout.addWidget(self.algorithm_combo, 0, 1)
        
        swarm_layout.addWidget(QLabel("Agent Count:"), 1, 0)
        self.agent_count = QSpinBox()
        self.agent_count.setRange(10, 500)
        self.agent_count.setValue(50)
        swarm_layout.addWidget(self.agent_count, 1, 1)
        
        swarm_layout.addWidget(QLabel("Iterations:"), 2, 0)
        self.iterations = QSpinBox()
        self.iterations.setRange(10, 1000)
        self.iterations.setValue(100)
        swarm_layout.addWidget(self.iterations, 2, 1)
        
        swarm_layout.addWidget(QLabel("Exploration Rate:"), 3, 0)
        self.exploration_rate = QDoubleSpinBox()
        self.exploration_rate.setRange(0.0, 1.0)
        self.exploration_rate.setValue(0.3)
        self.exploration_rate.setSingleStep(0.1)
        swarm_layout.addWidget(self.exploration_rate, 3, 1)
        
        left_layout.addWidget(swarm_group)
        
        # Attack options
        attack_group = QGroupBox("Attack Options")
        attack_layout = QVBoxLayout(attack_group)
        
        self.reconnaissance = QCheckBox("Reconnaissance phase")
        self.reconnaissance.setChecked(True)
        attack_layout.addWidget(self.reconnaissance)
        
        self.enumeration = QCheckBox("Service enumeration")
        self.enumeration.setChecked(True)
        attack_layout.addWidget(self.enumeration)
        
        self.exploitation = QCheckBox("Exploitation phase")
        attack_layout.addWidget(self.exploitation)
        
        self.lateral_movement = QCheckBox("Lateral movement")
        attack_layout.addWidget(self.lateral_movement)
        
        left_layout.addWidget(attack_group)
        
        # Control buttons
        controls = QHBoxLayout()
        
        self.start_btn = QPushButton("🐝 Start Simulation")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.clicked.connect(self._start_simulation)
        controls.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_simulation)
        controls.addWidget(self.stop_btn)
        
        left_layout.addLayout(controls)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        left_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to deploy swarm")
        self.status_label.setStyleSheet("color: #888;")
        left_layout.addWidget(self.status_label)
        
        left_layout.addStretch()
        splitter.addWidget(left_panel)
        
        # Right - Live status
        right_panel = QFrame()
        right_panel.setObjectName("statusPanel")
        right_layout = QVBoxLayout(right_panel)
        
        right_layout.addWidget(QLabel("Swarm Activity Log:"))
        
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        right_layout.addWidget(self.activity_log)
        
        # Discoveries
        discoveries_group = QGroupBox("Discoveries")
        discoveries_layout = QVBoxLayout(discoveries_group)
        
        self.discoveries_table = QTableWidget()
        self.discoveries_table.setColumnCount(4)
        self.discoveries_table.setHorizontalHeaderLabels([
            "Target", "Discovery", "Agent", "Time"
        ])
        self.discoveries_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        discoveries_layout.addWidget(self.discoveries_table)
        
        right_layout.addWidget(discoveries_group)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_algorithms_tab(self) -> QWidget:
        """Create algorithms tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Algorithm selection
        algo_group = QGroupBox("Select Algorithm")
        algo_layout = QVBoxLayout(algo_group)
        
        algorithms = [
            ("🐜 Ant Colony Optimization", "Best for path finding and network mapping"),
            ("🔵 Particle Swarm Optimization", "Optimal for parameter tuning and vulnerability scanning"),
            ("🐝 Bee Colony Algorithm", "Excellent for distributed search operations"),
            ("🐺 Wolf Pack Algorithm", "Effective for coordinated attacks"),
            ("🔥 Firefly Algorithm", "Good for optimization problems")
        ]
        
        self.algo_buttons = []
        for name, desc in algorithms:
            frame = QFrame()
            frame.setObjectName("algoCard")
            frame_layout = QHBoxLayout(frame)
            
            btn = QPushButton(name)
            btn.setCheckable(True)
            btn.setMinimumWidth(250)
            self.algo_buttons.append(btn)
            frame_layout.addWidget(btn)
            
            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color: #888;")
            frame_layout.addWidget(desc_label)
            
            frame_layout.addStretch()
            algo_layout.addWidget(frame)
        
        self.algo_buttons[0].setChecked(True)
        layout.addWidget(algo_group)
        
        # Algorithm parameters
        params_group = QGroupBox("Algorithm Parameters")
        params_layout = QGridLayout(params_group)
        
        # Ant Colony params
        params_layout.addWidget(QLabel("Pheromone Decay:"), 0, 0)
        self.pheromone_decay = QDoubleSpinBox()
        self.pheromone_decay.setRange(0.01, 0.5)
        self.pheromone_decay.setValue(0.1)
        params_layout.addWidget(self.pheromone_decay, 0, 1)
        
        params_layout.addWidget(QLabel("Alpha (Pheromone Weight):"), 1, 0)
        self.alpha = QDoubleSpinBox()
        self.alpha.setRange(0.1, 5.0)
        self.alpha.setValue(1.0)
        params_layout.addWidget(self.alpha, 1, 1)
        
        params_layout.addWidget(QLabel("Beta (Heuristic Weight):"), 2, 0)
        self.beta = QDoubleSpinBox()
        self.beta.setRange(0.1, 5.0)
        self.beta.setValue(2.0)
        params_layout.addWidget(self.beta, 2, 1)
        
        params_layout.addWidget(QLabel("Inertia Weight:"), 0, 2)
        self.inertia = QDoubleSpinBox()
        self.inertia.setRange(0.1, 1.0)
        self.inertia.setValue(0.7)
        params_layout.addWidget(self.inertia, 0, 3)
        
        params_layout.addWidget(QLabel("Cognitive Weight:"), 1, 2)
        self.cognitive = QDoubleSpinBox()
        self.cognitive.setRange(0.1, 3.0)
        self.cognitive.setValue(1.5)
        params_layout.addWidget(self.cognitive, 1, 3)
        
        params_layout.addWidget(QLabel("Social Weight:"), 2, 2)
        self.social = QDoubleSpinBox()
        self.social.setRange(0.1, 3.0)
        self.social.setValue(1.5)
        params_layout.addWidget(self.social, 2, 3)
        
        layout.addWidget(params_group)
        
        layout.addStretch()
        return widget
    
    def _create_agents_tab(self) -> QWidget:
        """Create agent monitor tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Agent overview
        overview = QHBoxLayout()
        
        for label, value, color in [
            ("Total Agents", "50", "#ffd700"),
            ("Active", "47", "#00ff88"),
            ("Idle", "2", "#888888"),
            ("Exhausted", "1", "#ff4444")
        ]:
            stat_frame = QFrame()
            stat_frame.setObjectName("statCard")
            stat_v = QVBoxLayout(stat_frame)
            
            val = QLabel(value)
            val.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
            val.setStyleSheet(f"color: {color};")
            val.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_v.addWidget(val)
            
            lbl = QLabel(label)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet("color: #888;")
            stat_v.addWidget(lbl)
            
            overview.addWidget(stat_frame)
        
        layout.addLayout(overview)
        
        # Agent table
        agents_group = QGroupBox("Agent Status")
        agents_layout = QVBoxLayout(agents_group)
        
        self.agents_table = QTableWidget()
        self.agents_table.setColumnCount(7)
        self.agents_table.setHorizontalHeaderLabels([
            "Agent ID", "Role", "Position", "Energy", "Discoveries", "Status", "Last Action"
        ])
        self.agents_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        agents = [
            ("agent_a1b2", "Scout", "(45.2, 78.1, 12.4)", "95%", "3", "● Active", "Exploring"),
            ("agent_c3d4", "Worker", "(12.8, 34.5, 67.2)", "87%", "5", "● Active", "Following trail"),
            ("agent_e5f6", "Soldier", "(89.1, 23.4, 45.6)", "72%", "2", "● Active", "Attacking"),
            ("agent_g7h8", "Coordinator", "(50.0, 50.0, 50.0)", "100%", "0", "● Active", "Coordinating"),
            ("agent_i9j0", "Scout", "(67.3, 12.9, 88.7)", "15%", "7", "⚠ Low Energy", "Returning"),
        ]
        
        self.agents_table.setRowCount(len(agents))
        for row, agent in enumerate(agents):
            for col, value in enumerate(agent):
                item = QTableWidgetItem(value)
                if col == 3:  # Energy
                    energy = int(value.replace("%", ""))
                    if energy < 30:
                        item.setForeground(QColor("#ff4444"))
                    elif energy < 60:
                        item.setForeground(QColor("#ff8800"))
                    else:
                        item.setForeground(QColor("#00ff88"))
                elif col == 5:  # Status
                    if "Active" in value:
                        item.setForeground(QColor("#00ff88"))
                    elif "Low" in value:
                        item.setForeground(QColor("#ff8800"))
                self.agents_table.setItem(row, col, item)
        
        agents_layout.addWidget(self.agents_table)
        layout.addWidget(agents_group)
        
        return widget
    
    def _create_visualization_tab(self) -> QWidget:
        """Create visualization tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Placeholder for visualization
        viz_frame = QFrame()
        viz_frame.setObjectName("vizFrame")
        viz_frame.setMinimumHeight(400)
        viz_layout = QVBoxLayout(viz_frame)
        
        viz_label = QLabel("🌐 Swarm Visualization")
        viz_label.setFont(QFont("Segoe UI", 24))
        viz_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        viz_layout.addWidget(viz_label)
        
        viz_text = QLabel("Real-time 3D swarm visualization would appear here\n(Requires OpenGL/WebGL integration)")
        viz_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        viz_text.setStyleSheet("color: #888;")
        viz_layout.addWidget(viz_text)
        
        layout.addWidget(viz_frame)
        
        # Visualization controls
        controls = QHBoxLayout()
        
        controls.addWidget(QLabel("View:"))
        view_combo = QComboBox()
        view_combo.addItems(["3D Space", "Network Graph", "Heatmap", "Timeline"])
        controls.addWidget(view_combo)
        
        controls.addWidget(QLabel("Speed:"))
        speed_slider = QSlider(Qt.Orientation.Horizontal)
        speed_slider.setRange(1, 10)
        speed_slider.setValue(5)
        speed_slider.setMaximumWidth(150)
        controls.addWidget(speed_slider)
        
        controls.addStretch()
        
        export_btn = QPushButton("📸 Capture")
        controls.addWidget(export_btn)
        
        layout.addLayout(controls)
        
        return widget
    
    def _create_results_tab(self) -> QWidget:
        """Create results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Results summary
        summary_group = QGroupBox("Simulation Results")
        summary_layout = QGridLayout(summary_group)
        
        results = [
            ("Total Iterations", "100"),
            ("Targets Discovered", "12"),
            ("Vulnerabilities Found", "5"),
            ("Services Enumerated", "47"),
            ("Best Path Found", "Yes"),
            ("Convergence Time", "45 iterations"),
        ]
        
        for i, (label, value) in enumerate(results):
            lbl = QLabel(label + ":")
            lbl.setStyleSheet("color: #888;")
            summary_layout.addWidget(lbl, i // 2, (i % 2) * 2)
            
            val = QLabel(value)
            val.setStyleSheet("color: #ffd700; font-weight: bold;")
            summary_layout.addWidget(val, i // 2, (i % 2) * 2 + 1)
        
        layout.addWidget(summary_group)
        
        # Findings table
        findings_group = QGroupBox("Findings")
        findings_layout = QVBoxLayout(findings_group)
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(5)
        self.findings_table.setHorizontalHeaderLabels([
            "Target", "Finding", "Severity", "Discovered By", "Iteration"
        ])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        findings = [
            ("192.168.1.10", "Open SSH Port", "Medium", "agent_a1b2", "15"),
            ("192.168.1.15", "SQL Injection", "Critical", "agent_e5f6", "42"),
            ("192.168.1.20", "Default Credentials", "High", "agent_c3d4", "67"),
            ("192.168.1.25", "Outdated Apache", "Medium", "agent_a1b2", "78"),
            ("192.168.1.30", "RCE Vulnerability", "Critical", "agent_e5f6", "89"),
        ]
        
        self.findings_table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            for col, value in enumerate(finding):
                item = QTableWidgetItem(value)
                if col == 2:  # Severity
                    if value == "Critical":
                        item.setForeground(QColor("#ff4444"))
                    elif value == "High":
                        item.setForeground(QColor("#ff8800"))
                self.findings_table.setItem(row, col, item)
        
        findings_layout.addWidget(self.findings_table)
        layout.addWidget(findings_group)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        export_report = QPushButton("📊 Export Report")
        export_report.setObjectName("primaryButton")
        export_layout.addWidget(export_report)
        
        export_findings = QPushButton("📋 Export Findings")
        export_layout.addWidget(export_findings)
        
        export_json = QPushButton("📁 Export JSON")
        export_layout.addWidget(export_json)
        
        layout.addLayout(export_layout)
        
        return widget
    
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
                    stop:0 #3d3a1f, stop:1 #1a1a2e);
                border-radius: 10px;
                padding: 15px;
            }
            
            QFrame#configPanel, QFrame#statusPanel {
                background-color: #16213e;
                border-radius: 8px;
                padding: 10px;
            }
            
            QFrame#statCard, QFrame#algoCard {
                background-color: #16213e;
                border: 1px solid #0f3460;
                border-radius: 8px;
                padding: 10px;
            }
            
            QFrame#vizFrame {
                background-color: #0d1b2a;
                border: 2px solid #ffd700;
                border-radius: 10px;
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
                    stop:0 #ffd700, stop:1 #daa520);
                color: #000;
            }
            
            QPushButton#primaryButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ffe135, stop:1 #e5b533);
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
                border-bottom: 2px solid #ffd700;
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
            
            QProgressBar {
                border: 1px solid #0f3460;
                border-radius: 5px;
                background-color: #0d1b2a;
            }
            
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ffd700, stop:1 #00ff88);
                border-radius: 4px;
            }
            
            QTabWidget::pane {
                border: 1px solid #0f3460;
                border-radius: 5px;
            }
            
            QTabBar::tab {
                background-color: #16213e;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            
            QTabBar::tab:selected {
                background-color: #0f3460;
                border-bottom: 2px solid #ffd700;
            }
            
            QCheckBox::indicator:checked {
                background-color: #ffd700;
                border-color: #ffd700;
            }
        """)
    
    def _deploy_swarm(self):
        """Deploy swarm"""
        self._start_simulation()
    
    def _start_simulation(self):
        """Start swarm simulation"""
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Deploying swarm agents...")
        
        self.activity_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Swarm deployment initiated")
        self.activity_log.append(f"Algorithm: {self.algorithm_combo.currentText()}")
        self.activity_log.append(f"Agents: {self.agent_count.value()}")
        
        self.worker = SwarmSimulationWorker(self.swarm, {})
        self.worker.progress.connect(self._update_progress)
        self.worker.iteration_complete.connect(self._handle_iteration)
        self.worker.result.connect(self._handle_result)
        self.worker.finished.connect(self._simulation_finished)
        self.worker.start()
    
    def _stop_simulation(self):
        """Stop simulation"""
        if self.worker:
            self.worker.terminate()
        self._simulation_finished()
    
    def _update_progress(self, value):
        """Update progress"""
        self.progress_bar.setValue(value)
    
    def _handle_iteration(self, data):
        """Handle iteration update"""
        self.activity_log.append(
            f"[Iteration {data['iteration']}] Discoveries: {data['discoveries']}, Active: {data['agents_active']}"
        )
        self.discoveries_label.setText(f"Discoveries: {data['discoveries']}")
    
    def _handle_result(self, result):
        """Handle simulation result"""
        if "error" in result:
            self.status_label.setText(f"Error: {result['error']}")
            return
        
        self.status_label.setText(
            f"Completed: {result['targets_discovered']} targets, {result['vulnerabilities']} vulnerabilities"
        )
    
    def _simulation_finished(self):
        """Handle simulation completion"""
        self.progress_bar.setVisible(False)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
