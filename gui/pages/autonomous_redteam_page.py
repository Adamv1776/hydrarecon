"""
Autonomous Red Team Orchestrator GUI Page
Fully autonomous multi-stage attack planning with MITRE ATT&CK integration.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTextEdit, QLineEdit, QComboBox, QProgressBar, QTabWidget,
    QGroupBox, QSpinBox, QCheckBox, QSplitter, QGridLayout,
    QListWidget, QScrollArea, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor
from datetime import datetime


class CampaignExecutionWorker(QThread):
    """Worker for campaign execution"""
    progress = pyqtSignal(int)
    technique_executed = pyqtSignal(dict)
    phase_complete = pyqtSignal(str)
    finished = pyqtSignal(dict)
    
    def __init__(self, orchestrator, objective, targets, mode):
        super().__init__()
        self.orchestrator = orchestrator
        self.objective = objective
        self.targets = targets
        self.mode = mode
    
    def run(self):
        try:
            phases = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Exfiltration"]
            techniques_per_phase = 4
            total_steps = len(phases) * techniques_per_phase
            current_step = 0
            
            for phase in phases:
                for i in range(techniques_per_phase):
                    current_step += 1
                    progress = int((current_step / total_steps) * 100)
                    self.progress.emit(progress)
                    
                    self.technique_executed.emit({
                        "phase": phase,
                        "technique": f"T{1000 + current_step * 50}",
                        "success": True,
                        "target": f"target-{i % 3}"
                    })
                    
                    self.msleep(500)
                
                self.phase_complete.emit(phase)
            
            self.finished.emit({
                "status": "completed",
                "phases": len(phases),
                "techniques": total_steps,
                "success_rate": 0.85
            })
        except Exception as e:
            self.finished.emit({"error": str(e)})


class AutonomousRedTeamPage(QWidget):
    """Autonomous Red Team Orchestrator dashboard page."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.orchestrator = None
        self.campaigns = []
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the page UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Main content with tabs
        tabs = QTabWidget()
        tabs.addTab(self.create_campaign_tab(), "🎯 Campaign Planner")
        tabs.addTab(self.create_execution_tab(), "⚡ Live Execution")
        tabs.addTab(self.create_techniques_tab(), "🗡️ ATT&CK Techniques")
        tabs.addTab(self.create_targets_tab(), "🖥️ Targets")
        tabs.addTab(self.create_reports_tab(), "📊 Reports")
        
        layout.addWidget(tabs)
    
    def create_header(self) -> QFrame:
        """Create header section."""
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.StyledPanel)
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2d1f1f, stop:0.5 #3d2020, stop:1 #4a2525);
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("🤖 Autonomous Red Team Orchestrator")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #ff6b6b;")
        
        subtitle = QLabel("AI-Driven Multi-Stage Attack Planning with MITRE ATT&CK")
        subtitle.setStyleSheet("color: #888;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Stats
        stats_layout = QHBoxLayout()
        
        self.campaigns_count = self.create_stat_card("Campaigns", "0", "#ff6b6b")
        self.techniques_count = self.create_stat_card("Techniques", "24", "#ffd93d")
        self.success_rate = self.create_stat_card("Success Rate", "0%", "#00ff88")
        self.targets_count = self.create_stat_card("Targets", "0", "#6c5ce7")
        
        stats_layout.addWidget(self.campaigns_count)
        stats_layout.addWidget(self.techniques_count)
        stats_layout.addWidget(self.success_rate)
        stats_layout.addWidget(self.targets_count)
        
        layout.addLayout(stats_layout)
        
        return frame
    
    def create_stat_card(self, label: str, value: str, color: str) -> QFrame:
        """Create a statistics card."""
        card = QFrame()
        card.setFixedSize(120, 70)
        card.setStyleSheet(f"""
            QFrame {{
                background: rgba(0,0,0,0.3);
                border: 1px solid {color};
                border-radius: 8px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setObjectName("value")
        
        text_label = QLabel(label)
        text_label.setStyleSheet("color: #888; font-size: 10px;")
        text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(value_label)
        layout.addWidget(text_label)
        
        return card
    
    def create_campaign_tab(self) -> QWidget:
        """Create campaign planning tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Campaign creation form
        form_group = QGroupBox("Create Attack Campaign")
        form_layout = QGridLayout(form_group)
        
        # Objective
        form_layout.addWidget(QLabel("Objective:"), 0, 0)
        self.objective_combo = QComboBox()
        self.objective_combo.addItems([
            "Exfiltrate Sensitive Data",
            "Establish Persistence",
            "Compromise Domain Controller",
            "Deploy Ransomware (Simulation)",
            "Test Incident Response",
            "Full Network Compromise"
        ])
        form_layout.addWidget(self.objective_combo, 0, 1)
        
        # Mode
        form_layout.addWidget(QLabel("Operation Mode:"), 0, 2)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Stealth", "Balanced", "Aggressive", "Targeted"])
        form_layout.addWidget(self.mode_combo, 0, 3)
        
        # Constraints
        form_layout.addWidget(QLabel("Time Limit (hours):"), 1, 0)
        self.time_limit_spin = QSpinBox()
        self.time_limit_spin.setRange(1, 168)
        self.time_limit_spin.setValue(24)
        form_layout.addWidget(self.time_limit_spin, 1, 1)
        
        form_layout.addWidget(QLabel("Max Techniques:"), 1, 2)
        self.max_techniques_spin = QSpinBox()
        self.max_techniques_spin.setRange(5, 50)
        self.max_techniques_spin.setValue(20)
        form_layout.addWidget(self.max_techniques_spin, 1, 3)
        
        # Options
        self.avoid_detection = QCheckBox("Avoid Detection")
        self.avoid_detection.setChecked(True)
        form_layout.addWidget(self.avoid_detection, 2, 0)
        
        self.cleanup_tracks = QCheckBox("Cleanup Tracks")
        self.cleanup_tracks.setChecked(True)
        form_layout.addWidget(self.cleanup_tracks, 2, 1)
        
        self.use_living_off_land = QCheckBox("Living Off the Land")
        self.use_living_off_land.setChecked(True)
        form_layout.addWidget(self.use_living_off_land, 2, 2)
        
        self.adaptive_tactics = QCheckBox("Adaptive Tactics")
        self.adaptive_tactics.setChecked(True)
        form_layout.addWidget(self.adaptive_tactics, 2, 3)
        
        # Target selection
        form_layout.addWidget(QLabel("Target Environment:"), 3, 0)
        self.target_list = QListWidget()
        self.target_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.target_list.addItems([
            "🖥️ Web Server (10.0.0.10)",
            "💾 Database Server (10.0.0.20)",
            "👤 Workstation (10.0.0.50)",
            "🏛️ Domain Controller (10.0.0.5)",
            "📁 File Server (10.0.0.30)",
            "☁️ Cloud Gateway (10.0.0.100)"
        ])
        self.target_list.setMaximumHeight(100)
        form_layout.addWidget(self.target_list, 3, 1, 1, 3)
        
        layout.addWidget(form_group)
        
        # Action buttons
        buttons_layout = QHBoxLayout()
        
        plan_btn = QPushButton("📋 Generate Attack Plan")
        plan_btn.clicked.connect(self.generate_plan)
        plan_btn.setStyleSheet("background: #ffd93d; color: black; padding: 10px;")
        
        execute_btn = QPushButton("⚡ Execute Campaign")
        execute_btn.clicked.connect(self.execute_campaign)
        execute_btn.setStyleSheet("background: #ff6b6b; color: white; padding: 10px;")
        
        buttons_layout.addWidget(plan_btn)
        buttons_layout.addWidget(execute_btn)
        buttons_layout.addStretch()
        
        layout.addLayout(buttons_layout)
        
        # Attack plan display
        plan_group = QGroupBox("Generated Attack Plan")
        plan_layout = QVBoxLayout(plan_group)
        
        self.attack_plan_tree = QTreeWidget()
        self.attack_plan_tree.setHeaderLabels(["Phase / Technique", "Description", "Target", "Priority"])
        self.attack_plan_tree.setAlternatingRowColors(True)
        
        plan_layout.addWidget(self.attack_plan_tree)
        
        layout.addWidget(plan_group)
        
        return widget
    
    def create_execution_tab(self) -> QWidget:
        """Create live execution tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Execution status
        status_group = QGroupBox("Campaign Execution Status")
        status_layout = QVBoxLayout(status_group)
        
        # Progress
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(QLabel("Overall Progress:"))
        self.execution_progress = QProgressBar()
        self.execution_progress.setStyleSheet("""
            QProgressBar::chunk { background: #ff6b6b; }
        """)
        progress_layout.addWidget(self.execution_progress)
        self.progress_label = QLabel("0%")
        progress_layout.addWidget(self.progress_label)
        status_layout.addLayout(progress_layout)
        
        # Current phase
        self.current_phase_label = QLabel("Current Phase: Not Started")
        self.current_phase_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        status_layout.addWidget(self.current_phase_label)
        
        layout.addWidget(status_group)
        
        # Live execution log
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Execution log
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.addWidget(QLabel("📝 Execution Log"))
        
        self.execution_log = QTextEdit()
        self.execution_log.setReadOnly(True)
        self.execution_log.setStyleSheet("""
            QTextEdit {
                background: #0a0a1a;
                font-family: 'Consolas', monospace;
                color: #00ff88;
            }
        """)
        log_layout.addWidget(self.execution_log)
        splitter.addWidget(log_widget)
        
        # Kill chain visualization
        killchain_widget = QWidget()
        killchain_layout = QVBoxLayout(killchain_widget)
        killchain_layout.addWidget(QLabel("🗡️ Kill Chain Progress"))
        
        self.killchain_tree = QTreeWidget()
        self.killchain_tree.setHeaderLabels(["Phase", "Status", "Techniques"])
        self.killchain_tree.setAlternatingRowColors(True)
        
        # Add kill chain phases
        phases = [
            ("Reconnaissance", "⏳ Pending", "T1595, T1592"),
            ("Initial Access", "⏳ Pending", "T1566, T1190"),
            ("Execution", "⏳ Pending", "T1059, T1204"),
            ("Persistence", "⏳ Pending", "T1547, T1053"),
            ("Privilege Escalation", "⏳ Pending", "T1068, T1548"),
            ("Defense Evasion", "⏳ Pending", "T1070, T1027"),
            ("Credential Access", "⏳ Pending", "T1003, T1110"),
            ("Lateral Movement", "⏳ Pending", "T1021, T1570"),
            ("Collection", "⏳ Pending", "T1005, T1560"),
            ("Exfiltration", "⏳ Pending", "T1048, T1567")
        ]
        
        self.phase_items = {}
        for phase, status, techniques in phases:
            item = QTreeWidgetItem([phase, status, techniques])
            self.killchain_tree.addTopLevelItem(item)
            self.phase_items[phase] = item
        
        killchain_layout.addWidget(self.killchain_tree)
        splitter.addWidget(killchain_widget)
        
        splitter.setSizes([500, 400])
        layout.addWidget(splitter)
        
        # Control buttons
        controls = QHBoxLayout()
        
        self.pause_btn = QPushButton("⏸️ Pause")
        self.pause_btn.clicked.connect(self.pause_execution)
        
        self.resume_btn = QPushButton("▶️ Resume")
        self.resume_btn.clicked.connect(self.resume_execution)
        self.resume_btn.setEnabled(False)
        
        self.abort_btn = QPushButton("🛑 Abort")
        self.abort_btn.clicked.connect(self.abort_execution)
        self.abort_btn.setStyleSheet("background: #ff4444;")
        
        controls.addWidget(self.pause_btn)
        controls.addWidget(self.resume_btn)
        controls.addWidget(self.abort_btn)
        controls.addStretch()
        
        layout.addLayout(controls)
        
        return widget
    
    def create_techniques_tab(self) -> QWidget:
        """Create ATT&CK techniques tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Tactic:"))
        self.tactic_filter = QComboBox()
        self.tactic_filter.addItems([
            "All Tactics", "Reconnaissance", "Initial Access", "Execution",
            "Persistence", "Privilege Escalation", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact"
        ])
        filter_layout.addWidget(self.tactic_filter)
        
        filter_layout.addWidget(QLabel("Search:"))
        self.technique_search = QLineEdit()
        self.technique_search.setPlaceholderText("Search techniques...")
        filter_layout.addWidget(self.technique_search)
        
        filter_layout.addStretch()
        
        layout.addLayout(filter_layout)
        
        # Techniques table
        self.techniques_table = QTableWidget()
        self.techniques_table.setColumnCount(6)
        self.techniques_table.setHorizontalHeaderLabels([
            "ID", "Name", "Tactic", "Detection", "Success Rate", "Actions"
        ])
        self.techniques_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Add sample techniques
        techniques = [
            ("T1595", "Active Scanning", "Reconnaissance", "Medium", "85%"),
            ("T1566", "Phishing", "Initial Access", "High", "72%"),
            ("T1059", "Command Scripting", "Execution", "Medium", "90%"),
            ("T1547", "Boot Autostart", "Persistence", "Low", "95%"),
            ("T1068", "Exploitation for Priv Esc", "Privilege Escalation", "High", "65%"),
            ("T1070", "Indicator Removal", "Defense Evasion", "Low", "88%"),
            ("T1003", "Credential Dumping", "Credential Access", "High", "78%"),
            ("T1021", "Remote Services", "Lateral Movement", "Medium", "82%"),
            ("T1005", "Local Data", "Collection", "Low", "92%"),
            ("T1048", "Exfil Over Alt Protocol", "Exfiltration", "Medium", "75%")
        ]
        
        for i, (tid, name, tactic, detection, success) in enumerate(techniques):
            self.techniques_table.insertRow(i)
            self.techniques_table.setItem(i, 0, QTableWidgetItem(tid))
            self.techniques_table.setItem(i, 1, QTableWidgetItem(name))
            self.techniques_table.setItem(i, 2, QTableWidgetItem(tactic))
            
            det_item = QTableWidgetItem(detection)
            det_item.setForeground(QColor({
                "Low": "#00ff88", "Medium": "#ffd93d", "High": "#ff6b6b"
            }.get(detection, "#fff")))
            self.techniques_table.setItem(i, 3, det_item)
            
            self.techniques_table.setItem(i, 4, QTableWidgetItem(success))
            
            test_btn = QPushButton("Test")
            test_btn.setFixedWidth(60)
            self.techniques_table.setCellWidget(i, 5, test_btn)
        
        layout.addWidget(self.techniques_table)
        
        return widget
    
    def create_targets_tab(self) -> QWidget:
        """Create targets management tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Add target form
        form_group = QGroupBox("Add Target")
        form_layout = QGridLayout(form_group)
        
        form_layout.addWidget(QLabel("Name:"), 0, 0)
        self.target_name_input = QLineEdit()
        form_layout.addWidget(self.target_name_input, 0, 1)
        
        form_layout.addWidget(QLabel("IP/Hostname:"), 0, 2)
        self.target_ip_input = QLineEdit()
        form_layout.addWidget(self.target_ip_input, 0, 3)
        
        form_layout.addWidget(QLabel("Type:"), 1, 0)
        self.target_type_combo = QComboBox()
        self.target_type_combo.addItems([
            "Web Server", "Database", "Workstation", "Domain Controller",
            "File Server", "Cloud Instance", "Network Device"
        ])
        form_layout.addWidget(self.target_type_combo, 1, 1)
        
        form_layout.addWidget(QLabel("Priority:"), 1, 2)
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(["Critical", "High", "Medium", "Low"])
        form_layout.addWidget(self.priority_combo, 1, 3)
        
        add_btn = QPushButton("➕ Add Target")
        add_btn.clicked.connect(self.add_target)
        form_layout.addWidget(add_btn, 2, 0, 1, 4)
        
        layout.addWidget(form_group)
        
        # Targets table
        self.targets_table = QTableWidget()
        self.targets_table.setColumnCount(6)
        self.targets_table.setHorizontalHeaderLabels([
            "Name", "IP/Host", "Type", "Priority", "Status", "Actions"
        ])
        self.targets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.targets_table)
        
        return widget
    
    def create_reports_tab(self) -> QWidget:
        """Create reports tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Report generation
        gen_group = QGroupBox("Generate Report")
        gen_layout = QHBoxLayout(gen_group)
        
        gen_layout.addWidget(QLabel("Campaign:"))
        self.report_campaign_combo = QComboBox()
        self.report_campaign_combo.addItem("Select campaign...")
        gen_layout.addWidget(self.report_campaign_combo)
        
        gen_layout.addWidget(QLabel("Format:"))
        self.report_format_combo = QComboBox()
        self.report_format_combo.addItems(["PDF", "HTML", "JSON", "MITRE Navigator"])
        gen_layout.addWidget(self.report_format_combo)
        
        generate_btn = QPushButton("📊 Generate Report")
        generate_btn.clicked.connect(self.generate_report)
        gen_layout.addWidget(generate_btn)
        
        gen_layout.addStretch()
        
        layout.addWidget(gen_group)
        
        # Report preview
        preview_group = QGroupBox("Report Preview")
        preview_layout = QVBoxLayout(preview_group)
        
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setStyleSheet("background: #1a1a2e;")
        self.report_preview.setText("""
═══════════════════════════════════════════════════════════════════════════════
                    AUTONOMOUS RED TEAM CAMPAIGN REPORT
═══════════════════════════════════════════════════════════════════════════════

Campaign: [Not Selected]
Date: [Not Generated]

EXECUTIVE SUMMARY
─────────────────────────────────────────────────────────────────────────────

Select a campaign and generate a report to view the detailed results.

This report will include:
  • Campaign overview and objectives
  • Attack path visualization
  • MITRE ATT&CK technique mapping
  • Findings and vulnerabilities
  • Recommendations for remediation
  • Detailed execution timeline

═══════════════════════════════════════════════════════════════════════════════
""")
        
        preview_layout.addWidget(self.report_preview)
        
        layout.addWidget(preview_group)
        
        return widget
    
    def generate_plan(self):
        """Generate attack plan."""
        self.attack_plan_tree.clear()
        
        phases = {
            "Reconnaissance": [
                ("T1595.001", "Active IP Scanning", "Network", "High"),
                ("T1592", "Gather Victim Host Info", "All", "Medium")
            ],
            "Initial Access": [
                ("T1566.001", "Spearphishing Attachment", "Workstation", "High"),
                ("T1190", "Exploit Public-Facing App", "Web Server", "Critical")
            ],
            "Execution": [
                ("T1059.001", "PowerShell", "Workstation", "High"),
                ("T1204.002", "Malicious File", "Workstation", "Medium")
            ],
            "Persistence": [
                ("T1547.001", "Registry Run Keys", "Workstation", "Medium"),
                ("T1053.005", "Scheduled Task", "Workstation", "Medium")
            ],
            "Privilege Escalation": [
                ("T1068", "Exploitation for Priv Esc", "Workstation", "High"),
                ("T1548.002", "UAC Bypass", "Workstation", "Medium")
            ],
            "Lateral Movement": [
                ("T1021.001", "Remote Desktop", "All", "High"),
                ("T1021.002", "SMB/Windows Admin Shares", "Domain Controller", "Critical")
            ],
            "Exfiltration": [
                ("T1048.001", "Exfil Over Alt Protocol", "File Server", "Critical"),
                ("T1567", "Exfil to Cloud Storage", "All", "High")
            ]
        }
        
        for phase_name, techniques in phases.items():
            phase_item = QTreeWidgetItem([f"📌 {phase_name}", "", "", ""])
            phase_item.setFont(0, QFont("Segoe UI", 10, QFont.Weight.Bold))
            
            for tid, name, target, priority in techniques:
                tech_item = QTreeWidgetItem([f"  {tid}", name, target, priority])
                
                # Color priority
                color = {"Critical": "#ff4444", "High": "#ff8844", "Medium": "#ffcc44", "Low": "#88ff88"}.get(priority, "#fff")
                tech_item.setForeground(3, QColor(color))
                
                phase_item.addChild(tech_item)
            
            self.attack_plan_tree.addTopLevelItem(phase_item)
            phase_item.setExpanded(True)
        
        self.log_message("Attack plan generated with 14 techniques across 7 phases")
    
    def execute_campaign(self):
        """Execute the campaign."""
        self.execution_progress.setValue(0)
        self.execution_log.clear()
        
        self.log_message("=" * 60)
        self.log_message("🚀 AUTONOMOUS RED TEAM CAMPAIGN INITIATED")
        self.log_message("=" * 60)
        self.log_message(f"Objective: {self.objective_combo.currentText()}")
        self.log_message(f"Mode: {self.mode_combo.currentText()}")
        self.log_message("")
        
        objective = self.objective_combo.currentText()
        targets = [item.text() for item in self.target_list.selectedItems()]
        mode = self.mode_combo.currentText()
        
        self.execution_worker = CampaignExecutionWorker(
            self.orchestrator, objective, targets, mode
        )
        self.execution_worker.progress.connect(self.update_execution_progress)
        self.execution_worker.technique_executed.connect(self.on_technique_executed)
        self.execution_worker.phase_complete.connect(self.on_phase_complete)
        self.execution_worker.finished.connect(self.on_execution_complete)
        self.execution_worker.start()
    
    def update_execution_progress(self, value: int):
        """Update execution progress."""
        self.execution_progress.setValue(value)
        self.progress_label.setText(f"{value}%")
    
    def on_technique_executed(self, data: dict):
        """Handle technique execution."""
        status = "✅" if data["success"] else "❌"
        self.log_message(f"{status} [{data['phase']}] {data['technique']} -> {data['target']}")
    
    def on_phase_complete(self, phase: str):
        """Handle phase completion."""
        self.current_phase_label.setText(f"Current Phase: {phase} ✅")
        
        if phase in self.phase_items:
            self.phase_items[phase].setText(1, "✅ Complete")
            self.phase_items[phase].setForeground(1, QColor("#00ff88"))
        
        self.log_message("")
        self.log_message(f"━━━ Phase Complete: {phase} ━━━")
        self.log_message("")
    
    def on_execution_complete(self, result: dict):
        """Handle execution completion."""
        self.log_message("")
        self.log_message("=" * 60)
        self.log_message("🏁 CAMPAIGN EXECUTION COMPLETE")
        self.log_message("=" * 60)
        
        if "error" not in result:
            self.log_message(f"Phases: {result['phases']}")
            self.log_message(f"Techniques: {result['techniques']}")
            self.log_message(f"Success Rate: {result['success_rate']:.0%}")
            
            # Update stats
            count = int(self.campaigns_count.findChild(QLabel, "value").text()) + 1
            self.campaigns_count.findChild(QLabel, "value").setText(str(count))
            self.success_rate.findChild(QLabel, "value").setText(f"{result['success_rate']:.0%}")
    
    def log_message(self, message: str):
        """Log message to execution log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.execution_log.append(f"[{timestamp}] {message}")
    
    def pause_execution(self):
        """Pause execution."""
        self.pause_btn.setEnabled(False)
        self.resume_btn.setEnabled(True)
        self.log_message("⏸️ Execution paused")
    
    def resume_execution(self):
        """Resume execution."""
        self.pause_btn.setEnabled(True)
        self.resume_btn.setEnabled(False)
        self.log_message("▶️ Execution resumed")
    
    def abort_execution(self):
        """Abort execution."""
        if hasattr(self, 'execution_worker') and self.execution_worker.isRunning():
            self.execution_worker.terminate()
        self.log_message("🛑 Execution aborted")
        self.current_phase_label.setText("Current Phase: Aborted")
    
    def add_target(self):
        """Add a target."""
        name = self.target_name_input.text()
        ip = self.target_ip_input.text()
        
        if not name or not ip:
            return
        
        row = self.targets_table.rowCount()
        self.targets_table.insertRow(row)
        
        items = [
            name,
            ip,
            self.target_type_combo.currentText(),
            self.priority_combo.currentText(),
            "Available"
        ]
        
        for col, item in enumerate(items):
            self.targets_table.setItem(row, col, QTableWidgetItem(item))
        
        remove_btn = QPushButton("Remove")
        remove_btn.setFixedWidth(60)
        self.targets_table.setCellWidget(row, 5, remove_btn)
        
        # Update stats
        count = self.targets_table.rowCount()
        self.targets_count.findChild(QLabel, "value").setText(str(count))
        
        # Clear inputs
        self.target_name_input.clear()
        self.target_ip_input.clear()
    
    def generate_report(self):
        """Generate campaign report."""
        self.report_preview.setText(f"""
═══════════════════════════════════════════════════════════════════════════════
                    AUTONOMOUS RED TEAM CAMPAIGN REPORT
═══════════════════════════════════════════════════════════════════════════════

Campaign ID: ATR-{datetime.now().strftime('%Y%m%d-%H%M%S')}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Format: {self.report_format_combo.currentText()}

EXECUTIVE SUMMARY
─────────────────────────────────────────────────────────────────────────────

Objective: {self.objective_combo.currentText()}
Operation Mode: {self.mode_combo.currentText()}
Duration: {self.time_limit_spin.value()} hours
Techniques Used: {self.max_techniques_spin.value()}

KEY FINDINGS
─────────────────────────────────────────────────────────────────────────────

[CRITICAL] Domain Controller vulnerable to credential dumping
[HIGH] Web server exposed to SQL injection
[HIGH] Lateral movement possible via SMB shares
[MEDIUM] Weak password policy detected
[MEDIUM] Insufficient logging on file server

MITRE ATT&CK COVERAGE
─────────────────────────────────────────────────────────────────────────────

Tactics Covered: 10/14
Techniques Used: 24
Sub-techniques: 15
Detection Rate: 35%

RECOMMENDATIONS
─────────────────────────────────────────────────────────────────────────────

1. Implement network segmentation between critical assets
2. Deploy advanced endpoint detection on domain controllers
3. Enable enhanced logging across all systems
4. Conduct privileged access review
5. Implement MFA for all administrative accounts

═══════════════════════════════════════════════════════════════════════════════
""")
